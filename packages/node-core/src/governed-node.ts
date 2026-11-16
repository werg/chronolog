import {
  encodeGenesisManifest, isCapabilityActive, validationPolicyId,
  type CapabilitySnapshot, type SignedGenesis,
} from '@chronolog/capabilities'
import type { ControlStore } from '@chronolog/control-store/browser'
import type { ChronologMaterializationRuntime } from '@chronolog/materializer'
import { DOMAINS, equalBytes, hashDomain, type Ed25519KeyPair } from '@chronolog/protocol'
import type { ChronologTransport } from '@chronolog/records'

import { CapabilityMembershipResolver } from './capability-membership.js'
import { EnrollmentIssuer, verifyEnrollmentDescriptor, type EnrollmentDescriptor } from './enrollment.js'
import type { FeedForkRegistry } from './feed-forks.js'
import { GovernanceActivationIndex } from './governance-activation.js'
import { GovernanceControlPlane, isInvalidGovernanceRecord } from './governance.js'
import { CoordinatedHistoryPolicy } from './history-policy.js'
import { ChronologNode } from './node.js'
import type { DurableOperationStore } from './operations.js'
import { PeerGovernanceController } from './peer-governance.js'
import type { Clock, OperationalMembershipState, RandomSource, ValidatorOptions } from './types.js'

export interface GovernedNodeOptions {
  readonly genesis: SignedGenesis
  readonly groupRoute: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly transport: ChronologTransport
  readonly materialization: ChronologMaterializationRuntime
  readonly operationStore: DurableOperationStore
  readonly recipient?: { readonly id: Uint8Array; readonly privateKey: CryptoKey }
  readonly controlStore?: ControlStore
  readonly validator?: Omit<ValidatorOptions, 'capabilityId'>
  readonly initialEpochContentKey?: Uint8Array
  readonly clock?: Clock
  readonly random?: RandomSource
  readonly feedForkRegistry?: FeedForkRegistry
}

/** The same governance, history and enrollment composition on native and browser peers. */
export async function createGovernedNode(options: GovernedNodeOptions) {
  const { genesis } = options
  const configured = genesis.manifest.historyPolicy
  if (configured === undefined) throw new Error('GENESIS_HISTORY_POLICY_REQUIRED')
  if (configured.kind === 'coordinated' && (configured.historyId === undefined || configured.authorityPublicKey === undefined)) {
    throw new Error('GENESIS_HISTORY_POLICY_INVALID')
  }
  const descriptor: EnrollmentDescriptor = {
    genesis, groupRoute: options.groupRoute,
    history: {
      ...(configured.kind === 'peer' ? { kind: 'peer' as const } : {
        kind: 'coordinated' as const, historyId: configured.historyId!, authorityPublicKey: configured.authorityPublicKey!,
      }), groupId: genesis.manifest.groupId,
      genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)),
      executionManifestDigest: options.materialization.queries.executionManifestDigest,
    },
  }
  await verifyEnrollmentDescriptor(descriptor)
  const governance = await GovernanceControlPlane.create({
    genesis, groupRoute: options.groupRoute, transport: options.transport,
    identity: options.identity, operationStore: options.operationStore,
    ...(options.recipient === undefined ? {} : { recipient: options.recipient }),
  })
  const initial = governance.snapshot
  const validationPolicy = await validationPolicyId(genesis.manifest.validationPolicies[0]!)
  const activation = new GovernanceActivationIndex(initial, configured.kind)
  const coordinated = descriptor.history.kind === 'coordinated'
    ? await CoordinatedHistoryPolicy.open(descriptor.history, options.operationStore) : undefined
  let node: ChronologNode
  const peer = configured.kind === 'peer' ? new PeerGovernanceController({
    genesis: initial, governance, groupRoute: options.groupRoute, transport: options.transport,
    identity: options.identity, store: options.operationStore, cipher: governance.cipherRing,
    closeRevision: (previous, next) => node.closeGovernanceRevision(previous, next),
    onActivation: () => { void node.refreshMembership() },
  }) : undefined
  const activeSnapshot = (): CapabilitySnapshot => peer?.activeSnapshot ?? activation.activeSnapshot
  const membershipState = (): OperationalMembershipState => {
    const snapshot = activeSnapshot()
    const capabilities = [...snapshot.capabilities.values()].filter((capability) =>
      equalBytes(capability.grant.signingPublicKey, options.identity.publicKeyBytes) &&
      isCapabilityActive(capability, snapshot.revision))
    const writer = capabilities.find((capability) => capability.grant.role === 'writer')
    const validator = capabilities.find((capability) => capability.grant.role === 'validator')
    return {
      membershipRevision: snapshot.revisionDigest, validationPolicy,
      ...(writer === undefined ? {} : { writerCapability: writer.id }),
      ...(validator === undefined ? {} : { validatorCapability: validator.id }),
      ...(peer === undefined ? {} : { minimumAuthorTimestampMs: peer.minimumAuthorTimestampMs }),
    }
  }
  const membership = new CapabilityMembershipResolver({
    snapshotForRevision: (digest) => governance.snapshotForRevision(digest),
    authorizationSnapshot: (context) => {
      if (peer !== undefined) return peer.ready
        ? context.authorTimestampMs === undefined ? peer.activeSnapshot : peer.snapshotFor(context)
        : null
      return context.canonicalPosition === undefined ? activation.activeSnapshot : activation.snapshotFor(context)
    },
  })
  const validatorCapability = membershipState().validatorCapability
  node = new ChronologNode({
    groupId: genesis.manifest.groupId, groupRoute: options.groupRoute,
    membershipRevision: initial.revisionDigest, validationPolicy, identity: options.identity,
    transport: options.transport, materialization: options.materialization, membership, membershipState,
    operationStore: options.operationStore, envelopeCipher: governance.cipherRing,
    ...(options.controlStore === undefined ? {} : { controlStore: options.controlStore }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.random === undefined ? {} : { random: options.random }),
    ...(options.feedForkRegistry === undefined ? {} : { feedForkRegistry: options.feedForkRegistry }),
    ...(peer === undefined ? {} : { peerGovernance: peer }),
    ...(peer === undefined || validatorCapability === undefined ? {} : {
      validator: { ...options.validator, capabilityId: validatorCapability },
    }),
    historyPolicy: coordinated === undefined ? { kind: 'peer' } : {
      kind: 'coordinated', policy: coordinated,
      receiveControlRecord: async (entry) => {
        try { await governance.ingestCanonical(entry) }
        catch (error) { if (!isInvalidGovernanceRecord(error)) throw error }
      },
      applyControlRecord: async (entry) => {
        try {
          const snapshot = await governance.ingestCanonical(entry)
          if (snapshot !== null && snapshot.revision > activation.activeSnapshot.revision) {
            activation.observe(snapshot)
            activation.activateCoordinated(snapshot, BigInt(entry.position))
          }
        } catch (error) {
          if (!isInvalidGovernanceRecord(error)) throw error
          // Known invalid administrative bytes occupy their canonical position.
        }
      },
    },
  })
  const abort = new AbortController()
  let follow: Promise<void> | undefined
  let started = false
  const enrollmentIssuer = equalBytes(options.identity.publicKeyBytes, genesis.manifest.rootAdminPublicKey) && governance.ownsCapabilityFeed
    ? new EnrollmentIssuer({
      descriptor, governance, store: options.operationStore, rootPrivateKey: options.identity.privateKey,
      captureFinalTarget: async () => {
        await node.waitForIdle()
        return { frontier: await node.finalTarget(), requiredEpochs: governance.knownEpochs,
          executionManifestDigest: node.executionManifestDigest }
      },
    }) : undefined
  return {
    node, governance, descriptor, enrollmentIssuer,
    get activeSnapshot(): CapabilitySnapshot { return activeSnapshot() },
    get peerGovernance(): PeerGovernanceController | undefined { return peer },
    async start(): Promise<void> {
      if (started) return
      await governance.start()
      if (governance.currentEpoch === null && governance.ownsCapabilityFeed) {
        await governance.rotateEpoch(options.identity.privateKey, options.initialEpochContentKey,
          { operationId: 'bootstrap-epoch-0' })
      }
      await peer?.start()
      await node.start()
      started = true
      follow = (async () => {
        for await (const _event of governance.events(0n, abort.signal)) await node.refreshMembership()
      })()
    },
    async close(): Promise<void> {
      abort.abort()
      await follow?.catch(() => undefined)
      await peer?.close()
      await governance.close()
      await node.close()
    },
  }
}

export type GovernedNode = Awaited<ReturnType<typeof createGovernedNode>>

import {
  encodeGenesisManifest, isCapabilityActive, validationPolicyId,
  type CapabilitySnapshot, type SignedGenesis,
} from '@chronolog/capabilities'
import type { ControlStore } from '@chronolog/control-store/browser'
import type { ChronologMaterializationRuntime } from '@chronolog/materializer'
import { DOMAINS, equalBytes, hashDomain, type Ed25519KeyPair } from '@chronolog/protocol'
import type { ChronologTransport } from '@chronolog/records'

import { Mutex } from './async.js'
import { ControlHistory, type MembershipLedgerPage } from './control-proof.js'
import { CapabilityMembershipResolver } from './capability-membership.js'
import { EnrollmentIssuer, verifyEnrollmentDescriptor, type EnrollmentDescriptor } from './enrollment.js'
import type { FeedForkRegistry } from './feed-forks.js'
import { GovernanceActivationIndex } from './governance-activation.js'
import { GovernanceControlPlane, GovernanceRecordPendingError, isInvalidGovernanceRecord, orderFinalizedGovernanceRecords } from './governance.js'
import { SignedInclusionFinalityProvider, encodeHistoryConfiguration, type CoordinatedHistoryConfiguration, type OrderedRecordEntry } from './history-policy.js'
import { resolveFinalityClockPolicy, type LiveInclusionFinalityProvider } from './finality.js'
import { ChronologNode } from './node.js'
import type { DurableOperationStore } from './operations.js'
import { PeerGovernanceController } from './peer-governance.js'
import type { Clock, OperationalMembershipState, RandomSource, ValidatorOptions } from './types.js'

export interface GovernedNodeOptions {
  /** Inclusion-family verifiers selected by signed provider ID and parameters; peer validators are built in. */
  readonly liveInclusionProviders?: Readonly<Record<string, (configuration: CoordinatedHistoryConfiguration,
    store: DurableOperationStore) => Promise<LiveInclusionFinalityProvider>>>
  readonly genesis: SignedGenesis
  readonly groupRoute: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly transport: ChronologTransport
  readonly materialization: ChronologMaterializationRuntime
  readonly operationStore: DurableOperationStore
  readonly recipient?: { readonly id: Uint8Array; readonly privateKey: CryptoKey }
  readonly controlStore?: ControlStore
  /** Recovery floor only; validator timing and policy come from signed genesis. */
  readonly validator?: Pick<ValidatorOptions, 'initialAcceptedAboveMs'>
  readonly initialEpochContentKey?: Uint8Array
  readonly clock?: Clock
  readonly random?: RandomSource
  readonly feedForkRegistry?: FeedForkRegistry
}

/** The same governance, history and enrollment composition on native and browser peers. */
export async function createGovernedNode(options: GovernedNodeOptions) {
  // Verification and all derived runtime policy must observe one owned input,
  // even when a caller changes its configuration while crypto is awaited.
  options = { ...options, genesis: structuredClone(options.genesis), groupRoute: options.groupRoute.slice() }
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
      ...(configured.providerId === undefined ? {} : { providerId: configured.providerId }),
      ...(configured.providerParameters === undefined ? {} : { providerParameters: configured.providerParameters }),
    },
  }
  await verifyEnrollmentDescriptor(descriptor)
  const clock = resolveFinalityClockPolicy(genesis.manifest.clockPolicy)
  const governance = await GovernanceControlPlane.create({
    genesis, groupRoute: options.groupRoute, transport: options.transport,
    identity: options.identity, operationStore: options.operationStore,
    ...(options.recipient === undefined ? {} : { recipient: options.recipient }),
  })
  const initial = governance.snapshot
  const validationPolicy = await validationPolicyId(genesis.manifest.validationPolicies[0]!)
  const activation = new GovernanceActivationIndex(initial)
  let coordinated: LiveInclusionFinalityProvider | undefined
  if (descriptor.history.kind === 'coordinated') {
    const providerId = descriptor.history.providerId ?? 'signed-inclusion-v2'
    const factory = options.liveInclusionProviders?.[providerId]
    if (factory !== undefined) coordinated = await factory(structuredClone(descriptor.history), options.operationStore)
    else if (providerId === 'signed-inclusion-v2') {
      coordinated = await SignedInclusionFinalityProvider.open(descriptor.history, options.operationStore)
    } else throw new Error('FINALITY_PROVIDER_UNAVAILABLE')
    if (!equalBytes(encodeHistoryConfiguration(coordinated.configuration), encodeHistoryConfiguration(descriptor.history))) {
      throw new Error('FINALITY_PROVIDER_CONFIGURATION_MISMATCH')
    }
  }
  const bootstrapControls = descriptor.history.kind === 'coordinated' &&
    (descriptor.history.providerId ?? 'signed-inclusion-v2') === 'signed-inclusion-v2'
    ? await ControlHistory.open(descriptor.history, options.operationStore) : null
  const controlApplication = new Mutex()
  const applyControl = (entry: OrderedRecordEntry, cutoffMs: bigint) => controlApplication.run(async () => {
    try {
      const snapshot = await governance.ingestFinalized(entry, activation.activeSnapshot, cutoffMs)
      if (snapshot !== null && snapshot.revision > activation.activeSnapshot.revision) {
        activation.observe(snapshot); activation.activateFinalized(snapshot, cutoffMs)
      }
    } catch (error) {
      if (!isInvalidGovernanceRecord(error)) throw error
    }
  })
  const applyBootstrapControls = async (): Promise<void> => {
    if (bootstrapControls === null) return
    const controls = await orderFinalizedGovernanceRecords(bootstrapControls.entries().map(control => ({
      entry: control.entry, cutoffMs: control.cutoffMs,
    })), options.groupRoute)
    for (const control of controls) {
      try { await applyControl(control.entry, control.cutoffMs) }
      catch (error) { if (!(error instanceof GovernanceRecordPendingError)) throw error }
    }
  }
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
      minimumAuthorTimestampMs: peer?.minimumAuthorTimestampMs ?? activation.activationBoundary + 1n,
    }
  }
  const membership = new CapabilityMembershipResolver({
    snapshotForRevision: (digest) => governance.snapshotForRevision(digest),
    authorizationSnapshot: (context) => {
      if (peer !== undefined) return peer.ready
        ? context.authorTimestampMs === undefined ? peer.activeSnapshot : peer.snapshotFor(context)
        : null
      return context.authorTimestampMs === undefined ? activation.activeSnapshot : activation.snapshotFor(context)
    },
  })
  const validatorCapability = membershipState().validatorCapability
  const node: ChronologNode = new ChronologNode({
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
      validator: { ...options.validator, capabilityId: validatorCapability,
        cutoffLagMs: clock.cutoffLagMs, maxFutureSkewMs: clock.maxFutureSkewMs,
        heartbeatIntervalMs: clock.heartbeatIntervalMs },
    }),
    historyPolicy: coordinated === undefined ? { kind: 'peer' } : {
      kind: 'coordinated', policy: coordinated, futureAdmissionWindowMs: clock.futureAdmissionWindowMs,
      applyGovernanceRecord: applyControl,
      hasEncryptionEpoch: (epochId, includedThrough) => governance.hasFinalizedEpoch(epochId, includedThrough),
      encryptionEpochStatusAt: (timestamp, epochId) => governance.finalizedEpochStatusAt(timestamp, epochId),
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
    /** Establish current reader grants/keys from compact host evidence; application history still comes from peers. */
    async ingestMembership(page: MembershipLedgerPage): Promise<void> {
      if (bootstrapControls === null) throw new Error('MEMBERSHIP_CONTROL_PROOF_UNAVAILABLE')
      await bootstrapControls.ingest(page)
      await applyBootstrapControls()
      await node.refreshMembership()
    },
    get activeSnapshot(): CapabilitySnapshot { return activeSnapshot() },
    get peerGovernance(): PeerGovernanceController | undefined { return peer },
    async start(): Promise<void> {
      if (started) return
      await governance.start()
      await applyBootstrapControls()
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

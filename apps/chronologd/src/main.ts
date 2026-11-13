import { join, resolve } from 'node:path'

import { executionManifestArtifacts } from '@chronolog/protocol'
import { isCapabilityActive } from '@chronolog/capabilities'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import {
  CapabilityMembershipResolver,
  ChronologNode,
  GovernanceControlPlane,
  FeedForkRegistry,
  SqliteFeedForkPersistence,
  createEpochEnvelopeCipher,
  type MembershipResolver,
} from '@chronolog/node-core'
import { equalBytes } from '@chronolog/protocol'
import { HttpRpcServer, NodeRpcService } from '@chronolog/rpc'
import { FeedTransport, type SsbPeer } from '@chronolog/transport-ssb'

import { fromBase64, loadOrCreateConfig, parseDaemonRuntimeConfig } from './config.js'
import { loadOrCreateGovernanceBootstrap } from './governance-config.js'
import { loadStaticMembership, readStaticRootAdministrator } from './static-membership.js'
import { discoverPublicSsbAddress, verifyPublicSsbReachability, type NatVerificationResult } from './nat-discovery.js'
import { daemonHealth, prometheusMetrics } from './observability.js'
import { daemonSecretStoreFromEnvironment } from './secret-store.js'
import { createGovernanceRpcAdmin } from './governance-admin.js'
import { acquireDataDirectoryLock } from './data-lock.js'

const dataDirectory = resolve(process.env.CHRONOLOG_DATA_DIR ?? '.chronolog')
const dataLock = await acquireDataDirectoryLock(dataDirectory, 'daemon')
const runtime = parseDaemonRuntimeConfig(process.env)
const secretStore = daemonSecretStoreFromEnvironment(process.env)
const { config, identity } = await loadOrCreateConfig(dataDirectory, secretStore)
const groupId = fromBase64(config.groupId)
const configuredMembershipRevision = fromBase64(config.membershipRevision)
const configuredValidationPolicy = fromBase64(config.validationPolicy)
const configuredValidatorCapability = fromBase64(config.validatorCapability)

const configuredPeers: readonly SsbPeer[] = runtime.peers
const executionManifest = createDoltLiteExecutionManifest()
const { executionManifestDigest } = await executionManifestArtifacts(executionManifest)
const { transport, materializer, node, server, address, governance, nat, nodeState } = await startRuntime()
process.stdout.write(`${JSON.stringify({
  event: 'chronologd.ready',
  url: address.url,
  healthUrl: `${address.url}/health`,
  metricsUrl: `${address.url}/metrics`,
  groupId: Buffer.from(groupId).toString('base64url'),
  nodeId: Buffer.from(identity.publicKeyBytes).toString('base64url'),
  ssbId: transport.identity,
  ssbAddress: transport.address(runtime.ssbScope),
  publicSsbAddress: nat.address,
  publicSsbAddressSource: nat.source,
  natDiscoveryError: nat.error ?? null,
  publicSsbReachability: nat.reachability.status,
  publicSsbReachabilityError: nat.reachability.error ?? null,
  materializer: materializer.backend,
  executionManifestDigest: Buffer.from(materializer.executionManifestDigest).toString('base64url'),
  membershipRevision: Buffer.from(node.membershipRevision).toString('base64url'),
  governanceRevision: governance?.snapshot.revision.toString() ?? null,
  encryptionEpoch: governance?.currentEpoch?.toString() ?? config.epoch,
})}\n`)

let stopping = false
async function stop(signal: string): Promise<void> {
  if (stopping) return
  stopping = true
  process.stdout.write(`${JSON.stringify({ event: 'chronologd.stopping', signal })}\n`)
  await server.close()
  await governance?.close()
  await node.close()
  nodeState.close()
  await dataLock.release()
}

function terminate(signal: string): void {
  void stop(signal).then(
    () => process.exit(0),
    (error: unknown) => {
      process.stderr.write(`${JSON.stringify({
        event: 'chronologd.stop_failed',
        signal,
        error: error instanceof Error ? error.stack ?? error.message : String(error),
      })}\n`)
      process.exit(1)
    },
  )
}

process.once('SIGINT', () => terminate('SIGINT'))
process.once('SIGTERM', () => terminate('SIGTERM'))

async function startRuntime() {
  const transport = await FeedTransport.open({
    path: join(dataDirectory, 'ssb'),
    network: {
      listen: {
        host: runtime.ssbHost,
        port: runtime.ssbPort,
        scope: runtime.ssbScope,
      },
      peers: configuredPeers,
      ...(runtime.staleReconnectMs === undefined ? {} : { reconnect: { staleAfterMs: runtime.staleReconnectMs } }),
    },
  })
  let materializer: DeterministicMaterializer | undefined
  let node: ChronologNode | undefined
  let server: HttpRpcServer | undefined
  let governance: GovernanceControlPlane | undefined
  let reachability: NatVerificationResult = { status: 'not-configured', address: null }
  // The node's own state (control index, validator cutoffs, feed continuity).
  const nodeState = new NodeStateDatabase(join(dataDirectory, 'node-state.sqlite'))
  // Opened once the genesis root administrator is known: it is the first schema administrator.
  // A fork's genesis names its source group; only then may the root seed rows.
  const openMaterializer = async (rootAdministrator: Uint8Array, forkSeeding = false): Promise<DeterministicMaterializer> => {
    materializer = await DeterministicMaterializer.open({
      path: join(dataDirectory, 'application.db'),
      checkpointEvery: runtime.checkpointEvery,
      executionManifest,
      rootAdministrator,
      forkSeeding,
    })
    return materializer
  }
  try {
    const controlStore = new ControlStore(new SqliteControlStorePersistence(nodeState))
    let membership: MembershipResolver
    let membershipRevision = configuredMembershipRevision
    let validationPolicy = configuredValidationPolicy
    let validatorCapability = configuredValidatorCapability
    const envelopeCipher = createEpochEnvelopeCipher(fromBase64(config.epochContentKey), BigInt(config.epoch))
    let membershipState: (() => {
      readonly membershipRevision: Uint8Array
      readonly validationPolicy: Uint8Array
      readonly validatorCapability?: Uint8Array
    }) | undefined
    if (process.env.CHRONOLOG_STATIC_MEMBERSHIP_FILE !== undefined) {
      const membershipFile = resolve(process.env.CHRONOLOG_STATIC_MEMBERSHIP_FILE)
      membership = await loadStaticMembership(membershipFile, {
        groupId,
        membershipRevision,
        validationPolicy,
      })
      await openMaterializer(await readStaticRootAdministrator(membershipFile))
    } else {
      const bootstrap = await loadOrCreateGovernanceBootstrap({
        dataDirectory,
        groupId,
        schemaId: executionManifestDigest,
        identity,
        transportAuthor: transport.identity,
        ...(secretStore === undefined ? {} : { secretStore }),
      })
      await openMaterializer(bootstrap.genesis.manifest.rootAdminPublicKey, bootstrap.genesis.manifest.forkedFrom !== undefined)
      governance = await GovernanceControlPlane.create({
        genesis: bootstrap.genesis,
        groupRoute: fromBase64(config.groupRoute),
        transport,
        identity,
        recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey },
      })
      await governance.start()
      // Only the administration-feed owner creates the first epoch; a node that
      // joined an existing group waits for the epoch wrapped to its reader key.
      if (governance.currentEpoch === null && governance.ownsCapabilityFeed) {
        await governance.rotateEpoch(identity.privateKey, fromBase64(config.epochContentKey))
      }
      membership = new CapabilityMembershipResolver({
        snapshotForRevision: (digest) => governance!.snapshotForRevision(digest),
      })
      validationPolicy = bootstrap.validationPolicyId
      const state = () => {
        const snapshot = governance!.snapshot
        const activeValidator = [...snapshot.capabilities.values()].find((capability) =>
          capability.grant.role === 'validator' &&
          equalBytes(capability.grant.signingPublicKey, identity.publicKeyBytes) &&
          isCapabilityActive(capability, snapshot.revision))
        return {
          membershipRevision: snapshot.revisionDigest,
          validationPolicy,
          ...(activeValidator === undefined ? {} : { validatorCapability: activeValidator.id }),
        }
      }
      const initial = state()
      membershipRevision = initial.membershipRevision
      validatorCapability = initial.validatorCapability ?? configuredValidatorCapability
      membershipState = state
      // The node reads the ring's current epoch lazily: a node that joined an
      // existing group has no epoch until the administrator wraps one to it.
    }
    node = new ChronologNode({
      groupId,
      groupRoute: fromBase64(config.groupRoute),
      membershipRevision,
      validationPolicy,
      identity,
      transport,
      materialization: createDoltLiteMaterializationRuntime(materializer!),
      controlStore,
      membership,
      ...(membershipState === undefined ? {} : { membershipState }),
      validator: {
        capabilityId: validatorCapability,
        cutoffLagMs: runtime.cutoffLagMs,
        maxFutureSkewMs: runtime.maxFutureSkewMs,
        heartbeatIntervalMs: runtime.heartbeatIntervalMs,
      },
      envelopeCipher: governance?.cipherRing ?? envelopeCipher,
      feedForkRegistry: new FeedForkRegistry(new SqliteFeedForkPersistence(nodeState.database)),
    })
    await node.start()
    server = new HttpRpcServer({
      service: new NodeRpcService({
        node,
        ...(governance === undefined ? {} : {
          governanceAdmin: createGovernanceRpcAdmin({ governance, rootPrivateKey: identity.privateKey }),
        }),
      }),
      host: runtime.host,
      port: runtime.port,
      ...(runtime.token === undefined ? {} : { token: runtime.token }),
      health: async () => daemonHealth(await node!.status(), stopping, traversalError(runtime.ssbScope, reachability)),
      metrics: async () => prometheusMetrics(await node!.status(), traversalError(runtime.ssbScope, reachability)),
    })
    const address = await server.listen()
    const nat = await discoverPublicSsbAddress({
      timeoutMs: runtime.natDiscoveryTimeoutMs,
      ...(runtime.publicSsbAddress === undefined ? {} : { explicitAddress: runtime.publicSsbAddress }),
      ...(runtime.natDiscoveryUrl === undefined ? {} : { discoveryUrl: runtime.natDiscoveryUrl }),
    })
    reachability = await verifyPublicSsbReachability({
      address: nat.address,
      timeoutMs: runtime.natDiscoveryTimeoutMs,
      ...(runtime.natVerificationUrl === undefined ? {} : { verificationUrl: runtime.natVerificationUrl }),
    })
    return { transport, materializer: materializer!, node, server, address, governance, nat: { ...nat, reachability }, nodeState }
  } catch (error) {
    await server?.close().catch(() => undefined)
    await governance?.close().catch(() => undefined)
    if (node !== undefined) {
      await node.close().catch(() => undefined)
    } else {
      materializer?.close()
      await transport.close().catch(() => undefined)
    }
    nodeState.close()
    throw error
  }
}

function traversalError(scope: 'device' | 'local' | 'public', result: NatVerificationResult): string | undefined {
  if (scope !== 'public') return undefined
  if (result.status === 'verified') return undefined
  return result.error ?? 'PUBLIC_SSB_REACHABILITY_NOT_VERIFIED'
}

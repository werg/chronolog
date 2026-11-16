import { join, resolve } from 'node:path'

import { executionManifestArtifacts } from '@chronolog/protocol'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import {
  DeterministicMaterializer,
  createDoltLiteExecutionManifest,
  createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import {
  ChronologNode,
  type GovernanceControlPlane,
  FeedForkRegistry,
  SqliteFeedForkPersistence,
  createEpochEnvelopeCipher,
  createGovernedNode,
  createEnrollmentService,
  type GovernedNode,
} from '@chronolog/node-core'
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
import { SqliteOperationStore } from './operation-store.js'

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
const { transport, materializer, node, server, address, governance, governed, nat, nodeState } = await startRuntime()
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
  if (governed !== undefined) await governed.close()
  else await node.close()
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
  let governed: GovernedNode | undefined
  let enrollment: ReturnType<typeof createEnrollmentService> | undefined
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
    const operationStore = new SqliteOperationStore(nodeState.database)
    if (process.env.CHRONOLOG_STATIC_MEMBERSHIP_FILE !== undefined) {
      const membershipFile = resolve(process.env.CHRONOLOG_STATIC_MEMBERSHIP_FILE)
      const membership = await loadStaticMembership(membershipFile, {
        groupId, membershipRevision: configuredMembershipRevision, validationPolicy: configuredValidationPolicy,
      })
      await openMaterializer(await readStaticRootAdministrator(membershipFile))
      node = new ChronologNode({
        groupId, groupRoute: fromBase64(config.groupRoute), identity, transport, membership,
        membershipRevision: configuredMembershipRevision, validationPolicy: configuredValidationPolicy,
        materialization: createDoltLiteMaterializationRuntime(materializer!), operationStore,
        controlStore: new ControlStore(new SqliteControlStorePersistence(nodeState)),
        validator: { capabilityId: configuredValidatorCapability, cutoffLagMs: runtime.cutoffLagMs,
          maxFutureSkewMs: runtime.maxFutureSkewMs, heartbeatIntervalMs: runtime.heartbeatIntervalMs },
        envelopeCipher: createEpochEnvelopeCipher(fromBase64(config.epochContentKey), BigInt(config.epoch)),
        feedForkRegistry: new FeedForkRegistry(new SqliteFeedForkPersistence(nodeState.database)),
      })
      await node.start()
    } else {
      const bootstrap = await loadOrCreateGovernanceBootstrap({
        dataDirectory, groupId, schemaId: executionManifestDigest, identity, transportAuthor: transport.identity,
        ...(secretStore === undefined ? {} : { secretStore }),
      })
      await openMaterializer(bootstrap.genesis.manifest.rootAdminPublicKey, bootstrap.genesis.manifest.forkedFrom !== undefined)
      const orderPolicy = bootstrap.genesis.manifest.historyPolicy?.kind
      if (orderPolicy === undefined) throw new Error('GENESIS_HISTORY_POLICY_REQUIRED')
      governed = await createGovernedNode({
        genesis: bootstrap.genesis, groupRoute: fromBase64(config.groupRoute), identity, transport,
        recipient: { id: bootstrap.recipientId, privateKey: bootstrap.recipientPrivateKey },
        materialization: createDoltLiteMaterializationRuntime(materializer!), operationStore,
        controlStore: new ControlStore(new SqliteControlStorePersistence(nodeState), { orderPolicy }),
        validator: { cutoffLagMs: runtime.cutoffLagMs, maxFutureSkewMs: runtime.maxFutureSkewMs,
          heartbeatIntervalMs: runtime.heartbeatIntervalMs },
        initialEpochContentKey: fromBase64(config.epochContentKey),
        feedForkRegistry: new FeedForkRegistry(new SqliteFeedForkPersistence(nodeState.database)),
      })
      node = governed.node
      governance = governed.governance
      await governed.start()
      enrollment = createEnrollmentService({
        descriptor: governed.descriptor, store: operationStore, identity,
        readerPublicKey: bootstrap.recipientPublicKey, transportAuthor: transport.identity, governance,
        activeMembership: () => governed!.activeSnapshot,
        ...(governed.enrollmentIssuer === undefined ? {} : { issuer: governed.enrollmentIssuer }),
        connected: async () => {
          const status = await transport.status()
          return governance!.ownsCapabilityFeed || (status.connected ?? status.peers.length > 0)
        },
        executionManifestDigest,
        isFinalTargetApplied: (target) => node!.isFinalTargetApplied(target.frontier),
      })
    }
    server = new HttpRpcServer({
      service: new NodeRpcService({
        node,
        ...(enrollment === undefined ? {} : { enrollment }),
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
    return { transport, materializer: materializer!, node, server, address, governance, governed, nat: { ...nat, reachability }, nodeState }
  } catch (error) {
    await server?.close().catch(() => undefined)
    if (governed !== undefined) {
      await governed.close().catch(() => undefined)
    } else if (node !== undefined) {
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

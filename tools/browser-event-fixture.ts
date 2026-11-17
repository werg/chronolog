import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'

import { NativeAgentStore, type AgentApplicationModule } from '@chronolog/agent-service'
import { encodeSignedGenesis, signGenesis, type CapabilityGrant } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createEventMaterializationRuntime, eventExecutionManifest, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, type EnrollmentIdentity } from '@chronolog/node-core'
import { base64UrlToBytes, bytesToBase64Url, encodeExecutionManifest, executionManifestArtifacts, utf8, type ExecutionManifest } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'

import { createDaemonAgentRuntime } from '../apps/chronologd/src/agent-runtime.js'
import type { BrowserEventBootstrap, BrowserEventIdentity } from '../test/browser/event-contract.js'
import { createHttpPeerFixture } from './lib/http-peer-fixture.js'

/**
 * Real native fixed authority used by browser and contrib acceptance gates.
 * Every application record and certificate travels through the authenticated
 * framed range protocol. HTTP provides reliable bytes, never group authority.
 */
export async function createNativeBrowserFixture(options: {
  readonly directory: string
  readonly browsers: readonly BrowserEventIdentity[]
  readonly topics?: readonly string[]
  /** Semantic tests may supply one controlled author/finality clock; browser gates use wall time. */
  readonly authorClock?: () => number
  /** Qualification-only clock control; signed proposal timestamps are unchanged. */
  readonly finalityClock?: () => number
  readonly manifest?: ExecutionManifest
  readonly materialization?: (context: { readonly store: NativeAgentStore; readonly identity: EnrollmentIdentity;
    readonly executionManifest: ExecutionManifest }) => Promise<ChronologMaterializationRuntime>
  readonly application?: AgentApplicationModule
}) {
  await mkdir(options.directory, { recursive: true })
  const store = new NativeAgentStore(join(options.directory, 'agent.sqlite'))
  const control = new NodeStateDatabase(join(options.directory, 'control.sqlite'))
  const identity = await loadOrCreateEnrollmentIdentity(store, 'browser-fixture-native')
  const feedStore = await DurableFeedStore.open(store, webFeedCrypto)
  const transport = new PortableFeedTransport({ store: feedStore, crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
  const executionManifest = options.manifest ?? await eventExecutionManifest()
  const { executionManifestDigest } = await executionManifestArtifacts(executionManifest)
  const materialization = options.materialization === undefined
    ? await createEventMaterializationRuntime({ store, namespace: 'application' })
    : await options.materialization({ store, identity, executionManifest })
  const groupId = crypto.getRandomValues(new Uint8Array(32)), groupRoute = crypto.getRandomValues(new Uint8Array(32))
  const epochContentKey = crypto.getRandomValues(new Uint8Array(32))
  const root = { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes,
    transportAuthor: transport.identity, validFromRevision: 0n }
  const browserGrants = options.browsers.flatMap((browser): CapabilityGrant[] => {
    const publicKey = base64UrlToBytes(browser.identity)
    const common = { subjectId: publicKey, signingPublicKey: publicKey, transportAuthor: browser.transportAuthor, validFromRevision: 0n }
    return [{ ...common, role: 'reader', hpkePublicKey: base64UrlToBytes(browser.readerKey) },
      { ...common, role: 'writer', program: { sql: options.materialization !== undefined,
        topics: options.topics ?? ['conversation', 'tasks', 'job-requests'], signals: ['typing'] } }]
  })
  const genesis = await signGenesis({ groupId, schemaId: executionManifestDigest,
    rootAdminPublicKey: identity.signing.publicKeyBytes, schemaAdminPublicKey: identity.signing.publicKeyBytes, capabilityLogFeed: utf8(transport.identity),
    historyPolicy: { kind: 'coordinated', executionManifestDigest,
      historyId: `h_${crypto.randomUUID().replaceAll('-', '')}`, authorityPublicKey: identity.signing.publicKeyBytes },
    initialCapabilities: [{ ...root, role: 'reader', hpkePublicKey: identity.reader.publicKeyBytes },
      { ...root, role: 'writer', program: { sql: options.materialization !== undefined, topics: ['*'], signals: ['*'] } }, ...browserGrants],
    validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.signing.privateKey)
  const governed = await createGovernedNode({ genesis, groupRoute, identity: identity.signing, transport, operationStore: store,
    ...(options.authorClock === undefined ? {} : { clock: { now: options.authorClock } }),
    controlStore: new ControlStore(new SqliteControlStorePersistence(control)), materialization,
    recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey }, initialEpochContentKey: epochContentKey })
  await governed.start()
  const agent = await createDaemonAgentRuntime({ node: governed.node, identity: identity.signing, descriptor: governed.descriptor,
    store, transport, activeMembership: () => governed.activeSnapshot,
    ...(options.finalityClock === undefined ? {} : { finalityClock: options.finalityClock }),
    ...(options.application === undefined ? {} : { application: options.application }),
    peerLinks: { local: transport.asLink(), attach: (link) => transport.connect(link) } })
  const running = agent.run()
  let serviceFailure: Error | undefined
  void running.catch((error: unknown) => { serviceFailure = error instanceof Error ? error : new Error('NATIVE_AGENT_FAILED', { cause: error }) })
  const client = new ChronologClient({ groupId: bytesToBase64Url(groupId),
    transport: new InProcessRpcTransport(new NodeRpcService({ node: governed.node, signals: agent.context.signals })), unaryRetryAttempts: 1 })
  const failures: string[] = []
  const http = await createHttpPeerFixture({ accept: connection => agent.context.connectPeer({ connection }),
    onError: error => { failures.push(error instanceof Error ? error.message : String(error)) } })
  const bootstrap: BrowserEventBootstrap = { genesis: bytesToBase64Url(encodeSignedGenesis(genesis)), groupRoute: bytesToBase64Url(groupRoute),
    epochContentKey: bytesToBase64Url(epochContentKey), executionManifest: bytesToBase64Url(encodeExecutionManifest(executionManifest)),
    nativeIdentity: bytesToBase64Url(identity.signing.publicKeyBytes), peerUrl: http.url, peerToken: http.token }
  let closed = false
  return { bootstrap, node: governed.node, governed, client, store, feedStore, identity, agent, transport,
    assertHealthy() {
      if (serviceFailure !== undefined) throw serviceFailure
      if (failures.length > 0) throw new Error(`BROWSER_PEER_SESSION_FAILED: ${failures.join('; ')}`)
    },
    async close() {
      if (closed) return
      closed = true
      await http.close()
      try { await agent.close(); await client.close(); await governed.close() }
      finally { control.close(); store.close() }
    },
  }
}

export type NativeBrowserFixture = Awaited<ReturnType<typeof createNativeBrowserFixture>>

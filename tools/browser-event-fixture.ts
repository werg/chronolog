import { once } from 'node:events'
import { mkdir } from 'node:fs/promises'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { join } from 'node:path'

import { NativeAgentStore, framePeerStream, type AgentApplicationModule } from '@chronolog/agent-service'
import { encodeSignedGenesis, isCapabilityActive, signGenesis, type CapabilityGrant } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createEventMaterializationRuntime, eventExecutionManifest, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, type EnrollmentIdentity } from '@chronolog/node-core'
import { base64UrlToBytes, bytesToBase64Url, encodeExecutionManifest, equalBytes, executionManifestArtifacts, utf8, type ExecutionManifest } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'

import { createDaemonAgentRuntime } from '../apps/chronologd/src/agent-runtime.js'
import type { BrowserEventBootstrap, BrowserEventIdentity } from '../test/browser/event-contract.js'

/**
 * Real native fixed authority used by browser and contrib acceptance gates.
 * Every application record and certificate travels through the authenticated
 * framed range protocol. HTTP provides reliable bytes, never group authority.
 */
export async function createNativeBrowserFixture(options: {
  readonly directory: string
  readonly browsers: readonly BrowserEventIdentity[]
  readonly topics?: readonly string[]
  readonly manifest?: ExecutionManifest
  readonly materialization?: (context: { readonly store: NativeAgentStore; readonly identity: EnrollmentIdentity;
    readonly executionManifest: ExecutionManifest }) => Promise<ChronologMaterializationRuntime>
  readonly application?: AgentApplicationModule
}) {
  await mkdir(options.directory, { recursive: true })
  const store = new NativeAgentStore(join(options.directory, 'agent.sqlite'))
  const control = new NodeStateDatabase(join(options.directory, 'control.sqlite'))
  const identity = await loadOrCreateEnrollmentIdentity(store, 'browser-fixture-native')
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
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
    initialCapabilities: [{ ...root, role: 'administrator' },
      { ...root, role: 'reader', hpkePublicKey: identity.reader.publicKeyBytes },
      { ...root, role: 'writer', program: { sql: options.materialization !== undefined, topics: ['*'], signals: ['*'] } }, ...browserGrants],
    validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.signing.privateKey)
  const governed = await createGovernedNode({ genesis, groupRoute, identity: identity.signing, transport, operationStore: store,
    controlStore: new ControlStore(new SqliteControlStorePersistence(control), { orderPolicy: 'coordinated' }), materialization,
    recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey }, initialEpochContentKey: epochContentKey })
  await governed.start()
  const agent = await createDaemonAgentRuntime({ node: governed.node, identity: identity.signing, history: governed.descriptor.history,
    store, transport, activeMembership: () => governed.activeSnapshot,
    cutoffLagMs: Number(genesis.manifest.clockPolicy.cutoffLagMs),
    futureAdmissionWindowMs: Number(genesis.manifest.clockPolicy.maxFutureSkewMs + genesis.manifest.clockPolicy.cutoffLagMs),
    closureIntervalMs: Number(genesis.manifest.clockPolicy.heartbeatIntervalMs),
    ...(options.application === undefined ? {} : { application: options.application }),
    peerLinks: { local: transport.asLink(), attach(link) { transport.connect(link); return () => transport.disconnect(link.identity) } } })
  const running = agent.run()
  let serviceFailure: Error | undefined
  void running.catch((error: unknown) => { serviceFailure = error instanceof Error ? error : new Error('NATIVE_AGENT_FAILED', { cause: error }) })
  const client = new ChronologClient({ groupId: bytesToBase64Url(groupId),
    transport: new InProcessRpcTransport(new NodeRpcService({ node: governed.node })), unaryRetryAttempts: 1 })
  const token = crypto.randomUUID()
  const sessions = new Map<string, { readonly writer: WritableStreamDefaultWriter<Uint8Array>;
    sendSignal(bytes: Uint8Array): Promise<void>; close(): Promise<void> }>()
  const nativeWriter = [...governed.activeSnapshot.capabilities.values()].find((capability) => capability.grant.role === 'writer' &&
    isCapabilityActive(capability, governed.activeSnapshot.revision) && equalBytes(capability.grant.signingPublicKey, identity.signing.publicKeyBytes))!
  const signals = await agent.context.createSignals({ grantId: nativeWriter.id, send: async () => { /* This fixture only forwards original signed signals. */ } })
  const failures: string[] = []
  const server = createServer((request, response) => {
    response.setHeader('Access-Control-Allow-Origin', '*')
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    response.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
    response.setHeader('Cache-Control', 'no-store')
    if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return }
    const handle = async () => {
      const url = new URL(request.url ?? '/', 'http://localhost')
      const id = /^\/peer\/([a-z0-9-]{36})$/u.exec(url.pathname)?.[1]
      if (id === undefined || url.searchParams.get('token') !== token) { response.writeHead(403); response.end(); return }
      if (request.method === 'GET') {
        if (sessions.has(id)) { response.writeHead(409); response.end(); return }
        if (sessions.size >= 16) { response.writeHead(429); response.end(); return }
        response.writeHead(200, { 'Content-Type': 'application/octet-stream' }); response.flushHeaders()
        const incoming = new TransformStream<Uint8Array, Uint8Array>(), writer = incoming.writable.getWriter()
        const connection = framePeerStream({ readable: incoming.readable, writable: new WritableStream<Uint8Array>({
          write: (bytes) => writeStream(response, bytes), close: () => { response.end() }, abort: () => { response.destroy() },
        }) })
        let session: Awaited<ReturnType<typeof agent.context.connectPeer>> | undefined
        let closed = false
        const close = async () => {
          if (closed) return
          closed = true
          sessions.delete(id)
          await Promise.allSettled([connection.close(), writer.abort(), session?.close()])
        }
        sessions.set(id, { writer, close, async sendSignal(bytes) { await session?.sendSignal(bytes) } })
        response.on('close', () => { void close() })
        void agent.context.connectPeer({ connection, signals: { async receive(bytes) {
          const verified = await signals.receive(bytes)
          // Host send queues and receive concurrency are bounded. Expired or
          // congested replaceable signals may be dropped, never persisted.
          await Promise.allSettled([...sessions.entries()].filter(([other]) => other !== id).map(([, other]) => other.sendSignal(bytes)))
          return verified
        } } }).then((value) => {
          session = value
          if (closed) { void value.close(); return }
          void value.completion.catch((error: unknown) => {
            if (!closed) failures.push(error instanceof Error ? error.message : String(error))
          }).finally(close)
        }, (error: unknown) => {
          if (!closed) failures.push(error instanceof Error ? error.message : String(error))
          void close()
        })
      } else {
        const session = sessions.get(id)
        if (session === undefined) { response.writeHead(410); response.end(); return }
        if (request.method === 'POST') await session.writer.write(await boundedBody(request))
        else if (request.method === 'DELETE') await session.close()
        else { response.writeHead(405); response.end(); return }
        response.writeHead(204); response.end()
      }
    }
    void handle().catch((error: unknown) => {
      if (!response.headersSent) { response.writeHead(500); response.end(error instanceof Error ? error.message : String(error)) }
      else response.destroy()
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('BROWSER_FIXTURE_ADDRESS_UNAVAILABLE')
  const bootstrap: BrowserEventBootstrap = { genesis: bytesToBase64Url(encodeSignedGenesis(genesis)), groupRoute: bytesToBase64Url(groupRoute),
    epochContentKey: bytesToBase64Url(epochContentKey), executionManifest: bytesToBase64Url(encodeExecutionManifest(executionManifest)),
    nativeIdentity: bytesToBase64Url(identity.signing.publicKeyBytes), peerUrl: `http://127.0.0.1:${address.port}/peer`, peerToken: token }
  let closed = false
  return { bootstrap, node: governed.node, governed, client, store, identity, agent, transport,
    assertHealthy() {
      if (serviceFailure !== undefined) throw serviceFailure
      if (failures.length > 0) throw new Error(`BROWSER_PEER_SESSION_FAILED: ${failures.join('; ')}`)
    },
    async close() {
      if (closed) return
      closed = true
      await Promise.all([...sessions.values()].map((session) => session.close()))
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)))
      try { await agent.close(); await client.close(); await governed.close() }
      finally { control.close(); store.close() }
    },
  }
}

async function boundedBody(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of request) {
    const bytes = typeof chunk === 'string' ? utf8(chunk) : new Uint8Array(chunk as Uint8Array)
    length += bytes.length
    if (length > 1_048_576 + 65_540) throw new Error('PEER_HTTP_FRAME_TOO_LARGE')
    chunks.push(bytes)
  }
  if (length === 0) throw new Error('PEER_HTTP_FRAME_EMPTY')
  const body = new Uint8Array(length)
  let offset = 0
  for (const bytes of chunks) { body.set(bytes, offset); offset += bytes.length }
  return body
}

function writeStream(response: ServerResponse, bytes: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    response.write(bytes, (error) => error === undefined || error === null ? resolve() : reject(error))
  })
}

export type NativeBrowserFixture = Awaited<ReturnType<typeof createNativeBrowserFixture>>

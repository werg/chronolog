import { once } from 'node:events'
import { mkdir } from 'node:fs/promises'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { join } from 'node:path'

import { NativeAgentStore, framePeerStream } from '@chronolog/agent-service'
import { createMembershipLedgerHandler } from '@chronolog/agent-service/membership-http'
import { decodeSignedGenesis, encodeSignedGenesis, type CapabilityGrant } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, type GovernedNode } from '@chronolog/node-core'
import { decodeLedgerRecord } from '@chronolog/node-core/ledger'
import { decodeMembershipLedgerResponse, verifyMembershipLedgerRequest } from '@chronolog/node-core/membership'
import {
  GROUP_COLLECTIVE_ID, base64UrlToBytes, bytesToBase64Url, digestExecutionManifest, emit, encodeExecutionManifest, equalBytes, program, sqlStatement, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'

import { createDaemonAgentRuntime } from '../apps/chronologd/src/agent-runtime.js'

export interface ThinMembershipBootstrap {
  readonly genesis: string
  readonly groupRoute: string
  readonly executionManifest: string
  readonly nativeIdentity: string
  readonly peerUrl: string
  readonly peerToken: string
}

export interface ThinMembershipTraffic {
  membershipRequests: number
  membershipRequestBytes: number
  membershipResponseBytes: number
  descriptorTransfers: number
  candidateDescriptorBytes: number
  inlineControlDescriptorBytes: number
  inlineControlEnvelopeBytes: number
  applicationEnvelopeBytesToAdministrator: number
  unexpectedAdministratorRequests: number
  peerInboundBytes: number
  peerOutboundBytes: number
}

/**
 * Native half of the thin-administration qualification. The Cloudflare host
 * creates the root and signed genesis; this fixture owns only the distinct
 * native authority and its full application replica. No raw epoch key is ever
 * returned to a test device.
 */
export async function createThinMembershipNative(options: {
  readonly directory: string
  readonly extraRequest?: (request: Request) => Promise<Response | null>
}) {
  await mkdir(options.directory, { recursive: true })
  const store = new NativeAgentStore(join(options.directory, 'native.sqlite'))
  const identity = await loadOrCreateEnrollmentIdentity(store, 'native')
  let savedHistory = await store.get('qualification/native-history')
  if (savedHistory === null) {
    savedHistory = utf8(`h_${crypto.randomUUID().replaceAll('-', '')}`)
    await store.put('qualification/native-history', savedHistory)
  }
  const historyId = new TextDecoder().decode(savedHistory)
  const executionManifest = createDoltLiteExecutionManifest()
  const executionManifestDigest = await digestExecutionManifest(executionManifest)
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
  const common = { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes,
    transportAuthor: transport.identity, validFromRevision: 0n }
  const initialCapabilities: readonly CapabilityGrant[] = [
    { ...common, role: 'reader', hpkePublicKey: identity.reader.publicKeyBytes },
    { ...common, role: 'writer', program: { sql: true, topics: ['*'], signals: ['*'] } },
  ]
  const traffic: ThinMembershipTraffic = { membershipRequests: 0, membershipRequestBytes: 0, membershipResponseBytes: 0,
    descriptorTransfers: 0, candidateDescriptorBytes: 0, inlineControlDescriptorBytes: 0, inlineControlEnvelopeBytes: 0,
    applicationEnvelopeBytesToAdministrator: 0, unexpectedAdministratorRequests: 0, peerInboundBytes: 0, peerOutboundBytes: 0 }
  let governed: GovernedNode | undefined
  let control: NodeStateDatabase | undefined
  let agent: Awaited<ReturnType<typeof createDaemonAgentRuntime>> | undefined
  let client: ChronologClient | undefined
  let membershipHandler: ((request: Request) => Promise<Response>) | undefined
  let failure: Error | undefined
  let schemaReady = false
  let dropAppendReply = false
  const peerToken = crypto.randomUUID()
  const sessions = new Map<string, { readonly writer: WritableStreamDefaultWriter<Uint8Array>; close(): Promise<void> }>()
  const checked = () => {
    if (failure !== undefined) throw failure
    if (governed === undefined || agent === undefined || client === undefined) throw new Error('THIN_NATIVE_NOT_STARTED')
    return { governed, agent, client }
  }
  const server = createServer((incoming, outgoing) => {
    outgoing.setHeader('Access-Control-Allow-Origin', '*')
    outgoing.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    outgoing.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    outgoing.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
    outgoing.setHeader('Cache-Control', 'no-store')
    if (incoming.method === 'OPTIONS') { outgoing.writeHead(204); outgoing.end(); return }
    const handle = async () => {
      const url = new URL(incoming.url ?? '/', 'http://localhost')
      if (url.pathname.startsWith('/peer/')) {
        const current = checked()
        const id = /^\/peer\/([a-z0-9-]{36})$/u.exec(url.pathname)?.[1]
        if (id === undefined || url.searchParams.get('token') !== peerToken) { outgoing.writeHead(403); outgoing.end(); return }
        if (incoming.method === 'GET') {
          if (sessions.has(id)) { outgoing.writeHead(409); outgoing.end(); return }
          if (sessions.size >= 8) { outgoing.writeHead(429); outgoing.end(); return }
          outgoing.writeHead(200, { 'Content-Type': 'application/octet-stream' }); outgoing.flushHeaders()
          const input = new TransformStream<Uint8Array, Uint8Array>(), writer = input.writable.getWriter()
          const connection = framePeerStream({ readable: input.readable, writable: new WritableStream<Uint8Array>({
            async write(bytes) { traffic.peerOutboundBytes += bytes.length; await writeStream(outgoing, bytes) },
            close() { outgoing.end() }, abort() { outgoing.destroy() },
          }) })
          let session: Awaited<ReturnType<typeof current.agent.context.connectPeer>> | undefined
          let closed = false
          const close = async () => {
            if (closed) return
            closed = true; sessions.delete(id)
            await Promise.allSettled([connection.close(), writer.abort(), session?.close()])
          }
          sessions.set(id, { writer, close })
          outgoing.once('close', () => { void close() })
          void current.agent.context.connectPeer({ connection }).then(value => {
            session = value
            if (closed) { void value.close(); return }
            void value.completion.catch((error: unknown) => { if (!closed) failure = asError(error) }).finally(close)
          }, (error: unknown) => { if (!closed) failure = asError(error); void close() })
        } else {
          const session = sessions.get(id)
          if (session === undefined) { outgoing.writeHead(410); outgoing.end(); return }
          if (incoming.method === 'POST') {
            const bytes = await boundedBody(incoming)
            traffic.peerInboundBytes += bytes.length
            await session.writer.write(bytes)
          } else if (incoming.method === 'DELETE') await session.close()
          else { outgoing.writeHead(405); outgoing.end(); return }
          outgoing.writeHead(204); outgoing.end()
        }
        return
      }
      const request = await webRequest(incoming)
      if (url.pathname === '/_chronolog/membership') {
        if (membershipHandler === undefined) { outgoing.writeHead(503); outgoing.end(); return }
        const requestBytes = new Uint8Array(await request.clone().arrayBuffer())
        traffic.membershipRequests += 1; traffic.membershipRequestBytes += requestBytes.length
        const response = await membershipHandler(request)
        const bytes = new Uint8Array(await response.arrayBuffer())
        if (response.ok) {
          const input = await verifyMembershipLedgerRequest(requestBytes, checked().governed.descriptor)
          const entries = input.kind === 'read' ? decodeMembershipLedgerResponse(bytes, 'read').entries
            : [decodeMembershipLedgerResponse(bytes, 'append')]
          for (const entry of entries) {
            const record = decodeLedgerRecord(entry.bytes)
            traffic.descriptorTransfers += 1
            if (record.kind === 'candidate') {
              traffic.candidateDescriptorBytes += entry.bytes.length
              // The actual bytes returned by the production handler are the
              // measured boundary. The canonical decoder rejects inline bodies.
              if (record.inlinePayload !== null) throw new Error('THIN_ADMIN_RECEIVED_APPLICATION_BODY')
            } else {
              traffic.inlineControlDescriptorBytes += entry.bytes.length
              traffic.inlineControlEnvelopeBytes += record.inlinePayload.length
            }
          }
          if (input.kind === 'append' && dropAppendReply) { dropAppendReply = false; outgoing.destroy(); return }
        }
        traffic.membershipResponseBytes += bytes.length
        response.headers.forEach((value, name) => outgoing.setHeader(name, value))
        outgoing.writeHead(response.status); outgoing.end(bytes)
        return
      }
      const response = await options.extraRequest?.(request)
      if (response !== null && response !== undefined) {
        response.headers.forEach((value, name) => outgoing.setHeader(name, value))
        outgoing.writeHead(response.status)
        outgoing.end(new Uint8Array(await response.arrayBuffer())); return
      }
      traffic.unexpectedAdministratorRequests += 1
      outgoing.writeHead(404); outgoing.end()
    }
    void handle().catch((error: unknown) => {
      if (!outgoing.headersSent) { outgoing.writeHead(500); outgoing.end(error instanceof Error ? error.stack : String(error)) }
      else outgoing.destroy()
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('THIN_NATIVE_ADDRESS_UNAVAILABLE')
  const base = `http://127.0.0.1:${address.port}`
  const bootstrap = (): ThinMembershipBootstrap => {
    const descriptor = checked().governed.descriptor
    return { genesis: bytesToBase64Url(encodeSignedGenesis(descriptor.genesis)), groupRoute: bytesToBase64Url(descriptor.groupRoute),
      executionManifest: bytesToBase64Url(encodeExecutionManifest(executionManifest)),
      nativeIdentity: bytesToBase64Url(identity.signing.publicKeyBytes), peerUrl: `${base}/peer`, peerToken }
  }
  let closed = false
  return {
    base, membershipUrl: `${base}/_chronolog/membership`, identity, historyId, executionManifestDigest, initialCapabilities,
    traffic: () => structuredClone(traffic), bootstrap,
    async start(input: { readonly genesis: string; readonly groupRoute: string }) {
      if (governed !== undefined) throw new Error('THIN_NATIVE_ALREADY_STARTED')
      const genesis = decodeSignedGenesis(base64UrlToBytes(input.genesis))
      const policy = genesis.manifest.historyPolicy
      if (policy?.kind !== 'coordinated' || policy.historyId !== historyId || policy.authorityPublicKey === undefined ||
          !equalBytes(policy.authorityPublicKey, identity.signing.publicKeyBytes) ||
          !equalBytes(policy.executionManifestDigest, executionManifestDigest) ||
          !equalBytes(genesis.manifest.schemaAdminPublicKey, identity.signing.publicKeyBytes) ||
          equalBytes(genesis.manifest.rootAdminPublicKey, identity.signing.publicKeyBytes)) throw new Error('THIN_NATIVE_CONFIGURATION_MISMATCH')
      control = new NodeStateDatabase(join(options.directory, 'native-control.sqlite'))
      const materializer = await DeterministicMaterializer.open({ path: join(options.directory, 'application.sqlite'),
        executionManifest, rootAdministrator: genesis.manifest.schemaAdminPublicKey })
      governed = await createGovernedNode({ genesis, groupRoute: base64UrlToBytes(input.groupRoute), identity: identity.signing,
        transport, operationStore: store, materialization: createDoltLiteMaterializationRuntime(materializer),
        controlStore: new ControlStore(new SqliteControlStorePersistence(control), { orderPolicy: 'coordinated' }),
        recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
      await governed.start()
      agent = await createDaemonAgentRuntime({ node: governed.node, identity: identity.signing, history: governed.descriptor.history,
        store, transport, activeMembership: () => governed!.activeSnapshot,
        peerLinks: { local: transport.asLink(), attach: (link) => transport.connect(link) } })
      if (agent.authority === null) throw new Error('THIN_NATIVE_AUTHORITY_REQUIRED')
      membershipHandler = createMembershipLedgerHandler({ authority: agent.authority, descriptor: governed.descriptor, sink: transport })
      void agent.run().catch((error: unknown) => { failure = asError(error) })
      client = new ChronologClient({ groupId: bytesToBase64Url(genesis.manifest.groupId),
        transport: new InProcessRpcTransport(new NodeRpcService({ node: governed.node })), unaryRetryAttempts: 1 })
      return bootstrap()
    },
    async publishWorkload(input: { readonly count: number; readonly payloadBytes: number; readonly namespace: string }) {
      if (!Number.isSafeInteger(input.count) || input.count < 1 || input.count > 64 || !Number.isSafeInteger(input.payloadBytes) ||
          input.payloadBytes < 0 || input.payloadBytes > 196_608 || !/^[a-z0-9-]{1,40}$/u.test(input.namespace)) throw new Error('THIN_WORKLOAD_INVALID')
      const { client, governed, agent } = checked()
      const finalize = async (handle: Awaited<ReturnType<typeof client.submit>>) => {
        try {
          const final = await handle.final({ signal: AbortSignal.timeout(20_000) })
          if (final.outcome.type !== 'accepted') throw new Error(`THIN_WORKLOAD_REJECTED: ${JSON.stringify(final.outcome)}`)
          return handle.proposalId
        } finally { handle.dispose() }
      }
      if (!schemaReady) {
        await finalize(await client.submit(program(sqlStatement('CREATE TABLE qualification_payloads(id TEXT PRIMARY KEY, body TEXT NOT NULL)')),
          { operationId: 'thin-schema' }))
        schemaReady = true
      }
      const before = await agent.authority!.head(), proposals: string[] = []
      for (let index = 0; index < input.count; index += 1) {
        const id = `${input.namespace}-${index}`
        proposals.push(await finalize(await client.submit(program(
          sqlStatement('INSERT INTO qualification_payloads(id,body) VALUES(?,?)', [id, 'x'.repeat(input.payloadBytes)]),
          emit('qualification', { id, bytes: input.payloadBytes }),
        ), { operationId: id })))
      }
      await governed.node.waitForIdle()
      const range = await agent.authority!.read({ after: before.position, limit: 128 })
      const candidates = range.entries.map(entry => ({ entry, record: decodeLedgerRecord(entry.bytes) }))
        .filter(value => value.record.kind === 'candidate')
      return { proposals, count: candidates.length, descriptorBytes: candidates.reduce((sum, value) => sum + value.entry.bytes.length, 0),
        detachedEnvelopeBytes: candidates.reduce((sum, value) => sum + value.record.payloadLength, 0),
        finalThrough: governed.node.finalThrough }
    },
    async snapshot() {
      const current = checked(); await current.governed.node.waitForIdle()
      const view = await current.client.readView({ view: 'final' })
      let nativeSchemaAdministrators: number, membershipRootGroupMembers: number
      try {
        const count = async (key: Uint8Array, admin: boolean) => {
          const result = await view.query(`SELECT count(*) FROM chronolog_collective_members WHERE collective_id=? AND member_key=? AND state='active'${admin ? " AND role='admin'" : ''}`,
            [GROUP_COLLECTIVE_ID, key])
          return Number(result.rows[0]?.[0])
        }
        nativeSchemaAdministrators = await count(identity.signing.publicKeyBytes, true)
        membershipRootGroupMembers = await count(current.governed.descriptor.genesis.manifest.rootAdminPublicKey, false)
      } finally { await view.release() }
      return { finalThrough: current.governed.node.finalThrough, membershipRevision: String(current.governed.activeSnapshot.revision),
        availableEpochs: current.governed.governance.cipherRing.epochs().map(String), head: await current.agent.authority!.head(),
        schemaRoles: { nativeSchemaAdministrators, membershipRootGroupMembers }, traffic: structuredClone(traffic) }
    },
    loseNextAppendReply() { dropAppendReply = true },
    assertHealthy() { checked() },
    async close() {
      if (closed) return
      closed = true
      await Promise.all([...sessions.values()].map(session => session.close()))
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
      try { await agent?.close(); await client?.close(); if (governed === undefined) await transport.close(); else await governed.close() }
      finally { control?.close(); store.close() }
    },
  }
}

async function webRequest(request: IncomingMessage): Promise<Request> {
  const headers = new Headers()
  for (const [name, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) for (const entry of value) headers.append(name, entry)
    else if (value !== undefined) headers.set(name, value)
  }
  const method = request.method ?? 'GET'
  return new Request(`http://localhost${request.url ?? '/'}`, { method, headers,
    ...(method === 'GET' || method === 'HEAD' ? {} : { body: (await boundedBody(request)).slice().buffer }) })
}

async function boundedBody(request: IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of request) {
    const bytes = typeof chunk === 'string' ? utf8(chunk) : new Uint8Array(chunk as Uint8Array)
    length += bytes.length
    if (length > 2 * 1024 * 1024) throw new Error('THIN_FIXTURE_BODY_TOO_LARGE')
    chunks.push(bytes)
  }
  const result = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length }
  return result
}

async function writeStream(response: ServerResponse, bytes: Uint8Array): Promise<void> {
  if (!response.write(bytes)) await once(response, 'drain')
}

function asError(error: unknown): Error { return error instanceof Error ? error : new Error('THIN_FIXTURE_FAILED', { cause: error }) }

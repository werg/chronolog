import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir } from 'node:fs/promises'
import { createServer, type IncomingMessage } from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import os from 'node:os'
import { join } from 'node:path'

import { NativeAgentStore, waitForAbortableDelay, type NativeFinalityService } from '@chronolog/agent-service'
import { createMembershipLedgerHandler } from '@chronolog/agent-service/membership-http'
import { decodeSignedGenesis, encodeSignedGenesis, type CapabilityGrant } from '@chronolog/capabilities'
import { ChronologClient } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { createGovernedNode, loadOrCreateEnrollmentIdentity, type GovernedNode } from '@chronolog/node-core'
import { decodeLedgerRecord } from '@chronolog/node-core/ledger'
import { isFinalityClosureRecord } from '@chronolog/node-core/finality'
import type { OrderedRecordEntry, OrderedRecordHead } from '@chronolog/node-core/history'
import { decodeMembershipLedgerResponse, verifyMembershipLedgerRequest } from '@chronolog/node-core/membership'
import {
  GROUP_COLLECTIVE_ID, base64UrlToBytes, bytesToBase64Url, decodeEnvelope, digestExecutionManifest, emit, encodeExecutionManifest, equalBytes, program, sqlStatement, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { createWebRtcOfferHandler, WEBRTC_HTTP_LIMITS, type DataChannelConnection } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'

import { createDaemonAgentRuntime } from '../apps/chronologd/src/agent-runtime.js'

export interface ThinMembershipBootstrap {
  readonly genesis: string
  readonly groupRoute: string
  readonly executionManifest: string
  readonly nativeIdentity: string
  readonly rtcUrl: string
  readonly rtcToken: string
}

export interface ThinMembershipTraffic {
  membershipRequests: number
  membershipRequestBytes: number
  membershipResponseBytes: number
  descriptorTransfers: number
  closureRecordTransfers: number
  closureRecordBytes: number
  candidateDescriptorBytes: number
  inlineControlDescriptorBytes: number
  inlineControlEnvelopeBytes: number
  applicationEnvelopeBytesToAdministrator: number
  unexpectedAdministratorRequests: number
  peerInboundBytes: number
  peerOutboundBytes: number
  rtcSignalingRequests: number
  rtcSignalingRequestBytes: number
  rtcSignalingResponseBytes: number
  rtcSignalingDescriptions: number
  rtcSdpBytes: number
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
  /** Semantic tests may advance shared author/finality time after retained inclusion. Live qualification uses the wall clock. */
  readonly clock?: { now(): number; advanceTo(timestampMs: number): void }
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
    descriptorTransfers: 0, closureRecordTransfers: 0, closureRecordBytes: 0,
    candidateDescriptorBytes: 0, inlineControlDescriptorBytes: 0, inlineControlEnvelopeBytes: 0,
    applicationEnvelopeBytesToAdministrator: 0, unexpectedAdministratorRequests: 0, peerInboundBytes: 0, peerOutboundBytes: 0,
    rtcSignalingRequests: 0, rtcSignalingRequestBytes: 0, rtcSignalingResponseBytes: 0, rtcSignalingDescriptions: 0, rtcSdpBytes: 0 }
  let governed: GovernedNode | undefined
  let control: NodeStateDatabase | undefined
  let agent: Awaited<ReturnType<typeof createDaemonAgentRuntime>> | undefined
  let client: ChronologClient | undefined
  let membershipHandler: ((request: Request) => Promise<Response>) | undefined
  let failure: Error | undefined
  let firstFailure: { source: 'peer' | 'agent'; observedAt: string; name: string; message: string; stack: string | null } | null = null
  const retainFailure = (error: unknown, source: 'peer' | 'agent'): void => {
    if (failure !== undefined) return
    failure = asError(error)
    firstFailure = { source, observedAt: new Date().toISOString(), name: failure.name, message: failure.message, stack: failure.stack ?? null }
    process.stderr.write(`Thin native ${source} failure: ${failure.stack ?? failure.message}\n`)
  }
  let schemaReady = false
  let dropAppendReply = false
  const rtcToken = crypto.randomUUID(), connections = new Set<DataChannelConnection>()
  const enumerate = os.networkInterfaces
  let restrictedInterfaceEnumeration = false
  try { enumerate() } catch {
    // Qualification binds loopback explicitly; this sandbox denies optional
    // interface enumeration. Production adapter behavior remains unchanged.
    restrictedInterfaceEnumeration = true; os.networkInterfaces = () => ({}); syncBuiltinESMExports()
  }
  const measuredTraffic = (): ThinMembershipTraffic => {
    const value = { ...traffic }
    for (const connection of connections) {
      value.peerInboundBytes += connection.stats.receivedBytes
      value.peerOutboundBytes += connection.stats.sentBytes
    }
    return value
  }
  const checked = () => {
    if (failure !== undefined) throw failure
    if (governed === undefined || agent === undefined || client === undefined) throw new Error('THIN_NATIVE_NOT_STARTED')
    return { governed, agent, client }
  }
  const advancedCandidates = new Set<string>()
  const advanceAfterInclusion = async (envelope: Uint8Array, signal: AbortSignal): Promise<void> => {
    if (options.clock === undefined) throw new Error('THIN_CONTROLLED_CLOCK_REQUIRED')
    if (decodeEnvelope(envelope).messageType !== 'candidate') throw new Error('THIN_CANDIDATE_REQUIRED')
    const hash = createHash('sha256').update(envelope).digest('hex')
    if (advancedCandidates.has(hash)) return
    for (;;) {
      signal.throwIfAborted()
      const current = checked()
      const receipts = await current.agent.finality!.read({ limit: 256 })
      if (receipts.hasMore) throw new Error('THIN_FIXTURE_RECEIPT_LIMIT')
      if (receipts.entries.some(entry => !isFinalityClosureRecord(entry.bytes) && decodeLedgerRecord(entry.bytes).payloadHash === hash)) {
        const next = options.clock.now() + Number(current.governed.descriptor.genesis.manifest.clockPolicy.cutoffLagMs) + 1
        if (!Number.isSafeInteger(next)) throw new Error('THIN_CLOCK_EXHAUSTED')
        options.clock.advanceTo(next)
        advancedCandidates.add(hash)
        return
      }
      await waitForAbortableDelay(5, signal)
    }
  }
  const server = createServer((incoming, outgoing) => {
    outgoing.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
    outgoing.setHeader('Cache-Control', 'no-store')
    const handle = async () => {
      const url = new URL(incoming.url ?? '/', 'http://localhost')
      if (url.pathname === '/_chronolog/rtc') {
        const request = await webRequest(incoming, WEBRTC_HTTP_LIMITS.messageBytes)
        const requestBytes = new Uint8Array(await request.clone().arrayBuffer())
        traffic.rtcSignalingRequests++; traffic.rtcSignalingRequestBytes += requestBytes.length
        const response = await introduction.fetch(request), bytes = new Uint8Array(await response.arrayBuffer())
        traffic.rtcSignalingResponseBytes += bytes.length
        if (request.method === 'POST' && response.ok) {
          const offer = JSON.parse(new TextDecoder().decode(requestBytes)) as { description: { sdp: string } }
          const answer = JSON.parse(new TextDecoder().decode(bytes)) as { description: { sdp: string } }
          traffic.rtcSignalingDescriptions += 2
          traffic.rtcSdpBytes += new TextEncoder().encode(offer.description.sdp).length + new TextEncoder().encode(answer.description.sdp).length
        }
        response.headers.forEach((value, name) => outgoing.setHeader(name, value))
        outgoing.writeHead(response.status); outgoing.end(bytes); return
      }
      outgoing.setHeader('Access-Control-Allow-Origin', '*')
      outgoing.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      outgoing.setHeader('Access-Control-Allow-Headers', 'Content-Type')
      if (incoming.method === 'OPTIONS') { outgoing.writeHead(204); outgoing.end(); return }
      const request = await webRequest(incoming)
      if (url.pathname === '/_chronolog/membership') {
        if (membershipHandler === undefined) { outgoing.writeHead(503); outgoing.end(); return }
        const requestBytes = new Uint8Array(await request.clone().arrayBuffer())
        traffic.membershipRequests += 1; traffic.membershipRequestBytes += requestBytes.length
        const response = await membershipHandler(request)
        const bytes = new Uint8Array(await response.arrayBuffer())
        if (response.ok) {
          const input = await verifyMembershipLedgerRequest(requestBytes, checked().governed.descriptor)
          const page = input.kind === 'read' ? decodeMembershipLedgerResponse(bytes, 'read') : null
          const entries = page === null ? [decodeMembershipLedgerResponse(bytes, 'append')]
            : [...page.entries.map(control => control.entry), ...(page.checkpoint === null ? [] : [page.checkpoint])]
          for (const entry of entries) {
            if (isFinalityClosureRecord(entry.bytes)) {
              traffic.closureRecordTransfers += 1
              traffic.closureRecordBytes += entry.bytes.length
              continue
            }
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
  const introduction = createWebRtcOfferHandler({ allowedOrigins: [base], maxConnections: 8,
    authorize: request => agent !== undefined && request.headers.get('Authorization') === `Bearer ${rtcToken}`,
    createPeerConnection: configuration => createNativePeerConnection(configuration,
      { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }), configuration: { iceServers: [] },
    onError(error) {
      const value = asError(error)
      if (!['WEBRTC_CONNECTION_ENDED', 'WEBRTC_CONNECTION_CLOSED'].includes(value.message)) retainFailure(value, 'peer')
    },
    async accept(connection) {
      connections.add(connection)
      const retire = (): void => {
        if (!connections.delete(connection)) return
        traffic.peerInboundBytes += connection.stats.receivedBytes; traffic.peerOutboundBytes += connection.stats.sentBytes
      }
      try {
        const session = await checked().agent.context.connectPeer({ connection })
        void session.completion.finally(retire).catch(() => undefined)
        return { completion: session.completion, async close() { try { await session.close() } finally { retire() } } }
      } catch (error) { retire(); throw error }
    } })
  const bootstrap = (): ThinMembershipBootstrap => {
    const descriptor = checked().governed.descriptor
    return { genesis: bytesToBase64Url(encodeSignedGenesis(descriptor.genesis)), groupRoute: bytesToBase64Url(descriptor.groupRoute),
      executionManifest: bytesToBase64Url(encodeExecutionManifest(executionManifest)),
      nativeIdentity: bytesToBase64Url(identity.signing.publicKeyBytes), rtcUrl: `${base}/_chronolog/rtc`, rtcToken }
  }
  let closed = false
  return {
    base, membershipUrl: `${base}/_chronolog/membership`, identity, historyId, executionManifestDigest, initialCapabilities,
    traffic: measuredTraffic, bootstrap, advanceAfterInclusion,
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
        ...(options.clock === undefined ? {} : { clock: options.clock }),
        controlStore: new ControlStore(new SqliteControlStorePersistence(control), { orderPolicy: 'coordinated' }),
        recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
      await governed.start()
      agent = await createDaemonAgentRuntime({ node: governed.node, identity: identity.signing, descriptor: governed.descriptor,
        store, transport, activeMembership: () => governed!.activeSnapshot,
        ...(options.clock === undefined ? {} : { finalityClock: () => options.clock!.now() }),
        peerLinks: { local: transport.asLink(), attach: (link) => transport.connect(link) } })
      if (agent.finality === null) throw new Error('THIN_NATIVE_FINALITY_REQUIRED')
      membershipHandler = createMembershipLedgerHandler({ finality: agent.finality, descriptor: governed.descriptor, sink: transport })
      void agent.run().catch((error: unknown) => { retainFailure(error, 'agent') })
      client = new ChronologClient({ groupId: bytesToBase64Url(genesis.manifest.groupId),
        transport: new InProcessRpcTransport(new NodeRpcService({ node: governed.node, signals: agent.context.signals })), unaryRetryAttempts: 1 })
      return bootstrap()
    },
    async publishWorkload(input: { readonly count: number; readonly payloadBytes: number; readonly namespace: string }) {
      if (!Number.isSafeInteger(input.count) || input.count < 1 || input.count > 64 || !Number.isSafeInteger(input.payloadBytes) ||
          input.payloadBytes < 0 || input.payloadBytes > 196_608 || !/^[a-z0-9-]{1,40}$/u.test(input.namespace)) throw new Error('THIN_WORKLOAD_INVALID')
      const { client, governed, agent } = checked()
      const finalize = async (handle: Awaited<ReturnType<typeof client.submit>>) => {
        try {
          const signal = AbortSignal.timeout(20_000)
          if (options.clock !== undefined) {
            // This fixture submits one native operation at a time. The one
            // new exact envelope must reach the actual service before time
            // can close; payload size or host load cannot consume its window.
            const pending = (await transport.history()).filter(record => record.author === transport.identity &&
              decodeEnvelope(record.payload).messageType === 'candidate' &&
              !advancedCandidates.has(createHash('sha256').update(record.payload).digest('hex')))
            if (pending.length !== 1) throw new Error('THIN_FIXTURE_CANDIDATE_COUNT')
            await advanceAfterInclusion(pending[0]!.payload, signal)
          }
          const final = await handle.final({ signal })
          if (final.outcome.type !== 'accepted') throw new Error(`THIN_WORKLOAD_REJECTED: ${JSON.stringify(final.outcome)}`)
          return handle.proposalId
        } finally { handle.dispose() }
      }
      if (!schemaReady) {
        await finalize(await client.submit(program(sqlStatement('CREATE TABLE qualification_payloads(id TEXT PRIMARY KEY, body TEXT NOT NULL)')),
          { operationId: 'thin-schema' }))
        schemaReady = true
      }
      const before = await agent.finality!.head(), proposals: string[] = []
      for (let index = 0; index < input.count; index += 1) {
        const id = `${input.namespace}-${index}`
        proposals.push(await finalize(await client.submit(program(
          sqlStatement('INSERT INTO qualification_payloads(id,body) VALUES(?,?)', [id, 'x'.repeat(input.payloadBytes)]),
          emit('qualification', { id, bytes: input.payloadBytes }),
        ), { operationId: id })))
      }
      await governed.node.waitForIdle()
      const through = await agent.finality!.head()
      const retained = await collectRetainedRange(agent.finality!, before, through)
      const candidates = retained.filter(entry => !isFinalityClosureRecord(entry.bytes))
        .map(entry => ({ entry, record: decodeLedgerRecord(entry.bytes) }))
        .filter(value => value.record.kind === 'candidate')
      if (candidates.length !== input.count) throw new Error('THIN_WORKLOAD_RECEIPT_COUNT_MISMATCH')
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
        availableEpochs: current.governed.governance.cipherRing.epochs().map(String), head: await current.agent.finality!.head(),
        schemaRoles: { nativeSchemaAdministrators, membershipRootGroupMembers }, traffic: measuredTraffic(),
        rtc: { ...introduction.stats, transport: 'webrtc', nativeImplementation: 'werift', restrictedInterfaceEnumeration,
          byteBoundary: 'Logical authenticated peer frame payload; excludes framing headers/credit and SCTP/DTLS/IP overhead.' } }
    },
    // Failure evidence must remain available when checked() rejects. Observe
    // cached frontiers and counters without requesting SQL replay or a view.
    diagnostics() {
      return { failure: firstFailure === null ? null : { ...firstFailure }, started: governed !== undefined,
        finalThrough: governed?.node.finalThrough ?? null,
        membershipRevision: governed === undefined ? null : String(governed.activeSnapshot.revision),
        availableEpochs: governed?.governance.cipherRing.epochs().map(String) ?? [],
        traffic: measuredTraffic(), rtc: { ...introduction.stats, transport: 'webrtc', nativeImplementation: 'werift' } }
    },
    loseNextAppendReply() { dropAppendReply = true },
    assertHealthy() { checked() },
    async close() {
      if (closed) return
      closed = true
      await introduction.close()
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
      try { await agent?.close(); await client?.close(); if (governed === undefined) await transport.close(); else await governed.close() }
      finally {
        control?.close(); store.close()
        if (restrictedInterfaceEnumeration) { os.networkInterfaces = enumerate; syncBuiltinESMExports() }
      }
    },
  }
}

/** Collect one fixed retained interval; later closure ticks cannot extend the measurement. */
export async function collectRetainedRange(source: Pick<NativeFinalityService, 'read'>,
  after: OrderedRecordHead, through: OrderedRecordHead): Promise<readonly OrderedRecordEntry[]> {
  let cursor = { ...after }
  const target = { ...through }, retained: OrderedRecordEntry[] = []
  const validHead = (head: OrderedRecordHead): boolean => Number.isSafeInteger(head.position) && head.position >= 0 &&
    typeof head.historyId === 'string' && head.historyId.length > 0 && typeof head.root === 'string' && head.root.length > 0
  if (!validHead(cursor) || !validHead(target) || cursor.historyId !== target.historyId || cursor.position > target.position) {
    throw new Error('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
  }
  const expectedLength = target.position - cursor.position
  while (cursor.position < target.position) {
    const limit = Math.min(128, target.position - cursor.position)
    const page = await source.read({ after: cursor.position, limit })
    if (!validHead(page.head) || page.head.historyId !== target.historyId || page.head.position < target.position || page.entries.length > limit) {
      throw new Error('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
    }
    if (page.entries.length === 0) throw new Error('THIN_WORKLOAD_RANGE_NO_PROGRESS')
    for (const entry of page.entries) {
      if (entry.historyId !== target.historyId || entry.position !== cursor.position + 1 || entry.position > target.position ||
          entry.previousRoot !== cursor.root || typeof entry.root !== 'string' || entry.root.length === 0) {
        throw new Error('THIN_WORKLOAD_RANGE_DISCONTINUOUS')
      }
      retained.push(entry)
      cursor = { historyId: entry.historyId, position: entry.position, root: entry.root }
    }
    if (page.hasMore !== (cursor.position < page.head.position) || cursor.position === page.head.position && cursor.root !== page.head.root) {
      throw new Error('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
    }
  }
  if (cursor.root !== target.root || retained.length !== expectedLength) throw new Error('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
  return retained
}

async function webRequest(request: IncomingMessage, maximum?: number): Promise<Request> {
  const headers = new Headers()
  for (const [name, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) for (const entry of value) headers.append(name, entry)
    else if (value !== undefined) headers.set(name, value)
  }
  const method = request.method ?? 'GET'
  return new Request(`http://localhost${request.url ?? '/'}`, { method, headers,
    ...(method === 'GET' || method === 'HEAD' ? {} : { body: (await boundedBody(request, maximum)).slice().buffer }) })
}

async function boundedBody(request: IncomingMessage, maximum = 2 * 1024 * 1024): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of request) {
    const bytes = typeof chunk === 'string' ? utf8(chunk) : new Uint8Array(chunk as Uint8Array)
    length += bytes.length
    if (length > maximum) throw new Error('THIN_FIXTURE_BODY_TOO_LARGE')
    chunks.push(bytes)
  }
  const result = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length }
  return result
}

function asError(error: unknown): Error { return error instanceof Error ? error : new Error('THIN_FIXTURE_FAILED', { cause: error }) }

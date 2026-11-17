import { once } from 'node:events'
import { mkdir } from 'node:fs/promises'
import { createServer, type IncomingMessage } from 'node:http'
import { join } from 'node:path'

import { createGovernedPeerService, type GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { decodeSignedGenesis, encodeGenesisManifest, encodeSignedGenesis, signGenesis } from '@chronolog/capabilities'
import { ChronologClient, OWNER_FOR_KEY_SQL, type TransactionHandle } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import {
  createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer,
} from '@chronolog/materializer-doltlite'
import {
  createEnrollmentService, createGovernedNode, decodeFinalityClosureRecord, evaluateFinalitySnapshot, isFinalityClosureRecord, loadOrCreateEnrollmentIdentity, Mutex,
  type EnrollmentRole, type GovernedNode,
} from '@chronolog/node-core'
import {
  ReferenceRecordLog,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry,
} from '@chronolog/node-core/history'
import {
  base64UrlToBytes, bytesToBase64Url, digestExecutionManifest, DOMAINS, encodeExecutionManifest,
  equalBytes, hashDomain, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import {
  authorizeThroughRecordLog, createCertificateFetcher, TendrillerTransport, withTendrillerFinality,
  type FinalityHttp,
} from '@chronolog/transport-tendriller'
import {
  createRecordLogClient, decodeRecord, encodeRecord, RECORD_LOG_FORMAT, RECORD_LOG_LIMITS, recordGenesisRoot,
} from '@tendriller/core/records'

import { SqliteOperationStore } from '../apps/chronologd/src/operation-store.js'
import type { BrowserBridgeBootstrap } from '../test/browser/bridge-contract.js'
import { createHttpPeerFixture } from './lib/http-peer-fixture.js'

/**
 * Native half of the browser acceptance gate. All proposals, capabilities and
 * keys are signed by real peers; only the retained-log HTTP host is a fixture.
 * The host speaks the pinned public SDK contract and signs its own durable head.
 */
export async function createBrowserBridgeFixture(options: { readonly rootDirectory: string }) {
  await mkdir(options.rootDirectory, { recursive: true })
  const state = new NodeStateDatabase(join(options.rootDirectory, 'native-control.db'))
  const logState = new NodeStateDatabase(join(options.rootDirectory, 'reference-log.db'))
  const operations = new SqliteOperationStore(state.database)
  const administrator = await loadOrCreateEnrollmentIdentity(operations, 'bridge-administrator')
  const authority = await loadOrCreateEnrollmentIdentity(operations, 'bridge-authority')
  const executionManifest = createDoltLiteExecutionManifest()
  const executionManifestDigest = await digestExecutionManifest(executionManifest)
  const administratorFeed = feedIdFromPublicKey(administrator.signing.publicKeyBytes)
  const groupRoute = new Uint8Array(32).fill(102)
  let savedGenesis = await operations.get('qualification/genesis')
  if (savedGenesis === null) {
    const common = { subjectId: administrator.signing.publicKeyBytes, signingPublicKey: administrator.signing.publicKeyBytes,
      transportAuthor: administratorFeed, validFromRevision: 0n }
    const genesis = await signGenesis({
      groupId: crypto.getRandomValues(new Uint8Array(32)), schemaId: executionManifestDigest,
      rootAdminPublicKey: administrator.signing.publicKeyBytes, schemaAdminPublicKey: administrator.signing.publicKeyBytes, capabilityLogFeed: utf8(administratorFeed),
      initialCapabilities: [
        { ...common, role: 'writer', program: { sql: true, topics: [], signals: [] } },
        { ...common, role: 'reader', hpkePublicKey: administrator.reader.publicKeyBytes },
      ],
      historyPolicy: { kind: 'coordinated', executionManifestDigest,
        historyId: `h_${crypto.randomUUID().replaceAll('-', '')}`, authorityPublicKey: authority.signing.publicKeyBytes },
      validationPolicies: [{ version: 1n, minimumValidators: 1n }],
      clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
      resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
      encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
    }, administrator.signing.privateKey)
    savedGenesis = encodeSignedGenesis(genesis)
    await operations.put('qualification/genesis', savedGenesis)
  }
  const genesis = decodeSignedGenesis(savedGenesis)
  const history = genesis.manifest.historyPolicy
  if (history?.kind !== 'coordinated' || history.historyId === undefined || history.authorityPublicKey === undefined ||
      !equalBytes(history.executionManifestDigest, executionManifestDigest) ||
      !equalBytes(history.authorityPublicKey, authority.signing.publicKeyBytes)) throw new Error('BRIDGE_FIXTURE_CONFIGURATION_MISMATCH')
  const log = await ReferenceRecordLog.open(history.historyId, new SqliteOperationStore(logState.database))
  const appendMutex = new Mutex()
  const token = crypto.randomUUID()
  let governed: GovernedNode | undefined
  let peers: GovernedPeerService | undefined
  const peerToken = crypto.randomUUID()
  const peerHttp = createHttpPeerFixture({ token: peerToken, async connect(connection) {
    if (peers === undefined) { await connection.close(); throw new Error('BRIDGE_NATIVE_NOT_STARTED') }
    return peers.connectPeer({ connection })
  } })
  let online = true
  let loseAppendResponse = false
  let lostAppend: { readonly position: number; readonly recordId: string } | undefined
  const droppedRequests = new WeakSet<Request>()
  const requests = { records: 0, certificates: 0 }
  const wire = (entry: OrderedRecordEntry) => ({
    historyId: entry.historyId, position: entry.position, recordId: entry.recordId,
    previousRoot: entry.previousRoot, root: entry.root, record: encodeRecord(entry.bytes),
  })
  const head = async () => {
    const entries = await log.read()
    return { entries, head: { historyId: log.historyId, position: entries.length,
      root: entries.at(-1)?.root ?? await recordGenesisRoot(log.historyId),
      bytes: entries.reduce((total, entry) => total + entry.bytes.byteLength, 0) } }
  }
  const engine = {
    async fetch(request: Request, _env: object, _context: object): Promise<Response> {
      if (!online) return Response.json({ code: 'BRIDGE_HUB_OFFLINE' }, { status: 503 })
      if (request.headers.get('Authorization') !== `Bearer ${token}`) return new Response(null, { status: 403 })
      const url = new URL(request.url)
      if (url.pathname !== '/records' && url.pathname !== '/records/entries') return new Response(null, { status: 404 })
      const requestedHistory = url.searchParams.get('historyId')
      if (requestedHistory !== null && requestedHistory !== log.historyId) return new Response(null, { status: 409 })
      if (request.method === 'POST' && url.pathname === '/records/entries') {
        const input = await request.json() as { historyId?: string; record?: string; expectedHead?: { position: number; root: string } }
        if (input.historyId !== log.historyId || typeof input.record !== 'string') return new Response(null, { status: 400 })
        const bytes = decodeRecord(input.record)
        const entry = await appendMutex.run(async () => {
          const current = await log.head()
          if (input.expectedHead !== undefined && (input.expectedHead.position !== current.position || input.expectedHead.root !== current.root)) return null
          return log.append(bytes)
        })
        if (entry === null) return Response.json({ code: 'record_head_conflict' }, { status: 409 })
        if (loseAppendResponse) {
          loseAppendResponse = false
          lostAppend = { position: entry.position, recordId: entry.recordId }
          droppedRequests.add(request)
        }
        return Response.json(wire(entry))
      }
      const captured = await head()
      if (request.method === 'GET' && url.pathname === '/records/entries') {
        const after = Number(url.searchParams.get('after'))
        const limit = Number(url.searchParams.get('limit') ?? RECORD_LOG_LIMITS.readEntries)
        if (!Number.isSafeInteger(after) || after < 0 || after > captured.entries.length ||
            !Number.isSafeInteger(limit) || limit < 1 || limit > RECORD_LOG_LIMITS.readEntries) {
          return new Response(null, { status: 400 })
        }
        const entries: ReturnType<typeof wire>[] = []
        let bytes = 0
        for (const entry of captured.entries.slice(after, after + limit)) {
          const encoded = wire(entry)
          const size = new TextEncoder().encode(JSON.stringify(encoded)).byteLength
          if (bytes + size > RECORD_LOG_LIMITS.readBytes) break
          entries.push(encoded)
          bytes += size
        }
        return Response.json({ historyId: log.historyId, after, cursor: entries.at(-1)?.position ?? after, entries, head: captured.head })
      }
      if (url.pathname === '/records' && (request.method === 'GET' || request.method === 'POST')) {
        return Response.json({ descriptor: { historyId: log.historyId, format: RECORD_LOG_FORMAT, limits: RECORD_LOG_LIMITS }, head: captured.head })
      }
      return new Response(null, { status: 405 })
    },
  }
  let dispatch = (request: Request) => engine.fetch(request, {}, {})
  const server = createServer((incoming, outgoing) => {
    outgoing.setHeader('Access-Control-Allow-Origin', '*')
    outgoing.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type')
    outgoing.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    outgoing.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
    outgoing.setHeader('Cache-Control', 'no-store')
    if (incoming.method === 'OPTIONS') { outgoing.writeHead(204); outgoing.end(); return }
    const respond = async () => {
      if (await peerHttp.handle(incoming, outgoing)) return
      const request = await webRequest(incoming)
      const path = new URL(request.url).pathname
      if (path === '/_chronolog/certificate') requests.certificates += 1
      else requests.records += 1
      const response = await dispatch(request)
      // The durable append completed, but the client never receives its reply.
      if (droppedRequests.has(request)) { outgoing.destroy(); return }
      outgoing.statusCode = response.status
      response.headers.forEach((value, key) => outgoing.setHeader(key, value))
      outgoing.end(new Uint8Array(await response.arrayBuffer()))
    }
    void respond().catch((error: unknown) => {
      outgoing.statusCode = 500
      outgoing.end(error instanceof Error ? error.message : String(error))
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('BRIDGE_FIXTURE_ADDRESS_UNAVAILABLE')
  const hubUrl = `http://127.0.0.1:${address.port}`
  const headers = () => ({ Authorization: `Bearer ${token}` })
  const records = createRecordLogClient({ base: hubUrl, headers })
  const local = new PortableFeedTransport({
    store: await DurableFeedStore.open(operations, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(administratorFeed, administrator.signing.privateKey),
  })
  const materializer = await DeterministicMaterializer.open({ path: join(options.rootDirectory, 'native-application.db'),
    executionManifest, rootAdministrator: genesis.manifest.schemaAdminPublicKey, checkpointEvery: 1 })
  let client: ChronologClient | undefined
  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    try {
      await peerHttp.close()
      await peers?.close()
      await client?.close()
      if (governed !== undefined) await governed.close()
      else { materializer.close(); await local.close() }
    } finally {
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)))
      state.close()
      logState.close()
    }
  }
  try {
    // The signed descriptor constructor verifies all history bindings before use.
    const configuration: CoordinatedHistoryConfiguration = {
      kind: 'coordinated', historyId: history.historyId, authorityPublicKey: history.authorityPublicKey,
      groupId: genesis.manifest.groupId, executionManifestDigest,
      genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)),
    }
    const http: FinalityHttp<Request, Response> = {
      request: (url, init) => new Request(url, init), response: (body, init) => new Response(body, init),
    }
    const handler = await withTendrillerFinality(engine, { descriptor: { genesis, groupRoute, history: configuration }, identity: authority.signing, records, http,
      authorize: authorizeThroughRecordLog(engine, { base: hubUrl, historyId: log.historyId, http }) })
    dispatch = (request) => handler.fetch(request, {}, {})
    const adapter = new TendrillerTransport({ local, records, configuration, groupRoute, watch: false,
      certificate: createCertificateFetcher({ url: `${hubUrl}/_chronolog/certificate`, headers }) })
    governed = await createGovernedNode({ genesis, groupRoute, identity: administrator.signing, transport: adapter,
      operationStore: operations, controlStore: new ControlStore(new SqliteControlStorePersistence(state)),
      materialization: createDoltLiteMaterializationRuntime(materializer),
      recipient: { id: administrator.signing.publicKeyBytes, privateKey: administrator.reader.privateKey },
    })
    const root = governed
    peers = await createGovernedPeerService({ identity: administrator.signing, groupId: root.descriptor.history.groupId,
      activeMembership: () => root.activeSnapshot, local: local.asLink(), attach: link => local.connect(link) })
    const enrollment = createEnrollmentService({ descriptor: root.descriptor, store: operations, identity: administrator.signing,
      readerPublicKey: administrator.reader.publicKeyBytes, transportAuthor: adapter.identity,
      governance: root.governance, activeMembership: () => root.activeSnapshot, issuer: root.enrollmentIssuer!,
      connected: () => online, executionManifestDigest,
      isFinalTargetApplied: (target) => root.node.isFinalTargetApplied(target.frontier) })
    client = new ChronologClient({ groupId: bytesToBase64Url(genesis.manifest.groupId),
      transport: new InProcessRpcTransport(new NodeRpcService({ node: root.node, enrollment, signals: peers.signals })), unaryRetryAttempts: 1 })
    const native = client
    const syncEvidence = async () => {
      const throughMs = BigInt(Date.now())
      const deadline = Date.now() + 10_000
      for (;;) {
        peerHttp.assertHealthy()
        await adapter.catchUp()
        await root.node.waitForIdle()
        const status = await root.node.status()
        if (status.lastError !== undefined) throw new Error(`BRIDGE_NATIVE_SYNC_FAILED: ${status.lastError}`)
        const retained = await log.read()
        const marker = retained.at(-1)
        if (marker === undefined || !isFinalityClosureRecord(marker.bytes)) throw new Error('BRIDGE_NATIVE_CLOSURE_MISSING')
        const closure = decodeFinalityClosureRecord(marker.bytes)
        if (root.node.finalThrough < closure.includedHead.position) throw new Error('BRIDGE_NATIVE_PREFIX_INCOMPLETE')
        const proof = await evaluateFinalitySnapshot(configuration, retained)
        const allowance = genesis.manifest.clockPolicy.maxFutureSkewMs + genesis.manifest.clockPolicy.cutoffLagMs
        const horizon = proof.records.reduce((last, record) => record.closureBoundary === null ? last :
          record.closureBoundary.closedThroughMs + allowance > last ? record.closureBoundary.closedThroughMs + allowance : last, -1n)
        const target = throughMs < horizon ? throughMs : horizon
        if (closure.closedThroughMs >= target) return
        if (Date.now() >= deadline) throw new Error('BRIDGE_NATIVE_CLOSURE_TIMEOUT')
        await new Promise(resolve => setTimeout(resolve, Math.min(Number(target - closure.closedThroughMs) + 1, 1_000)))
      }
    }
    const finalize = async (handle: TransactionHandle) => {
      try {
        await syncEvidence()
        const outcome = await handle.final({ signal: AbortSignal.timeout(10_000) })
        if (outcome.outcome.type !== 'accepted') throw new Error(`BRIDGE_SETUP_REJECTED: ${JSON.stringify(outcome.outcome)}`)
        return handle.transactionId
      } finally { handle.dispose() }
    }
    await root.start()
    await syncEvidence()
    const schemaId = await finalize(await native.transaction([
      'CREATE TABLE tasks (id INTEGER PRIMARY KEY, claimed_by TEXT) STRICT',
      'CREATE TABLE history (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT',
      "INSERT INTO history (id, value) VALUES (1, 'before-enrollment')",
    ], { operationId: 'bridge-schema' }))
    const bootstrap: BrowserBridgeBootstrap = {
      hubUrl, token, genesis: bytesToBase64Url(savedGenesis), groupRoute: bytesToBase64Url(groupRoute),
      executionManifest: bytesToBase64Url(encodeExecutionManifest(executionManifest)),
      rootIdentity: bytesToBase64Url(administrator.signing.publicKeyBytes),
      nativeIdentity: bytesToBase64Url(administrator.signing.publicKeyBytes), peerUrl: `${hubUrl}/peer`, peerToken,
    }
    const snapshot = async (transactionIds: readonly string[] = []) => {
      await root.node.waitForIdle()
      return {
        identity: bootstrap.rootIdentity, hash: materializer.databaseContentHash,
        finalOrderLength: root.node.finalOrderLength, finalThrough: root.node.finalThrough,
        rows: root.node.localSql('SELECT id, claimed_by FROM tasks ORDER BY id', [], { view: 'final' }).rows,
        outcomes: await Promise.all(transactionIds.map((transactionId) => native.getTransactionOutcome(transactionId))),
        logPosition: (await log.head()).position,
        includedRecordCount: (await log.read()).filter(entry => !isFinalityClosureRecord(entry.bytes)).length,
      }
    }
    return {
      bootstrap, descriptor: root.descriptor,
      async approveEnrollment(signedRequest: string, operationId: string, roles: readonly EnrollmentRole[] = ['reader', 'writer']) {
        await syncEvidence()
        const approval = await native.enrollment.approveRequest({ operationId, signedRequest, roles, grantFullHistory: true,
          ...(roles.includes('writer') ? { writerProgram: { sql: true, topics: [], signals: [] } } : {}) })
        await syncEvidence()
        return approval
      },
      async prepareTask(browserIdentity: string) {
        const team = await native.ownership.createTeam({ invite: [base64UrlToBytes(browserIdentity)] }, { operationId: 'bridge-team' })
        const teamTransaction = await finalize(team.handle)
        const taskTransaction = await finalize(await native.transaction([{
          sql: `INSERT INTO tasks (id, chronolog_owner) VALUES (1, ${OWNER_FOR_KEY_SQL})`, params: [team.id],
        }], { operationId: 'bridge-task' }))
        return { teamId: bytesToBase64Url(team.id), transactionIds: [schemaId, teamTransaction, taskTransaction] }
      },
      async claimTask(operationId = 'native-claim') {
        const handle = await native.transaction([
          "SELECT chronolog_assert((SELECT claimed_by IS NULL FROM tasks WHERE id = 1), 'already_claimed')",
          { sql: 'UPDATE tasks SET claimed_by = ? WHERE id = 1', params: ['native'] },
        ], { operationId: operationId })
        try { return handle.transactionId } finally { handle.dispose() }
      },
      async sync(transactionIds: readonly string[] = []) { await syncEvidence(); return snapshot(transactionIds) },
      snapshot,
      loseNextAppendResponse() { loseAppendResponse = true; lostAppend = undefined },
      lastLostAppend() { return lostAppend },
      cutHub() { online = false },
      restoreHub() { online = true },
      hubRequests() { return { ...requests } },
      async exportPeer() {
        const evidence: string[] = []
        for await (const batch of local.evidenceHistory()) evidence.push(...batch.map((item) => bytesToBase64Url(item.bytes)))
        return { identity: local.identity,
          records: (await local.asLink().read(local.identity, 0n, 4_096)).map(bytesToBase64Url),
          evidence }
      },
      close,
    }
  } catch (error) { await close(); throw error }
}

async function webRequest(incoming: IncomingMessage): Promise<Request> {
  const headers = new Headers()
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value)
  }
  const method = incoming.method ?? 'GET'
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of incoming) {
    const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : Uint8Array.from(chunk as Uint8Array)
    size += bytes.length
    if (size > 1024 * 1024) throw new Error('BRIDGE_HTTP_BODY_TOO_LARGE')
    chunks.push(bytes)
  }
  const body = new Uint8Array(size)
  let offset = 0
  for (const bytes of chunks) { body.set(bytes, offset); offset += bytes.length }
  return new Request(`http://${incoming.headers.host ?? '127.0.0.1'}${incoming.url ?? '/'}`, {
    method, headers, ...(size === 0 ? {} : { body: body.buffer }),
  })
}

export type BrowserBridgeFixture = Awaited<ReturnType<typeof createBrowserBridgeFixture>>

import { createLedgerRecord } from '@chronolog/node-core/ledger'
import { Mutex, membershipDescriptor, provisionMembership } from '@chronolog/node-core/browser'
import { signGenesis } from '@chronolog/capabilities'
import { evaluateFinalitySnapshot } from '@chronolog/node-core/finality'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'

import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  createRecordLogClient, decodeRecord, encodeRecord, RECORD_LOG_FORMAT, RECORD_LOG_LIMITS,
  type RecordLogEntry,
} from '@tendriller/core/records'
import {
  SignedInclusionFinalityProvider, decodeOrderingEvidence, ReferenceRecordLog, verifyPrefixCertificate,
  type OrderedRecordEntry,
} from '@chronolog/node-core/history'
import { encodeEnvelope, generateEd25519KeyPair, type EnvelopeMessageType } from '@chronolog/protocol'
import {
  connectInProcess, DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner,
  type AtomicBytesStore,
} from '@chronolog/records'

import { authorizeThroughRecordLog, createCertificateFetcher, withTendrillerFinality, type FinalityHttp } from './finality-service.js'
import { TendrillerTransport } from './transport.js'

const historyId = 'h_00112233445566778899aabbccddeeff'
const groupRoute = new Uint8Array(32).fill(7)
const http: FinalityHttp<Request, Response> = {
  request: (url, init) => new Request(url, init), response: (body, init) => new Response(body, init),
}
const closers: Array<() => Promise<void>> = []
afterEach(async () => {
  vi.useRealTimers()
  for (const close of closers.splice(0).reverse()) await close()
})
function storage(): AtomicBytesStore {
  const values = new Map<string, Uint8Array>()
  return { get: async (key) => values.get(key)?.slice() ?? null, put: async (key, bytes) => { values.set(key, bytes.slice()) } }
}
async function peer(saved = storage(), keys?: CryptoKeyPair) {
  keys ??= await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const identity = feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)))
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(saved, webFeedCrypto),
    signer: webFeedSigner(identity, keys.privateKey), crypto: webFeedCrypto })
  closers.push(() => transport.close())
  return { saved, keys, transport }
}
function envelope(messageType: EnvelopeMessageType, n = 1, route = groupRoute): Uint8Array {
  return encodeEnvelope({ groupRoute: route, messageType, encryptionEpoch: null, payload: Uint8Array.of(n) })
}
const wireEntry = (entry: OrderedRecordEntry): RecordLogEntry => ({
  historyId: entry.historyId, position: entry.position, recordId: entry.recordId,
  previousRoot: entry.previousRoot, root: entry.root, record: encodeRecord(entry.bytes),
})

async function fixture(futureAdmissionWindowMs = 31_000) {
  const identity = await generateEd25519KeyPair()
  const provisioned = await provisionMembership({ store: storage(), nativeAuthority: { historyId, publicKey: identity.publicKeyBytes },
    groupId: new Uint8Array(32).fill(1), groupRoute, executionManifestDigest: new Uint8Array(32).fill(3),
    schemaAdministratorPublicKey: identity.publicKeyBytes })
  const genesis = await signGenesis({ ...provisioned.descriptor.genesis.manifest,
    clockPolicy: { cutoffLagMs: 0n, maxFutureSkewMs: BigInt(futureAdmissionWindowMs), heartbeatIntervalMs: 1_000n },
  }, provisioned.identity.privateKey)
  const descriptor = await membershipDescriptor(genesis, groupRoute), configuration = descriptor.history
  if (configuration.kind !== 'coordinated') throw new Error('SIGNED_INCLUSION_REQUIRED')
  const log = await ReferenceRecordLog.open(historyId, storage())
  const writes = new Mutex(), clock = { now: 1_000 }
  let online = true, loseAppendReply = false, headReads = 0, scheduled = 0, raceClosure = false
  const serve = async (request: Request): Promise<Response> => {
    if (!online) return Response.json({ error: { code: 'offline', message: 'Hub unavailable' } }, { status: 503 })
    if (request.headers.get('Authorization') !== 'Bearer owner') return new Response(null, { status: 403 })
    const url = new URL(request.url)
    const entries = await log.read()
    const head = { ...await log.head(), bytes: entries.reduce((size, entry) => size + entry.bytes.length, 0) }
    if (url.pathname === '/records') {
      headReads += 1
      return Response.json({ descriptor: { historyId, format: RECORD_LOG_FORMAT, limits: RECORD_LOG_LIMITS }, head })
    }
    if (url.pathname === '/records/entries' && request.method === 'POST') {
      const body = await request.json() as { historyId: string; record: string; expectedHead?: { position: number; root: string } }
      if (body.historyId !== historyId) return new Response(null, { status: 409 })
      if (raceClosure && body.expectedHead !== undefined) {
        raceClosure = false
        await log.append((await createLedgerRecord(envelope('candidate', 99))).recordBytes)
      }
      return writes.run(async () => {
        const previous = (await log.read()).find((entry) => encodeRecord(entry.bytes) === body.record)
        if (previous !== undefined) return Response.json(wireEntry(previous))
        const current = await log.head()
        if (body.expectedHead !== undefined && (current.position !== body.expectedHead.position || current.root !== body.expectedHead.root)) {
          return Response.json({ error: { code: 'record_head_conflict', message: 'Concurrent append changed the predecessor' } }, { status: 409 })
        }
        const result = wireEntry(await log.append(decodeRecord(body.record)))
        if (loseAppendReply) { loseAppendReply = false; throw new Error('APPEND_REPLY_LOST') }
        return Response.json(result)
      })
    }
    if (url.pathname === '/records/entries') {
      const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'))
      const page = entries.slice(after, after + limit).map(wireEntry)
      return Response.json({ historyId, after, cursor: page.at(-1)?.position ?? after, entries: page, head })
    }
    return new Response('ordinary engine request')
  }
  const records = createRecordLogClient({ base: 'https://hub.test', headers: () => ({ Authorization: 'Bearer owner' }),
    fetch: (input, init) => serve(new Request(input, init)) })
  const engine = { fetch: (request: Request, _env: object, _context: object) => serve(request), scheduled: () => { scheduled += 1 } }
  const handler = await withTendrillerFinality(engine, { descriptor, identity, records, http, now: () => clock.now,
    authorize: (request) => request.headers.get('Authorization') === 'Bearer owner' })
  const certificate = createCertificateFetcher({ url: 'https://hub.test/_chronolog/certificate', headers: () => ({ Authorization: 'Bearer owner' }),
    fetch: (input, init) => handler.fetch(new Request(input, init), {}, {}) })
  const adapter = (local: PortableFeedTransport) => {
    const transport = new TendrillerTransport({ local, records, configuration, groupRoute, certificate, watch: false })
    closers.push(() => transport.close())
    return transport
  }
  return { descriptor, configuration, identity, log, records, certificate, handler, engine, adapter, clock,
    offline: () => { online = false }, online: () => { online = true }, loseReply: () => { loseAppendReply = true },
    headReads: () => headReads, scheduled: () => scheduled, raceClosure: () => { raceClosure = true } }
}

describe('public Tendriller adapter', () => {
  it('authenticates the signed clock policy before serving or accessing retained state', async () => {
    const f = await fixture(), descriptor = structuredClone(f.descriptor)
    const changed = { ...descriptor, genesis: { ...descriptor.genesis,
      manifest: { ...descriptor.genesis.manifest, clockPolicy: { ...descriptor.genesis.manifest.clockPolicy, cutoffLagMs: 500n } } } }
    await expect(withTendrillerFinality(f.engine, { descriptor: changed, identity: f.identity, records: f.records, http }))
      .rejects.toThrow('ENROLLMENT_DESCRIPTOR_INVALID')
    expect(f.headReads()).toBe(0)
    expect((await f.log.head()).position).toBe(0)
  })

  it('pins the built public SDK/engine artifacts and provenance', async () => {
    const manifestUrl = new URL('../package.json', import.meta.url)
    const manifest = JSON.parse(await readFile(manifestUrl, 'utf8')) as { devDependencies: Record<string, string> }
    for (const [dependency, name] of [['@tendriller/core', 'sdk'], ['@tendriller/engine', 'engine']]) {
      const reference = manifest.devDependencies[dependency!]!
      expect(reference).toMatch(new RegExp(`^file:.*tendriller-${name}-[0-9a-f]{8}\\.tgz$`))
      const artifact = new URL(reference.slice('file:'.length), manifestUrl)
      const provenance = JSON.parse(await readFile(new URL(artifact.href.replace(/\.tgz$/u, '.provenance.json')), 'utf8')) as {
        sha256: string; sourceCommit: string; sourceDirty: boolean; package: string; repository: string
      }
      expect(createHash('sha256').update(await readFile(artifact)).digest('hex')).toBe(provenance.sha256)
      expect(provenance.repository).toBe('https://github.com/werg/tendriller')
      expect(provenance.package).toBe(dependency)
      expect(provenance.sourceCommit).toMatch(/^[0-9a-f]{40}$/u)
      expect(provenance.sourceDirty).toBe(false)
      expect(artifact.pathname.endsWith(`-${provenance.sourceCommit.slice(0, 8)}.tgz`)).toBe(true)
    }
    expect(RECORD_LOG_FORMAT).toBe('record-log/v1')
  })

  it('recovers exact authored bytes after a lost append response without another feed record', async () => {
    const f = await fixture(), author = await peer(), adapter = f.adapter(author.transport)
    const bytes = envelope('candidate')
    f.loseReply()
    await expect(adapter.publish(bytes)).rejects.toThrow('APPEND_REPLY_LOST')
    const original = (await author.transport.history())[0]!
    expect((await f.log.head()).position).toBe(1)
    await adapter.close()
    const reopened = await peer(author.saved, author.keys), resumed = f.adapter(reopened.transport)
    await resumed.ensurePublished(original)
    expect(await resumed.publish(bytes)).toEqual(original)
    expect(await resumed.history()).toHaveLength(1)
    expect((await f.log.head()).position).toBe(1)
    await resumed.catchUp()
    expect((await resumed.evidenceHistory()).map((item) => decodeOrderingEvidence(item.bytes).kind).sort()).toEqual(['ordered-entry', 'ordered-entry', 'prefix-certificate'])
  })

  it('retains closure markers, keeps prefix certificates separate and relays complete proofs through another peer offline', async () => {
    const f = await fixture(), author = await peer(), reader = await peer(), adapter = f.adapter(author.transport)
    const original = await adapter.publish(envelope('candidate'))
    await adapter.catchUp()
    expect((await f.log.head()).position).toBe(2)
    await adapter.catchUp()
    expect((await f.log.head()).position).toBe(2)
    f.offline()
    connectInProcess(author.transport, reader.transport)
    await reader.transport.catchUp()
    expect(await reader.transport.get(original.id)).toMatchObject({
      id: original.id, author: original.author, sequence: original.sequence, payload: original.payload,
    })
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, storage())
    for (const item of await reader.transport.evidenceHistory()) await policy.ingest(decodeOrderingEvidence(item.bytes))
    expect(policy.progress.finalThrough).toBe(2)
    expect(policy.snapshot().closedThroughMs).toBe(1_000n)
    expect(policy.entries()[0]!.bytes).toEqual((await createLedgerRecord(original.payload)).recordBytes)
  })

  it('preserves governance publication order and keeps other feeds/groups out of the relay', async () => {
    const f = await fixture(), author = await peer(), adapter = f.adapter(author.transport)
    const first = await author.transport.publish(envelope('capability', 1))
    const second = await author.transport.publish(envelope('epoch-manifest', 2))
    await author.transport.publish(envelope('heartbeat', 3))
    await author.transport.publish(envelope('candidate', 4, new Uint8Array(32).fill(9)))
    f.loseReply()
    await expect(adapter.ensurePublished(second)).rejects.toThrow('APPEND_REPLY_LOST')
    await adapter.ensurePublished(second)
    expect((await f.log.read()).map((entry) => entry.bytes)).toEqual(await Promise.all([first, second].map(async record => (await createLedgerRecord(record.payload)).recordBytes)))
    expect((await adapter.history()).map((record) => record.id)).toEqual((await author.transport.history()).map((record) => record.id))
  })

  it('leaves durable local work and evidence usable while the authority route is unavailable', async () => {
    const f = await fixture(), author = await peer(), adapter = f.adapter(author.transport)
    expect(await adapter.status()).toMatchObject({ connected: false, peers: [] })
    await adapter.publish(envelope('candidate', 1)); await adapter.catchUp()
    expect(await adapter.status()).toMatchObject({ connected: true, peers: [] })
    f.offline()
    await expect(adapter.publish(envelope('candidate', 2))).rejects.toThrow('Hub unavailable')
    expect(await adapter.history()).toHaveLength(2)
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, storage())
    for (const item of await adapter.evidenceHistory()) await policy.ingest(decodeOrderingEvidence(item.bytes))
    expect(policy.progress.finalThrough).toBe(2)
    expect((await adapter.status()).lastCatchUpError).toContain('Hub unavailable')
    expect(await adapter.status()).toMatchObject({ connected: false, peers: [] })
    f.online(); await adapter.catchUp()
    for (const item of await adapter.evidenceHistory()) await policy.ingest(decodeOrderingEvidence(item.bytes))
    expect(policy.progress.finalThrough).toBe(4)
    expect((await f.log.head()).position).toBe(4)
    expect(await adapter.status()).toMatchObject({ connected: true, peers: [] })
    await adapter.close()
    expect((await adapter.status()).connected).toBe(false)
  })

  it('retries a lost certificate response even when no new head hint arrives', async () => {
    const f = await fixture(), author = await peer()
    await author.transport.publish(envelope('candidate'))
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    let attempts = 0
    let failed!: () => void
    const firstFailure = new Promise<void>(resolve => { failed = resolve })
    const adapter = new TendrillerTransport({ local: author.transport, configuration: f.configuration, groupRoute,
      records: { ...f.records, watch: () => () => undefined },
      certificate: async () => {
        const certificate = await f.certificate()
        if (++attempts === 1) { failed(); throw new Error('CERTIFICATE_REPLY_LOST') }
        return certificate
      },
    })
    closers.push(() => adapter.close())
    const stopped = new AbortController()
    const observed = (async () => {
      for await (const item of adapter.subscribeEvidence(stopped.signal)) {
        if (decodeOrderingEvidence(item.bytes).kind === 'prefix-certificate') return
      }
      throw new Error('CERTIFICATE_NOT_RETAINED')
    })()
    // Mark rejection handled immediately; a failing assertion still cleans up
    // the subscription without an unrelated unhandled promise rejection.
    void observed.catch(() => undefined)
    closers.push(async () => { stopped.abort(); await observed.catch(() => undefined) })
    await firstFailure
    await vi.advanceTimersByTimeAsync(0)
    expect((await adapter.status()).lastCatchUpError).toBe('CERTIFICATE_REPLY_LOST')
    expect((await adapter.evidenceHistory()).some(item => decodeOrderingEvidence(item.bytes).kind === 'prefix-certificate')).toBe(false)
    await vi.advanceTimersByTimeAsync(999)
    expect(attempts).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    await observed
    expect(attempts).toBe(2)
    expect((await f.log.head()).position).toBe(2)
  })

  it('retries a raced closure without retaining a marker for the wrong predecessor', async () => {
    const f = await fixture(), author = await peer(), adapter = f.adapter(author.transport)
    await adapter.publish(envelope('candidate'))
    f.raceClosure()
    await adapter.catchUp()
    const snapshot = await evaluateFinalitySnapshot(f.configuration, await f.log.read())
    expect(snapshot.records).toHaveLength(2)
    expect(snapshot.closures).toHaveLength(1)
    expect(snapshot.closedThroughMs).toBe(1_000n)
    expect(snapshot.includedThrough).toBe(3)
  })

  it('polls the finality provider while receipt-head hints are quiet', async () => {
    const f = await fixture(), author = await peer()
    await author.transport.publish(envelope('candidate'))
    const adapter = new TendrillerTransport({ local: author.transport, configuration: f.configuration, groupRoute,
      records: { ...f.records, watch: () => () => undefined }, certificate: f.certificate, finalityPollIntervalMs: 5 })
    closers.push(() => adapter.close())
    const policy = await SignedInclusionFinalityProvider.open(f.configuration, storage())
    const frontier = async () => {
      for (const item of await adapter.evidenceHistory()) await policy.ingest(decodeOrderingEvidence(item.bytes))
      return policy.snapshot().closedThroughMs
    }
    await expect.poll(frontier).toBe(1_000n)
    f.clock.now = 1_200
    await expect.poll(frontier).toBe(1_200n)
    expect(policy.snapshot().records).toHaveLength(1)
  })

  it('uses the cutoff observed before asynchronous head and proof verification', async () => {
    const f = await fixture()
    await f.records.append((await createLedgerRecord(envelope('candidate'))).recordBytes, { historyId })
    const handler = await withTendrillerFinality(f.engine, { descriptor: f.descriptor, identity: f.identity,
      records: { ...f.records, info: async options => {
        const head = await f.records.info(options)
        f.clock.now = 5_000
        return head
      } }, http, now: () => f.clock.now, authorize: () => true })
    const response = await handler.fetch(new Request('https://hub.test/_chronolog/certificate', { method: 'POST' }), {}, {})
    expect(response.status).toBe(200)
    expect((await evaluateFinalitySnapshot(f.configuration, await f.log.read())).closedThroughMs).toBe(1_000n)
  })

  it('bounds idle closures by the first closure window and restores that bound from retained history', async () => {
    const f = await fixture(100)
    expect((await f.certificate()).position).toBe(0)
    await f.records.append((await createLedgerRecord(envelope('candidate'))).recordBytes, { historyId })
    await f.certificate()
    f.clock.now = 1_050
    await f.certificate()
    expect((await evaluateFinalitySnapshot(f.configuration, await f.log.read())).closedThroughMs).toBe(1_050n)
    f.clock.now = 10_000
    await f.certificate()
    const head = await f.log.head()
    expect((await evaluateFinalitySnapshot(f.configuration, await f.log.read())).closedThroughMs).toBe(1_100n)
    for (let idle = 0; idle < 20; idle += 1) {
      f.clock.now += 1_000
      expect(await f.certificate()).toMatchObject(head)
    }
    const reopened = await withTendrillerFinality(f.engine, { descriptor: f.descriptor, identity: f.identity,
      records: f.records, http, now: () => f.clock.now,
      authorize: () => true })
    const response = await reopened.fetch(new Request('https://hub.test/_chronolog/certificate', { method: 'POST' }), {}, {})
    expect(response.status).toBe(200)
    expect(decodeOrderingEvidence(new Uint8Array(await response.arrayBuffer())))
      .toMatchObject({ kind: 'prefix-certificate', certificate: head })
    expect(await f.log.head()).toEqual(head)
  })

  it.each(['rollback', 'fork'] as const)('stops visibly if the history changes by %s between head and retained range reads', async (change) => {
    const f = await fixture(), local = await peer()
    await f.log.append(envelope('candidate', 1))
    if (change === 'rollback') await f.log.append(envelope('candidate', 2))
    const replacement = await ReferenceRecordLog.open(historyId, storage())
    await replacement.append(envelope('candidate', change === 'rollback' ? 1 : 3))
    let reads = 0
    const records = createRecordLogClient({ base: 'https://restored.test', fetch: async (input) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
      if (url.pathname === '/records') return Response.json(await f.records.info())
      if (++reads > 1) throw new Error('UNEXPECTED_REPEATED_READ')
      const entries = await replacement.read(), after = Number(url.searchParams.get('after'))
      const page = entries.slice(after).map(wireEntry)
      return Response.json({ historyId, after, cursor: page.at(-1)?.position ?? after, entries: page,
        head: { ...await replacement.head(), bytes: entries.reduce((size, entry) => size + entry.bytes.length, 0) } })
    } })
    const adapter = new TendrillerTransport({ local: local.transport, records, configuration: f.configuration, groupRoute, watch: false })
    closers.push(() => adapter.close())
    await expect(adapter.catchUp()).rejects.toThrow('TENDRILLER_HISTORY_CONFLICT')
    expect(reads).toBe(1)
    expect(await adapter.evidenceHistory()).toHaveLength(0)
  })

  it('fails closed before reading/signing and composes ordinary engine requests and scheduling', async () => {
    const f = await fixture()
    const denied = await withTendrillerFinality(f.engine, { descriptor: f.descriptor, identity: f.identity, records: f.records, http })
    expect((await denied.fetch(new Request('https://hub.test/_chronolog/certificate', { method: 'POST' }), {}, {})).status).toBe(403)
    expect(f.headReads()).toBe(0)
    expect((await f.handler.fetch(new Request('https://hub.test/_chronolog/certificate', { method: 'POST',
      headers: { Authorization: 'Bearer owner' }, body: JSON.stringify({ root: 'attacker-root' }) }), {}, {})).status).toBe(400)
    expect(f.headReads()).toBe(0)
    const certificate = await f.certificate()
    await verifyPrefixCertificate(certificate, f.configuration)
    expect(certificate).toMatchObject(await f.log.head())
    const ordinary = await f.handler.fetch(new Request('https://hub.test/ordinary', { headers: { Authorization: 'Bearer owner' } }), {}, {})
    expect(await ordinary.text()).toBe('ordinary engine request')
    f.handler.scheduled(); expect(f.scheduled()).toBe(1)
  })

  it('can authorize through the configured public engine record route with the original credentials', async () => {
    const f = await fixture()
    const handler = await withTendrillerFinality(f.engine, { descriptor: f.descriptor, identity: f.identity, records: f.records, http,
      authorize: authorizeThroughRecordLog(f.engine, { base: 'https://hub.test', historyId, http }),
    })
    const request = (token: string) => new Request('https://hub.test/_chronolog/certificate', {
      method: 'POST', headers: { Authorization: `Bearer ${token}` },
    })
    expect((await handler.fetch(request('revoked-agent'), {}, {})).status).toBe(403)
    expect(f.headReads()).toBe(0)
    expect((await handler.fetch(request('owner'), {}, {})).status).toBe(200)
    expect(f.headReads()).toBe(2)
  })
})

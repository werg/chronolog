import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ChronologClient, OWNER_FOR_KEY_SQL } from '@chronolog/client'
import { signGenesis } from '@chronolog/capabilities'
import {
  createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer,
} from '@chronolog/materializer-doltlite'
import { ChronologNode, Mutex, membershipDescriptor, provisionMembership } from '@chronolog/node-core'
import { evaluateFinalitySnapshot } from '@chronolog/node-core/finality'
import { createLedgerRecord } from '@chronolog/node-core/ledger'
import {
  SignedInclusionFinalityProvider, decodeOrderingEvidence, ReferenceRecordLog,
} from '@chronolog/node-core/history'
import { digestExecutionManifest, equalBytes, generateEd25519KeyPair } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import {
  connectInProcess, DurableFeedStore, feedIdFromPublicKey, PortableFeedTransport, webFeedCrypto, webFeedSigner,
} from '@chronolog/records'
import type { AtomicBytesStore } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { createRecordLogClient, decodeRecord, encodeRecord, RECORD_LOG_FORMAT, RECORD_LOG_LIMITS } from '@tendriller/core/records'
import { afterEach, describe, expect, it } from 'vitest'

import { createCertificateFetcher, withTendrillerFinality } from './finality-service.js'
import type { FinalityHttp } from './finality-service.js'
import { TendrillerTransport } from './transport.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes32 = (value: number) => new Uint8Array(32).fill(value)
function storage(): AtomicBytesStore {
  const values = new Map<string, Uint8Array>()
  return { get: async (key) => values.get(key)?.slice() ?? null, put: async (key, bytes) => { values.set(key, bytes.slice()) } }
}

/** An independent durable log speaks the packed Tendriller SDK's public HTTP format. */
async function hub(executionManifestDigest: Uint8Array) {
  const identity = await generateEd25519KeyPair()
  const provisioned = await provisionMembership({ store: storage(),
    nativeAuthority: { historyId: 'h_ffeeddccbbaa99887766554433221100', publicKey: identity.publicKeyBytes },
    groupId: bytes32(11), groupRoute: bytes32(11), executionManifestDigest, schemaAdministratorPublicKey: identity.publicKeyBytes })
  const genesis = await signGenesis({ ...provisioned.descriptor.genesis.manifest,
    clockPolicy: { cutoffLagMs: 0n, maxFutureSkewMs: 31_000n, heartbeatIntervalMs: 1_000n },
  }, provisioned.identity.privateKey)
  const descriptor = await membershipDescriptor(genesis, bytes32(11)), configuration = descriptor.history
  if (configuration.kind !== 'coordinated') throw new Error('SIGNED_INCLUSION_REQUIRED')
  const log = await ReferenceRecordLog.open(configuration.historyId, storage())
  const writes = new Mutex(), clock = { now: 1_000 }
  let online = true
  const wire = (entry: Awaited<ReturnType<typeof log.append>>) => ({
    historyId: entry.historyId, position: entry.position, recordId: entry.recordId,
    previousRoot: entry.previousRoot, root: entry.root, record: encodeRecord(entry.bytes),
  })
  const serve = async (request: Request): Promise<Response> => {
    if (!online) throw new Error('TENDRILLER_UNAVAILABLE')
    if (request.headers.get('Authorization') !== 'Bearer owner') return new Response(null, { status: 403 })
    const url = new URL(request.url)
    if (request.method === 'POST' && url.pathname.endsWith('/entries')) {
      const { record, historyId, expectedHead } = await request.json() as {
        record: string; historyId: string; expectedHead?: { position: number; root: string }
      }
      if (historyId !== configuration.historyId) return new Response(null, { status: 409 })
      return writes.run(async () => {
        const previous = (await log.read()).find((entry) => encodeRecord(entry.bytes) === record)
        if (previous !== undefined) return Response.json(wire(previous))
        const head = await log.head()
        if (expectedHead !== undefined && (head.position !== expectedHead.position || head.root !== expectedHead.root)) {
          return Response.json({ error: { code: 'record_head_conflict', message: 'Retained head changed' } }, { status: 409 })
        }
        return Response.json(wire(await log.append(decodeRecord(record))))
      })
    }
    const entries = await log.read()
    const head = { ...await log.head(), bytes: entries.reduce((size, entry) => size + entry.bytes.length, 0) }
    if (url.pathname.endsWith('/entries')) {
      const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'))
      const page = entries.slice(after, after + limit).map(wire)
      return Response.json({ historyId: configuration.historyId, after, cursor: page.at(-1)?.position ?? after, entries: page, head })
    }
    return Response.json({ descriptor: { historyId: configuration.historyId, format: RECORD_LOG_FORMAT, limits: RECORD_LOG_LIMITS }, head })
  }
  const records = createRecordLogClient({ base: 'https://hub.test', headers: () => ({ Authorization: 'Bearer owner' }),
    fetch: (input, init) => serve(new Request(input, init)) })
  const http: FinalityHttp<Request, Response> = {
    request: (url, init) => new Request(url, init), response: (body, init) => new Response(body, init),
  }
  const handler = await withTendrillerFinality({ fetch: (request: Request, _env: object, _context: object) => serve(request) }, {
    descriptor, identity, records, http, now: () => clock.now,
    authorize: (request) => request.headers.get('Authorization') === 'Bearer owner',
  })
  const certificate = createCertificateFetcher({ url: 'https://hub.test/_chronolog/certificate', headers: () => ({ Authorization: 'Bearer owner' }),
    fetch: (input, init) => handler.fetch(new Request(input, init), {}, {}) })
  return { configuration, records, certificate, log, clock, offline: () => { online = false } }
}

describe('Tendriller coordinated SQL connection', () => {
  it('uses signed author time despite reversed claim receipts and replays final SQL through a peer without the hub', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'chronolog-tendriller-sql-'))
    cleanup.push(() => rm(directory, { recursive: true, force: true, maxRetries: 5 }))
    const executionManifest = createDoltLiteExecutionManifest()
    const authority = await hub(await digestExecutionManifest(executionManifest))
    const [aliceKey, bobKey, readerKey] = await Promise.all([
      generateEd25519KeyPair(), generateEd25519KeyPair(), generateEd25519KeyPair(),
    ])
    const open = async (name: string, identity: Ed25519KeyPair, relay: boolean) => {
      const saved = storage()
      const local = new PortableFeedTransport({ store: await DurableFeedStore.open(saved, webFeedCrypto), crypto: webFeedCrypto,
        signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
      const adapter = relay ? new TendrillerTransport({ local, records: authority.records, configuration: authority.configuration,
        groupRoute: authority.configuration.groupId, certificate: authority.certificate, watch: false }) : undefined
      const transport = adapter ?? local
      const materializer = await DeterministicMaterializer.open({ path: join(directory, `${name}.db`), executionManifest,
        rootAdministrator: aliceKey.publicKeyBytes })
      const policy = await SignedInclusionFinalityProvider.open(authority.configuration, saved)
      const node = new ChronologNode({
        groupId: authority.configuration.groupId, membershipRevision: bytes32(13), validationPolicy: bytes32(14), identity,
        transport, operationStore: saved, historyPolicy: { kind: 'coordinated', policy },
        clock: { now: () => authority.clock.now + (name === 'alice' ? 2 : 1) },
        materialization: createDoltLiteMaterializationRuntime(materializer),
        membership: {
          canWrite: ({ writerId }) => [aliceKey, bobKey].some((key) => equalBytes(key.publicKeyBytes, writerId)),
          canValidate: () => false, threshold: () => 1,
          canUseTransportAuthor: ({ signingId, transportAuthor }) => feedIdFromPublicKey(signingId) === transportAuthor,
        },
      })
      const client = new ChronologClient({ groupId: Buffer.from(authority.configuration.groupId).toString('base64url'),
        transport: new InProcessRpcTransport(new NodeRpcService({ node })) })
      cleanup.push(async () => { await client.close(); await node.close() })
      await node.start()
      return { node, client, local, transport, adapter, materializer }
    }
    const alice = await open('alice', aliceKey, true), bob = await open('bob', bobKey, true)
    // The host retains small descriptors; application envelopes travel between peers.
    const disconnect = connectInProcess(alice.local, bob.local)
    const participants = [alice, bob]
    const sync = async () => {
      authority.clock.now += 100
      for (const peer of participants) {
        await peer.adapter!.catchUp()
        for (const item of await peer.transport.evidenceHistory()) {
          await peer.node.ingestOrderingEvidence(decodeOrderingEvidence(item.bytes))
        }
      }
    }
    const created = await alice.client.transaction(['CREATE TABLE tasks (id INTEGER PRIMARY KEY, claimed_by TEXT) STRICT'])
    // The proposal is two milliseconds ahead of the first closure. It executes
    // provisionally, then becomes final when time advances without a new write.
    await alice.adapter!.catchUp()
    for (const item of await alice.transport.evidenceHistory()) {
      await alice.node.ingestOrderingEvidence(decodeOrderingEvidence(item.bytes))
    }
    expect(await created.local()).toMatchObject({ final: false, outcome: { type: 'accepted' } })
    await sync(); expect(await created.final()).toMatchObject({ final: true, outcome: { type: 'accepted' } })
    const team = await alice.client.ownership.createTeam({ invite: [bobKey.publicKeyBytes] })
    await sync(); expect(await team.handle.final()).toMatchObject({ final: true, outcome: { type: 'accepted' } })
    const joined = await bob.client.ownership.acceptInvitation(team.id)
    await sync(); expect(await joined.handle.final()).toMatchObject({ final: true, outcome: { type: 'accepted' } })
    const inserted = await alice.client.transaction([{
      sql: `INSERT INTO tasks (id, chronolog_owner) VALUES (1, ${OWNER_FOR_KEY_SQL})`, params: [team.id],
    }])
    await sync(); expect(await inserted.final()).toMatchObject({ final: true, outcome: { type: 'accepted' } })

    const claim = (name: string) => [
      "SELECT chronolog_assert((SELECT claimed_by IS NULL FROM tasks WHERE id = 1), 'already_claimed')",
      { sql: 'UPDATE tasks SET claimed_by = ? WHERE id = 1', params: [name] },
    ]
    // Author concurrently from the same final setup. If Bob applied Alice's
    // claim first, the causal author clock would correctly put his claim later.
    await bob.local.catchUp()
    await bob.node.waitForIdle()
    expect(await bob.client.getTransactionOutcome(inserted.transactionId)).toMatchObject({ final: true })
    disconnect()
    // Alice reaches the receipt log first. Bob's independently signed author
    // time is earlier, so every replica must execute his claim first.
    const aliceClaim = await alice.client.transaction(claim('alice'))
    const bobClaim = await bob.client.transaction(claim('bob'))
    expect(BigInt(bobClaim.submission.authorTimestampMs)).toBeLessThan(BigInt(aliceClaim.submission.authorTimestampMs))
    const claimReceipts = await Promise.all(participants.map(async peer => {
      const ownRecords = (await peer.local.history()).filter(record => record.author === peer.local.identity)
      return (await createLedgerRecord(ownRecords.at(-1)!.payload)).recordBytes
    }))
    connectInProcess(alice.local, bob.local)
    // Both have local results, but a stored append does not make either final.
    expect((await aliceClaim.local()).final).toBe(false)
    expect((await bobClaim.local()).final).toBe(false)
    await sync()
    const outcomes = await Promise.all([aliceClaim.final(), bobClaim.final()])
    expect(outcomes.map((outcome) => outcome.outcome.type)).toEqual(['rejected', 'accepted'])
    const losing = outcomes.find((outcome) => outcome.outcome.type === 'rejected')!
    expect(losing.outcome).toMatchObject({ type: 'rejected', rejection: { code: 'assert:already_claimed' } })
    const finalRows = (node: ChronologNode) => node.localSql('SELECT id, claimed_by FROM tasks', [], { view: 'final' })
    const expectedRows = [[{ kind: 'integer', value: '1' }, { kind: 'text', value: 'bob' }]]
    const proof = await evaluateFinalitySnapshot(authority.configuration, await authority.log.read())
    expect(proof.records.slice(-2).map(({ entry }) => entry.bytes)).toEqual(claimReceipts)
    for (const peer of participants) {
      expect(finalRows(peer.node).rows).toEqual(expectedRows)
      expect(peer.node.finalOrderLength).toBe(6)
      expect(peer.node.finalThrough).toBe(proof.closedReceiptThrough)
    }
    // Re-encapsulating an existing signed proposal in another author's feed
    // preserves its exact log identity and cannot create another SQL effect.
    const repeated = (await alice.local.history())[0]!
    const forwarded = await bob.adapter!.publish(repeated.payload)
    expect(forwarded.author).not.toBe(repeated.author)
    await sync()
    const afterRetry = await evaluateFinalitySnapshot(authority.configuration, await authority.log.read())
    expect(afterRetry.records).toHaveLength(6)
    expect(alice.node.finalOrderLength).toBe(6)

    // The new reader has no adapter, record client, or authority endpoint. It
    // receives original signed records and immutable evidence from Alice.
    authority.offline()
    const reader = await open('reader', readerKey, false)
    connectInProcess(alice.local, reader.local)
    await reader.local.catchUp()
    for (const item of await reader.local.evidenceHistory()) await reader.node.ingestOrderingEvidence(decodeOrderingEvidence(item.bytes))
    expect(finalRows(reader.node).rows).toEqual(expectedRows)
    expect(reader.node.finalThrough).toBe(afterRetry.closedReceiptThrough)
    expect(reader.node.finalOrderLength).toBe(6)
    for (const handle of [aliceClaim, bobClaim]) {
      expect((await reader.client.getTransactionOutcome(handle.transactionId)).outcome)
        .toEqual((await alice.client.getTransactionOutcome(handle.transactionId)).outcome)
    }
    expect((await evaluateFinalitySnapshot(authority.configuration, await authority.log.read())).records).toHaveLength(6)
  }, 30_000)
})

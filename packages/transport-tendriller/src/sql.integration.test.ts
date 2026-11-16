import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ChronologClient, OWNER_FOR_KEY_SQL } from '@chronolog/client'
import {
  createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime, DeterministicMaterializer,
} from '@chronolog/materializer-doltlite'
import { ChronologNode } from '@chronolog/node-core'
import {
  CoordinatedHistoryPolicy, decodeOrderingEvidence, ReferenceRecordLog,
  type CoordinatedHistoryConfiguration,
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

import { createCertificateFetcher, withTendrillerAuthority } from './authority.js'
import type { AuthorityHttp } from './authority.js'
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
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', historyId: 'h_ffeeddccbbaa99887766554433221100',
    groupId: bytes32(11), genesisDigest: bytes32(12), executionManifestDigest, authorityPublicKey: identity.publicKeyBytes,
  }
  const log = await ReferenceRecordLog.open(configuration.historyId, storage())
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
      const { record, historyId } = await request.json() as { record: string; historyId: string }
      if (historyId !== configuration.historyId) return new Response(null, { status: 409 })
      return Response.json(wire(await log.append(decodeRecord(record))))
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
  const http: AuthorityHttp<Request, Response> = {
    request: (url, init) => new Request(url, init), response: (body, init) => new Response(body, init),
  }
  const handler = withTendrillerAuthority({ fetch: (request: Request, _env: object, _context: object) => serve(request) }, {
    configuration, identity, records, http,
    authorize: (request) => request.headers.get('Authorization') === 'Bearer owner',
  })
  const certificate = createCertificateFetcher({ url: 'https://hub.test/_chronolog/certificate', headers: () => ({ Authorization: 'Bearer owner' }),
    fetch: (input, init) => handler.fetch(new Request(input, init), {}, {}) })
  return { configuration, records, certificate, log, offline: () => { online = false } }
}

describe('Tendriller coordinated SQL connection', () => {
  it('resolves two collective members claiming one task and replays certified SQL through a peer without the hub', async () => {
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
      const policy = await CoordinatedHistoryPolicy.open(authority.configuration, saved)
      const node = new ChronologNode({
        groupId: authority.configuration.groupId, membershipRevision: bytes32(13), validationPolicy: bytes32(14), identity,
        transport, operationStore: saved, historyPolicy: { kind: 'coordinated', policy },
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
    connectInProcess(alice.local, bob.local)
    const participants = [alice, bob]
    const sync = async () => {
      for (const peer of participants) {
        await peer.adapter!.catchUp()
        for (const item of await peer.transport.evidenceHistory()) {
          await peer.node.ingestOrderingEvidence(decodeOrderingEvidence(item.bytes))
        }
      }
    }
    const created = await alice.client.transaction(['CREATE TABLE tasks (id INTEGER PRIMARY KEY, claimed_by TEXT) STRICT'])
    await sync(); await created.accepted()
    const team = await alice.client.ownership.createTeam({ invite: [bobKey.publicKeyBytes] })
    await sync(); await team.handle.accepted()
    const joined = await bob.client.ownership.acceptInvitation(team.id)
    await sync(); await joined.handle.accepted()
    const inserted = await alice.client.transaction([{
      sql: `INSERT INTO tasks (id, chronolog_owner) VALUES (1, ${OWNER_FOR_KEY_SQL})`, params: [team.id],
    }])
    await sync(); await inserted.accepted()

    const claim = (name: string) => [
      "SELECT chronolog_assert((SELECT claimed_by IS NULL FROM tasks WHERE id = 1), 'already_claimed')",
      { sql: 'UPDATE tasks SET claimed_by = ? WHERE id = 1', params: [name] },
    ]
    const [aliceClaim, bobClaim] = await Promise.all([
      alice.client.transaction(claim('alice')), bob.client.transaction(claim('bob')),
    ])
    // A stored append is not finality: both claims are still pending locally.
    expect((await alice.client.getTransactionOutcome(aliceClaim.transactionId)).outcome.type).toBe('pending')
    expect((await bob.client.getTransactionOutcome(bobClaim.transactionId)).outcome.type).toBe('pending')
    await sync()
    const outcomes = await Promise.all([aliceClaim.settled(), bobClaim.settled()])
    expect(outcomes.map((outcome) => outcome.outcome.type).sort()).toEqual(['accepted', 'rejected'])
    const losing = outcomes.find((outcome) => outcome.outcome.type === 'rejected')!
    expect(losing.outcome).toMatchObject({ type: 'rejected', rejection: { code: 'assert:already_claimed' } })
    const winner = outcomes[0].outcome.type === 'accepted' ? 'alice' : 'bob'
    const finalRows = (node: ChronologNode) => node.localSql('SELECT id, claimed_by FROM tasks', [], { view: 'final' })
    const expectedRows = [[{ kind: 'integer', value: '1' }, { kind: 'text', value: winner }]]
    for (const peer of participants) {
      expect(finalRows(peer.node).rows).toEqual(expectedRows)
      expect(peer.node.finalOrderLength).toBe(6)
      expect(peer.node.finalThrough).toBe(6)
    }
    // Re-encapsulating an existing signed proposal in another author's feed
    // preserves its exact log identity and cannot create another SQL effect.
    const repeated = (await alice.local.history())[0]!
    const forwarded = await bob.adapter!.publish(repeated.payload)
    expect(forwarded.author).not.toBe(repeated.author)
    await sync()
    expect((await authority.log.head()).position).toBe(6)
    expect(alice.node.finalOrderLength).toBe(6)

    // The new reader has no adapter, record client, or authority endpoint. It
    // receives original signed records and immutable evidence from Alice.
    authority.offline()
    const reader = await open('reader', readerKey, false)
    connectInProcess(alice.local, reader.local)
    await reader.local.catchUp()
    for (const item of await reader.local.evidenceHistory()) await reader.node.ingestOrderingEvidence(decodeOrderingEvidence(item.bytes))
    expect(finalRows(reader.node).rows).toEqual(expectedRows)
    expect(reader.node.finalThrough).toBe(6)
    expect(reader.node.finalOrderLength).toBe(6)
    for (const handle of [aliceClaim, bobClaim]) {
      expect((await reader.client.getTransactionOutcome(handle.transactionId)).outcome)
        .toEqual((await alice.client.getTransactionOutcome(handle.transactionId)).outcome)
    }
    expect((await authority.log.head()).position).toBe(6)
  }, 30_000)
})

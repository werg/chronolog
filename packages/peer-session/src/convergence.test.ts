import { afterEach, describe, expect, it, vi } from 'vitest'
import { compareTransactionOrder, transactionOrderKey, emit, program } from '@chronolog/protocol'
import { bytesToHex, recordDigest, signMembership } from '@chronolog/authority'
import { createApplicationSession } from './runtime.js'
import { openApplicationDevice } from './device.js'
import { unwrapOperation } from './operation-codec.js'
import { sessionFixture, eventDefinition } from './test-fixture.js'
import { createLiveView } from './live-view.js'
import { createViewStore } from './view-store.js'
const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); vi.restoreAllMocks() })
describe('immutable authored operation set', () => {
  it('authors independently while disconnected; union inserts earlier work and converges after restart', async () => {
    const fixture = await sessionFixture(), left = await fixture.open(0), right = await fixture.open(1); cleanup.push(() => left.close(), () => right.close())
    const late = await left.command('say', 'later', { operationId: 'later', authorTimestampMs: 20n }), early = await right.command('say', 'earlier', { operationId: 'earlier', authorTimestampMs: 10n })
    await late.materialized(); await early.materialized(); expect(left.status.connectedPeers).toBe(0)
    const before = await left.readEvents(); expect(before.events.map(event => event.payload)).toEqual(['later'])
    const a = left.exportFacts(), b = right.exportFacts(); await left.mergeFacts(b); await right.mergeFacts(a); await left.retryMaterialization(); await right.retryMaterialization()
    const merged = await left.readEvents(); expect(merged.events.map(event => event.payload)).toEqual(['earlier', 'later']); expect((await right.readEvents()).revision.digest).toBe(merged.revision.digest)
    await expect(left.readEvents({ cursor: before.cursor })).rejects.toThrow('EVENT_CURSOR_STALE')
    await left.close(); const reopened = await fixture.open(0); cleanup.push(() => reopened.close()); expect((await reopened.readEvents()).events.map(event => event.payload)).toEqual(['earlier', 'later'])
    await expect(late.finalized()).rejects.toThrow('FINALITY_UNSUPPORTED'); expect('applied' in late).toBe(false); expect('shared' in late).toBe(false)
  })
  it('uses authenticated author-key then canonical proposal identity for exact bigint ties', async () => {
    const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); cleanup.push(() => a.close(), () => b.close())
    const ops = await Promise.all([a.command('say', 'A', { authorTimestampMs: 42n }), b.command('say', 'B', { authorTimestampMs: 42n })]); await Promise.all(ops.map(op => op.materialized()))
    const facts = { envelopes: [...a.exportFacts().envelopes, ...b.exportFacts().envelopes], retentions: [], finality: [] }; await a.mergeFacts(facts); await b.mergeFacts(facts)
    const bodies = await Promise.all(facts.envelopes.map(envelope => unwrapOperation(envelope, a.authority)))
    const expected = bodies.map(body => { if (typeof body === 'string') throw new Error(body); return { core: body.core, id: body.body.payload.proposalId } }).sort((left, right) => compareTransactionOrder(transactionOrderKey(left.core, Uint8Array.from(Buffer.from(left.id, 'hex'))), transactionOrderKey(right.core, Uint8Array.from(Buffer.from(right.id, 'hex')))))
    expect((await a.readEvents()).events.map(event => event.proposalId)).toEqual(expected.map(item => item.id)); expect((await b.readEvents()).revision).toEqual((await a.readEvents()).revision)
  })
  it('allocates default timestamps once monotonically under a frozen wall clock and rejects changed retries', async () => {
    const f = await sessionFixture({ count: 1 }), session = await f.open(0); cleanup.push(() => session.close()); vi.spyOn(Date, 'now').mockReturnValue(100)
    const first = await session.command('say', 'one', { operationId: 'one' }), second = await session.command('say', 'two', { operationId: 'two' })
    expect(session.exportFacts().envelopes.map(envelope => envelope.payload.authorTimestampMs)).toEqual([100n, 101n])
    const bytes = await recordDigest(session.exportFacts()), retry = await session.command('say', 'one', { operationId: 'one' }); expect(retry.id).toBe(first.id); expect(await recordDigest(session.exportFacts())).toBe(bytes)
    await expect(session.command('say', 'different', { operationId: 'one' })).rejects.toThrow('OPERATION_ID_REUSED'); await expect(session.command('say', 'one', { operationId: 'one', authorTimestampMs: 102n })).rejects.toThrow('OPERATION_ID_REUSED')
    await second.materialized(); expect((await session.readEvents()).events.map(event => event.payload)).toEqual(['one', 'two'])
  })
  it('stores before engine warmup/failure and exact retries survive an uncertain durable reply', async () => {
    const f = await sessionFixture({ count: 1 }), store = f.stores[0]!, originalPut = store.put.bind(store); let fail = true
    store.put = async (key, bytes) => { await originalPut(key, bytes); if (fail && key.startsWith('operation-set/') && new TextDecoder().decode(bytes).includes('lost-reply')) { fail = false; throw new Error('LOST_REPLY') } }
    const device = await openApplicationDevice({ store, create: true, managedSigner: f.identities[0]! })
    const session = await createApplicationSession({ device, definition: eventDefinition, authority: f.bundle, epochKeys: new Map([[0, f.epochKey]]), createMaterializer: () => { throw new Error('SQL_WARMUP_UNAVAILABLE') } }); cleanup.push(() => session.close())
    await expect(session.command('say', 'stored', { operationId: 'lost-reply', authorTimestampMs: 1n })).rejects.toThrow('LOST_REPLY')
    const operation = await session.command('say', 'stored', { operationId: 'lost-reply', authorTimestampMs: 1n }); expect(operation.stored).toBe(true); expect(session.exportFacts().envelopes).toHaveLength(1)
    await expect(session.retryMaterialization()).rejects.toThrow('SQL_WARMUP_UNAVAILABLE'); expect(operation.inspect().pending).toBe('materializer'); expect(operation.inspect().materialized).toBeNull()
  })
  it('keeps unknown keys pending then replays on key arrival without a fake SQL rejection', async () => {
    const f = await sessionFixture(), a = await f.open(0), b = await f.open(1, false); cleanup.push(() => a.close(), () => b.close()); const op = await a.command('say', 'secret', { authorTimestampMs: 4n }); await op.materialized()
    await b.mergeFacts(a.exportFacts()); await b.retryMaterialization(); const remote = b.operations.get(op.id)!; expect(remote.inspect().pending).toBe('key'); expect(remote.inspect().materialized).toBeNull(); expect(b.status.canAuthor).toBe(false)
    await b.authority.installEpochKey(0, f.epochKey); await b.retryMaterialization(); expect((await remote.materialized()).outcome).toBe('accepted'); expect((await b.readEvents()).events[0]?.payload).toBe('secret')
  })
  it('uses historical membership windows without overwriting application permission state', async () => {
    const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); cleanup.push(() => a.close(), () => b.close())
    const original = await b.command('say', 'old', { authorTimestampMs: 5n }); await original.materialized()
    const membership = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, authorTimeAfterMs: 10n, members: f.membership.payload.members.map(member => ({ ...member, writer: member.publicKey === f.identities[0]!.publicKey })) }, f.authorityIdentity)
    await a.authority.merge({ descriptor: f.descriptor, memberships: [f.membership, membership] }); await b.authority.merge({ descriptor: f.descriptor, memberships: [f.membership, membership] })
    await a.mergeFacts(b.exportFacts()); await a.retryMaterialization(); expect((await a.readEvents()).events.map(event => event.payload)).toEqual(['old'])
    await expect(b.command('say', 'revoked', { authorTimestampMs: 6n })).rejects.toThrow('OPERATION_WRITER_FORBIDDEN')
    const backdated = await a.command('say', 'backdated', { authorTimestampMs: 8n }); await backdated.materialized(); const body = await unwrapOperation(a.exportFacts().envelopes.at(-1)!, a.authority); expect(typeof body !== 'string' && bytesToHex(body.core.membershipRevision)).toBe(f.membershipId)
  })
  it('rederives coherent domain projections for late insertions while retaining local drafts', async () => {
    const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); cleanup.push(() => a.close(), () => b.close())
    const draftData = new Map<string, string>(), drafts = createViewStore<{ text: string }>({ applicationId: f.applicationId, profileId: 'profile', viewId: 'view', storage: { get length() { return draftData.size }, key: index => [...draftData.keys()][index] ?? null, getItem: key => draftData.get(key) ?? null, setItem: (key, value) => { draftData.set(key, value) }, removeItem: key => { draftData.delete(key) } } }); drafts.writeDraft({ text: 'unsaved' })
    const projection = createLiveView(a, view => view.readEvents().events.map(event => event.payload)); cleanup.push(async () => projection.close())
    await projection.ready(); await (await a.submit({ program: program(emit('message', 'later')), authorTimestampMs: 20n })).materialized(); await projection.refresh()
    await (await b.command('say', 'earlier', { authorTimestampMs: 10n })).materialized(); await a.mergeFacts(b.exportFacts()); await a.retryMaterialization()
    expect((await projection.refresh()).value).toEqual(['earlier', 'later']); expect(drafts.readDraft()).toEqual({ text: 'unsaved' })
  })
})

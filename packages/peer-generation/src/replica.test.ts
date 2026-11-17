import { afterEach, describe, expect, it, vi } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { decodeTransactionCore, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type PeerStore, type PrefixProof,
} from './index.js'
import { bytesToHex, signPeerValue } from './codec.js'

const opened: PeerReplica[] = []
afterEach(async () => { for (const peer of opened.splice(0)) await peer.close() })
async function fixture() {
  const [host, a, b, c] = await Promise.all(Array.from({ length: 4 }, () => createPeerIdentity())) as [PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity]
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'replica-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: '11'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a, dataRole: 'member' as const })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (who: PeerIdentity, base: PrefixProof | null, id: string) => {
    const authority = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
      profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: id,
      expectedGeneration: authority.generations.at(-1)?.id ?? null, coordinator: who.publicKey,
      requester: who.publicKey, controlRevision: 0, reason: base === null ? 'create' : 'takeover', base }, who))
  }
  await select(a, null, 'initial')
  const open = async (identity: PeerIdentity, store: PeerStore = new MemoryPeerStore(), authority?: AuthorityBundle, storageId = identity.publicKey) => {
    const materializer = await createEventMaterializationRuntime({ store, namespace: 'test', historyProfile: 'peer-generation-v1' })
    const peer = await createPeerReplica({ authority: authority ?? await registry.read(), device: identity, store, storageId, materializer, epochKeys: keys })
    opened.push(peer); return peer
  }
  return { host, a, b, c, key, keys, control, registry, select, open }
}
const event = (name: string) => program(emit('message', { name }))

describe('peer-owned encrypted history and tolerant recovery', () => {
  it('executes delegated order without altering author times and replays identically', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = await a.prepare({ operationId: 'first', program: event('first'), authorTimestampMs: 500n })
    const second = await a.prepare({ operationId: 'second', program: event('second'), authorTimestampMs: 100n })
    await a.order(first)
    const firstView = await a.capture(); const firstRevision = firstView.revision; firstView.release()
    await a.order(second); await b.ingest(await a.exportCommands())
    expect(await a.exportCommands({ at: firstRevision })).toHaveLength(1)
    await expect(a.exportCommands({ at: firstRevision, offset: 2 })).rejects.toThrow('PEER_RANGE_OFFSET_INVALID')
    const av = await a.capture(), bv = await b.capture()
    try {
      expect(av.read.orderLength).toBe(2)
      const transactions = [0, 1].map(index => av.read.transactionAt(index)!)
      expect(transactions).toEqual([0, 1].map(index => bv.read.transactionAt(index)))
      expect(transactions.map(value => decodeTransactionCore(value.canonicalCandidate).authorTimestampMs)).toEqual([500n, 100n])
    } finally { av.release(); bv.release() }
    expect(await a.order(first)).toEqual((await a.exportCommands())[0])
    expect((await a.exportCommands()).length).toBe(2)
    await b.observeCoverage(await a.retainedCoverage())
    expect(b.shared()).toHaveLength(1)
  })
  it('bounds captured reads and publishes outcomes with one indexed pass instead of history lookups', async () => {
    const f = await fixture(), a = await f.open(f.a)
    for (let index = 0; index < 4; index++) {
      await a.order(await a.prepare({ operationId: `entry-${index}`, program: index === 3 ? program('SELECT 1') : event(String(index)) }))
    }
    const store = new MemoryPeerStore()
    const runtime = await createEventMaterializationRuntime({ store, namespace: 'test', historyProfile: 'peer-generation-v1' })
    const outcomeLookups = vi.spyOn(runtime.queries, 'outcome'), materialize = vi.spyOn(runtime.coordinator, 'materialize')
    const publicationReads: number[] = [], viewReads: number[] = []
    const captureApplication = runtime.queries.captureApplication.bind(runtime.queries)
    const captureRead = runtime.queries.captureRead!.bind(runtime.queries)
    vi.spyOn(runtime.queries, 'captureApplication').mockImplementation(options => {
      const snapshot = captureApplication(options)
      return { ...snapshot, transactionAt(index) { publicationReads.push(index); return snapshot.transactionAt(index) } }
    })
    vi.spyOn(runtime.queries, 'captureRead').mockImplementation(options => {
      const read = captureRead(options)
      return { ...read, transactionAt(index) { viewReads.push(index); return read.transactionAt(index) } }
    })
    const b = await createPeerReplica({ authority: await f.registry.read(), device: f.b, store,
      storageId: f.b.publicKey, materializer: runtime, epochKeys: f.keys })
    opened.push(b)
    await b.ingest(await a.exportCommands())
    expect(publicationReads).toHaveLength(4)
    expect(outcomeLookups).not.toHaveBeenCalled()
    expect(await b.operation('entry-3', f.a.publicKey)).toMatchObject({ outcome: 'rejected', rejectionCode: 'profile:sql-disabled' })

    publicationReads.length = 0
    await b.ingest([])
    expect(await materialize.mock.results.at(-1)!.value).toBeNull()
    expect(publicationReads).toHaveLength(4)
    expect(outcomeLookups).not.toHaveBeenCalled()

    const captured = await b.capture()
    try {
      expect(captured.read.orderLength).toBe(4)
      expect(viewReads).toHaveLength(0)
      expect(publicationReads).toHaveLength(4)
      expect(outcomeLookups).not.toHaveBeenCalled()
      const window = [2, 3].map(index => captured.read.transactionAt(index)!)
      expect(viewReads).toHaveLength(2)
      expect(window.map(({ outcome, rejectionCode, failingStatementIndex }) => ({ outcome, rejectionCode, failingStatementIndex }))).toEqual([
        { outcome: 'accepted', rejectionCode: null, failingStatementIndex: null },
        { outcome: 'rejected', rejectionCode: 'profile:sql-disabled', failingStatementIndex: 0 },
      ])
    } finally { captured.release() }
  })
  it('recovers rejection details from the applied snapshot when its result journal write was lost', async () => {
    const f = await fixture(), retained = new MemoryPeerStore()
    let failResult = false
    const store: PeerStore = { get: key => retained.get(key), async put(key, value) {
      if (failResult && key.includes('/result/')) { failResult = false; throw new Error('RESULT_WRITE_LOST') }
      await retained.put(key, value)
    } }
    const a = await f.open(f.a, store), attempt = await a.prepare({ operationId: 'rejected', program: program('SELECT 1') })
    failResult = true
    await expect(a.order(attempt)).rejects.toThrow('RESULT_WRITE_LOST')
    await a.close()

    const runtime = await createEventMaterializationRuntime({ store, namespace: 'test', historyProfile: 'peer-generation-v1' })
    const outcomeLookups = vi.spyOn(runtime.queries, 'outcome'), materialize = vi.spyOn(runtime.coordinator, 'materialize')
    const reopened = await createPeerReplica({ authority: await f.registry.read(), device: f.a, store,
      storageId: f.a.publicKey, materializer: runtime, epochKeys: f.keys })
    opened.push(reopened)
    expect(await materialize.mock.results.at(-1)!.value).toBeNull()
    expect(outcomeLookups).not.toHaveBeenCalled()
    expect(await reopened.operation('rejected')).toMatchObject({ status: 'applied', outcome: 'rejected', rejectionCode: 'profile:sql-disabled' })
  })
  it('adopts an older complete prefix, seeds a fresh peer and quarantines the returning suffix', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const one = await a.prepare({ operationId: 'one', program: event('one') })
    await a.order(one); await b.ingest(await a.exportCommands())
    const inheritedView = await b.capture(); const inheritedRevision = inheritedView.revision; inheritedView.release()
    const two = await a.prepare({ operationId: 'two', program: event('two') })
    await a.order(two)
    const held = await a.capture(), oldRevision = held.revision, oldEntry = held.read.transactionAt(1)
    const base = await b.recoveryPoint(), g2 = await f.select(f.b, base, 'second')
    await b.adopt(await f.registry.read())
    await expect(b.exportCommands({ at: inheritedRevision })).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
    const three = await b.prepare({ operationId: 'three', program: event('three') }); await b.order(three)
    const c = await f.open(f.c)
    await expect(c.capture()).rejects.toThrow('PEER_RECOVERING')
    await c.synchronize(await f.registry.read(), await b.exportCommands())
    expect((await c.operation('one', f.a.publicKey))?.status).toBe('applied')
    const notice = await a.synchronize(await f.registry.read(), await b.exportCommands())
    expect(notice?.abandoned).toContainEqual(expect.objectContaining({ operationId: 'two', status: 'abandoned' }))
    expect(notice?.unknownLoss, 'known abandoned work does not prove that no unseen suffix exists').toBe(true)
    expect((await a.operation('two'))?.status).toBe('abandoned')
    expect(held.read.orderLength).toBe(2)
    expect(held.read.transactionAt(1)).toEqual(oldEntry)
    held.release()
    await expect(a.prepare({ operationId: 'stale-view', program: event('stale'), basedOn: oldRevision })).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
    await expect(b.order(two)).rejects.toThrow('PEER_ATTEMPT_NEEDS_REAPPLY')
    expect(await b.order(one)).toEqual((await b.exportCommands())[0])
    const reapplied = await a.prepare({ operationId: 'two-reapplied', program: event('two'), reapplyOf: two.id })
    await b.order(reapplied); await a.ingest(await b.exportCommands())
    expect(await a.operation('two-reapplied')).toMatchObject({ status: 'applied', generation: g2.id })
    expect((await a.operation('two'))?.status).toBe('abandoned')
    const g3 = await f.select(f.c, await b.recoveryPoint(), 'third')
    await c.synchronize(await f.registry.read(), await b.exportCommands())
    expect(c.generation.id).toBe(g3.id)
    const before = (await c.exportCommands()).map(value => value.attempt.id)
    expect(before).not.toContain(two.id); expect(before).toContain(reapplied.id)
  })
  it('reopens a locally committed receipt after its acknowledgment is lost', async () => {
    const f = await fixture(), retained = new MemoryPeerStore()
    let fail = false
    const store: PeerStore = { get: key => retained.get(key), async put(key, value) { await retained.put(key, value); if (fail && key.includes('/head/')) { fail = false; throw new Error('LOST_STORAGE_ACK') } } }
    const a = await f.open(f.a, store), attempt = await a.prepare({ operationId: 'once', program: event('once') })
    fail = true
    await expect(a.order(attempt)).rejects.toThrow('LOST_STORAGE_ACK')
    await a.close()
    const reopened = await f.open(f.a, store)
    const exact = await reopened.prepare({ operationId: 'once', program: event('once') })
    expect(exact).toEqual(attempt)
    expect((await reopened.order(exact)).receipt.payload.sequence).toBe(1)
    expect(await reopened.operation('once')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(await reopened.exportCommands()).toHaveLength(1)
  })
  it('durably fences learned restrictive controls while the replacement prefix is incomplete', async () => {
    const f = await fixture(), oldAuthority = await f.registry.read(), retained = new MemoryPeerStore()
    const a = await f.open(f.a), b = await f.open(f.b); let c = await f.open(f.c, retained)
    for (let index = 0; index < 3; index++) await a.order(await a.prepare({ operationId: `before-${index}`, program: event(`before-${index}`) }))
    await b.ingest(await a.exportCommands()); await c.ingest(await a.exportCommands({ limit: 1 }))
    const held = await c.capture()
    await c.prepare({ operationId: 'saved-before-revocation', program: event('draft') })
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: f.control.payload.grants.map(grant => grant.publicKey === f.c.publicKey ? { ...grant, writer: false, coordinator: false, dataRole: null } : grant) }, f.host)
    const generation = await f.registry.select(await signTransitionRequest({ applicationId: a.descriptor.applicationId,
      profile: a.descriptor.profile, policy: a.descriptor.policy, transitionId: 'restrict-while-behind', expectedGeneration: a.generation.id,
      requester: f.a.publicKey, coordinator: f.b.publicKey, controlRevision: 1, reason: 'control-change', base: await b.recoveryPoint() }, f.a), { control })
    const selected = await f.registry.read(); await b.adopt(selected)
    await expect(c.adopt(selected)).rejects.toThrow('PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(c.generation.id).toBe(generation.id)
    expect(c.authority.controls[1]!.payload.grants.find(grant => grant.publicKey === f.c.publicKey)?.writer).toBe(false)
    await expect(c.capture()).rejects.toThrow('PEER_RECOVERING')
    await expect(c.operation('saved-before-revocation')).rejects.toThrow('PEER_RECOVERING')
    await expect(c.prepare({ operationId: 'revoked', program: event('forbidden') })).rejects.toThrow('PEER_RECOVERING')
    expect(held.read.orderLength).toBe(1); held.release()
    await c.close(); c = await f.open(f.c, retained, oldAuthority)
    expect(c.generation.id).toBe(generation.id)
    const notice = await c.synchronize(selected, await b.exportCommands())
    expect(notice).toMatchObject({ previousGeneration: oldAuthority.generations[0]!.id, generation: generation.id, unknownLoss: true })
    expect((await c.operation('saved-before-revocation'))?.status).toBe('needsReapply')
    await expect(c.prepare({ operationId: 'still-revoked', program: event('forbidden') })).rejects.toThrow('PEER_AUTHOR_FORBIDDEN')
    await c.close(); c = await f.open(f.c, retained, oldAuthority)
    expect(c.inspectRecovery().filter(value => value.generation === generation.id)).toHaveLength(1)
  })
  it('rejects missing bodies, gaps, wrong signatures and altered operation reuse', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = await a.prepare({ operationId: 'stable', program: event('one') }); await a.order(first)
    await a.order(await a.prepare({ operationId: 'other', program: event('two') }))
    const commands = await a.exportCommands()
    await expect(b.ingest([commands[1]!])).rejects.toThrow('PEER_HISTORY_GAP')
    const broken = structuredClone(commands[0]!); (broken.attempt.payload as { ciphertext: string }).ciphertext = '00'.repeat(32)
    await expect(b.ingest([broken])).rejects.toThrow('PEER_ATTEMPT_ID_INVALID')
    await expect(a.prepare({ operationId: 'stable', program: event('changed') })).rejects.toThrow('PEER_OPERATION_ID_REUSED')
    expect((await b.recoveryPoint()).point.sequence).toBe(0)
  })
  it('detects coordinator equivocation and fences further ordering', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const attempt = await a.prepare({ operationId: 'one', program: event('one') }), ordered = await a.order(attempt)
    await b.ingest([ordered])
    const payload = { ...ordered.receipt.payload, previousRoot: 'ff'.repeat(32) }
    const forged = { attempt, receipt: { ...await signPeerValue('chronolog/peer-generation/order/v1', payload, f.a), root: await peerDigest(['chronolog/peer-generation/order/v1', payload]) } }
    await expect(a.ingest([forged])).rejects.toThrow('PEER_COORDINATOR_EQUIVOCATION')
    const another = await a.prepare({ operationId: 'two', program: event('two') })
    await expect(a.order(another)).rejects.toThrow('PEER_COORDINATOR_FENCED')
  })
  it('retains bounded pages outside the serial lock and publishes only the complete captured target', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await a.order(await a.prepare({ operationId: 'one', program: event('one') }))
    const first = a.revision
    await a.order(await a.prepare({ operationId: 'two', program: event('two') }))
    const commands = await a.exportCommands(), target = a.revision, before = b.revision
    let observed = 0
    async function* pages() {
      for (const command of commands) {
        // A network source may need this replica's ranges before returning its
        // next page. Holding the serial lock across next() would deadlock here.
        const view = await b.capture()
        try { expect(view.revision).toEqual(before); expect(view.read.orderLength).toBe(0); observed++ }
        finally { view.release() }
        yield [command]
      }
    }
    await b.synchronize(a.authority, pages(), { at: target })
    expect(observed).toBe(2)
    expect(b.revision.point).toEqual(target.point)
    const coverage = await b.retainedCoverage(first.point)
    expect(coverage.payload.point).toEqual(first.point)
    await a.observeCoverage(coverage)
    expect(a.shared(first.point)).toHaveLength(1)
    expect(a.shared(target.point)).toHaveLength(0)
  })
  it('rejects an incomplete captured tail and retries exactly from retained pages', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await a.order(await a.prepare({ operationId: 'one', program: event('one') }))
    await a.order(await a.prepare({ operationId: 'two', program: event('two') }))
    const commands = await a.exportCommands(), target = a.revision, before = b.revision
    async function* incomplete() { yield commands.slice(0, 1) }
    await expect(b.synchronize(a.authority, incomplete(), { at: target })).rejects.toThrow('PEER_REPLICATION_TARGET_INCOMPLETE')
    expect(b.revision).toEqual(before)
    async function* complete() { for (const command of commands) yield [command] }
    await b.synchronize(a.authority, complete(), { at: target })
    expect(await b.exportCommands()).toEqual(commands)
    expect(b.revision.point).toEqual(target.point)
  })
  it('does not publish an older captured generation after authority changes between pages', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const base = await b.recoveryPoint()
    await a.order(await a.prepare({ operationId: 'one', program: event('one') }))
    await a.order(await a.prepare({ operationId: 'two', program: event('two') }))
    const commands = await a.exportCommands(), target = a.revision
    let generation = ''
    async function* pages() {
      yield commands.slice(0, 1)
      generation = (await f.select(f.b, base, 'during-transfer')).id
      await b.adopt(await f.registry.read())
      yield commands.slice(1)
    }
    await expect(b.synchronize(a.authority, pages(), { at: target })).rejects.toThrow('PEER_AUTHORITY_REGRESSION')
    expect(b.revision.generation).toBe(generation)
    expect(b.revision.point.sequence).toBe(0)
    expect(await b.exportCommands()).toEqual([])
  })
  it('does not count a second tab on the same storage owner as a separate copy', async () => {
    const f = await fixture(), a = await f.open(f.a, undefined, undefined, 'same-device'), b = await f.open(f.b, undefined, undefined, 'same-device')
    await a.observeCoverage(await b.retainedCoverage())
    expect(a.shared()).toHaveLength(0)
  })
  it('bounds retention evidence by current peer identity and refuses stale or revoked claims', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const old = await b.retainedCoverage()
    await a.order(await a.prepare({ operationId: 'retained', program: event('retained') }))
    await b.ingest(await a.exportCommands())
    const latest = await b.retainedCoverage()
    for (let index = 0; index < 32; index++) {
      await a.observeCoverage(await signPeerValue('chronolog/peer-generation/coverage/v1',
        { ...latest.payload, storageId: `claimed-store-${index}` }, f.b))
    }
    expect(a.shared()).toHaveLength(1)
    await a.observeCoverage(old)
    expect(a.shared()).toHaveLength(1)
    expect(a.shared()[0]?.payload.point).toEqual(latest.payload.point)

    const key = crypto.getRandomValues(new Uint8Array(32)); f.keys.set(1, key)
    const next = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      epoch: 1, keyDigest: await bytesDigest(key), grants: f.control.payload.grants.filter(grant => grant.publicKey !== f.b.publicKey) }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.descriptor.applicationId, profile: a.descriptor.profile,
      policy: a.descriptor.policy, expectedGeneration: a.generation.id, coordinator: f.a.publicKey, requester: f.a.publicKey,
      controlRevision: 1, base: await a.recoveryPoint(), transitionId: 'revoke-reader', reason: 'control-change' }, f.a), { control: next })
    await a.adopt(await f.registry.read())
    expect(a.shared()).toEqual([])
    await expect(a.observeCoverage(latest)).rejects.toThrow('PEER_COVERAGE_INVALID')
    const revoked = await signPeerValue('chronolog/peer-generation/coverage/v1',
      { ...latest.payload, generation: a.generation.id, point: a.revision.point }, f.b)
    await expect(a.observeCoverage(revoked)).rejects.toThrow('PEER_COVERAGE_INVALID')
  })
})

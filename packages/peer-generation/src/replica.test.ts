import { afterEach, describe, expect, it, vi } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { decodeTransactionCore, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryBytesStore, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type BytesStore, type PrefixProof,
} from './index.js'
import { bytesToHex, encodePeerValue, signPeerValue } from './codec.js'

const opened: PeerReplica[] = []
afterEach(async () => { for (const peer of opened.splice(0)) await peer.close() })
async function fixture() {
  const [host, a, b, c] = await Promise.all(Array.from({ length: 4 }, () => createPeerIdentity())) as [PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity]
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'replica-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: '11'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a, publisher: false, dataRole: 'member' as const })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  const select = async (who: PeerIdentity, base: PrefixProof | null, id: string) => {
    const authority = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
      profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: id,
      expectedGeneration: authority.generations.at(-1)?.id ?? null, coordinator: who.publicKey,
      requester: who.publicKey, controlRevision: 0, reason: base === null ? 'create' : 'takeover', base }, who))
  }
  await select(a, null, 'initial')
  const materializers = new Map<PeerReplica, Awaited<ReturnType<typeof createEventMaterializationRuntime>>>()
  const open = async (identity: PeerIdentity, store: BytesStore = new MemoryBytesStore(), authority?: AuthorityBundle, storageId = identity.publicKey) => {
    const materializer = await createEventMaterializationRuntime({ store, namespace: 'test' })
    const peer = await createPeerReplica({ authority: authority ?? await registry.read(), device: identity, store, storageId, materializer, epochKeys: keys })
    opened.push(peer); materializers.set(peer, materializer); return peer
  }
  return { host, a, b, c, key, keys, control, registry, select, open, materializers }
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
      const transactions = Array.from({ length: av.read.orderLength }, (_, index) => av.read.transactionAt(index)!)
      expect(transactions).toEqual(Array.from({ length: bv.read.orderLength }, (_, index) => bv.read.transactionAt(index)))
      expect(transactions.map(value => decodeTransactionCore(value.canonicalCandidate).authorTimestampMs)).toEqual([500n, 100n])
    } finally { av.release(); bv.release() }
    expect(await a.order(first)).toEqual((await a.exportCommands())[0])
    expect((await a.exportCommands()).length).toBe(2)
    await b.observeCoverage(await a.retainedCoverage())
    expect(b.shared()).toHaveLength(1)
  })
  it('captures views and exports bounded ranges without scanning the growing selected history', async () => {
    const f = await fixture(), store = new MemoryBytesStore(), a = await f.open(f.a, store)
    const append = async (from: number, through: number) => {
      for (let index = from; index < through; index++) await a.order(await a.prepare({ operationId: `event-${index}`, program: event(String(index)) }))
    }
    const measure = async (peer: PeerReplica, offset: number, limit: number) => {
      const outcomes = vi.spyOn(f.materializers.get(peer)!.queries, 'outcome'), indexedReads = vi.spyOn(Map.prototype, 'get')
      try {
        const captured = await peer.capture()
        try {
          expect(outcomes).not.toHaveBeenCalled()
          expect(indexedReads.mock.calls.filter(([key]) => typeof key === 'number')).toHaveLength(0)
          expect(captured.read.transactionAt(offset)).not.toBeNull()
        } finally { captured.release() }
        indexedReads.mockClear()
        const page = await peer.exportCommands({ offset, limit })
        const scannedRecords = indexedReads.mock.calls.filter(([key]) => typeof key === 'number').length
        return { page, scannedRecords }
      } finally { outcomes.mockRestore(); indexedReads.mockRestore() }
    }
    await append(0, 8)
    const base = await a.recoveryPoint(), small = await measure(a, 6, 2)
    await append(8, 64)
    const large = await measure(a, 62, 2), old = await a.capture()
    expect(large.scannedRecords).toBe(small.scannedRecords)
    expect(large.scannedRecords).toBeLessThanOrEqual(4)
    expect(large.page.map(value => value.attempt.payload.header.operationId)).toEqual(['event-62', 'event-63'])
    try {
      await f.select(f.a, base, 'recover-short-prefix'); await a.adopt(await f.registry.read())
      await append(64, 66)
      const recovered = await measure(a, 7, 3)
      expect(recovered.scannedRecords).toBeLessThanOrEqual(8)
      expect(recovered.page.map(value => value.attempt.payload.header.operationId)).toEqual(['event-7', 'event-64', 'event-65'])
      expect(old.read.orderLength).toBe(64)
      expect(decodeTransactionCore(old.read.transactionAt(63)!.canonicalCandidate).operationId).toBe('event-63')
      await a.close()
      const reopened = await f.open(f.a, store), afterReopen = await measure(reopened, 7, 3)
      expect(afterReopen.page).toEqual(recovered.page)
      expect(afterReopen.scannedRecords).toBeLessThanOrEqual(8)
    } finally { old.release() }
  }, 30_000)
  it('adopts an older complete prefix, seeds a fresh peer and quarantines the returning suffix', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const one = await a.prepare({ operationId: 'one', program: event('one') })
    await a.order(one); await b.ingest(await a.exportCommands())
    const inheritedView = await b.capture(); const inheritedRevision = inheritedView.revision; inheritedView.release()
    const two = await a.prepare({ operationId: 'two', program: event('two') })
    await a.order(two)
    const held = await a.capture(), oldRevision = held.revision
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
    expect(held.read.orderLength).toBe(2); held.release()
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
    const f = await fixture(), retained = new MemoryBytesStore()
    let fail = false
    const store: BytesStore = { get: key => retained.get(key), async put(key, value) { await retained.put(key, value); if (fail && key.includes('/head/')) { fail = false; throw new Error('LOST_STORAGE_ACK') } } }
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
    const f = await fixture(), oldAuthority = await f.registry.read(), retained = new MemoryBytesStore()
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
  it('persists an incomplete selection and its abandoned-operation recovery across reopen', async () => {
    const f = await fixture(), store = new MemoryBytesStore(), a = await f.open(f.a, store), b = await f.open(f.b)
    const inherited = await a.prepare({ operationId: 'inherited', program: event('inherited') })
    await a.order(inherited); await b.ingest(await a.exportCommands())
    const tail = await a.prepare({ operationId: 'tail', program: event('tail') })
    await a.order(tail)
    const oldAuthority = a.authority, previousResult = await a.operation('tail'), held = await a.capture()
    await f.select(f.b, await b.recoveryPoint(), 'survivor')
    await b.adopt(await f.registry.read())
    await b.order(await b.prepare({ operationId: 'next-generation', program: event('next-generation') }))
    const surviving = await b.exportCommands()
    const selected = await f.select(f.c, await b.recoveryPoint(), 'next-survivor'), authority = await f.registry.read()

    expect(await a.receiveHistory(authority, [])).toEqual({ ready: false, recovery: null })
    expect(a.generation.id).toBe(selected.id)
    expect(a.ready).toBe(false)
    expect(() => a.revision).toThrow('PEER_RECOVERING')
    await expect(a.capture()).rejects.toThrow('PEER_RECOVERING')
    await expect(a.operation('tail')).rejects.toThrow('PEER_RECOVERING')
    expect((await a.exportCommands({ limit: 1 })).map(value => value.attempt.id)).toEqual([inherited.id])
    expect(a.retainedPoint).toEqual({ generation: inherited.payload.header.generation, sequence: 1, root: surviving[0]!.receipt.root })
    expect((await a.retainedCoverage(a.retainedPoint!)).payload.point).toEqual(a.retainedPoint)
    await expect(a.retainedCoverage({ generation: surviving[1]!.receipt.payload.generation, sequence: 1, root: surviving[1]!.receipt.root })).rejects.toThrow('PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(held.read.orderLength).toBe(2); held.release()
    await a.close()

    // The stale bootstrap hint cannot roll back the durably accepted selection.
    const reopened = await f.open(f.a, store, oldAuthority)
    expect(reopened.generation.id).toBe(selected.id)
    expect(reopened.ready).toBe(false)
    const received = await reopened.receiveHistory(authority, surviving)
    expect(received.ready).toBe(true)
    expect(received.recovery).toMatchObject({ previousGeneration: oldAuthority.generations[0]!.id, generation: selected.id, unknownLoss: true })
    expect(received.recovery?.abandoned).toContainEqual(expect.objectContaining({ operationId: 'tail', status: 'abandoned', previous: previousResult }))
    expect((await reopened.operation('inherited'))?.status).toBe('applied')
    expect((await reopened.operation('tail'))?.status).toBe('abandoned')
    expect((await reopened.receiveHistory(authority, [])).recovery).toBeNull()
    expect(reopened.inspectRecovery()).toHaveLength(1)
  })
  it('continues a retained range across an empty selected generation', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const empty = await a.recoveryPoint()
    await f.select(f.b, empty, 'empty-parent')
    await b.adopt(await f.registry.read())
    const command = await b.order(await b.prepare({ operationId: 'child', program: event('child') }))
    expect(await b.exportCommands({ after: empty.point, limit: 1 })).toEqual([command])
  })
  it('does not duplicate a durable recovery notice after its storage acknowledgement is lost', async () => {
    const f = await fixture(), durable = new MemoryBytesStore()
    let loseAck = false
    const store: BytesStore = { get: key => durable.get(key), async put(key, value) {
      await durable.put(key, value)
      if (loseAck && key.endsWith('/recoveries')) { loseAck = false; throw new Error('LOST_RECOVERY_ACK') }
    } }
    const a = await f.open(f.a, store), b = await f.open(f.b), oldAuthority = a.authority
    await a.order(await a.prepare({ operationId: 'discarded', program: event('discarded') }))
    const original = await a.operation('discarded')
    const selected = await f.select(f.b, await b.recoveryPoint(), 'notice-retry')
    loseAck = true
    await expect(a.receiveHistory(await f.registry.read(), [])).rejects.toThrow('LOST_RECOVERY_ACK')
    await a.close()
    const reopened = await f.open(f.a, store, oldAuthority)
    expect(reopened.generation.id).toBe(selected.id)
    expect(reopened.inspectRecovery()).toHaveLength(1)
    expect(await reopened.operation('discarded')).toMatchObject({ status: 'abandoned', previous: original })
    expect((await reopened.receiveHistory(await f.registry.read(), [])).recovery).toBeNull()
    expect(reopened.inspectRecovery()).toHaveLength(1)
  })
  it('keeps at most one retained coverage claim per authenticated signer', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), clone = await f.open(f.b, undefined, undefined, 'renamed-store')
    await a.observeCoverage(await b.retainedCoverage())
    await a.observeCoverage(await clone.retainedCoverage())
    expect(a.shared()).toHaveLength(1)
    expect(a.shared()[0]?.payload.peer).toBe(f.b.publicKey)
  })
  it('bounds exported command pages before copying their encrypted bodies', async () => {
    const f = await fixture(), a = await f.open(f.a)
    await a.order(await a.prepare({ operationId: 'first', program: event('first') }))
    await a.order(await a.prepare({ operationId: 'second', program: event('second') }))
    const commands = await a.exportCommands(), firstBytes = encodePeerValue(commands[0]!).byteLength
    expect(await a.exportCommands({ limit: 2, maxBytes: firstBytes })).toEqual([commands[0]])
    await expect(a.exportCommands({ maxBytes: firstBytes - 1 })).rejects.toThrow('PEER_RANGE_RECORD_TOO_LARGE')
    await expect(a.exportCommands({ maxBytes: 0 })).rejects.toThrow('PEER_RANGE_BYTES_INVALID')
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

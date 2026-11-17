import { describe, expect, it } from 'vitest'
import { bytesToHex, emit, encodeTransactionCore, program, transactionDigest, utf8, type ChangeProgram, type TransactionCore } from '@chronolog/protocol'
import { createEventMaterializationRuntime } from './events.js'
import type { ReplayProposal } from './types.js'
import type { MaterializedApplicationSnapshot } from './runtime.js'

function snapshotData(snapshot: MaterializedApplicationSnapshot) {
  return { view: snapshot.view, revision: snapshot.revision, orderLength: snapshot.orderLength,
    finalRevision: snapshot.finalRevision, finalOrderLength: snapshot.finalOrderLength,
    transactions: Array.from({ length: snapshot.orderLength }, (_, index) => snapshot.transactionAt(index)) }
}

function store() {
  const values = new Map<string, Uint8Array>()
  return { fail: false, async get(key: string) { return values.get(key)?.slice() ?? null },
    async put(key: string, value: Uint8Array) { if (this.fail) throw new Error('power loss'); values.set(key, value.slice()) } }
}
async function proposal(digest: Uint8Array, sequence: number, change: ChangeProgram, operationId = `op-${sequence}`): Promise<ReplayProposal> {
  const core: TransactionCore = { operationId, groupId: new Uint8Array(32), membershipRevision: new Uint8Array(32), validationPolicy: new Uint8Array(32),
    authorId: new Uint8Array(32), authorTimestampMs: BigInt(sequence), nonce: new Uint8Array(32).fill(sequence), executionManifestDigest: digest, program: change }
  const canonicalCandidate = encodeTransactionCore(core), candidateDigest = await transactionDigest(canonicalCandidate)
  return { txId: utf8(`tx_${bytesToHex(candidateDigest)}`), candidateDigest, canonicalCandidate, core }
}
describe('SQL-free durable event execution', () => {
  it('reopens final outcomes and deterministic operation conflicts without an SQL runtime', async () => {
    const bytes = store()
    const first = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    const digest = first.queries.executionManifestDigest
    const one = await proposal(digest, 1, program(emit('chat', 'one')), 'same')
    const conflict = await proposal(digest, 2, program(emit('chat', 'changed')), 'same')
    const sql = await proposal(digest, 3, program('SELECT 1', emit('chat', 'suppressed')))
    await first.coordinator.materialize([one, conflict, sql])
    await first.coordinator.publishFinal!(3)
    expect(first.queries.outcome(one.txId)?.outcome).toBe('accepted')
    expect(first.queries.outcome(conflict.txId)?.rejectionCode).toBe('operation_conflict')
    expect(first.queries.outcome(sql.txId)?.rejectionCode).toBe('profile:sql-disabled')
    await first.close()
    const reopened = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    expect(reopened.queries.finalOrderLength).toBe(3)
    expect(reopened.queries.outcome(one.txId)?.outcome).toBe('accepted')
    expect(() => reopened.queries.localSql('SELECT 1')).toThrow('SQL_DISABLED')
    await expect(reopened.coordinator.materialize([conflict, sql])).rejects.toThrow('FINAL_PREFIX_CHANGED')
  })
  it('never exposes an outcome or final cursor ahead of a failed durable write', async () => {
    const bytes = store()
    let runtime = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    const entry = await proposal(runtime.queries.executionManifestDigest, 1, program(emit('chat', 'one')))
    bytes.fail = true
    await expect(runtime.coordinator.materialize([entry])).rejects.toThrow('power loss')
    expect(runtime.queries.orderLength).toBe(0)
    expect(runtime.queries.outcome(entry.txId)).toBeNull()
    bytes.fail = false
    await expect(runtime.coordinator.materialize([entry])).rejects.toThrow('EVENT_EXECUTION_CLOSED')
    runtime = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    await runtime.coordinator.materialize([entry])
    bytes.fail = true
    await expect(runtime.coordinator.publishFinal!(1)).rejects.toThrow('power loss')
    expect(runtime.queries.finalOrderLength).toBe(0)
  })

  it('cannot overwrite a committed durable final prefix after its reply was lost', async () => {
    const bytes = store()
    let loseReply = false
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      await bytes.put(key, value)
      if (loseReply) { loseReply = false; throw new Error('lost write acknowledgment') }
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'lost-final-reply' })
    const digest = runtime.queries.executionManifestDigest
    const late = await proposal(digest, 20, program(emit('chat', 'later')))
    const early = await proposal(digest, 10, program(emit('chat', 'earlier')))
    await runtime.coordinator.materialize([late])
    loseReply = true
    await expect(runtime.coordinator.publishFinal!(1)).rejects.toThrow('lost write acknowledgment')
    expect(runtime.queries.finalOrderLength).toBe(0)
    await expect(runtime.coordinator.materialize([early, late])).rejects.toThrow('EVENT_EXECUTION_CLOSED')
    const reopened = await createEventMaterializationRuntime({ store: storage, namespace: 'lost-final-reply' })
    expect(reopened.queries.finalOrderLength).toBe(1)
    expect(reopened.queries.orderLength).toBe(1)
    await expect(reopened.coordinator.materialize([early, late])).rejects.toThrow('FINAL_PREFIX_CHANGED')
  })

  it('recovers applied identities before retrying after a lost materialization reply', async () => {
    const bytes = store()
    let loseReply = true
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      await bytes.put(key, value)
      if (loseReply && key === 'event-execution/lost-order-reply') { loseReply = false; throw new Error('lost write acknowledgment') }
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'lost-order-reply' })
    const digest = runtime.queries.executionManifestDigest
    const one = await proposal(digest, 10, program(emit('chat', 'one')))
    const two = await proposal(digest, 20, program(emit('chat', 'two')))
    await expect(runtime.coordinator.materialize([one])).rejects.toThrow('lost write acknowledgment')
    await expect(runtime.coordinator.materialize([two])).rejects.toThrow('EVENT_EXECUTION_CLOSED')
    const reopened = await createEventMaterializationRuntime({ store: storage, namespace: 'lost-order-reply' })
    expect(reopened.queries.orderLength).toBe(1)
    await expect(reopened.coordinator.materialize([one])).resolves.toBeNull()
    await reopened.coordinator.materialize([one, two])
    expect(reopened.queries.orderLength).toBe(2)
  })

  it('keeps a body written before a lost acknowledgment outside the published history until exact retry', async () => {
    const bytes = store(); let loseReply = true
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      await bytes.put(key, value)
      if (loseReply && key.includes('/node/')) { loseReply = false; throw new Error('lost body acknowledgment') }
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'body-before-head' })
    const entry = await proposal(runtime.queries.executionManifestDigest, 1, program(emit('chat', 'durable body')))
    await expect(runtime.coordinator.materialize([entry])).rejects.toThrow('lost body acknowledgment')
    expect(runtime.queries.orderLength).toBe(0)
    const reopened = await createEventMaterializationRuntime({ store: storage, namespace: 'body-before-head' })
    expect(reopened.queries.orderLength).toBe(0)
    await reopened.coordinator.materialize([entry])
    expect(reopened.queries.outcome(entry.txId)?.outcome).toBe('accepted')
  })

  it('writes only new immutable records and a bounded head while history grows', async () => {
    const bytes = store(), writes: { key: string; bytes: number }[] = []
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      writes.push({ key, bytes: value.length }); await bytes.put(key, value)
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'bounded-growth' })
    const history: ReplayProposal[] = []
    for (let index = 0; index < 32; index++) {
      history.push(await proposal(runtime.queries.executionManifestDigest, index, program(emit('chat', 'x'.repeat(1024)))))
      await runtime.coordinator.materialize(history)
    }
    const records = writes.filter(write => write.key.includes('/node/')), heads = writes.filter(write => !write.key.includes('/node/'))
    expect(records).toHaveLength(history.length)
    expect(new Set(records.map(write => write.key)).size).toBe(history.length)
    expect(heads).toHaveLength(history.length)
    expect(Math.max(...heads.map(write => write.bytes))).toBeLessThan(256)
    const bodyBytes = history.reduce((total, entry) => total + entry.canonicalCandidate.length, 0)
    expect(writes.reduce((total, write) => total + write.bytes, 0)).toBeLessThan(bodyBytes * 1.5)
    await runtime.coordinator.materialize(history.slice(0, 12))
    const reopened = await createEventMaterializationRuntime({ store: storage, namespace: 'bounded-growth' })
    expect(reopened.queries.orderLength).toBe(12)
    expect(reopened.queries.outcome(history[12]!.txId)).toBeNull()
    expect(records).toHaveLength(32)
  }, 30_000)

  it('replays a provisional suffix on late insertion and retains its exact outcomes after reopen', async () => {
    const bytes = store(), runtime = await createEventMaterializationRuntime({ store: bytes, namespace: 'replay' })
    const digest = runtime.queries.executionManifestDigest
    const late = await proposal(digest, 20, program(emit('chat', 'later')), 'same-operation')
    const early = await proposal(digest, 10, program(emit('chat', 'earlier')), 'same-operation')
    await runtime.coordinator.materialize([late])
    expect(runtime.queries.outcome(late.txId)?.outcome).toBe('accepted')
    const held = runtime.queries.captureRead!({ view: 'local' })
    const before = runtime.queries.captureApplication({ view: 'local' })
    expect(snapshotData(held)).toEqual(snapshotData(before))
    expect(snapshotData(runtime.queries.captureApplication())).toEqual(snapshotData(before))
    expect(snapshotData(runtime.queries.captureApplication({ view: 'final' }))).toEqual({
      view: 'final', revision: 0n, orderLength: 0, finalRevision: 0n, finalOrderLength: 0, transactions: [],
    })
    const changed = await runtime.coordinator.materialize([early, late])
    expect(changed?.revision.replayFromIndex).toBe(0)
    expect(changed?.revision.outcomeChanges).toContainEqual({ txId: late.txId, previous: 'accepted', current: 'rejected',
      previousRejectionCode: null, currentRejectionCode: 'operation_conflict' })
    expect(snapshotData(held)).toEqual(snapshotData(before))
    expect(snapshotData(before).transactions).toEqual([{ txId: late.txId, canonicalCandidate: late.canonicalCandidate, outcome: 'accepted' }])
    const applied = runtime.queries.captureApplication({ view: 'local' })
    expect(snapshotData(applied)).toMatchObject({ revision: 2n, orderLength: 2, finalRevision: 0n, finalOrderLength: 0,
      transactions: [
        { txId: early.txId, canonicalCandidate: early.canonicalCandidate, outcome: 'accepted' },
        { txId: late.txId, canonicalCandidate: late.canonicalCandidate, outcome: 'rejected' },
      ] })
    const detached = applied.transactionAt(0)!
    detached.txId.fill(0)
    detached.canonicalCandidate.fill(0)
    expect(applied.transactionAt(0))
      .toEqual({ txId: early.txId, canonicalCandidate: early.canonicalCandidate, outcome: 'accepted' })
    await runtime.coordinator.publishFinal!(2)
    const final = runtime.queries.captureApplication({ view: 'final' })
    expect(final).toMatchObject({ view: 'final', revision: 1n, orderLength: 2, finalRevision: 1n, finalOrderLength: 2 })
    expect(snapshotData(held)).toEqual(snapshotData(before))
    held.release()
    await runtime.close()
    const reopened = await createEventMaterializationRuntime({ store: bytes, namespace: 'replay' })
    expect(reopened.queries.outcome(early.txId)?.outcome).toBe('accepted')
    expect(reopened.queries.outcome(late.txId)?.rejectionCode).toBe('operation_conflict')
    expect(reopened.queries.finalOrderLength).toBe(2)
    expect(snapshotData(reopened.queries.captureApplication({ view: 'final' }))).toEqual(snapshotData(final))
    await reopened.close()
  })

  it('owns queued inputs and keeps returned outcome identities detached from internal state', async () => {
    const bytes = store()
    let unblock!: () => void, didBlock!: () => void
    const blocked = new Promise<void>(resolve => { didBlock = resolve })
    const gate = new Promise<void>(resolve => { unblock = resolve })
    let delay = true
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      if (delay) { delay = false; didBlock(); await gate }
      await bytes.put(key, value)
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'owned-inputs' })
    const digest = runtime.queries.executionManifestDigest
    const one = await proposal(digest, 10, program(emit('chat', 'one')))
    const two = await proposal(digest, 20, program(emit('chat', 'two')))
    const originalTwoId = two.txId.slice()
    const first = runtime.coordinator.materialize([one])
    await blocked
    expect(snapshotData(runtime.queries.captureApplication({ view: 'local' }))).toEqual({
      view: 'local', revision: 0n, orderLength: 0, finalRevision: 0n, finalOrderLength: 0, transactions: [],
    })
    const second = runtime.coordinator.materialize([one, two])
    two.txId.fill(0)
    unblock()
    await first
    const result = await second
    expect(runtime.queries.outcome(originalTwoId)?.outcome).toBe('accepted')
    result!.revision.outcomeChanges[0]!.txId.fill(0)
    expect(runtime.queries.outcome(originalTwoId)?.outcome).toBe('accepted')
    expect(runtime.queries.outcome(two.txId)).toBeNull()
  })

  it('replays a replaceable provisional suffix in timestamp order while preserving final identities', async () => {
    const bytes = store(), runtime = await createEventMaterializationRuntime({ store: bytes, namespace: 'identity' })
    const digest = runtime.queries.executionManifestDigest
    const final = await proposal(digest, 1, program(emit('chat', 'final')))
    const one = await proposal(digest, 2, program(emit('chat', 'one')), 'same')
    const two = await proposal(digest, 3, program(emit('chat', 'two')), 'same')
    await runtime.coordinator.materialize([final, one, two])
    await runtime.coordinator.publishFinal!(1)
    expect(runtime.queries.outcome(two.txId)?.rejectionCode).toBe('operation_conflict')
    const removed = await runtime.coordinator.materialize([final, two])
    expect(runtime.queries.outcome(two.txId)?.outcome).toBe('accepted')
    expect(runtime.queries.outcome(one.txId)).toBeNull()
    expect(runtime.queries.proposalIdAt(1)).toEqual(two.txId)
    expect(runtime.queries.proposalIdAt(2)).toBeNull()
    expect(removed?.revision.outcomeChanges).toContainEqual({ txId: one.txId, previous: 'accepted', current: null,
      previousRejectionCode: null, currentRejectionCode: null })
    await runtime.coordinator.materialize([final, one, two])
    expect(runtime.queries.outcome(one.txId)?.outcome).toBe('accepted')
    expect(runtime.queries.outcome(two.txId)?.rejectionCode).toBe('operation_conflict')
    await runtime.coordinator.materialize([final, two, one])
    expect(runtime.queries.outcome(two.txId)?.outcome).toBe('accepted')
    expect(runtime.queries.outcome(one.txId)?.rejectionCode).toBe('operation_conflict')
    await runtime.coordinator.materialize([final, two])
    const changed = await proposal(digest, 3, program(emit('chat', 'changed')), 'same')
    await expect(runtime.coordinator.materialize([final, { ...changed, txId: two.txId }])).rejects.toThrow('IDENTITY_CONFLICT')
    await expect(runtime.coordinator.materialize([two])).rejects.toThrow('FINAL_PREFIX_CHANGED')
    await runtime.coordinator.publishFinal!(2)
    const reopened = await createEventMaterializationRuntime({ store: bytes, namespace: 'identity' })
    expect(reopened.queries.finalOrderLength).toBe(2)
    expect(reopened.queries.outcome(two.txId)?.outcome).toBe('accepted')
    expect(reopened.queries.outcome(one.txId)).toBeNull()
    await expect(reopened.coordinator.materialize([final, one, two])).rejects.toThrow('FINAL_PREFIX_CHANGED')
  })

  it('binds finality to complete proposal identities, including their event IDs', async () => {
    const runtime = await createEventMaterializationRuntime({ store: store(), namespace: 'final-identity' })
    const digest = runtime.queries.executionManifestDigest
    const one = await proposal(digest, 1, program(emit('chat', 'one')))
    const two = await proposal(digest, 2, program(emit('chat', 'two')))
    await runtime.coordinator.materialize([one])
    await runtime.coordinator.publishFinal!(1)
    await expect(runtime.coordinator.materialize([{ ...one, txId: utf8('replacement-id') }, two]))
      .rejects.toThrow('FINAL_PREFIX_CHANGED')
    expect(runtime.queries.orderLength).toBe(1)
    expect(runtime.queries.finalOrderLength).toBe(1)
    expect(runtime.queries.outcome(one.txId)?.outcome).toBe('accepted')
  })

  it('rejects the same signed proposal under two transaction IDs', async () => {
    const runtime = await createEventMaterializationRuntime({ store: store(), namespace: 'duplicate' })
    const one = await proposal(runtime.queries.executionManifestDigest, 1, program(emit('chat', 'one')))
    await expect(runtime.coordinator.materialize([one, { ...one, txId: utf8('duplicate-id') }]))
      .rejects.toThrow('DUPLICATE_PROPOSAL')
    expect(runtime.queries.orderLength).toBe(0)
  })
  it('ignores an incomplete tail and recovers the previously published prefix', async () => {
    const bytes = store()
    let untilFailure = Infinity
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      if (--untilFailure === 0) throw new Error('power loss during tail')
      await bytes.put(key, value)
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'partial-tail' })
    const digest = runtime.queries.executionManifestDigest
    const entries = await Promise.all([1, 2, 3].map(index => proposal(digest, index, program(emit('chat', index)))))
    await runtime.coordinator.materialize(entries.slice(0, 1))
    untilFailure = 2
    await expect(runtime.coordinator.materialize(entries)).rejects.toThrow('power loss during tail')
    expect(runtime.queries.orderLength).toBe(1)
    untilFailure = Infinity
    const reopened = await createEventMaterializationRuntime({ store: storage, namespace: 'partial-tail' })
    expect(reopened.queries.orderLength).toBe(1)
    await reopened.coordinator.materialize(entries)
    expect(reopened.queries.orderLength).toBe(3)
  })

  it('rejects corrupt or missing records referenced by a durable head', async () => {
    const bytes = store()
    let recordKey = ''
    const storage = { get: (key: string) => bytes.get(key), async put(key: string, value: Uint8Array) {
      if (key.includes('/node/')) recordKey = key
      await bytes.put(key, value)
    } }
    const runtime = await createEventMaterializationRuntime({ store: storage, namespace: 'corrupt-record' })
    await runtime.coordinator.materialize([await proposal(runtime.queries.executionManifestDigest, 1, program(emit('chat', 'one')))])
    const original = (await bytes.get(recordKey))!
    const corrupt = original.slice(); corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1
    await bytes.put(recordKey, corrupt)
    await expect(createEventMaterializationRuntime({ store: storage, namespace: 'corrupt-record' })).rejects.toThrow('HISTORY_INCOMPLETE')
    await bytes.put(recordKey, original)
    await expect(createEventMaterializationRuntime({ store: { get: async key => key === recordKey ? null : bytes.get(key), put: (key, value) => storage.put(key, value) }, namespace: 'corrupt-record' })).rejects.toThrow('HISTORY_INCOMPLETE')
  })
})

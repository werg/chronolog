import { describe, expect, it } from 'vitest'
import { bytesToHex, emit, encodeTransactionCore, program, transactionDigest, utf8, type ChangeProgram, type TransactionCore } from '@chronolog/protocol'
import { createEventMaterializationRuntime } from './events.js'
import type { AdmittedTransaction } from './types.js'

function store() {
  const values = new Map<string, Uint8Array>()
  return { fail: false, async get(key: string) { return values.get(key)?.slice() ?? null },
    async put(key: string, value: Uint8Array) { if (this.fail) throw new Error('power loss'); values.set(key, value.slice()) } }
}
async function admitted(digest: Uint8Array, sequence: number, change: ChangeProgram, operationId = `op-${sequence}`): Promise<AdmittedTransaction> {
  const core: TransactionCore = { operationId, groupId: new Uint8Array(32), membershipRevision: new Uint8Array(32), validationPolicy: new Uint8Array(32),
    authorId: new Uint8Array(32), authorTimestampMs: BigInt(sequence), nonce: new Uint8Array(32).fill(sequence), executionManifestDigest: digest, program: change }
  const canonicalCandidate = encodeTransactionCore(core), candidateDigest = await transactionDigest(canonicalCandidate)
  return { txId: utf8(`tx_${bytesToHex(candidateDigest)}`), authorFeedSequence: BigInt(sequence), candidateDigest, canonicalCandidate, core }
}
describe('SQL-free durable event execution', () => {
  it('reopens final outcomes and deterministic operation conflicts without an SQL runtime', async () => {
    const bytes = store()
    const first = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    const digest = first.queries.executionManifestDigest
    const one = await admitted(digest, 1, program(emit('chat', 'one')), 'same')
    const conflict = await admitted(digest, 2, program(emit('chat', 'changed')), 'same')
    const sql = await admitted(digest, 3, program('SELECT 1', emit('chat', 'suppressed')))
    await first.coordinator.materialize([one, conflict, sql])
    await first.coordinator.publishFinal!(3)
    expect(first.queries.outcome(one.txId)?.outcome).toBe('accepted')
    expect(first.queries.outcome(conflict.txId)?.rejectionCode).toBe('operation_conflict')
    expect(first.queries.outcome(sql.txId)?.rejectionCode).toBe('profile:sql-disabled')
    first.close()
    const reopened = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    expect(reopened.queries.finalOrderLength).toBe(3)
    expect(reopened.queries.outcome(one.txId)?.outcome).toBe('accepted')
    expect(() => reopened.queries.localSql('SELECT 1')).toThrow('SQL_DISABLED')
    await expect(reopened.coordinator.materialize([conflict, one, sql])).rejects.toThrow('FINAL_PREFIX_CHANGED')
  })
  it('never exposes an outcome or final cursor ahead of a failed durable write', async () => {
    const bytes = store(), runtime = await createEventMaterializationRuntime({ store: bytes, namespace: 'group' })
    const entry = await admitted(runtime.queries.executionManifestDigest, 1, program(emit('chat', 'one')))
    bytes.fail = true
    await expect(runtime.coordinator.materialize([entry])).rejects.toThrow('power loss')
    expect(runtime.queries.orderLength).toBe(0)
    expect(runtime.queries.outcome(entry.txId)).toBeNull()
    bytes.fail = false
    await runtime.coordinator.materialize([entry])
    bytes.fail = true
    await expect(runtime.coordinator.publishFinal!(1)).rejects.toThrow('power loss')
    expect(runtime.queries.finalOrderLength).toBe(0)
  })
})

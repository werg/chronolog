import { describe, expect, it } from 'vitest'

import { DurableOperationJournal, MemoryOperationStore } from './operations.js'

describe('durable operation journal', () => {
  it('recovers exact prepared bytes after a lost publication response before preparing later work', async () => {
    const store = new MemoryOperationStore()
    const first = new DurableOperationJournal(store, 'governance')
    const published: number[] = []
    let prepares = 0
    await expect(first.run({
      operationId: 'approval-1', fingerprint: Uint8Array.of(1),
      prepare: async () => { prepares += 1; return Uint8Array.of(40) },
      apply: async (payload) => { published.push(payload[0]!); throw new Error('lost response') },
    })).rejects.toThrow('lost response')

    const reopened = new DurableOperationJournal(store, 'governance')
    const recovered: number[] = []
    await reopened.run({
      operationId: 'approval-2', fingerprint: Uint8Array.of(2),
      prepare: async () => {
        expect(recovered).toEqual([40])
        prepares += 1
        return Uint8Array.of(41)
      },
      apply: async (payload) => { recovered.push(payload[0]!) },
    })
    expect(published).toEqual([40])
    expect(recovered).toEqual([40, 41])
    expect(prepares).toBe(2)
    const retry = await reopened.run({
      operationId: 'approval-1', fingerprint: Uint8Array.of(1),
      prepare: async () => { throw new Error('must not reauthor') },
      apply: async () => { throw new Error('must not republish') },
    })
    expect(retry).toEqual(Uint8Array.of(40))
  })

  it('rejects reuse of an operation identity for a different decision', async () => {
    const journal = new DurableOperationJournal(new MemoryOperationStore(), 'test')
    const base = { operationId: 'same', prepare: async () => Uint8Array.of(5), apply: async () => undefined }
    await journal.run({ ...base, fingerprint: Uint8Array.of(1) })
    await expect(journal.run({ ...base, fingerprint: Uint8Array.of(2) })).rejects.toThrow('OPERATION_ID_CONFLICT')
  })
})

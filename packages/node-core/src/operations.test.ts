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

  it('owns the retry identity, fingerprint and publication callbacks before entering the journal lane', async () => {
    const store = new MemoryOperationStore()
    const journal = new DurableOperationJournal(store, 'owned-input')
    const published: number[] = []
    const options = {
      operationId: 'original', fingerprint: Uint8Array.of(1),
      prepare: async () => Uint8Array.of(40),
      apply: async (payload: Uint8Array) => { published.push(payload[0]!) },
    }
    const submission = journal.run(options)
    options.operationId = 'changed'
    options.fingerprint[0] = 2
    options.prepare = async () => Uint8Array.of(99)
    options.apply = async () => { throw new Error('changed callback must not run') }
    expect(await submission).toEqual(Uint8Array.of(40))
    expect(published).toEqual([40])
    const reopened = new DurableOperationJournal(store, 'owned-input')
    expect(await reopened.lookup('original')).toEqual(Uint8Array.of(40))
    expect(await reopened.lookup('changed')).toBeNull()
    expect(await reopened.run({ operationId: 'original', fingerprint: Uint8Array.of(1),
      prepare: async () => { throw new Error('must not reauthor') },
      apply: async () => { throw new Error('must not republish') },
    })).toEqual(Uint8Array.of(40))
  })

  it('keeps an existing operation visible while its completed receipt replaces the pending entry', async () => {
    let holdCompletedRead = false
    let completedRead!: () => void, resumeRead!: () => void
    const captured = new Promise<void>((resolve) => { completedRead = resolve })
    const resume = new Promise<void>((resolve) => { resumeRead = resolve })
    class PausingStore extends MemoryOperationStore {
      override async get(key: string): Promise<Uint8Array | null> {
        const value = await super.get(key)
        if (holdCompletedRead && key === 'visibility/completed/publishing') {
          holdCompletedRead = false
          completedRead()
          await resume
        }
        return value
      }
    }
    const journal = new DurableOperationJournal(new PausingStore(), 'visibility')
    let entered!: () => void, finishApply!: () => void
    const applying = new Promise<void>((resolve) => { entered = resolve })
    const releaseApply = new Promise<void>((resolve) => { finishApply = resolve })
    const publication = journal.run({ operationId: 'publishing', fingerprint: Uint8Array.of(1),
      prepare: async () => Uint8Array.of(7), apply: async () => { entered(); await releaseApply },
    })
    await applying
    holdCompletedRead = true
    const overlappingRead = journal.lookup('publishing')
    await captured
    finishApply()
    await publication
    resumeRead()
    expect(await overlappingRead).toEqual(Uint8Array.of(7))
  })
})

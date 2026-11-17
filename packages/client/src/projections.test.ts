import type { EventBatch, EventReadOptions } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { DurableProjection, ProjectionConflictError, type ProjectionCheckpoint, type ProjectionEventSource, type ProjectionIdentity, type ProjectionStore } from './projections.js'

const identity: ProjectionIdentity = { groupId: 'group', historyId: 'history', filterVersion: 'filter/v1', reducerVersion: 'reducer/v1' }
const batch = (cursor: string, values: readonly number[] = [], hasMore = false, revision = 'final-1'): EventBatch => ({
  scannedThrough: cursor, revision, hasMore,
  transactions: [{ proposalId: `tx-${cursor}`, events: values.map((value, eventOrdinal) => ({
    id: `${cursor}:${eventOrdinal}`, proposalId: `tx-${cursor}`, eventOrdinal, topic: 'counts', payload: value,
    origin: { kind: 'chronolog', groupId: 'A'.repeat(43), authorId: '11'.repeat(32), operationId: `operation-${cursor}`,
      authorTimestampMs: '123', membershipRevision: 'A'.repeat(43), writerCapability: null },
  })) }],
})

class AtomicStore implements ProjectionStore<{ total: number }> {
  saved: ProjectionCheckpoint<{ total: number }> | null = null
  fail = false
  commits = 0
  async load(): Promise<ProjectionCheckpoint<{ total: number }> | null> { return structuredClone(this.saved) }
  async commit(_key: string, expected: number | null, next: ProjectionCheckpoint<{ total: number }>): Promise<void> {
    if (this.fail) throw new Error('Disk unavailable')
    if ((this.saved?.generation ?? null) !== expected) throw new ProjectionConflictError()
    this.saved = structuredClone(next); this.commits++
  }
}

function fixture(store: AtomicStore, batches: readonly EventBatch[], selectedIdentity = identity) {
  const cursors: Array<string | undefined> = []
  const source: ProjectionEventSource = {
    async read(options: EventReadOptions = {}) { cursors.push(options.cursor); return batches[options.cursor === undefined ? 0 : 1] ?? batches[0]! },
    subscribe() { return { async *[Symbol.asyncIterator]() { yield* batches } } },
  }
  const projection = new DurableProjection({ key: 'sum', identity: selectedIdentity, topics: ['counts'], store, source,
    initial: () => ({ total: 0 }), reduce: (state, event) => { state.total += Number(event.payload); return state } })
  return { projection, cursors }
}

describe('durable application projections', () => {
  it('commits state and scanned progress together, including empty matching ranges', async () => {
    const store = new AtomicStore()
    const { projection, cursors } = fixture(store, [batch('empty-scan', [], true), batch('after-event', [2, 3])])
    expect((await projection.catchUp()).state.total).toBe(5)
    expect(cursors).toEqual([undefined, 'empty-scan'])
    expect(store.saved).toMatchObject({ cursor: 'after-event', state: { total: 5 }, generation: 2, identity })
  })

  it('replays after a failed commit without mutating the previous checkpoint or skipping work', async () => {
    const store = new AtomicStore()
    await fixture(store, [batch('old', [1])]).projection.catchUp()
    const previous = structuredClone(store.saved)
    store.fail = true
    await expect(fixture(store, [batch('unused'), batch('new', [4])]).projection.catchUp()).rejects.toThrow('Disk unavailable')
    expect(store.saved).toEqual(previous)
    store.fail = false
    const recovered = fixture(store, [batch('unused'), batch('new', [4])])
    expect((await recovered.projection.catchUp()).state.total).toBe(5)
    expect(recovered.cursors).toEqual(['old'])
  })

  it.each(['historyId', 'reducerVersion', 'filterVersion'] as const)('rebuilds without reusing an old cursor when %s changes', async field => {
    const store = new AtomicStore()
    await fixture(store, [batch('old', [5])]).projection.catchUp()
    const changed = fixture(store, [batch('new', [2])], { ...identity, [field]: 'changed' })
    expect((await changed.projection.catchUp()).state.total).toBe(2)
    expect(changed.cursors).toEqual([undefined])
  })

  it('does not process a delivered continuation twice and still records revision-only progress', async () => {
    const store = new AtomicStore()
    await fixture(store, [batch('same', [3])]).projection.catchUp()
    const state = await fixture(store, [batch('unused'), batch('same', [3], false, 'final-2')]).projection.catchUp()
    expect(state.state.total).toBe(3)
    expect(state.revision).toBe('final-2')
  })

  it('publishes follow checkpoints only after storage accepts the state/cursor pair', async () => {
    const store = new AtomicStore()
    const { projection } = fixture(store, [batch('first', [1]), batch('second', [2])])
    const iterator = projection.follow()[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.state.total).toBe(1)
    expect(store.saved?.cursor).toBe('first')
    expect(store.commits).toBe(1)
    store.fail = true
    await expect(iterator.next()).rejects.toThrow('Disk unavailable')
    expect(store.saved?.cursor).toBe('first')
  })

  it('rejects competing checkpoint writers through atomic generation comparison', async () => {
    const store = new AtomicStore()
    await fixture(store, [batch('one', [1])]).projection.catchUp()
    const old = structuredClone(store.saved!)
    await fixture(store, [batch('unused'), batch('two', [2])]).projection.catchUp()
    await expect(store.commit('sum', old.generation, { ...old, generation: old.generation + 1 })).rejects.toBeInstanceOf(ProjectionConflictError)
    expect(store.saved?.cursor).toBe('two')
  })
})

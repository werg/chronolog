import { describe, expect, it } from 'vitest'
import { program, emit } from '@chronolog/protocol'
import { RevisionBroadcaster, type NodeRevisionEvent } from '@chronolog/node-core'
import { createChronologApplicationBackend, type NodeApplicationSource } from './application.js'

function fixture() {
  type RawStatus = NonNullable<Awaited<ReturnType<NodeApplicationSource['operation']>>>
  let current: RawStatus | null = null, revision = 0n, reads = 0, watchers = 0, released = 0
  const calls: unknown[] = [], parameters: unknown[] = [], revisions = new RevisionBroadcaster<NodeRevisionEvent>()
  const batch = { revision: 'pinned', transactions: [], scannedThrough: 'cursor', hasMore: false }
  const source = {
    get revision() { return revision },
    async publish(input: unknown) { calls.push(input); return { txIdText: 'original-proposal' } },
    async operation() { reads++; return current },
    async *revisions(_after: bigint, signal?: AbortSignal) {
      watchers++
      try { yield* revisions.subscribe(signal === undefined ? {} : { signal }) }
      finally { watchers-- }
    },
    events: { read: async () => batch, async *subscribe() { yield batch } },
    async readView() { return { revision: batch.revision,
      query(_sql: string, values: unknown[]) { parameters.push(values); return { columns: [{ name: 'count' }], rows: [[{ kind: 'integer', value: '7' }]] } },
      readEvents: () => batch, release() { released++ },
    } },
  } as unknown as NodeApplicationSource
  return { source, calls, parameters, get reads() { return reads }, get watchers() { return watchers }, get released() { return released },
    set(outcome: 'accepted' | 'rejected' | null, final: boolean) {
      current = { operationId: 'stable', proposalId: 'original-proposal', final,
        outcome: outcome === null ? null : { outcome, rejectionCode: outcome === 'rejected' ? 'claim_conflict' : null, failingStatementIndex: outcome === 'rejected' ? 1 : null } } as RawStatus
      revisions.emit({ revision: ++revision, reason: 'materialized' })
    },
  }
}

describe('selected Chronolog application adapter', () => {
  it('delegates one exact authored program and never creates a second command identity', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: false })
    const change = program(emit('conversation', { text: 'reviewed' }))
    expect(await backend.submit(change, { operationId: 'stable' })).toEqual({ operationId: 'stable', proposalId: 'original-proposal', status: 'queued' })
    expect(f.calls).toEqual([{ program: change, operationId: 'stable' }])
    expect(backend.capabilities).not.toContain('sql')
    await expect(backend.events.publish('conversation', { text: 'reviewed' }, { operationId: 'stable' })).resolves.toMatchObject({ proposalId: 'original-proposal' })
    expect(f.calls).toHaveLength(2)
    expect(() => backend.events.publish('conversation', { text: undefined }, { operationId: 'invalid' })).toThrow()
    expect(f.calls).toHaveLength(2)
  })

  it('keeps speculative rejection provisional and observes finality even when its outcome does not change', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: true })
    f.set('rejected', false)
    const stop = new AbortController(), iterator = backend.operations.subscribe({ operationId: 'stable', signal: stop.signal })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toMatchObject({ status: 'provisional', outcome: 'rejected', error: 'claim_conflict' })
    expect(f.watchers).toBe(1)
    const before = f.reads
    for (let index = 0; index < 100; index++) f.set('rejected', false)
    f.set('rejected', true)
    await Promise.resolve()
    expect(f.reads, 'a paused consumer only receives replacement operation state on its next pull').toBe(before)
    expect((await iterator.next()).value).toMatchObject({ operationId: 'stable', proposalId: 'original-proposal', status: 'final', outcome: 'rejected' })
    expect((await iterator.next()).done).toBe(true)
    expect(f.watchers).toBe(0)
  })

  it('captures one view, normalizes native SQL values and releases it once', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: true })
    const view = await backend.readView({ view: 'final' })
    const result = await view.query('SELECT ?', [7n])
    expect(result).toEqual({ revision: 'pinned', columns: [{ name: 'count' }], rows: [[7n]], truncated: false })
    expect(f.parameters).toEqual([[{ kind: 'integer', value: '7' }]])
    expect((await view.readEvents()).revision).toBe(view.revision)
    await view.release(); await view.release()
    expect(f.released).toBe(1)
    await expect(view.query('SELECT 1')).rejects.toThrow('APPLICATION_VIEW_RELEASED')
    const noSql = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: false })
    const eventsOnly = await noSql.readView()
    await expect(eventsOnly.query('SELECT 1')).rejects.toThrow('SQL_DISABLED_FOR_EVENT_PROFILE')
    await eventsOnly.release()
  })

  it('returns an original terminal outcome immediately on exact retry', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: true })
    f.set('rejected', true)
    expect(await backend.submit(program(emit('conversation', null)), { operationId: 'stable' })).toMatchObject({
      operationId: 'stable', proposalId: 'original-proposal', status: 'final', outcome: 'rejected', error: 'claim_conflict',
    })
  })
})

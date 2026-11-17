import { describe, expect, it } from 'vitest'
import { program, emit } from '@chronolog/protocol'
import { RevisionBroadcaster, type NodeRevisionEvent } from '@chronolog/node-core'
import type { ApplicationChangeOptions } from '@tendriller/core/application'
import { createChronologApplicationBackend, type ClientApplicationSource, type NodeApplicationSource } from './application.js'

function fixture() {
  type RawStatus = NonNullable<Awaited<ReturnType<NodeApplicationSource['operation']>>>
  let current: RawStatus | null = null, revision = 0n, reads = 0, watchers = 0, released = 0, changesReleased = 0
  const calls: unknown[] = [], parameters: unknown[] = [], changeCalls: unknown[] = [], viewCalls: unknown[] = [], revisions = new RevisionBroadcaster<NodeRevisionEvent>()
  const batch = { revision: 'pinned', transactions: [], scannedThrough: 'cursor', hasMore: false }
  const changes = { async *[Symbol.asyncIterator]() {
    try { yield { view: 'final' as const, revision: batch.revision, finalRevision: batch.revision } }
    finally { changesReleased++ }
  } }
  const source = {
    get revision() { return revision },
    async publish(input: unknown) { calls.push(input); return { txIdText: 'original-proposal' } },
    async operation() { reads++; return current },
    async *revisions(_after: bigint, signal?: AbortSignal) {
      watchers++
      try { yield* revisions.subscribe(signal === undefined ? {} : { signal }) }
      finally { watchers-- }
    },
    events: { historyProfile: 'chronological', read: async () => batch, async *subscribe() { yield batch } },
    changes(options: unknown) { changeCalls.push(options); return changes },
    async readView(options: { view?: 'local' | 'final' } = {}) { viewCalls.push(options); return { view: options.view ?? 'final', revision: batch.revision,
      finalRevision: options.view === 'local' ? 'pinned-final' : batch.revision,
      query(_sql: string, values: unknown[]) { parameters.push(values); return { columns: [{ name: 'count' }], rows: [[{ kind: 'integer', value: '7' }]] } },
      readEvents: () => batch, release() { released++ },
    } },
  } as unknown as NodeApplicationSource
  const client = {
    changes: source.changes, readView: source.readView, events: source.events,
    async submit(change: unknown, options: { operationId: string }) {
      calls.push({ program: change, operationId: options.operationId })
      return { proposalId: 'original-proposal', dispose() {} }
    },
    operations: { get: source.operation, async *subscribe() {} },
  } as unknown as ClientApplicationSource
  return { source, client, calls, parameters, changes, changeCalls, viewCalls, get changesReleased() { return changesReleased },
    get reads() { return reads }, get watchers() { return watchers }, get released() { return released },
    set(outcome: 'accepted' | 'rejected' | null, final: boolean) {
      current = { operationId: 'stable', proposalId: 'original-proposal', final,
        outcome: outcome === null ? null : { outcome, rejectionCode: outcome === 'rejected' ? 'claim_conflict' : null, failingStatementIndex: outcome === 'rejected' ? 1 : null } } as RawStatus
      revisions.emit({ revision: ++revision, reason: 'materialized' })
    },
  }
}

describe('selected Chronolog application adapter', () => {
  it('refuses a generation source before labelling its events as chronological', () => {
    const f = fixture()
    Object.assign(f.source.events, { historyProfile: 'peer-generation-v1' })
    expect(() => createChronologApplicationBackend({ id: 'history', replica: f.source, sql: false }))
      .toThrowError(expect.objectContaining({ code: 'unsupported_history_profile' }))
    expect(f.calls).toEqual([]); expect(f.reads).toBe(0)
  })

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

  it.each(['node', 'client'] as const)('rejects ordering barriers before either %s submission path writes', async kind => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: kind === 'node' ? f.source : f.client, sql: false })
    const change = program(emit('conversation', { text: 'reviewed' }))
    for (const basedOn of ['captured-revision', '']) {
      await expect(backend.submit(change, { operationId: 'stable', basedOn })).rejects.toMatchObject({ code: 'unsupported_barrier' })
      await expect(backend.events.publish('conversation', { text: 'reviewed' }, { operationId: 'stable', basedOn })).rejects.toMatchObject({ code: 'unsupported_barrier' })
    }
    expect(f.calls).toEqual([])
    expect(f.reads).toBe(0)
    await expect(backend.submit(change, { operationId: 'stable' })).resolves.toEqual({ operationId: 'stable', proposalId: 'original-proposal', status: 'queued' })
    await expect(backend.events.publish('conversation', { text: 'reviewed' }, { operationId: 'stable' })).resolves.toMatchObject({ proposalId: 'original-proposal', status: 'queued' })
    expect(f.calls).toEqual([{ program: change, operationId: 'stable' }, { program: change, operationId: 'stable' }])
  })

  it.each(['node', 'client'] as const)('rejects unsupported %s views before observing or capturing a replica', async kind => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: kind === 'node' ? f.source : f.client, sql: false })
    for (const view of ['applied', 'eventual', '', null, 1, {}]) {
      const options = { view } as unknown as ApplicationChangeOptions
      expect(() => backend.changes(options)).toThrowError(expect.objectContaining({ code: 'invalid_view' }))
      await expect(backend.readView(options)).rejects.toMatchObject({ code: 'invalid_view' })
    }
    expect(f.changeCalls).toEqual([])
    expect(f.viewCalls).toEqual([])
    for (const view of ['local', 'final'] as const) {
      expect(backend.changes({ view })).toBe(f.changes)
      const captured = await backend.readView({ view })
      expect(captured).toMatchObject({ view, revision: 'pinned', finalRevision: view === 'local' ? 'pinned-final' : 'pinned' })
      await captured.release()
    }
    const captured = await backend.readView()
    expect(captured).toMatchObject({ view: 'final', finalRevision: 'pinned' })
    await captured.release()
    expect(f.changeCalls).toEqual([{ view: 'local' }, { view: 'final' }])
    expect(f.viewCalls).toEqual([{ view: 'local' }, { view: 'final' }, { view: 'final' }])
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

  it('releases an abandoned operation observer while its next pull is waiting', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: false })
    f.set('accepted', false)
    const iterator = backend.operations.subscribe({ operationId: 'stable' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.status).toBe('provisional')
    const pending = iterator.next()
    await Promise.resolve()
    await iterator.return?.()
    expect(await pending).toMatchObject({ done: true })
    expect(f.watchers).toBe(0)
  })

  it('returns the original final result from an exact retry instead of regressing it to queued', async () => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: true })
    const change = program(emit('conversation', { text: 'original' }))
    f.set('rejected', true)
    expect(await backend.submit(change, { operationId: 'stable' })).toMatchObject({
      operationId: 'stable', proposalId: 'original-proposal', status: 'final', outcome: 'rejected', error: 'claim_conflict',
    })
    expect(f.calls).toEqual([{ program: change, operationId: 'stable' }])
  })

  it.each(['node', 'client'] as const)('delegates the %s view changes stream and preserves its revision and lifetime', async kind => {
    const f = fixture(), controller = new AbortController()
    const replica = kind === 'node' ? f.source : {
      changes: f.source.changes, readView: f.source.readView, events: f.source.events,
      submit: async () => { throw new Error('not used') },
      operations: { get: f.source.operation, async *subscribe() {} },
    } as unknown as ClientApplicationSource
    const backend = createChronologApplicationBackend({ id: 'history', replica, sql: false })
    const options = { view: 'final' as const, signal: controller.signal }
    const stream = backend.changes(options)
    expect(stream).toBe(f.changes)
    expect(f.changeCalls).toEqual([options])
    const iterator = stream[Symbol.asyncIterator](), view = await backend.readView({ view: 'final' })
    try {
      expect(view).toMatchObject({ view: 'final', revision: 'pinned', finalRevision: 'pinned' })
      expect((await iterator.next()).value).toEqual({ view: 'final', revision: view.revision, finalRevision: view.revision })
      await iterator.return?.()
      expect(f.changesReleased).toBe(1)
    } finally { await iterator.return?.(); await view.release() }
  })

  it.each(['final', 'local'] as const)('captures one %s view with its final boundary, normalizes SQL values and releases it once', async selected => {
    const f = fixture(), backend = createChronologApplicationBackend({ id: 'history', replica: f.source, sql: true })
    const view = await backend.readView({ view: selected })
    expect(view).toMatchObject({ view: selected, revision: 'pinned', finalRevision: selected === 'final' ? 'pinned' : 'pinned-final' })
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

})

import { describe, expect, it, vi } from 'vitest'
import type { PeerRevision, RecoveryNotice } from '@chronolog/peer-generation'
import { createLiveView, type LiveViewSession } from './live-view.js'
import { EventForwarderRecoveryError, forwardSessionEvents, type EventForwarderSession } from './event-forwarder.js'
import type { ApplicationChange, ApplicationEventBatch, SessionStatus } from './session-types.js'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const revision: PeerRevision = { applicationId: 'a'.repeat(64), historyId: 'history', generation: 'b'.repeat(64),
  point: { generation: 'b'.repeat(64), sequence: 0, root: 'c'.repeat(64) }, controlRevision: 0, materializationRevision: '0' }
const status: SessionStatus = { phase: 'ready', database: 'ready', role: 'coordinator', generation: revision.generation,
  coordinator: 'd'.repeat(64), connectedPeers: 0 }
const change: ApplicationChange = { kind: 'applied', revision, recovery: null }
const notice: RecoveryNotice = { previousGeneration: 'e'.repeat(64), generation: revision.generation, adopted: null,
  revision, abandoned: [], unknownLoss: false }

function liveFixture() {
  const result = deferred<{ revision: PeerRevision; value: number }>()
  const next = deferred<IteratorResult<ApplicationChange>>()
  const stopStatus = vi.fn(), stopRecovery = vi.fn(), returned = vi.fn()
  const query = vi.fn(() => result.promise)
  const changes = vi.fn(() => ({ [Symbol.asyncIterator]: () => ({ next: () => next.promise, return: () => { returned(); return Promise.resolve({ done: true as const, value: undefined }) } }) }))
  const session: LiveViewSession<'query', null, number> = { query, changes,
    onStatus: listener => { listener(status); return stopStatus },
    onRecovery: () => stopRecovery,
  }
  return { session, result, next, stopStatus, stopRecovery, returned, query, changes }
}

describe('live-view teardown', () => {
  it('releases a recovery subscription acquired after its synchronous callback aborts', async () => {
    const f = liveFixture(), stop = new AbortController(), reason = Error('cancelled during registration')
    f.session.onRecovery = listener => { listener(notice); return f.stopRecovery }
    const view = createLiveView(f.session, { query: 'query', signal: stop.signal, onRecovery: () => stop.abort(reason) })
    await expect(view.ready()).rejects.toBe(reason)
    expect(f.stopStatus).toHaveBeenCalledOnce(); expect(f.stopRecovery).toHaveBeenCalledOnce()
    expect(f.changes).not.toHaveBeenCalled(); expect(f.query).not.toHaveBeenCalled()
  })

  it('settles pending reads and releases every subscription even when an unsubscriber throws', async () => {
    const f = liveFixture(), view = createLiveView(f.session, { query: 'query' })
    f.stopStatus.mockImplementation(() => { throw Error('bad cleanup') })
    const ready = view.ready(), refresh = view.refresh()
    const rejected = [expect(ready).rejects.toThrow('closed'), expect(refresh).rejects.toThrow('closed')]
    expect(() => view.close()).not.toThrow()
    await Promise.all(rejected); await Promise.resolve()
    expect(f.stopRecovery).toHaveBeenCalledOnce(); expect(f.returned).toHaveBeenCalledOnce()
    f.result.resolve({ revision, value: 99 }); await Promise.resolve()
    expect(view.snapshot).toBeNull()
  })

  it('fails pending readiness when the change stream ends instead of leaving an apparently live observer', async () => {
    const f = liveFixture(), view = createLiveView(f.session, { query: 'query' })
    const rejected = expect(view.ready()).rejects.toThrow('closed')
    f.next.resolve({ done: true, value: undefined }); await rejected
    expect(f.stopStatus).toHaveBeenCalledOnce(); expect(f.stopRecovery).toHaveBeenCalledOnce()
  })
})

function forwardFixture() {
  const controller = new AbortController(), next = deferred<IteratorResult<ApplicationChange>>()
  const batch: ApplicationEventBatch = { revision, cursor: 'cursor', hasMore: false, events: [
    { id: 'event', attemptId: 'a'.repeat(64), operationId: 'operation', author: 'b'.repeat(64), authorTimestampMs: '0', topic: 'topic', payload: { text: 'event' } },
  ] }
  const release = vi.fn(), project = vi.fn(() => Promise.resolve('projected')), deliver = vi.fn(), save = vi.fn(), returned = vi.fn()
  let first = true
  const session: EventForwarderSession = {
    signal: controller.signal,
    changes: () => ({ [Symbol.asyncIterator]: () => ({ next: () => { if (first) { first = false; return Promise.resolve({ done: false as const, value: change }) } return next.promise },
      return: () => { returned(); return Promise.resolve({ done: true as const, value: undefined }) } }) }),
    readView: async () => ({ readEvents: () => batch, release }),
  }
  const options = { session, checkpoint: { load: () => undefined, save }, project, deliver }
  return { controller, next, batch, session, release, project, deliver, save, returned, options }
}

describe('event-forwarder cancellation and checkpoints', () => {
  it('does not deliver a projection completed after cancellation', async () => {
    const f = forwardFixture(), pending = deferred<string>(), started = deferred<void>(), reason = Error('stop projection')
    f.project.mockImplementation(() => { started.resolve(); return pending.promise })
    const task = forwardSessionEvents(f.options), rejected = expect(task).rejects.toBe(reason)
    await started.promise; f.controller.abort(reason); await rejected
    pending.resolve('late'); await Promise.resolve(); await Promise.resolve()
    expect(f.deliver).not.toHaveBeenCalled(); expect(f.save).not.toHaveBeenCalled(); expect(f.release).toHaveBeenCalledOnce()
  })

  it('does not checkpoint a delivery completed after cancellation', async () => {
    const f = forwardFixture(), pending = deferred<void>(), started = deferred<void>(), reason = Error('stop delivery')
    f.deliver.mockImplementation(() => { started.resolve(); return pending.promise })
    const task = forwardSessionEvents(f.options), rejected = expect(task).rejects.toBe(reason)
    await started.promise; f.controller.abort(reason); await rejected
    pending.resolve(); await Promise.resolve(); await Promise.resolve()
    expect(f.save).not.toHaveBeenCalled(); expect(f.returned).toHaveBeenCalledOnce()
  })

  it('releases a view that arrives after cancellation without reading or delivering', async () => {
    const f = forwardFixture(), pending = deferred<Awaited<ReturnType<EventForwarderSession['readView']>>>(), started = deferred<void>()
    const readEvents = vi.fn(() => f.batch), reason = Error('stop opening')
    f.session.readView = () => { started.resolve(); return pending.promise }
    const task = forwardSessionEvents(f.options), rejected = expect(task).rejects.toBe(reason)
    await started.promise; f.controller.abort(reason); await rejected
    pending.resolve({ readEvents, release: f.release }); await new Promise(setImmediate)
    expect(f.release).toHaveBeenCalledOnce(); expect(readEvents).not.toHaveBeenCalled(); expect(f.deliver).not.toHaveBeenCalled()
  })

  it('does not open subscriptions or storage when already cancelled', async () => {
    const f = forwardFixture(), reason = Error('already stopped'), load = vi.fn(() => undefined)
    f.controller.abort(reason)
    await expect(forwardSessionEvents({ ...f.options, checkpoint: { load, save: f.save } })).rejects.toBe(reason)
    expect(load).not.toHaveBeenCalled(); expect(f.release).not.toHaveBeenCalled()
  })
})

describe('event-forwarder recovery and failure evidence', () => {
  it('represents missing recovery evidence explicitly without asserting continuity', () => {
    const error = new EventForwarderRecoveryError({ ...change, kind: 'recovery', recovery: null })
    expect(error.recovery).toBeNull(); expect(error.revision).toEqual(revision)
    expect(error.code).toBe('EVENT_FORWARDER_REVIEW_RECOVERY')
  })

  it('starts from the recovered view when recovery precedes the first capture', async () => {
    const f = forwardFixture(), started = deferred<void>(), recovered = deferred<void>()
    const pending = deferred<Awaited<ReturnType<EventForwarderSession['readView']>>>()
    let step = 0
    f.session.changes = () => ({ [Symbol.asyncIterator]: () => ({
      next: async () => {
        if (step++ === 0) return { done: false as const, value: change }
        if (step === 2) { await recovered.promise; return { done: false as const, value: { ...change, kind: 'recovery' as const, recovery: notice } } }
        return f.next.promise
      },
    }) })
    f.session.readView = () => { started.resolve(); return pending.promise }
    const saved = deferred<void>()
    f.save.mockImplementation(() => { saved.resolve() })
    const task = forwardSessionEvents(f.options)
    await started.promise
    recovered.resolve()
    await new Promise(setImmediate)
    pending.resolve({ readEvents: () => f.batch, release: f.release })
    await saved.promise
    f.next.resolve({ done: true, value: undefined })
    await task
    expect(f.deliver).toHaveBeenCalled()
    expect(f.save).toHaveBeenCalledWith('cursor')
  })

  it('observes recovery during a pending external delivery and never saves that old cursor', async () => {
    const f = forwardFixture(), pending = deferred<void>(), started = deferred<void>()
    f.deliver.mockImplementation(() => { started.resolve(); return pending.promise })
    const task = forwardSessionEvents({ ...f.options, checkpoint: { load: () => 'previous', save: f.save } })
    const rejected = expect(task).rejects.toMatchObject({ name: 'EventForwarderRecoveryError', code: 'EVENT_FORWARDER_REVIEW_RECOVERY',
      revision, recovery: { reason: null, adopted: null, unknownLoss: false } })
    await started.promise; f.next.resolve({ done: false, value: { kind: 'recovery', revision, recovery: notice } })
    await rejected; pending.resolve(); await new Promise(setImmediate)
    expect(f.save).not.toHaveBeenCalled(); expect(f.returned).toHaveBeenCalledOnce()
  })

  it('preserves a read error when releasing its view also fails', async () => {
    const f = forwardFixture(), original = Error('read failed')
    f.session.readView = async () => ({ readEvents: () => { throw original }, release: () => { throw Error('release failed') } })
    await expect(forwardSessionEvents(f.options)).rejects.toBe(original)
    expect(f.save).not.toHaveBeenCalled(); expect(f.deliver).not.toHaveBeenCalled(); expect(f.returned).toHaveBeenCalledOnce()
  })

  it('stops on checkpoint failure after delivery, preserving the unsaved cursor for replay', async () => {
    const f = forwardFixture(), original = Error('checkpoint failed')
    f.save.mockImplementation(() => { throw original })
    await expect(forwardSessionEvents(f.options)).rejects.toBe(original)
    expect(f.deliver).toHaveBeenCalledOnce(); expect(f.release).toHaveBeenCalledOnce(); expect(f.returned).toHaveBeenCalledOnce()
  })
})

it('a failed live change stream rejects pending refreshes and ignores a late query result', async () => {
  const f = liveFixture(), original = Error('change subscription failed')
  const view = createLiveView(f.session, { query: 'query' }), refresh = view.refresh()
  const rejected = expect(refresh).rejects.toBe(original)
  f.next.reject(original); await rejected
  expect(f.stopStatus).toHaveBeenCalledOnce(); expect(f.stopRecovery).toHaveBeenCalledOnce()
  f.result.resolve({ revision, value: 9 }); await new Promise(setImmediate)
  expect(view.snapshot).toBeNull(); expect(view.error).toBe(original)
})

import type { ApplicationChange as InlineApplicationChange } from './session-types.js'
import type { ApplicationReadView, MaterializedRevision, SessionStatus } from './session-types.js'
export interface LiveViewSnapshot<Value> { readonly revision: MaterializedRevision; readonly value: Value }
export interface LiveView<Value> { readonly snapshot: LiveViewSnapshot<Value> | null; readonly status: SessionStatus | null; readonly error: unknown; ready(options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number }): Promise<LiveViewSnapshot<Value>>; refresh(): Promise<LiveViewSnapshot<Value>>; subscribe(listener: (value: LiveViewSnapshot<Value>) => void): () => void; close(): void }
export interface ReactiveReadView { readonly revision: MaterializedRevision; release(): void | Promise<void> }
export interface ReactiveSession<View extends ReactiveReadView = ApplicationReadView> { readView(): Promise<View>; onChange(listener: (change: InlineApplicationChange) => void): () => void; onStatus(listener: (value: SessionStatus) => void): () => void }
/** Invalidation rederives a coherent captured snapshot. It never incrementally mirrors arrival events. */
export function createLiveView<Value, View extends ReactiveReadView = ApplicationReadView>(session: ReactiveSession<View>, derive: (view: View) => Value | Promise<Value>, options: { readonly signal?: AbortSignal; readonly onError?: (error: unknown) => void; readonly onStatus?: (status: SessionStatus) => void } = {}): LiveView<Value> {
  let snapshot: LiveViewSnapshot<Value> | null = null, status: SessionStatus | null = null, error: unknown = null, closed = false, dirty = false, running = false
  const listeners = new Set<(snapshot: LiveViewSnapshot<Value>) => void>(), waiters = new Set<{ resolve(value: LiveViewSnapshot<Value>): void; reject(error: unknown): void }>()
  let stopChange: () => void = () => {}, stopStatus: () => void = () => {}
  const notify = (fn: () => void): void => { try { fn() } catch { /* Observers do not control the session. */ } }
  const run = async (): Promise<void> => {
    if (closed || running) return; running = true
    try {
      while (dirty && !closed) {
        dirty = false
        let view: View | undefined
        try {
          view = await session.readView(); const value = await derive(view)
          if (closed) return
          if (dirty) continue
          snapshot = { revision: view.revision, value }; error = null
          for (const listener of listeners) notify(() => listener(snapshot!))
          for (const waiter of waiters) waiter.resolve(snapshot); waiters.clear()
        } catch (failure) { error = failure; notify(() => options.onError?.(failure)); for (const waiter of waiters) waiter.reject(failure); waiters.clear() }
        finally { await view?.release() }
      }
    } finally { running = false; if (dirty && !closed) void run() }
  }
  const invalidate = (): void => { dirty = true; void run() }
  const close = (): void => { if (closed) return; closed = true; stopChange(); stopStatus(); options.signal?.removeEventListener('abort', close); for (const waiter of waiters) waiter.reject(new Error('LIVE_VIEW_CLOSED')); waiters.clear(); listeners.clear() }
  const ready = (input: { readonly signal?: AbortSignal; readonly timeoutMs?: number } = {}): Promise<LiveViewSnapshot<Value>> => {
    if (closed) return Promise.reject(new Error('LIVE_VIEW_CLOSED')); if (input.signal?.aborted) return Promise.reject(input.signal.reason); if (snapshot !== null) return Promise.resolve(snapshot)
    const timeoutMs = input.timeoutMs ?? 30_000
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) return Promise.reject(new Error('LIVE_VIEW_WAIT_LIMIT'))
    return new Promise((resolve, reject) => {
      const done = (): void => { clearTimeout(timer); input.signal?.removeEventListener('abort', abort); waiters.delete(waiter) }
      const abort = (): void => { done(); reject(input.signal?.reason) }
      const waiter = { resolve(value: LiveViewSnapshot<Value>) { done(); resolve(value) }, reject(failure: unknown) { done(); reject(failure) } }
      const timer = setTimeout(() => { done(); reject(new Error('LIVE_VIEW_TIMEOUT')) }, timeoutMs); waiters.add(waiter); input.signal?.addEventListener('abort', abort, { once: true }); invalidate()
    })
  }
  stopChange = session.onChange(invalidate)
  stopStatus = session.onStatus(value => { status = value; notify(() => options.onStatus?.(value)); if (value.phase === 'closed') close(); else if (value.database === 'ready') invalidate() })
  options.signal?.addEventListener('abort', close, { once: true }); if (options.signal?.aborted) close(); else invalidate()
  return { get snapshot() { return snapshot }, get status() { return status }, get error() { return error }, ready, refresh() { snapshot = null; return ready() }, subscribe(listener) { if (closed) throw new Error('LIVE_VIEW_CLOSED'); listeners.add(listener); if (snapshot !== null) notify(() => listener(snapshot!)); return () => { listeners.delete(listener) } }, close }
}

import type { PeerRevision, RecoveryNotice } from '@chronolog/peer-generation'
import type { ApplicationChange, SessionStatus } from './session-types.js'

export interface LiveViewSnapshot<Value = unknown> {
  readonly revision: PeerRevision
  readonly value: Value
}

export interface LiveViewSession<Name extends string = string, Input = unknown, Value = unknown> {
  readonly signal?: AbortSignal
  query(name: Name, input: Input): Promise<LiveViewSnapshot<Value>>
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationChange>
  onStatus(listener: (status: SessionStatus) => void): () => void
  onRecovery(listener: (notice: RecoveryNotice) => void): () => void
}

export interface LiveViewOptions<Name extends string = string, Input = unknown, Value = unknown> {
  readonly query: Name
  readonly input?: Input
  readonly onSnapshot?: (snapshot: LiveViewSnapshot<Value>) => void
  readonly onStatus?: (status: SessionStatus) => void
  readonly onRecovery?: (notice: RecoveryNotice) => void
  readonly onError?: (error: unknown) => void
  readonly signal?: AbortSignal
}

export interface LiveView<Value = unknown> {
  readonly snapshot: LiveViewSnapshot<Value> | null
  readonly status: SessionStatus | null
  readonly error: unknown
  refresh(): Promise<LiveViewSnapshot<Value>>
  ready(options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number }): Promise<LiveViewSnapshot<Value>>
  subscribe(listener: (snapshot: LiveViewSnapshot<Value>) => void): () => void
  close(): void
}

function isRecovering(failure: unknown): boolean {
  if (failure === null || typeof failure !== 'object') return false
  const record = failure as { code?: unknown; message?: unknown }
  return (record.code ?? record.message) === 'PEER_RECOVERING'
}

/**
 * Reactive coherent query observer over any native or Worker peer session.
 * Owns only subscription invalidation, never storage, transport or identity.
 */
export function createLiveView<Name extends string, Input = null, Value = unknown>(
  session: LiveViewSession<Name, Input, Value>,
  options: LiveViewOptions<NoInfer<Name>, NoInfer<Input>, NoInfer<Value>>,
): LiveView<Value> {
  const { query, input = null as Input, onSnapshot, onStatus, onRecovery, onError, signal } = options
  if (typeof query !== 'string' || !query) throw new TypeError('A declared query name is required.')
  const capturedInput = structuredClone(input)
  const lifetime = new AbortController()
  const signals = [lifetime.signal, ...(session.signal === undefined ? [] : [session.signal]), ...(signal === undefined ? [] : [signal])]
  const owned = AbortSignal.any(signals)

  let closed = false
  let running = false
  let dirty = false
  let requested = 0
  let snapshot: LiveViewSnapshot<Value> | null = null
  let status: SessionStatus | null = null
  let currentError: unknown = null
  let hasError = false
  let statusKey: string | undefined
  let stopStatus: () => void = () => undefined
  let stopRecovery: () => void = () => undefined
  let iterator: AsyncIterator<ApplicationChange> | undefined

  const waiting = new Set<{ resolve: (value: LiveViewSnapshot<Value>) => void; reject: (reason: unknown) => void }>()
  const initial = new Set<(failed: boolean, value: unknown) => void>()
  const listeners = new Set<(snapshot: LiveViewSnapshot<Value>) => void>()

  const settleInitial = (failed: boolean, value: unknown): void => {
    for (const finish of [...initial]) finish(failed, value)
  }
  const notify = <T>(listener: ((value: T) => void) | undefined, value: T): void => {
    if (closed || listener === undefined) return
    try { listener(value) } catch (err) { if ((listener as unknown) !== onError) notify(onError, err) }
  }
  const settle = (err: unknown, value: LiveViewSnapshot<Value> | undefined, failed = false): void => {
    for (const held of waiting) {
      if (failed) held.reject(err)
      else if (value !== undefined) held.resolve(value)
    }
    waiting.clear()
  }
  const invalidate = (): void => {
    if (closed) return
    requested++
    dirty = true
    queueMicrotask(() => { void pump() })
  }

  async function pump(): Promise<void> {
    if (running || closed) return
    running = true
    try {
      while (dirty && !closed) {
        dirty = false
        const request = requested
        try {
          const result = await session.query(query, capturedInput)
          if (closed || request !== requested) continue
          snapshot = Object.freeze({ revision: result.revision, value: result.value })
          currentError = null
          hasError = false
          settle(null, snapshot)
          settleInitial(false, snapshot)
          notify(onSnapshot, snapshot)
          for (const listener of listeners) notify(listener, snapshot)
        } catch (failure) {
          if (closed || request !== requested) continue
          const quietRecovery = isRecovering(failure) && snapshot === null && initial.size > 0 && waiting.size === 0
          currentError = failure
          hasError = true
          settle(failure, undefined, true)
          if (!isRecovering(failure)) settleInitial(true, failure)
          if (!quietRecovery) notify(onError, failure)
        }
      }
    } finally {
      running = false
    }
  }

  function refresh(): Promise<LiveViewSnapshot<Value>> {
    if (closed) return Promise.reject(owned.reason)
    const task = new Promise<LiveViewSnapshot<Value>>((resolve, reject) => { waiting.add({ resolve, reject }) })
    invalidate()
    return task
  }

  function ready(readyOptions: { readonly signal?: AbortSignal; readonly timeoutMs?: number } = {}): Promise<LiveViewSnapshot<Value>> {
    const { signal: readySignal, timeoutMs = 30_000 } = readyOptions
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
      return Promise.reject(new TypeError('Initial read timeout must be 1..120000 milliseconds.'))
    }
    if (readySignal?.aborted === true) return Promise.reject(readySignal.reason)
    if (closed) return Promise.reject(owned.reason)
    if (snapshot !== null) return Promise.resolve(snapshot)
    if (hasError && !isRecovering(currentError)) return Promise.reject(currentError)
    return new Promise<LiveViewSnapshot<Value>>((resolve, reject) => {
      const finish = (failed: boolean, value: unknown): void => {
        clearTimeout(timer)
        readySignal?.removeEventListener('abort', abort)
        initial.delete(finish)
        if (failed) reject(value)
        else resolve(value as LiveViewSnapshot<Value>)
      }
      const abort = (): void => { finish(true, readySignal?.reason) }
      const timer = setTimeout(() => {
        finish(true, Object.assign(new Error('INITIAL_READ_TIMEOUT'), { code: 'INITIAL_READ_TIMEOUT' }))
      }, timeoutMs)
      initial.add(finish)
      readySignal?.addEventListener('abort', abort, { once: true })
      if (readySignal?.aborted === true) abort()
    })
  }

  function subscribe(listener: (value: LiveViewSnapshot<Value>) => void): () => void {
    if (typeof listener !== 'function') throw new TypeError('A snapshot listener is required.')
    if (closed) throw new Error('Live view is closed.')
    listeners.add(listener)
    if (snapshot !== null) notify(listener, snapshot)
    return () => { listeners.delete(listener) }
  }

  function close(): void {
    if (closed) return
    closed = true
    owned.removeEventListener('abort', close)
    lifetime.abort(new Error('Live view is closed.'))
    try { stopStatus() } catch { /* Continue releasing the remaining owned subscriptions. */ }
    try { stopRecovery() } catch { /* A faulty unsubscriber cannot strand waiters. */ }
    listeners.clear()
    settle(owned.reason, undefined, true)
    settleInitial(true, owned.reason)
    void Promise.resolve().then(() => iterator?.return?.()).catch(() => undefined)
  }

  owned.addEventListener('abort', close, { once: true })
  if (owned.aborted) {
    close()
  } else {
    try {
      stopStatus = session.onStatus(value => {
        const generationChanged = status !== null && status.generation !== value.generation
        const becameReady = status?.phase !== 'ready' && value.phase === 'ready'
        status = value
        notify(onStatus, value)
        const next = `${value.generation}/${value.database}/${value.phase}`
        if (generationChanged || becameReady || (next !== statusKey && value.database === 'ready' && value.phase === 'ready')) invalidate()
        statusKey = next
        if (value.phase === 'closed' || value.database === 'closed') close()
      })
      if (closed) {
        stopStatus()
      } else {
        stopRecovery = session.onRecovery(notice => { notify(onRecovery, notice); invalidate() })
        if (closed) { stopRecovery(); return result() }
        iterator = session.changes({ signal: owned })[Symbol.asyncIterator]()
        void (async () => {
          try {
            while (!closed) {
              const change = await iterator.next()
              if (change.done === true) { close(); break }
              invalidate()
            }
          } catch (failure) {
            if (!closed) {
              currentError = failure
              hasError = true
              if (!isRecovering(failure)) settleInitial(true, failure)
              notify(onError, failure)
              lifetime.abort(failure)
            }
          }
        })()
        invalidate()
      }
    } catch (err) {
      close()
      throw err
    }
  }

  function result(): LiveView<Value> { return Object.freeze({
    refresh,
    ready,
    subscribe,
    close,
    get snapshot() { return snapshot },
    get status() { return status },
    get error() { return currentError },
  }) }
  return result()
}

/** A connection lifetime, independent of its transport and replica implementation. */
export interface SupervisedPeerSession {
  readonly signal: AbortSignal
  close(): void | Promise<void>
}

export interface PeerSessionRetry {
  readonly initialDelayMs: number
  readonly maxDelayMs: number
  /** Includes the initial attempt. A stopped supervisor requires an explicit replacement. */
  readonly maxAttempts: number
  /** Proportional jitter, from zero to one. Defaults to 0.2. */
  readonly jitter?: number
  /** A brief connection does not reset the retry budget. Defaults to 30 seconds. */
  readonly resetAfterMs?: number
}

export interface PeerSessionState {
  readonly phase: 'connecting' | 'connected' | 'waiting' | 'stopped'
  readonly attempt: number
  /** Only populated after the connector completes its declared readiness boundary. */
  readonly readiness: 'transport' | 'authenticated' | null
  readonly nextRetryAt: number | null
  readonly error: string | null
}

export interface PeerSessionSupervisor<S extends SupervisedPeerSession> {
  readonly ready: Promise<S>
  readonly completion: Promise<void>
  readonly state: PeerSessionState
  readonly session: S | undefined
  /** Returns the current live session or waits for the next successful attempt. */
  waitForSession(options?: { readonly signal?: AbortSignal }): Promise<S>
  close(): Promise<void>
}

/**
 * Owns one connection attempt/session and an explicit, bounded retry policy.
 * A healthy connection schedules no timer, ping, discovery or host request.
 * The connector must honor its signal and own cleanup on a failed attempt.
 * A late successful result is closed and can never replace a current session.
 *
 * `transport` means negotiation only. An `authenticated` connector must await
 * the owning replica's authentication/attachment before returning its session;
 * neither readiness level implies that history replay or finality is complete.
 */
export function supervisePeerSession<S extends SupervisedPeerSession>(options: {
  readonly connect: (signal: AbortSignal) => Promise<S>
  readonly readiness: 'transport' | 'authenticated'
  readonly retry: PeerSessionRetry
  readonly signal?: AbortSignal
  /** Observation failures are isolated from the connection lifetime. */
  readonly onState?: (state: PeerSessionState) => void | Promise<void>
}): PeerSessionSupervisor<S> {
  const { initialDelayMs, maxDelayMs, maxAttempts } = options.retry
  const jitter = options.retry.jitter ?? 0.2, resetAfterMs = options.retry.resetAfterMs ?? 30_000
  if (![initialDelayMs, maxDelayMs, maxAttempts, resetAfterMs].every(Number.isSafeInteger) ||
      initialDelayMs < 1 || maxDelayMs < initialDelayMs || maxDelayMs > 600_000 || maxAttempts < 1 || maxAttempts > 64 ||
      resetAfterMs < 1 || resetAfterMs > 3_600_000 || !Number.isFinite(jitter) || jitter < 0 || jitter > 1 ||
      !['transport', 'authenticated'].includes(options.readiness) || typeof options.connect !== 'function') {
    throw new Error('PEER_SESSION_SUPERVISOR_OPTIONS_INVALID')
  }
  const controller = new AbortController(), waiters = new Set<{
    resolve(value: S): void
    reject(error: unknown): void
  }>(), closing = new WeakMap<S, Promise<void>>()
  let current: S | undefined, stopped = false, terminalError: unknown
  let state: PeerSessionState = { phase: 'connecting', attempt: 0, readiness: null, nextRetryAt: null, error: null }
  const publish = (next: PeerSessionState): void => {
    state = Object.freeze(next)
    try { void Promise.resolve(options.onState?.(state)).catch(() => undefined) } catch { /* Observers do not own the session. */ }
  }
  const closeSession = (session: S): Promise<void> => {
    const previous = closing.get(session)
    if (previous !== undefined) return previous
    const result = Promise.resolve().then(() => session.close())
    closing.set(session, result)
    return result
  }
  const waitForSession = ({ signal }: { readonly signal?: AbortSignal } = {}): Promise<S> => {
    if (signal?.aborted === true) return Promise.reject(signal.reason)
    if (controller.signal.aborted || stopped) return Promise.reject(terminalError ?? controller.signal.reason ?? new Error('PEER_SESSION_SUPERVISOR_STOPPED'))
    if (current !== undefined && !current.signal.aborted) return Promise.resolve(current)
    return new Promise<S>((resolve, reject) => {
      const finish = (): void => { waiters.delete(waiter); signal?.removeEventListener('abort', abort) }
      const waiter = { resolve(value: S) { finish(); resolve(value) }, reject(error: unknown) { finish(); reject(error) } }
      const abort = (): void => waiter.reject(signal?.reason)
      waiters.add(waiter); signal?.addEventListener('abort', abort, { once: true })
    })
  }
  const abort = (): void => controller.abort(options.signal?.reason)
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  const ready = waitForSession()
  void ready.catch(() => undefined)
  const completion = Promise.resolve().then(async () => {
    let attempt = 0
    try {
      while (!controller.signal.aborted) {
        attempt++
        const lifetime = new AbortController(), cancel = (): void => lifetime.abort(controller.signal.reason)
        controller.signal.addEventListener('abort', cancel, { once: true })
        let session: S | undefined, failure: unknown, healthyDuration = 0
        try {
          publish({ phase: 'connecting', attempt, readiness: null, nextRetryAt: null, error: state.error })
          controller.signal.throwIfAborted()
          const opening = Promise.resolve().then(() => { lifetime.signal.throwIfAborted(); return options.connect(lifetime.signal) })
          // Cancellation does not wait for a misbehaving connector. It still
          // owns any resource it eventually returns, which is retired here.
          void opening.then(value => { if (lifetime.signal.aborted) return closeSession(value) }, () => undefined).catch(() => undefined)
          session = await interruptible(opening, lifetime.signal)
          controller.signal.throwIfAborted(); session.signal.throwIfAborted()
          current = session
          const connectedAt = Date.now(), retire = (): void => lifetime.abort(session!.signal.reason)
          publish({ phase: 'connected', attempt, readiness: options.readiness, nextRetryAt: null, error: null })
          controller.signal.throwIfAborted(); session.signal.throwIfAborted()
          for (const waiter of [...waiters]) waiter.resolve(session)
          session.signal.addEventListener('abort', retire, { once: true })
          try { await ended(session.signal, controller.signal) }
          finally { session.signal.removeEventListener('abort', retire) }
          healthyDuration = Date.now() - connectedAt
          failure = session.signal.reason ?? new Error('PEER_SESSION_ENDED')
        } catch (error) { failure = error }
        finally {
          // Fence Worker attachment before any asynchronous session disposal.
          lifetime.abort(failure ?? controller.signal.reason)
          if (current === session) current = undefined
          controller.signal.removeEventListener('abort', cancel)
          if (session !== undefined) {
            try { await closeSession(session) } catch (error) { failure ??= error }
          }
        }
        if (controller.signal.aborted) break
        if (healthyDuration >= resetAfterMs) attempt = 0
        if (attempt >= maxAttempts) throw failure instanceof Error ? failure : new Error(message(failure ?? 'PEER_SESSION_RETRY_EXHAUSTED'))
        const base = Math.min(maxDelayMs, initialDelayMs * 2 ** Math.max(0, attempt - 1))
        const delay = Math.max(1, Math.min(maxDelayMs, Math.round(base * (1 + jitter * (2 * Math.random() - 1)))))
        publish({ phase: 'waiting', attempt, readiness: null, nextRetryAt: Date.now() + delay, error: message(failure) })
        await pause(delay, controller.signal)
      }
    } catch (error) {
      if (!controller.signal.aborted) { terminalError = error; throw error }
    } finally {
      stopped = true
      options.signal?.removeEventListener('abort', abort)
      const reason: unknown = terminalError ?? controller.signal.reason ?? new Error('PEER_SESSION_SUPERVISOR_STOPPED')
      for (const waiter of [...waiters]) waiter.reject(reason)
      publish({ phase: 'stopped', attempt, readiness: null, nextRetryAt: null, error: terminalError === undefined ? null : message(terminalError) })
    }
  })
  void completion.catch(() => undefined)
  return {
    ready, completion,
    get state() { return state },
    get session() { return !controller.signal.aborted && !stopped && current?.signal.aborted === false ? current : undefined },
    waitForSession,
    async close() {
      controller.abort(new Error('PEER_SESSION_SUPERVISOR_CLOSED'))
      await completion.catch(() => undefined)
    },
  }
}

function message(error: unknown): string { return error instanceof Error ? error.message : String(error) }
function interruptible<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}
function ended(session: AbortSignal, lifetime: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const finish = (): void => { session.removeEventListener('abort', finish); lifetime.removeEventListener('abort', finish); resolve() }
    session.addEventListener('abort', finish, { once: true }); lifetime.addEventListener('abort', finish, { once: true })
    if (session.aborted || lifetime.aborted) finish()
  })
}
function pause(ms: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = (): void => { clearTimeout(timer); reject(signal.reason) }
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve() }, ms)
    signal.addEventListener('abort', abort, { once: true })
  })
}

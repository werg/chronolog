import { assertSignalName, decodeSignal, encodeSignal, MAX_SIGNAL_BYTES, signalAuthorId, signalPayload } from './codec.js'
import { DEFAULT_SIGNAL_TTL_MS, MAX_SIGNAL_TTL_MS, SignalError } from './types.js'
import type { EphemeralSignal, SignalAuthorization, SignalChannelOptions, SignalPayload, SignalRoute,
  SignalSendOptions, Signals, SignalSubscribeOptions, SignalTransport } from './types.js'

interface RouteState { readonly transport: SignalTransport; readonly controller: AbortController; busy: boolean; retired: boolean }
interface PendingSignal { readonly message: EphemeralSignal; readonly bytes: number }
interface Subscription {
  readonly topics: ReadonlySet<string> | null
  readonly mode: 'all' | 'latest'
  readonly queue: Map<string, PendingSignal>
  readonly latest: Map<string, { readonly sequence: number; readonly retainThroughMs: number }>
  bytes: number
  error: Error | null
  wake: (() => void) | null
  clean: () => void
}

/** Live signed messages: explicit routes, no database, protocol, grants or reconnect outbox. */
export class SignalChannel implements Signals {
  readonly #options: SignalChannelOptions
  readonly #authorId: string
  readonly #sessionId: string
  readonly #controller = new AbortController()
  readonly #routes = new Set<RouteState>()
  readonly #seen = new Map<string, number>()
  readonly #subscriptions = new Set<Subscription>()
  readonly #ttl: number
  readonly #skew: number
  readonly #maxSends: number
  readonly #maxReceives: number
  readonly #maxRoutes: number
  readonly #maxSubscriptions: number
  readonly #maxQueue: number
  readonly #maxQueueBytes: number
  readonly #maxReplay: number
  readonly #timeout: number
  readonly #receiveTimeout: number
  #sequence = 0
  #pendingSends = 0
  #pendingReceives = 0
  #pendingDispatches = 0
  #observedTime = 0
  #sendTail: Promise<unknown> = Promise.resolve()
  #admission: Promise<void> = Promise.resolve()

  constructor(options: SignalChannelOptions) {
    assertSignalName(options.scope, 'scope')
    if (typeof options.authorize !== 'function') throw new SignalError('signal_authorization_required')
    this.#authorId = signalAuthorId(options.identity.publicKeyBytes)
    this.#sessionId = signalAuthorId(crypto.getRandomValues(new Uint8Array(32)))
    this.#options = { ...options, identity: { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() } }
    this.#ttl = bound(options.maxTtlMs ?? 30_000, 1, MAX_SIGNAL_TTL_MS)
    this.#skew = bound(options.maxClockSkewMs ?? 2_000, 0, 60_000)
    this.#maxSends = bound(options.maxPendingSends ?? 32, 1, 1024)
    this.#maxReceives = bound(options.maxPendingReceives ?? 32, 1, 1024)
    this.#maxRoutes = bound(options.maxRoutes ?? 32, 1, 1024)
    this.#maxSubscriptions = bound(options.maxSubscriptions ?? 16, 1, 1024)
    this.#maxQueue = bound(options.maxQueuedSignals ?? 64, 1, 4096)
    this.#maxQueueBytes = bound(options.maxQueuedBytes ?? 262_144, 1, 16_777_216)
    this.#maxReplay = bound(options.maxReplayEntries ?? 4096, 1, 1_048_576)
    this.#timeout = bound(options.sendTimeoutMs ?? 5_000, 1, 300_000)
    this.#receiveTimeout = bound(options.receiveTimeoutMs ?? 5_000, 1, 300_000)
  }
  get scope(): string { return this.#options.scope }
  get authorId(): string { return this.#authorId }
  get routeCount(): number { return this.#routes.size }

  attachRoute(transport: SignalTransport): SignalRoute {
    this.#assertOpen()
    if (typeof transport?.send !== 'function') throw new SignalError('signal_route_invalid')
    if (this.#routes.size >= this.#maxRoutes) throw new SignalError('signal_route_limit')
    const state: RouteState = { transport, controller: new AbortController(), busy: false, retired: false }
    this.#routes.add(state)
    return { receive: frame => this.#receive(frame, state), close: () => this.#detach(state) }
  }

  send(topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> {
    try {
      this.#assertOpen()
      assertOptions(options, ['ttlMs', 'signal'])
      options.signal?.throwIfAborted(); assertSignalName(topic, 'topic')
      if (this.#routes.size === 0) throw new SignalError('signal_disconnected')
      if (this.#pendingSends >= this.#maxSends) throw new SignalError('signal_backpressure')
      const snapshot = signalPayload(payload), ttl = options.ttlMs ?? Math.min(DEFAULT_SIGNAL_TTL_MS, this.#ttl)
      if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > this.#ttl) throw new SignalError('signal_ttl_invalid')
      // Queueing or policy work never refreshes an intent's TTL or chooses a new route.
      const issuedAtMs = this.#now(), expiresAtMs = issuedAtMs + ttl, routes = [...this.#routes]
      if (!Number.isSafeInteger(expiresAtMs)) throw new SignalError('signal_clock_invalid')
      const deadline = new AbortController()
      const timer = setTimeout(() => deadline.abort(new SignalError('signal_send_timeout')), Math.min(this.#timeout, ttl))
      const signal = AbortSignal.any([this.#controller.signal, deadline.signal, ...(options.signal === undefined ? [] : [options.signal])])
      this.#pendingSends++
      let started = false
      const queued = this.#sendTail.then(() => {
        signal.throwIfAborted(); started = true
        const operation = (async () => {
          const authorization = { scope: this.scope, authorId: this.#authorId, topic }
          await this.#authorize(authorization, signal)
          if (this.#sequence >= Number.MAX_SAFE_INTEGER) throw new SignalError('signal_clock_or_sequence_exhausted')
          const message = { ...authorization, sessionId: this.#sessionId, sequence: ++this.#sequence,
            issuedAtMs, expiresAtMs, payload: snapshot }
          this.#checkFresh(message)
          const frame = await encodeSignal(message, this.#options.identity)
          await this.#authorize(authorization, signal)
          this.#checkFresh(message); this.#remember(message)
          await this.#dispatch(frame, message, routes, signal, true)
          return structuredClone(message)
        })().finally(() => { clearTimeout(timer); this.#pendingSends-- })
        // A cancelled policy callback retains its capacity slot until it settles.
        return abortable(operation, signal)
      }).finally(() => { if (!started) { clearTimeout(timer); this.#pendingSends-- } })
      this.#sendTail = queued.catch(() => undefined)
      return abortable(queued, signal)
    } catch (error) { return Promise.reject(error) }
  }

  #receive(input: Uint8Array, source: RouteState): Promise<EphemeralSignal | null> {
    try {
      this.#assertOpen(); source.controller.signal.throwIfAborted()
      if (!(input instanceof Uint8Array) || input.length > MAX_SIGNAL_BYTES) throw new SignalError('signal_frame_too_large')
      if (this.#pendingReceives >= this.#maxReceives) throw new SignalError('signal_backpressure')
      const frame = input.slice(), previous = this.#admission
      let release!: () => void
      this.#admission = new Promise<void>(resolve => { release = resolve })
      const deadline = new AbortController()
      const timer = setTimeout(() => deadline.abort(new SignalError('signal_receive_timeout')), this.#receiveTimeout)
      const signal = AbortSignal.any([this.#controller.signal, deadline.signal, source.controller.signal])
      this.#pendingReceives++
      const operation = (async () => {
        const message = await decodeSignal(frame)
        signal.throwIfAborted()
        if (message.scope !== this.scope) throw new SignalError('signal_scope_mismatch')
        this.#checkClock(message)
        await this.#authorize(message, signal)
        // Verify concurrently, then admit in receive-call order. Permission may
        // change while an earlier frame is pending, so recheck at admission.
        await abortable(previous, signal)
        await this.#authorize(message, signal)
        this.#checkClock(message)
        if (message.expiresAtMs <= this.#now()) return null
        if (!this.#remember(message)) return null
        this.#deliver(message, frame.length)
        if (this.#options.relay === true) {
          const routes = [...this.#routes].filter(route => route !== source)
          if (routes.length > 0) void this.#dispatch(frame, message, routes, signal, false).catch(error => this.#report(error))
        }
        return structuredClone(message)
      })().finally(() => { clearTimeout(timer); this.#pendingReceives-- })
      const observed = abortable(operation, signal)
      // Timeout/close frees admission ordering even when policy ignores abort;
      // that underlying operation still retains its verification capacity slot.
      void observed.finally(() => { void previous.then(release) }).catch(() => undefined)
      return observed
    } catch (error) { return Promise.reject(error) }
  }

  subscribe(options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> {
    assertOptions(options, ['topics', 'mode', 'signal'])
    const channel = this, external = options.signal
    const snapshot = { ...options, ...(options.topics === undefined ? {} : { topics: Array.isArray(options.topics) ? [...options.topics as readonly string[]] : options.topics }) }
    return { [Symbol.asyncIterator]() {
      const controller = new AbortController()
      const signal = external === undefined ? controller.signal : AbortSignal.any([controller.signal, external])
      const iterator = channel.#subscribe({ ...snapshot, signal })
      return { next: () => iterator.next(),
        async return() { controller.abort(); return iterator.return() },
        async throw(error: unknown) { controller.abort(); return iterator.throw(error) } }
    } }
  }

  async *#subscribe(options: SignalSubscribeOptions): AsyncGenerator<EphemeralSignal, void> {
    this.#assertOpen()
    if (options.mode !== undefined && options.mode !== 'all' && options.mode !== 'latest') throw new SignalError('signal_mode_invalid')
    if (options.topics !== undefined) {
      if (!Array.isArray(options.topics) || options.topics.length > 128) throw new SignalError('signal_topic_filter_invalid')
      for (const topic of options.topics) assertSignalName(topic, 'topic')
    }
    if (this.#subscriptions.size >= this.#maxSubscriptions) throw new SignalError('signal_subscription_limit')
    const subscription: Subscription = { topics: options.topics === undefined ? null : new Set(options.topics),
      mode: options.mode ?? 'all', queue: new Map(), latest: new Map(), bytes: 0, error: null, wake: null, clean: () => undefined }
    this.#subscriptions.add(subscription)
    const abort = (): void => { this.#release(subscription); subscription.wake?.() }
    subscription.clean = () => options.signal?.removeEventListener('abort', abort)
    options.signal?.addEventListener('abort', abort, { once: true })
    try {
      while (!this.#controller.signal.aborted && options.signal?.aborted !== true) {
        if (subscription.error !== null) throw subscription.error
        const item = subscription.queue.entries().next().value
        if (item !== undefined) {
          subscription.queue.delete(item[0]); subscription.bytes -= item[1].bytes
          if (item[1].message.expiresAtMs > this.#now()) yield structuredClone(item[1].message)
        } else {
          await new Promise<void>(resolve => { subscription.wake = resolve })
          subscription.wake = null
        }
      }
    } finally { this.#release(subscription) }
  }

  close(): void {
    if (this.#controller.signal.aborted) return
    this.#controller.abort(new SignalError('signal_channel_closed'))
    for (const state of this.#routes) this.#detach(state)
    this.#seen.clear()
    for (const subscription of this.#subscriptions) { this.#release(subscription); subscription.wake?.() }
  }
  #release(subscription: Subscription): void {
    subscription.clean(); subscription.queue.clear(); subscription.latest.clear(); subscription.bytes = 0
    this.#subscriptions.delete(subscription)
  }
  async #authorize(message: SignalAuthorization, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted()
    if (!await this.#options.authorize({ scope: message.scope, authorId: message.authorId, topic: message.topic })) throw new SignalError('signal_unauthorized')
    signal.throwIfAborted()
  }
  #checkClock(message: EphemeralSignal): void {
    if (message.expiresAtMs - message.issuedAtMs > this.#ttl || message.issuedAtMs > this.#now() + this.#skew) throw new SignalError('signal_clock_invalid')
  }
  #checkFresh(message: EphemeralSignal): void {
    this.#checkClock(message)
    if (message.expiresAtMs <= this.#now()) throw new SignalError('signal_expired')
  }
  #remember(message: EphemeralSignal): boolean {
    const now = this.#now()
    for (const [key, expires] of this.#seen) if (expires <= now) this.#seen.delete(key)
    const id = `${message.authorId}/${message.sessionId}/${message.sequence}`
    if (this.#seen.has(id)) return false
    if (this.#seen.size >= this.#maxReplay) throw new SignalError('signal_replay_limit')
    this.#seen.set(id, message.expiresAtMs)
    return true
  }
  #deliver(message: EphemeralSignal, bytes: number): void {
    const now = this.#now()
    for (const subscription of this.#subscriptions) {
      if (subscription.topics !== null && !subscription.topics.has(message.topic)) continue
      for (const [key, pending] of subscription.queue) if (pending.message.expiresAtMs <= now) {
        subscription.queue.delete(key); subscription.bytes -= pending.bytes
      }
      const key = `${message.authorId}/${message.sessionId}/${subscription.mode === 'latest' ? message.topic : message.sequence}`
      if (subscription.mode === 'latest') {
        for (const [id, previous] of subscription.latest) if (previous.retainThroughMs <= now) subscription.latest.delete(id)
        const previous = subscription.latest.get(key)
        if (previous !== undefined && previous.sequence >= message.sequence) continue
        if (previous === undefined && subscription.latest.size >= this.#maxQueue) { this.#overflow(subscription); continue }
        subscription.latest.set(key, { sequence: message.sequence, retainThroughMs: now + this.#ttl + this.#skew })
      }
      const replaced = subscription.queue.get(key)
      if (replaced !== undefined) { subscription.queue.delete(key); subscription.bytes -= replaced.bytes }
      if (subscription.queue.size >= this.#maxQueue || subscription.bytes + bytes > this.#maxQueueBytes) this.#overflow(subscription)
      else { subscription.queue.set(key, { message: structuredClone(message), bytes }); subscription.bytes += bytes; subscription.wake?.() }
    }
  }
  #overflow(subscription: Subscription): void {
    subscription.error = new SignalError('signal_subscription_overflow')
    this.#release(subscription); subscription.wake?.()
  }
  async #dispatch(frame: Uint8Array, message: EphemeralSignal, routes: readonly RouteState[], signal: AbortSignal, required: boolean): Promise<void> {
    if (routes.length === 0) { if (required) throw new SignalError('signal_disconnected'); return }
    const attempts = routes.map(async state => {
      if (!this.#routes.has(state)) throw new SignalError('signal_route_closed')
      if (state.busy || this.#pendingDispatches >= this.#maxRoutes) throw new SignalError('signal_route_backpressure')
      state.busy = true; this.#pendingDispatches++
      const deadline = new AbortController()
      const timer = setTimeout(() => deadline.abort(new SignalError('signal_send_timeout')), Math.min(this.#timeout, Math.max(1, message.expiresAtMs - this.#now())))
      const combined = AbortSignal.any([this.#controller.signal, state.controller.signal, deadline.signal, signal])
      let handedOff = false, settled = false
      const operation = (async () => {
        await this.#authorize(message, combined); this.#checkFresh(message)
        handedOff = true
        await state.transport.send(frame.slice(), { signal: combined })
      })().finally(() => { settled = true; state.busy = false; this.#pendingDispatches-- })
      try { await abortable(operation, combined) }
      catch (error) {
        if (handedOff && combined.aborted && !settled) await new Promise<void>(resolve => { setTimeout(resolve, 0) })
        const refused = error instanceof SignalError && error.code === 'signal_route_backpressure'
        if (handedOff && !refused && (!combined.aborted || !settled)) this.#detach(state, true)
        throw error
      } finally { clearTimeout(timer) }
    })
    const completed = Promise.allSettled(attempts)
    void completed.then(results => {
      if (!required || results.some(result => result.status === 'fulfilled')) {
        for (const result of results) if (result.status === 'rejected') this.#report(result.reason)
      }
    })
    if (required) {
      try { await Promise.any(attempts) }
      catch (error) {
        if (error instanceof AggregateError) throw error.errors[0] as unknown
        throw error
      }
    } else await completed
  }
  #detach(state: RouteState, retire = false): void {
    this.#routes.delete(state); state.controller.abort(new SignalError('signal_route_closed'))
    if (retire && !state.retired) {
      state.retired = true
      try { void Promise.resolve(state.transport.close?.()).catch(() => undefined) } catch { /* Already retired. */ }
    }
  }
  #report(error: unknown): void {
    try { this.#options.onError?.(error instanceof Error ? error : new Error(String(error))) } catch { /* Diagnostics do not own live traffic. */ }
  }
  #assertOpen(): void { if (this.#controller.signal.aborted) throw new SignalError('signal_channel_closed') }
  #now(): number {
    const now = this.#options.now?.() ?? Date.now()
    if (!Number.isSafeInteger(now) || now < 0) throw new SignalError('signal_clock_invalid')
    this.#observedTime = Math.max(this.#observedTime, now)
    return this.#observedTime
  }
}
function assertOptions(value: unknown, names: readonly string[]): void {
  const prototype: unknown = typeof value === 'object' && value !== null ? Object.getPrototypeOf(value) : undefined
  if (typeof value !== 'object' || value === null ||
      (prototype !== Object.prototype && prototype !== null) ||
      Object.keys(value).some(name => !names.includes(name))) throw new SignalError('signal_options_invalid')
}
function bound(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new SignalError('signal_bounds_invalid')
  return value
}
function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = (): void => { signal.removeEventListener('abort', abort); reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    if (signal.aborted) abort()
    void promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

import { assertCanonicalCbor, bytesToHex, encodeCanonicalCbor } from '@chronolog/canonical'
import { assertSignalTopic, canonicalSignalPayload, type SignalPayload } from './payload.js'
export { assertSignalTopic, canonicalSignalPayload, type SignalPayload } from './payload.js'

export const SIGNAL_DOMAIN = 'chronolog/signal/v1'
export const MAX_SIGNAL_BYTES = 16_384
export interface SignalIdentity { readonly publicKeyBytes: Uint8Array; readonly privateKey: CryptoKey }
/** Generate an in-memory identity; applications may persist their own key instead. */
export async function generateSignalIdentity(): Promise<SignalIdentity> {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  return { publicKeyBytes: new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)), privateKey: keys.privateKey }
}
export interface SignalAuthorization {
  readonly scope: string
  readonly authorId: Uint8Array
  /** Opaque application credential. Standalone channels need no ledger grant. */
  readonly credential: Uint8Array | null
  readonly topic: string
}
export interface EphemeralSignal {
  readonly scope: string
  readonly authorId: string
  readonly sessionId: string
  readonly sequence: number
  readonly topic: string
  readonly payload: SignalPayload
  readonly issuedAtMs: number
  readonly expiresAtMs: number
}
export interface SignalSendOptions { readonly ttlMs?: number; readonly signal?: AbortSignal }
export interface SignalSubscribeOptions {
  readonly topics?: readonly string[]
  /** all preserves accepted messages; latest coalesces by author, session and topic. */
  readonly mode?: 'all' | 'latest'
  readonly signal?: AbortSignal
}
export interface Signals {
  /** Local dispatch, never a delivery receipt, retained operation or finality promise. */
  send(topic: string, payload: SignalPayload, options?: SignalSendOptions): Promise<EphemeralSignal>
  subscribe(options?: SignalSubscribeOptions): AsyncIterable<EphemeralSignal>
}
export type SignalSender = (frame: Uint8Array, options: { readonly signal: AbortSignal }) => Promise<void>
export interface SignalChannelOptions {
  readonly scope: string
  readonly identity: SignalIdentity
  readonly credential?: Uint8Array | ((topic: string) => Uint8Array | Promise<Uint8Array>)
  /** Explicit application policy; the core has no membership or finality dependency. */
  readonly authorize: (input: SignalAuthorization) => boolean | Promise<boolean>
  readonly send?: SignalSender
  /** Forward verified original frames to other live routes. Disabled by default. */
  readonly relay?: boolean
  readonly now?: () => number
  readonly maxTtlMs?: number
  readonly maxClockSkewMs?: number
  readonly maxSessions?: number
  readonly maxPendingSends?: number
  readonly maxPendingReceives?: number
  readonly maxSubscriptions?: number
  readonly maxSubscriptionMessages?: number
  readonly maxRoutes?: number
  readonly sendTimeoutMs?: number
}
interface SessionProgress { sequence: number; seen: bigint; retainThroughMs: number }
interface Subscription {
  readonly topics: ReadonlySet<string> | null
  readonly mode: 'all' | 'latest'
  readonly pending: EphemeralSignal[]
  readonly latest: Map<string, { sessionId: string; sequence: number }>
  error: Error | null
  wake: (() => void) | null
}
const REPLAY_WINDOW = 256
const REPLAY_MASK = (1n << BigInt(REPLAY_WINDOW)) - 1n

/** Portable signed, expiring messages. No database, history, retry outbox or finality. */
export class SignalChannel implements Signals {
  readonly #options: SignalChannelOptions
  readonly #authorId: Uint8Array
  readonly #session = crypto.getRandomValues(new Uint8Array(32))
  readonly #sessions = new Map<string, SessionProgress>()
  readonly #subscriptions = new Set<Subscription>()
  readonly #routes = new Set<SignalSender>()
  readonly #busyRoutes = new Set<SignalSender>()
  readonly #abort = new AbortController()
  readonly #ttl: number
  readonly #skew: number
  readonly #maxSessions: number
  readonly #maxSends: number
  readonly #maxReceives: number
  readonly #maxSubscriptions: number
  readonly #maxMessages: number
  readonly #maxRoutes: number
  readonly #sendTimeout: number
  #sequence = 0
  #sendTail: Promise<unknown> = Promise.resolve()
  #pendingSends = 0
  #pendingReceives = 0

  constructor(options: SignalChannelOptions) {
    if (typeof options.scope !== 'string' || options.scope.length === 0 || new TextEncoder().encode(options.scope).length > 256) throw new Error('SIGNAL_SCOPE_INVALID')
    if (!(options.identity.publicKeyBytes instanceof Uint8Array) || options.identity.publicKeyBytes.length !== 32 || typeof options.authorize !== 'function') throw new Error('SIGNAL_IDENTITY_INVALID')
    this.#options = { ...options, identity: { publicKeyBytes: options.identity.publicKeyBytes.slice(), privateKey: options.identity.privateKey }, ...(options.credential instanceof Uint8Array ? { credential: options.credential.slice() } : {}) }
    this.#authorId = options.identity.publicKeyBytes.slice()
    this.#ttl = bound(options.maxTtlMs ?? 30_000, 60_000)
    this.#skew = bound(options.maxClockSkewMs ?? 2_000, 10_000, 0)
    this.#maxSessions = bound(options.maxSessions ?? 1024, 16_384)
    this.#maxSends = bound(options.maxPendingSends ?? 32, 1024)
    this.#maxReceives = bound(options.maxPendingReceives ?? 32, 1024)
    this.#maxSubscriptions = bound(options.maxSubscriptions ?? 64, 1024)
    this.#maxMessages = bound(options.maxSubscriptionMessages ?? 64, 4096)
    this.#maxRoutes = bound(options.maxRoutes ?? 32, 1024)
    this.#sendTimeout = bound(options.sendTimeoutMs ?? 10_000, 120_000)
    if (options.send !== undefined) this.#routes.add(options.send)
  }

  /** Attach one live connection. Detaching never queues messages for reconnect. */
  attach(send: SignalSender): () => void {
    this.#assertOpen()
    if (this.#routes.size >= this.#maxRoutes) throw new Error('SIGNAL_ROUTE_QUOTA_EXCEEDED')
    // A unique wrapper makes delayed cleanup safe when a route is reattached.
    const route: SignalSender = (frame, options) => send(frame, options)
    this.#routes.add(route)
    return () => { this.#routes.delete(route) }
  }

  async send(topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> {
    this.#assertOpen(); options.signal?.throwIfAborted()
    if (this.#routes.size === 0) throw new Error('SIGNAL_DISCONNECTED')
    if (this.#pendingSends >= this.#maxSends) throw new Error('SIGNAL_BACKPRESSURE')
    assertSignalTopic(topic)
    const encodedPayload = canonicalSignalPayload(payload)
    const ttlMs = options.ttlMs ?? Math.min(5_000, this.#ttl)
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > this.#ttl) throw new Error('SIGNAL_TTL_INVALID')
    const issuedAtMs = this.#now(), expiresAtMs = issuedAtMs + ttlMs
    if (!Number.isSafeInteger(expiresAtMs)) throw new Error('SIGNAL_CLOCK_OR_SEQUENCE_EXHAUSTED')
    const deadline = AbortSignal.timeout(this.#sendTimeout), expiry = AbortSignal.timeout(ttlMs)
    const signal = AbortSignal.any([this.#abort.signal, deadline, expiry, ...(options.signal === undefined ? [] : [options.signal])])
    this.#pendingSends++
    let started = false
    const task = this.#sendTail.then(async () => {
      this.#assertOpen(); signal.throwIfAborted()
      if (this.#now() >= expiresAtMs) throw new Error('SIGNAL_EXPIRED')
      started = true
      const operation = (async () => {
        const value = typeof this.#options.credential === 'function' ? await this.#options.credential(topic) : this.#options.credential
        if (value !== undefined && (!(value instanceof Uint8Array) || value.length > 1024)) throw new Error('SIGNAL_CREDENTIAL_INVALID')
        const authorization: SignalAuthorization = { scope: this.#options.scope, authorId: this.#authorId.slice(), credential: value?.slice() ?? null, topic }
        if (!await this.#options.authorize(structuredClone(authorization))) throw new Error('SIGNAL_UNAUTHORIZED')
        signal.throwIfAborted()
        if (this.#sequence >= Number.MAX_SAFE_INTEGER) throw new Error('SIGNAL_CLOCK_OR_SEQUENCE_EXHAUSTED')
        const sequence = ++this.#sequence
        const fields = [1n, SIGNAL_DOMAIN, authorization.scope, this.#authorId, authorization.credential, this.#session,
          BigInt(sequence), BigInt(issuedAtMs), BigInt(expiresAtMs), topic, encodedPayload] as const
        const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', this.#options.identity.privateKey, encodeCanonicalCbor(fields).slice().buffer))
        const frame = encodeCanonicalCbor([...fields, signature])
        if (frame.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
        // Key work and policy reads may suspend across revocation or close.
        if (!await this.#options.authorize(structuredClone(authorization))) throw new Error('SIGNAL_UNAUTHORIZED')
        signal.throwIfAborted()
        if (this.#now() >= expiresAtMs) throw new Error('SIGNAL_EXPIRED')
        const message: EphemeralSignal = { scope: authorization.scope, authorId: bytesToHex(this.#authorId), sessionId: bytesToHex(this.#session),
          sequence, issuedAtMs, expiresAtMs, topic, payload: JSON.parse(encodedPayload) as SignalPayload }
        // An echo through a relay cannot publish our own message a second time.
        this.#remember(message)
        await this.#dispatch(frame, signal)
        return message
      })().finally(() => { this.#pendingSends-- })
      // Keep noncooperative policy work counted until it actually settles.
      // Cancellation can release the caller without creating unlimited tasks.
      return abortable(() => operation, signal)
    }).finally(() => { if (!started) this.#pendingSends-- })
    this.#sendTail = task.catch(() => undefined)
    return abortable(() => task, signal)
  }

  async receive(input: Uint8Array): Promise<EphemeralSignal> {
    this.#assertOpen()
    if (!(input instanceof Uint8Array) || input.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
    if (this.#pendingReceives >= this.#maxReceives) throw new Error('SIGNAL_BACKPRESSURE')
    this.#pendingReceives++
    try {
      const bytes = input.slice(), frame = assertCanonicalCbor(bytes, {
        maxBytes: MAX_SIGNAL_BYTES, maxDepth: 2, maxArrayItems: 12, maxMapItems: 0,
        maxTextBytes: MAX_SIGNAL_BYTES, maxBlobBytes: 1024,
      })
      if (!Array.isArray(frame) || frame.length !== 12 || frame[0] !== 1n || frame[1] !== SIGNAL_DOMAIN || frame[2] !== this.#options.scope ||
          !(frame[3] instanceof Uint8Array) || frame[3].length !== 32 ||
          (frame[4] !== null && (!(frame[4] instanceof Uint8Array) || frame[4].length > 1024)) ||
          !(frame[5] instanceof Uint8Array) || frame[5].length !== 32 ||
          typeof frame[6] !== 'bigint' || typeof frame[7] !== 'bigint' || typeof frame[8] !== 'bigint' ||
          typeof frame[9] !== 'string' || typeof frame[10] !== 'string' || !(frame[11] instanceof Uint8Array) || frame[11].length !== 64) throw new Error('SIGNAL_FRAME_INVALID')
      const sequence = Number(frame[6]), issuedAtMs = Number(frame[7]), expiresAtMs = Number(frame[8]), now = this.#now()
      if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 ||
          !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > this.#ttl ||
          issuedAtMs > now + this.#skew || expiresAtMs <= now) throw new Error('SIGNAL_EXPIRED_OR_CLOCK_INVALID')
      assertSignalTopic(frame[9])
      const payload = JSON.parse(frame[10]) as SignalPayload
      if (canonicalSignalPayload(payload) !== frame[10]) throw new Error('SIGNAL_PAYLOAD_INVALID')
      const key = await crypto.subtle.importKey('raw', frame[3].slice().buffer, 'Ed25519', false, ['verify'])
      if (!await crypto.subtle.verify('Ed25519', key, frame[11].slice().buffer, encodeCanonicalCbor(frame.slice(0, 11)).slice().buffer)) throw new Error('SIGNAL_SIGNATURE_INVALID')
      const authorization: SignalAuthorization = { scope: this.#options.scope, authorId: frame[3].slice(),
        credential: frame[4] instanceof Uint8Array ? frame[4].slice() : null, topic: frame[9] }
      if (!await this.#options.authorize(authorization)) throw new Error('SIGNAL_UNAUTHORIZED')
      this.#assertOpen()
      if (expiresAtMs <= this.#now()) throw new Error('SIGNAL_EXPIRED')
      const message: EphemeralSignal = { scope: this.#options.scope, authorId: bytesToHex(frame[3]), sessionId: bytesToHex(frame[5]),
        sequence, issuedAtMs, expiresAtMs, topic: frame[9], payload }
      this.#remember(message)
      for (const subscriber of this.#subscriptions) this.#deliver(subscriber, message)
      if (this.#options.relay === true && this.#routes.size > 0) {
        const signal = AbortSignal.any([this.#abort.signal, AbortSignal.timeout(Math.max(1, Math.min(this.#sendTimeout, expiresAtMs - this.#now())))])
        await abortable(() => this.#dispatch(bytes, signal), signal).catch(() => undefined)
      }
      return structuredClone(message)
    } finally { this.#pendingReceives-- }
  }

  subscribe(options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> {
    const self = this
    return {
      [Symbol.asyncIterator]() {
        const controller = new AbortController()
        const signal = options.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, options.signal])
        const iterator = self.#subscribe({ ...options, signal })
        return {
          next: () => iterator.next(),
          async return() { controller.abort(); return iterator.return() },
          async throw(error: unknown) { controller.abort(); return iterator.throw(error) },
        }
      },
    }
  }

  async *#subscribe(options: SignalSubscribeOptions): AsyncGenerator<EphemeralSignal, void> {
    this.#assertOpen()
    if (options.topics !== undefined) {
      if (!Array.isArray(options.topics) || options.topics.length > 64) throw new Error('SIGNAL_TOPIC_FILTER_TOO_LARGE')
      options.topics.forEach(assertSignalTopic)
    }
    if (options.mode !== undefined && options.mode !== 'all' && options.mode !== 'latest') throw new Error('SIGNAL_SUBSCRIPTION_MODE_INVALID')
    if (this.#subscriptions.size >= this.#maxSubscriptions) throw new Error('SIGNAL_SUBSCRIPTION_QUOTA_EXCEEDED')
    const subscriber: Subscription = { topics: options.topics === undefined ? null : new Set(options.topics), mode: options.mode ?? 'all',
      pending: [], latest: new Map(), error: null, wake: null }
    this.#subscriptions.add(subscriber)
    const abort = (): void => { subscriber.wake?.() }
    options.signal?.addEventListener('abort', abort, { once: true })
    try {
      while (!this.#abort.signal.aborted && options.signal?.aborted !== true) {
        if (subscriber.error !== null) throw subscriber.error
        const message = subscriber.pending.shift()
        if (message !== undefined) {
          if (message.expiresAtMs > this.#now()) yield structuredClone(message)
        } else {
          await new Promise<void>(resolve => {
            subscriber.wake = resolve
            if (this.#abort.signal.aborted || options.signal?.aborted === true || subscriber.pending.length > 0 || subscriber.error !== null) resolve()
          })
          subscriber.wake = null
        }
      }
    } finally { options.signal?.removeEventListener('abort', abort); this.#subscriptions.delete(subscriber) }
  }

  close(): void {
    this.#abort.abort(new Error('SIGNAL_CHANNEL_CLOSED'))
    for (const subscriber of this.#subscriptions) { subscriber.pending.length = 0; subscriber.wake?.() }
    this.#routes.clear(); this.#sessions.clear()
  }

  #deliver(subscriber: Subscription, message: EphemeralSignal): void {
    if (subscriber.error !== null || (subscriber.topics !== null && !subscriber.topics.has(message.topic))) return
    // A paused consumer must not overflow on values that are already unusable.
    const now = this.#now()
    for (let index = subscriber.pending.length - 1; index >= 0; index--) {
      if (subscriber.pending[index]!.expiresAtMs <= now) subscriber.pending.splice(index, 1)
    }
    if (subscriber.mode === 'latest') {
      const key = `${message.authorId}/${message.sessionId}/${message.topic}`, previous = subscriber.latest.get(key)
      if (previous?.sessionId === message.sessionId && previous.sequence >= message.sequence) return
      subscriber.latest.delete(key)
      if (subscriber.latest.size >= this.#maxMessages) subscriber.latest.delete(subscriber.latest.keys().next().value!)
      subscriber.latest.set(key, { sessionId: message.sessionId, sequence: message.sequence })
      const index = subscriber.pending.findIndex(value => value.authorId === message.authorId && value.sessionId === message.sessionId && value.topic === message.topic)
      if (index >= 0) subscriber.pending.splice(index, 1)
      if (subscriber.pending.length >= this.#maxMessages) subscriber.pending.shift()
    } else if (subscriber.pending.length >= this.#maxMessages) {
      subscriber.error = new Error('SIGNAL_SUBSCRIPTION_OVERFLOW')
      subscriber.pending.length = 0; subscriber.wake?.(); return
    }
    subscriber.pending.push(structuredClone(message)); subscriber.wake?.()
  }

  #remember(message: EphemeralSignal): void {
    const now = this.#now()
    for (const [key, value] of this.#sessions) if (value.retainThroughMs <= now) this.#sessions.delete(key)
    const key = `${message.authorId}/${message.sessionId}`, previous = this.#sessions.get(key)
    if (previous === undefined) {
      if (this.#sessions.size >= this.#maxSessions) throw new Error('SIGNAL_SESSION_QUOTA_EXCEEDED')
      this.#sessions.set(key, { sequence: message.sequence, seen: 1n, retainThroughMs: now + this.#ttl + this.#skew })
      return
    }
    const offset = previous.sequence - message.sequence
    if (offset >= REPLAY_WINDOW || (offset >= 0 && (previous.seen & (1n << BigInt(offset))) !== 0n)) throw new Error('SIGNAL_REPLAY')
    if (offset < 0) {
      previous.seen = -offset >= REPLAY_WINDOW ? 1n : ((previous.seen << BigInt(-offset)) | 1n) & REPLAY_MASK
      previous.sequence = message.sequence
    } else previous.seen |= 1n << BigInt(offset)
    previous.retainThroughMs = Math.max(previous.retainThroughMs, now + this.#ttl + this.#skew)
  }

  async #dispatch(bytes: Uint8Array, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted()
    if (this.#routes.size === 0) throw new Error('SIGNAL_DISCONNECTED')
    const routes = [...this.#routes].filter(send => !this.#busyRoutes.has(send))
    if (routes.length === 0) throw new Error('SIGNAL_BACKPRESSURE')
    const dispatches = routes.map(async send => {
      this.#busyRoutes.add(send)
      try { await abortable(() => send(bytes.slice(), { signal }), signal) }
      catch (error) {
        // Never keep invoking a route whose previous dispatch may still be
        // running after cancellation. Explicit reattachment starts a new route.
        if (signal.aborted) this.#routes.delete(send)
        throw error
      }
      finally { this.#busyRoutes.delete(send) }
    })
    // A slow route must not delay healthy peers. Each route has at most one
    // outstanding dispatch; overload skips it and its own deadline retires it.
    try { await Promise.any(dispatches) }
    catch (error) { throw new AggregateError([error], 'SIGNAL_SEND_FAILED', { cause: error }) }
    signal.throwIfAborted()
  }
  #assertOpen(): void { if (this.#abort.signal.aborted) throw new Error('SIGNAL_CHANNEL_CLOSED') }
  #now(): number {
    const now = this.#options.now?.() ?? Date.now()
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('SIGNAL_CLOCK_INVALID')
    return now
  }
}

function bound(value: number, maximum: number, minimum = 1): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error('SIGNAL_BOUNDS_INVALID')
  return value
}
async function abortable<T>(run: () => Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  let abort!: () => void
  const interrupted = new Promise<never>((_resolve, reject) => { abort = () => reject(signal.reason); signal.addEventListener('abort', abort, { once: true }) })
  try { return await Promise.race([run(), interrupted]) }
  finally { signal.removeEventListener('abort', abort) }
}

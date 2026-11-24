import { assertCanonicalCbor, bytesToHex, encodeCanonicalCbor } from '@chronolog/canonical'
import { assertSignalTopic, canonicalSignalPayload, type SignalPayload } from './payload.js'
export { assertSignalTopic, canonicalSignalPayload, type SignalPayload } from './payload.js'

export const SIGNAL_DOMAIN = 'chronolog/signal/v1'
export const SIGNAL_STREAM_DOMAIN = 'chronolog/signal/v2'
export const MAX_SIGNAL_BYTES = 16_384

export interface SignalIdentity { readonly publicKeyBytes: Uint8Array; readonly privateKey: CryptoKey }
/** A standalone identity; persistence is an explicit application responsibility. */
export async function generateSignalIdentity(): Promise<SignalIdentity> {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  return { publicKeyBytes: new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)), privateKey: keys.privateKey }
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
  /** Signer-attested stream context; owners bind endpoint fields to the actual attachment. */
  readonly stream?: SignalStream
}
export interface SignalStream {
  readonly streamId: string
  readonly endpointId?: string
  readonly endpointIncarnation?: string
  /** An application-defined recipient scope; routing is not a confidentiality boundary. */
  readonly target?: string
}
export interface SignalStreamSelector {
  readonly authorId?: string
  readonly sessionId?: string
  readonly streamId?: string
  readonly endpointId?: string
  readonly endpointIncarnation?: string
  readonly target?: string
}
export interface SignalSendOptions { readonly ttlMs?: number; readonly signal?: AbortSignal; readonly stream?: SignalStream }
export interface SignalSubscribeOptions {
  readonly topics?: readonly string[]
  /** OR of bounded exact selectors, applied before latest coalescing. */
  readonly streams?: readonly SignalStreamSelector[]
  readonly mode?: 'all' | 'latest'
  /** Seed a latest-mode subscription with currently fresh retained values for late joiners. */
  readonly includeLatest?: boolean
  readonly signal?: AbortSignal
}
export interface Signals {
  /** Dispatch scope; no send receipt claims every recipient received or processed it. */
  readonly delivery?: 'neighbors' | 'application'
  send(topic: string, payload: SignalPayload, options?: SignalSendOptions): Promise<EphemeralSignal>
  subscribe(options?: SignalSubscribeOptions): AsyncIterable<EphemeralSignal>
}
export class SignalError extends Error {
  constructor(readonly code: string, message = code) { super(message); this.name = 'SignalError' }
}
/** Credentials are authenticated opaque bytes; only the supplied policy interprets them. */
export interface SignalAuthorization {
  readonly scope: string
  readonly authorId: Uint8Array
  readonly topic: string
  readonly credential: Uint8Array | null
  readonly stream?: SignalStream
}
/** Lifetime of this attempt, including caller cancellation, channel close and its deadline. */
export interface SignalPolicyContext { readonly signal: AbortSignal }
export interface SignalTransport {
  /** False refuses congestion before queueing or dispatching. Actual failures throw. Honor cancellation. */
  trySend(frame: Uint8Array, options: { readonly signal: AbortSignal }): Promise<boolean>
  /** Retire an underlying connection on its actual failure or dispatch deadline. */
  close?(reason?: unknown): void | Promise<void>
}
export interface SignalRoute {
  /**
   * Verify once, deliver locally and relay unchanged to the other live routes.
   * Returns null for duplicate/expired/unauthorized frames or a capacity drop before delivery.
   * Capacity drops do not evict retained replay protection or queue a retry.
   */
  receive(frame: Uint8Array): Promise<EphemeralSignal | null>
  close(): void
}
export interface SignalChannelOptions extends SignalLimits {
  readonly scope: string
  readonly identity: SignalIdentity
  readonly authorize: (input: SignalAuthorization, context: SignalPolicyContext) => boolean | Promise<boolean>
  readonly credential?: Uint8Array | ((topic: string, context: SignalPolicyContext) => Uint8Array | undefined | Promise<Uint8Array | undefined>)
  /** Optional standalone outgoing transport. Attach routes for bidirectional relay. */
  readonly trySend?: SignalTransport['trySend']
  readonly relay?: boolean
  /** Allow explicitly configured local-owner fan-out without opening a network route. */
  readonly localEcho?: boolean
  readonly now?: () => number
}
/** Independent live-resource budgets; no database or finality configuration. */
export interface SignalLimits {
  readonly maxTtlMs?: number
  readonly maxClockSkewMs?: number
  readonly maxSessions?: number
  readonly maxSequencesPerSession?: number
  readonly maxRememberedSignals?: number
  readonly maxPendingSends?: number
  readonly maxPendingReceives?: number
  readonly maxRoutes?: number
  readonly maxSubscriptions?: number
  readonly maxQueuedSignals?: number
  readonly maxQueuedBytes?: number
  readonly maxRetainedLatest?: number
  readonly sendTimeoutMs?: number
}

interface SessionProgress { readonly seen: Map<number, number> }
interface Route extends SignalTransport { readonly lifetime: AbortController; busy: boolean; retired: boolean }
interface QueuedSignal { readonly value: EphemeralSignal; readonly bytes: number; readonly key: string }
interface Subscription {
  readonly topics: ReadonlySet<string> | null
  readonly streams: readonly SignalStreamSelector[] | null
  readonly mode: 'all' | 'latest'
  readonly pending: QueuedSignal[]
  readonly latest: Map<string, { readonly sequence: number; readonly retainThroughMs: number }>
  bytes: number
  error: Error | null
  wake: (() => void) | null
  clean: () => void
}
interface VerifiedSignal {
  readonly value: EphemeralSignal
  readonly authorization: SignalAuthorization
  readonly frame: Uint8Array
}

/** Live signed JSON, with no durable storage, history policy or reconnect outbox. */
export class SignalChannel implements Signals {
  readonly #options: SignalChannelOptions
  readonly #authorId: string
  readonly #session = crypto.getRandomValues(new Uint8Array(32))
  readonly #sessions = new Map<string, SessionProgress>()
  readonly #subscriptions = new Set<Subscription>()
  readonly #routes = new Set<Route>()
  /** Detached callbacks retain their quota until the actual operation settles. */
  readonly #retiring = new Set<Route>()
  readonly #lifetime = new AbortController()
  readonly #ttl: number
  readonly #skew: number
  readonly #maxSessions: number
  readonly #maxSequences: number
  readonly #maxRemembered: number
  readonly #maxSends: number
  readonly #maxReceives: number
  readonly #maxRoutes: number
  readonly #maxSubscriptions: number
  readonly #maxQueuedSignals: number
  readonly #maxQueuedBytes: number
  readonly #maxRetainedLatest: number
  readonly #sendTimeout: number
  readonly #verifyKeys = new Map<string, CryptoKey>()
  readonly #retainedLatest = new Map<string, { readonly value: EphemeralSignal; readonly bytes: number }>()
  #sequence = 0
  #sendTail: Promise<unknown> = Promise.resolve()
  #pendingSends = 0
  #pendingReceives = 0
  #remembered = 0
  #observedTime = 0
  #lastPruneAt = 0

  constructor(options: SignalChannelOptions) {
    if (typeof options.scope !== 'string' || options.scope.length === 0 || new TextEncoder().encode(options.scope).length > 256 ||
        !(options.identity.publicKeyBytes instanceof Uint8Array) || options.identity.publicKeyBytes.length !== 32 ||
        typeof options.authorize !== 'function') throw new SignalError('SIGNAL_CONFIGURATION_INVALID')
    const credential = typeof options.credential === 'function' ? options.credential : credentialBytes(options.credential)
    this.#options = { ...options, identity: { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() },
      ...(credential === undefined ? {} : { credential }) }
    this.#authorId = bytesToHex(options.identity.publicKeyBytes)
    this.#ttl = bound(options.maxTtlMs ?? 30_000, 1, 60_000)
    this.#skew = bound(options.maxClockSkewMs ?? 2_000, 0, 10_000)
    this.#maxSessions = bound(options.maxSessions ?? 1024, 1, 65_536)
    this.#maxSequences = bound(options.maxSequencesPerSession ?? 1024, 1, 65_536)
    this.#maxRemembered = bound(options.maxRememberedSignals ?? 8192, 1, 1_048_576)
    this.#maxSends = bound(options.maxPendingSends ?? 32, 1, 1024)
    this.#maxReceives = bound(options.maxPendingReceives ?? 32, 1, 1024)
    this.#maxRoutes = bound(options.maxRoutes ?? 64, 1, 1024)
    this.#maxSubscriptions = bound(options.maxSubscriptions ?? 16, 1, 1024)
    this.#maxQueuedSignals = bound(options.maxQueuedSignals ?? 64, 1, 4096)
    this.#maxQueuedBytes = bound(options.maxQueuedBytes ?? 262_144, 1, 16_777_216)
    this.#maxRetainedLatest = bound(options.maxRetainedLatest ?? 128, 0, 4096)
    this.#sendTimeout = bound(options.sendTimeoutMs ?? 10_000, 1, 120_000)
    if (options.trySend !== undefined) this.attachRoute({ trySend: options.trySend })
  }

  get delivery(): 'neighbors' | 'application' { return this.#options.relay === true ? 'application' : 'neighbors' }

  attachRoute(transport: SignalTransport): SignalRoute {
    this.#assertOpen()
    if (typeof transport.trySend !== 'function') throw new SignalError('SIGNAL_TRANSPORT_INVALID')
    if (this.#routes.size + this.#retiring.size >= this.#maxRoutes) throw new SignalError('SIGNAL_ROUTE_QUOTA_EXCEEDED')
    const route: Route = { trySend: transport.trySend.bind(transport), lifetime: new AbortController(), busy: false, retired: false,
      ...(transport.close === undefined ? {} : { close: transport.close.bind(transport) }) }
    this.#routes.add(route)
    return { receive: frame => this.#enqueueReceive(frame, route), close: () => this.#detach(route) }
  }

  send(topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> {
    try {
      if (typeof options !== 'object' || options === null) throw new SignalError('SIGNAL_OPTIONS_INVALID')
      this.#assertOpen(); options.signal?.throwIfAborted()
      if (this.#routes.size === 0 && this.#options.localEcho !== true) throw new SignalError('SIGNAL_ROUTE_UNAVAILABLE')
      const routes = [...this.#routes]
      if (this.#pendingSends >= this.#maxSends) throw new SignalError('SIGNAL_BACKPRESSURE')
      assertSignalTopic(topic)
      const encodedPayload = canonicalSignalPayload(payload)
      const stream = options.stream === undefined ? undefined : checkedStream(options.stream)
      const ttlMs = bound(options.ttlMs ?? Math.min(5_000, this.#ttl), 1, this.#ttl, 'SIGNAL_TTL_INVALID')
      // Queueing does not refresh a transient intent's lifetime.
      const issuedAtMs = this.#now(), expiresAtMs = issuedAtMs + ttlMs
      if (!Number.isSafeInteger(expiresAtMs)) throw new SignalError('SIGNAL_CLOCK_INVALID')
      const expiry = new AbortController()
      const timer = setTimeout(() => expiry.abort(new SignalError('SIGNAL_SEND_TIMEOUT')), Math.min(ttlMs, this.#sendTimeout))
      const signal = AbortSignal.any([this.#lifetime.signal, expiry.signal, ...(options.signal === undefined ? [] : [options.signal])])
      this.#pendingSends += 1
      let started = false
      const task = this.#sendTail.then(() => {
        signal.throwIfAborted()
        started = true
        const operation = (async () => {
          const configured = this.#options.credential
          const credential = credentialBytes(typeof configured === 'function' ? await configured(topic, { signal }) : configured)
          const authorization: SignalAuthorization = { scope: this.#options.scope, authorId: this.#options.identity.publicKeyBytes.slice(), topic, credential: credential ?? null, ...(stream === undefined ? {} : { stream }) }
          await this.#authorize(authorization, signal)
          if (this.#sequence >= Number.MAX_SAFE_INTEGER) throw new SignalError('SIGNAL_SEQUENCE_EXHAUSTED')
          const sequence = ++this.#sequence
          const fields = [stream === undefined ? 1n : 2n, stream === undefined ? SIGNAL_DOMAIN : SIGNAL_STREAM_DOMAIN, this.#options.scope, this.#options.identity.publicKeyBytes, credential ?? null, this.#session,
            BigInt(sequence), BigInt(issuedAtMs), BigInt(expiresAtMs), topic, encodedPayload, ...(stream === undefined ? [] : [JSON.stringify(stream)])] as const
          const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', this.#options.identity.privateKey,
            encodeCanonicalCbor(fields).slice().buffer))
          const frame = encodeCanonicalCbor([...fields, signature])
          if (frame.length > MAX_SIGNAL_BYTES) throw new SignalError('SIGNAL_FRAME_TOO_LARGE')
          const value: EphemeralSignal = { scope: this.#options.scope, authorId: this.#authorId, sessionId: bytesToHex(this.#session),
            sequence, topic, payload: JSON.parse(encodedPayload) as SignalPayload, issuedAtMs, expiresAtMs, ...(stream === undefined ? {} : { stream }) }
          await this.#authorize(authorization, signal)
          this.#assertFresh(value)
          if (!this.#remember(value)) throw new SignalError('SIGNAL_BACKPRESSURE')
          const local = this.#options.localEcho === true
          if (local) {
            this.#deliver(value, frame.length)
            // Local attachments must not wait behind an unavailable network route.
            if (routes.length > 0) void this.#dispatch({ value, authorization, frame }, routes, signal, false).catch(() => undefined)
          }
          if (!local && !await this.#dispatch({ value, authorization, frame }, routes, signal, true)) {
            // Every route explicitly refused before dispatch. No future loop can
            // replay this intent; retain its sequence but release replay budget.
            this.#forget(value)
            throw new SignalError('SIGNAL_BACKPRESSURE')
          }
          return structuredClone(value)
        })().finally(() => { clearTimeout(timer); this.#pendingSends -= 1 })
        return interrupted(operation, signal)
      }).finally(() => { if (!started) { clearTimeout(timer); this.#pendingSends -= 1 } })
      this.#sendTail = task.catch(() => undefined)
      return interrupted(task, signal)
    } catch (error) { return Promise.reject(error) }
  }

  /** Standalone receive validates and delivers without inferring a relay source. */
  receive(frame: Uint8Array): Promise<EphemeralSignal | null> { return this.#enqueueReceive(frame) }

  #enqueueReceive(input: Uint8Array, route?: Route): Promise<EphemeralSignal | null> {
    try {
      this.#assertOpen()
      if (!(input instanceof Uint8Array) || input.byteLength > MAX_SIGNAL_BYTES) throw new SignalError('SIGNAL_FRAME_TOO_LARGE')
      if (route?.lifetime.signal.aborted === true) throw new SignalError('SIGNAL_ROUTE_CLOSED')
      if (this.#pendingReceives >= this.#maxReceives) return Promise.resolve(null)
      const frame = input.slice()
      const routes = [...this.#routes].filter(attached => attached !== route)
      this.#pendingReceives += 1
      const expiry = new AbortController()
      const timer = setTimeout(() => expiry.abort(new SignalError('SIGNAL_RECEIVE_TIMEOUT')), this.#ttl)
      const signal = AbortSignal.any([this.#lifetime.signal, expiry.signal, ...(route === undefined ? [] : [route.lifetime.signal])])
      const operation = (async () => {
        signal.throwIfAborted()
        const verified = await this.#verify(frame, signal)
        if (verified === null || !this.#remember(verified.value)) return null
        this.#deliver(verified.value, frame.length)
        if (this.#options.relay === true) await this.#dispatch(verified, routes, signal, false)
        return structuredClone(verified.value)
      })().finally(() => { clearTimeout(timer); this.#pendingReceives -= 1 })
      return interrupted(operation, signal)
    } catch (error) { return Promise.reject(error) }
  }

  async #verify(bytes: Uint8Array, signal: AbortSignal): Promise<VerifiedSignal | null> {
    const frame = assertCanonicalCbor(bytes, { maxBytes: MAX_SIGNAL_BYTES, maxDepth: 2, maxArrayItems: 13,
      maxMapItems: 0, maxTextBytes: MAX_SIGNAL_BYTES, maxBlobBytes: 1024 })
    if (!Array.isArray(frame) || !(frame.length === 12 && frame[0] === 1n && frame[1] === SIGNAL_DOMAIN || frame.length === 13 && frame[0] === 2n && frame[1] === SIGNAL_STREAM_DOMAIN) || frame[2] !== this.#options.scope ||
        !(frame[3] instanceof Uint8Array) || frame[3].length !== 32 ||
        (frame[4] !== null && (!(frame[4] instanceof Uint8Array) || frame[4].length > 1024)) ||
        !(frame[5] instanceof Uint8Array) || frame[5].length !== 32 ||
        typeof frame[6] !== 'bigint' || typeof frame[7] !== 'bigint' || typeof frame[8] !== 'bigint' ||
        typeof frame[9] !== 'string' || typeof frame[10] !== 'string' ||
        !(frame[frame.length - 1] instanceof Uint8Array) || (frame[frame.length - 1] as Uint8Array).length !== 64) throw new SignalError('SIGNAL_FRAME_INVALID')
    assertSignalTopic(frame[9])
    const stream = frame.length === 13 ? decodeStream(frame[11]) : undefined
    const payload = JSON.parse(frame[10]) as SignalPayload
    if (canonicalSignalPayload(payload) !== frame[10]) throw new SignalError('SIGNAL_PAYLOAD_INVALID')
    const value: EphemeralSignal = { scope: this.#options.scope, authorId: bytesToHex(frame[3]), sessionId: bytesToHex(frame[5]),
      sequence: Number(frame[6]), issuedAtMs: Number(frame[7]), expiresAtMs: Number(frame[8]), topic: frame[9], payload, ...(stream === undefined ? {} : { stream }) }
    this.#assertClock(value)
    let key = this.#verifyKeys.get(value.authorId)
    if (key === undefined) {
      key = await crypto.subtle.importKey('raw', frame[3].slice().buffer, 'Ed25519', false, ['verify'])
      if (this.#verifyKeys.size >= 256) {
        const oldest = this.#verifyKeys.keys().next().value
        if (oldest !== undefined) this.#verifyKeys.delete(oldest)
      }
      this.#verifyKeys.set(value.authorId, key)
    }
    if (!await crypto.subtle.verify('Ed25519', key, (frame[frame.length - 1] as Uint8Array).slice().buffer, encodeCanonicalCbor(frame.slice(0, -1)).slice().buffer)) {
      throw new SignalError('SIGNAL_SIGNATURE_INVALID')
    }
    const credential = frame[4] as Uint8Array | null
    const authorization: SignalAuthorization = { scope: value.scope, authorId: frame[3].slice(), topic: value.topic, credential: credential?.slice() ?? null, ...(stream === undefined ? {} : { stream }) }
    if (!await this.#allowed(authorization, signal)) return null
    this.#assertClock(value)
    if (value.expiresAtMs <= this.#now()) return null
    return { value, authorization, frame: bytes }
  }

  async #allowed(input: SignalAuthorization, signal: AbortSignal): Promise<boolean> {
    signal.throwIfAborted()
    const allowed = await this.#options.authorize(structuredClone(input), { signal })
    signal.throwIfAborted()
    return allowed
  }

  async #authorize(input: SignalAuthorization, signal: AbortSignal): Promise<void> {
    if (!await this.#allowed(input, signal)) throw new SignalError('SIGNAL_UNAUTHORIZED')
  }

  async #dispatch(verified: VerifiedSignal, eligible: readonly Route[], signal: AbortSignal, required: boolean): Promise<boolean> {
    // A replacement connection is eligible only for a later admitted attempt.
    const attached = eligible.filter(route => !route.lifetime.signal.aborted)
    if (required && attached.length === 0) throw new SignalError('SIGNAL_ROUTE_UNAVAILABLE')
    const routes = attached.filter(route => !route.busy)
    if (routes.length === 0) return false
    const attempts = routes.map(route => {
      route.busy = true
      let handedOff = false, settled = false
      const deadline = new AbortController()
      const timer = setTimeout(() => {
        const reason = new SignalError('SIGNAL_SEND_TIMEOUT')
        deadline.abort(reason)
        if (handedOff && !settled) this.#detach(route, true, reason)
      }, Math.max(1, Math.min(this.#sendTimeout, verified.value.expiresAtMs - this.#now())))
      const lifetime = AbortSignal.any([signal, route.lifetime.signal, deadline.signal])
      const operation = (async () => {
        await this.#authorize(verified.authorization, lifetime)
        this.#assertFresh(verified.value)
        handedOff = true
        const result = await route.trySend(verified.frame.slice(), { signal: lifetime })
        if (typeof result !== 'boolean') {
          throw new SignalError('SIGNAL_TRANSPORT_RESULT_INVALID')
        }
        return result
      })().catch((error: unknown) => {
        // Inspect the actual transport result even if this send's observer has
        // already cancelled. A caller's abort is not a shared-route failure.
        if (handedOff && (!lifetime.aborted || error !== lifetime.reason)) this.#detach(route, true, error)
        throw error
      }).finally(() => { settled = true; route.busy = false; this.#retiring.delete(route); clearTimeout(timer) })
      // Caller cancellation releases its waiter immediately, but cannot release
      // this admitted write's capacity or deadline. WebCrypto can settle on a
      // later event-loop turn; only settlement or the write's own deadline ends
      // that ownership. A permanently stuck callback remains bounded per route.
      return interrupted(operation, lifetime)
    })
    // Healthy routes progress without waiting for a slow peer. Each route keeps
    // its own deadline and at most one unsettled dispatch after this resolves.
    if (required) {
      const refused = new Error('Signal dispatch refused')
      try {
        return await Promise.any(attempts.map(async attempt => {
          if (!await attempt) throw refused
          return true
        }))
      }
      catch (error) {
        if (error instanceof AggregateError) {
          const failures = error.errors.filter(value => value !== refused)
          if (failures.length === 0) return false
          if (failures.length === 1) throw failures[0]
        }
        throw new SignalError('SIGNAL_SEND_FAILED')
      }
    }
    return (await Promise.allSettled(attempts)).some(result => result.status === 'fulfilled' && result.value)
  }

  #pruneRemembered(now: number): void {
    this.#lastPruneAt = now
    for (const [id, progress] of this.#sessions) {
      for (const [sequence, expiresAtMs] of progress.seen) if (expiresAtMs <= now) { progress.seen.delete(sequence); this.#remembered -= 1 }
      if (progress.seen.size === 0) this.#sessions.delete(id)
    }
  }

  #remember(value: EphemeralSignal): boolean {
    const now = this.#now()
    const key = `${value.authorId}/${value.sessionId}`
    let previous = this.#sessions.get(key)
    const existingExpiry = previous?.seen.get(value.sequence)
    if (existingExpiry !== undefined) {
      if (existingExpiry > now) return false
      previous!.seen.delete(value.sequence); this.#remembered -= 1
      if (previous!.seen.size === 0) { this.#sessions.delete(key); previous = undefined }
    }
    if (now - this.#lastPruneAt >= 1_000 ||
        (previous === undefined && this.#sessions.size >= this.#maxSessions) ||
        (previous?.seen.size ?? 0) >= this.#maxSequences ||
        this.#remembered >= this.#maxRemembered) {
      this.#pruneRemembered(now)
      previous = this.#sessions.get(key)
    }
    if (previous === undefined && this.#sessions.size >= this.#maxSessions) return false
    if ((previous?.seen.size ?? 0) >= this.#maxSequences || this.#remembered >= this.#maxRemembered) return false
    // Relay paths can reorder distinct sequences. Retain each fresh identity;
    // never evict still-valid duplicates to make room for unbounded traffic.
    const progress = previous ?? { seen: new Map<number, number>() }
    progress.seen.set(value.sequence, value.expiresAtMs); this.#remembered += 1
    this.#sessions.set(key, progress)
    return true
  }

  #forget(value: EphemeralSignal): void {
    const key = `${value.authorId}/${value.sessionId}`, session = this.#sessions.get(key)
    if (session?.seen.delete(value.sequence) === true) this.#remembered -= 1
    if (session?.seen.size === 0) this.#sessions.delete(key)
  }

  #deliver(value: EphemeralSignal, bytes: number): void {
    const now = this.#now()
    const streamKey = JSON.stringify([value.authorId, value.sessionId, value.topic, value.stream?.endpointId ?? null, value.stream?.endpointIncarnation ?? null, value.stream?.streamId ?? null, value.stream?.target ?? null])
    if (this.#maxRetainedLatest > 0 && value.expiresAtMs > now) {
      const prior = this.#retainedLatest.get(streamKey)
      if (prior === undefined || prior.value.sequence < value.sequence || prior.value.expiresAtMs <= now) {
        if (prior !== undefined) this.#retainedLatest.delete(streamKey)
        else if (this.#retainedLatest.size >= this.#maxRetainedLatest) {
          for (const [id, entry] of this.#retainedLatest) if (entry.value.expiresAtMs <= now) this.#retainedLatest.delete(id)
          if (this.#retainedLatest.size >= this.#maxRetainedLatest) {
            const oldest = this.#retainedLatest.keys().next().value
            if (oldest !== undefined) this.#retainedLatest.delete(oldest)
          }
        }
        this.#retainedLatest.set(streamKey, { value: structuredClone(value), bytes })
      }
    }
    for (const subscriber of this.#subscriptions) {
      if (subscriber.topics !== null && !subscriber.topics.has(value.topic)) continue
      if (subscriber.streams !== null && !subscriber.streams.some(selector => matchesStream(value, selector))) continue
      for (let index = subscriber.pending.length - 1; index >= 0; index -= 1) {
        if (subscriber.pending[index]!.value.expiresAtMs <= now) subscriber.bytes -= subscriber.pending.splice(index, 1)[0]!.bytes
      }
      for (const [id, latest] of subscriber.latest) if (latest.retainThroughMs <= now) subscriber.latest.delete(id)
      const key = streamKey
      if (subscriber.mode === 'latest') {
        const previous = subscriber.latest.get(key)
        if (previous !== undefined && previous.sequence >= value.sequence) continue
        if (previous === undefined && subscriber.latest.size >= this.#maxQueuedSignals) {
          this.#overflow(subscriber); continue
        }
        // Remember delivered values too, across the full remaining lifetime of
        // a reordered older frame, even if this newer value had a shorter TTL.
        subscriber.latest.set(key, { sequence: value.sequence, retainThroughMs: now + this.#ttl + this.#skew })
        const index = subscriber.pending.findIndex(item => item.key === key)
        if (index !== -1) subscriber.bytes -= subscriber.pending.splice(index, 1)[0]!.bytes
      }
      if (subscriber.pending.length >= this.#maxQueuedSignals || subscriber.bytes + bytes > this.#maxQueuedBytes) {
        this.#overflow(subscriber)
      } else {
        subscriber.pending.push({ value: structuredClone(value), bytes, key }); subscriber.bytes += bytes
      }
      subscriber.wake?.()
    }
  }

  #overflow(subscriber: Subscription): void {
    subscriber.error = new SignalError('SIGNAL_SUBSCRIPTION_OVERFLOW')
    subscriber.pending.length = 0; subscriber.bytes = 0; subscriber.latest.clear()
    subscriber.clean(); this.#subscriptions.delete(subscriber); subscriber.wake?.()
  }

  subscribe(options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> {
    if (typeof options !== 'object' || options === null) throw new SignalError('SIGNAL_OPTIONS_INVALID')
    const self = this
    return { [Symbol.asyncIterator]() {
      const controller = new AbortController()
      const signal = options.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, options.signal])
      const iterator = self.#subscribe({ ...options, signal })
      return { next: () => iterator.next(),
        async return() { controller.abort(); return iterator.return() },
        async throw(error: unknown) { controller.abort(); return iterator.throw(error) } }
    } }
  }

  async *#subscribe(options: SignalSubscribeOptions): AsyncGenerator<EphemeralSignal, void> {
    this.#assertOpen()
    if (typeof options !== 'object' || options === null) throw new SignalError('SIGNAL_OPTIONS_INVALID')
    const mode = options.mode ?? 'all'
    if (mode !== 'all' && mode !== 'latest') throw new SignalError('SIGNAL_SUBSCRIPTION_MODE_INVALID')
    if (options.topics !== undefined) {
      if (!Array.isArray(options.topics) || options.topics.length > 64) throw new SignalError('SIGNAL_TOPIC_FILTER_TOO_LARGE')
      for (const topic of options.topics as readonly unknown[]) {
        if (typeof topic !== 'string') throw new SignalError('SIGNAL_TOPIC_FILTER_INVALID')
        assertSignalTopic(topic)
      }
    }
    const streams = options.streams === undefined ? null : checkedSelectors(options.streams)
    if (this.#subscriptions.size >= this.#maxSubscriptions) throw new SignalError('SIGNAL_SUBSCRIPTION_QUOTA_EXCEEDED')
    const subscriber: Subscription = { topics: options.topics === undefined ? null : new Set(options.topics), streams, mode,
      pending: [], latest: new Map(), bytes: 0, error: null, wake: null, clean: () => undefined }
    if (options.includeLatest === true) {
      if (mode !== 'latest') throw new SignalError('SIGNAL_SUBSCRIPTION_MODE_INVALID')
      const now = this.#now()
      for (const [key, entry] of this.#retainedLatest) {
        if (entry.value.expiresAtMs <= now) { this.#retainedLatest.delete(key); continue }
        if (subscriber.topics !== null && !subscriber.topics.has(entry.value.topic)) continue
        if (subscriber.streams !== null && !subscriber.streams.some(selector => matchesStream(entry.value, selector))) continue
        if (subscriber.pending.length >= this.#maxQueuedSignals || subscriber.bytes + entry.bytes > this.#maxQueuedBytes) break
        subscriber.latest.set(key, { sequence: entry.value.sequence, retainThroughMs: now + this.#ttl + this.#skew })
        subscriber.pending.push({ value: structuredClone(entry.value), bytes: entry.bytes, key })
        subscriber.bytes += entry.bytes
      }
    }
    this.#subscriptions.add(subscriber)
    const signal = options.signal
    const abort = (): void => {
      subscriber.pending.length = 0; subscriber.bytes = 0; subscriber.latest.clear()
      subscriber.clean()
      this.#subscriptions.delete(subscriber); subscriber.wake?.()
    }
    subscriber.clean = () => signal?.removeEventListener('abort', abort)
    signal?.addEventListener('abort', abort, { once: true })
    try {
      while (!this.#lifetime.signal.aborted && signal?.aborted !== true) {
        if (subscriber.error !== null) throw subscriber.error
        const item = subscriber.pending.shift()
        if (item !== undefined) {
          subscriber.bytes -= item.bytes
          if (item.value.expiresAtMs > this.#now()) yield structuredClone(item.value)
        } else {
          await new Promise<void>(resolve => {
            subscriber.wake = resolve
            if (this.#lifetime.signal.aborted || signal?.aborted === true || subscriber.pending.length > 0 || subscriber.error !== null) resolve()
          })
          subscriber.wake = null
        }
      }
    } finally { subscriber.clean(); this.#subscriptions.delete(subscriber) }
  }

  close(): void {
    if (this.#lifetime.signal.aborted) return
    this.#lifetime.abort(new SignalError('SIGNAL_CHANNEL_CLOSED'))
    for (const route of this.#routes) this.#detach(route)
    for (const subscriber of this.#subscriptions) { subscriber.pending.length = 0; subscriber.latest.clear(); subscriber.clean(); subscriber.wake?.() }
    this.#subscriptions.clear(); this.#sessions.clear(); this.#retainedLatest.clear(); this.#verifyKeys.clear(); this.#remembered = 0
  }

  #detach(route: Route, retire = false, reason: unknown = new SignalError('SIGNAL_ROUTE_CLOSED')): void {
    if (route.busy) this.#retiring.add(route)
    this.#routes.delete(route); route.lifetime.abort(reason)
    if (retire && !route.retired) {
      route.retired = true
      try { void Promise.resolve(route.close?.(reason)).catch(() => undefined) } catch { /* The route is already retired. */ }
    }
  }
  #assertOpen(): void { this.#lifetime.signal.throwIfAborted() }
  #assertFresh(value: EphemeralSignal): void {
    this.#assertClock(value)
    if (value.expiresAtMs <= this.#now()) throw new SignalError('SIGNAL_EXPIRED')
  }
  #assertClock(value: EphemeralSignal): void {
    const now = this.#now()
    if (!Number.isSafeInteger(value.sequence) || value.sequence < 1 || !Number.isSafeInteger(value.issuedAtMs) || value.issuedAtMs < 0 ||
        !Number.isSafeInteger(value.expiresAtMs) || value.expiresAtMs <= value.issuedAtMs || value.expiresAtMs - value.issuedAtMs > this.#ttl ||
        value.issuedAtMs > now + this.#skew) throw new SignalError('SIGNAL_CLOCK_INVALID')
  }
  #now(): number {
    const now = bound(this.#options.now?.() ?? Date.now(), 0, Number.MAX_SAFE_INTEGER, 'SIGNAL_CLOCK_INVALID')
    // A local wall-clock adjustment cannot make expired frames admissible again.
    this.#observedTime = Math.max(this.#observedTime, now)
    return this.#observedTime
  }
}

function credentialBytes(value: Uint8Array | undefined): Uint8Array | undefined {
  if (value === undefined) return undefined
  if (!(value instanceof Uint8Array) || value.length > 1024) throw new SignalError('SIGNAL_CREDENTIAL_INVALID')
  return value.slice()
}
function bound(value: number, minimum: number, maximum: number, code = 'SIGNAL_BOUNDS_INVALID'): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new SignalError(code)
  return value
}
function interrupted<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => { reject(signal.reason); signal.removeEventListener('abort', abort) }
    signal.addEventListener('abort', abort, { once: true })
    void operation.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
    if (signal.aborted) abort()
  })
}

function checkedStream(value: SignalStream): SignalStream {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !['streamId', 'endpointId', 'endpointIncarnation', 'target'].includes(key)) ||
      !boundedLabel(value.streamId) ||
      (value.endpointId === undefined) !== (value.endpointIncarnation === undefined) ||
      value.endpointId !== undefined && !boundedLabel(value.endpointId) ||
      value.endpointIncarnation !== undefined && !boundedLabel(value.endpointIncarnation) ||
      value.target !== undefined && !boundedLabel(value.target)) throw new SignalError('SIGNAL_STREAM_INVALID')
  return { streamId: value.streamId, ...(value.endpointId === undefined ? {} : { endpointId: value.endpointId, endpointIncarnation: value.endpointIncarnation! }),
    ...(value.target === undefined ? {} : { target: value.target }) }
}
function decodeStream(value: unknown): SignalStream {
  if (typeof value !== 'string' || value.length > 2048) throw new SignalError('SIGNAL_STREAM_INVALID')
  let parsed: unknown
  try { parsed = JSON.parse(value) as unknown } catch { throw new SignalError('SIGNAL_STREAM_INVALID') }
  const stream = checkedStream(parsed as SignalStream)
  if (JSON.stringify(stream) !== value) throw new SignalError('SIGNAL_STREAM_INVALID')
  return stream
}
function boundedLabel(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(value)
}
function checkedSelectors(value: readonly SignalStreamSelector[]): readonly SignalStreamSelector[] {
  const keys = ['authorId', 'sessionId', 'streamId', 'endpointId', 'endpointIncarnation', 'target']
  if (!Array.isArray(value) || value.length > 64 || value.some((selector: unknown) => selector === null || typeof selector !== 'object' ||
      Array.isArray(selector) || Object.entries(selector as Record<string, unknown>).some(([key, item]) => !keys.includes(key) || !boundedLabel(item)))) {
    throw new SignalError('SIGNAL_STREAM_FILTER_INVALID')
  }
  return structuredClone(value as readonly SignalStreamSelector[])
}
function matchesStream(value: EphemeralSignal, selector: SignalStreamSelector): boolean {
  return (selector.authorId === undefined || selector.authorId === value.authorId) &&
    (selector.sessionId === undefined || selector.sessionId === value.sessionId) &&
    (selector.streamId === undefined || selector.streamId === value.stream?.streamId) &&
    (selector.endpointId === undefined || selector.endpointId === value.stream?.endpointId) &&
    (selector.endpointIncarnation === undefined || selector.endpointIncarnation === value.stream?.endpointIncarnation) &&
    (selector.target === undefined || selector.target === value.stream?.target)
}

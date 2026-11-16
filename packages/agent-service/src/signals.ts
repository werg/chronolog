import {
  assertCanonicalCbor, assertEventTopic, bytesToHex, canonicalEventPayload, encodeCanonicalCbor, equalBytes,
} from '@chronolog/protocol'
import type { Ed25519KeyPair, EventPayload } from '@chronolog/protocol'

const SIGNAL_DOMAIN = 'chronolog/ephemeral/v1'
export const MAX_SIGNAL_BYTES = 16_384

export interface SignalAuthorization {
  readonly authorId: Uint8Array
  readonly grantId: Uint8Array
  readonly topic: string
}

export interface EphemeralSignal extends SignalAuthorization {
  readonly groupId: Uint8Array
  readonly sessionId: string
  readonly sequence: number
  readonly issuedAtMs: number
  readonly expiresAtMs: number
  readonly payload: EventPayload
}

export interface EphemeralChannelOptions {
  readonly groupId: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly grantId: Uint8Array
  /** The connection carries these bounded frames independently of durable sync. */
  readonly send: (frame: Uint8Array) => Promise<void>
  /** Check the receiver's currently active Chronolog grant, never connection identity. */
  readonly authorize: (input: SignalAuthorization) => boolean | Promise<boolean>
  readonly now?: () => number
  readonly maxTtlMs?: number
  readonly maxClockSkewMs?: number
  readonly maxSessions?: number
  readonly maxPendingSends?: number
  readonly maxPendingReceives?: number
  readonly maxSubscriptionKeys?: number
}

interface SessionProgress { readonly sequence: number; readonly retainThroughMs: number }
interface SignalSubscription {
  readonly topics: ReadonlySet<string> | null
  readonly pending: Map<string, EphemeralSignal>
  wake: (() => void) | null
}

/**
 * Signed, replaceable peer signals. Nothing here is an event log, checkpoint or
 * source of finality. A disconnected receiver only knows local revocations.
 */
export class EphemeralChannel {
  readonly #options: EphemeralChannelOptions
  readonly #groupId: Uint8Array
  readonly #grantId: Uint8Array
  readonly #authorId: Uint8Array
  readonly #session = crypto.getRandomValues(new Uint8Array(32))
  readonly #sessions = new Map<string, SessionProgress>()
  readonly #subscriptions = new Set<SignalSubscription>()
  readonly #ttl: number
  readonly #skew: number
  readonly #maxSessions: number
  readonly #maxSends: number
  readonly #maxReceives: number
  readonly #maxSubscriptionKeys: number
  #sequence = 0
  #sendTail: Promise<unknown> = Promise.resolve()
  #pendingSends = 0
  #pendingReceives = 0
  #closed = false

  private constructor(options: EphemeralChannelOptions) {
    for (const bytes of [options.groupId, options.grantId, options.identity.publicKeyBytes]) {
      if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('SIGNAL_IDENTITY_INVALID')
    }
    this.#options = options
    this.#groupId = options.groupId.slice(); this.#grantId = options.grantId.slice(); this.#authorId = options.identity.publicKeyBytes.slice()
    this.#ttl = options.maxTtlMs ?? 30_000
    this.#skew = options.maxClockSkewMs ?? 2_000
    this.#maxSessions = options.maxSessions ?? 1024
    this.#maxSends = options.maxPendingSends ?? 32
    this.#maxReceives = options.maxPendingReceives ?? 32
    this.#maxSubscriptionKeys = options.maxSubscriptionKeys ?? 64
    for (const value of [this.#ttl, this.#maxSessions, this.#maxSends, this.#maxReceives, this.#maxSubscriptionKeys]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error('SIGNAL_BOUNDS_INVALID')
    }
    if (this.#ttl > 60_000 || !Number.isSafeInteger(this.#skew) || this.#skew < 0 || this.#skew > 10_000) {
      throw new Error('SIGNAL_BOUNDS_INVALID')
    }
  }

  static async open(options: EphemeralChannelOptions): Promise<EphemeralChannel> { return new EphemeralChannel(options) }

  publish(topic: string, payload: EventPayload, options: { readonly ttlMs?: number } = {}): Promise<EphemeralSignal> {
    if (this.#closed) return Promise.reject(new Error('SIGNAL_CHANNEL_CLOSED'))
    if (this.#pendingSends >= this.#maxSends) return Promise.reject(new Error('SIGNAL_BACKPRESSURE'))
    assertEventTopic(topic)
    const encodedPayload = canonicalEventPayload(payload)
    const ttlMs = options.ttlMs ?? Math.min(5_000, this.#ttl)
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > this.#ttl) return Promise.reject(new Error('SIGNAL_TTL_INVALID'))
    this.#pendingSends += 1
    const task = this.#sendTail.then(async () => {
      if (this.#closed) throw new Error('SIGNAL_CHANNEL_CLOSED')
      const authorization = { authorId: this.#authorId.slice(), grantId: this.#grantId.slice(), topic }
      if (!await this.#options.authorize(structuredClone(authorization))) throw new Error('SIGNAL_UNAUTHORIZED')
      const issuedAtMs = this.#now(), expiresAtMs = issuedAtMs + ttlMs
      if (!Number.isSafeInteger(expiresAtMs) || this.#sequence >= Number.MAX_SAFE_INTEGER) throw new Error('SIGNAL_CLOCK_OR_SEQUENCE_EXHAUSTED')
      const sequence = ++this.#sequence
      const fields = [1n, SIGNAL_DOMAIN, this.#groupId, this.#authorId, this.#grantId, this.#session,
        BigInt(sequence), BigInt(issuedAtMs), BigInt(expiresAtMs), topic, encodedPayload] as const
      const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', this.#options.identity.privateKey,
        encodeCanonicalCbor(fields).slice().buffer))
      const frame = encodeCanonicalCbor([...fields, signature])
      if (frame.length > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
      // Queued/signing work must not send an already-expired replaceable signal.
      if (this.#now() >= expiresAtMs) throw new Error('SIGNAL_EXPIRED')
      await this.#options.send(frame)
      return { ...authorization, groupId: this.#groupId.slice(), sessionId: bytesToHex(this.#session), sequence,
        issuedAtMs, expiresAtMs, payload: JSON.parse(encodedPayload) as EventPayload }
    }).finally(() => { this.#pendingSends -= 1 })
    this.#sendTail = task.catch(() => undefined)
    return task
  }

  async receive(input: Uint8Array): Promise<EphemeralSignal> {
    if (this.#closed) throw new Error('SIGNAL_CHANNEL_CLOSED')
    if (!(input instanceof Uint8Array) || input.byteLength > MAX_SIGNAL_BYTES) throw new Error('SIGNAL_FRAME_TOO_LARGE')
    if (this.#pendingReceives >= this.#maxReceives) throw new Error('SIGNAL_BACKPRESSURE')
    this.#pendingReceives += 1
    try {
      const frame = assertCanonicalCbor(input.slice())
      if (!Array.isArray(frame) || frame.length !== 12 || frame[0] !== 1n || frame[1] !== SIGNAL_DOMAIN ||
          !(frame[2] instanceof Uint8Array) || !equalBytes(frame[2], this.#groupId) ||
          !(frame[3] instanceof Uint8Array) || frame[3].length !== 32 ||
          !(frame[4] instanceof Uint8Array) || frame[4].length !== 32 ||
          !(frame[5] instanceof Uint8Array) || frame[5].length !== 32 ||
          typeof frame[6] !== 'bigint' || typeof frame[7] !== 'bigint' || typeof frame[8] !== 'bigint' ||
          typeof frame[9] !== 'string' || typeof frame[10] !== 'string' ||
          !(frame[11] instanceof Uint8Array) || frame[11].length !== 64) throw new Error('SIGNAL_FRAME_INVALID')
      const sequence = Number(frame[6]), issuedAtMs = Number(frame[7]), expiresAtMs = Number(frame[8])
      const now = this.#now()
      if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 ||
          !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > this.#ttl ||
          issuedAtMs > now + this.#skew || expiresAtMs <= now) throw new Error('SIGNAL_EXPIRED_OR_CLOCK_INVALID')
      assertEventTopic(frame[9])
      const payload = JSON.parse(frame[10]) as EventPayload
      if (canonicalEventPayload(payload) !== frame[10]) throw new Error('SIGNAL_PAYLOAD_INVALID')
      const key = await crypto.subtle.importKey('raw', frame[3].slice().buffer, 'Ed25519', false, ['verify'])
      if (!await crypto.subtle.verify('Ed25519', key, frame[11].slice().buffer, encodeCanonicalCbor(frame.slice(0, 11)).slice().buffer)) {
        throw new Error('SIGNAL_SIGNATURE_INVALID')
      }
      const authorization = { authorId: frame[3].slice(), grantId: frame[4].slice(), topic: frame[9] }
      if (!await this.#options.authorize(structuredClone(authorization))) throw new Error('SIGNAL_UNAUTHORIZED')
      const currentTime = this.#now()
      if (this.#closed) throw new Error('SIGNAL_CHANNEL_CLOSED')
      if (expiresAtMs <= currentTime) throw new Error('SIGNAL_EXPIRED')
      for (const [id, progress] of this.#sessions) if (progress.retainThroughMs <= currentTime) this.#sessions.delete(id)
      const sessionId = bytesToHex(frame[5]), senderSession = `${bytesToHex(frame[3])}/${sessionId}`
      const previous = this.#sessions.get(senderSession)
      if (previous !== undefined && sequence <= previous.sequence) throw new Error('SIGNAL_REPLAY')
      if (previous === undefined && this.#sessions.size >= this.#maxSessions) throw new Error('SIGNAL_SESSION_QUOTA_EXCEEDED')
      // A lower-sequence frame can have a longer TTL than the latest frame. Keep
      // the replay floor for the entire admissible lifetime, not only this
      // frame's expiry; otherwise a delayed older frame could become fresh again.
      this.#sessions.set(senderSession, { sequence,
        retainThroughMs: Math.max(currentTime + this.#ttl + this.#skew, previous?.retainThroughMs ?? 0) })
      const signal: EphemeralSignal = { ...authorization, groupId: this.#groupId.slice(), sessionId, sequence,
        issuedAtMs, expiresAtMs, payload }
      for (const subscriber of this.#subscriptions) {
        if (subscriber.topics !== null && !subscriber.topics.has(signal.topic)) continue
        const replacementKey = `${bytesToHex(signal.authorId)}/${signal.topic}`
        subscriber.pending.delete(replacementKey)
        if (subscriber.pending.size >= this.#maxSubscriptionKeys) subscriber.pending.delete(subscriber.pending.keys().next().value!)
        subscriber.pending.set(replacementKey, structuredClone(signal))
        subscriber.wake?.()
      }
      return structuredClone(signal)
    } finally { this.#pendingReceives -= 1 }
  }

  /** Slow consumers see latest replaceable values, with a fixed memory bound. */
  async *subscribe(options: { readonly topics?: readonly string[]; readonly signal?: AbortSignal } = {}): AsyncIterable<EphemeralSignal> {
    if (options.topics !== undefined) {
      if (options.topics.length > 64) throw new Error('SIGNAL_TOPIC_FILTER_TOO_LARGE')
      for (const topic of options.topics) assertEventTopic(topic)
    }
    const subscriber: SignalSubscription = { topics: options.topics === undefined ? null : new Set(options.topics), pending: new Map(), wake: null }
    this.#subscriptions.add(subscriber)
    const abort = (): void => { subscriber.wake?.() }
    options.signal?.addEventListener('abort', abort, { once: true })
    try {
      while (!this.#closed && options.signal?.aborted !== true) {
        const item = subscriber.pending.entries().next().value
        if (item !== undefined) {
          subscriber.pending.delete(item[0])
          if (item[1].expiresAtMs > this.#now()) yield structuredClone(item[1])
        } else {
          await new Promise<void>((resolve) => {
            subscriber.wake = resolve
            if (this.#closed || options.signal?.aborted === true || subscriber.pending.size > 0) resolve()
          })
          subscriber.wake = null
        }
      }
    } finally {
      options.signal?.removeEventListener('abort', abort)
      this.#subscriptions.delete(subscriber)
    }
  }

  close(): void {
    this.#closed = true
    for (const subscriber of this.#subscriptions) subscriber.wake?.()
    this.#sessions.clear()
  }

  #now(): number {
    const now = this.#options.now?.() ?? Date.now()
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('SIGNAL_CLOCK_INVALID')
    return now
  }
}

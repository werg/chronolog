import { WEBRTC_LIMITS } from './channel.js'
import type { DataChannelConnection } from './channel.js'
import { openWebRtcConnection } from './negotiation.js'
import type { PeerDescription, PeerSignaling, RtcPeerConnection } from './types.js'

export const WEBRTC_HTTP_PROTOCOL = 'chronolog.webrtc.v1'
export const WEBRTC_HTTP_LIMITS = Object.freeze({ messageBytes: 128 * 1024, pending: 8, connections: 32, timeoutMs: 30_000 })

export interface HttpWebRtcSignaling extends PeerSignaling {
  readonly stats: { readonly requests: number; readonly requestBytes: number; readonly responseBytes: number; readonly closed: boolean }
  close(): void
}

/** One direct offer/answer request to a reachable resident; no polling or live host subscription. */
export function createHttpWebRtcSignaling(options: {
  readonly url: string
  readonly headers?: HeadersInit
  readonly fetch?: typeof globalThis.fetch
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
}): HttpWebRtcSignaling {
  const url = endpointUrl(options.url), timeoutMs = deadline(options.timeoutMs)
  options.signal?.throwIfAborted()
  const controller = new AbortController(), answer = deferred<PeerDescription>()
  let sent = false, reading = false, closed = false, requests = 0, requestBytes = 0, responseBytes = 0
  const close = (reason: unknown = new Error('WEBRTC_HTTP_SIGNALING_CLOSED')): void => {
    if (closed) return
    closed = true; clearTimeout(timer); options.signal?.removeEventListener('abort', abort)
    controller.abort(reason); answer.reject(reason)
  }
  const abort = (): void => close(options.signal?.reason)
  const timer = setTimeout(() => close(new Error('WEBRTC_HTTP_SIGNALING_TIMEOUT')), timeoutMs)
  options.signal?.addEventListener('abort', abort, { once: true })
  return {
    get stats() { return { requests, requestBytes, responseBytes, closed } },
    messages: { async *[Symbol.asyncIterator]() {
      if (reading) throw new Error('WEBRTC_HTTP_SIGNALING_READER_EXISTS')
      reading = true
      yield await answer.promise
    } },
    async send(description) {
      if (sent || closed) throw new Error('WEBRTC_HTTP_OFFER_ALREADY_SENT_OR_CLOSED')
      sent = true
      try {
        const body = envelope(description, 'offer'), headers = new Headers(options.headers)
        headers.set('Content-Type', 'application/json'); headers.set('Accept', 'application/json')
        requests++; requestBytes += new TextEncoder().encode(body).length
        const fetching = (options.fetch ?? globalThis.fetch)(url, { method: 'POST', headers, body, cache: 'no-store',
          credentials: 'omit', redirect: 'error', signal: controller.signal })
        void fetching.then(response => { if (controller.signal.aborted) void response.body?.cancel().catch(() => undefined) }, () => undefined)
        const response = await interruptible(fetching, controller.signal)
        if (!response.ok) { void response.body?.cancel().catch(() => undefined); throw new Error(`WEBRTC_HTTP_INTRODUCTION_REJECTED: ${response.status}`) }
        if (!jsonContentType(response.headers)) throw new Error('WEBRTC_HTTP_CONTENT_TYPE_INVALID')
        const returned = await readJson(response, controller.signal)
        responseBytes += returned.bytes
        answer.resolve(descriptionFromEnvelope(returned.value, 'answer'))
      } catch (error) { close(error); throw error }
    },
    close,
  }
}

export interface AcceptedWebRtcPeer {
  readonly completion: Promise<void>
  close(): Promise<void>
}
export interface WebRtcOfferHandler {
  fetch(request: Request): Promise<Response>
  readonly stats: { readonly requests: number; readonly offers: number; readonly accepted: number; readonly rejected: number;
    readonly failed: number; readonly pending: number; readonly active: number; readonly closed: boolean }
  close(): Promise<void>
}

/**
 * A resident-owned introduction endpoint. The answer is returned before ICE or
 * authentication completes, so the caller can install it and finish connecting.
 * Introduction permission is separate from the accepted peer's read capability.
 */
export function createWebRtcOfferHandler(options: {
  readonly createPeerConnection: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly accept: (connection: DataChannelConnection, signal: AbortSignal) => Promise<AcceptedWebRtcPeer>
  readonly authorize: (request: Request, signal: AbortSignal) => boolean | Promise<boolean>
  readonly allowedOrigins: readonly string[]
  readonly configuration?: RTCConfiguration
  readonly maxPending?: number
  readonly maxConnections?: number
  readonly timeoutMs?: number
  readonly onError?: (error: unknown) => void
}): WebRtcOfferHandler {
  if (typeof options.authorize !== 'function' || typeof options.accept !== 'function' || typeof options.createPeerConnection !== 'function') {
    throw new Error('WEBRTC_HTTP_HANDLER_PORTS_REQUIRED')
  }
  const timeoutMs = deadline(options.timeoutMs), maxPending = options.maxPending ?? WEBRTC_HTTP_LIMITS.pending
  const maxConnections = options.maxConnections ?? WEBRTC_HTTP_LIMITS.connections
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 64 ||
      !Number.isSafeInteger(maxConnections) || maxConnections < 1 || maxConnections > 256) throw new Error('WEBRTC_HTTP_CONNECTION_LIMIT_INVALID')
  if (!Array.isArray(options.allowedOrigins) || options.allowedOrigins.length > 32) throw new Error('WEBRTC_HTTP_ORIGINS_REQUIRED')
  const origins = new Set(options.allowedOrigins.map((value: string) => {
    const url = endpointUrl(value)
    if (url.origin !== value) throw new Error('WEBRTC_HTTP_ORIGIN_INVALID')
    return value
  }))
  type Entry = { active: boolean; close(reason?: unknown): Promise<void> }
  const entries = new Set<Entry>()
  let closed = false, requests = 0, offers = 0, accepted = 0, rejected = 0, failed = 0
  const pending = (): number => [...entries].filter(entry => !entry.active).length
  const observe = (error: unknown): void => { try { options.onError?.(error) } catch { /* Observer failures cannot retain a connection. */ } }
  return {
    get stats() { return { requests, offers, accepted, rejected, failed, pending: pending(), active: entries.size - pending(), closed } },
    async fetch(request) {
      requests++
      const origin = request.headers.get('Origin'), headers = new Headers({ 'Cache-Control': 'no-store', 'Vary': 'Origin', 'X-Content-Type-Options': 'nosniff' })
      const respond = (status: number, value: unknown): Response => Response.json(value, { status, headers })
      const reject = (status: number, code: string): Response => { rejected++; return respond(status, { error: code }) }
      if (origin !== null && !origins.has(origin)) return reject(403, 'origin_not_allowed')
      if (origin !== null) headers.set('Access-Control-Allow-Origin', origin)
      if (closed) return reject(503, 'introduction_closed')
      if (request.method === 'OPTIONS') {
        const requestedHeaders = (request.headers.get('Access-Control-Request-Headers') ?? '').toLowerCase().split(',').map(value => value.trim()).filter(Boolean)
        if (origin === null || request.headers.get('Access-Control-Request-Method') !== 'POST' ||
            requestedHeaders.some(value => !['authorization', 'content-type'].includes(value))) return reject(403, 'preflight_not_allowed')
        headers.set('Access-Control-Allow-Methods', 'POST'); headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        return new Response(null, { status: 204, headers })
      }
      if (request.method !== 'POST') { headers.set('Allow', 'POST, OPTIONS'); return reject(405, 'method_not_allowed') }
      if (!jsonContentType(request.headers)) return reject(415, 'json_required')
      if (entries.size >= maxConnections || pending() >= maxPending) return reject(429, 'introduction_capacity')
      const controller = new AbortController(), answer = deferred<PeerDescription>()
      let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined, peer: AcceptedWebRtcPeer | undefined
      let opening: ReturnType<typeof openWebRtcConnection> | undefined
      let closing: Promise<void> | undefined, answered = false
      const entry: Entry = { active: false, close(reason = new HttpIntroductionError(503, 'introduction_closed')) {
        if (closing !== undefined) return closing
        closing = Promise.resolve().then(async () => {
          await Promise.allSettled([peer?.close(), rtc?.close(), opening?.then(value => value.close())])
          entries.delete(entry)
        })
        clearTimeout(timer); controller.abort(reason); answer.reject(reason)
        return closing
      } }
      entries.add(entry)
      const timer = setTimeout(() => {
        const error = new HttpIntroductionError(408, 'introduction_timeout')
        if (answered) { failed++; observe(error) }
        void entry.close(error)
      }, timeoutMs)
      const abort = (): void => { void entry.close(new HttpIntroductionError(408, 'introduction_cancelled')) }
      request.signal.addEventListener('abort', abort, { once: true })
      const run = async (): Promise<void> => {
        controller.signal.throwIfAborted()
        const permitted = await interruptible(Promise.resolve().then(() => options.authorize(request, controller.signal)), controller.signal)
        if (permitted !== true) {
          throw new HttpIntroductionError(403, 'introduction_unauthorized')
        }
        const body = await readJson(request, controller.signal)
        const offer = descriptionFromEnvelope(body.value, 'offer')
        offers++
        opening = openWebRtcConnection({ role: 'answerer', signaling: {
          messages: { async *[Symbol.asyncIterator]() { yield offer } },
          async send(description) { answer.resolve(description) },
          close() { /* The one HTTP response owns signaling only, never the RTC session. */ },
        }, createPeerConnection: options.createPeerConnection, configuration: options.configuration ?? {}, timeoutMs, signal: controller.signal })
        const opened = await opening
        rtc = opened
        if (closing !== undefined) { await opened.close(); return }
        const accepting = Promise.resolve().then(() => options.accept(opened, controller.signal))
        // An application that finishes accepting after cancellation still owns a
        // resource. Close that late result even if it ignored the deadline.
        void accepting.then(async value => { if (closing !== undefined) await value.close() }, () => undefined).catch(observe)
        peer = await interruptible(accepting, controller.signal)
        if (closing !== undefined) { await peer.close(); return }
        entry.active = true; accepted++; clearTimeout(timer)
        void peer.completion.catch((error: unknown) => { if (closing === undefined) { failed++; observe(error) } }).finally(() => entry.close())
      }
      if (request.signal.aborted) abort()
      void run().catch((error: unknown) => {
        if (closing === undefined) { if (answered) failed++; observe(error) }
        answer.reject(error); void entry.close(error)
      })
      try {
        const description = await answer.promise
        if (closing !== undefined) throw new HttpIntroductionError(408, 'introduction_cancelled')
        answered = true
        return respond(200, JSON.parse(envelope(description, 'answer')) as unknown)
      } catch (error) {
        if (error instanceof HttpIntroductionError) return reject(error.status, error.message)
        return reject(400, 'invalid_introduction')
      } finally {
        // Closing a completed HTTP exchange must never close its RTC peer.
        request.signal.removeEventListener('abort', abort)
      }
    },
    async close() { closed = true; await Promise.all([...entries].map(entry => entry.close())) },
  }
}

class HttpIntroductionError extends Error { constructor(readonly status: number, message: string) { super(message) } }
function deadline(value: number = WEBRTC_HTTP_LIMITS.timeoutMs): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 120_000) throw new Error('WEBRTC_HTTP_TIMEOUT_INVALID')
  return value
}
function endpointUrl(value: string): URL {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('WEBRTC_HTTP_URL_INVALID')
  const url = new URL(value), loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (url.username || url.password || url.hash || url.search || !(url.protocol === 'https:' || url.protocol === 'http:' && loopback)) {
    throw new Error('WEBRTC_HTTP_HTTPS_REQUIRED')
  }
  return url
}
function jsonContentType(headers: Headers): boolean { return headers.get('Content-Type')?.split(';')[0]?.trim().toLowerCase() === 'application/json' }
function descriptionFromEnvelope(value: unknown, type: PeerDescription['type']): PeerDescription {
  if (typeof value !== 'object' || value === null || !('protocol' in value) || value.protocol !== WEBRTC_HTTP_PROTOCOL || !('description' in value) ||
      Object.keys(value).some(key => !['protocol', 'description'].includes(key))) throw new HttpIntroductionError(400, 'introduction_envelope_invalid')
  const description = value.description
  if (typeof description !== 'object' || description === null || !('type' in description) || description.type !== type || !('sdp' in description) ||
      typeof description.sdp !== 'string' || description.sdp.length === 0 || new TextEncoder().encode(description.sdp).length > WEBRTC_LIMITS.sdpBytes ||
      Object.keys(description).some(key => !['type', 'sdp'].includes(key))) throw new HttpIntroductionError(400, 'introduction_description_invalid')
  return { type, sdp: description.sdp }
}
function envelope(description: PeerDescription, type: PeerDescription['type']): string {
  const value = { protocol: WEBRTC_HTTP_PROTOCOL, description }
  descriptionFromEnvelope(value, type)
  const encoded = JSON.stringify(value)
  if (new TextEncoder().encode(encoded).length > WEBRTC_HTTP_LIMITS.messageBytes) throw new HttpIntroductionError(413, 'introduction_message_too_large')
  return encoded
}
async function readJson(message: Request | Response, signal: AbortSignal): Promise<{ value: unknown; bytes: number }> {
  const declared = message.headers.get('Content-Length')
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > WEBRTC_HTTP_LIMITS.messageBytes)) throw new HttpIntroductionError(413, 'introduction_message_too_large')
  if (message.body === null) throw new HttpIntroductionError(400, 'introduction_body_required')
  const reader = message.body.getReader(), combined = new Uint8Array(WEBRTC_HTTP_LIMITS.messageBytes)
  let bytes = 0, chunks = 0
  try {
    for (;;) {
      const item = await interruptible(reader.read(), signal)
      if (item.done) break
      if (++chunks > WEBRTC_HTTP_LIMITS.messageBytes) throw new HttpIntroductionError(413, 'introduction_stream_fragment_limit')
      if (bytes + item.value.length > combined.length) throw new HttpIntroductionError(413, 'introduction_message_too_large')
      combined.set(item.value, bytes); bytes += item.value.length
    }
    return { value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(combined.subarray(0, bytes))) as unknown, bytes }
  } finally { void reader.cancel().catch(() => undefined); reader.releaseLock() }
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  void promise.catch(() => undefined)
  return { promise, resolve, reject }
}
function interruptible<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}

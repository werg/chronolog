import { frameRtcPeerChannels, negotiateWebRtc, type WebRtcOptions, type WebRtcSession } from '@chronolog/transport-webrtc'
import { connectApplicationTransport, type ApplicationPeerConnection } from './network.js'
import type { ApplicationSession } from './session.js'

const CHANNEL_TRANSFER = 'chronolog/peer-session/rtc-channels/v1'
const MAX_CONNECTIONS = 8, MAX_REQUESTS = 16
/** A DedicatedWorker or its owning global scope; application messages use a separate namespace. */
export interface ApplicationWorkerEndpoint {
  postMessage(message: unknown, transfer: Transferable[]): void
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
}

/**
 * Install once beside the Worker-owned application. Each transfer has an isolated
 * control port; authenticated history and live frames stay in the Worker.
 */
export function installApplicationWorkerTransport(session: ApplicationSession, endpoint: ApplicationWorkerEndpoint): { close(): Promise<void> } {
  const active = new Set<() => Promise<void>>()
  let closed = false
  const receive = (event: MessageEvent): void => {
    const data = event.data as Record<string, unknown> | null
    if (data === null || typeof data !== 'object' || data.type !== CHANNEL_TRANSFER) return
    const port = data.port as MessagePort | undefined
    if (port === undefined || typeof port.postMessage !== 'function') return
    if (closed || active.size >= MAX_CONNECTIONS) {
      port.postMessage({ type: 'ended', error: closed ? 'APPLICATION_WORKER_CLOSED' : 'APPLICATION_PEER_LIMIT' }); port.close()
      return
    }
    const lifetime = new AbortController()
    let link: ApplicationPeerConnection | undefined, stopping: Promise<void> | undefined
    let connection: ReturnType<typeof frameRtcPeerChannels> | undefined
    const end = (reason: unknown = new Error('APPLICATION_PEER_DISCONNECTED')): Promise<void> => {
      if (stopping !== undefined) return stopping
      stopping = Promise.resolve().then(async () => {
        await Promise.allSettled([link?.close(), connection?.close()])
        active.delete(end); port.close()
      })
      lifetime.abort(reason)
      port.postMessage({ type: 'ended', error: errorMessage(reason) })
      port.removeEventListener('message', request)
      return stopping
    }
    let pending = 0
    const request = (message: MessageEvent): void => {
      const input = message.data as Record<string, unknown> | null
      if (input === null || typeof input !== 'object') { void end(new Error('APPLICATION_WORKER_MESSAGE_INVALID')); return }
      if (input.type === 'close') { void end(); return }
      if (input.type !== 'synchronize' || !Number.isSafeInteger(input.id) || pending >= MAX_REQUESTS || link === undefined) {
        void end(new Error('APPLICATION_WORKER_REQUEST_INVALID')); return
      }
      pending++
      void link.synchronize().then(() => {
        lifetime.signal.throwIfAborted()
        port.postMessage({ type: 'result', id: input.id, stats: link!.stats })
      }).catch((error: unknown) => {
        if (!lifetime.signal.aborted) port.postMessage({ type: 'result', id: input.id, error: errorMessage(error) })
      }).finally(() => { pending-- })
    }
    active.add(end); port.addEventListener('message', request); port.start()
    void (async () => {
      try {
        if (typeof data.expectedPeerId !== 'string' || !/^[0-9a-f]{64}$/u.test(data.expectedPeerId) ||
            typeof data.timeoutMs !== 'number' || !Number.isSafeInteger(data.timeoutMs) || data.timeoutMs < 100 || data.timeoutMs > 60_000) {
          throw new Error('APPLICATION_WORKER_OPTIONS_INVALID')
        }
        connection = frameRtcPeerChannels({ reliable: data.reliable as RTCDataChannel, live: data.live as RTCDataChannel })
        const timer = setTimeout(() => { void end(new Error('APPLICATION_WORKER_CONNECTION_TIMEOUT')) }, data.timeoutMs)
        try {
          const candidate = await connectApplicationTransport(session, { connection, expectedPeerId: data.expectedPeerId,
            signal: lifetime.signal, timeoutMs: data.timeoutMs })
          link = candidate
          if (lifetime.signal.aborted) { await candidate.close(); return }
          candidate.signal.addEventListener('abort', () => { void end(candidate.signal.reason) }, { once: true })
          port.postMessage({ type: 'ready', peerId: candidate.peerId, stats: candidate.stats })
        } finally { clearTimeout(timer) }
      } catch (error) { await end(error) }
    })().catch(() => undefined)
  }
  endpoint.addEventListener('message', receive)
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true; endpoint.removeEventListener('message', receive); session.signal.removeEventListener('abort', abort)
    await Promise.all([...active].map(end => end()))
  }
  const abort = (): void => { void close() }
  session.signal.addEventListener('abort', abort, { once: true })
  if (session.signal.aborted) abort()
  return { close }
}

/**
 * Page-owned negotiation with synchronous two-channel handoff. Readiness includes
 * Worker authentication and initial replay. No application-owned RPC map is needed.
 */
export async function connectWorkerApplicationWebRtc(endpoint: ApplicationWorkerEndpoint, options: WebRtcOptions & {
  readonly expectedPeerId: string
}): Promise<ApplicationPeerConnection & { readonly rtc: WebRtcSession }> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!/^[0-9a-f]{64}$/u.test(options.expectedPeerId) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new Error('APPLICATION_WORKER_OPTIONS_INVALID')
  }
  const channel = new MessageChannel(), port = channel.port1, lifetime = new AbortController()
  let rtc: WebRtcSession | undefined, closing: Promise<void> | undefined, peerId = '', sequence = 0
  let stats: ApplicationPeerConnection['stats'] = { sentBytes: 0, receivedBytes: 0, sentRequests: 0, receivedRequests: 0 }
  const pending = new Map<number, { resolve(): void; reject(reason: unknown): void; timer: ReturnType<typeof setTimeout> }>()
  let resolveReady!: () => void, rejectReady!: (reason: unknown) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  const close = (reason: unknown = new Error('APPLICATION_PEER_DISCONNECTED')): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve().then(async () => { await rtc?.close(); port.close(); channel.port2.close() })
    lifetime.abort(reason); clearTimeout(timer); options.signal?.removeEventListener('abort', abort)
    port.postMessage({ type: 'close' }); port.removeEventListener('message', receive)
    rejectReady(reason)
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(reason) }
    pending.clear()
    void closing.catch(() => undefined)
    return closing
  }
  const abort = (): void => { void close(options.signal?.reason) }
  const receive = (event: MessageEvent): void => {
    try {
      const value = event.data as Record<string, unknown> | null
      if (value === null || typeof value !== 'object') throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      if (value.type === 'ended') { void close(new Error(String(value.error))); return }
      if (value.type === 'ready') {
        if (peerId || value.peerId !== options.expectedPeerId) throw new Error('APPLICATION_WORKER_PEER_INVALID')
        const nextStats = checkedStats(value.stats)
        peerId = value.peerId; stats = nextStats; resolveReady(); return
      }
      if (value.type === 'result' && Number.isSafeInteger(value.id)) {
        const request = pending.get(Number(value.id))
        if (request === undefined) throw new Error('APPLICATION_WORKER_RESPONSE_UNKNOWN')
        // Validate before removing the waiter: a malformed reply must retire the
        // connection and reject every pending request, not orphan this promise.
        const nextStats = value.error === undefined ? checkedStats(value.stats) : stats
        pending.delete(Number(value.id)); clearTimeout(request.timer)
        if (value.error !== undefined) request.reject(new Error(typeof value.error === 'string' ? value.error : 'APPLICATION_WORKER_REQUEST_FAILED'))
        else { stats = nextStats; request.resolve() }
      } else throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    } catch (error) { void close(error) }
  }
  const timer = setTimeout(() => { void close(new Error('APPLICATION_WORKER_CONNECTION_TIMEOUT')) }, timeoutMs)
  port.addEventListener('message', receive); port.start()
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  try {
    rtc = await negotiateWebRtc({ ...options, signal: lifetime.signal, onDataChannels(channels) {
      endpoint.postMessage({ type: CHANNEL_TRANSFER, reliable: channels.reliable, live: channels.live, port: channel.port2,
        expectedPeerId: options.expectedPeerId, timeoutMs }, [channels.reliable as RTCDataChannel, channels.live as RTCDataChannel, channel.port2])
    } })
    if (lifetime.signal.aborted) { await rtc.close(); lifetime.signal.throwIfAborted() }
    rtc.signal.addEventListener('abort', () => { void close(rtc!.signal.reason) }, { once: true })
    await ready; lifetime.signal.throwIfAborted(); clearTimeout(timer)
    const result: ApplicationPeerConnection & { readonly rtc: WebRtcSession } = {
      peerId, rtc, signal: lifetime.signal, get stats() { return stats },
      async synchronize() {
        lifetime.signal.throwIfAborted()
        if (pending.size >= MAX_REQUESTS) throw new Error('APPLICATION_PEER_REQUEST_LIMIT')
        const id = ++sequence
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => { void close(new Error('APPLICATION_WORKER_REQUEST_TIMEOUT')) }, timeoutMs)
          pending.set(id, { resolve, reject, timer }); port.postMessage({ type: 'synchronize', id })
        })
      },
      close: () => close(),
    }
    return result
  } catch (error) { await close(error); throw error }
}

function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error) }
function checkedStats(value: unknown): ApplicationPeerConnection['stats'] {
  if (value === null || typeof value !== 'object') throw new Error('APPLICATION_WORKER_STATS_INVALID')
  const candidate = value as ApplicationPeerConnection['stats']
  if (![candidate.sentBytes, candidate.receivedBytes, candidate.sentRequests, candidate.receivedRequests].every(number => Number.isSafeInteger(number) && number >= 0)) {
    throw new Error('APPLICATION_WORKER_STATS_INVALID')
  }
  return { sentBytes: candidate.sentBytes, receivedBytes: candidate.receivedBytes, sentRequests: candidate.sentRequests, receivedRequests: candidate.receivedRequests }
}

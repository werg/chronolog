import {
  frameRtcPeerChannels, negotiateWebRtc, WEBRTC_LIMITS,
  type PeerDescription, type RtcPeerConnection, type WebRtcOptions, type WebRtcSession, type WebRtcRoute,
} from '@chronolog/transport-webrtc'
import type { FramedPeerConnection } from '@chronolog/records'
import { awaitOwnedTask } from './lifetime.js'

const NEGOTIATE = 'chronolog/peer-session/rtc-negotiation/v1'
const MAX_CONNECTIONS = 8
/** A DedicatedWorker or its owning global scope; application RPC has its own namespace. */
export interface ApplicationWorkerEndpoint {
  postMessage(message: unknown, transfer: Transferable[]): void
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
}
export interface WorkerWebRtcConnection extends FramedPeerConnection {
  /** Selected ICE pair without exposing addresses to the application. */
  getRoute(): Promise<WebRtcRoute>
}

/**
 * Page-side RTC mechanics. The Worker chooses peers, owns signaling and policy,
 * and receives both channels before they cease to be transferable. The page
 * never attaches an application peer, authenticates history or chooses recovery.
 */
export function serveWorkerWebRtcConnections(endpoint: ApplicationWorkerEndpoint, options: {
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
} = {}): { close(): Promise<void> } {
  const active = new Set<(reason?: unknown) => Promise<void>>()
  let closing: Promise<void> | undefined, closed = false
  const receive = (event: MessageEvent): void => {
    const data = message(event.data)
    if (data?.type !== NEGOTIATE) return
    const port = data.port as MessagePort | undefined
    if (port === undefined || typeof port.postMessage !== 'function') return
    const reject = (error: string): void => {
      try { port.postMessage({ type: 'ended', error }) } finally { port.close() }
    }
    if (closed || active.size >= MAX_CONNECTIONS) {
      reject(closed ? 'APPLICATION_WORKER_CLOSED' : 'APPLICATION_PEER_LIMIT'); return
    }
    if (!['offerer', 'answerer'].includes(String(data.role)) || !validTimeout(data.timeoutMs) || !validConfiguration(data.configuration)) {
      reject('APPLICATION_WORKER_OPTIONS_INVALID'); return
    }
    const lifetime = new AbortController(), received = deferred<PeerDescription>(), sent = deferred<void>(), signalingClosed = deferred<void>()
    let rtc: WebRtcSession | undefined, stopping: Promise<void> | undefined
    let remoteSeen = false, sendRequested = false, sendAcknowledged = false, closeRequested = false, closeAcknowledged = false
    let lastRoute = 0, routePending = false
    const end = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
      if (stopping !== undefined) return stopping
      stopping = Promise.resolve().then(async () => { try { await rtc?.close() } finally { port.close() } })
      void stopping.catch(() => undefined)
      lifetime.abort(reason)
      received.reject(reason); sent.reject(reason); signalingClosed.reject(reason)
      active.delete(end); port.removeEventListener('message', request)
      try { port.postMessage({ type: 'ended', error: errorMessage(reason) }) } catch { /* The Worker may have stopped. */ }
      return stopping
    }
    const request = (event: MessageEvent): void => {
      try {
        const input = message(event.data)
        if (input?.type === 'close') { void end(); return }
        if (input?.type === 'description' && !remoteSeen) {
          remoteSeen = true
          received.resolve(description(input.description, data.role === 'offerer' ? 'answer' : 'offer')); return
        }
        if (input?.type === 'sent' && sendRequested && !sendAcknowledged) { sendAcknowledged = true; sent.resolve(); return }
        if (input?.type === 'signaling-closed' && closeRequested && !closeAcknowledged) {
          closeAcknowledged = true; signalingClosed.resolve(); return
        }
        if (input?.type === 'route' && rtc !== undefined && !routePending && Number.isSafeInteger(input.id) && Number(input.id) > lastRoute) {
          lastRoute = Number(input.id); routePending = true
          void awaitOwnedTask(lifetime.signal, () => rtc!.getRoute()).then(value => {
            lifetime.signal.throwIfAborted(); port.postMessage({ type: 'route', id: input.id, value })
          }, error => {
            if (!lifetime.signal.aborted) port.postMessage({ type: 'route', id: input.id, error: errorMessage(error) })
          }).catch(error => { void end(error) }).finally(() => { routePending = false })
          return
        }
        throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      } catch (error) { void end(error) }
    }
    active.add(end); port.addEventListener('message', request); port.start()
    void (async () => {
      try {
        const candidate = await negotiateWebRtc({
          role: data.role as WebRtcOptions['role'],
          ...(data.configuration === undefined ? {} : { configuration: data.configuration as RTCConfiguration }),
          ...(options.createPeerConnection === undefined ? {} : { createPeerConnection: options.createPeerConnection }),
          timeoutMs: data.timeoutMs as number, signal: lifetime.signal,
          signaling: {
            messages: { async *[Symbol.asyncIterator]() { yield await awaitOwnedTask(lifetime.signal, () => received.promise) } },
            async send(value) {
              lifetime.signal.throwIfAborted()
              if (sendRequested) throw new Error('APPLICATION_WORKER_DESCRIPTION_REPEATED')
              sendRequested = true; port.postMessage({ type: 'send', description: value })
              await awaitOwnedTask(lifetime.signal, () => sent.promise)
            },
            async close() {
              lifetime.signal.throwIfAborted()
              if (!closeRequested) { closeRequested = true; port.postMessage({ type: 'close-signaling' }) }
              await awaitOwnedTask(lifetime.signal, () => signalingClosed.promise)
            },
          },
          onDataChannels(channels) {
            lifetime.signal.throwIfAborted()
            port.postMessage({ type: 'channels', reliable: channels.reliable, live: channels.live },
              [channels.reliable as RTCDataChannel, channels.live as RTCDataChannel])
          },
        })
        rtc = candidate
        if (lifetime.signal.aborted) { await candidate.close(); return }
        candidate.signal.addEventListener('abort', () => { void end(candidate.signal.reason) }, { once: true })
        if (candidate.signal.aborted) { await end(candidate.signal.reason); return }
        port.postMessage({ type: 'ready' })
      } catch (error) { await end(error) }
    })().catch(() => undefined)
  }
  const abort = (): void => { void close() }
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    closed = true; endpoint.removeEventListener('message', receive)
    options.signal?.removeEventListener('abort', abort)
    closing = Promise.allSettled([...active].map(end => end(new Error('APPLICATION_WORKER_CLOSED')))).then(() => undefined)
    return closing
  }
  endpoint.addEventListener('message', receive)
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  return { close }
}

/**
 * Worker-side raw transport for session.participate(). Only bounded SDP crosses
 * the control port. Framing, peer authentication, history and live data all stay
 * beside the owned session and use its ordinary connectPeer path.
 */
export async function openWorkerWebRtcConnection(endpoint: ApplicationWorkerEndpoint,
  options: Omit<WebRtcOptions, 'createPeerConnection'>): Promise<WorkerWebRtcConnection> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!validTimeout(timeoutMs) || !['offerer', 'answerer'].includes(options.role)) throw new Error('APPLICATION_WORKER_OPTIONS_INVALID')
  options.signal?.throwIfAborted()
  const channel = new MessageChannel(), port = channel.port1, lifetime = new AbortController()
  const negotiated = deferred<void>()
  let framed: ReturnType<typeof frameRtcPeerChannels> | undefined, closing: Promise<void> | undefined
  let signalingClose: Promise<void> | undefined, sendSeen = false, readySeen = false, closeSeen = false
  let routeId = 0, routePending: { id: number; result: ReturnType<typeof deferred<WebRtcRoute>>; timer: ReturnType<typeof setTimeout> } | undefined
  const stopSignaling = (): Promise<void> => {
    signalingClose ??= Promise.resolve().then(() => options.signaling.close())
    void signalingClose.catch(() => undefined)
    return signalingClose
  }
  const close = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve().then(async () => { try { await framed?.close() } finally { port.close(); channel.port2.close() } })
    void closing.catch(() => undefined)
    lifetime.abort(reason); clearTimeout(timer); options.signal?.removeEventListener('abort', abort)
    negotiated.reject(reason)
    if (routePending !== undefined) { clearTimeout(routePending.timer); routePending.result.reject(reason); routePending = undefined }
    try { port.postMessage({ type: 'close' }) } catch { /* The page may have stopped. */ }
    port.removeEventListener('message', receive)
    // A misbehaving signaling cleanup cannot hold the owning session open.
    void stopSignaling()
    return closing
  }
  const fail = (error: unknown): void => { void close(error) }
  const abort = (): void => { fail(options.signal?.reason) }
  const receive = (event: MessageEvent): void => {
    const value = message(event.data)
    try {
      if (value?.type === 'ended') throw new Error(typeof value.error === 'string' ? value.error : 'APPLICATION_RTC_CLOSED')
      if (value?.type === 'channels') {
        if (framed !== undefined || lifetime.signal.aborted) { retireTransferred(value); throw new Error('APPLICATION_WORKER_CHANNELS_REPEATED') }
        try { framed = frameRtcPeerChannels({ reliable: value.reliable as RTCDataChannel, live: value.live as RTCDataChannel }) }
        catch (error) { retireTransferred(value); throw error }
        framed.signal.addEventListener('abort', () => fail(framed!.signal.reason), { once: true })
        if (framed.signal.aborted) fail(framed.signal.reason)
        return
      }
      if (value?.type === 'send' && !sendSeen) {
        sendSeen = true
        const outgoing = description(value.description, options.role === 'offerer' ? 'offer' : 'answer')
        void awaitOwnedTask(lifetime.signal, () => options.signaling.send(outgoing)).then(() => {
          lifetime.signal.throwIfAborted(); port.postMessage({ type: 'sent' })
        }).catch(fail)
        return
      }
      if (value?.type === 'close-signaling' && !closeSeen && sendSeen) {
        closeSeen = true
        void awaitOwnedTask(lifetime.signal, stopSignaling).then(() => {
          lifetime.signal.throwIfAborted(); port.postMessage({ type: 'signaling-closed' })
        }).catch(fail)
        return
      }
      if (value?.type === 'ready' && !readySeen && framed !== undefined && closeSeen) {
        readySeen = true; negotiated.resolve(); return
      }
      if (value?.type === 'route' && routePending !== undefined && value.id === routePending.id) {
        const pending = routePending
        const selected = value.error === undefined ? route(value.value) : undefined
        routePending = undefined; clearTimeout(pending.timer)
        if (selected !== undefined) pending.result.resolve(selected)
        else pending.result.reject(new Error(typeof value.error === 'string' ? value.error : 'APPLICATION_WORKER_ROUTE_INVALID'))
        return
      }
      throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    } catch (error) { fail(error) }
  }
  const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_CONNECTION_TIMEOUT')), timeoutMs)
  port.addEventListener('message', receive); port.start()
  options.signal?.addEventListener('abort', abort, { once: true })
  let descriptions: AsyncIterator<PeerDescription> | undefined
  try {
    descriptions = options.signaling.messages[Symbol.asyncIterator]()
    lifetime.signal.throwIfAborted()
    endpoint.postMessage({ type: NEGOTIATE, role: options.role, timeoutMs, configuration: options.configuration, port: channel.port2 }, [channel.port2])
    void awaitOwnedTask(lifetime.signal, () => descriptions!.next()).then(item => {
      lifetime.signal.throwIfAborted()
      if (item.done) throw new Error('APPLICATION_WORKER_SIGNALING_ENDED')
      port.postMessage({ type: 'description', description: description(item.value, options.role === 'offerer' ? 'answer' : 'offer') })
    }).catch(fail)
    await awaitOwnedTask(lifetime.signal, () => negotiated.promise)
    const connection = framed!
    await awaitOwnedTask(lifetime.signal, () => connection.ready)
    lifetime.signal.throwIfAborted(); clearTimeout(timer)
    return { signal: lifetime.signal, live: connection.live,
      send: (bytes, sendOptions) => connection.send(bytes, sendOptions), frames: signal => connection.frames(signal), close: () => close(),
      getRoute() {
        lifetime.signal.throwIfAborted()
        if (routePending !== undefined) return routePending.result.promise
        const id = ++routeId
        if (!Number.isSafeInteger(id)) throw new Error('APPLICATION_WORKER_REQUEST_ID_EXHAUSTED')
        const result = deferred<WebRtcRoute>()
        const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_ROUTE_TIMEOUT')), timeoutMs)
        routePending = { id, result, timer }
        port.postMessage({ type: 'route', id })
        return result.promise
      } }
  } catch (error) { await close(error); throw error }
  finally { void Promise.resolve().then(() => descriptions?.return?.()).catch(() => undefined) }
}

function validTimeout(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= 120_000
}
function validConfiguration(value: unknown): boolean {
  if (value === undefined) return true
  try { return value !== null && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(value).length <= 16_384 }
  catch { return false }
}
function message(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
}
function description(value: unknown, expected: PeerDescription['type']): PeerDescription {
  const input = message(value)
  if (input?.type !== expected || typeof input.sdp !== 'string' || input.sdp.length < 1 ||
      new TextEncoder().encode(input.sdp).length > WEBRTC_LIMITS.sdpBytes) throw new Error('APPLICATION_WORKER_DESCRIPTION_INVALID')
  return { type: expected, sdp: input.sdp }
}
function route(value: unknown): WebRtcRoute {
  const input = message(value), candidates = [null, 'host', 'srflx', 'prflx', 'relay']
  if (input === null || !['direct', 'relay', 'unknown'].includes(String(input.route)) ||
      !candidates.includes(input.localCandidateType as string | null) || !candidates.includes(input.remoteCandidateType as string | null)) {
    throw new Error('APPLICATION_WORKER_ROUTE_INVALID')
  }
  return { route: input.route as WebRtcRoute['route'], localCandidateType: input.localCandidateType as WebRtcRoute['localCandidateType'],
    remoteCandidateType: input.remoteCandidateType as WebRtcRoute['remoteCandidateType'] }
}
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  void promise.catch(() => undefined)
  return { promise, resolve, reject }
}
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error) }
function retireTransferred(value: Record<string, unknown>): void {
  for (const key of ['reliable', 'live']) {
    const channel = value[key] as { close?: () => void } | undefined
    try { channel?.close?.() } catch { /* Closing an already retired channel is harmless. */ }
  }
}

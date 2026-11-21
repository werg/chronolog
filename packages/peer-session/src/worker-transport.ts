import {
  openWebRtcConnection, WEBRTC_LIMITS,
  type PeerDescription, type RtcPeerConnection, type WebRtcOptions, type WebRtcRoute,
} from '@chronolog/transport-webrtc'
import type { FramedPeerConnection } from '@chronolog/records'
import { awaitOwnedTask } from './lifetime.js'
import { workerRtcLanes, type Lane } from './worker-transport-lanes.js'

const PROTOCOL = 'chronolog/peer-session/rtc-endpoint/v1'
const MAX_CONNECTIONS = 8
/** Ordered, authenticated endpoint: Worker, started SharedWorker port, or a virtual endpoint.
 * The RTC bridge calls postMessage with one argument only; it transfers no resources.
 * Optional transfer is used by the separate application-RPC API, not this protocol. */
export interface ApplicationWorkerEndpoint {
  postMessage(message: unknown, transfer?: Transferable[]): void
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
}
export interface WorkerWebRtcConnection extends FramedPeerConnection { getRoute(): Promise<WebRtcRoute> }
type Wire = Record<string, unknown>
const clients = new WeakMap<ApplicationWorkerEndpoint, Set<string>>()
const validId = (id: unknown): id is string => typeof id === 'string' && /^[0-9a-f-]{36}$/u.test(id)
const payload = ({ type: _type, id: _id, from: _from, ...value }: Wire): Wire => value
const envelope = (data: unknown, from: string): Wire | null => {
  const value = message(data)
  return value?.type === PROTOCOL && value.from === from && validId(value.id) ? value : null
}

/** Page-side RTC and raw framing only. Peer crypto, keys and state stay in the owner.
 * Opaque frames use bounded multiplexed messages; no RTCDataChannel/MessagePort transfer. */
export function serveWorkerWebRtcConnections(endpoint: ApplicationWorkerEndpoint, options: {
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
} = {}): { close(): Promise<void> } {
  const active = new Map<string, { receive(value: Wire): void; close(reason?: unknown): Promise<void> }>()
  let closing: Promise<void> | undefined, closed = false
  const post = (id: string, value: Wire) => endpoint.postMessage({ ...value, type: PROTOCOL, id, from: 'page' })
  const receive = (event: MessageEvent) => {
    const data = envelope(event.data, 'worker')
    if (data === null || closed) return
    const id = data.id as string, existing = active.get(id)
    if (existing !== undefined) { existing.receive(payload(data)); return }
    if (data.action !== 'open') return // Late callbacks from retired connection IDs.
    if (active.size >= MAX_CONNECTIONS) { post(id, { action: 'ended', error: 'APPLICATION_PEER_LIMIT' }); return }
    if (!['offerer', 'answerer'].includes(String(data.role)) || !validTimeout(data.timeoutMs) || !validConfiguration(data.configuration)) {
      post(id, { action: 'ended', error: 'APPLICATION_WORKER_OPTIONS_INVALID' }); return
    }
    const lifetime = new AbortController(), received = deferred<PeerDescription>(), sent = deferred<void>(), signalingClosed = deferred<void>()
    let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined, stopping: Promise<void> | undefined
    let remoteSeen = false, sendRequested = false, sendAcknowledged = false, closeRequested = false, closeAcknowledged = false
    let lastRoute = 0, routePending = false
    const end = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
      if (stopping !== undefined) return stopping
      stopping = Promise.resolve().then(async () => { await rtc?.close() })
      void stopping.catch(() => undefined)
      lifetime.abort(reason); received.reject(reason); sent.reject(reason); signalingClosed.reject(reason)
      active.delete(id)
      try { post(id, { action: 'ended', error: errorMessage(reason) }) } catch { /* Endpoint retired. */ }
      return stopping
    }
    const lanes = workerRtcLanes(value => post(id, value), lifetime.signal, error => { void end(error) }, data.timeoutMs,
      async (lane, bytes) => {
        if (rtc === undefined) throw new Error('APPLICATION_WORKER_NOT_READY')
        if (lane === 'live') return rtc.live.trySend(bytes, { signal: lifetime.signal })
        await rtc.send(bytes, { signal: lifetime.signal }); return true
      })
    const request = (input: Wire) => {
      try {
        if (input.action === 'close') { void end(); return }
        if (input.action === 'frame' || input.action === 'ack') { lanes.receive(input); return }
        if (input.action === 'description' && !remoteSeen) {
          remoteSeen = true; received.resolve(description(input.description, data.role === 'offerer' ? 'answer' : 'offer')); return
        }
        if (input.action === 'sent' && sendRequested && !sendAcknowledged) { sendAcknowledged = true; sent.resolve(); return }
        if (input.action === 'signaling-closed' && closeRequested && !closeAcknowledged) { closeAcknowledged = true; signalingClosed.resolve(); return }
        if (input.action === 'route' && rtc !== undefined && !routePending && Number.isSafeInteger(input.request) && Number(input.request) > lastRoute) {
          lastRoute = Number(input.request); routePending = true
          void awaitOwnedTask(lifetime.signal, () => rtc!.session.getRoute()).then(value => {
            lifetime.signal.throwIfAborted(); post(id, { action: 'route', request: input.request, value: route(value) })
          }, error => {
            if (!lifetime.signal.aborted) post(id, { action: 'route', request: input.request, error: errorMessage(error) })
          }).catch(error => { void end(error) }).finally(() => { routePending = false }); return
        }
        throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      } catch (error) { void end(error) }
    }
    active.set(id, { receive: request, close: end })
    void (async () => {
      try {
        const candidate = await openWebRtcConnection({ role: data.role as WebRtcOptions['role'],
          ...(data.configuration === undefined ? {} : { configuration: data.configuration as RTCConfiguration }),
          ...(options.createPeerConnection === undefined ? {} : { createPeerConnection: options.createPeerConnection }),
          timeoutMs: data.timeoutMs as number, signal: lifetime.signal,
          signaling: {
            messages: { async *[Symbol.asyncIterator]() { yield await awaitOwnedTask(lifetime.signal, () => received.promise) } },
            async send(value) {
              lifetime.signal.throwIfAborted()
              if (sendRequested) throw new Error('APPLICATION_WORKER_DESCRIPTION_REPEATED')
              sendRequested = true; post(id, { action: 'send', description: value }); await awaitOwnedTask(lifetime.signal, () => sent.promise)
            },
            async close() {
              lifetime.signal.throwIfAborted()
              if (!closeRequested) { closeRequested = true; post(id, { action: 'close-signaling' }) }
              await awaitOwnedTask(lifetime.signal, () => signalingClosed.promise)
            },
          },
        })
        rtc = candidate
        if (lifetime.signal.aborted) { await candidate.close(); return }
        candidate.signal.addEventListener('abort', () => { void end(candidate.signal.reason) }, { once: true })
        candidate.session.signal.addEventListener('abort', () => { void end(candidate.session.signal.reason) }, { once: true })
        if (candidate.signal.aborted || candidate.session.signal.aborted) { await end(candidate.signal.reason ?? candidate.session.signal.reason); return }
        post(id, { action: 'ready' })
        const forward = async (lane: Lane) => {
          const source = lane === 'reliable' ? candidate : candidate.live
          for await (const bytes of source.frames(lifetime.signal)) {
            lifetime.signal.throwIfAborted()
            await lanes[lane].send(bytes, lifetime.signal)
          }
          if (!lifetime.signal.aborted) await end(new Error('APPLICATION_RTC_ENDED'))
        }
        void forward('reliable').catch(error => { void end(error) })
        void forward('live').catch(error => { void end(error) })
      } catch (error) { await end(error) }
    })().catch(() => undefined)
  }
  const abort = () => { void close() }
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    closed = true; endpoint.removeEventListener('message', receive); options.signal?.removeEventListener('abort', abort)
    closing = Promise.allSettled([...active.values()].map(value => value.close(new Error('APPLICATION_WORKER_CLOSED')))).then(() => undefined)
    return closing
  }
  endpoint.addEventListener('message', receive); options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  return { close }
}

/** Owner-side framed connection. Only bounded signaling and opaque peer frames cross the endpoint. */
export async function openWorkerWebRtcConnection(endpoint: ApplicationWorkerEndpoint,
  options: Omit<WebRtcOptions, 'createPeerConnection'>): Promise<WorkerWebRtcConnection> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!validTimeout(timeoutMs) || !['offerer', 'answerer'].includes(options.role) || !validConfiguration(options.configuration)) throw new Error('APPLICATION_WORKER_OPTIONS_INVALID')
  options.signal?.throwIfAborted()
  let owned = clients.get(endpoint)
  if (owned === undefined) clients.set(endpoint, owned = new Set())
  if (owned.size >= MAX_CONNECTIONS) throw new Error('APPLICATION_PEER_LIMIT')
  const id = crypto.randomUUID(), lifetime = new AbortController(), negotiated = deferred<void>()
  owned.add(id)
  const post = (value: Wire) => endpoint.postMessage({ ...value, type: PROTOCOL, id, from: 'worker' })
  let closing: Promise<void> | undefined, signalingClose: Promise<void> | undefined, sendSeen = false, closeSeen = false, readySeen = false
  let routeId = 0, routePending: { id: number; result: ReturnType<typeof deferred<WebRtcRoute>>; timer: ReturnType<typeof setTimeout> } | undefined
  const stopSignaling = (): Promise<void> => {
    signalingClose ??= Promise.resolve().then(() => options.signaling.close()); void signalingClose.catch(() => undefined); return signalingClose
  }
  const close = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve()
    lifetime.abort(reason); clearTimeout(timer); options.signal?.removeEventListener('abort', abort); negotiated.reject(reason)
    owned.delete(id); if (!owned.size) clients.delete(endpoint)
    if (routePending !== undefined) { clearTimeout(routePending.timer); routePending.result.reject(reason); routePending = undefined }
    try { post({ action: 'close' }) } catch { /* Endpoint retired. */ }
    endpoint.removeEventListener('message', receive); void stopSignaling(); return closing
  }
  const fail = (error: unknown) => { void close(error) }
  const lanes = workerRtcLanes(post, lifetime.signal, fail, timeoutMs)
  const abort = () => fail(options.signal?.reason)
  const receive = (event: MessageEvent) => {
    const value = envelope(event.data, 'page')
    if (value?.id !== id || lifetime.signal.aborted) return
    try {
      if (value.action === 'ended') throw new Error(errorMessage(value.error ?? 'APPLICATION_RTC_CLOSED'))
      if (value.action === 'frame' || value.action === 'ack') {
        if (!readySeen) throw new Error('APPLICATION_WORKER_NOT_READY')
        lanes.receive(payload(value)); return
      }
      if (value.action === 'send' && !sendSeen) {
        sendSeen = true
        const outgoing = description(value.description, options.role === 'offerer' ? 'offer' : 'answer')
        void awaitOwnedTask(lifetime.signal, () => options.signaling.send(outgoing)).then(() => {
          lifetime.signal.throwIfAborted(); post({ action: 'sent' })
        }).catch(fail); return
      }
      if (value.action === 'close-signaling' && !closeSeen && sendSeen) {
        closeSeen = true
        void awaitOwnedTask(lifetime.signal, stopSignaling).then(() => {
          lifetime.signal.throwIfAborted(); post({ action: 'signaling-closed' })
        }).catch(fail); return
      }
      if (value.action === 'ready' && !readySeen && closeSeen && sendSeen) { readySeen = true; negotiated.resolve(); return }
      if (value.action === 'route' && routePending !== undefined && value.request === routePending.id) {
        const pending = routePending, selected = value.error === undefined ? route(value.value) : undefined
        routePending = undefined; clearTimeout(pending.timer)
        if (selected !== undefined) pending.result.resolve(selected)
        else pending.result.reject(new Error(errorMessage(value.error))); return
      }
      throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    } catch (error) { fail(error) }
  }
  const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_CONNECTION_TIMEOUT')), timeoutMs)
  endpoint.addEventListener('message', receive); options.signal?.addEventListener('abort', abort, { once: true })
  let descriptions: AsyncIterator<PeerDescription> | undefined
  try {
    descriptions = options.signaling.messages[Symbol.asyncIterator](); lifetime.signal.throwIfAborted()
    post({ action: 'open', role: options.role, timeoutMs, configuration: options.configuration })
    void awaitOwnedTask(lifetime.signal, () => descriptions!.next()).then(item => {
      lifetime.signal.throwIfAborted()
      if (item.done) throw new Error('APPLICATION_WORKER_SIGNALING_ENDED')
      post({ action: 'description', description: description(item.value, options.role === 'offerer' ? 'answer' : 'offer') })
    }).catch(fail)
    await awaitOwnedTask(lifetime.signal, () => negotiated.promise); lifetime.signal.throwIfAborted(); clearTimeout(timer)
    return { signal: lifetime.signal, send: async (bytes, sendOptions) => { await lanes.reliable.send(bytes, sendOptions?.signal) },
      frames: signal => lanes.reliable.frames(signal), close: () => close(),
      live: { signal: lifetime.signal, trySend: (bytes, sendOptions) => lanes.live.send(bytes, sendOptions?.signal),
        frames: signal => lanes.live.frames(signal), close: () => close() },
      getRoute() {
        lifetime.signal.throwIfAborted()
        if (routePending !== undefined) return routePending.result.promise
        const request = ++routeId
        if (!Number.isSafeInteger(request)) throw new Error('APPLICATION_WORKER_REQUEST_ID_EXHAUSTED')
        const result = deferred<WebRtcRoute>(), timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_ROUTE_TIMEOUT')), timeoutMs)
        routePending = { id: request, result, timer }
        try { post({ action: 'route', request }) } catch (error) { fail(error) }
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
function errorMessage(error: unknown): string { return (error instanceof Error ? error.message : String(error)).slice(0, 256) }

import {
  openWebRtcConnection, validatePeerDescription, validatePeerIceCandidate, validateRtcSignalMessage,
  type InBandSignalingHandle, type InBandSignalingOptions, type PeerDescription, type PeerIceCandidate,
  type PeerMediaController, type PeerSignalingMessage, type PeerStreamsController,
  type RtcPeerConnection, type RtcSignalMessage, type WebRtcOptions, type WebRtcRoute,
} from '@chronolog/transport-webrtc'
import type { FramedPeerConnection } from '@chronolog/records'
import { awaitOwnedTask } from './lifetime.js'
import { workerRtcLanes, type Lane } from './worker-transport-lanes.js'

const PROTOCOL = 'chronolog/peer-session/rtc-endpoint/v1'
const MAX_CONNECTIONS = 16
const MAX_BOOTSTRAP_CANDIDATES = 40

/** Ordered, authenticated endpoint: Worker, dedicated port, or a virtual endpoint. */
export interface ApplicationWorkerEndpoint {
  postMessage(message: unknown, transfer?: Transferable[]): void
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  /** Owned MessagePort endpoints may release their physical handle on detach. */
  close?(): void
}
export interface WorkerWebRtcConnection extends FramedPeerConnection {
  getRoute(): Promise<WebRtcRoute>
  attachInBandSignaling(options: InBandSignalingOptions & { readonly peerId: string }): InBandSignalingHandle
}
export interface PagePeerHandle {
  readonly peerId: string
  readonly connectionId: string
  readonly transportKind: 'direct'
  readonly media: PeerMediaController
  readonly streams: PeerStreamsController
  readonly signal: AbortSignal
}
export interface WorkerWebRtcServer {
  getPeer(peerId: string): PagePeerHandle | undefined
  peers(): readonly PagePeerHandle[]
  onPeer(listener: (event: { readonly type: 'connected' | 'disconnected'; readonly peer: PagePeerHandle }) => void): () => void
  close(): Promise<void>
}

type Wire = Record<string, unknown>
const clients = new WeakMap<ApplicationWorkerEndpoint, Set<string>>()
const validId = (id: unknown): id is string => typeof id === 'string' && /^[0-9a-f-]{36}$/u.test(id)
const validPeerId = (id: unknown): id is string => typeof id === 'string' && /^[0-9a-f]{64}$/u.test(id)
const payload = ({ type: _type, id: _id, from: _from, ...value }: Wire): Wire => value
const envelope = (data: unknown, from: string): Wire | null => {
  const value = message(data)
  return value?.type === PROTOCOL && value.from === from && validId(value.id) ? value : null
}

function signalingQueue(signal: AbortSignal) {
  const items: PeerSignalingMessage[] = []
  let wake: (() => void) | undefined
  let ended = false
  let failure: unknown
  const stop = (error?: unknown) => {
    if (ended) return
    ended = true
    if (error !== undefined) failure = error
    wake?.(); wake = undefined
  }
  signal.addEventListener('abort', () => stop(signal.reason), { once: true })
  return {
    push(value: PeerSignalingMessage) {
      if (ended) return
      items.push(value)
      wake?.(); wake = undefined
    },
    end: stop,
    messages: {
      async *[Symbol.asyncIterator]() {
        while (true) {
          if (items.length > 0) { yield items.shift()!; continue }
          if (ended) { if (failure !== undefined) throw (failure instanceof Error ? failure : new Error(errorMessage(failure))); return }
          await new Promise<void>(resolve => { wake = resolve })
        }
      },
    },
  }
}

/** Page-side RTC and raw framing. Media tracks and `app:*` DataChannels stay directly in the page. */
export function serveWorkerWebRtcConnections(endpoint: ApplicationWorkerEndpoint, options: {
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
} = {}): WorkerWebRtcServer {
  const active = new Map<string, { receive(value: Wire): void; close(reason?: unknown): Promise<void> }>()
  const authenticatedPeers = new Map<string, PagePeerHandle>()
  const peerListeners = new Set<(event: { readonly type: 'connected' | 'disconnected'; readonly peer: PagePeerHandle }) => void>()
  let closing: Promise<void> | undefined, closed = false
  const post = (id: string, value: Wire) => endpoint.postMessage({ ...value, type: PROTOCOL, id, from: 'page' })

  const notifyPeer = (type: 'connected' | 'disconnected', peer: PagePeerHandle) => {
    for (const listener of peerListeners) {
      try { listener({ type, peer }) } catch { /* Isolate page observer errors. */ }
    }
  }

  const receive = (event: MessageEvent) => {
    const data = envelope(event.data, 'worker')
    if (data === null || closed) return
    const id = data.id as string, existing = active.get(id)
    if (existing !== undefined) { existing.receive(payload(data)); return }
    if (data.action !== 'open') return
    if (active.size >= MAX_CONNECTIONS) { post(id, { action: 'ended', error: 'APPLICATION_PEER_LIMIT' }); return }
    if (!['offerer', 'answerer'].includes(String(data.role)) || !validTimeout(data.timeoutMs) || !validGatheringTimeout(data.gatheringTimeoutMs, data.timeoutMs) || !validConfiguration(data.configuration)) {
      post(id, { action: 'ended', error: 'APPLICATION_WORKER_OPTIONS_INVALID' }); return
    }
    const lifetime = new AbortController(), incoming = signalingQueue(lifetime.signal)
    const sent = deferred<void>(), signalingClosed = deferred<void>()
    let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined, stopping: Promise<void> | undefined
    let inBand: InBandSignalingHandle | undefined, peerHandle: PagePeerHandle | undefined
    let remoteDescriptionSeen = false, remoteCandidates = 0, sendRequested = false, sendAcknowledged = false, closeRequested = false, closeAcknowledged = false
    let lastRoute = 0, routePending = false
    const end = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
      if (stopping !== undefined) return stopping
      stopping = Promise.resolve().then(async () => { await rtc?.close() })
      void stopping.catch(() => undefined)
      inBand?.close(); inBand = undefined
      if (peerHandle !== undefined) {
        const retired = peerHandle; peerHandle = undefined
        if (authenticatedPeers.get(retired.peerId)?.connectionId === id) {
          authenticatedPeers.delete(retired.peerId)
        }
        notifyPeer('disconnected', retired)
      }
      lifetime.abort(reason); incoming.end(reason); sent.reject(reason); signalingClosed.reject(reason)
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
        if (input.action === 'description' && !remoteDescriptionSeen) {
          remoteDescriptionSeen = true
          incoming.push(description(input.description, data.role === 'offerer' ? 'answer' : 'offer'))
          return
        }
        if (input.action === 'candidate' && remoteCandidates < MAX_BOOTSTRAP_CANDIDATES) {
          remoteCandidates += 1
          incoming.push({ kind: 'candidate', candidate: validatePeerIceCandidate(input.candidate) })
          return
        }
        if (input.action === 'sent' && sendRequested && !sendAcknowledged) { sendAcknowledged = true; sent.resolve(); return }
        if (input.action === 'signaling-closed' && closeRequested && !closeAcknowledged) { closeAcknowledged = true; signalingClosed.resolve(); return }
        if (input.action === 'authenticated' && rtc !== undefined && inBand === undefined && validPeerId(input.peerId) && typeof input.polite === 'boolean') {
          const peerId = input.peerId
          inBand = rtc.session.attachInBandSignaling({
            polite: input.polite,
            async send(rtcMessage) {
              lifetime.signal.throwIfAborted()
              post(id, { action: 'rtc', message: rtcMessage })
            },
          })
          peerHandle = Object.freeze({
            peerId,
            connectionId: id,
            transportKind: 'direct' as const,
            media: rtc.session.media,
            streams: rtc.session.streams,
            signal: lifetime.signal,
          })
          authenticatedPeers.set(peerId, peerHandle)
          notifyPeer('connected', peerHandle)
          return
        }
        if (input.action === 'rtc' && inBand !== undefined) {
          void inBand.receive(validateRtcSignalMessage(input.message)).catch(() => undefined)
          return
        }
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
        const candidate = await openWebRtcConnection({
          role: data.role as WebRtcOptions['role'],
          ...(data.configuration === undefined ? {} : { configuration: data.configuration as RTCConfiguration }),
          ...(options.createPeerConnection === undefined ? {} : { createPeerConnection: options.createPeerConnection }),
          timeoutMs: data.timeoutMs as number,
          signal: lifetime.signal,
          ...(data.gatheringTimeoutMs === undefined ? {} : { gatheringTimeoutMs: data.gatheringTimeoutMs as number }),
          ...(typeof data.trickle === 'boolean' ? { trickle: data.trickle } : {}),
          signaling: {
            messages: incoming.messages,
            async send(value) {
              lifetime.signal.throwIfAborted()
              if ('type' in value) {
                if (sendRequested) throw new Error('APPLICATION_WORKER_DESCRIPTION_REPEATED')
                sendRequested = true; post(id, { action: 'send', description: value }); await awaitOwnedTask(lifetime.signal, () => sent.promise)
              } else if (value.kind === 'candidate') {
                post(id, { action: 'candidate', candidate: value.candidate })
              } else if (value.kind === 'connected') {
                post(id, { action: 'connected' })
              }
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
    closing = Promise.allSettled([...active.values()].map(value => value.close(new Error('APPLICATION_WORKER_CLOSED')))).then(() => {
      authenticatedPeers.clear()
      peerListeners.clear()
    })
    return closing
  }
  endpoint.addEventListener('message', receive); options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  return {
    getPeer: peerId => authenticatedPeers.get(peerId),
    peers: () => [...authenticatedPeers.values()],
    onPeer(listener) {
      peerListeners.add(listener)
      for (const peer of authenticatedPeers.values()) {
        try { listener({ type: 'connected', peer }) } catch { /* Isolate observer errors. */ }
      }
      return () => { peerListeners.delete(listener) }
    },
    close,
  }
}

/** Owner-side framed connection. Only bounded signaling and opaque peer frames cross the endpoint. */
export async function openWorkerWebRtcConnection(endpoint: ApplicationWorkerEndpoint,
  options: Omit<WebRtcOptions, 'createPeerConnection'>): Promise<WorkerWebRtcConnection> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!validTimeout(timeoutMs) || !validGatheringTimeout(options.gatheringTimeoutMs, timeoutMs) || !['offerer', 'answerer'].includes(options.role) || !validConfiguration(options.configuration)) throw new Error('APPLICATION_WORKER_OPTIONS_INVALID')
  options.signal?.throwIfAborted()
  let owned = clients.get(endpoint)
  if (owned === undefined) clients.set(endpoint, owned = new Set())
  if (owned.size >= MAX_CONNECTIONS) throw new Error('APPLICATION_PEER_LIMIT')
  const id = crypto.randomUUID(), lifetime = new AbortController(), negotiated = deferred<void>()
  owned.add(id)
  const post = (value: Wire) => endpoint.postMessage({ ...value, type: PROTOCOL, id, from: 'worker' })
  let closing: Promise<void> | undefined, signalingClose: Promise<void> | undefined
  let sendSeen = false, closeSeen = false, readySeen = false, outgoingCandidates = 0
  let inBandSend: ((message: RtcSignalMessage) => Promise<void>) | undefined
  let routeId = 0, routePending: { id: number; result: ReturnType<typeof deferred<WebRtcRoute>>; timer: ReturnType<typeof setTimeout> } | undefined
  const stopSignaling = (): Promise<void> => {
    signalingClose ??= Promise.resolve().then(() => options.signaling.close()); void signalingClose.catch(() => undefined); return signalingClose
  }
  const close = (reason: unknown = new Error('APPLICATION_RTC_CLOSED')): Promise<void> => {
    if (closing !== undefined) return closing
    closing = Promise.resolve()
    inBandSend = undefined
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
      if (value.action === 'candidate' && !closeSeen && outgoingCandidates < MAX_BOOTSTRAP_CANDIDATES) {
        outgoingCandidates += 1
        const candidate: PeerIceCandidate | null = validatePeerIceCandidate(value.candidate)
        void Promise.resolve(options.signaling.send({ kind: 'candidate', candidate })).catch(() => undefined)
        return
      }
      if (value.action === 'connected' && !closeSeen) {
        void Promise.resolve(options.signaling.send({ kind: 'connected' })).catch(() => undefined)
        return
      }
      if (value.action === 'close-signaling' && !closeSeen && sendSeen) {
        closeSeen = true
        void awaitOwnedTask(lifetime.signal, stopSignaling).then(() => {
          lifetime.signal.throwIfAborted(); post({ action: 'signaling-closed' })
        }).catch(fail); return
      }
      if (value.action === 'ready' && !readySeen && closeSeen && sendSeen) { readySeen = true; negotiated.resolve(); return }
      if (value.action === 'rtc' && readySeen && inBandSend !== undefined) {
        const rtcMessage = validateRtcSignalMessage(value.message)
        void inBandSend(rtcMessage).catch(() => undefined)
        return
      }
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
  let remoteMessages: AsyncIterator<PeerSignalingMessage> | undefined
  try {
    remoteMessages = options.signaling.messages[Symbol.asyncIterator](); lifetime.signal.throwIfAborted()
    post({
      action: 'open',
      role: options.role,
      timeoutMs,
      configuration: options.configuration,
      gatheringTimeoutMs: options.gatheringTimeoutMs,
      ...(options.trickle === undefined ? {} : { trickle: options.trickle }),
    })
    void (async () => {
      let seenDescription = false, seenCandidates = 0
      while (!lifetime.signal.aborted && !closeSeen) {
        const item = await awaitOwnedTask(lifetime.signal, () => remoteMessages!.next())
        if (item.done) {
          if (!seenDescription) throw new Error('APPLICATION_WORKER_SIGNALING_ENDED')
          return
        }
        const incoming = item.value
        if (typeof incoming === 'object' && incoming !== null && 'type' in incoming && 'sdp' in incoming) {
          if (seenDescription) throw new Error('APPLICATION_WORKER_DESCRIPTION_INVALID')
          seenDescription = true
          post({ action: 'description', description: description(incoming, options.role === 'offerer' ? 'answer' : 'offer') })
        } else if (typeof incoming === 'object' && incoming !== null && 'kind' in incoming && incoming.kind === 'candidate') {
          if (seenCandidates < MAX_BOOTSTRAP_CANDIDATES) {
            seenCandidates += 1
            post({ action: 'candidate', candidate: validatePeerIceCandidate(incoming.candidate) })
          }
        }
      }
    })().catch(fail)
    await awaitOwnedTask(lifetime.signal, () => negotiated.promise); lifetime.signal.throwIfAborted(); clearTimeout(timer)
    return {
      signal: lifetime.signal,
      send: async (bytes, sendOptions) => { await lanes.reliable.send(bytes, sendOptions?.signal) },
      frames: signal => lanes.reliable.frames(signal),
      close: () => close(),
      live: {
        signal: lifetime.signal,
        trySend: (bytes, sendOptions) => lanes.live.send(bytes, sendOptions?.signal),
        frames: signal => lanes.live.frames(signal),
        close: () => close(),
      },
      attachInBandSignaling(binding) {
        if (lifetime.signal.aborted) throw new Error('APPLICATION_RTC_CLOSED')
        if (!validPeerId(binding.peerId)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
        inBandSend = binding.send
        post({ action: 'authenticated', peerId: binding.peerId, polite: binding.polite })
        return {
          async receive(rtcMessage) {
            if (lifetime.signal.aborted) return
            post({ action: 'rtc', message: validateRtcSignalMessage(rtcMessage) })
          },
          close() { inBandSend = undefined },
        }
      },
      getRoute() {
        lifetime.signal.throwIfAborted()
        if (routePending !== undefined) return routePending.result.promise
        const request = ++routeId
        if (!Number.isSafeInteger(request)) throw new Error('APPLICATION_WORKER_REQUEST_ID_EXHAUSTED')
        const result = deferred<WebRtcRoute>(), routeTimer = setTimeout(() => fail(new Error('APPLICATION_WORKER_ROUTE_TIMEOUT')), timeoutMs)
        routePending = { id: request, result, timer: routeTimer }
        try { post({ action: 'route', request }) } catch (error) { fail(error) }
        return result.promise
      },
    }
  } catch (error) { await close(error); throw error }
  finally { void Promise.resolve().then(() => remoteMessages?.return?.()).catch(() => undefined) }
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
  try { return validatePeerDescription(value, expected) }
  catch { throw new Error('APPLICATION_WORKER_DESCRIPTION_INVALID') }
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
function validGatheringTimeout(value: unknown, timeoutMs: number): boolean {
  return value === undefined || validTimeout(value) && value <= timeoutMs
}

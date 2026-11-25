import { frameRtcPeerChannels, WEBRTC_LIMITS } from './channel.js'
import type { PeerDataChannelConnection } from './channel.js'
import {
  createPeerMediaAndStreams, serializeIceCandidate, validatePeerDescription, validatePeerIceCandidate,
} from './renegotiation.js'
import { observeWebRtcRoute } from './route.js'
import type {
  PeerDescription, PeerIceCandidate, PeerSignalingMessage, RtcPeerConnection,
  WebRtcChannels, WebRtcOptions, WebRtcSession,
} from './types.js'

const PROTOCOL = 'chronolog.peer.v2'
const MAX_INITIAL_TRICKLE_CANDIDATES = 32

function isDescription(value: unknown): value is PeerDescription {
  return typeof value === 'object' && value !== null && 'type' in value && 'sdp' in value
}

/**
 * Both fixed negotiated channels are created synchronously on each endpoint.
 * The callback attaches raw framing synchronously. Supports trickle ICE during
 * initial rendezvous (default when adapter implements `addIceCandidate`) plus
 * in-band W3C Perfect Negotiation after Chronolog peer authentication.
 */
export async function negotiateWebRtc(options: WebRtcOptions & {
  readonly onDataChannels: (channels: WebRtcChannels) => void
}): Promise<WebRtcSession> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('WEBRTC_TIMEOUT_INVALID')
  const gatheringMs = options.gatheringTimeoutMs ?? Math.min(WEBRTC_LIMITS.gatheringMs, timeoutMs)
  if (!Number.isSafeInteger(gatheringMs) || gatheringMs < 1 || gatheringMs > timeoutMs) throw new Error('WEBRTC_GATHERING_TIMEOUT_INVALID')
  let connection: RtcPeerConnection
  try {
    options.signal?.throwIfAborted()
    const factory = options.createPeerConnection ?? ((configuration: RTCConfiguration) => new RTCPeerConnection(configuration))
    connection = factory(structuredClone(options.configuration ?? {}))
  } catch (error) {
    void Promise.resolve().then(() => options.signaling.close()).catch(() => undefined)
    throw error
  }
  const controller = new AbortController(), signal = controller.signal
  const useTrickle = options.trickle !== false && typeof connection.addIceCandidate === 'function'
  let negotiationFailed = false
  let closing: Promise<void> | undefined, outcome: WebRtcSession | undefined
  let negotiationError: unknown
  let sentMessages = 0, receivedMessages = 0, sentBytes = 0, receivedBytes = 0
  let bootstrapActive = true
  let localDescriptionSent = false
  let sentCandidates = 0
  const bufferedLocalCandidates: Array<PeerIceCandidate | null> = []
  let remoteDescriptionSet = false
  const bufferedRemoteCandidates: Array<PeerIceCandidate | null> = []

  const mediaAndStreams = createPeerMediaAndStreams(connection, signal, {
    onUnexpectedPreAuthChannel(unexpected) {
      try { unexpected.close() } catch { /* Already closed. */ }
      controller.abort(new Error('WEBRTC_CHANNEL_UNEXPECTED'))
      void close().catch(() => undefined)
    },
  })

  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    bootstrapActive = false
    controller.abort(new Error('WEBRTC_CONNECTION_CLOSED'))
    options.signal?.removeEventListener('abort', abort)
    connection.removeEventListener('connectionstatechange', failed)
    connection.removeEventListener('icecandidate', onBootstrapCandidate)
    mediaAndStreams.close()
    closing = Promise.resolve().then(() => connection.close())
    return closing
  }
  const abort = (): void => { controller.abort(options.signal?.reason); void close().catch(() => undefined) }
  options.signal?.addEventListener('abort', abort, { once: true })
  const failed = (): void => {
    if (['failed', 'closed'].includes(connection.connectionState)) {
      controller.abort(new Error('WEBRTC_CONNECTION_FAILED')); void close().catch(() => undefined)
    }
  }
  connection.addEventListener('connectionstatechange', failed)

  const sendLocalCandidate = (candidate: PeerIceCandidate | null): void => {
    if (!bootstrapActive || signal.aborted || sentCandidates >= MAX_INITIAL_TRICKLE_CANDIDATES) return
    sentCandidates += 1
    sentMessages += 1
    sentBytes += candidate ? new TextEncoder().encode(candidate.candidate).length : 4
    void Promise.resolve(options.signaling.send({ kind: 'candidate', candidate })).catch(() => undefined)
  }

  const onBootstrapCandidate: EventListener = event => {
    if (!useTrickle || !bootstrapActive || signal.aborted) return
    const raw = (event as { candidate?: unknown }).candidate
    let candidate: PeerIceCandidate | null
    try { candidate = serializeIceCandidate(raw) } catch { return }
    if (!localDescriptionSent) {
      if (bufferedLocalCandidates.length < MAX_INITIAL_TRICKLE_CANDIDATES) bufferedLocalCandidates.push(candidate)
      return
    }
    sendLocalCandidate(candidate)
  }
  if (useTrickle) connection.addEventListener('icecandidate', onBootstrapCandidate)

  if (options.signal?.aborted === true) abort()
  const timeout = setTimeout(() => controller.abort(new Error('WEBRTC_NEGOTIATION_TIMEOUT')), timeoutMs)
  let messages: AsyncIterator<PeerSignalingMessage> | undefined

  const applyRemoteCandidate = async (candidate: PeerIceCandidate | null): Promise<void> => {
    if (typeof connection.addIceCandidate !== 'function') return
    if (!remoteDescriptionSet) {
      if (bufferedRemoteCandidates.length < MAX_INITIAL_TRICKLE_CANDIDATES + 4) {
        bufferedRemoteCandidates.push(candidate)
      }
      return
    }
    try { await connection.addIceCandidate(candidate) } catch { /* Ignore stale/duplicate trickle candidate. */ }
  }

  const flushBufferedCandidates = async (): Promise<void> => {
    remoteDescriptionSet = true
    if (typeof connection.addIceCandidate !== 'function') return
    for (const candidate of bufferedRemoteCandidates.splice(0)) {
      if (signal.aborted) return
      try { await connection.addIceCandidate(candidate) } catch { /* Ignore stale candidate. */ }
    }
  }

  const receivedDescription = async (type: PeerDescription['type']): Promise<PeerDescription> => {
    while (true) {
      const item = await interruptible(messages!.next(), signal)
      if (item.done) throw new Error('WEBRTC_SIGNALING_ENDED')
      const value = item.value
      if (isDescription(value)) {
        const description = validatePeerDescription(value, type)
        receivedMessages += 1; receivedBytes += new TextEncoder().encode(description.sdp).length
        return description
      }
      if (useTrickle && typeof value === 'object' && value !== null && 'kind' in value && value.kind === 'candidate') {
        const candidate = validatePeerIceCandidate(value.candidate)
        receivedMessages += 1
        receivedBytes += candidate ? new TextEncoder().encode(candidate.candidate).length : 4
        await applyRemoteCandidate(candidate)
        continue
      }
      throw new Error('WEBRTC_DESCRIPTION_INVALID')
    }
  }

  const publish = async (type: PeerDescription['type']): Promise<void> => {
    if (!useTrickle) {
      const complete = await gatherBatch(connection, gatheringMs, signal)
      const description = validatePeerDescription(connection.localDescription, type)
      if (!complete && !usableCandidate(description.sdp, options.configuration?.iceTransportPolicy)) throw new Error('WEBRTC_ICE_CANDIDATES_UNAVAILABLE')
      await interruptible(options.signaling.send(description), signal)
      sentMessages += 1; sentBytes += new TextEncoder().encode(description.sdp).length
      return
    }
    const description = validatePeerDescription(connection.localDescription, type)
    await interruptible(options.signaling.send(description), signal)
    sentMessages += 1; sentBytes += new TextEncoder().encode(description.sdp).length
    localDescriptionSent = true
    for (const candidate of bufferedLocalCandidates.splice(0)) sendLocalCandidate(candidate)
  }

  let trickleDrain: Promise<void> | undefined
  try {
    const channels: WebRtcChannels = {
      reliable: connection.createDataChannel('chronolog.reliable', { negotiated: true, id: 0, ordered: true, protocol: PROTOCOL }),
      live: connection.createDataChannel('chronolog.live', { negotiated: true, id: 1, ordered: false, maxRetransmits: 0, protocol: PROTOCOL }),
    }
    const returned: unknown = options.onDataChannels(channels)
    if (typeof returned === 'object' && returned !== null && 'then' in returned) {
      void Promise.resolve(returned).catch(() => undefined)
      throw new Error('WEBRTC_CHANNEL_HANDOFF_MUST_BE_SYNCHRONOUS')
    }
    messages = options.signaling.messages[Symbol.asyncIterator]()
    if (options.role === 'offerer') {
      await interruptible(connection.setLocalDescription(await interruptible(connection.createOffer(), signal)), signal)
      await publish('offer')
      await interruptible(connection.setRemoteDescription(await receivedDescription('answer')), signal)
      await flushBufferedCandidates()
    } else {
      await interruptible(connection.setRemoteDescription(await receivedDescription('offer')), signal)
      await flushBufferedCandidates()
      await interruptible(connection.setLocalDescription(await interruptible(connection.createAnswer(), signal)), signal)
      await publish('answer')
    }
    // Keep reading incoming trickle candidates while waiting for ICE to connect.
    if (useTrickle) {
      trickleDrain = (async () => {
        let receivedCandidates = 0
        while (bootstrapActive && !signal.aborted && receivedCandidates <= MAX_INITIAL_TRICKLE_CANDIDATES + 4) {
          const item = await messages.next()
          if (item.done || !bootstrapActive) break
          const value = item.value
          if (typeof value === 'object' && value !== null && 'kind' in value && value.kind === 'candidate') {
            receivedCandidates += 1
            const candidate = validatePeerIceCandidate(value.candidate)
            receivedMessages += 1
            receivedBytes += candidate ? new TextEncoder().encode(candidate.candidate).length : 4
            await applyRemoteCandidate(candidate)
          }
        }
      })().catch(() => undefined)
    }
    await waitFor(connection, 'connectionstatechange', () => connection.connectionState === 'connected', signal)
    signal.throwIfAborted()
    bootstrapActive = false
    connection.removeEventListener('icecandidate', onBootstrapCandidate)
    if (useTrickle) {
      void Promise.resolve(options.signaling.send({ kind: 'connected' })).catch(() => undefined)
    }
    outcome = {
      connection,
      signal,
      signaling: { sentMessages, receivedMessages, sentBytes, receivedBytes },
      media: mediaAndStreams.media,
      streams: mediaAndStreams.streams,
      attachInBandSignaling: binding => mediaAndStreams.attachInBandSignaling(binding),
      getRoute: () => observeWebRtcRoute(connection),
      close,
    }
  } catch (error) { negotiationFailed = true; negotiationError = error; await close().catch(() => undefined) }
  bootstrapActive = false
  connection.removeEventListener('icecandidate', onBootstrapCandidate)
  try { await interruptible(Promise.resolve().then(() => options.signaling.close()), signal) }
  catch (error) {
    await close().catch(() => undefined)
    if (!negotiationFailed) { negotiationFailed = true; negotiationError = error }
  }
  clearTimeout(timeout)
  void trickleDrain
  void Promise.resolve().then(() => messages?.return?.()).catch(() => undefined)
  if (negotiationFailed) throw negotiationError
  if (outcome === undefined) throw new Error('WEBRTC_NEGOTIATION_INCOMPLETE')
  return outcome
}

export async function openWebRtcConnection(options: WebRtcOptions): Promise<PeerDataChannelConnection & { readonly session: WebRtcSession }> {
  const deadline = Date.now() + (options.timeoutMs ?? 30_000)
  let framed: PeerDataChannelConnection | undefined
  const session = await negotiateWebRtc({ ...options, onDataChannels(channels) { framed = frameRtcPeerChannels(channels) } })
  if (framed === undefined) { await session.close(); throw new Error('WEBRTC_CHANNEL_MISSING') }
  const selected = framed
  const retire = (): void => { void session.close().catch(() => undefined) }
  selected.signal.addEventListener('abort', retire, { once: true })
  if (selected.signal.aborted) retire()
  const handshake = new AbortController()
  const timer = setTimeout(() => handshake.abort(new Error('WEBRTC_HANDSHAKE_TIMEOUT')), Math.max(1, deadline - Date.now()))
  try { await interruptible(selected.ready, AbortSignal.any([handshake.signal, session.signal])) }
  catch (error) { await selected.close(); await session.close(); throw error }
  finally { clearTimeout(timer) }
  return {
    ready: selected.ready, signal: selected.signal, session, live: selected.live,
    get stats() { return selected.stats },
    send: (bytes, sendOptions) => selected.send(bytes, sendOptions),
    frames: signal => selected.frames(signal),
    async close() { await selected.close(); await session.close() },
  }
}

function interruptible<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void operation.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void operation.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}

function waitFor(connection: RtcPeerConnection, event: string, complete: () => boolean, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted()
  if (complete()) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const cleanup = (): void => { connection.removeEventListener(event, check); signal.removeEventListener('abort', abort) }
    const check = (): void => { if (complete()) { cleanup(); resolve() } }
    const abort = (): void => { cleanup(); reject(signal.reason) }
    connection.addEventListener(event, check); signal.addEventListener('abort', abort, { once: true }); check()
  })
}

/** Event-driven batch gathering (used only when trickle ICE is explicitly disabled). */
function gatherBatch(connection: RtcPeerConnection, budgetMs: number, signal: AbortSignal): Promise<boolean> {
  signal.throwIfAborted()
  if (connection.iceGatheringState === 'complete') return Promise.resolve(true)
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); connection.removeEventListener('icegatheringstatechange', check); signal.removeEventListener('abort', abort) }
    const finish = () => { cleanup(); resolve(connection.iceGatheringState === 'complete') }
    const check = () => { if (connection.iceGatheringState === 'complete') finish() }
    const abort = () => { cleanup(); reject(signal.reason) }
    const timer = setTimeout(finish, budgetMs)
    connection.addEventListener('icegatheringstatechange', check); signal.addEventListener('abort', abort, { once: true }); check()
  })
}
function usableCandidate(sdp: string, policy?: RTCIceTransportPolicy): boolean {
  return sdp.split(/\r?\n/u).some(line => {
    const fields = line.trim().split(/\s+/u), port = Number(fields[5])
    return fields[0]?.startsWith('a=candidate:') === true && fields[6] === 'typ' &&
      ['udp', 'tcp'].includes(fields[2]?.toLowerCase() ?? '') && Number.isInteger(port) && port > 0 && port <= 65535 &&
      fields[4] !== undefined && !['0.0.0.0', '::', '0:0:0:0:0:0:0:0'].includes(fields[4]) &&
      ['host', 'srflx', 'prflx', 'relay'].includes(fields[7] ?? '') && (policy !== 'relay' || fields[7] === 'relay')
  })
}

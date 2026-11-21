import { frameRtcPeerChannels, WEBRTC_LIMITS } from './channel.js'
import type { PeerDataChannelConnection } from './channel.js'
import { observeWebRtcRoute } from './route.js'
import type { PeerDescription, RtcPeerConnection, WebRtcChannels, WebRtcOptions, WebRtcSession } from './types.js'

const PROTOCOL = 'chronolog.peer.v2'

/**
 * Both fixed negotiated channels are created synchronously on each endpoint.
 * The callback attaches raw framing synchronously. The portable Worker bridge
 * forwards opaque frames; it does not transfer these channels.
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
    // The caller already handed us a signaling lifetime. Even a failed peer
    // factory must retire it; an uncooperative cleanup cannot hide that error.
    void Promise.resolve().then(() => options.signaling.close()).catch(() => undefined)
    throw error
  }
  const controller = new AbortController(), signal = controller.signal
  let negotiationFailed = false
  let closing: Promise<void> | undefined, outcome: WebRtcSession | undefined
  let negotiationError: unknown
  let sentMessages = 0, receivedMessages = 0, sentBytes = 0, receivedBytes = 0
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    controller.abort(new Error('WEBRTC_CONNECTION_CLOSED'))
    options.signal?.removeEventListener('abort', abort)
    connection.removeEventListener('datachannel', dataChannel)
    connection.removeEventListener('connectionstatechange', failed)
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
  // Only the two predeclared lanes belong to this connection. A remote DCEP
  // channel cannot inject a new unbound application path into the session.
  const dataChannel: EventListener = event => {
    const unexpected = (event as RTCDataChannelEvent).channel
    unexpected.close()
    controller.abort(new Error('WEBRTC_CHANNEL_UNEXPECTED'))
    void close().catch(() => undefined)
  }
  connection.addEventListener('datachannel', dataChannel)
  if (options.signal?.aborted === true) abort()
  const timeout = setTimeout(() => controller.abort(new Error('WEBRTC_NEGOTIATION_TIMEOUT')), timeoutMs)
  let descriptions: AsyncIterator<PeerDescription> | undefined
  const receivedDescription = async (type: PeerDescription['type']): Promise<PeerDescription> => {
    const item = await interruptible(descriptions!.next(), signal)
    if (item.done) throw new Error('WEBRTC_SIGNALING_ENDED')
    const description = validateDescription(item.value, type)
    receivedMessages += 1; receivedBytes += new TextEncoder().encode(description.sdp).length
    return description
  }
  const publish = async (type: PeerDescription['type']): Promise<void> => {
    const complete = await gatherBatch(connection, gatheringMs, signal)
    const description = validateDescription(connection.localDescription, type)
    // Only locally generated SDP is inspected here. Preserve every candidate and
    // SDP attribute; a slow server must not block a usable batch until full ICE.
    if (!complete && !usableCandidate(description.sdp, options.configuration?.iceTransportPolicy)) throw new Error('WEBRTC_ICE_CANDIDATES_UNAVAILABLE')
    await interruptible(options.signaling.send(description), signal)
    sentMessages += 1; sentBytes += new TextEncoder().encode(description.sdp).length
  }
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
    descriptions = options.signaling.messages[Symbol.asyncIterator]()
    if (options.role === 'offerer') {
      await interruptible(connection.setLocalDescription(await interruptible(connection.createOffer(), signal)), signal)
      await publish('offer')
      await interruptible(connection.setRemoteDescription(await receivedDescription('answer')), signal)
    } else {
      await interruptible(connection.setRemoteDescription(await receivedDescription('offer')), signal)
      await interruptible(connection.setLocalDescription(await interruptible(connection.createAnswer(), signal)), signal)
      await publish('answer')
    }
    await waitFor(connection, 'connectionstatechange', () => connection.connectionState === 'connected', signal)
    signal.throwIfAborted()
    outcome = { connection, signal, signaling: { sentMessages, receivedMessages, sentBytes, receivedBytes },
      getRoute: () => observeWebRtcRoute(connection), close }
  } catch (error) { negotiationFailed = true; negotiationError = error; await close().catch(() => undefined) }
  try { await interruptible(Promise.resolve().then(() => options.signaling.close()), signal) }
  catch (error) {
    await close().catch(() => undefined)
    if (!negotiationFailed) { negotiationFailed = true; negotiationError = error }
  }
  clearTimeout(timeout)
  // close() is the signaling cancellation boundary; do not wait for a remote
  // iterator return that can remain blocked after an aborted negotiation.
  void Promise.resolve().then(() => descriptions?.return?.()).catch(() => undefined)
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
  return { ready: selected.ready, signal: selected.signal, session, live: selected.live, get stats() { return selected.stats },
    send: (bytes, sendOptions) => selected.send(bytes, sendOptions),
    frames: signal => selected.frames(signal), async close() { await selected.close(); await session.close() } }
}

function validateDescription(value: unknown, type: PeerDescription['type']): PeerDescription {
  if (typeof value !== 'object' || value === null || !('type' in value) || value.type !== type || !('sdp' in value) ||
      typeof value.sdp !== 'string' || value.sdp.length < 1 || new TextEncoder().encode(value.sdp).length > WEBRTC_LIMITS.sdpBytes) {
    throw new Error('WEBRTC_DESCRIPTION_INVALID')
  }
  return { type, sdp: value.sdp }
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

/** Event-driven batch gathering. Only this active phase owns a timer. */
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

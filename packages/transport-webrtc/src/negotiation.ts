import { frameRtcDataChannel, WEBRTC_LIMITS } from './channel.js'
import type { DataChannelConnection } from './channel.js'
import { observeWebRtcRoute } from './route.js'
import type { PeerDescription, RtcDataChannel, RtcPeerConnection, WebRtcOptions, WebRtcSession } from './types.js'

const LABEL = 'chronolog', PROTOCOL = 'chronolog.peer.v1'

/**
 * The callback runs synchronously at channel creation/receipt, so a browser can
 * transfer the channel straight to its owning Worker before it ceases to be
 * transferable. Only negotiation remains on the page.
 */
export async function negotiateWebRtc(options: WebRtcOptions & {
  readonly onDataChannel: (channel: RtcDataChannel) => void
}): Promise<WebRtcSession> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('WEBRTC_TIMEOUT_INVALID')
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
  let channel: RtcDataChannel | undefined, negotiationFailed = false
  let closing: Promise<void> | undefined, outcome: WebRtcSession | undefined
  let negotiationError: unknown
  let channelCreated!: () => void
  const channelReady = new Promise<void>(resolve => { channelCreated = resolve })
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
  const accept = (incoming: RtcDataChannel): void => {
    if (channel !== undefined || incoming.label !== LABEL || !incoming.ordered || incoming.maxPacketLifeTime !== null || incoming.maxRetransmits !== null) {
      incoming.close(); controller.abort(new Error('WEBRTC_CHANNEL_UNEXPECTED')); void close().catch(() => undefined); return
    }
    channel = incoming
    try {
      const returned: unknown = options.onDataChannel(incoming)
      if (typeof returned === 'object' && returned !== null && 'then' in returned) {
        void Promise.resolve(returned).catch(() => undefined)
        throw new Error('WEBRTC_CHANNEL_HANDOFF_MUST_BE_SYNCHRONOUS')
      }
      channelCreated()
    } catch (error) { controller.abort(error) }
  }
  const dataChannel: EventListener = event => accept((event as RTCDataChannelEvent).channel)
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
    await waitFor(connection, 'icegatheringstatechange', () => connection.iceGatheringState === 'complete', signal)
    const description = validateDescription(connection.localDescription, type)
    await interruptible(options.signaling.send(description), signal)
    sentMessages += 1; sentBytes += new TextEncoder().encode(description.sdp).length
  }
  try {
    descriptions = options.signaling.messages[Symbol.asyncIterator]()
    if (options.role === 'offerer') {
      accept(connection.createDataChannel(LABEL, { ordered: true, protocol: PROTOCOL }))
      await interruptible(connection.setLocalDescription(await interruptible(connection.createOffer(), signal)), signal)
      await publish('offer')
      await interruptible(connection.setRemoteDescription(await receivedDescription('answer')), signal)
    } else {
      await interruptible(connection.setRemoteDescription(await receivedDescription('offer')), signal)
      await interruptible(connection.setLocalDescription(await interruptible(connection.createAnswer(), signal)), signal)
      await publish('answer')
    }
    await waitFor(connection, 'connectionstatechange', () => connection.connectionState === 'connected', signal)
    await interruptible(channelReady, signal)
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

export async function openWebRtcConnection(options: WebRtcOptions): Promise<DataChannelConnection & { readonly session: WebRtcSession }> {
  const deadline = Date.now() + (options.timeoutMs ?? 30_000)
  let framed: DataChannelConnection | undefined
  const session = await negotiateWebRtc({ ...options, onDataChannel(channel) { framed = frameRtcDataChannel(channel) } })
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
  return { ready: selected.ready, signal: selected.signal, session, get stats() { return selected.stats }, send: bytes => selected.send(bytes),
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

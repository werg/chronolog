import { WEBRTC_LIMITS } from './channel.js'
import type {
  InBandSignalingHandle, InBandSignalingOptions, PeerDataStream, PeerDataStreamOptions,
  PeerDescription, PeerIceCandidate, PeerMediaController, PeerStreamsController,
  PeerTrackEvent, RtcDataChannel, RtcPeerConnection, RtcSignalMessage,
} from './types.js'

export const APP_STREAM_PREFIX = 'app:'
export const MAX_APP_STREAMS = 16
export const MAX_APP_STREAM_LABEL = 128
export const MAX_APP_STREAM_MESSAGE_BYTES = 1024 * 1024
export const MAX_APP_STREAM_QUEUE = 256
export const MAX_ICE_CANDIDATE_BYTES = 2048
export const RENEGOTIATION_TIMEOUT_MS = 5000
export const ICE_RESTART_DEBOUNCE_MS = 2000

const utf8Bytes = (value: string): number => new TextEncoder().encode(value).length

export function validatePeerDescription(value: unknown, expectedType?: PeerDescription['type']): PeerDescription {
  if (typeof value !== 'object' || value === null || !('type' in value) || !('sdp' in value)) {
    throw new Error('WEBRTC_DESCRIPTION_INVALID')
  }
  const type = (value as { type: unknown }).type
  const sdp = (value as { sdp: unknown }).sdp
  if ((type !== 'offer' && type !== 'answer') || (expectedType !== undefined && type !== expectedType) ||
      typeof sdp !== 'string' || sdp.length < 1 || utf8Bytes(sdp) > WEBRTC_LIMITS.sdpBytes) {
    throw new Error('WEBRTC_DESCRIPTION_INVALID')
  }
  return { type, sdp }
}

export function validatePeerIceCandidate(value: unknown): PeerIceCandidate | null {
  if (value === null) return null
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('WEBRTC_CANDIDATE_INVALID')
  const record = value as Record<string, unknown>
  if (typeof record.candidate !== 'string' || utf8Bytes(record.candidate) > MAX_ICE_CANDIDATE_BYTES) {
    throw new Error('WEBRTC_CANDIDATE_INVALID')
  }
  const sdpMid = record.sdpMid === undefined || record.sdpMid === null
    ? null
    : (typeof record.sdpMid === 'string' && record.sdpMid.length <= 128 ? record.sdpMid : undefined)
  if (sdpMid === undefined) throw new Error('WEBRTC_CANDIDATE_INVALID')
  const sdpMLineIndex = record.sdpMLineIndex === undefined || record.sdpMLineIndex === null
    ? null
    : (typeof record.sdpMLineIndex === 'number' && Number.isSafeInteger(record.sdpMLineIndex) && record.sdpMLineIndex >= 0 && record.sdpMLineIndex <= 1024 ? record.sdpMLineIndex : undefined)
  if (sdpMLineIndex === undefined) throw new Error('WEBRTC_CANDIDATE_INVALID')
  const usernameFragment = record.usernameFragment === undefined || record.usernameFragment === null
    ? null
    : (typeof record.usernameFragment === 'string' && record.usernameFragment.length <= 256 ? record.usernameFragment : undefined)
  if (usernameFragment === undefined) throw new Error('WEBRTC_CANDIDATE_INVALID')
  return {
    candidate: record.candidate,
    ...(sdpMid !== null ? { sdpMid } : {}),
    ...(sdpMLineIndex !== null ? { sdpMLineIndex } : {}),
    ...(usernameFragment !== null ? { usernameFragment } : {}),
  }
}

export function validateRtcSignalMessage(value: unknown): RtcSignalMessage {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('WEBRTC_SIGNAL_INVALID')
  const record = value as Record<string, unknown>
  if (record.kind === 'description') {
    return { kind: 'description', description: validatePeerDescription(record.description) }
  }
  if (record.kind === 'candidate') {
    return { kind: 'candidate', candidate: validatePeerIceCandidate(record.candidate) }
  }
  throw new Error('WEBRTC_SIGNAL_INVALID')
}

export function serializeIceCandidate(candidate: unknown): PeerIceCandidate | null {
  if (candidate === null || candidate === undefined) return null
  const raw = candidate as {
    candidate?: unknown; sdpMid?: unknown; sdpMLineIndex?: unknown; usernameFragment?: unknown
    toJSON?: () => Record<string, unknown>
  }
  const source = typeof raw.toJSON === 'function' ? raw.toJSON() : raw
  if (typeof source.candidate !== 'string') return null
  return validatePeerIceCandidate({
    candidate: source.candidate,
    sdpMid: source.sdpMid ?? null,
    sdpMLineIndex: source.sdpMLineIndex ?? null,
    usernameFragment: source.usernameFragment ?? null,
  })
}

function validStreamLabel(label: string): string {
  if (typeof label !== 'string' || !label.length || label.length > MAX_APP_STREAM_LABEL || !/^[A-Za-z0-9_.:/-]{1,128}$/u.test(label)) {
    throw new Error('WEBRTC_STREAM_LABEL_INVALID')
  }
  return label
}

function wrapDataStream(channel: RtcDataChannel, label: string, parentSignal: AbortSignal, onClose: () => void): PeerDataStream {
  try { channel.binaryType = 'arraybuffer' } catch { /* Adapter may use default binaryType. */ }
  const controller = new AbortController()
  const signal = AbortSignal.any([controller.signal, parentSignal])
  const queue: Array<Uint8Array | string> = []
  let wake: (() => void) | undefined
  let reading = false
  let closed = false

  const finish = (): void => {
    if (closed) return
    closed = true
    controller.abort(new Error('WEBRTC_STREAM_CLOSED'))
    channel.removeEventListener('message', onMessage)
    channel.removeEventListener('close', onChannelClose)
    channel.removeEventListener('error', onChannelClose)
    parentSignal.removeEventListener('abort', onParentAbort)
    wake?.(); wake = undefined
    onClose()
  }
  const onParentAbort = (): void => {
    try { channel.close() } catch { /* Already closed. */ }
    finish()
  }
  const onChannelClose = (): void => { finish() }
  const onMessage: EventListener = event => {
    if (closed) return
    const data: unknown = (event as MessageEvent).data
    let item: Uint8Array | string
    if (typeof data === 'string') {
      if (utf8Bytes(data) > MAX_APP_STREAM_MESSAGE_BYTES) return
      item = data
    } else if (data instanceof ArrayBuffer) {
      if (data.byteLength > MAX_APP_STREAM_MESSAGE_BYTES) return
      item = new Uint8Array(data)
    } else if (ArrayBuffer.isView(data)) {
      if (data.byteLength > MAX_APP_STREAM_MESSAGE_BYTES) return
      item = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    } else {
      return
    }
    if (queue.length >= MAX_APP_STREAM_QUEUE) {
      if (!channel.ordered) queue.shift()
      else return
    }
    queue.push(item)
    wake?.(); wake = undefined
  }

  channel.addEventListener('message', onMessage)
  channel.addEventListener('close', onChannelClose)
  channel.addEventListener('error', onChannelClose)
  parentSignal.addEventListener('abort', onParentAbort, { once: true })
  if (parentSignal.aborted || channel.readyState === 'closed') onParentAbort()

  return {
    label,
    ordered: channel.ordered,
    get readyState() { return closed ? 'closed' : channel.readyState },
    get bufferedAmount() { return channel.bufferedAmount },
    signal,
    send(data: Uint8Array | string) {
      if (closed || channel.readyState !== 'open') throw new Error('WEBRTC_STREAM_NOT_OPEN')
      if (typeof data === 'string') {
        if (utf8Bytes(data) > MAX_APP_STREAM_MESSAGE_BYTES) throw new Error('WEBRTC_STREAM_MESSAGE_TOO_LARGE')
        ;(channel as unknown as { send(payload: string): void }).send(data)
      } else if (data instanceof Uint8Array) {
        if (data.byteLength > MAX_APP_STREAM_MESSAGE_BYTES) throw new Error('WEBRTC_STREAM_MESSAGE_TOO_LARGE')
        const copy = data.byteOffset === 0 && data.byteLength === data.buffer.byteLength && data.buffer instanceof ArrayBuffer
          ? data.buffer
          : data.slice().buffer
        channel.send(copy)
      } else {
        throw new Error('WEBRTC_STREAM_PAYLOAD_INVALID')
      }
    },
    messages(readSignal?: AbortSignal): AsyncIterable<Uint8Array | string> {
      return {
        async *[Symbol.asyncIterator]() {
          if (reading) throw new Error('WEBRTC_STREAM_READER_ACTIVE')
          reading = true
          const combined = readSignal ? AbortSignal.any([signal, readSignal]) : signal
          const onAbort = () => { wake?.(); wake = undefined }
          combined.addEventListener('abort', onAbort, { once: true })
          try {
            while (true) {
              if (queue.length > 0) { yield queue.shift()!; continue }
              if (closed || combined.aborted) return
              await new Promise<void>(resolve => { wake = resolve })
            }
          } finally {
            combined.removeEventListener('abort', onAbort)
            reading = false
          }
        },
      }
    },
    close() {
      try { channel.close() } catch { /* Already closed. */ }
      finish()
    },
  }
}

function withTimeout<T>(operation: Promise<T>, ms: number, signal: AbortSignal, code: string): Promise<T> {
  if (signal.aborted) { void operation.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error(code)) }, ms)
    const onAbort = () => { cleanup(); reject(signal.reason) }
    const cleanup = () => { clearTimeout(timer); signal.removeEventListener('abort', onAbort) }
    signal.addEventListener('abort', onAbort, { once: true })
    void operation.then(value => { cleanup(); resolve(value) }, error => { cleanup(); reject(error) })
  })
}

export interface PeerMediaAndStreamsRuntime {
  readonly media: PeerMediaController
  readonly streams: PeerStreamsController
  attachInBandSignaling(options: InBandSignalingOptions): InBandSignalingHandle
  close(): void
}

/**
 * Manages W3C Perfect Negotiation, ICE restart, RTP tracks, and dynamic `app:*`
 * DataChannels on an authenticated Chronolog WebRTC connection without disrupting
 * the pre-negotiated `chronolog.reliable` (id:0) and `chronolog.live` (id:1) lanes.
 */
export function createPeerMediaAndStreams(
  connection: RtcPeerConnection,
  sessionSignal: AbortSignal,
  options: { readonly onUnexpectedPreAuthChannel: (channel: RtcDataChannel) => void },
): PeerMediaAndStreamsRuntime {
  const activeStreams = new Set<PeerDataStream>()
  const streamListeners = new Set<(stream: PeerDataStream) => void>()
  const trackListeners = new Set<(event: PeerTrackEvent) => void>()
  const activeTracks = new Map<unknown, PeerTrackEvent>()

  let inBand: InBandSignalingOptions | null = null
  let makingOffer = false
  let ignoreOffer = false
  let isSettingRemoteAnswerPending = false
  let pendingCandidates: Array<PeerIceCandidate | null> = []
  let negotiateTail: Promise<void> = Promise.resolve()
  let restartTimer: ReturnType<typeof setTimeout> | undefined
  let lastRestartAt = 0
  let closed = false

  const supportsMedia = typeof connection.addTrack === 'function' && typeof connection.addTransceiver === 'function'

  const reportError = (error: unknown): void => {
    if (closed || sessionSignal.aborted) return
    try { inBand?.onError?.(error) } catch { /* Observer error cannot tear down sync. */ }
  }

  const runOffer = async (iceRestart = false): Promise<void> => {
    if (!inBand || closed || sessionSignal.aborted) return
    makingOffer = true
    let local: PeerDescription | undefined
    try {
      const offer = await withTimeout(
        connection.createOffer(iceRestart ? { iceRestart: true } : undefined),
        RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT',
      )
      if (closed || sessionSignal.aborted || !inBand) return
      if (connection.signalingState !== undefined && connection.signalingState !== 'stable') return
      await withTimeout(connection.setLocalDescription(offer), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT')
      local = validatePeerDescription(connection.localDescription, 'offer')
    } catch (error) {
      // Roll back a half-applied local offer so channels 0/1 remain unaffected.
      if (!closed && connection.signalingState === 'have-local-offer') {
        try { await connection.setLocalDescription({ type: 'rollback' }) } catch { /* Best-effort rollback. */ }
      }
      reportError(error)
      return
    } finally {
      makingOffer = false
    }
    if (local !== undefined && inBand && !closed && !sessionSignal.aborted) {
      void withTimeout(inBand.send({ kind: 'description', description: local }), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT').catch(reportError)
    }
  }

  const enqueueOffer = (iceRestart = false): Promise<void> => {
    negotiateTail = negotiateTail.then(() => runOffer(iceRestart)).catch(reportError)
    return negotiateTail
  }

  const flushPendingCandidates = async (): Promise<void> => {
    if (typeof connection.addIceCandidate !== 'function' || !pendingCandidates.length) return
    const batch = pendingCandidates.splice(0)
    for (const candidate of batch) {
      if (closed || sessionSignal.aborted) return
      try { await connection.addIceCandidate(candidate) }
      catch (error) { if (!ignoreOffer) reportError(error) }
    }
  }

  const handleIncomingSignal = async (raw: RtcSignalMessage): Promise<void> => {
    if (!inBand || closed || sessionSignal.aborted) return
    const message = validateRtcSignalMessage(raw)
    if (message.kind === 'candidate') {
      if (typeof connection.addIceCandidate !== 'function') return
      if (connection.signalingState === 'closed') return
      try {
        await connection.addIceCandidate(message.candidate)
      } catch (error) {
        if (!ignoreOffer) {
          // Buffer if remote description isn't installed yet; otherwise report cleanly.
          if (pendingCandidates.length < 64) pendingCandidates.push(message.candidate)
          else reportError(error)
        }
      }
      return
    }
    const { description } = message
    const readyForOffer = !makingOffer && (connection.signalingState === undefined || connection.signalingState === 'stable' || isSettingRemoteAnswerPending)
    const offerCollision = description.type === 'offer' && !readyForOffer
    ignoreOffer = !inBand.polite && offerCollision
    if (ignoreOffer) return

    isSettingRemoteAnswerPending = description.type === 'answer'
    try {
      if (offerCollision && inBand.polite && connection.signalingState === 'have-local-offer') {
        try { await connection.setLocalDescription({ type: 'rollback' }) } catch { /* Implicit rollback if supported. */ }
      }
      await withTimeout(connection.setRemoteDescription(description), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT')
      await flushPendingCandidates()
      if (description.type === 'offer') {
        const answer = await withTimeout(connection.createAnswer(), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT')
        await withTimeout(connection.setLocalDescription(answer), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT')
        const local = validatePeerDescription(connection.localDescription, 'answer')
        await withTimeout(inBand.send({ kind: 'description', description: local }), RENEGOTIATION_TIMEOUT_MS, sessionSignal, 'WEBRTC_RENEGOTIATION_TIMEOUT')
      }
    } catch (error) {
      reportError(error)
    } finally {
      isSettingRemoteAnswerPending = false
    }
  }

  const onNegotiationNeeded: EventListener = () => {
    if (!inBand || closed || sessionSignal.aborted) return
    void enqueueOffer(false)
  }

  const onIceCandidate: EventListener = event => {
    if (!inBand || closed || sessionSignal.aborted) return
    const raw = (event as { candidate?: unknown }).candidate
    let candidate: PeerIceCandidate | null
    try { candidate = serializeIceCandidate(raw) } catch { return }
    void inBand.send({ kind: 'candidate', candidate }).catch(reportError)
  }

  const onIceConnectionStateChange: EventListener = () => {
    if (!inBand || closed || sessionSignal.aborted) return
    const state = connection.iceConnectionState
    if (state === 'connected' || state === 'completed') {
      if (restartTimer !== undefined) { clearTimeout(restartTimer); restartTimer = undefined }
      return
    }
    if (state === 'disconnected' && restartTimer === undefined) {
      restartTimer = setTimeout(() => {
        restartTimer = undefined
        if (!inBand || closed || sessionSignal.aborted || connection.iceConnectionState !== 'disconnected') return
        if (Date.now() - lastRestartAt < ICE_RESTART_DEBOUNCE_MS) return
        lastRestartAt = Date.now()
        try { connection.restartIce?.() } catch { /* Fall back to explicit offer flag. */ }
        void enqueueOffer(true)
      }, ICE_RESTART_DEBOUNCE_MS)
      if (typeof restartTimer === 'object' && 'unref' in restartTimer) (restartTimer as { unref(): void }).unref()
    }
  }

  const onDataChannel: EventListener = event => {
    const channel = (event as unknown as { channel?: RtcDataChannel }).channel
    if (!channel) return
    if (!inBand) {
      options.onUnexpectedPreAuthChannel(channel)
      return
    }
    if (closed || !channel.label.startsWith(APP_STREAM_PREFIX) || activeStreams.size >= MAX_APP_STREAMS) {
      try { channel.close() } catch { /* Reject unauthorized/over-limit DCEP channel without killing sync. */ }
      return
    }
    const stripped = channel.label.slice(APP_STREAM_PREFIX.length)
    try { validStreamLabel(stripped) } catch {
      try { channel.close() } catch { /* Ignore invalid label. */ }
      return
    }
    const stream = wrapDataStream(channel, stripped, sessionSignal, () => { activeStreams.delete(stream) })
    activeStreams.add(stream)
    for (const listener of streamListeners) {
      try { listener(stream) } catch { /* Listener failure stays isolated. */ }
    }
  }

  const onTrack: EventListener = event => {
    if (closed || sessionSignal.aborted) return
    const raw = event as unknown as { track?: unknown; streams?: readonly unknown[]; transceiver?: unknown }
    if (!raw.track) return
    const trackEvent: PeerTrackEvent = Object.freeze({
      track: raw.track,
      streams: Object.freeze(Array.isArray(raw.streams) ? [...(raw.streams as readonly unknown[])] : []),
      ...(raw.transceiver !== undefined ? { transceiver: raw.transceiver } : {}),
    })
    activeTracks.set(raw.track, trackEvent)
    const maybeTrack = raw.track as { addEventListener?: (t: string, fn: () => void, o?: { once?: boolean }) => void }
    maybeTrack.addEventListener?.('ended', () => { activeTracks.delete(raw.track) }, { once: true })
    if (!inBand) return // Hold track notifications until Ed25519 peer auth completes.
    for (const listener of trackListeners) {
      try { listener(trackEvent) } catch { /* Listener failure stays isolated. */ }
    }
  }

  connection.addEventListener('datachannel', onDataChannel)
  connection.addEventListener('track', onTrack)
  connection.addEventListener('negotiationneeded', onNegotiationNeeded)
  connection.addEventListener('icecandidate', onIceCandidate)
  connection.addEventListener('iceconnectionstatechange', onIceConnectionStateChange)

  const close = (): void => {
    if (closed) return
    closed = true
    inBand = null
    if (restartTimer !== undefined) { clearTimeout(restartTimer); restartTimer = undefined }
    connection.removeEventListener('datachannel', onDataChannel)
    connection.removeEventListener('track', onTrack)
    connection.removeEventListener('negotiationneeded', onNegotiationNeeded)
    connection.removeEventListener('icecandidate', onIceCandidate)
    connection.removeEventListener('iceconnectionstatechange', onIceConnectionStateChange)
    for (const stream of [...activeStreams]) stream.close()
    activeStreams.clear()
    activeTracks.clear()
    streamListeners.clear()
    trackListeners.clear()
    pendingCandidates = []
  }

  sessionSignal.addEventListener('abort', close, { once: true })

  const media: PeerMediaController = {
    get available() { return !closed && !sessionSignal.aborted && supportsMedia },
    get unavailableReason() {
      if (closed || sessionSignal.aborted) return 'closed'
      return supportsMedia ? undefined : 'unsupported'
    },
    addTrack(track, ...streams) {
      if (!this.available || !inBand) throw new Error('WEBRTC_MEDIA_UNAVAILABLE')
      return connection.addTrack!(track, ...streams)
    },
    removeTrack(sender) {
      if (!this.available || !inBand) throw new Error('WEBRTC_MEDIA_UNAVAILABLE')
      connection.removeTrack!(sender)
    },
    addTransceiver(kindOrTrack, init) {
      if (!this.available || !inBand) throw new Error('WEBRTC_MEDIA_UNAVAILABLE')
      return connection.addTransceiver!(kindOrTrack, init)
    },
    getTransceivers() {
      return connection.getTransceivers?.() ?? []
    },
    onTrack(listener) {
      trackListeners.add(listener)
      if (inBand) {
        for (const existing of activeTracks.values()) {
          try { listener(existing) } catch { /* Isolate observer errors. */ }
        }
      }
      return () => { trackListeners.delete(listener) }
    },
    async restartIce() {
      if (closed || sessionSignal.aborted || !inBand) throw new Error('WEBRTC_MEDIA_UNAVAILABLE')
      lastRestartAt = Date.now()
      try { connection.restartIce?.() } catch { /* Fall back to explicit offer flag. */ }
      await enqueueOffer(true)
    },
  }

  const streams: PeerStreamsController = {
    get available() { return !closed && !sessionSignal.aborted },
    get unavailableReason() { return closed || sessionSignal.aborted ? 'closed' : undefined },
    open(label: string, streamOptions: PeerDataStreamOptions = {}): PeerDataStream {
      if (closed || sessionSignal.aborted || !inBand) throw new Error('WEBRTC_STREAMS_UNAVAILABLE')
      if (activeStreams.size >= MAX_APP_STREAMS) throw new Error('WEBRTC_STREAM_LIMIT')
      const clean = validStreamLabel(label)
      const ordered = streamOptions.ordered ?? true
      const channel = connection.createDataChannel(`${APP_STREAM_PREFIX}${clean}`, {
        ordered,
        negotiated: false,
        protocol: 'chronolog.app.v1',
        ...(streamOptions.maxRetransmits !== undefined ? { maxRetransmits: streamOptions.maxRetransmits } : {}),
        ...(streamOptions.maxPacketLifeTime !== undefined ? { maxPacketLifeTime: streamOptions.maxPacketLifeTime } : {}),
      })
      const stream = wrapDataStream(channel, clean, sessionSignal, () => { activeStreams.delete(stream) })
      activeStreams.add(stream)
      return stream
    },
    onStream(listener) {
      streamListeners.add(listener)
      return () => { streamListeners.delete(listener) }
    },
  }

  return {
    media,
    streams,
    attachInBandSignaling(binding: InBandSignalingOptions): InBandSignalingHandle {
      if (closed || sessionSignal.aborted) throw new Error('WEBRTC_CONNECTION_CLOSED')
      if (inBand !== null) throw new Error('WEBRTC_INBAND_ALREADY_ATTACHED')
      inBand = binding
      // Flush any tracks that arrived right before auth finalized.
      for (const existing of activeTracks.values()) {
        for (const listener of trackListeners) {
          try { listener(existing) } catch { /* Isolate observer errors. */ }
        }
      }
      return {
        receive(message: RtcSignalMessage): Promise<void> {
          negotiateTail = negotiateTail.then(() => handleIncomingSignal(message)).catch(reportError)
          return negotiateTail
        },
        close() {
          if (inBand === binding) inBand = null
        },
      }
    },
    close,
  }
}

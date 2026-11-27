import {
  framePeerMessageChannels, type PeerMessageChannel, type PeerMessageConnection,
} from '@chronolog/records'

/** The standard browser/Worker/native WebSocket surface, including relay socket ports. */
export interface PeerWebSocket {
  readonly readyState: number
  readonly bufferedAmount: number
  binaryType: string
  send(data: ArrayBuffer): void
  close(): void
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}

export interface WebSocketPeerChannels {
  readonly reliable: PeerWebSocket
  readonly live: PeerWebSocket
}

export interface WebSocketPeerOptions {
  /** Transport admission may finish after listeners have been installed. */
  readonly ready?: Promise<unknown>
  readonly signal?: AbortSignal
  readonly openTimeoutMs?: number
}

/** Acquire both lanes synchronously, then return only after bounded admission and framing. */
export async function openWebSocketConnection(sockets: WebSocketPeerChannels,
  options: WebSocketPeerOptions = {}): Promise<PeerMessageConnection> {
  const connection = frameWebSocketPeerConnection(sockets, options)
  try { await connection.ready; return connection }
  catch (error) { await connection.close(); throw error }
}

/**
 * Two independent WebSockets use the same bounded framing owner as WebRTC.
 * Install this synchronously when acquiring the sockets: no frame may arrive
 * before its reader is attached. Peer authentication/encryption belongs to the
 * application session above this byte transport.
 */
export function frameWebSocketPeerConnection(sockets: WebSocketPeerChannels,
  options: WebSocketPeerOptions = {}): PeerMessageConnection {
  const timeoutMs = options.openTimeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000 || sockets.reliable === sockets.live)
    throw new Error('PEER_WEBSOCKET_OPTIONS_INVALID')
  const lifetime = new AbortController()
  const fail = (reason: unknown): void => { lifetime.abort(reason) }
  const ready = options.ready ?? Promise.resolve()
  const channels = { reliable: messageChannel(sockets.reliable, ready, fail), live: messageChannel(sockets.live, ready, fail) }
  let framed: PeerMessageConnection
  try { framed = framePeerMessageChannels(channels) }
  catch (error) { channels.reliable.close(); channels.live.close(); throw error }
  const signal = AbortSignal.any([lifetime.signal, framed.signal])
  const abort = (): void => { fail(options.signal?.reason ?? new Error('PEER_WEBSOCKET_CLOSED')) }
  const timer = setTimeout(() => fail(new Error('PEER_WEBSOCKET_OPEN_TIMEOUT')), timeoutMs)
  const stop = (): void => {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abort)
    void framed.close()
  }
  signal.addEventListener('abort', stop, { once: true })
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  if (signal.aborted) stop()
  void framed.ready.then(() => clearTimeout(timer), fail)
  return {
    signal, ready: framed.ready, live: framed.live,
    get stats() { return framed.stats },
    send: (frame, input) => framed.send(frame, input),
    frames: input => framed.frames(input),
    close: () => framed.close(),
  }
}

/** Open a single multiplexed binary WebSocket carrying reliable (0x00) and live (0x01) lanes. */
export async function openSingleWebSocketConnection(
  socket: PeerWebSocket,
  options: WebSocketPeerOptions = {},
): Promise<PeerMessageConnection> {
  const connection = frameSingleWebSocketPeerConnection(socket, options)
  try { await connection.ready; return connection }
  catch (error) { await connection.close(); throw error }
}

/** Frame reliable (0x00) + live (0x01) lanes over ONE binary WebSocket (halves DO sockets & pairing races). */
export function frameSingleWebSocketPeerConnection(
  socket: PeerWebSocket,
  options: WebSocketPeerOptions = {},
): PeerMessageConnection {
  const timeoutMs = options.openTimeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000)
    throw new Error('PEER_WEBSOCKET_OPTIONS_INVALID')
  const lifetime = new AbortController()
  const fail = (reason: unknown): void => { lifetime.abort(reason) }
  const ready = options.ready ?? Promise.resolve()
  const channels = muxMessageChannels(socket, ready, fail)
  let framed: PeerMessageConnection
  try { framed = framePeerMessageChannels(channels) }
  catch (error) { channels.reliable.close(); channels.live.close(); throw error }
  const signal = AbortSignal.any([lifetime.signal, framed.signal])
  const abort = (): void => { fail(options.signal?.reason ?? new Error('PEER_WEBSOCKET_CLOSED')) }
  const timer = setTimeout(() => fail(new Error('PEER_WEBSOCKET_OPEN_TIMEOUT')), timeoutMs)
  const stop = (): void => {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abort)
    void framed.close()
  }
  signal.addEventListener('abort', stop, { once: true })
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted === true) abort()
  if (signal.aborted) stop()
  void framed.ready.then(() => clearTimeout(timer), fail)
  return {
    signal, ready: framed.ready, live: framed.live,
    get stats() { return framed.stats },
    send: (frame, input) => framed.send(frame, input),
    frames: input => framed.frames(input),
    close: () => framed.close(),
  }
}

function muxMessageChannels(
  socket: PeerWebSocket,
  admitted: Promise<unknown>,
  fail: (reason: unknown) => void,
): { readonly reliable: PeerMessageChannel; readonly live: PeerMessageChannel } {
  const relEvents = new EventTarget()
  const liveEvents = new EventTarget()
  const listeners: Array<readonly [string, EventListener]> = []
  let closed = false, allowed = false, relThreshold = 0, liveThreshold = 0, timer: ReturnType<typeof setTimeout> | undefined
  socket.binaryType = 'arraybuffer'
  const on = (type: string, listener: EventListener): void => {
    listeners.push([type, listener]); socket.addEventListener(type, listener)
  }
  const close = (): void => {
    if (closed) return
    closed = true; clearTimeout(timer)
    for (const [type, listener] of listeners) socket.removeEventListener(type, listener)
    try { socket.close() } catch { /* already closed */ }
  }
  const failed = (error: unknown): void => { if (!closed) { fail(error); close() } }
  const opened = (): void => {
    if (!closed && allowed && socket.readyState === 1) {
      relEvents.dispatchEvent(new Event('open'))
      liveEvents.dispatchEvent(new Event('open'))
    }
  }
  const buffered = (): number => {
    const value = socket.bufferedAmount
    if (!Number.isFinite(value) || value < 0) { failed(new Error('PEER_WEBSOCKET_BUFFER_INVALID')); return Infinity }
    return value
  }
  const poll = (): void => {
    timer = undefined
    if (closed) return
    const b = buffered()
    if (b <= relThreshold) relEvents.dispatchEvent(new Event('bufferedamountlow'))
    if (b <= liveThreshold) liveEvents.dispatchEvent(new Event('bufferedamountlow'))
    if (b > Math.min(relThreshold, liveThreshold) && !closed) timer = setTimeout(poll, 10)
  }
  const watch = (): void => {
    if (timer === undefined && !closed && buffered() > Math.min(relThreshold, liveThreshold)) {
      timer = setTimeout(poll, 10)
    }
  }
  on('open', opened)
  on('close', () => failed(new Error('PEER_WEBSOCKET_ENDED')))
  on('error', () => failed(new Error('PEER_WEBSOCKET_ERROR')))
  on('message', event => {
    if (closed) return
    const data = (event as MessageEvent<unknown>).data
    if (!(data instanceof ArrayBuffer)) { failed(new Error('PEER_WEBSOCKET_BINARY_REQUIRED')); return }
    const view = new Uint8Array(data)
    if (view.byteLength < 1) { failed(new Error('PEER_WEBSOCKET_FRAME_INVALID')); return }
    const lane = view[0]
    const payload = data.slice(1)
    if (lane === 0) relEvents.dispatchEvent(new MessageEvent('message', { data: payload }))
    else if (lane === 1) liveEvents.dispatchEvent(new MessageEvent('message', { data: payload }))
    else failed(new Error('PEER_WEBSOCKET_LANE_INVALID'))
  })
  void admitted.then(() => {
    if (closed) return
    allowed = true
    if (socket.readyState >= 2) failed(new Error('PEER_WEBSOCKET_CLOSED'))
    else opened()
  }, failed)
  const makeLane = (laneByte: number, events: EventTarget, getT: () => number, setT: (v: number) => void): PeerMessageChannel => ({
    get readyState() { return closed || socket.readyState >= 2 ? 'closed' : allowed && socket.readyState === 1 ? 'open' : 'connecting' },
    get bufferedAmount() { const value = buffered(); watch(); return value },
    get bufferedAmountLowThreshold() { return getT() },
    set bufferedAmountLowThreshold(value) { setT(value); watch() },
    get binaryType() { return socket.binaryType },
    set binaryType(value) { socket.binaryType = value },
    send(data) {
      if (closed || !allowed || socket.readyState !== 1) throw new Error('PEER_WEBSOCKET_NOT_OPEN')
      const out = new Uint8Array(1 + data.byteLength)
      out[0] = laneByte
      out.set(new Uint8Array(data), 1)
      socket.send(out.buffer); watch()
    },
    close,
    addEventListener: (type, listener) => events.addEventListener(type, listener),
    removeEventListener: (type, listener) => events.removeEventListener(type, listener),
  })
  return {
    reliable: makeLane(0, relEvents, () => relThreshold, v => { relThreshold = v }),
    live: makeLane(1, liveEvents, () => liveThreshold, v => { liveThreshold = v }),
  }
}

/** WebSocket has no drain event; only this physical adapter polls its writable buffer. */
function messageChannel(socket: PeerWebSocket, admitted: Promise<unknown>, fail: (reason: unknown) => void): PeerMessageChannel {
  const events = new EventTarget(), listeners: Array<readonly [string, EventListener]> = []
  let closed = false, allowed = false, threshold = 0, timer: ReturnType<typeof setTimeout> | undefined
  socket.binaryType = 'arraybuffer'
  const on = (type: string, listener: EventListener): void => {
    listeners.push([type, listener]); socket.addEventListener(type, listener)
  }
  const close = (): void => {
    if (closed) return
    closed = true; clearTimeout(timer)
    for (const [type, listener] of listeners) socket.removeEventListener(type, listener)
    try { socket.close() } catch { /* The framing owner is already closed. */ }
  }
  const failed = (error: unknown): void => { if (!closed) { fail(error); close() } }
  const opened = (): void => { if (!closed && allowed && socket.readyState === 1) events.dispatchEvent(new Event('open')) }
  const buffered = (): number => {
    const value = socket.bufferedAmount
    if (!Number.isFinite(value) || value < 0) { failed(new Error('PEER_WEBSOCKET_BUFFER_INVALID')); return Infinity }
    return value
  }
  const poll = (): void => {
    timer = undefined
    if (closed) return
    if (buffered() <= threshold) events.dispatchEvent(new Event('bufferedamountlow'))
    else if (!closed) timer = setTimeout(poll, 10)
  }
  const watch = (): void => { if (timer === undefined && !closed && buffered() > threshold) timer = setTimeout(poll, 10) }
  on('open', opened)
  on('close', () => failed(new Error('PEER_WEBSOCKET_ENDED')))
  on('error', () => failed(new Error('PEER_WEBSOCKET_ERROR')))
  on('message', event => {
    if (closed) return
    const data = (event as MessageEvent<unknown>).data
    if (!(data instanceof ArrayBuffer)) { failed(new Error('PEER_WEBSOCKET_BINARY_REQUIRED')); return }
    events.dispatchEvent(new MessageEvent('message', { data }))
  })
  void admitted.then(() => {
    if (closed) return
    allowed = true
    if (socket.readyState >= 2) failed(new Error('PEER_WEBSOCKET_CLOSED'))
    else opened()
  }, failed)
  return {
    get readyState() { return closed || socket.readyState >= 2 ? 'closed' : allowed && socket.readyState === 1 ? 'open' : 'connecting' },
    get bufferedAmount() { const value = buffered(); watch(); return value },
    get bufferedAmountLowThreshold() { return threshold },
    set bufferedAmountLowThreshold(value) { threshold = value; watch() },
    get binaryType() { return socket.binaryType },
    set binaryType(value) { socket.binaryType = value },
    send(data) {
      if (closed || !allowed || socket.readyState !== 1) throw new Error('PEER_WEBSOCKET_NOT_OPEN')
      socket.send(data); watch()
    },
    close,
    addEventListener: (type, listener) => events.addEventListener(type, listener),
    removeEventListener: (type, listener) => events.removeEventListener(type, listener),
  }
}

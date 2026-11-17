import type { FramedPeerConnection } from './connection.js'

import { frameLiveMessageChannel, type LiveMessageConnection } from './live-channel.js'

/** A binary message transport with a writable-buffer low-water notification. */
export interface PeerMessageChannel {
  readonly readyState: string
  readonly bufferedAmount: number
  bufferedAmountLowThreshold: number
  binaryType: string
  send(data: ArrayBuffer): void
  close(): void
  addEventListener(type: string, listener: EventListener): void
  removeEventListener(type: string, listener: EventListener): void
}
export interface PeerMessageChannels {
  readonly reliable: PeerMessageChannel
  readonly live: PeerMessageChannel
}

export const PEER_MESSAGE_LIMITS = Object.freeze({
  frameBytes: 1_048_576 + 65_536,
  packetBytes: 16 * 1024,
  queueBytes: 4 * 1024 * 1024,
  queueFrames: 16,
  bufferedBytes: 256 * 1024,
})
const HEADER = 16, HELLO = 1, DATA = 2, CREDIT = 3

export interface MessageChannelStats {
  readonly sentBytes: number
  readonly receivedBytes: number
  readonly sentPackets: number
  readonly receivedPackets: number
  readonly queuedSendBytes: number
  readonly queuedReceiveBytes: number
  readonly queuedReceiveFrames: number
}
export interface MessageConnection extends FramedPeerConnection {
  readonly ready: Promise<void>
  /** Ends on framing failure or physical channel closure. */
  readonly signal: AbortSignal
  readonly stats: MessageChannelStats
}

export interface PeerMessageConnection extends MessageConnection {
  readonly live: LiveMessageConnection
}

/** Compose separate traffic lanes while retaining one close/authentication lifetime. */
export function framePeerMessageChannels(channels: PeerMessageChannels,
  options: Parameters<typeof frameMessageChannel>[1] = {}): PeerMessageConnection {
  const reliable = frameMessageChannel(channels.reliable, options)
  let live: LiveMessageConnection
  try { live = frameLiveMessageChannel(channels.live) }
  catch (error) { void reliable.close(); channels.live.close(); throw error }
  const signal = AbortSignal.any([reliable.signal, live.signal])
  const close = async (): Promise<void> => { await Promise.all([reliable.close(), live.close()]) }
  signal.addEventListener('abort', () => { void close() }, { once: true })
  if (signal.aborted) void close()
  const ready = Promise.all([reliable.ready, live.ready]).then(() => undefined)
  void ready.catch(() => undefined)
  return {
    ready, signal, live,
    get stats() {
      const a = reliable.stats, b = live.stats
      return { sentBytes: a.sentBytes + b.sentBytes, receivedBytes: a.receivedBytes + b.receivedBytes,
        sentPackets: a.sentPackets + b.sentPackets, receivedPackets: a.receivedPackets + b.receivedPackets,
        queuedSendBytes: a.queuedSendBytes + b.queuedSendBytes, queuedReceiveBytes: a.queuedReceiveBytes + b.queuedReceiveBytes,
        queuedReceiveFrames: a.queuedReceiveFrames + b.queuedReceiveFrames }
    },
    send: (bytes, sendOptions) => reliable.send(bytes, sendOptions), frames: input => reliable.frames(input), close,
  }
}

/**
 * One reliable ordered binary message channel. Whole-frame receive credit bounds
 * allocation and object count; transport bufferedAmount separately bounds writes.
 * Credits are returned only after the application advances its frame iterator.
 */
export function frameMessageChannel(channel: PeerMessageChannel, options: {
  readonly maxFrameBytes?: number
  readonly queueBytes?: number
  readonly queueFrames?: number
  readonly sendTimeoutMs?: number
  /** Starts when the local channel opens, independently of transport admission. */
  readonly helloTimeoutMs?: number
} = {}): MessageConnection {
  const maximum = options.maxFrameBytes ?? PEER_MESSAGE_LIMITS.frameBytes
  const windowBytes = options.queueBytes ?? PEER_MESSAGE_LIMITS.queueBytes
  const windowFrames = options.queueFrames ?? PEER_MESSAGE_LIMITS.queueFrames
  const timeoutMs = options.sendTimeoutMs ?? 30_000
  const helloTimeoutMs = options.helloTimeoutMs ?? 10_000
  if (![maximum, windowBytes, windowFrames, timeoutMs, helloTimeoutMs].every(Number.isSafeInteger) || maximum < 1 || maximum > PEER_MESSAGE_LIMITS.frameBytes ||
      windowBytes < maximum || windowBytes > PEER_MESSAGE_LIMITS.queueBytes || windowFrames < 1 || windowFrames > PEER_MESSAGE_LIMITS.queueFrames ||
      timeoutMs < 1 || timeoutMs > 120_000 || helloTimeoutMs < 1 || helloTimeoutMs > 120_000) throw new Error('PEER_MESSAGE_BOUNDS_INVALID')
  channel.binaryType = 'arraybuffer'
  channel.bufferedAmountLowThreshold = PEER_MESSAGE_LIMITS.bufferedBytes / 2
  let closed = false, failure: Error | null = null, opened = false, greeted = false, reading = false
  let remoteMaximum = 0, remoteWindow = 0, remoteFrames = 0, creditBytes = 0, creditFrames = 0
  let queuedSendBytes = 0, queuedSendFrames = 0, reservedBytes = 0, reservedFrames = 0
  let assembling: Uint8Array | null = null, received = 0
  let sentBytes = 0, receivedBytes = 0, sentPackets = 0, receivedPackets = 0
  const lifetime = new AbortController()
  const queue: Uint8Array[] = [], waiters = new Set<() => void>()
  let tail: Promise<void> = Promise.resolve()
  let helloTimer: ReturnType<typeof setTimeout> | undefined
  let resolveReady!: () => void, rejectReady!: (error: Error) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  const wake = (): void => { for (const resolve of waiters) resolve(); waiters.clear() }
  const wait = (): Promise<void> => new Promise(resolve => { waiters.add(resolve) })
  const assertOpen = (): void => { if (closed) throw failure ?? new Error('PEER_MESSAGE_CONNECTION_CLOSED') }
  const listeners: Array<readonly [string, EventListener]> = []
  const stop = (error?: Error): void => {
    if (closed) return
    closed = true; failure = error ?? null
    clearTimeout(helloTimer)
    rejectReady(error ?? new Error('PEER_MESSAGE_CONNECTION_CLOSED'))
    for (const [type, listener] of listeners) channel.removeEventListener(type, listener)
    queue.length = 0; assembling = null; reservedBytes = 0; reservedFrames = 0
    lifetime.abort(error ?? new Error('PEER_MESSAGE_CONNECTION_CLOSED'))
    channel.close(); wake()
  }
  const fail = (error: unknown): void => stop(error instanceof Error ? error : new Error(String(error)))
  const packet = (kind: number, a: number, b: number, c = 0, payload?: Uint8Array): void => {
    assertOpen()
    const bytes = new Uint8Array(HEADER + (payload?.length ?? 0)), fields = new DataView(bytes.buffer)
    bytes.set([0x43, 0x52, 1, kind]); fields.setUint32(4, a); fields.setUint32(8, b); fields.setUint32(12, c)
    if (payload !== undefined) bytes.set(payload, HEADER)
    channel.send(bytes.buffer); sentPackets += 1
  }
  const open = (): void => {
    if (opened || closed) return
    try {
      packet(HELLO, maximum, windowBytes, windowFrames)
      opened = true
      if (greeted) resolveReady()
      else helloTimer = setTimeout(() => fail(new Error('PEER_MESSAGE_HELLO_TIMEOUT')), helloTimeoutMs)
    } catch (error) { fail(error) }
  }
  const on = (type: string, listener: EventListener): void => { listeners.push([type, listener]); channel.addEventListener(type, listener) }
  on('open', open)
  on('bufferedamountlow', wake)
  on('close', () => fail(new Error(assembling === null ? 'PEER_MESSAGE_CONNECTION_ENDED' : 'PEER_MESSAGE_FRAME_TRUNCATED')))
  on('error', () => fail(new Error('PEER_MESSAGE_CHANNEL_ERROR')))
  on('message', event => {
    if (closed) return
    try {
      const value = (event as MessageEvent<unknown>).data
      if (!(value instanceof ArrayBuffer) || value.byteLength < HEADER || value.byteLength > PEER_MESSAGE_LIMITS.packetBytes) throw new Error('PEER_MESSAGE_PACKET_INVALID')
      const bytes = new Uint8Array(value), fields = new DataView(value), kind = bytes[3]
      if (bytes[0] !== 0x43 || bytes[1] !== 0x52 || bytes[2] !== 1) throw new Error('PEER_MESSAGE_PROTOCOL_INVALID')
      const a = fields.getUint32(4), b = fields.getUint32(8), c = fields.getUint32(12)
      receivedPackets += 1
      if (kind === HELLO) {
        if (greeted || bytes.length !== HEADER || a < 1 || a > PEER_MESSAGE_LIMITS.frameBytes || b < a || b > PEER_MESSAGE_LIMITS.queueBytes ||
            c < 1 || c > PEER_MESSAGE_LIMITS.queueFrames) throw new Error('PEER_MESSAGE_HELLO_INVALID')
        greeted = true; remoteMaximum = a; remoteWindow = b; remoteFrames = c; creditBytes = b; creditFrames = c
        // Some transports can receive HELLO before local open notification.
        // Never enqueue DATA ahead of our own HELLO.
        if (opened) { clearTimeout(helloTimer); resolveReady() }
        wake(); return
      }
      if (!greeted) throw new Error('PEER_MESSAGE_HELLO_REQUIRED')
      if (kind === CREDIT) {
        if (bytes.length !== HEADER || a < 1 || b !== 1 || c !== 0 || creditBytes + a > remoteWindow || creditFrames + 1 > remoteFrames) {
          throw new Error('PEER_MESSAGE_CREDIT_INVALID')
        }
        creditBytes += a; creditFrames += 1; wake(); return
      }
      const length = bytes.length - HEADER
      if (kind !== DATA || c !== 0 || a < 1 || a > maximum || b !== received || length < 1 || length > a - b ||
          assembling !== null && assembling.length !== a) throw new Error('PEER_MESSAGE_FRAGMENT_INVALID')
      if (assembling === null) {
        if (reservedBytes + a > windowBytes || reservedFrames + 1 > windowFrames) throw new Error('PEER_MESSAGE_RECEIVE_CREDIT_EXCEEDED')
        assembling = new Uint8Array(a); reservedBytes += a; reservedFrames += 1
      }
      assembling.set(bytes.subarray(HEADER), b); received += length; receivedBytes += length
      if (received === a) { queue.push(assembling); assembling = null; received = 0; wake() }
    } catch (error) { fail(error) }
  })
  if (channel.readyState === 'open') queueMicrotask(open)
  else if (channel.readyState !== 'connecting') stop(new Error('PEER_MESSAGE_CONNECTION_CLOSED'))
  return {
    ready, signal: lifetime.signal,
    get stats() { return { sentBytes, receivedBytes, sentPackets, receivedPackets, queuedSendBytes,
      queuedReceiveBytes: reservedBytes, queuedReceiveFrames: reservedFrames } },
    send(input, sendOptions = {}) {
      if (closed) return Promise.reject(failure ?? new Error('PEER_MESSAGE_CONNECTION_CLOSED'))
      if (sendOptions.signal?.aborted === true) return Promise.reject(sendOptions.signal.reason)
      if (!(input instanceof Uint8Array) || input.length < 1 || input.length > maximum) return Promise.reject(new Error('PEER_MESSAGE_FRAME_TOO_LARGE'))
      if (queuedSendBytes + input.length > windowBytes || queuedSendFrames + 1 > windowFrames) return Promise.reject(new Error('PEER_MESSAGE_SEND_BACKPRESSURE'))
      const bytes = input.slice()
      queuedSendBytes += bytes.length; queuedSendFrames += 1
      const task = tail.then(async () => {
        let dispatched = false
        const assertSending = (): void => { assertOpen(); sendOptions.signal?.throwIfAborted() }
        const cancelled = (): void => { wake() }
        sendOptions.signal?.addEventListener('abort', cancelled, { once: true })
        const timeout = setTimeout(() => fail(new Error('PEER_MESSAGE_SEND_TIMEOUT')), timeoutMs)
        try {
          await ready; assertSending()
          if (bytes.length > remoteMaximum) throw new Error('PEER_MESSAGE_REMOTE_FRAME_TOO_LARGE')
          while (creditBytes < bytes.length || creditFrames === 0) { assertSending(); await wait() }
          assertSending()
          for (let offset = 0; offset < bytes.length; offset += PEER_MESSAGE_LIMITS.packetBytes - HEADER) {
            while (channel.bufferedAmount > PEER_MESSAGE_LIMITS.bufferedBytes - PEER_MESSAGE_LIMITS.packetBytes) { assertSending(); await wait() }
            assertSending()
            if (!dispatched) { creditBytes -= bytes.length; creditFrames -= 1; dispatched = true }
            const part = bytes.subarray(offset, offset + PEER_MESSAGE_LIMITS.packetBytes - HEADER)
            packet(DATA, bytes.length, offset, 0, part); sentBytes += part.length
          }
        } catch (error) {
          if (dispatched || sendOptions.signal?.aborted !== true || error !== sendOptions.signal.reason) fail(error)
          throw error
        } finally { clearTimeout(timeout); sendOptions.signal?.removeEventListener('abort', cancelled) }
      }).finally(() => { queuedSendBytes -= bytes.length; queuedSendFrames -= 1 })
      tail = task.catch(() => undefined)
      return task
    },
    async *frames(signal) {
      if (reading) throw new Error('PEER_MESSAGE_READER_EXISTS')
      reading = true
      const abort = (): void => stop()
      signal?.addEventListener('abort', abort, { once: true })
      try {
        if (signal?.aborted === true) return
        await ready
        for (;;) {
          if (failure !== null) throw failure
          if (closed) return
          const frame = queue.shift()
          if (frame === undefined) { await wait(); continue }
          yield frame
          if (!closed) { reservedBytes -= frame.length; reservedFrames -= 1; packet(CREDIT, frame.length, 1) }
        }
      } finally { signal?.removeEventListener('abort', abort); stop() }
    },
    async close() { stop(); await tail },
  }
}

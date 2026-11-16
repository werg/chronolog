import type { FramedPeerConnection } from '@chronolog/agent-service/framing'

import type { RtcDataChannel } from './types.js'

export const WEBRTC_LIMITS = Object.freeze({
  frameBytes: 1_048_576 + 65_536,
  packetBytes: 16 * 1024,
  queueBytes: 4 * 1024 * 1024,
  queueFrames: 16,
  bufferedBytes: 256 * 1024,
  sdpBytes: 64 * 1024,
})
const HEADER = 16, HELLO = 1, DATA = 2, CREDIT = 3

export interface DataChannelStats {
  readonly sentBytes: number
  readonly receivedBytes: number
  readonly sentPackets: number
  readonly receivedPackets: number
  readonly queuedSendBytes: number
  readonly queuedReceiveBytes: number
  readonly queuedReceiveFrames: number
}
export interface DataChannelConnection extends FramedPeerConnection {
  readonly ready: Promise<void>
  readonly stats: DataChannelStats
}

/**
 * One reliable ordered SCTP channel. Whole-frame receive credit bounds both
 * allocation and object count; SCTP bufferedAmount separately bounds writes.
 * Credits are returned only after the application advances its frame iterator.
 */
export function frameRtcDataChannel(channel: RtcDataChannel, options: {
  readonly maxFrameBytes?: number
  readonly queueBytes?: number
  readonly queueFrames?: number
  readonly sendTimeoutMs?: number
} = {}): DataChannelConnection {
  const maximum = options.maxFrameBytes ?? WEBRTC_LIMITS.frameBytes
  const windowBytes = options.queueBytes ?? WEBRTC_LIMITS.queueBytes
  const windowFrames = options.queueFrames ?? WEBRTC_LIMITS.queueFrames
  const timeoutMs = options.sendTimeoutMs ?? 30_000
  if (![maximum, windowBytes, windowFrames, timeoutMs].every(Number.isSafeInteger) || maximum < 1 || maximum > WEBRTC_LIMITS.frameBytes ||
      windowBytes < maximum || windowBytes > WEBRTC_LIMITS.queueBytes || windowFrames < 1 || windowFrames > WEBRTC_LIMITS.queueFrames ||
      timeoutMs < 1 || timeoutMs > 120_000) throw new Error('WEBRTC_BOUNDS_INVALID')
  if (!channel.ordered || channel.maxPacketLifeTime !== null || channel.maxRetransmits !== null) throw new Error('WEBRTC_RELIABLE_ORDERED_REQUIRED')
  channel.binaryType = 'arraybuffer'
  channel.bufferedAmountLowThreshold = WEBRTC_LIMITS.bufferedBytes / 2
  let closed = false, failure: Error | null = null, opened = false, greeted = false, reading = false
  let remoteMaximum = 0, remoteWindow = 0, remoteFrames = 0, creditBytes = 0, creditFrames = 0
  let queuedSendBytes = 0, queuedSendFrames = 0, reservedBytes = 0, reservedFrames = 0
  let assembling: Uint8Array | null = null, received = 0
  let sentBytes = 0, receivedBytes = 0, sentPackets = 0, receivedPackets = 0
  const queue: Uint8Array[] = [], waiters = new Set<() => void>()
  let tail: Promise<void> = Promise.resolve()
  let resolveReady!: () => void, rejectReady!: (error: Error) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  const wake = (): void => { for (const resolve of waiters) resolve(); waiters.clear() }
  const wait = (): Promise<void> => new Promise(resolve => { waiters.add(resolve) })
  const assertOpen = (): void => { if (closed) throw failure ?? new Error('WEBRTC_CONNECTION_CLOSED') }
  const listeners: Array<readonly [string, EventListener]> = []
  const stop = (error?: Error): void => {
    if (closed) return
    closed = true; failure = error ?? null
    rejectReady(error ?? new Error('WEBRTC_CONNECTION_CLOSED'))
    for (const [type, listener] of listeners) channel.removeEventListener(type, listener)
    queue.length = 0; assembling = null; reservedBytes = 0; reservedFrames = 0
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
    opened = true
    try { packet(HELLO, maximum, windowBytes, windowFrames) } catch (error) { fail(error) }
  }
  const on = (type: string, listener: EventListener): void => { listeners.push([type, listener]); channel.addEventListener(type, listener) }
  on('open', open)
  on('bufferedamountlow', wake)
  on('close', () => fail(new Error(assembling === null ? 'WEBRTC_CONNECTION_ENDED' : 'WEBRTC_FRAME_TRUNCATED')))
  on('error', () => fail(new Error('WEBRTC_CHANNEL_ERROR')))
  on('message', event => {
    if (closed) return
    try {
      const value = (event as MessageEvent<unknown>).data
      if (!(value instanceof ArrayBuffer) || value.byteLength < HEADER || value.byteLength > WEBRTC_LIMITS.packetBytes) throw new Error('WEBRTC_PACKET_INVALID')
      const bytes = new Uint8Array(value), fields = new DataView(value), kind = bytes[3]
      if (bytes[0] !== 0x43 || bytes[1] !== 0x52 || bytes[2] !== 1) throw new Error('WEBRTC_PROTOCOL_INVALID')
      const a = fields.getUint32(4), b = fields.getUint32(8), c = fields.getUint32(12)
      receivedPackets += 1
      if (kind === HELLO) {
        if (greeted || bytes.length !== HEADER || a < 1 || a > WEBRTC_LIMITS.frameBytes || b < a || b > WEBRTC_LIMITS.queueBytes ||
            c < 1 || c > WEBRTC_LIMITS.queueFrames) throw new Error('WEBRTC_HELLO_INVALID')
        greeted = true; remoteMaximum = a; remoteWindow = b; remoteFrames = c; creditBytes = b; creditFrames = c
        resolveReady(); wake(); return
      }
      if (!greeted) throw new Error('WEBRTC_HELLO_REQUIRED')
      if (kind === CREDIT) {
        if (bytes.length !== HEADER || a < 1 || b !== 1 || c !== 0 || creditBytes + a > remoteWindow || creditFrames + 1 > remoteFrames) {
          throw new Error('WEBRTC_CREDIT_INVALID')
        }
        creditBytes += a; creditFrames += 1; wake(); return
      }
      const length = bytes.length - HEADER
      if (kind !== DATA || c !== 0 || a < 1 || a > maximum || b !== received || length < 1 || length > a - b ||
          assembling !== null && assembling.length !== a) throw new Error('WEBRTC_FRAGMENT_INVALID')
      if (assembling === null) {
        if (reservedBytes + a > windowBytes || reservedFrames + 1 > windowFrames) throw new Error('WEBRTC_RECEIVE_CREDIT_EXCEEDED')
        assembling = new Uint8Array(a); reservedBytes += a; reservedFrames += 1
      }
      assembling.set(bytes.subarray(HEADER), b); received += length; receivedBytes += length
      if (received === a) { queue.push(assembling); assembling = null; received = 0; wake() }
    } catch (error) { fail(error) }
  })
  if (channel.readyState === 'open') queueMicrotask(open)
  else if (channel.readyState !== 'connecting') stop(new Error('WEBRTC_CONNECTION_CLOSED'))
  return {
    ready,
    get stats() { return { sentBytes, receivedBytes, sentPackets, receivedPackets, queuedSendBytes,
      queuedReceiveBytes: reservedBytes, queuedReceiveFrames: reservedFrames } },
    send(input) {
      if (closed) return Promise.reject(failure ?? new Error('WEBRTC_CONNECTION_CLOSED'))
      if (!(input instanceof Uint8Array) || input.length < 1 || input.length > maximum) return Promise.reject(new Error('WEBRTC_FRAME_TOO_LARGE'))
      if (queuedSendBytes + input.length > windowBytes || queuedSendFrames + 1 > windowFrames) return Promise.reject(new Error('WEBRTC_SEND_BACKPRESSURE'))
      const bytes = input.slice()
      queuedSendBytes += bytes.length; queuedSendFrames += 1
      const task = tail.then(async () => {
        const timeout = setTimeout(() => fail(new Error('WEBRTC_SEND_TIMEOUT')), timeoutMs)
        try {
          await ready; assertOpen()
          if (bytes.length > remoteMaximum) throw new Error('WEBRTC_REMOTE_FRAME_TOO_LARGE')
          while (creditBytes < bytes.length || creditFrames === 0) { assertOpen(); await wait() }
          assertOpen(); creditBytes -= bytes.length; creditFrames -= 1
          for (let offset = 0; offset < bytes.length; offset += WEBRTC_LIMITS.packetBytes - HEADER) {
            while (channel.bufferedAmount > WEBRTC_LIMITS.bufferedBytes - WEBRTC_LIMITS.packetBytes) { assertOpen(); await wait() }
            assertOpen()
            const part = bytes.subarray(offset, offset + WEBRTC_LIMITS.packetBytes - HEADER)
            packet(DATA, bytes.length, offset, 0, part); sentBytes += part.length
          }
        } finally { clearTimeout(timeout) }
      }).catch((error: unknown) => { fail(error); throw error }).finally(() => { queuedSendBytes -= bytes.length; queuedSendFrames -= 1 })
      tail = task.catch(() => undefined)
      return task
    },
    async *frames(signal) {
      if (reading) throw new Error('WEBRTC_READER_EXISTS')
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

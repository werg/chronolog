import type { MessageChannelStats, PeerMessageChannel } from './message-channel.js'
import type { PeerLiveLane } from './connection.js'

export const PEER_LIVE_MESSAGE_LIMITS = Object.freeze({ frameBytes: 16_448, queueFrames: 64, bufferedBytes: 65_536 })

export interface LiveMessageConnection extends PeerLiveLane {
  readonly ready: Promise<void>
  readonly signal: AbortSignal
  readonly stats: MessageChannelStats & { readonly droppedPackets: number }
}

/**
 * Disposable frames on an independent message channel. The physical transport
 * determines delivery ordering; this lane never adds a queue, credit wait or retry.
 * Congestion refuses dispatch; a slow reader loses oldest pending datagrams.
 */
export function frameLiveMessageChannel(channel: PeerMessageChannel): LiveMessageConnection {
  channel.binaryType = 'arraybuffer'
  let closed = false, reading = false, failure: Error | null = null
  let sentBytes = 0, receivedBytes = 0, sentPackets = 0, receivedPackets = 0, queuedReceiveBytes = 0, droppedPackets = 0
  let resolveReady!: () => void, rejectReady!: (error: Error) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  void ready.catch(() => undefined)
  const lifetime = new AbortController(), queue: Uint8Array[] = [], waiters = new Set<() => void>()
  const listeners: Array<readonly [string, EventListener]> = []
  const wake = (): void => { for (const resolve of waiters) resolve(); waiters.clear() }
  const stop = (error?: Error): void => {
    if (closed) return
    closed = true; failure = error ?? null
    rejectReady(error ?? new Error('PEER_MESSAGE_LIVE_CLOSED'))
    for (const [type, listener] of listeners) channel.removeEventListener(type, listener)
    queue.length = 0; queuedReceiveBytes = 0
    lifetime.abort(error ?? new Error('PEER_MESSAGE_LIVE_CLOSED'))
    channel.close(); wake()
  }
  const on = (type: string, listener: EventListener): void => { listeners.push([type, listener]); channel.addEventListener(type, listener) }
  on('open', () => resolveReady())
  on('close', () => stop(new Error('PEER_MESSAGE_LIVE_ENDED')))
  on('error', () => stop(new Error('PEER_MESSAGE_LIVE_ERROR')))
  on('message', event => {
    if (closed) return
    const value = (event as MessageEvent<unknown>).data
    if (!(value instanceof ArrayBuffer) || value.byteLength < 1 || value.byteLength > PEER_LIVE_MESSAGE_LIMITS.frameBytes) {
      stop(new Error('PEER_MESSAGE_LIVE_FRAME_INVALID')); return
    }
    receivedBytes += value.byteLength; receivedPackets += 1
    if (queue.length === PEER_LIVE_MESSAGE_LIMITS.queueFrames) {
      queuedReceiveBytes -= queue.shift()!.length; droppedPackets += 1
    }
    const bytes = new Uint8Array(value.slice(0))
    queue.push(bytes); queuedReceiveBytes += bytes.length; wake()
  })
  if (channel.readyState === 'open') resolveReady()
  else if (channel.readyState !== 'connecting') stop(new Error('PEER_MESSAGE_LIVE_CLOSED'))

  async function* read(signal: AbortSignal): AsyncGenerator<Uint8Array, void> {
    if (reading) throw new Error('PEER_MESSAGE_LIVE_READER_EXISTS')
    reading = true
    const abort = (): void => stop()
    signal.addEventListener('abort', abort, { once: true })
    try {
      if (signal.aborted) return
      for (;;) {
        if (failure !== null) throw failure
        if (closed) return
        const bytes = queue.shift()
        if (bytes === undefined) { await new Promise<void>(resolve => { waiters.add(resolve) }); continue }
        queuedReceiveBytes -= bytes.length
        yield bytes
      }
    } finally { signal.removeEventListener('abort', abort); stop() }
  }

  return {
    ready, signal: lifetime.signal,
    get stats() { return { sentBytes, receivedBytes, sentPackets, receivedPackets, droppedPackets,
      queuedSendBytes: channel.bufferedAmount, queuedReceiveBytes, queuedReceiveFrames: queue.length } },
    async trySend(input, options = {}) {
      options.signal?.throwIfAborted()
      if (closed) throw failure ?? new Error('PEER_MESSAGE_LIVE_CLOSED')
      if (channel.readyState !== 'open') throw new Error('PEER_MESSAGE_LIVE_NOT_OPEN')
      if (!(input instanceof Uint8Array) || input.length < 1 || input.length > PEER_LIVE_MESSAGE_LIMITS.frameBytes) throw new Error('PEER_MESSAGE_LIVE_FRAME_TOO_LARGE')
      if (channel.bufferedAmount + input.length > PEER_LIVE_MESSAGE_LIMITS.bufferedBytes) return false
      // No application queue or suspension can dispatch this frame after cancellation.
      channel.send(input.slice().buffer); sentBytes += input.length; sentPackets += 1
      return true
    },
    frames(signal) {
      return { [Symbol.asyncIterator]() {
        const controller = new AbortController()
        const iterator = read(signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal]))
        return { next: () => iterator.next(),
          async return() { controller.abort(); return iterator.return() },
          async throw(error: unknown) { controller.abort(); return iterator.throw(error) } }
      } }
    },
    async close() { stop() },
  }
}

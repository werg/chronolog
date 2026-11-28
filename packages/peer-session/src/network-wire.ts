import type { FramedPeerConnection } from '@chronolog/records'
import { perfCount } from '@chronolog/canonical'
import { decodeWireValue, encodeWireValue } from './wire-codec.js'
export type { FramedPeerConnection, PeerLiveLane } from '@chronolog/records'
export const APPLICATION_NETWORK_LIMITS = Object.freeze({
  messageBytes: 32 * 1024 * 1024, fragmentBytes: 48 * 1024, queuedMessages: 8,
  queuedBytes: 32 * 1024 * 1024, pendingRequests: 4, incomingRequests: 4,
  rangeCommands: 32, rangeBytes: 4 * 1024 * 1024, peers: 16,
})
export function networkError(code: string): Error { return new Error(code) }
export function requireNetwork(value: unknown, code: string): asserts value {
  if (!value) throw networkError(code)
}
export function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  requireNetwork(value !== null && typeof value === 'object' && !Array.isArray(value), 'APPLICATION_NETWORK_MESSAGE_INVALID')
  const result = value as Record<string, unknown>
  requireNetwork(Object.keys(result).length === keys.length && keys.every(key => Object.hasOwn(result, key)), 'APPLICATION_NETWORK_MESSAGE_INVALID')
  return result
}
export function interruptible<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(signal.reason)
    signal.addEventListener('abort', abort, { once: true })
    void promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}
export function timeout(milliseconds: number, message: string): { signal: AbortSignal; cancel(): void } {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(networkError(message)), milliseconds)
  return { signal: controller.signal, cancel: () => clearTimeout(timer) }
}

/** One bounded assembly and one serialized writer; no JSON-sized RTC frame. */
const FRAGMENT_VERSION = 2
const FRAGMENT_HEADER = 13

/** Fragment frame: [version u8][message id u32][offset u32][total u32][fragment bytes]. */
function encodeFragment(id: number, offset: number, total: number, fragment: Uint8Array): Uint8Array {
  const frame = new Uint8Array(FRAGMENT_HEADER + fragment.length), view = new DataView(frame.buffer)
  frame[0] = FRAGMENT_VERSION
  view.setUint32(1, id); view.setUint32(5, offset); view.setUint32(9, total)
  frame.set(fragment, FRAGMENT_HEADER)
  return frame
}

function decodeFragment(frame: Uint8Array): { id: number; position: number; total: number; chunk: Uint8Array } {
  requireNetwork(frame.length > FRAGMENT_HEADER && frame[0] === FRAGMENT_VERSION, 'APPLICATION_NETWORK_FRAME_INVALID')
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength)
  return { id: view.getUint32(1), position: view.getUint32(5), total: view.getUint32(9), chunk: frame.subarray(FRAGMENT_HEADER) }
}

export class ApplicationMessageWire {
  readonly #connection: FramedPeerConnection
  readonly #signal: AbortSignal
  readonly #timeoutMs: number
  readonly #authorize: () => void
  #outgoing = 0
  #incoming = 0
  #pending = 0
  #pendingBytes = 0
  #sentBytes = 0
  #receivedBytes = 0
  #tail: Promise<void> = Promise.resolve()
  constructor(connection: FramedPeerConnection, signal: AbortSignal, timeoutMs: number, authorize: () => void = () => {}) {
    this.#connection = connection; this.#signal = signal; this.#timeoutMs = timeoutMs; this.#authorize = authorize
  }
  get stats(): { readonly sentBytes: number; readonly receivedBytes: number } {
    return { sentBytes: this.#sentBytes, receivedBytes: this.#receivedBytes }
  }
  send(value: unknown, authorize?: () => void): Promise<void> {
    this.#signal.throwIfAborted()
    requireNetwork(this.#pending < APPLICATION_NETWORK_LIMITS.queuedMessages, 'APPLICATION_NETWORK_BACKPRESSURE')
    const bytes = encodeWireValue(value)
    const kind = typeof (value as { kind?: unknown } | null)?.kind === 'string' ? (value as { kind: string }).kind : 'unknown'
    perfCount(`wire.send.${kind}`); perfCount(`wire.send.${kind}.bytes`, bytes.length)
    requireNetwork(bytes.length > 0 && bytes.length <= APPLICATION_NETWORK_LIMITS.messageBytes &&
      this.#pendingBytes + bytes.length <= APPLICATION_NETWORK_LIMITS.queuedBytes, 'APPLICATION_NETWORK_BACKPRESSURE')
    this.#pending++; this.#pendingBytes += bytes.length
    const queued = timeout(this.#timeoutMs, 'APPLICATION_NETWORK_WRITE_TIMEOUT')
    const signal = AbortSignal.any([this.#signal, queued.signal])
    const task = this.#tail.then(async () => {
      signal.throwIfAborted(); authorize?.()
      requireNetwork(this.#outgoing < 0xffff_ffff, 'APPLICATION_NETWORK_SEQUENCE_EXHAUSTED')
      const id = ++this.#outgoing
      for (let offset = 0; offset < bytes.length; offset += APPLICATION_NETWORK_LIMITS.fragmentBytes) {
        signal.throwIfAborted(); this.#authorize(); authorize?.()
        const fragment = bytes.subarray(offset, offset + APPLICATION_NETWORK_LIMITS.fragmentBytes)
        const frame = encodeFragment(id, offset, bytes.length, fragment)
        await interruptible(this.#connection.send(frame, { signal }), signal)
        this.#sentBytes += frame.length
      }
    }).finally(() => { queued.cancel(); this.#pending--; this.#pendingBytes -= bytes.length })
    this.#tail = task.catch(() => undefined)
    return task
  }
  async *messages(): AsyncIterable<unknown> {
    let body: Uint8Array | null = null, offset = 0
    let assembly: ReturnType<typeof timeout> | undefined
    const iterator = this.#connection.frames(this.#signal)[Symbol.asyncIterator]()
    try {
      while (!this.#signal.aborted) {
        const signal = assembly === undefined ? this.#signal : AbortSignal.any([this.#signal, assembly.signal])
        const next = await interruptible(iterator.next(), signal)
        if (next.done) {
          requireNetwork(body === null, 'APPLICATION_NETWORK_TRUNCATED')
          return
        }
        const bytes = next.value
        requireNetwork(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= APPLICATION_NETWORK_LIMITS.fragmentBytes + 128,
          'APPLICATION_NETWORK_FRAME_LIMIT')
        this.#receivedBytes += bytes.length
        const { id, position, total, chunk } = decodeFragment(bytes)
        requireNetwork(Number.isSafeInteger(id) && id === this.#incoming + 1 && Number.isSafeInteger(position) && position === offset &&
          Number.isSafeInteger(total) && total > 0 && total <= APPLICATION_NETWORK_LIMITS.messageBytes &&
          chunk.length > 0 && chunk.length <= APPLICATION_NETWORK_LIMITS.fragmentBytes && offset + chunk.length <= total,
        'APPLICATION_NETWORK_FRAME_INVALID')
        if (body === null) { body = new Uint8Array(total); assembly = timeout(this.#timeoutMs, 'APPLICATION_NETWORK_READ_TIMEOUT') }
        requireNetwork(body.length === total, 'APPLICATION_NETWORK_FRAME_INVALID')
        body.set(chunk, offset); offset += chunk.length
        if (offset === total) {
          const complete = body; body = null; offset = 0; this.#incoming++
          assembly?.cancel(); assembly = undefined
          let message: unknown
          try { message = decodeWireValue(complete) } catch { throw networkError('APPLICATION_NETWORK_MESSAGE_INVALID') }
          perfCount('wire.recv'); perfCount('wire.recv.bytes', complete.length)
          yield message
        }
      }
    } finally {
      assembly?.cancel()
      // A noncooperative transport cannot hold shutdown open. Its late frames
      // remain fenced by the connection lifetime.
      void iterator.return?.().catch(() => undefined)
    }
  }
}

function memoryLane(maxBytes: number, maxFrames: number) {
  const queue: Uint8Array[] = [], waiters = new Set<() => void>()
  let bytes = 0, closed = false, reading = false
  const notify = (): void => { for (const wake of [...waiters]) wake() }
  return {
    push(frame: Uint8Array): boolean {
      requireNetwork(!closed, 'APPLICATION_NETWORK_CLOSED')
      if (queue.length >= maxFrames || bytes + frame.length > maxBytes) return false
      queue.push(frame.slice()); bytes += frame.length; notify(); return true
    },
    async wait(signal: AbortSignal): Promise<void> {
      signal.throwIfAborted()
      await new Promise<void>((resolve, reject) => {
        const done = (): void => { waiters.delete(wake); signal.removeEventListener('abort', abort) }
        const wake = (): void => { done(); resolve() }, abort = (): void => { done(); reject(signal.reason) }
        waiters.add(wake); signal.addEventListener('abort', abort, { once: true })
      })
    },
    async *frames(signal: AbortSignal): AsyncIterable<Uint8Array> {
      requireNetwork(!reading, 'APPLICATION_NETWORK_READER_EXISTS'); reading = true
      while (!closed && !signal.aborted) {
        const frame = queue.shift()
        if (frame !== undefined) { bytes -= frame.length; notify(); yield frame }
        else await this.wait(signal)
      }
    },
    close(): void { closed = true; queue.length = 0; bytes = 0; notify() },
  }
}
/** Test/embedded transport only; sessions still execute the actual authenticated wire. */
export function createFramedPeerConnectionPair(): readonly [FramedPeerConnection, FramedPeerConnection] {
  const controller = new AbortController(), reliable = [memoryLane(4 * 1024 * 1024, 64), memoryLane(4 * 1024 * 1024, 64)] as const
  const live = [memoryLane(128 * 1024, 8), memoryLane(128 * 1024, 8)] as const
  const close = async (): Promise<void> => {
    if (controller.signal.aborted) return
    controller.abort(networkError('APPLICATION_NETWORK_CLOSED'))
    for (const lane of [...reliable, ...live]) lane.close()
  }
  const side = (index: 0 | 1): FramedPeerConnection => {
    const opposite = index === 0 ? 1 : 0
    return { signal: controller.signal, close,
      async send(frame, options = {}) {
        const signal = options.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, options.signal])
        while (true) { signal.throwIfAborted(); if (reliable[opposite].push(frame)) return; await reliable[opposite].wait(signal) }
      },
      frames: signal => reliable[index].frames(signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal])),
      live: { signal: controller.signal, close,
        async trySend(frame, options = {}) { controller.signal.throwIfAborted(); options.signal?.throwIfAborted(); return live[opposite].push(frame) },
        frames: signal => live[index].frames(signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal])),
      },
    }
  }
  return [side(0), side(1)]
}

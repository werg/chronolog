import { PEER_LIVE_MESSAGE_LIMITS, PEER_MESSAGE_LIMITS } from '@chronolog/records'
import { awaitOwnedTask } from './lifetime.js'

export type Lane = 'reliable' | 'live'
type Wire = Record<string, unknown>
interface Entry { readonly sequence: number; readonly bytes: Uint8Array }
const bounds = (lane: Lane) => lane === 'reliable'
  ? { frame: PEER_MESSAGE_LIMITS.frameBytes, bytes: PEER_MESSAGE_LIMITS.queueBytes, count: PEER_MESSAGE_LIMITS.queueFrames }
  : { frame: PEER_LIVE_MESSAGE_LIMITS.frameBytes, bytes: PEER_LIVE_MESSAGE_LIMITS.bufferedBytes, count: PEER_LIVE_MESSAGE_LIMITS.queueFrames }

/** Bounded opaque-frame bridge. It never interprets a peer record or owns its keys. */
export function workerRtcLanes(post: (value: Wire) => void, lifetime: AbortSignal, fail: (error: unknown) => void,
  timeoutMs: number, consume?: (lane: Lane, bytes: Uint8Array) => Promise<boolean>) {
  const lanes = (['reliable', 'live'] as const).map(lane => {
    const limit = bounds(lane), queue: Entry[] = []
    const pending = new Map<number, { bytes: number; resolve: (accepted: boolean) => void; reject: (error: unknown) => void;
      timer: ReturnType<typeof setTimeout> }>()
    let sequence = 0, received = 0, credited = 0, queuedBytes = 0, outgoingBytes = 0, reading = false, pumping = false
    let wake: (() => void) | undefined
    const requireOpen = () => lifetime.throwIfAborted()
    const validBytes = (bytes: unknown): bytes is Uint8Array => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= limit.frame
    const abort = () => {
      queue.length = 0; queuedBytes = 0
      for (const held of pending.values()) { clearTimeout(held.timer); held.reject(lifetime.reason) }
      pending.clear(); outgoingBytes = 0; wake?.(); wake = undefined
    }
    lifetime.addEventListener('abort', abort, { once: true })
    const acknowledge = (entry: Entry, accepted: boolean) => {
      requireOpen(); queuedBytes -= entry.bytes.length; credited = entry.sequence
      post({ action: 'ack', lane, sequence: entry.sequence, accepted })
    }
    const pump = async () => {
      if (pumping || consume === undefined) return
      pumping = true
      try {
        while (queue.length && !lifetime.aborted) {
          const entry = queue[0]!
          const accepted = await awaitOwnedTask(lifetime, () => consume(lane, entry.bytes))
          requireOpen(); queue.shift(); acknowledge(entry, accepted)
        }
      } catch (error) { if (!lifetime.aborted) fail(error) }
      finally { pumping = false }
    }
    const send = async (bytes: Uint8Array, signal?: AbortSignal): Promise<boolean> => {
      signal?.throwIfAborted(); requireOpen()
      if (!validBytes(bytes)) throw new Error('APPLICATION_WORKER_FRAME_INVALID')
      if (pending.size >= limit.count || outgoingBytes + bytes.length > limit.bytes) {
        if (lane === 'live') return false
        throw new Error('APPLICATION_WORKER_SEND_LIMIT')
      }
      if (!Number.isSafeInteger(sequence + 1)) throw new Error('APPLICATION_WORKER_SEQUENCE_EXHAUSTED')
      const id = ++sequence
      const accepted = new Promise<boolean>((resolve, reject) => {
        const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_FRAME_TIMEOUT')), timeoutMs)
        pending.set(id, { bytes: bytes.length, resolve, reject, timer }); outgoingBytes += bytes.length
        try { post({ action: 'frame', lane, sequence: id, bytes: bytes.slice() }) }
        catch (error) { fail(error) }
      })
      // A cancelled dispatched send cannot be retracted. Fence the whole route,
      // settle its credits, and never dispatch a queued retry after cancellation.
      const owned = signal === undefined ? lifetime : AbortSignal.any([signal, lifetime])
      try { return await awaitOwnedTask(owned, () => accepted) }
      catch (error) { if (!lifetime.aborted) fail(error); throw error }
    }
    const frames = (signal?: AbortSignal): AsyncIterable<Uint8Array> => ({ [Symbol.asyncIterator]() {
      const controller = new AbortController(), owned = AbortSignal.any([lifetime, controller.signal, ...[signal].filter((s): s is AbortSignal => s !== undefined)])
      const cancelled = () => { wake?.(); wake = undefined }
      async function* read() {
        if (reading || consume !== undefined) throw new Error('APPLICATION_WORKER_READER_EXISTS')
        reading = true; owned.addEventListener('abort', cancelled, { once: true })
        try {
          for (;;) {
            owned.throwIfAborted()
            const entry = queue.shift()
            if (entry === undefined) { await new Promise<void>(resolve => { wake = resolve }); continue }
            yield entry.bytes
            // Count the yielded frame until the reader advances. No premature credit.
            acknowledge(entry, true)
          }
        } finally {
          reading = false; owned.removeEventListener('abort', cancelled)
          if (!lifetime.aborted) fail(new Error('APPLICATION_WORKER_READER_CLOSED'))
        }
      }
      const iterator = read()
      return { next: () => iterator.next(), async return() { controller.abort(); return iterator.return() },
        async throw(error: unknown) { controller.abort(error); return iterator.throw(error) } }
    } })
    return { lane, send, frames, receive(value: Wire) {
      requireOpen()
      if (!Number.isSafeInteger(value.sequence) || Number(value.sequence) < 1) throw new Error('APPLICATION_WORKER_SEQUENCE_INVALID')
      if (value.action === 'ack') {
        const first = pending.entries().next().value
        if (first === undefined || first[0] !== value.sequence || typeof value.accepted !== 'boolean' || lane === 'reliable' && !value.accepted)
          throw new Error('APPLICATION_WORKER_CREDIT_INVALID')
        pending.delete(first[0]); clearTimeout(first[1].timer); outgoingBytes -= first[1].bytes; first[1].resolve(value.accepted)
      } else {
        if (value.sequence !== received + 1 || !validBytes(value.bytes)) throw new Error('APPLICATION_WORKER_FRAME_INVALID')
        // A yielded frame still consumes a credit, even though it left the array.
        if (received - credited >= limit.count || queuedBytes + value.bytes.length > limit.bytes) throw new Error('APPLICATION_WORKER_RECEIVE_LIMIT')
        received++; queuedBytes += value.bytes.length
        queue.push({ sequence: received, bytes: value.bytes.slice() }); wake?.(); wake = undefined
        void pump()
      }
    } }
  })
  return { reliable: lanes[0]!, live: lanes[1]!, receive(value: Wire) {
    if (value.lane !== 'reliable' && value.lane !== 'live') throw new Error('APPLICATION_WORKER_LANE_INVALID')
    if (value.action !== 'frame' && value.action !== 'ack') throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    const expected = value.action === 'frame' ? ['action', 'lane', 'sequence', 'bytes'] : ['action', 'lane', 'sequence', 'accepted']
    if (Object.keys(value).some(key => !expected.includes(key))) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    lanes[value.lane === 'reliable' ? 0 : 1]!.receive(value)
  } }
}

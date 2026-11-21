import { afterEach, expect, it, vi } from 'vitest'
import { PEER_LIVE_MESSAGE_LIMITS, PEER_MESSAGE_LIMITS } from '@chronolog/records'
import { workerRtcLanes } from './worker-transport-lanes.js'
const clean: Array<() => void> = []
afterEach(() => { for (const close of clean.splice(0)) close(); vi.useRealTimers() })
function fixture(consume?: Parameters<typeof workerRtcLanes>[4]) {
  const lifetime = new AbortController(), posted: Array<Record<string, unknown>> = []
  const fail = vi.fn((error: unknown) => lifetime.abort(error))
  clean.push(() => lifetime.abort(Error('test close')))
  return { lifetime, posted, fail, lanes: workerRtcLanes(value => posted.push(value), lifetime.signal, fail, 1000, consume) }
}
it('bounds outgoing reliable frames by count and bytes before cloning; sends no idle messages or timers', async () => {
  vi.useFakeTimers()
  const a = fixture(); expect(a.posted).toHaveLength(0); expect(vi.getTimerCount()).toBe(0)
  const pending = Array.from({ length: PEER_MESSAGE_LIMITS.queueFrames }, () => a.lanes.reliable.send(new Uint8Array([1])).catch(() => false))
  await expect(a.lanes.reliable.send(new Uint8Array([2]))).rejects.toThrow('APPLICATION_WORKER_SEND_LIMIT')
  expect(a.posted).toHaveLength(PEER_MESSAGE_LIMITS.queueFrames)
  a.lifetime.abort(); await Promise.all(pending); expect(vi.getTimerCount()).toBe(0)
  const b = fixture(), frames = []
  const count = Math.floor(PEER_MESSAGE_LIMITS.queueBytes / PEER_MESSAGE_LIMITS.frameBytes)
  for (let i = 0; i < count; i++) frames.push(b.lanes.reliable.send(new Uint8Array(PEER_MESSAGE_LIMITS.frameBytes)).catch(() => false))
  await expect(b.lanes.reliable.send(new Uint8Array(PEER_MESSAGE_LIMITS.frameBytes))).rejects.toThrow('APPLICATION_WORKER_SEND_LIMIT')
  b.lifetime.abort(); await Promise.all(frames)
})
it('live pressure refuses before dispatch without a retry and preserves the physical refusal ACK', async () => {
  const a = fixture(), pending: Array<Promise<boolean>> = []
  const count = Math.floor(PEER_LIVE_MESSAGE_LIMITS.bufferedBytes / PEER_LIVE_MESSAGE_LIMITS.frameBytes)
  for (let i = 0; i < count; i++) pending.push(a.lanes.live.send(new Uint8Array(PEER_LIVE_MESSAGE_LIMITS.frameBytes)))
  expect(await a.lanes.live.send(new Uint8Array(PEER_LIVE_MESSAGE_LIMITS.frameBytes))).toBe(false)
  expect(a.posted).toHaveLength(count)
  for (let i = 1; i <= count; i++) a.lanes.receive({ action: 'ack', lane: 'live', sequence: i, accepted: false })
  expect(await Promise.all(pending)).toEqual(Array.from({ length: count }, () => false))
  expect(a.posted).toHaveLength(count)
})
it('receive credit includes a held yielded frame; iterator return unblocks a pending read', async () => {
  const a = fixture(), reader = a.lanes.reliable.frames()[Symbol.asyncIterator]()
  const first = reader.next()
  for (let i = 1; i <= PEER_MESSAGE_LIMITS.queueFrames; i++) a.lanes.receive({ action: 'frame', lane: 'reliable', sequence: i, bytes: new Uint8Array([i]) })
  expect((await first).value).toEqual(new Uint8Array([1])); expect(a.posted).toHaveLength(0)
  expect(() => a.lanes.receive({ action: 'frame', lane: 'reliable', sequence: PEER_MESSAGE_LIMITS.queueFrames + 1, bytes: new Uint8Array([0]) })).toThrow('APPLICATION_WORKER_RECEIVE_LIMIT')
  await reader.next(); expect(a.posted).toEqual([{ action: 'ack', lane: 'reliable', sequence: 1, accepted: true }])
  await reader.return!(); expect(a.lifetime.signal.aborted).toBe(true)
  const b = fixture(), blocked = b.lanes.reliable.frames()[Symbol.asyncIterator](), read = blocked.next()
  const rejected = expect(read).rejects.toThrow()
  await blocked.return!(); await rejected; expect(b.lifetime.signal.aborted).toBe(true)
})
it('dispatch ACKs wait for the raw transport and cancellation suppresses late callbacks', async () => {
  let release!: (accepted: boolean) => void
  const a = fixture(() => new Promise(resolve => { release = resolve }))
  a.lanes.receive({ action: 'frame', lane: 'live', sequence: 1, bytes: new Uint8Array([9]) })
  expect(a.posted).toHaveLength(0)
  release(false); await vi.waitFor(() => expect(a.posted).toEqual([{ action: 'ack', lane: 'live', sequence: 1, accepted: false }]))
  a.lanes.receive({ action: 'frame', lane: 'live', sequence: 2, bytes: new Uint8Array([8]) })
  a.lifetime.abort(); release(true); await Promise.resolve(); expect(a.posted).toHaveLength(1)
})
it('pending operation deadlines and cancellation retire credits; malformed frames and receipts fail closed', async () => {
  vi.useFakeTimers()
  const a = fixture(), pending = a.lanes.reliable.send(new Uint8Array([1]))
  const rejected = expect(pending).rejects.toThrow('APPLICATION_WORKER_FRAME_TIMEOUT')
  await vi.advanceTimersByTimeAsync(1000); await rejected; expect(a.fail).toHaveBeenCalledOnce()
  const b = fixture(), abort = new AbortController(), sending = b.lanes.reliable.send(new Uint8Array([1]), abort.signal)
  const cancelled = expect(sending).rejects.toThrow('stop send'); abort.abort(Error('stop send')); await cancelled
  for (const value of [
    { action: 'ack', lane: 'reliable', sequence: 1, accepted: true },
    { action: 'frame', lane: 'reliable', sequence: 2, bytes: new Uint8Array([1]) },
    { action: 'frame', lane: 'live', sequence: 1, bytes: new Uint8Array(PEER_LIVE_MESSAGE_LIMITS.frameBytes + 1) },
    { action: 'frame', lane: 'reliable', sequence: 1, bytes: new Uint8Array([1]), secret: true },
  ]) expect(() => fixture().lanes.receive(value)).toThrow()
})

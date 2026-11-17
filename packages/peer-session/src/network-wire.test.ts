import { afterEach, describe, expect, it, vi } from 'vitest'
import { encodeCanonicalCbor } from '@chronolog/protocol'
import {
  APPLICATION_NETWORK_LIMITS as limits, ApplicationMessageWire, createFramedPeerConnectionPair,
  type FramedPeerConnection,
} from './network-wire.js'

afterEach(() => { vi.useRealTimers() })
const never = <T>(): Promise<T> => new Promise(() => {})
function source(frames: readonly Uint8Array[], stalled = false): FramedPeerConnection {
  const controller = new AbortController()
  return { signal: controller.signal, send: async () => {}, close: async () => { controller.abort() },
    frames: () => ({ [Symbol.asyncIterator]() {
      let index = 0
      return { next: async () => index < frames.length ? { done: false as const, value: frames[index++]! }
        : stalled ? never<IteratorResult<Uint8Array>>() : { done: true as const, value: undefined },
      return: () => never<IteratorResult<Uint8Array>>() }
    } }),
  }
}
const fragment = (id: number, offset: number, total: number, chunk: Uint8Array) =>
  encodeCanonicalCbor([1n, BigInt(id), BigInt(offset), BigInt(total), chunk])

describe('bounded peer application wire', () => {
  it('fragments a detached message and preserves exact contents across byte lanes', async () => {
    const [a, b] = createFramedPeerConnectionPair(), sizes: number[] = []
    const wrapped = { ...a, async send(frame: Uint8Array, options?: { signal?: AbortSignal }) {
      sizes.push(frame.length); await a.send(frame, options)
    } }
    const out = new ApplicationMessageWire(wrapped, a.signal, 1000), input = new ApplicationMessageWire(b, b.signal, 1000)
    const value = { kind: 'detached', text: 'x'.repeat(3 * limits.fragmentBytes) }, iterator = input.messages()[Symbol.asyncIterator]()
    const received = iterator.next(), sent = out.send(value)
    value.text = 'changed after dispatch'
    expect((await received).value).toEqual({ kind: 'detached', text: 'x'.repeat(3 * limits.fragmentBytes) })
    await sent
    expect(sizes.length).toBeGreaterThan(3)
    expect(Math.max(...sizes)).toBeLessThanOrEqual(limits.fragmentBytes + 128)
    await a.close(); await iterator.return?.()
  })

  it.each([
    ['skipped transfer', fragment(2, 0, 1, new Uint8Array([1]))],
    ['offset gap', fragment(1, 1, 2, new Uint8Array([1]))],
    ['oversized body', fragment(1, 0, limits.messageBytes + 1, new Uint8Array([1]))],
    ['empty fragment', fragment(1, 0, 1, new Uint8Array())],
  ])('rejects %s before allocating or yielding a message', async (_name, frame) => {
    const connection = source([frame]), wire = new ApplicationMessageWire(connection, connection.signal, 20)
    await expect(wire.messages()[Symbol.asyncIterator]().next()).rejects.toThrow('APPLICATION_NETWORK_FRAME_INVALID')
  })

  it('rejects changed assembly lengths and a truncated message', async () => {
    const changed = source([fragment(1, 0, 3, new Uint8Array([1])), fragment(1, 1, 4, new Uint8Array([2]))])
    await expect(new ApplicationMessageWire(changed, changed.signal, 20).messages()[Symbol.asyncIterator]().next())
      .rejects.toThrow('APPLICATION_NETWORK_FRAME_INVALID')
    const truncated = source([fragment(1, 0, 3, new Uint8Array([1]))])
    await expect(new ApplicationMessageWire(truncated, truncated.signal, 20).messages()[Symbol.asyncIterator]().next())
      .rejects.toThrow('APPLICATION_NETWORK_TRUNCATED')
  })

  it('expires an incomplete assembly even when the transport ignores read cancellation', async () => {
    vi.useFakeTimers()
    const connection = source([fragment(1, 0, 3, new Uint8Array([1]))], true)
    const received = new ApplicationMessageWire(connection, connection.signal, 20).messages()[Symbol.asyncIterator]().next()
    const checked = expect(received).rejects.toThrow('APPLICATION_NETWORK_READ_TIMEOUT')
    await vi.advanceTimersByTimeAsync(21); await checked
  })

  it('bounds queued writes and expires a blocked transport without awaiting its cancellation', async () => {
    vi.useFakeTimers()
    const connection = { ...source([]), send: () => never<void>() }
    const wire = new ApplicationMessageWire(connection, connection.signal, 20)
    const writes = Array.from({ length: limits.queuedMessages }, (_, index) => wire.send({ index }))
    const checked = Promise.all(writes.map(write => expect(write).rejects.toThrow('APPLICATION_NETWORK_WRITE_TIMEOUT')))
    expect(() => wire.send({ overflow: true })).toThrow('APPLICATION_NETWORK_BACKPRESSURE')
    await vi.advanceTimersByTimeAsync(21); await checked
  })

  it('rechecks a queued message before dispatch without breaking a healthy byte stream', async () => {
    const [a, b] = createFramedPeerConnectionPair()
    let release!: () => void, blocked = true, allowed = true
    const gate = new Promise<void>(resolve => { release = resolve })
    const connection = { ...a, async send(bytes: Uint8Array, options?: { signal?: AbortSignal }) {
      if (blocked) { blocked = false; await gate }
      await a.send(bytes, options)
    } }
    const wire = new ApplicationMessageWire(connection, connection.signal, 1000)
    const received = new ApplicationMessageWire(b, b.signal, 1000).messages()[Symbol.asyncIterator]()
    const first = wire.send({ first: true })
    const second = wire.send({ forbidden: true }, () => { if (!allowed) throw new Error('writer revoked') })
    const checked = expect(second).rejects.toThrow('writer revoked')
    allowed = false; release()
    expect((await received.next()).value).toEqual({ first: true }); await first; await checked
    const third = wire.send({ third: true })
    expect((await received.next()).value).toEqual({ third: true }); await third
    expect(a.signal.aborted).toBe(false)
    await a.close(); await received.return?.()
  })

  it('aborts an idle noncooperative iterator and drops live congestion before queueing', async () => {
    const controller = new AbortController(), connection = source([], true)
    const received = new ApplicationMessageWire(connection, controller.signal, 20).messages()[Symbol.asyncIterator]().next()
    const checked = expect(received).rejects.toThrow('owner closed')
    controller.abort(new Error('owner closed')); await checked
    const [a, b] = createFramedPeerConnectionPair()
    for (let index = 0; index < 8; index++) expect(await a.live!.trySend(new Uint8Array([index]))).toBe(true)
    expect(await a.live!.trySend(new Uint8Array([99]))).toBe(false)
    const iterator = b.live!.frames()[Symbol.asyncIterator]()
    for (let index = 0; index < 8; index++) expect((await iterator.next()).value).toEqual(new Uint8Array([index]))
    await a.close(); await iterator.return?.()
    expect(a.signal.aborted).toBe(true); expect(b.signal.aborted).toBe(true)
  })
})

import { describe, expect, it } from 'vitest'
import { PEER_MESSAGE_LIMITS, PEER_LIVE_MESSAGE_LIMITS } from '@chronolog/records'
import { frameWebSocketPeerConnection, type PeerWebSocket, type WebSocketPeerOptions } from './index.js'

class Socket extends EventTarget implements PeerWebSocket {
  readyState = 1
  bufferedAmount = 0
  binaryType = 'blob'
  other!: Socket
  readonly sent: Uint8Array[] = []
  send(input: ArrayBuffer): void {
    if (this.readyState !== 1) throw new Error('socket closed')
    const data = input.slice(0)
    this.sent.push(new Uint8Array(data))
    queueMicrotask(() => {
      if (this.other.readyState === 1) this.other.dispatchEvent(new MessageEvent('message', { data }))
    })
  }
  close(): void {
    if (this.readyState === 3) return
    this.readyState = 3; this.dispatchEvent(new Event('close')); this.other.close()
  }
}
function sockets(): readonly [Socket, Socket] {
  const a = new Socket(), b = new Socket(); a.other = b; b.other = a
  return [a, b]
}
function admissionGate() {
  let resolve!: () => void
  const promise = new Promise<void>(ready => { resolve = ready })
  return { promise, resolve }
}
function pair(options: WebSocketPeerOptions = {}) {
  const [ar, br] = sockets(), [al, bl] = sockets()
  const a = frameWebSocketPeerConnection({ reliable: ar, live: al }, options)
  const b = frameWebSocketPeerConnection({ reliable: br, live: bl }, options)
  return { a, b, ar, br, al, bl, close: async () => { await Promise.all([a.close(), b.close()]) } }
}

describe('WebSocket byte adapter using shared message framing', () => {
  it('installs readers before admission and uses identical bounded packets in both directions', async () => {
    const admission = admissionGate(), value = pair({ ready: admission.promise })
    try {
      await Promise.resolve()
      expect(value.ar.sent).toHaveLength(0)
      admission.resolve()
      await Promise.all([value.a.ready, value.b.ready])
      const frame = new Uint8Array(500_000).fill(47), reverse = new Uint8Array([4, 5, 6])
      const left = value.a.frames()[Symbol.asyncIterator](), right = value.b.frames()[Symbol.asyncIterator]()
      const received = right.next(), returned = left.next()
      await Promise.all([value.a.send(frame), value.b.send(reverse)])
      expect((await received).value).toEqual(frame)
      expect((await returned).value).toEqual(reverse)
      expect(value.ar.sent.every(packet => packet.length <= PEER_MESSAGE_LIMITS.packetBytes)).toBe(true)
      expect(value.ar.binaryType).toBe('arraybuffer')
      expect(value.a.stats.sentBytes).toBe(frame.length)
    } finally { await value.close() }
  })

  it('keeps live dispatch independent while the reliable WebSocket buffer drains', async () => {
    const value = pair()
    try {
      await Promise.all([value.a.ready, value.b.ready])
      value.ar.bufferedAmount = PEER_MESSAGE_LIMITS.bufferedBytes
      let dispatched = false
      const sending = value.a.send(new Uint8Array([8])).then(() => { dispatched = true })
      const live = value.b.live.frames()[Symbol.asyncIterator]()
      await expect(value.a.live.trySend(new Uint8Array([9]))).resolves.toBe(true)
      expect((await live.next()).value).toEqual(new Uint8Array([9]))
      expect(dispatched).toBe(false)
      value.ar.bufferedAmount = 0
      await sending
      expect(dispatched).toBe(true)
      const frames = value.b.frames()[Symbol.asyncIterator]()
      expect((await frames.next()).value).toEqual(new Uint8Array([8]))
    } finally { await value.close() }
  })

  it('refuses congested live dispatch without a deferred send or retry', async () => {
    const value = pair()
    try {
      await Promise.all([value.a.ready, value.b.ready])
      value.al.bufferedAmount = PEER_LIVE_MESSAGE_LIMITS.bufferedBytes
      await expect(value.a.live.trySend(new Uint8Array([9]))).resolves.toBe(false)
      value.al.bufferedAmount = 0
      await new Promise(resolve => setTimeout(resolve, 20))
      expect(value.al.sent).toHaveLength(0)
      await expect(value.a.live.trySend(new Uint8Array([10]))).resolves.toBe(true)
      expect(value.al.sent).toHaveLength(1)
    } finally { await value.close() }
  })

  it('cancels reliable pre-dispatch work without consuming peer credit or closing the session', async () => {
    const value = pair(), cancellation = new AbortController()
    try {
      await Promise.all([value.a.ready, value.b.ready])
      value.ar.bufferedAmount = PEER_MESSAGE_LIMITS.bufferedBytes
      const sending = value.a.send(new Uint8Array([1]), { signal: cancellation.signal })
      const rejected = expect(sending).rejects.toThrow('cancel queued frame')
      await Promise.resolve(); cancellation.abort(new Error('cancel queued frame'))
      await rejected
      expect(value.a.signal.aborted).toBe(false)
      expect(value.ar.sent).toHaveLength(1) // Only the framing hello.
      value.ar.bufferedAmount = 0
      await value.a.send(new Uint8Array([2]))
      const frames = value.b.frames()[Symbol.asyncIterator]()
      expect((await frames.next()).value).toEqual(new Uint8Array([2]))
    } finally { await value.close() }
  })

  it('closes both lanes and wakes a blocked reader when either physical socket ends', async () => {
    const value = pair()
    try {
      await Promise.all([value.a.ready, value.b.ready])
      const frames = value.a.frames()[Symbol.asyncIterator](), read = frames.next()
      value.al.close()
      await read
      expect(value.a.signal.aborted).toBe(true)
      expect(value.a.signal.reason.message).toBe('PEER_WEBSOCKET_ENDED')
      expect([value.ar, value.br, value.al, value.bl].every(socket => socket.readyState === 3)).toBe(true)
    } finally { await value.close() }
  })

  it('rejects text frames and releases sockets when admission fails or is cancelled', async () => {
    const value = pair()
    await Promise.all([value.a.ready, value.b.ready])
    value.ar.dispatchEvent(new MessageEvent('message', { data: 'plaintext is not a peer packet' }))
    expect(value.a.signal.reason.message).toBe('PEER_WEBSOCKET_BINARY_REQUIRED')
    await value.close()

    const admission = admissionGate(), cancelled = pair({ ready: admission.promise })
    await cancelled.close(); admission.resolve(); await Promise.resolve()
    expect(cancelled.ar.sent).toHaveLength(0)

    const failed = pair({ ready: Promise.reject(new Error('relay admission denied')) })
    await expect(failed.a.ready).rejects.toThrow()
    expect(failed.a.signal.reason.message).toBe('relay admission denied')
    await failed.close()
  })

  it('bounds an unopened connection and treats the caller signal as its complete lifetime', async () => {
    const admission = admissionGate(), value = pair({ ready: admission.promise, openTimeoutMs: 10 })
    await expect(value.a.ready).rejects.toThrow()
    expect(value.a.signal.reason.message).toBe('PEER_WEBSOCKET_OPEN_TIMEOUT')
    await value.close()
    const cancellation = new AbortController(), opened = pair({ signal: cancellation.signal })
    await Promise.all([opened.a.ready, opened.b.ready])
    cancellation.abort(new Error('participation stopped'))
    expect(opened.a.signal.reason.message).toBe('participation stopped')
    expect(opened.ar.readyState).toBe(3)
    await opened.close()
  })
})

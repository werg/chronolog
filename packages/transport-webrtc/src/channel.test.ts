import { describe, expect, it, vi } from 'vitest'

import { frameRtcDataChannel, frameRtcPeerChannels, WEBRTC_LIMITS } from './channel.js'
import { frameRtcLiveChannel, WEBRTC_LIVE_LIMITS } from './live.js'
import type { RtcDataChannel } from './types.js'

class Channel extends EventTarget implements RtcDataChannel {
  readonly label = 'chronolog'
  readonly maxPacketLifeTime = null
  constructor(readonly ordered = true, readonly maxRetransmits: number | null = null) { super() }
  readyState = 'connecting'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  other!: Channel
  sent: Uint8Array[] = []
  send(data: ArrayBuffer): void {
    if (this.readyState !== 'open') throw new Error('closed channel')
    const copy = data.slice(0)
    this.sent.push(new Uint8Array(copy))
    queueMicrotask(() => { if (this.other.readyState !== 'closed') this.other.dispatchEvent(new MessageEvent('message', { data: copy })) })
  }
  close(): void {
    if (this.readyState === 'closed') return
    this.readyState = 'closed'; this.dispatchEvent(new Event('close'))
    this.other.close()
  }
}
function pair(options: Parameters<typeof frameRtcDataChannel>[1] = {}) {
  const left = new Channel(), right = new Channel()
  left.other = right; right.other = left
  const a = frameRtcDataChannel(left, options), b = frameRtcDataChannel(right, options)
  left.readyState = 'open'; right.readyState = 'open'
  left.dispatchEvent(new Event('open')); right.dispatchEvent(new Event('open'))
  return { a, b, left, right }
}

describe('reliable WebRTC frame transport', () => {
  it('bounds a silent HELLO only after local open, independently of slow ICE negotiation', async () => {
    vi.useFakeTimers()
    const left = new Channel(), right = new Channel()
    left.other = right; right.other = left
    const connection = frameRtcDataChannel(left, { helloTimeoutMs: 10 })
    const rejected = expect(connection.ready).rejects.toThrow('WEBRTC_HELLO_TIMEOUT')
    try {
      await vi.advanceTimersByTimeAsync(30_000)
      expect(left.readyState).toBe('connecting')
      left.readyState = 'open'; left.dispatchEvent(new Event('open'))
      await vi.advanceTimersByTimeAsync(9)
      expect(left.readyState).toBe('open')
      await vi.advanceTimersByTimeAsync(1)
      await rejected
      expect(left.readyState).toBe('closed')
    } finally { await connection.close(); vi.useRealTimers() }
  })

  it('waits for local HELLO before sending DATA when the remote HELLO precedes local open', async () => {
    const left = new Channel(), right = new Channel()
    left.other = right; right.other = left
    const a = frameRtcDataChannel(left), b = frameRtcDataChannel(right)
    const read = b.frames()[Symbol.asyncIterator]()
    let ready = false
    void a.ready.then(() => { ready = true }, () => undefined)
    const writing = a.send(new Uint8Array([9]))
    void writing.catch(() => undefined)
    try {
      right.readyState = 'open'; right.dispatchEvent(new Event('open'))
      await new Promise(resolve => setTimeout(resolve, 0))
      expect(a.stats.receivedPackets).toBe(1)
      expect(ready).toBe(false)
      expect(left.sent).toEqual([])
      left.readyState = 'open'; left.dispatchEvent(new Event('open'))
      await Promise.all([a.ready, b.ready, writing])
      expect(left.sent.map(packet => packet[3])).toEqual([1, 2])
      expect((await read.next()).value).toEqual(new Uint8Array([9]))
    } finally { await Promise.all([a.close(), b.close()]); await writing.catch(() => undefined); await read.return?.() }
  })

  it('fragments large signed frames without changing bytes and transfers both directions', async () => {
    const { a, b, left } = pair()
    const bytes = Uint8Array.from({ length: 700_003 }, (_, i) => i % 251)
    const ai = a.frames()[Symbol.asyncIterator](), bi = b.frames()[Symbol.asyncIterator]()
    try {
      await Promise.all([a.ready, b.ready])
      await Promise.all([a.send(bytes), b.send(new Uint8Array([1, 2, 3]))])
      expect((await bi.next()).value).toEqual(bytes)
      expect((await ai.next()).value).toEqual(new Uint8Array([1, 2, 3]))
      expect(left.sent.every(packet => packet.length <= WEBRTC_LIMITS.packetBytes)).toBe(true)
      expect(a.stats.sentBytes).toBe(bytes.length)
      expect(b.stats.receivedBytes).toBe(bytes.length)
    } finally { await Promise.all([a.close(), b.close()]); await Promise.all([ai.return?.(), bi.return?.()]) }
  })

  it('bounds both received bytes and frame count until the consumer advances', async () => {
    const { a, b } = pair({ maxFrameBytes: 32, queueBytes: 64, queueFrames: 2 })
    const read = b.frames()[Symbol.asyncIterator]()
    try {
      await a.send(new Uint8Array(32).fill(1)); await a.send(new Uint8Array(32).fill(2))
      let completed = false
      const waiting = a.send(new Uint8Array(32).fill(3)).then(() => { completed = true })
      await new Promise(resolve => setTimeout(resolve, 5))
      expect(completed).toBe(false)
      expect(b.stats.queuedReceiveBytes).toBe(64)
      expect(b.stats.queuedReceiveFrames).toBe(2)
      expect((await read.next()).value).toEqual(new Uint8Array(32).fill(1))
      expect(completed).toBe(false)
      expect((await read.next()).value).toEqual(new Uint8Array(32).fill(2))
      await waiting
      expect((await read.next()).value).toEqual(new Uint8Array(32).fill(3))
    } finally { await Promise.all([a.close(), b.close()]); await read.return?.() }
  })

  it('rejects excessive lengths before allocation and fails pending sends on close', async () => {
    const { a, b, left } = pair({ maxFrameBytes: 32, queueBytes: 32, queueFrames: 1 })
    try {
      await a.ready
      await expect(a.send(new Uint8Array(33))).rejects.toThrow('WEBRTC_FRAME_TOO_LARGE')
      await a.send(new Uint8Array(32))
      const waiting = a.send(new Uint8Array(32))
      const rejected = expect(waiting).rejects.toThrow('WEBRTC_CONNECTION_CLOSED')
      await a.close(); await rejected
      expect(left.readyState).toBe('closed')
    } finally { await b.close() }
  })

  it('rejects invalid receive credit and partial frames', async () => {
    const { a, b, left, right } = pair()
    try {
      await a.ready
      const packet = new Uint8Array(16); packet.set([0x43, 0x52, 1, 3])
      new DataView(packet.buffer).setUint32(4, 1); new DataView(packet.buffer).setUint32(8, 1)
      right.dispatchEvent(new MessageEvent('message', { data: packet.buffer }))
      await expect(b.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('WEBRTC_CREDIT_INVALID')
      expect(left.readyState).toBe('closed')
    } finally { await Promise.all([a.close(), b.close()]) }
  })

  it('does not accept an unreliable data channel', () => {
    const channel = new Channel()
    Object.defineProperty(channel, 'maxRetransmits', { value: 0 })
    expect(() => frameRtcDataChannel(channel)).toThrow('WEBRTC_RELIABLE_ORDERED_REQUIRED')
  })
})


describe('independent live WebRTC lane', () => {
  function channels(ordered: boolean, retransmits: number | null) {
    const left = new Channel(ordered, retransmits), right = new Channel(ordered, retransmits)
    left.other = right; right.other = left
    return { left, right, open() {
      left.readyState = right.readyState = 'open'
      left.dispatchEvent(new Event('open')); right.dispatchEvent(new Event('open'))
    } }
  }

  it('delivers live datagrams while reliable history has exhausted receiver credit', async () => {
    const history = channels(true, null), live = channels(false, 0)
    const options = { maxFrameBytes: 32, queueBytes: 32, queueFrames: 1 }
    const a = frameRtcPeerChannels({ reliable: history.left, live: live.left }, options)
    const b = frameRtcPeerChannels({ reliable: history.right, live: live.right }, options)
    const received = b.live.frames()[Symbol.asyncIterator]()
    history.open(); live.open()
    let completed = false
    let waiting: Promise<void> | undefined
    try {
      await Promise.all([a.ready, b.ready])
      await a.send(new Uint8Array(32).fill(1))
      waiting = a.send(new Uint8Array(32).fill(2)).then(() => { completed = true })
      void waiting.catch(() => undefined)
      await a.live.send(new Uint8Array([7]))
      expect((await received.next()).value).toEqual(new Uint8Array([7]))
      expect(completed).toBe(false)
      expect(history.left.sent.filter(packet => packet[3] === 2)).toHaveLength(1)
      expect(live.left.sent).toEqual([new Uint8Array([7])])
    } finally { await Promise.all([a.close(), b.close()]); await waiting?.catch(() => undefined); await received.return?.() }
  })

  it('never queues a cancelled, disconnected or congested live send', async () => {
    const source = channels(false, 0), a = frameRtcLiveChannel(source.left), b = frameRtcLiveChannel(source.right)
    try {
      await expect(a.send(new Uint8Array([1]))).rejects.toThrow('WEBRTC_LIVE_NOT_OPEN')
      source.open()
      const controller = new AbortController(); controller.abort(new Error('preview expired'))
      await expect(a.send(new Uint8Array([2]), { signal: controller.signal })).rejects.toThrow('preview expired')
      source.left.bufferedAmount = WEBRTC_LIVE_LIMITS.bufferedBytes
      await expect(a.send(new Uint8Array([3]))).rejects.toThrow('PEER_FRAME_BACKPRESSURE')
      source.left.bufferedAmount = 0
      await a.send(new Uint8Array([4]))
      expect(source.left.sent).toEqual([new Uint8Array([4])])
    } finally { await Promise.all([a.close(), b.close()]) }
  })

  it('bounds a slow live consumer and drops its oldest pending datagrams without a retry queue', async () => {
    const source = channels(false, 0), a = frameRtcLiveChannel(source.left), b = frameRtcLiveChannel(source.right)
    source.open()
    const received = b.frames()[Symbol.asyncIterator]()
    try {
      for (let index = 0; index <= WEBRTC_LIVE_LIMITS.queueFrames; index++) await a.send(new Uint8Array([index]))
      expect(b.stats.queuedReceiveFrames).toBe(WEBRTC_LIVE_LIMITS.queueFrames)
      expect(b.stats.droppedPackets).toBe(1)
      expect((await received.next()).value).toEqual(new Uint8Array([1]))
      await expect(a.send(new Uint8Array(WEBRTC_LIVE_LIMITS.frameBytes + 1))).rejects.toThrow('WEBRTC_LIVE_FRAME_TOO_LARGE')
    } finally { await Promise.all([a.close(), b.close()]); await received.return?.() }
  })

  it('ends an idle pending read when its iterator is returned', async () => {
    const source = channels(false, 0), a = frameRtcLiveChannel(source.left), b = frameRtcLiveChannel(source.right)
    source.open()
    try {
      const unused = b.frames()[Symbol.asyncIterator]()
      await unused.return?.()
      expect(b.signal.aborted).toBe(false)
      const iterator = b.frames()[Symbol.asyncIterator](), pending = iterator.next()
      expect((await iterator.return?.())?.done).toBe(true)
      expect((await pending).done).toBe(true)
      expect(b.signal.aborted).toBe(true)
      expect(a.signal.aborted).toBe(true)
      expect(b.stats.queuedReceiveFrames).toBe(0)
    } finally { await Promise.all([a.close(), b.close()]) }
  })

  it('rejects a malformed live frame and closes the shared connection lifetime', async () => {
    const history = channels(true, null), live = channels(false, 0)
    const a = frameRtcPeerChannels({ reliable: history.left, live: live.left })
    const b = frameRtcPeerChannels({ reliable: history.right, live: live.right })
    history.open(); live.open()
    try {
      await Promise.all([a.ready, b.ready])
      live.right.dispatchEvent(new MessageEvent('message', { data: new ArrayBuffer(WEBRTC_LIVE_LIMITS.frameBytes + 1) }))
      expect(b.signal.aborted).toBe(true)
      expect(history.right.readyState).toBe('closed')
    } finally { await Promise.all([a.close(), b.close()]) }
  })
})

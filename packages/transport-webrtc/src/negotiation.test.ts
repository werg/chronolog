import { afterEach, describe, expect, it, vi } from 'vitest'

import { WEBRTC_LIMITS } from './channel.js'
import { negotiateWebRtc, openWebRtcConnection } from './negotiation.js'
import type { PeerDescription, PeerSignaling, RtcDataChannel, RtcPeerConnection, WebRtcChannels } from './types.js'

class Channel extends EventTarget implements RtcDataChannel {
  readonly maxPacketLifeTime = null
  constructor(readonly label = 'chronolog.reliable', readonly ordered = true, readonly maxRetransmits: number | null = null) { super() }
  readyState = 'open'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  send(): void { /* Deliberately withhold the remote framing HELLO. */ }
  close(): void { this.readyState = 'closed'; this.dispatchEvent(new Event('close')) }
}
class Peer extends EventTarget implements RtcPeerConnection {
  readonly channel = new Channel()
  readonly liveChannel = new Channel('chronolog.live', false, 0)
  readonly created: Array<{ label: string; options: Parameters<RtcPeerConnection['createDataChannel']>[1] }> = []
  localDescription: { type: string; sdp: string } | null = null
  iceGatheringState = 'complete'
  connectionState = 'connected'
  closed = false
  createDataChannel(label: string, options: Parameters<RtcPeerConnection['createDataChannel']>[1]): RtcDataChannel {
    this.created.push({ label, options }); return options.id === 0 ? this.channel : this.liveChannel
  }
  createOffer(): Promise<RTCSessionDescriptionInit> { return Promise.resolve({ type: 'offer', sdp: 'fixture-offer' }) }
  createAnswer(): Promise<RTCSessionDescriptionInit> { return Promise.resolve({ type: 'answer', sdp: 'fixture-answer' }) }
  setLocalDescription(value: RTCSessionDescriptionInit): Promise<void> { this.localDescription = { type: value.type, sdp: value.sdp! }; return Promise.resolve() }
  setRemoteDescription(): Promise<void> { return Promise.resolve() }
  close(): void { this.closed = true; this.channel.close(); this.liveChannel.close() }
}
function fixture() {
  const peer = new Peer()
  let closed = false
  const signaling: PeerSignaling = { messages: { async *[Symbol.asyncIterator]() { yield { type: 'answer', sdp: 'fixture-answer' } } },
    async send() {}, close() { closed = true } }
  return { peer, signaling, closed: () => closed, options: { role: 'offerer' as const, signaling, createPeerConnection: () => peer } }
}

afterEach(() => { vi.useRealTimers() })

describe('WebRTC session lifecycle', () => {
  it('hands off both independently configured lanes together before SDP negotiation', async () => {
    const value = fixture()
    let handed = false
    const session = await negotiateWebRtc({ ...value.options, onDataChannels(channels) {
      expect(value.peer.localDescription).toBeNull()
      expect(channels).toEqual({ reliable: value.peer.channel, live: value.peer.liveChannel })
      handed = true
    } })
    try {
      expect(handed).toBe(true)
      expect(value.peer.created).toEqual([
        { label: 'chronolog.reliable', options: { negotiated: true, id: 0, ordered: true, protocol: 'chronolog.peer.v2' } },
        { label: 'chronolog.live', options: { negotiated: true, id: 1, ordered: false, maxRetransmits: 0, protocol: 'chronolog.peer.v2' } },
      ])
    } finally { await session.close() }
  })

  it('bounds a connected peer that never sends its framing HELLO', async () => {
    const value = fixture()
    await expect(openWebRtcConnection({ ...value.options, timeoutMs: 20 })).rejects.toThrow('WEBRTC_HANDSHAKE_TIMEOUT')
    expect(value.peer.closed).toBe(true)
    expect(value.closed()).toBe(true)
  })

  it('cancels signaling and closes the channel while waiting for an answer', async () => {
    const value = fixture(), controller = new AbortController()
    let send!: () => void
    const sent = new Promise<void>(resolve => { send = resolve })
    const signaling: PeerSignaling = { ...value.signaling, messages: { async *[Symbol.asyncIterator]() {
      await new Promise(() => undefined); yield { type: 'answer', sdp: 'unreachable' }
    } }, async send() { send() } }
    const opening = negotiateWebRtc({ ...value.options, signaling, signal: controller.signal, onDataChannels() {} })
    const rejected = expect(opening).rejects.toThrow('fixture aborted')
    await sent; controller.abort(new Error('fixture aborted'))
    await rejected
    expect(value.peer.closed).toBe(true); expect(value.closed()).toBe(true)
  })

  it('disposes a successful session when its peer connection fails', async () => {
    const value = fixture()
    const session = await negotiateWebRtc({ ...value.options, onDataChannels() {} })
    expect(session.signal.aborted).toBe(false)
    value.peer.connectionState = 'failed'; value.peer.dispatchEvent(new Event('connectionstatechange'))
    await session.close()
    expect(session.signal.aborted).toBe(true)
    expect(value.peer.closed).toBe(true)
  })

  it('refuses a second data channel after successful negotiation', async () => {
    const value = fixture()
    const session = await negotiateWebRtc({ ...value.options, onDataChannels() {} })
    const extra = new Channel()
    value.peer.dispatchEvent(Object.assign(new Event('datachannel'), { channel: extra }))
    await session.close()
    expect(extra.readyState).toBe('closed'); expect(value.peer.closed).toBe(true)
    expect(session.signal.aborted).toBe(true)
  })


  it('closes RTC when signaling cleanup fails after a successful negotiation', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options,
      signaling: { ...value.signaling, close() { throw new Error('cleanup failed') } }, onDataChannels() {},
    })).rejects.toThrow('cleanup failed')
    expect(value.peer.closed).toBe(true)
  })

  it('preserves the original error if signaling cleanup also fails', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options,
      signaling: { ...value.signaling, close() { throw new Error('cleanup failed') } },
      onDataChannels() { throw new Error('handoff failed') },
    })).rejects.toThrow('handoff failed')
    expect(value.peer.closed).toBe(true)
  })

  it('rejects asynchronous channel handoff explicitly', async () => {
    const value = fixture()
    const invalidHandoff: unknown = () => Promise.resolve()
    await expect(negotiateWebRtc({ ...value.options, onDataChannels: invalidHandoff as (channels: WebRtcChannels) => void })).rejects.toThrow('WEBRTC_CHANNEL_HANDOFF_MUST_BE_SYNCHRONOUS')
    expect(value.peer.closed).toBe(true)
  })

  it('closes signaling if the peer factory fails before negotiation starts', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options, createPeerConnection() { throw new Error('factory failed') }, onDataChannels() {} })).rejects.toThrow('factory failed')
    expect(value.closed()).toBe(true)
  })

  it('bounds successful negotiation when a signaling adapter never finishes cleanup', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options, timeoutMs: 20,
      signaling: { ...value.signaling, close: () => new Promise(() => undefined) }, onDataChannels() {},
    })).rejects.toThrow('WEBRTC_NEGOTIATION_TIMEOUT')
    expect(value.peer.closed).toBe(true)
  })

  it('cleans up a connection when the signaling reader cannot be acquired', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options, signaling: { ...value.signaling,
      messages: { [Symbol.asyncIterator]() { throw new Error('reader already owned') } },
    }, onDataChannels() {} })).rejects.toThrow('reader already owned')
    expect(value.peer.closed).toBe(true)
    expect(value.closed()).toBe(true)
  })
})


describe('bounded batch ICE gathering', () => {
  const host = 'a=candidate:1 1 udp 2122260223 peer.local 49152 typ host'
  const srflx = 'a=candidate:2 1 udp 1686052607 203.0.113.1 49153 typ srflx raddr 10.0.0.1 rport 49152'
  function gathering() {
    const value = fixture()
    value.peer.iceGatheringState = 'gathering'
    value.peer.createOffer = async () => ({ type: 'offer', sdp: `v=0\r\n${host}\r\n${srflx}\r\n` })
    const sent: PeerDescription[] = []
    return { ...value, sent, options: { ...value.options, timeoutMs: 5000,
      signaling: { ...value.signaling, async send(description: PeerDescription) { sent.push(description) } } } }
  }
  it('publishes all current candidates at the shared budget despite incomplete gathering', async () => {
    vi.useFakeTimers(); const value = gathering()
    const opening = negotiateWebRtc({ ...value.options, onDataChannels() {} })
    await vi.advanceTimersByTimeAsync(WEBRTC_LIMITS.gatheringMs - 1); expect(value.sent).toHaveLength(0)
    await vi.advanceTimersByTimeAsync(1); const session = await opening
    expect(value.peer.iceGatheringState).toBe('gathering')
    expect(value.sent).toEqual([{ type: 'offer', sdp: `v=0\r\n${host}\r\n${srflx}\r\n` }])
    expect(vi.getTimerCount()).toBe(0); await session.close()
  })
  it('publishes immediately when gathering completes early and disposes its phase timer', async () => {
    vi.useFakeTimers(); const value = gathering()
    const opening = negotiateWebRtc({ ...value.options, onDataChannels() {} })
    await vi.advanceTimersByTimeAsync(10)
    value.peer.iceGatheringState = 'complete'; value.peer.dispatchEvent(new Event('icegatheringstatechange'))
    const session = await opening; expect(value.sent).toHaveLength(1); expect(vi.getTimerCount()).toBe(0); await session.close()
  })
  it.each(['none', 'unspecified', 'relay-policy'] as const)('fails bounded partial gathering with no usable allowed candidate (%s)', async reason => {
    vi.useFakeTimers(); const value = gathering()
    if (reason === 'none') value.peer.createOffer = async () => ({ type: 'offer', sdp: 'v=0\r\n' })
    if (reason === 'unspecified') value.peer.createOffer = async () => ({ type: 'offer', sdp: 'v=0\r\na=candidate:1 1 udp 1 0.0.0.0 0 typ host\r\n' })
    if (reason === 'relay-policy') value.peer.createOffer = async () => ({ type: 'offer', sdp: `v=0\r\n${host}\r\n` })
    const opening = negotiateWebRtc({ ...value.options, ...(reason === 'relay-policy' ? { configuration: { iceTransportPolicy: 'relay' as const } } : {}), onDataChannels() {} })
    const rejected = expect(opening).rejects.toThrow('WEBRTC_ICE_CANDIDATES_UNAVAILABLE')
    await vi.advanceTimersByTimeAsync(WEBRTC_LIMITS.gatheringMs); await rejected
    expect(value.sent).toHaveLength(0); expect(value.peer.closed).toBe(true); expect(value.closed()).toBe(true); expect(vi.getTimerCount()).toBe(0)
  })
  it('honors an explicit longer batch budget and preserves cancellation without publishing', async () => {
    vi.useFakeTimers(); const value = gathering(), abort = new AbortController()
    const opening = negotiateWebRtc({ ...value.options, gatheringTimeoutMs: 2500, signal: abort.signal, onDataChannels() {} })
    const rejected = expect(opening).rejects.toThrow('cancel gather')
    await vi.advanceTimersByTimeAsync(2000); expect(value.sent).toHaveLength(0)
    abort.abort(Error('cancel gather')); await rejected; expect(vi.getTimerCount()).toBe(0); expect(value.peer.closed).toBe(true)
    for (const gatheringTimeoutMs of [0, -1, 1.5, 5001]) await expect(negotiateWebRtc({ ...value.options, gatheringTimeoutMs, onDataChannels() {} })).rejects.toThrow('WEBRTC_GATHERING_TIMEOUT_INVALID')
  })
})

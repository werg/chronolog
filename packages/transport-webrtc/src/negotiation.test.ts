import { describe, expect, it } from 'vitest'

import { negotiateWebRtc, openWebRtcConnection } from './negotiation.js'
import type { PeerSignaling, RtcDataChannel, RtcPeerConnection } from './types.js'

class Channel extends EventTarget implements RtcDataChannel {
  readonly label = 'chronolog'
  readonly ordered = true
  readonly maxPacketLifeTime = null
  readonly maxRetransmits = null
  readyState = 'open'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  send(): void { /* Deliberately withhold the remote framing HELLO. */ }
  close(): void { this.readyState = 'closed'; this.dispatchEvent(new Event('close')) }
}
class Peer extends EventTarget implements RtcPeerConnection {
  readonly channel = new Channel()
  localDescription: { type: string; sdp: string } | null = null
  iceGatheringState = 'complete'
  connectionState = 'connected'
  closed = false
  createDataChannel(): RtcDataChannel { return this.channel }
  createOffer(): Promise<RTCSessionDescriptionInit> { return Promise.resolve({ type: 'offer', sdp: 'fixture-offer' }) }
  createAnswer(): Promise<RTCSessionDescriptionInit> { return Promise.resolve({ type: 'answer', sdp: 'fixture-answer' }) }
  setLocalDescription(value: RTCSessionDescriptionInit): Promise<void> { this.localDescription = { type: value.type, sdp: value.sdp! }; return Promise.resolve() }
  setRemoteDescription(): Promise<void> { return Promise.resolve() }
  close(): void { this.closed = true; this.channel.close() }
}
function fixture() {
  const peer = new Peer()
  let closed = false
  const signaling: PeerSignaling = { messages: { async *[Symbol.asyncIterator]() { yield { type: 'answer', sdp: 'fixture-answer' } } },
    async send() {}, close() { closed = true } }
  return { peer, signaling, closed: () => closed, options: { role: 'offerer' as const, signaling, createPeerConnection: () => peer } }
}

describe('WebRTC session lifecycle', () => {
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
    const opening = negotiateWebRtc({ ...value.options, signaling, signal: controller.signal, onDataChannel() {} })
    const rejected = expect(opening).rejects.toThrow('fixture aborted')
    await sent; controller.abort(new Error('fixture aborted'))
    await rejected
    expect(value.peer.closed).toBe(true); expect(value.closed()).toBe(true)
  })

  it('disposes a successful session when its peer connection fails', async () => {
    const value = fixture()
    const session = await negotiateWebRtc({ ...value.options, onDataChannel() {} })
    expect(session.signal.aborted).toBe(false)
    value.peer.connectionState = 'failed'; value.peer.dispatchEvent(new Event('connectionstatechange'))
    await session.close()
    expect(session.signal.aborted).toBe(true)
    expect(value.peer.closed).toBe(true)
  })

  it('refuses a second data channel after successful negotiation', async () => {
    const value = fixture()
    const session = await negotiateWebRtc({ ...value.options, onDataChannel() {} })
    const extra = new Channel()
    value.peer.dispatchEvent(Object.assign(new Event('datachannel'), { channel: extra }))
    await session.close()
    expect(extra.readyState).toBe('closed'); expect(value.peer.closed).toBe(true)
    expect(session.signal.aborted).toBe(true)
  })


  it('closes RTC when signaling cleanup fails after a successful negotiation', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options,
      signaling: { ...value.signaling, close() { throw new Error('cleanup failed') } }, onDataChannel() {},
    })).rejects.toThrow('cleanup failed')
    expect(value.peer.closed).toBe(true)
  })

  it('preserves the original error if signaling cleanup also fails', async () => {
    const value = fixture()
    await expect(negotiateWebRtc({ ...value.options,
      signaling: { ...value.signaling, close() { throw new Error('cleanup failed') } },
      onDataChannel() { throw new Error('handoff failed') },
    })).rejects.toThrow('handoff failed')
    expect(value.peer.closed).toBe(true)
  })

  it('rejects asynchronous channel handoff explicitly', async () => {
    const value = fixture()
    const invalidHandoff: unknown = () => Promise.resolve()
    await expect(negotiateWebRtc({ ...value.options, onDataChannel: invalidHandoff as (channel: RtcDataChannel) => void })).rejects.toThrow('WEBRTC_CHANNEL_HANDOFF_MUST_BE_SYNCHRONOUS')
    expect(value.peer.closed).toBe(true)
  })
})

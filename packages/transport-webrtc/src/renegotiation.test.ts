import { afterEach, describe, expect, it, vi } from 'vitest'

import { createPeerMediaAndStreams } from './renegotiation.js'
import type { PeerIceCandidate, RtcDataChannel, RtcPeerConnection, RtcSignalMessage } from './types.js'

class MockChannel extends EventTarget implements RtcDataChannel {
  readonly maxPacketLifeTime = null
  readonly maxRetransmits: number | null = null
  readyState = 'open'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  binaryType = 'arraybuffer'
  sent: Array<ArrayBuffer | string> = []
  constructor(readonly label: string, readonly ordered = true) { super() }
  send(data: ArrayBuffer | string): void { this.sent.push(data) }
  close(): void { this.readyState = 'closed'; this.dispatchEvent(new Event('close')) }
}

class MockPeerConnection extends EventTarget implements RtcPeerConnection {
  localDescription: { type: string; sdp: string } | null = null
  iceGatheringState = 'complete'
  connectionState = 'connected'
  signalingState = 'stable'
  iceConnectionState = 'connected'
  rollbacks = 0
  restarts = 0
  addedCandidates: Array<PeerIceCandidate | null> = []
  createdChannels: MockChannel[] = []
  createDataChannel(label: string, options: { ordered?: boolean }): RtcDataChannel {
    const channel = new MockChannel(label, options.ordered ?? true)
    this.createdChannels.push(channel)
    return channel
  }
  async createOffer(options?: { readonly iceRestart?: boolean }): Promise<RTCSessionDescriptionInit> {
    if (options?.iceRestart) this.restarts += 1
    return { type: 'offer', sdp: options?.iceRestart ? 'v=0\r\no=restart\r\n' : 'v=0\r\no=offer\r\n' }
  }
  async createAnswer(): Promise<RTCSessionDescriptionInit> {
    return { type: 'answer', sdp: 'v=0\r\no=answer\r\n' }
  }
  async setLocalDescription(desc?: RTCSessionDescriptionInit | { readonly type: 'rollback' }): Promise<void> {
    if (desc?.type === 'rollback') {
      this.rollbacks += 1
      this.signalingState = 'stable'
      return
    }
    this.localDescription = { type: desc!.type, sdp: desc!.sdp! }
    this.signalingState = desc!.type === 'offer' ? 'have-local-offer' : 'stable'
  }
  async setRemoteDescription(desc: RTCSessionDescriptionInit): Promise<void> {
    this.signalingState = desc.type === 'offer' ? 'have-remote-offer' : 'stable'
  }
  async addIceCandidate(candidate: PeerIceCandidate | null): Promise<void> {
    this.addedCandidates.push(candidate)
  }
  restartIce(): void { /* handled in createOffer({ iceRestart: true }) */ }
  addTrack(): unknown { return {} }
  removeTrack(): void {}
  addTransceiver(): unknown { return {} }
  getTransceivers(): readonly unknown[] { return [] }
  close(): void { this.connectionState = 'closed'; this.signalingState = 'closed' }
}

afterEach(() => { vi.useRealTimers() })

describe('W3C Perfect Negotiation and dynamic app:* streams', () => {
  it('resolves offer glare deterministically: impolite ignores colliding offer, polite rolls back and answers', async () => {
    const stop = new AbortController()
    const politePc = new MockPeerConnection(), impolitePc = new MockPeerConnection()
    const politeSent: RtcSignalMessage[] = [], impoliteSent: RtcSignalMessage[] = []
    const politeRuntime = createPeerMediaAndStreams(politePc, stop.signal, { onUnexpectedPreAuthChannel() {} })
    const impoliteRuntime = createPeerMediaAndStreams(impolitePc, stop.signal, { onUnexpectedPreAuthChannel() {} })
    const politeHandle = politeRuntime.attachInBandSignaling({ polite: true, async send(msg) { politeSent.push(msg) } })
    const impoliteHandle = impoliteRuntime.attachInBandSignaling({ polite: false, async send(msg) { impoliteSent.push(msg) } })

    // Both peers are simultaneously in have-local-offer (glare).
    await politePc.setLocalDescription({ type: 'offer', sdp: 'v=0\r\no=polite\r\n' })
    await impolitePc.setLocalDescription({ type: 'offer', sdp: 'v=0\r\no=impolite\r\n' })

    // Impolite ignores colliding remote offer.
    await impoliteHandle.receive({ kind: 'description', description: { type: 'offer', sdp: 'v=0\r\no=polite\r\n' } })
    expect(impolitePc.rollbacks).toBe(0)
    expect(impoliteSent).toHaveLength(0)

    // Polite rolls back its local offer, accepts remote offer, and sends an answer.
    await politeHandle.receive({ kind: 'description', description: { type: 'offer', sdp: 'v=0\r\no=impolite\r\n' } })
    expect(politePc.rollbacks).toBe(1)
    expect(politeSent).toEqual([{ kind: 'description', description: { type: 'answer', sdp: 'v=0\r\no=answer\r\n' } }])
    stop.abort()
  })

  it('rejects non-app:* DataChannels post-auth without closing the peer connection', () => {
    const stop = new AbortController()
    const pc = new MockPeerConnection()
    let preAuthAborted = false
    const runtime = createPeerMediaAndStreams(pc, stop.signal, { onUnexpectedPreAuthChannel() { preAuthAborted = true } })
    runtime.attachInBandSignaling({ polite: true, async send() {} })
    const received: string[] = []
    runtime.streams.onStream(stream => received.push(stream.label))

    const rogue = new MockChannel('chronolog.injected')
    pc.dispatchEvent(Object.assign(new Event('datachannel'), { channel: rogue }))
    expect(rogue.readyState).toBe('closed')
    expect(preAuthAborted).toBe(false)
    expect(pc.connectionState).toBe('connected')
    expect(received).toEqual([])

    const valid = new MockChannel('app:telemetry', false)
    pc.dispatchEvent(Object.assign(new Event('datachannel'), { channel: valid }))
    expect(valid.readyState).toBe('open')
    expect(received).toEqual(['telemetry'])
    stop.abort()
  })

  it('triggers debounced ICE restart when iceConnectionState becomes disconnected', async () => {
    vi.useFakeTimers()
    const stop = new AbortController()
    const pc = new MockPeerConnection()
    const sent: RtcSignalMessage[] = []
    const runtime = createPeerMediaAndStreams(pc, stop.signal, { onUnexpectedPreAuthChannel() {} })
    runtime.attachInBandSignaling({ polite: true, async send(msg) { sent.push(msg) } })

    pc.iceConnectionState = 'disconnected'
    pc.dispatchEvent(new Event('iceconnectionstatechange'))
    await vi.advanceTimersByTimeAsync(2100)
    expect(pc.restarts).toBe(1)
    expect(sent).toEqual([{ kind: 'description', description: { type: 'offer', sdp: 'v=0\r\no=restart\r\n' } }])
    stop.abort()
  })
})

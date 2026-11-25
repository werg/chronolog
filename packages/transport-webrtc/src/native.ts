import { MediaStreamTrack, RTCPeerConnection, RTCRtpCodecParameters } from 'werift'
import type { MediaStream, PeerConfig, RTCDataChannel, RTCRtpSender } from 'werift'

import { WEBRTC_LIMITS } from './channel.js'
import type { PeerIceCandidate, RtcDataChannel, RtcDataChannelOptions, RtcPeerConnection } from './types.js'

export { MediaStreamTrack, RTCRtpCodecParameters }

export interface NativeAudioTrack {
  readonly kind: 'audio'
  readonly raw: unknown
  writeRtp(packet: Uint8Array | { readonly header: unknown; readonly payload: Uint8Array }): void
  onRtp(listener: (packet: { readonly payload: Uint8Array; readonly sequenceNumber: number; readonly timestamp: number; readonly payloadType: number; readonly ssrc: number }) => void): () => void
  stop(): void
}

/** Create a native Werift audio track for sending or wrapping RTP Opus frames in Node. */
export function createNativeAudioTrack(): NativeAudioTrack {
  const track = new MediaStreamTrack({ kind: 'audio' })
  return {
    kind: 'audio',
    raw: track,
    writeRtp(packet) {
      track.writeRtp(packet as Parameters<MediaStreamTrack['writeRtp']>[0])
    },
    onRtp(listener) {
      const sub = track.onReceiveRtp.subscribe(packet => {
        listener({
          payload: new Uint8Array(packet.payload),
          sequenceNumber: packet.header.sequenceNumber,
          timestamp: packet.header.timestamp,
          payloadType: packet.header.payloadType,
          ssrc: packet.header.ssrc,
        })
      })
      return () => { sub.unSubscribe() }
    },
    stop() { track.stop() },
  }
}

export type NativeRtcOptions = Partial<Pick<PeerConfig,
  'icePortRange' | 'iceInterfaceAddresses' | 'iceAdditionalHostAddresses' | 'iceUseIpv4' | 'iceUseIpv6' |
  'iceUseTcp' | 'iceTcpPassive' | 'iceStunGatherTimeout' | 'iceTurnConnectTimeout' | 'turnUdpFamily'>>

/** Explicit native entrypoint: no Node or Werift bytes enter browser bundles. */
export function createNativePeerConnection(configuration: RTCConfiguration = {}, native: NativeRtcOptions = {}): RtcPeerConnection {
  if (configuration.certificates !== undefined) throw new Error('WEBRTC_NATIVE_CERTIFICATES_UNSUPPORTED')
  const peer = new RTCPeerConnection({
    ...native,
    iceStunGatherTimeout: native.iceStunGatherTimeout ?? WEBRTC_LIMITS.gatheringMs / 1000,
    iceUseDefaultStunServer: false,
    certificateScope: 'peerConnection',
    codecs: {
      audio: [
        new RTCRtpCodecParameters({ mimeType: 'audio/opus', clockRate: 48000, channels: 2 }),
      ],
      video: [
        new RTCRtpCodecParameters({ mimeType: 'video/VP8', clockRate: 90000 }),
        new RTCRtpCodecParameters({ mimeType: 'video/H264', clockRate: 90000 }),
      ],
    },
    iceServers: configuration.iceServers?.map(server => ({
      urls: server.urls,
      ...(server.username === undefined ? {} : { username: server.username }),
      ...(server.credential === undefined ? {} : { credential: server.credential }),
    })) ?? [],
    ...(configuration.iceTransportPolicy === undefined ? {} : { iceTransportPolicy: configuration.iceTransportPolicy }),
    ...(configuration.bundlePolicy === undefined ? {} : { bundlePolicy: configuration.bundlePolicy }),
    ...(configuration.iceCandidatePoolSize === undefined ? {} : { iceCandidatePoolSize: configuration.iceCandidatePoolSize }),
  })
  const events = new EventTarget(), channels = new Set<NativeDataChannel>()
  const wrap = (channel: RTCDataChannel): NativeDataChannel => {
    const value = new NativeDataChannel(channel)
    channels.add(value)
    return value
  }
  const subscriptions = [
    peer.onDataChannel.subscribe(channel => events.dispatchEvent(Object.assign(new Event('datachannel'), { channel: wrap(channel) }))),
    peer.connectionStateChange.subscribe(() => events.dispatchEvent(new Event('connectionstatechange'))),
    peer.iceConnectionStateChange.subscribe(() => events.dispatchEvent(new Event('iceconnectionstatechange'))),
    peer.iceGatheringStateChange.subscribe(() => events.dispatchEvent(new Event('icegatheringstatechange'))),
    peer.signalingStateChange.subscribe(() => events.dispatchEvent(new Event('signalingstatechange'))),
    peer.onNegotiationneeded.subscribe(() => events.dispatchEvent(new Event('negotiationneeded'))),
    peer.onIceCandidate.subscribe(candidate => {
      events.dispatchEvent(Object.assign(new Event('icecandidate'), {
        candidate: candidate ? candidate.toJSON() : null,
      }))
    }),
    peer.onTrack.subscribe(track => {
      const transceiver = peer.getTransceivers().find(item => item.receiver?.track === track)
      events.dispatchEvent(Object.assign(new Event('track'), { track, streams: [], transceiver }))
    }),
  ]
  return {
    get localDescription() { return peer.localDescription },
    get iceGatheringState() { return peer.iceGatheringState },
    get connectionState() { return peer.connectionState },
    get signalingState() { return peer.signalingState },
    get iceConnectionState() { return peer.iceConnectionState },
    getStats: () => peer.getStats(),
    createDataChannel: (label: string, options: RtcDataChannelOptions) => wrap(peer.createDataChannel(label, options)),
    createOffer: (options?: { readonly iceRestart?: boolean }) => peer.createOffer(options),
    createAnswer: () => peer.createAnswer(),
    async setLocalDescription(description) {
      if (description === undefined) {
        await peer.setLocalDescription()
        return
      }
      if (description.type === 'rollback') {
        await peer.setLocalDescription({ type: 'rollback' })
        return
      }
      if ((description.type !== 'offer' && description.type !== 'answer') || description.sdp === undefined) {
        throw new Error('WEBRTC_DESCRIPTION_INVALID')
      }
      await peer.setLocalDescription({ type: description.type, sdp: description.sdp })
    },
    async setRemoteDescription(description) {
      if ((description.type !== 'offer' && description.type !== 'answer') || description.sdp === undefined) {
        throw new Error('WEBRTC_DESCRIPTION_INVALID')
      }
      await peer.setRemoteDescription({ type: description.type, sdp: description.sdp })
    },
    async addIceCandidate(candidate: PeerIceCandidate | null) {
      await peer.addIceCandidate(candidate ?? null)
    },
    restartIce: () => peer.restartIce(),
    addTrack: (track: unknown, ...streams: unknown[]) => peer.addTrack(track as MediaStreamTrack, ...(streams as MediaStream[])),
    removeTrack: (sender: unknown) => peer.removeTrack(sender as RTCRtpSender),
    addTransceiver: (kindOrTrack: unknown, init?: Record<string, unknown>) =>
      peer.addTransceiver(kindOrTrack as 'audio' | 'video' | MediaStreamTrack, init),
    getTransceivers: () => peer.getTransceivers(),
    getSenders: () => peer.getSenders(),
    getReceivers: () => peer.getReceivers(),
    addEventListener: (type, listener) => events.addEventListener(type, listener),
    removeEventListener: (type, listener) => events.removeEventListener(type, listener),
    async close() {
      for (const subscription of subscriptions) subscription.unSubscribe()
      for (const channel of channels) channel.close()
      await peer.close()
    },
  }
}

class NativeDataChannel extends EventTarget implements RtcDataChannel {
  binaryType = 'arraybuffer'
  #closed = false
  readonly #channel: RTCDataChannel
  readonly #subscriptions: Array<{ unSubscribe(): void }>
  constructor(channel: RTCDataChannel) {
    super(); this.#channel = channel
    this.#subscriptions = [
      channel.onMessage.subscribe(data => {
        const value = typeof data === 'string' ? data : new Uint8Array(data).buffer
        this.dispatchEvent(new MessageEvent('message', { data: value }))
      }),
      channel.stateChanged.subscribe(state => {
        if (state === 'open') this.dispatchEvent(new Event('open'))
        else if (state === 'closed') this.close()
      }),
      channel.bufferedAmountLow.subscribe(() => this.dispatchEvent(new Event('bufferedamountlow'))),
      channel.error.subscribe(() => this.dispatchEvent(new Event('error'))),
    ]
  }
  get label() { return this.#channel.label }
  get ordered() { return this.#channel.ordered }
  get maxPacketLifeTime() { return this.#channel.maxPacketLifeTime }
  get maxRetransmits() { return this.#channel.maxRetransmits }
  get readyState() { return this.#channel.readyState }
  get bufferedAmount() { return this.#channel.bufferedAmount }
  get bufferedAmountLowThreshold() { return this.#channel.bufferedAmountLowThreshold }
  set bufferedAmountLowThreshold(value: number) { this.#channel.bufferedAmountLowThreshold = value }
  send(data: ArrayBuffer | string): void {
    this.#channel.send(typeof data === 'string' ? data : Buffer.from(data))
  }
  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.dispatchEvent(new Event('close'))
    for (const subscription of this.#subscriptions) subscription.unSubscribe()
    this.#channel.close()
  }
}

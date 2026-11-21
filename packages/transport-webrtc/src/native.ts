import { RTCPeerConnection } from 'werift'
import type { PeerConfig, RTCDataChannel } from 'werift'

import type { RtcDataChannel, RtcPeerConnection } from './types.js'

export type NativeRtcOptions = Partial<Pick<PeerConfig,
  'icePortRange' | 'iceInterfaceAddresses' | 'iceAdditionalHostAddresses' | 'iceUseIpv4' | 'iceUseIpv6' |
  'iceUseTcp' | 'iceTcpPassive' | 'iceStunGatherTimeout' | 'iceTurnConnectTimeout' | 'turnUdpFamily'>>

/** Explicit native entrypoint: no Node or Werift bytes enter browser bundles. */
export function createNativePeerConnection(configuration: RTCConfiguration = {}, native: NativeRtcOptions = {}): RtcPeerConnection {
  if (configuration.certificates !== undefined) throw new Error('WEBRTC_NATIVE_CERTIFICATES_UNSUPPORTED')
  // Offer and answer gather serially before framing. Keep default STUN
  // gathering within a five-second direct attempt. Werift's timeout uses
  // seconds, not milliseconds; callers may override it.
  const peer = new RTCPeerConnection({ ...native, iceStunGatherTimeout: native.iceStunGatherTimeout ?? 1,
    iceUseDefaultStunServer: false, certificateScope: 'peerConnection',
    iceServers: configuration.iceServers?.map(server => ({ urls: server.urls,
      ...(server.username === undefined ? {} : { username: server.username }),
      ...(server.credential === undefined ? {} : { credential: server.credential }) })) ?? [],
    ...(configuration.iceTransportPolicy === undefined ? {} : { iceTransportPolicy: configuration.iceTransportPolicy }),
    ...(configuration.bundlePolicy === undefined ? {} : { bundlePolicy: configuration.bundlePolicy }),
    ...(configuration.iceCandidatePoolSize === undefined ? {} : { iceCandidatePoolSize: configuration.iceCandidatePoolSize }),
  })
  const events = new EventTarget(), channels = new Set<NativeDataChannel>()
  const wrap = (channel: RTCDataChannel): NativeDataChannel => { const value = new NativeDataChannel(channel); channels.add(value); return value }
  const subscriptions = [
    peer.onDataChannel.subscribe(channel => events.dispatchEvent(Object.assign(new Event('datachannel'), { channel: wrap(channel) }))),
    peer.connectionStateChange.subscribe(() => events.dispatchEvent(new Event('connectionstatechange'))),
    peer.iceGatheringStateChange.subscribe(() => events.dispatchEvent(new Event('icegatheringstatechange'))),
  ]
  return {
    get localDescription() { return peer.localDescription },
    get iceGatheringState() { return peer.iceGatheringState },
    get connectionState() { return peer.connectionState },
    getStats: () => peer.getStats(),
    createDataChannel: (label, options) => wrap(peer.createDataChannel(label, options)),
    createOffer: () => peer.createOffer(), createAnswer: () => peer.createAnswer(),
    async setLocalDescription(description) {
      if (description.type !== 'offer' && description.type !== 'answer' || description.sdp === undefined) throw new Error('WEBRTC_DESCRIPTION_INVALID')
      await peer.setLocalDescription({ type: description.type, sdp: description.sdp })
    },
    async setRemoteDescription(description) {
      if (description.type !== 'offer' && description.type !== 'answer' || description.sdp === undefined) throw new Error('WEBRTC_DESCRIPTION_INVALID')
      await peer.setRemoteDescription({ type: description.type, sdp: description.sdp })
    },
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
  send(data: ArrayBuffer): void { this.#channel.send(Buffer.from(data)) }
  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.dispatchEvent(new Event('close'))
    for (const subscription of this.#subscriptions) subscription.unSubscribe()
    this.#channel.close()
  }
}

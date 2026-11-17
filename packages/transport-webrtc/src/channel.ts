import {
  frameMessageChannel, framePeerMessageChannels, PEER_MESSAGE_LIMITS,
  type MessageConnection, type PeerMessageConnection, type MessageChannelStats,
} from '@chronolog/records'
import type { RtcDataChannel, WebRtcChannels } from './types.js'
import { requireRtcLiveChannel } from './live.js'

export const WEBRTC_LIMITS = Object.freeze({ ...PEER_MESSAGE_LIMITS, sdpBytes: 64 * 1024 })
export type DataChannelStats = MessageChannelStats
export type DataChannelConnection = MessageConnection
export type PeerDataChannelConnection = PeerMessageConnection

function requireReliable(channel: RtcDataChannel): void {
  if (!channel.ordered || channel.maxPacketLifeTime !== null || channel.maxRetransmits !== null)
    throw new Error('WEBRTC_RELIABLE_ORDERED_REQUIRED')
}

/** RTC supplies ordered history and disposable SCTP lanes to the shared framing owner. */
export function frameRtcPeerChannels(channels: WebRtcChannels,
  options: Parameters<typeof frameMessageChannel>[1] = {}): PeerDataChannelConnection {
  requireReliable(channels.reliable); requireRtcLiveChannel(channels.live)
  return framePeerMessageChannels(channels, options)
}

export function frameRtcDataChannel(channel: RtcDataChannel,
  options: Parameters<typeof frameMessageChannel>[1] = {}): DataChannelConnection {
  requireReliable(channel)
  return frameMessageChannel(channel, options)
}

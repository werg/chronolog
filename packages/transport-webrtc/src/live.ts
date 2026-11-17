import { frameLiveMessageChannel, PEER_LIVE_MESSAGE_LIMITS, type LiveMessageConnection } from '@chronolog/records'
import type { RtcDataChannel } from './types.js'

export const WEBRTC_LIVE_LIMITS = PEER_LIVE_MESSAGE_LIMITS
export type LiveDataChannelConnection = LiveMessageConnection

export function requireRtcLiveChannel(channel: RtcDataChannel): void {
  if (channel.ordered || channel.maxPacketLifeTime !== null || channel.maxRetransmits !== 0)
    throw new Error('WEBRTC_LIVE_CHANNEL_REQUIRED')
}

export function frameRtcLiveChannel(channel: RtcDataChannel): LiveDataChannelConnection {
  requireRtcLiveChannel(channel)
  return frameLiveMessageChannel(channel)
}

import { createNativePeerConnection, type NativeRtcOptions } from '@chronolog/transport-webrtc/native'

import type { ApplicationSession } from './session.js'
import { connectApplicationWebRtc, type WebRtcOptions } from './webrtc.js'
export { createNativePeerConnection, type NativeRtcOptions } from '@chronolog/transport-webrtc/native'

/** Optional Node RTC adapter; install the declared exact Werift peer dependency. */
export function connectNativeApplicationWebRtc(session: ApplicationSession, options: Omit<WebRtcOptions, 'createPeerConnection'> & {
  readonly peerIdentity?: string
  readonly native?: NativeRtcOptions
}) {
  return connectApplicationWebRtc(session, { ...options, createPeerConnection: configuration => createNativePeerConnection(configuration, options.native) })
}

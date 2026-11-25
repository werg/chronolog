import { createNativePeerConnection, type NativeRtcOptions } from '@chronolog/transport-webrtc/native'

import type { ApplicationPeerLink } from './network.js'
import type { ApplicationSession } from './session.js'
import { connectApplicationWebRtc, type WebRtcOptions, type WebRtcSession } from './webrtc.js'
export { createNativePeerConnection, createNativeAudioTrack, type NativeRtcOptions, type NativeAudioTrack } from '@chronolog/transport-webrtc/native'

/** Node RTC adapter included in the standard archive with its exact Werift dependency. */
export function connectNativeApplicationWebRtc(session: ApplicationSession, options: Omit<WebRtcOptions, 'createPeerConnection'> & {
  readonly peerIdentity?: string
  readonly native?: NativeRtcOptions
}): Promise<ApplicationPeerLink & { readonly rtc: WebRtcSession }> {
  return connectApplicationWebRtc(session, { ...options, createPeerConnection: configuration => createNativePeerConnection(configuration, options.native) })
}

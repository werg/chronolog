import { createNativePeerConnection, type NativeRtcOptions } from '@chronolog/transport-webrtc/native'

import type { ApplicationSession } from './session.js'
import { connectApplicationWebRtc, createApplicationWebRtcOfferHandler, type WebRtcOptions } from './webrtc.js'
import { maintainApplicationWebRtc, type ApplicationNetworkOptions } from './lifecycle.js'
export { createNativePeerConnection, type NativeRtcOptions } from '@chronolog/transport-webrtc/native'

/** Optional Node RTC adapter; install the declared exact Werift peer dependency. */
export function connectNativeApplicationWebRtc(session: ApplicationSession, options: Omit<WebRtcOptions, 'createPeerConnection'> & {
  readonly expectedPeerId?: string
  readonly native?: NativeRtcOptions
}) {
  return connectApplicationWebRtc(session, { ...options, createPeerConnection: configuration => createNativePeerConnection(configuration, options.native) })
}

export function createNativeApplicationWebRtcOfferHandler(session: ApplicationSession,
  options: Omit<Parameters<typeof createApplicationWebRtcOfferHandler>[1], 'createPeerConnection'> & { readonly native?: NativeRtcOptions }) {
  return createApplicationWebRtcOfferHandler(session, { ...options,
    createPeerConnection: configuration => createNativePeerConnection(configuration, options.native) })
}

/** One native owner for bounded discovery, invitations, reconnect and eligible takeover. */
export function maintainNativeApplicationWebRtc(session: ApplicationSession,
  options: Omit<ApplicationNetworkOptions, 'createPeerConnection'> & { readonly native?: NativeRtcOptions }) {
  return maintainApplicationWebRtc(session, { ...options,
    createPeerConnection: configuration => createNativePeerConnection(configuration, options.native) })
}

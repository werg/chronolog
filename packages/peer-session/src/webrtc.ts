import { openWebRtcConnection, type WebRtcOptions, type WebRtcSession } from '@chronolog/transport-webrtc'

import type { ApplicationPeerLink } from './network.js'
import type { ApplicationSession } from './session.js'

export type {
  WebRtcOptions, PeerSignaling, PeerSignalingMessage, PeerDescription, PeerIceCandidate,
  RtcSignalMessage, RtcPeerConnection, PeerDataStream, PeerDataStreamOptions,
  PeerMediaController, PeerStreamsController, PeerTrackEvent, WebRtcSession, WebRtcRoute,
} from '@chronolog/transport-webrtc'
export { openWebRtcConnection, WEBRTC_LIMITS, APP_STREAM_PREFIX, MAX_APP_STREAMS } from '@chronolog/transport-webrtc'
export {
  serveWorkerWebRtcConnections, openWorkerWebRtcConnection,
  type ApplicationWorkerEndpoint, type WorkerWebRtcConnection,
  type PagePeerHandle, type WorkerWebRtcServer,
} from './worker-transport.js'

/** The maintained browser/native composition owns both RTC lanes and peer authentication. */
export async function connectApplicationWebRtc(session: ApplicationSession, options: WebRtcOptions & {
  readonly peerIdentity?: string
}): Promise<ApplicationPeerLink & { readonly rtc: WebRtcSession }> {
  const connection = await openWebRtcConnection({ ...options, signal: options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]) })
  try {
    const link = await session.connectPeer({ connection,
      ...(options.peerIdentity === undefined ? {} : { peerIdentity: options.peerIdentity }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.timeoutMs === undefined ? {} : { handshakeTimeoutMs: options.timeoutMs }) })
    await link.synchronize()
    return Object.assign(link, { rtc: connection.session })
  } catch (error) { await connection.close(); throw error }
}

import { openWebRtcConnection, type WebRtcOptions, type WebRtcSession } from '@chronolog/transport-webrtc'

import type { ApplicationPeerLink } from './network.js'
import type { ApplicationSession } from './session.js'

export type { WebRtcOptions, PeerSignaling, PeerDescription, RtcPeerConnection } from '@chronolog/transport-webrtc'
export { openWebRtcConnection } from '@chronolog/transport-webrtc'
export { serveWorkerWebRtcConnections, openWorkerWebRtcConnection, type ApplicationWorkerEndpoint, type WorkerWebRtcConnection } from './worker-transport.js'

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

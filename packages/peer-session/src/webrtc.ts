import { openWebRtcConnection, type WebRtcOptions, type WebRtcSession } from '@chronolog/transport-webrtc'

import { connectApplicationTransport, type ApplicationPeerConnection } from './network.js'
import type { ApplicationSession } from './session.js'

export type { WebRtcOptions, PeerSignaling, PeerDescription, RtcPeerConnection } from '@chronolog/transport-webrtc'

/** The maintained browser/native composition owns both RTC lanes and peer authentication. */
export async function connectApplicationWebRtc(session: ApplicationSession, options: WebRtcOptions & {
  readonly expectedPeerId?: string
}): Promise<ApplicationPeerConnection & { readonly rtc: WebRtcSession }> {
  const connection = await openWebRtcConnection({ ...options, signal: options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal]) })
  try {
    const link = await connectApplicationTransport(session, { connection,
      ...(options.expectedPeerId === undefined ? {} : { expectedPeerId: options.expectedPeerId }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }) })
    return Object.assign(link, { rtc: connection.session })
  } catch (error) { await connection.close(); throw error }
}

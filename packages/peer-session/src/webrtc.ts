import { createWebRtcOfferHandler, openWebRtcConnection, type WebRtcOptions, type WebRtcSession } from '@chronolog/transport-webrtc'

import { connectApplicationTransport, type ApplicationPeerConnection } from './network.js'
import type { ApplicationSession } from './session.js'

export type { WebRtcOptions, PeerSignaling, PeerDescription, RtcPeerConnection } from '@chronolog/transport-webrtc'
export { installApplicationWorkerTransport, connectWorkerApplicationWebRtc, type ApplicationWorkerEndpoint } from './worker-transport.js'
export { maintainApplicationWebRtc, maintainWorkerApplicationWebRtc,
  type ApplicationNetwork, type ApplicationNetworkOptions, type ApplicationNetworkStatus,
  type ApplicationPeerHost, type ApplicationPeerAdvertisement, type ApplicationPeerLease, type ApplicationPeerRoute } from './lifecycle.js'

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

/** A normal native peer can expose an introduction route without acquiring extra authority. */
export function createApplicationWebRtcOfferHandler(session: ApplicationSession,
  options: Omit<Parameters<typeof createWebRtcOfferHandler>[0], 'accept'>) {
  const handler = createWebRtcOfferHandler({ ...options, accept: async (connection, signal) => {
    const link = await connectApplicationTransport(session, { connection, signal })
    const completion = new Promise<void>(resolve => {
      if (link.signal.aborted) resolve()
      else link.signal.addEventListener('abort', () => { resolve() }, { once: true })
    })
    return { completion, close: () => link.close() }
  } })
  const abort = (): void => { void handler.close() }
  session.signal.addEventListener('abort', abort, { once: true })
  if (session.signal.aborted) abort()
  return { fetch: handler.fetch.bind(handler), get stats() { return handler.stats }, async close() {
    session.signal.removeEventListener('abort', abort); await handler.close()
  } }
}

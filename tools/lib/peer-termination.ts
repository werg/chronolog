/** Expected per-connection outcomes, never a failure of the shared replica. */
const TERMINATIONS = new Set([
  'PEER_CONNECTION_ENDED', 'PEER_CONNECTION_CLOSED', 'PEER_LIVE_ENDED', 'PEER_READ_UNAUTHORIZED',
  'WEBRTC_CONNECTION_ENDED', 'WEBRTC_CONNECTION_CLOSED',
  'WEBRTC_LIVE_ENDED', 'WEBRTC_LIVE_CLOSED',
])

export function isExpectedPeerTermination(error: unknown): error is Error {
  return error instanceof Error && TERMINATIONS.has(error.message)
}

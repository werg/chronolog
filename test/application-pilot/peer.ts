import type { GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { base64UrlToBytes } from '@chronolog/protocol'
import type { DataChannelConnection } from '@chronolog/transport-webrtc'

/** Authentication attaches replication; applying retained history has its own lifetime. */
export async function attachPilotPeer(options: {
  readonly connection: DataChannelConnection
  readonly nativeIdentity: string
  readonly peer: Pick<GovernedPeerService, 'connectPeer'>
}) {
  const { connection } = options, started = performance.now()
  try {
    await connection.ready
    const session = await options.peer.connectPeer({ connection, peerIdentity: base64UrlToBytes(options.nativeIdentity) })
    return { ...session, authenticatedMs: performance.now() - started, stats: () => connection.stats }
  } catch (error) { await connection.close(); throw error }
}

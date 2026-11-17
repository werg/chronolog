import type { GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { base64UrlToBytes } from '@chronolog/protocol'
import type { DataChannelConnection } from '@chronolog/transport-webrtc'

/** The same fresh-device authentication boundary for Worker and native gates. */
export async function attachMembershipPeer(options: {
  readonly connection: DataChannelConnection
  readonly nativeIdentity: string
  readonly peer: Pick<GovernedPeerService, 'connectPeer'>
}) {
  const { connection } = options
  try {
    await connection.ready
    const session = await options.peer.connectPeer({ connection, peerIdentity: base64UrlToBytes(options.nativeIdentity) })
    return { ...session, stats: () => connection.stats }
  } catch (error) { await connection.close(); throw error }
}

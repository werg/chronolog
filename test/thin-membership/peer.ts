import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToHex, equalBytes } from '@chronolog/protocol'
import type { PortableFeedTransport } from '@chronolog/records'
import type { DataChannelConnection } from '@chronolog/transport-webrtc'

/** The same fresh-device authentication boundary for Worker and native gates. */
export async function attachMembershipPeer(options: {
  readonly connection: DataChannelConnection
  readonly nativeIdentity: string
  readonly identity: EnrollmentIdentity
  readonly transport: PortableFeedTransport
  readonly activeMembership: () => CapabilitySnapshot
}) {
  const { connection } = options
  try {
    await connection.ready
    const snapshot = options.activeMembership()
    const reader = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
      isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, options.identity.signing.publicKeyBytes))
    if (reader === undefined) throw new Error('THIN_BROWSER_READER_GRANT_MISSING')
    const session = await openAuthenticatedPeerLink({ connection, local: options.transport.asLink(),
      identity: options.identity.signing, groupId: snapshot.groupId, grantId: reader.id,
      authorizePeer: ({ authorId, grantId }) => {
        const current = options.activeMembership(), capability = current.capabilities.get(bytesToHex(grantId))
        return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, current.revision) &&
          equalBytes(capability.grant.signingPublicKey, authorId) && equalBytes(authorId, base64UrlToBytes(options.nativeIdentity))
      } })
    const detach = options.transport.connect(session.link)
    void session.completion.finally(detach).catch(() => undefined)
    return { completion: session.completion, stats: () => connection.stats,
      async close() { detach(); await session.close(); await connection.close() } }
  } catch (error) { await connection.close(); throw error }
}

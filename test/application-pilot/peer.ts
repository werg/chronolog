import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToHex, equalBytes } from '@chronolog/protocol'
import type { PortableFeedTransport } from '@chronolog/records'
import type { DataChannelConnection } from '@chronolog/transport-webrtc'

/** Authentication attaches replication; applying retained history has its own lifetime. */
export async function attachPilotPeer(options: {
  readonly connection: DataChannelConnection
  readonly nativeIdentity: string
  readonly identity: EnrollmentIdentity
  readonly transport: PortableFeedTransport
  readonly activeMembership: () => CapabilitySnapshot
  readonly receiveSignal?: (bytes: Uint8Array) => Promise<void>
}) {
  const { connection } = options, started = performance.now()
  try {
    await connection.ready
    const snapshot = options.activeMembership()
    const reader = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
      isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, options.identity.signing.publicKeyBytes))
    if (reader === undefined) throw new Error('PILOT_READER_GRANT_REQUIRED')
    const authenticated = await openAuthenticatedPeerLink({ connection, local: options.transport.asLink(),
      identity: options.identity.signing, groupId: snapshot.groupId, grantId: reader.id,
      ...(options.receiveSignal === undefined ? {} : { receiveSignal: options.receiveSignal }),
      authorizePeer: ({ authorId, grantId }) => {
        const current = options.activeMembership(), capability = current.capabilities.get(bytesToHex(grantId))
        return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, current.revision) &&
          equalBytes(capability.grant.signingPublicKey, authorId) && equalBytes(authorId, base64UrlToBytes(options.nativeIdentity))
      } })
    const detach = options.transport.connect(authenticated.link)
    void authenticated.completion.finally(detach).catch(() => undefined)
    return { completion: authenticated.completion, authenticatedMs: performance.now() - started,
      sendSignal: (bytes: Uint8Array) => authenticated.sendSignal(bytes), stats: () => connection.stats,
      async close() { detach(); await authenticated.close(); await connection.close() } }
  } catch (error) { await connection.close(); throw error }
}

import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import type { FramedPeerConnection } from '@chronolog/agent-service/framing'
import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import { bytesToHex, equalBytes, type Ed25519KeyPair } from '@chronolog/protocol'
import type { PortableFeedTransport } from '@chronolog/records'
import type { SignalChannel } from '@chronolog/signals'

export interface BrowserPeerConnectionOptions {
  readonly connection: FramedPeerConnection
  readonly grantId?: Uint8Array
  /** Optional endpoint pin, in addition to its current reader capability. */
  readonly peerIdentity?: Uint8Array
}
export interface BrowserPeerConnection { readonly completion: Promise<void>; close(): Promise<void> }

export function browserPeerConnections(options: {
  readonly identity: Ed25519KeyPair
  readonly groupId: Uint8Array
  readonly current?: () => CapabilitySnapshot
  readonly transport: PortableFeedTransport
  readonly signals?: SignalChannel
}) {
  const sessions = new Set<BrowserPeerConnection>()
  const opening = new Set<FramedPeerConnection>()
  let closed = false
  return {
    async connectPeer(input: BrowserPeerConnectionOptions): Promise<BrowserPeerConnection> {
      opening.add(input.connection)
      try {
        if (closed) throw new Error('PEER_CLOSED')
        if (options.current === undefined) throw new Error('PEER_GOVERNANCE_REQUIRED')
        const snapshot = options.current()
        const reader = input.grantId ?? [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
          isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, options.identity.publicKeyBytes))?.id
        if (reader === undefined) throw new Error('PEER_LOCAL_READER_GRANT_REQUIRED')
        const session = await openAuthenticatedPeerLink({ connection: input.connection, local: options.transport.asLink(),
          identity: options.identity, groupId: options.groupId, grantId: reader,
          authorizePeer({ authorId, grantId }) {
            const current = options.current!(), capability = current.capabilities.get(bytesToHex(grantId))
            return equalBytes(current.groupId, options.groupId) && capability !== undefined && capability.grant.role === 'reader' &&
              isCapabilityActive(capability, current.revision) && equalBytes(capability.grant.signingPublicKey, authorId) &&
              (input.peerIdentity === undefined || equalBytes(authorId, input.peerIdentity))
          },
          ...(options.signals === undefined ? {} : { receiveSignal: async (frame: Uint8Array) => { await options.signals!.receive(frame) } }),
        })
        let detach: (() => void) | undefined, detachSignals: (() => void) | undefined
        try {
          if (closed) throw new Error('PEER_CLOSED')
          detach = options.transport.connect(session.link)
          detachSignals = options.signals?.attach((frame) => session.sendSignal(frame))
          const cleanup = (): void => { detachSignals?.(); detach?.(); sessions.delete(connection) }
          const connection: BrowserPeerConnection = { completion: session.completion,
            async close() { cleanup(); await session.close() } }
          sessions.add(connection)
          void session.completion.finally(cleanup).catch(() => undefined)
          return connection
        } catch (error) { detachSignals?.(); detach?.(); await session.close(); throw error }

      } catch (error) { await input.connection.close(); throw error }
      finally { opening.delete(input.connection) }
    },
    async close() { closed = true; await Promise.allSettled([...sessions, ...opening].map(session => session.close())) },
  }
}

import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import type { EnrollmentIdentity } from '@chronolog/node-core/browser'
import { base64UrlToBytes, bytesToHex, equalBytes } from '@chronolog/protocol'
import type { PortableFeedTransport } from '@chronolog/records'

import type { BrowserEventBootstrap } from './event-contract.js'

/** A real reliable loopback stream for qualification; no feed or evidence bypass. */
export async function openHttpPeerConnection(base: string, token: string): Promise<FramedPeerConnection> {
  const controller = new AbortController()
  const url = new URL(`${base}/${crypto.randomUUID()}`)
  url.searchParams.set('token', token)
  const response = await fetch(url, { signal: controller.signal })
  if (!response.ok || response.body === null) throw new Error(`PEER_STREAM_OPEN_FAILED: ${response.status}`)
  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    controller.abort()
    try { await fetch(url, { method: 'DELETE' }) } catch { /* The server also observes stream cancellation. */ }
  }
  const connection = framePeerStream({ readable: response.body, writable: new WritableStream<Uint8Array>({
    async write(bytes) {
      const reply = await fetch(url, { method: 'POST', body: bytes.slice().buffer, signal: controller.signal })
      if (!reply.ok) throw new Error(`PEER_STREAM_WRITE_FAILED: ${reply.status}`)
    },
    close,
    abort: close,
  }) })
  return { send: (bytes) => connection.send(bytes), frames: (signal) => connection.frames(signal),
    async close() { await connection.close(); await close() } }
}

export async function connectGovernedBrowserPeer(options: {
  readonly bootstrap: Pick<BrowserEventBootstrap, 'peerUrl' | 'peerToken' | 'nativeIdentity'>
  readonly identity: EnrollmentIdentity
  readonly transport: PortableFeedTransport
  readonly activeMembership: () => CapabilitySnapshot
  readonly receiveSignal?: (frame: Uint8Array) => Promise<void>
}) {
  const snapshot = options.activeMembership()
  const reader = [...snapshot.capabilities.values()].find((capability) => capability.grant.role === 'reader' &&
    isCapabilityActive(capability, snapshot.revision) && equalBytes(capability.grant.signingPublicKey, options.identity.signing.publicKeyBytes))
  if (reader === undefined) throw new Error('BROWSER_READER_GRANT_MISSING')
  const started = performance.now()
  const connection = await openHttpPeerConnection(options.bootstrap.peerUrl, options.bootstrap.peerToken)
  const session = await openAuthenticatedPeerLink({
    connection,
    local: options.transport.asLink(), identity: options.identity.signing, groupId: snapshot.groupId, grantId: reader.id,
    ...(options.receiveSignal === undefined ? {} : { receiveSignal: options.receiveSignal }),
    authorizePeer: ({ authorId, grantId }) => {
      const current = options.activeMembership(), capability = current.capabilities.get(bytesToHex(grantId))
      return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, current.revision) &&
        equalBytes(capability.grant.signingPublicKey, authorId) && equalBytes(authorId, base64UrlToBytes(options.bootstrap.nativeIdentity))
    },
  })
  const detach = options.transport.connect(session.link)
  void session.completion.finally(detach).catch(() => undefined)
  const authenticatedMs = performance.now() - started
  return { completion: session.completion, sendSignal: (bytes: Uint8Array) => session.sendSignal(bytes),
    stats: () => ({ route: 'http-fixture', authenticatedMs }),
    async close() { detach(); await session.close() } }
}

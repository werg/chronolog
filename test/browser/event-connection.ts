import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'
import type { GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { base64UrlToBytes } from '@chronolog/protocol'

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
  readonly peer: Pick<GovernedPeerService, 'connectPeer'>
}) {
  const started = performance.now()
  const connection = await openHttpPeerConnection(options.bootstrap.peerUrl, options.bootstrap.peerToken)
  try {
    const session = await options.peer.connectPeer({ connection, peerIdentity: base64UrlToBytes(options.bootstrap.nativeIdentity) })
    const authenticatedMs = performance.now() - started
    return { ...session, stats: () => ({ route: 'http-fixture', authenticatedMs }) }
  } catch (error) { await connection.close(); throw error }
}

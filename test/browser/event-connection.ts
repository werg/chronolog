import { frameLivePeerStream, framePeerStream, type FramedPeerConnection, type PeerLiveLane, type PeerStreamOptions } from '@chronolog/agent-service/framing'
import type { GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { base64UrlToBytes } from '@chronolog/protocol'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'

import type { BrowserEventBootstrap } from './event-contract.js'

/** Independent loopback streams for qualification; no feed or evidence bypass. */
export async function openHttpPeerConnection(base: string, token: string): Promise<FramedPeerConnection> {
  const controller = new AbortController(), connections = new Set<FramedPeerConnection | PeerLiveLane>()
  const root = `${base}/${crypto.randomUUID()}`
  const urlFor = (lane: string): URL => {
    const url = new URL(`${root}/${lane}`)
    url.searchParams.set('token', token)
    return url
  }
  let closed = false
  const close = async () => {
    if (closed) return
    closed = true
    controller.abort(new Error('PEER_CONNECTION_CLOSED'))
    await Promise.allSettled([...connections].map(connection => connection.close()))
    try { await fetch(urlFor('reliable'), { method: 'DELETE' }) } catch { /* The server also observes stream cancellation. */ }
  }
  function open(lane: 'reliable'): Promise<FramedPeerConnection>
  function open(lane: 'live'): Promise<PeerLiveLane>
  async function open(lane: 'reliable' | 'live'): Promise<FramedPeerConnection | PeerLiveLane> {
    const url = urlFor(lane), response = await fetch(url, { signal: controller.signal })
    if (!response.ok || response.body === null) throw new Error(`PEER_STREAM_OPEN_FAILED: ${response.status}`)
    const stream: PeerStreamOptions = { readable: response.body,
      ...(lane === 'live' ? { maxFrameBytes: MAX_SIGNAL_BYTES } : {}),
      writable: new WritableStream<Uint8Array>({
        async write(bytes) {
          const reply = await fetch(url, { method: 'POST', body: bytes.slice().buffer, signal: controller.signal })
          if (!reply.ok) throw new Error(`PEER_STREAM_WRITE_FAILED: ${reply.status}`)
        }, close, abort: close,
      }) }
    const connection = lane === 'live' ? frameLivePeerStream(stream) : framePeerStream(stream)
    connections.add(connection)
    if (controller.signal.aborted) { await connection.close(); controller.signal.throwIfAborted() }
    return connection
  }
  try {
    const [reliable, live] = await Promise.all([open('reliable'), open('live')])
    const signal = AbortSignal.any([reliable.signal, live.signal, controller.signal])
    signal.addEventListener('abort', () => { void close() }, { once: true })
    if (signal.aborted) { await close(); signal.throwIfAborted() }
    return { signal, send: (bytes, options) => reliable.send(bytes, options), frames: signal => reliable.frames(signal), live, close }
  } catch (error) { await close(); throw error }
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

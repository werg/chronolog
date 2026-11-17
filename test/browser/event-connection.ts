import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'

/** Separate reliable/live loopback paths for qualification, with no feed/evidence bypass. */
export async function openHttpPeerConnection(base: string, token: string, signal?: AbortSignal): Promise<FramedPeerConnection> {
  const controller = new AbortController()
  const lifetime = signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal])
  lifetime.throwIfAborted()
  const url = new URL(`${base}/${crypto.randomUUID()}`)
  url.searchParams.set('token', token)
  const lanes = new Set<FramedPeerConnection>()
  let closed = false
  const abort = (): void => { void close() }
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true
    lifetime.removeEventListener('abort', abort)
    controller.abort(new Error('PEER_CONNECTION_CLOSED'))
    await Promise.allSettled([...lanes].map(lane => lane.close()))
    try { await fetch(url, { method: 'DELETE' }) } catch { /* The server also observes stream cancellation. */ }
  }
  lifetime.addEventListener('abort', abort, { once: true })
  const open = async (name: 'reliable' | 'live'): Promise<FramedPeerConnection> => {
    const laneUrl = new URL(url); laneUrl.pathname += `/${name}`
    const response = await fetch(laneUrl, { signal: lifetime })
    if (!response.ok || response.body === null) throw new Error(`PEER_STREAM_OPEN_FAILED: ${response.status}`)
    const connection = framePeerStream({ readable: response.body,
      ...(name === 'live' ? { maxFrameBytes: MAX_SIGNAL_BYTES, maxPendingSends: 1 } : {}),
      writable: new WritableStream<Uint8Array>({
        async write(bytes) {
          const reply = await fetch(laneUrl, { method: 'POST', body: bytes.slice().buffer, signal: lifetime })
          if (!reply.ok) throw new Error(`PEER_STREAM_WRITE_FAILED: ${reply.status}`)
        }, close, abort: close,
      }) })
    lanes.add(connection)
    if (lifetime.aborted) { await connection.close(); lifetime.throwIfAborted() }
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

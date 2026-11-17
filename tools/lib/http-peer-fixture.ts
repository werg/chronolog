import { once } from 'node:events'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'

import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'

type Lane = 'reliable' | 'live'
interface OwnedSession { readonly completion: Promise<void>; close(): Promise<void> }
interface StreamLane { readonly writer: WritableStreamDefaultWriter<Uint8Array>; readonly connection: FramedPeerConnection }
interface PairedStream { readonly lanes: Map<Lane, StreamLane>; start(): void; close(): Promise<void> }

/** Loopback qualification transport: independent streams, one authenticated owner. */
export async function createHttpPeerFixture(options: {
  readonly accept: (connection: FramedPeerConnection) => Promise<OwnedSession>
  readonly onError: (error: unknown) => void
}) {
  const token = crypto.randomUUID(), sessions = new Map<string, PairedStream>()
  const reportFailure = (error: unknown): void => {
    // Peer failure closes both lanes before its completion rejects. That cleanup
    // must not hide malformed traffic or failed authorization from qualification.
    if (error instanceof Error && (error.message === 'PEER_CONNECTION_CLOSED' || error.message === 'PEER_CONNECTION_ENDED')) return
    options.onError(error)
  }
  const pair = (id: string): PairedStream => {
    const lanes = new Map<Lane, StreamLane>()
    let closed = false, session: OwnedSession | undefined
    const timer = setTimeout(() => { void close() }, 10_000)
    const close = async (): Promise<void> => {
      if (closed) return
      closed = true; clearTimeout(timer); sessions.delete(id)
      await Promise.allSettled([...lanes.values()].flatMap(lane => [lane.connection.close(), lane.writer.abort()]).concat(session?.close() ?? []))
    }
    return { lanes, close, start() {
      if (closed || lanes.size !== 2) return
      clearTimeout(timer)
      const reliable = lanes.get('reliable')!.connection, live = lanes.get('live')!.connection
      const signal = AbortSignal.any([reliable.signal, live.signal])
      signal.addEventListener('abort', () => { void close() }, { once: true })
      if (signal.aborted) { void close(); return }
      const connection: FramedPeerConnection = { signal, send: (frame, options) => reliable.send(frame, options),
        frames: signal => reliable.frames(signal), live, close }
      void options.accept(connection).then(value => {
        session = value
        void value.completion.catch(reportFailure).finally(close)
        if (closed) void value.close()
      }, (error: unknown) => { reportFailure(error); void close() })
    } }
  }
  const server = createServer((request, response) => {
    response.setHeader('Access-Control-Allow-Origin', '*')
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    response.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
    response.setHeader('Cache-Control', 'no-store')
    if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return }
    const handle = async (): Promise<void> => {
      const url = new URL(request.url ?? '/', 'http://localhost')
      const matched = /^\/peer\/([a-z0-9-]{36})\/(reliable|live)$/u.exec(url.pathname)
      if (matched === null || url.searchParams.get('token') !== token) { response.writeHead(403); response.end(); return }
      const id = matched[1]!, lane = matched[2] as Lane
      const maximum = lane === 'live' ? MAX_SIGNAL_BYTES : 1_048_576 + 65_536
      if (request.method === 'GET') {
        let owner = sessions.get(id)
        if (owner?.lanes.has(lane) === true) { response.writeHead(409); response.end(); return }
        if (owner === undefined) {
          if (sessions.size >= 16) { response.writeHead(429); response.end(); return }
          owner = pair(id); sessions.set(id, owner)
        }
        response.writeHead(200, { 'Content-Type': 'application/octet-stream' }); response.flushHeaders()
        const incoming = new TransformStream<Uint8Array, Uint8Array>(), writer = incoming.writable.getWriter()
        const connection = framePeerStream({ readable: incoming.readable, maxFrameBytes: maximum,
          writable: new WritableStream<Uint8Array>({ write: bytes => writeStream(response, bytes),
            close: () => { response.end() }, abort: () => { response.destroy() } }) })
        owner.lanes.set(lane, { writer, connection })
        response.on('close', () => { void owner.close() })
        owner.start()
      } else {
        const owner = sessions.get(id), stream = owner?.lanes.get(lane)
        if (owner === undefined || stream === undefined) { response.writeHead(410); response.end(); return }
        if (request.method === 'POST') await stream.writer.write(await boundedBody(request, maximum + 4))
        else if (request.method === 'DELETE') await owner.close()
        else { response.writeHead(405); response.end(); return }
        response.writeHead(204); response.end()
      }
    }
    void handle().catch((error: unknown) => {
      if (!response.headersSent) { response.writeHead(500); response.end(error instanceof Error ? error.message : String(error)) }
      else response.destroy()
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('BROWSER_FIXTURE_ADDRESS_UNAVAILABLE')
  let closed = false
  return { url: `http://127.0.0.1:${address.port}/peer`, token, async close() {
    if (closed) return
    closed = true
    await Promise.all([...sessions.values()].map(session => session.close()))
    server.closeAllConnections()
    await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
  } }
}

async function boundedBody(request: IncomingMessage, maximum: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let length = 0
  for await (const chunk of request) {
    const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : new Uint8Array(chunk as Uint8Array)
    length += bytes.length
    if (length > maximum) throw new Error('PEER_HTTP_FRAME_TOO_LARGE')
    chunks.push(bytes)
  }
  if (length === 0) throw new Error('PEER_HTTP_FRAME_EMPTY')
  const body = new Uint8Array(length)
  let offset = 0
  for (const bytes of chunks) { body.set(bytes, offset); offset += bytes.length }
  return body
}

function writeStream(response: ServerResponse, bytes: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    response.write(bytes, error => error === undefined || error === null ? resolve() : reject(error))
  })
}

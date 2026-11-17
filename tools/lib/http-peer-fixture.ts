import type { IncomingMessage, ServerResponse } from 'node:http'

import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'
import { isExpectedPeerTermination } from './peer-termination.js'

type LaneName = 'reliable' | 'live'
interface HttpLane { readonly writer: WritableStreamDefaultWriter<Uint8Array>; readonly connection: FramedPeerConnection }

/** Two independent loopback byte lanes; the supplied handshake authenticates the peer. */
export function createHttpPeerFixture(options: {
  readonly token: string
  readonly connect: (connection: FramedPeerConnection) => Promise<{
    readonly completion: Promise<void>
    close(): Promise<void>
  }>
}) {
  interface Session { readonly lanes: Partial<Record<LaneName, HttpLane>>; readonly start: () => void; close(): Promise<void> }
  const sessions = new Map<string, Session>()
  let failure: Error | undefined
  const create = (id: string): Session => {
    const lanes: Session['lanes'] = {}
    let peer: Awaited<ReturnType<typeof options.connect>> | undefined, closed = false, started = false
    const timer = setTimeout(() => { void close() }, 10_000)
    const close = async (): Promise<void> => {
      if (closed) return
      closed = true; clearTimeout(timer); sessions.delete(id)
      await Promise.allSettled(Object.values(lanes).flatMap(lane => [lane.connection.close(), lane.writer.abort()]).concat(peer?.close() ?? []))
    }
    const failed = (error: unknown): void => {
      if (!isExpectedPeerTermination(error)) failure ??= error instanceof Error ? error : new Error('PEER_HTTP_SESSION_FAILED', { cause: error })
    }
    const session: Session = { lanes, close, start() {
      const reliable = lanes.reliable, live = lanes.live
      if (started || closed || reliable === undefined || live === undefined) return
      started = true; clearTimeout(timer)
      const signal = AbortSignal.any([reliable.connection.signal, live.connection.signal])
      signal.addEventListener('abort', () => { void close() }, { once: true })
      if (signal.aborted) { void close(); return }
      const connection: FramedPeerConnection = { signal, send: (frame, options) => reliable.connection.send(frame, options),
        frames: signal => reliable.connection.frames(signal), live: live.connection, close }
      void options.connect(connection).then(value => {
        peer = value
        // Physical cleanup may precede completion rejection; still retain its cause.
        void value.completion.catch(failed).finally(close)
        if (closed) void value.close()
      }, error => { failed(error); void close() })
    } }
    return session
  }
  return {
    async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
      const url = new URL(request.url ?? '/', 'http://localhost')
      if (!url.pathname.startsWith('/peer/')) return false
      const match = /^\/peer\/([a-z0-9-]{36})(?:\/(reliable|live))?$/u.exec(url.pathname)
      const id = match?.[1], laneName = match?.[2] as LaneName | undefined
      if (id === undefined || url.searchParams.get('token') !== options.token ||
          (laneName === undefined && request.method !== 'DELETE')) {
        response.writeHead(403); response.end(); return true
      }
      if (request.method === 'GET') {
        let session = sessions.get(id)
        if (session?.lanes[laneName!] !== undefined) { response.writeHead(409); response.end(); return true }
        if (session === undefined) {
          if (sessions.size >= 16) { response.writeHead(429); response.end(); return true }
          session = create(id); sessions.set(id, session)
        }
        response.writeHead(200, { 'Content-Type': 'application/octet-stream' }); response.flushHeaders()
        const incoming = new TransformStream<Uint8Array, Uint8Array>(), writer = incoming.writable.getWriter()
        const connection = framePeerStream({ readable: incoming.readable,
          ...(laneName === 'live' ? { maxFrameBytes: MAX_SIGNAL_BYTES, maxPendingSends: 1 } : {}),
          writable: new WritableStream<Uint8Array>({
            write: bytes => new Promise<void>((resolve, reject) => { response.write(bytes, error => error == null ? resolve() : reject(error)) }),
            close() { response.end() }, abort() { response.destroy() },
          }) })
        session.lanes[laneName!] = { writer, connection }
        response.once('close', () => { void session.close() })
        session.start()
      } else {
        const session = sessions.get(id)
        if (session === undefined) { response.writeHead(410); response.end(); return true }
        if (request.method === 'POST') {
          const lane = session.lanes[laneName!]
          if (lane === undefined) { response.writeHead(410); response.end(); return true }
          const chunks: Uint8Array[] = []
          let length = 0
          for await (const chunk of request) {
            const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : Uint8Array.from(chunk as Uint8Array)
            length += bytes.length
            if (length > (laneName === 'live' ? MAX_SIGNAL_BYTES + 4 : 1_048_576 + 65_536 + 4)) throw new Error('PEER_HTTP_FRAME_TOO_LARGE')
            chunks.push(bytes)
          }
          if (length === 0) throw new Error('PEER_HTTP_FRAME_EMPTY')
          const bytes = new Uint8Array(length)
          let offset = 0
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
          await lane.writer.write(bytes)
        } else if (request.method === 'DELETE') await session.close()
        else { response.writeHead(405); response.end(); return true }
        response.writeHead(204); response.end()
      }
      return true
    },
    assertHealthy() { if (failure !== undefined) throw failure },
    async close() { await Promise.all([...sessions.values()].map(session => session.close())) },
  }
}

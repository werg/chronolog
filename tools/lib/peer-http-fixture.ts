import type { IncomingMessage, ServerResponse } from 'node:http'

import { framePeerStream, type FramedPeerConnection } from '@chronolog/agent-service/framing'

/** HTTP carries reliable bytes; the supplied peer handshake authenticates readers. */
export function createPeerHttpFixture(options: {
  readonly token: string
  readonly connect: (connection: FramedPeerConnection) => Promise<{
    readonly completion: Promise<void>
    close(): Promise<void>
  }>
}) {
  const sessions = new Map<string, { readonly writer: WritableStreamDefaultWriter<Uint8Array>; close(): Promise<void> }>()
  const failures: Error[] = []
  return {
    async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
      const url = new URL(request.url ?? '/', 'http://localhost')
      if (!url.pathname.startsWith('/peer/')) return false
      const id = /^\/peer\/([a-z0-9-]{36})$/u.exec(url.pathname)?.[1]
      if (id === undefined || url.searchParams.get('token') !== options.token) {
        response.writeHead(403); response.end(); return true
      }
      if (request.method === 'GET') {
        if (sessions.has(id)) { response.writeHead(409); response.end(); return true }
        if (sessions.size >= 16) { response.writeHead(429); response.end(); return true }
        response.writeHead(200, { 'Content-Type': 'application/octet-stream' }); response.flushHeaders()
        const incoming = new TransformStream<Uint8Array, Uint8Array>(), writer = incoming.writable.getWriter()
        const connection = framePeerStream({ readable: incoming.readable, writable: new WritableStream<Uint8Array>({
          write: bytes => new Promise<void>((resolve, reject) => {
            response.write(bytes, error => error == null ? resolve() : reject(error))
          }),
          close() { response.end() }, abort() { response.destroy() },
        }) })
        let peer: Awaited<ReturnType<typeof options.connect>> | undefined
        let closed = false
        const close = async () => {
          if (closed) return
          closed = true; sessions.delete(id)
          await Promise.allSettled([connection.close(), writer.abort(), peer?.close()])
        }
        sessions.set(id, { writer, close })
        response.once('close', () => { void close() })
        const failed = (error: unknown) => {
          if (!closed) failures.push(error instanceof Error ? error : new Error('PEER_HTTP_SESSION_FAILED', { cause: error }))
        }
        void options.connect(connection).then(value => {
          peer = value
          if (closed) { void value.close(); return }
          void value.completion.catch(failed).finally(close)
        }, error => { failed(error); void close() })
      } else {
        const session = sessions.get(id)
        if (session === undefined) { response.writeHead(410); response.end(); return true }
        if (request.method === 'POST') {
          const chunks: Uint8Array[] = []
          let length = 0
          for await (const chunk of request) {
            const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : Uint8Array.from(chunk as Uint8Array)
            length += bytes.length
            if (length > 2 * 1024 * 1024) throw new Error('PEER_HTTP_FRAME_TOO_LARGE')
            chunks.push(bytes)
          }
          if (length === 0) throw new Error('PEER_HTTP_FRAME_EMPTY')
          const bytes = new Uint8Array(length)
          let offset = 0
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
          await session.writer.write(bytes)
        } else if (request.method === 'DELETE') await session.close()
        else { response.writeHead(405); response.end(); return true }
        response.writeHead(204); response.end()
      }
      return true
    },
    assertHealthy() { const failure = failures[0]; if (failure !== undefined) throw failure },
    async close() { await Promise.all([...sessions.values()].map(session => session.close())) },
  }
}

import { createServer } from 'node:https'
import type { Server, ServerOptions } from 'node:https'
import { Readable } from 'node:stream'

import { createWebRtcOfferHandler } from './http.js'
import type { WebRtcOfferHandler } from './http.js'
import { createNativePeerConnection } from './native.js'
import type { NativeRtcOptions } from './native.js'

export type WebRtcHttpsListenerOptions = Omit<Parameters<typeof createWebRtcOfferHandler>[0], 'createPeerConnection'> & {
  readonly endpoint: string
  readonly listen: { readonly host: string; readonly port: number }
  readonly tls: Pick<ServerOptions, 'key' | 'cert'>
  readonly nativeOptions?: NativeRtcOptions
}

export interface WebRtcHttpsListener {
  readonly stats: WebRtcOfferHandler['stats'] | null
  /** Own the listener and all accepted peers until this lifetime ends. */
  run(signal: AbortSignal): Promise<void>
}

/**
 * Node-only HTTPS adapter for a resident peer's one-request introduction port.
 * Deployment supplies TLS, admission and origins. The accept port authenticates
 * the resulting peer independently; HTTP admission is never a database grant.
 */
export function createWebRtcHttpsListener(options: WebRtcHttpsListenerOptions): WebRtcHttpsListener {
  const url = new URL(options.endpoint)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new TypeError('The resident endpoint must be an explicit HTTPS URL without credentials, query or fragment')
  }
  const { listen, tls } = options
  if (typeof listen?.host !== 'string' || !listen.host || !Number.isInteger(listen.port) || listen.port < 1 || listen.port > 65535) {
    throw new TypeError('An explicit resident HTTPS listen host and port are required')
  }
  if (!tls?.key || !tls.cert) throw new TypeError('The resident HTTPS listener requires its deployment TLS key and certificate')
  const observe = (error: unknown): void => {
    try { void Promise.resolve(options.onError?.(error)).catch(() => undefined) }
    catch { /* Observability must not retain a failed request. */ }
  }
  let service: WebRtcOfferHandler | undefined, running = false
  return {
    get stats() { return service?.stats ?? null },
    async run(signal) {
      if (running) throw new Error('Resident WebRTC listener is already running')
      signal.throwIfAborted()
      service = createWebRtcOfferHandler({ ...options, onError: observe,
        createPeerConnection: configuration => createNativePeerConnection(configuration, options.nativeOptions) })
      const handler = service
      running = true
      const listening = new AbortController()
      let server: Server | undefined, stop: (() => void) | undefined
      try {
        server = createServer({ ...tls, maxHeaderSize: 16 * 1024 }, (request, response) => {
          if (request.url !== url.pathname) {
            response.writeHead(404, { Connection: 'close' }); response.end(); return
          }
          const controller = new AbortController()
          const aborted = (): void => { controller.abort(new Error('Resident introduction HTTP request disconnected')) }
          const responseClosed = (): void => { if (!response.writableFinished) aborted() }
          request.once('aborted', aborted); response.once('close', responseClosed)
          const run = async (): Promise<void> => {
            const headers = new Headers()
            for (let index = 0; index < request.rawHeaders.length; index += 2) headers.append(request.rawHeaders[index]!, request.rawHeaders[index + 1]!)
            const method = request.method ?? 'GET'
            const input = new Request(url, { method, headers, signal: controller.signal,
              ...(method === 'GET' || method === 'HEAD' ? {} : { body: Readable.toWeb(request) as ReadableStream<Uint8Array>, duplex: 'half' }) })
            const result = await handler.fetch(input)
            const outputHeaders: Record<string, string> = {}
            result.headers.forEach((value, name) => { outputHeaders[name] = value })
            response.writeHead(result.status, { ...outputHeaders, ...(result.status >= 400 ? { Connection: 'close' } : {}) })
            response.end(Buffer.from(await result.arrayBuffer()))
          }
          void run().catch((error: unknown) => {
            observe(error)
            if (response.headersSent) response.destroy()
            else { response.writeHead(500, { Connection: 'close' }); response.end() }
          }).finally(() => {
            request.removeListener('aborted', aborted); response.removeListener('close', responseClosed)
          })
        })
        server.headersTimeout = 10_000
        server.requestTimeout = options.timeoutMs ?? 30_000
        server.keepAliveTimeout = 5_000
        server.maxConnections = 64
        const listener = server
        await new Promise<void>((resolve, reject) => {
          stop = () => { listening.abort(); listener.closeAllConnections(); resolve() }
          signal.addEventListener('abort', stop, { once: true })
          listener.once('error', reject)
          listener.once('close', resolve)
          // Abort also cancels an in-flight bind or hostname lookup.
          listener.listen({ ...listen, signal: listening.signal })
          if (signal.aborted) stop()
        })
      } finally {
        if (stop !== undefined) signal.removeEventListener('abort', stop)
        listening.abort()
        server?.closeAllConnections()
        if (server?.listening === true) await new Promise<void>(resolve => server!.close(() => resolve()))
        // An ordinary HTTP response never enters this owner-lifetime cleanup.
        try { await handler.close() } finally { running = false }
      }
    },
  }
}

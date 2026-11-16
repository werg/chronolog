import {
  ChronologRpcError, toChronologRpcError,
  type RpcCallOptions, type RpcTransport, type StreamRequest, type StreamResponse,
  type StreamRpcMethod, type UnaryRequest, type UnaryResponse, type UnaryRpcMethod,
} from '@chronolog/rpc/browser'

/** A dedicated Worker or one explicitly transferred MessagePort. */
export interface WorkerEndpoint {
  postMessage(value: unknown): void
  addEventListener(type: 'message' | 'messageerror', listener: (event: MessageEvent) => void): void
  removeEventListener(type: 'message' | 'messageerror', listener: (event: MessageEvent) => void): void
  start?(): void
}

const PROTOCOL = 'chronolog-worker-v1'
interface Request {
  readonly protocol: typeof PROTOCOL
  readonly id: number
  readonly kind: 'unary' | 'stream' | 'pull' | 'cancel' | 'close'
  readonly method?: UnaryRpcMethod | StreamRpcMethod
  readonly request?: unknown
  readonly options?: { readonly token?: string; readonly timeoutMs?: number }
}
interface Response {
  readonly protocol: typeof PROTOCOL
  readonly id: number
  readonly value?: unknown
  readonly error?: { readonly code: ChronologRpcError['code']; readonly message: string; readonly retryable: boolean; readonly details?: Readonly<Record<string, string>> }
}

/** Runs the ordinary public RPC contract against the database owned by this Worker. */
export function serveWorkerRpc(endpoint: WorkerEndpoint, transport: RpcTransport, closePeer: () => Promise<void>): () => Promise<void> {
  const controllers = new Map<number, AbortController>()
  const streams = new Map<number, AsyncIterator<unknown>>()
  let closed = false
  const respond = (id: number, value: unknown): void => { endpoint.postMessage({ protocol: PROTOCOL, id, value } satisfies Response) }
  const cancel = async (id: number): Promise<void> => {
    controllers.get(id)?.abort()
    controllers.delete(id)
    const stream = streams.get(id)
    streams.delete(id)
    await stream?.return?.().catch(() => undefined)
  }
  const close = async (): Promise<void> => {
    if (closed) return
    closed = true
    endpoint.removeEventListener('message', onMessage)
    await Promise.all([...controllers.keys()].map(cancel))
    await transport.close?.()
    await closePeer()
  }
  const handle = async (message: Request): Promise<void> => {
    if (message.kind === 'cancel') { await cancel(message.id); return }
    if (message.kind === 'close') { await close(); respond(message.id, null); return }
    if (closed) throw new ChronologRpcError('transport_unavailable', 'Browser peer is closed')
    if (message.kind === 'pull') {
      const iterator = streams.get(message.id)
      if (iterator === undefined) throw new ChronologRpcError('invalid_argument', 'Unknown Worker stream')
      const result = await iterator.next()
      if (result.done) await cancel(message.id)
      respond(message.id, result)
      return
    }
    if (controllers.has(message.id)) throw new ChronologRpcError('invalid_argument', 'Duplicate Worker request')
    const controller = new AbortController()
    controllers.set(message.id, controller)
    const options = { ...message.options, signal: controller.signal }
    if (message.kind === 'stream') {
      const iterator = transport.stream(message.method as StreamRpcMethod, message.request as StreamRequest<StreamRpcMethod>, options)[Symbol.asyncIterator]()
      streams.set(message.id, iterator)
      respond(message.id, null)
    } else {
      try { respond(message.id, await transport.unary(message.method as UnaryRpcMethod, message.request as UnaryRequest<UnaryRpcMethod>, options)) }
      finally { controllers.delete(message.id) }
    }
  }
  const onMessage = (event: MessageEvent): void => {
    const message = event.data as Partial<Request> | null
    if (message?.protocol !== PROTOCOL || !Number.isSafeInteger(message.id) || message.id! < 1 ||
        !['unary', 'stream', 'pull', 'cancel', 'close'].includes(message.kind ?? '')) return
    void handle(message as Request).catch(async (cause: unknown) => {
      await cancel(message.id!)
      const error = toChronologRpcError(cause)
      endpoint.postMessage({ protocol: PROTOCOL, id: message.id!, error: {
        code: error.code, message: error.message, retryable: error.retryable,
        ...(error.details === undefined ? {} : { details: error.details }),
      } } satisfies Response)
    })
  }
  endpoint.addEventListener('message', onMessage)
  endpoint.start?.()
  return close
}

/** Use with ChronologClient unchanged: queries execute in the local owned Worker. */
export class WorkerRpcTransport implements RpcTransport {
  readonly #endpoint: WorkerEndpoint
  readonly #pending = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
  #nextId = 1
  #closed = false
  readonly #onMessage = (event: MessageEvent): void => {
    const message = event.data as Partial<Response> | null
    if (message?.protocol !== PROTOCOL || typeof message.id !== 'number') return
    const waiting = this.#pending.get(message.id)
    if (waiting === undefined) return
    this.#pending.delete(message.id)
    if (message.error !== undefined) waiting.reject(new ChronologRpcError(message.error.code, message.error.message, message.error))
    else waiting.resolve(message.value)
  }
  readonly #onMessageError = (): void => { this.#fail(new ChronologRpcError('transport_unavailable', 'Worker message could not be received')) }

  constructor(endpoint: WorkerEndpoint) {
    this.#endpoint = endpoint
    endpoint.addEventListener('message', this.#onMessage)
    endpoint.addEventListener('messageerror', this.#onMessageError)
    endpoint.start?.()
  }

  async unary<M extends UnaryRpcMethod>(method: M, request: UnaryRequest<M>, options: RpcCallOptions = {}): Promise<UnaryResponse<M>> {
    return this.#request({ protocol: PROTOCOL, id: this.#nextId++, kind: 'unary', method, request, options: wireOptions(options) }, options) as Promise<UnaryResponse<M>>
  }

  stream<M extends StreamRpcMethod>(method: M, request: StreamRequest<M>, options: RpcCallOptions = {}): AsyncIterable<StreamResponse<M>> {
    const self = this
    return {
      async *[Symbol.asyncIterator]() {
        const id = self.#nextId++
        try {
          await self.#request({ protocol: PROTOCOL, id, kind: 'stream', method, request, options: wireOptions(options) }, options)
          for (;;) {
            // Pull only when the caller advances. Live SQL never queues an
            // unbounded series of result sets in the page or Worker bridge.
            const result = await self.#request({ protocol: PROTOCOL, id, kind: 'pull' }, options) as IteratorResult<StreamResponse<M>>
            if (result.done) return
            yield result.value
          }
        } finally { self.#endpoint.postMessage({ protocol: PROTOCOL, id, kind: 'cancel' } satisfies Request) }
      },
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return
    try { await this.#request({ protocol: PROTOCOL, id: this.#nextId++, kind: 'close' }, { timeoutMs: 30_000 }) }
    finally {
      this.#closed = true
      this.#endpoint.removeEventListener('message', this.#onMessage)
      this.#endpoint.removeEventListener('messageerror', this.#onMessageError)
      this.#fail(new ChronologRpcError('transport_unavailable', 'Worker transport is closed'))
    }
  }

  #request(message: Request, options: RpcCallOptions): Promise<unknown> {
    if (this.#closed) return Promise.reject(new ChronologRpcError('transport_unavailable', 'Worker transport is closed'))
    if (options.signal?.aborted) return Promise.reject(new ChronologRpcError('cancelled', 'Worker call was cancelled'))
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined
      const clean = (): void => { options.signal?.removeEventListener('abort', abort); if (timer !== undefined) clearTimeout(timer) }
      const abort = (): void => {
        clean(); this.#pending.delete(message.id)
        this.#endpoint.postMessage({ protocol: PROTOCOL, id: message.id, kind: 'cancel' } satisfies Request)
        reject(new ChronologRpcError('cancelled', 'Worker call was cancelled'))
      }
      this.#pending.set(message.id, {
        resolve: (value) => { clean(); resolve(value) },
        reject: (error) => { clean(); reject(error) },
      })
      options.signal?.addEventListener('abort', abort, { once: true })
      if (options.timeoutMs !== undefined) timer = setTimeout(() => {
        clean(); this.#pending.delete(message.id)
        this.#endpoint.postMessage({ protocol: PROTOCOL, id: message.id, kind: 'cancel' } satisfies Request)
        reject(new ChronologRpcError('deadline_exceeded', 'Worker call deadline exceeded'))
      }, options.timeoutMs)
      try { this.#endpoint.postMessage(message) } catch (error) { this.#pending.delete(message.id); clean(); reject(error) }
    })
  }

  #fail(error: unknown): void {
    for (const pending of this.#pending.values()) pending.reject(error)
    this.#pending.clear()
  }
}

function wireOptions(options: RpcCallOptions): { readonly token?: string; readonly timeoutMs?: number } {
  return {
    ...(options.token === undefined ? {} : { token: options.token }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  }
}

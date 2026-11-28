import { check } from '@chronolog/authority'
import {
  assertContentManifest, assertContentReference, assertContentRetention, CONTENT_CHUNK_BYTES,
  MAX_BLOB_BYTES, MAX_BLOB_CHUNKS, MAX_CONTENT_CHUNKS, MAX_CONTENT_ENCRYPTED_CHUNK_BYTES,
  type ApplicationContent, type BlobIndex, type ChunkSink, type ContentManifest, type ContentOptions, type ContentReference, type ContentRetention,
} from './content.js'
import { awaitOwnedTask } from './lifetime.js'

/**
 * Content RPC v2: raw `Uint8Array` chunks (the peer wire is binary CBOR), range requests answered
 * by a stream of one `*-chunk-response` per chunk, and at most `pending`/`active` requests per peer.
 * `timeoutMs` is an inactivity timeout: every streamed chunk re-arms it.
 */
export const CONTENT_NETWORK_LIMITS = Object.freeze({ pending: 16, active: 16, rangeChunks: 16, timeoutMs: 30_000,
  chunkBytes: MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, blobNodes: 64, blobNodeBytes: 16 * 1024 })
type Action = 'manifest' | 'chunks' | 'retain' | 'blob-info' | 'blob-chunks'
export type ContentWireMessage =
  | { readonly type: 'manifest-request'; readonly id: string; readonly reference: ContentReference }
  | { readonly type: 'chunks-request'; readonly id: string; readonly reference: ContentReference; readonly start: number; readonly count: number }
  | { readonly type: 'retain-request'; readonly id: string; readonly reference: ContentReference }
  | { readonly type: 'blob-info-request'; readonly id: string; readonly hash: string }
  | { readonly type: 'blob-chunks-request'; readonly id: string; readonly hash: string; readonly start: number; readonly count: number }
  | { readonly type: 'manifest-response'; readonly id: string; readonly manifest: ContentManifest | null }
  | { readonly type: 'chunk-response'; readonly id: string; readonly index: number; readonly bytes: Uint8Array | null }
  | { readonly type: 'retain-response'; readonly id: string; readonly receipt: ContentRetention }
  | { readonly type: 'blob-info-response'; readonly id: string; readonly bytes: number | null; readonly nodes: readonly Uint8Array[] }
  | { readonly type: 'blob-chunk-response'; readonly id: string; readonly index: number; readonly bytes: Uint8Array | null }
  | { readonly type: 'error'; readonly id: string; readonly code: 'CONTENT_UNAVAILABLE' | 'CONTENT_FORBIDDEN' | 'CONTENT_BUSY' }
  | { readonly type: 'cancel'; readonly id: string }
type IncomingRequest = Extract<ContentWireMessage, { type: 'manifest-request' | 'chunks-request' | 'retain-request' | 'blob-info-request' | 'blob-chunks-request' }>
type Reply = Extract<ContentWireMessage, { type: 'manifest-response' | 'chunk-response' | 'retain-response' | 'blob-info-response' | 'blob-chunk-response' | 'error' }>
const RESPONSE: Record<Action, Reply['type']> = {
  manifest: 'manifest-response', chunks: 'chunk-response', retain: 'retain-response', 'blob-info': 'blob-info-response', 'blob-chunks': 'blob-chunk-response',
}
interface Stream { next: number; readonly end: number; readonly onChunk: ChunkSink }
interface Pending { readonly action: Action; readonly stream?: Stream; resolve(value: Reply): void; reject(error: unknown): void; touch(): void; cleanup(): void }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
function fields(value: Record<string, unknown>, keys: readonly string[]): void {
  check(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'CONTENT_WIRE_INVALID')
}
function rangeValid(start: unknown, count: unknown, total: number): boolean {
  return Number.isSafeInteger(start) && Number.isSafeInteger(count) && Number(start) >= 0 && Number(count) > 0 &&
    Number(count) <= CONTENT_NETWORK_LIMITS.rangeChunks && Number(start) + Number(count) <= total
}
function chunkValid(index: unknown, bytes: unknown, maxIndex: number, maxBytes: number): boolean {
  return Number.isSafeInteger(index) && Number(index) >= 0 && Number(index) < maxIndex &&
    (bytes === null || (bytes instanceof Uint8Array && bytes.length <= maxBytes))
}
/** Validate shape and every size bound before any hashing, decryption or allocation. */
export function assertContentWireMessage(input: unknown): asserts input is ContentWireMessage {
  check(input !== null && typeof input === 'object' && !Array.isArray(input), 'CONTENT_WIRE_INVALID')
  const value = input as Record<string, unknown>
  check(typeof value.id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.id), 'CONTENT_WIRE_INVALID')
  switch (value.type) {
    case 'manifest-request': case 'retain-request':
      fields(value, ['type', 'id', 'reference']); assertContentReference(value.reference); break
    case 'chunks-request':
      fields(value, ['type', 'id', 'reference', 'start', 'count']); assertContentReference(value.reference)
      check(rangeValid(value.start, value.count, Math.min(MAX_CONTENT_CHUNKS, Math.ceil(value.reference.bytes / CONTENT_CHUNK_BYTES))), 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'blob-info-request':
      fields(value, ['type', 'id', 'hash']); check(digest(value.hash), 'CONTENT_WIRE_INVALID'); break
    case 'blob-chunks-request':
      fields(value, ['type', 'id', 'hash', 'start', 'count'])
      check(digest(value.hash) && rangeValid(value.start, value.count, MAX_BLOB_CHUNKS), 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'manifest-response':
      fields(value, ['type', 'id', 'manifest']); if (value.manifest !== null) assertContentManifest(value.manifest); break
    case 'chunk-response':
      fields(value, ['type', 'id', 'index', 'bytes'])
      check(chunkValid(value.index, value.bytes, MAX_CONTENT_CHUNKS, MAX_CONTENT_ENCRYPTED_CHUNK_BYTES), 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'blob-info-response':
      fields(value, ['type', 'id', 'bytes', 'nodes'])
      check(value.bytes === null || (Number.isSafeInteger(value.bytes) && Number(value.bytes) >= 0 && Number(value.bytes) <= MAX_BLOB_BYTES), 'CONTENT_WIRE_INVALID')
      check(Array.isArray(value.nodes) && value.nodes.length <= CONTENT_NETWORK_LIMITS.blobNodes && (value.bytes !== null || value.nodes.length === 0) &&
        value.nodes.every(node => node instanceof Uint8Array && node.length > 0 && node.length <= CONTENT_NETWORK_LIMITS.blobNodeBytes), 'CONTENT_WIRE_INVALID'); break
    case 'blob-chunk-response':
      fields(value, ['type', 'id', 'index', 'bytes'])
      check(chunkValid(value.index, value.bytes, MAX_BLOB_CHUNKS, CONTENT_CHUNK_BYTES), 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'retain-response':
      fields(value, ['type', 'id', 'receipt']); assertContentRetention(value.receipt); break
    case 'error':
      fields(value, ['type', 'id', 'code']); check(['CONTENT_UNAVAILABLE', 'CONTENT_FORBIDDEN', 'CONTENT_BUSY'].includes(String(value.code)), 'CONTENT_WIRE_INVALID'); break
    case 'cancel': fields(value, ['type', 'id']); break
    default: throw new Error('CONTENT_WIRE_INVALID')
  }
}

/** Content RPC on an already authenticated/encrypted channel. Owns no transport or writer queue. */
export function createNetworkContent(options: {
  readonly content: ApplicationContent
  readonly send: (message: ContentWireMessage) => Promise<void>
  readonly signal: AbortSignal
  readonly authorize: () => boolean
  readonly peerId: string
}): { handle(message: ContentWireMessage): Promise<void>; close(): void } {
  options.signal.throwIfAborted()
  check(/^[0-9a-f]{64}$/u.test(options.peerId), 'CONTENT_PEER_INVALID')
  const lifetime = new AbortController(), signal = AbortSignal.any([options.signal, lifetime.signal])
  const pending = new Map<string, Pending>(), active = new Map<string, AbortController>()
  const local = options.content.source()
  const allowed = (): void => { signal.throwIfAborted(); check(options.authorize() === true, 'CONTENT_FORBIDDEN') }
  const close = (): void => {
    if (lifetime.signal.aborted) return
    lifetime.abort(new Error('CONTENT_NETWORK_CLOSED'))
    options.signal.removeEventListener('abort', close)
    detach()
    for (const waiter of pending.values()) { waiter.cleanup(); waiter.reject(signal.reason) }
    pending.clear()
    for (const controller of active.values()) controller.abort(signal.reason)
    active.clear()
  }
  // Wire messages are validated where they are built (requests) or received (handle); the
  // serving path builds responses only from bounded, locally verified data.
  const send = async (message: ContentWireMessage): Promise<void> => {
    allowed()
    try { await awaitOwnedTask(signal, () => options.send(message)); allowed() }
    catch (error) { close(); throw error }
  }
  const cancel = (id: string): void => { if (!signal.aborted && options.authorize()) void send({ type: 'cancel', id }).catch(() => undefined) }
  const sendRequest = (action: Action, build: (id: string) => IncomingRequest, input: ContentOptions, stream?: Stream): Promise<Reply> => {
    allowed(); input.signal?.throwIfAborted()
    check(pending.size < CONTENT_NETWORK_LIMITS.pending, 'CONTENT_REQUEST_LIMIT')
    const id = crypto.randomUUID(), requestSignal = input.signal
    const message = build(id)
    assertContentWireMessage(message)
    return new Promise<Reply>((resolve, reject) => {
      const finish = (error: Error): void => {
        const waiter = pending.get(id)
        if (waiter === undefined) return
        pending.delete(id); waiter.cleanup(); reject(error); cancel(id)
      }
      const abort = (): void => finish(requestSignal?.reason instanceof Error ? requestSignal.reason : new Error('CONTENT_REQUEST_ABORTED'))
      let timer = setTimeout(() => finish(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs)
      const touch = (): void => { clearTimeout(timer); timer = setTimeout(() => finish(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs) }
      const cleanup = (): void => { clearTimeout(timer); requestSignal?.removeEventListener('abort', abort) }
      pending.set(id, { action, ...(stream === undefined ? {} : { stream }), resolve, reject, touch, cleanup })
      requestSignal?.addEventListener('abort', abort, { once: true })
      void send(message).catch(error => {
        const waiter = pending.get(id)
        if (waiter !== undefined) { pending.delete(id); cleanup(); reject(error) }
      })
    })
  }
  const collectOne = async (run: (sink: ChunkSink) => Promise<void>): Promise<Uint8Array | null> => {
    let value: Uint8Array | null = null
    await run((_index, bytes) => { value = bytes })
    return value
  }
  // Chunk bytes are verified once by ApplicationContent against its manifest / blob index.
  const chunks = async (reference: ContentReference, start: number, count: number, onChunk: ChunkSink, input: ContentOptions = {}): Promise<void> => {
    assertContentReference(reference)
    await sendRequest('chunks', id => ({ type: 'chunks-request', id, reference: { ...reference }, start, count }), input, { next: start, end: start + count, onChunk })
    allowed(); input.signal?.throwIfAborted()
  }
  const blobChunks = async (hash: string, start: number, count: number, onChunk: ChunkSink, input: ContentOptions = {}): Promise<void> => {
    check(digest(hash), 'CONTENT_BLOB_INVALID')
    await sendRequest('blob-chunks', id => ({ type: 'blob-chunks-request', id, hash, start, count }), input, { next: start, end: start + count, onChunk })
    allowed(); input.signal?.throwIfAborted()
  }
  const blobIndex = async (hash: string, input: ContentOptions = {}): Promise<BlobIndex | null> => {
    check(digest(hash), 'CONTENT_BLOB_INVALID')
    const response = await sendRequest('blob-info', id => ({ type: 'blob-info-request', id, hash }), input)
    check(response.type === 'blob-info-response', 'CONTENT_RESPONSE_INVALID')
    allowed(); input.signal?.throwIfAborted()
    return response.bytes === null ? null : { hash, bytes: response.bytes, nodes: response.nodes }
  }
  const detach = options.content.attachSource(`network:${options.peerId}:${crypto.randomUUID()}`, {
    async manifest(reference, input = {}) {
      assertContentReference(reference)
      const response = await sendRequest('manifest', id => ({ type: 'manifest-request', id, reference: { ...reference } }), input)
      check(response.type === 'manifest-response', 'CONTENT_RESPONSE_INVALID')
      return response.manifest
    },
    chunk: (reference, index, input = {}) => collectOne(sink => chunks(reference, index, 1, sink, input)),
    chunks,
    async retained(reference, input = {}) {
      assertContentReference(reference)
      const response = await sendRequest('retain', id => ({ type: 'retain-request', id, reference: { ...reference } }), input)
      check(response.type === 'retain-response', 'CONTENT_RESPONSE_INVALID')
      await options.content.verifyRetention(reference, response.receipt, options.peerId)
      allowed(); input.signal?.throwIfAborted(); return response.receipt
    },
    async blobInfo(hash, input = {}) {
      const index = await blobIndex(hash, input)
      return index === null ? null : { hash, bytes: index.bytes }
    },
    blobIndex,
    blobChunk: (hash, index, input = {}) => collectOne(sink => blobChunks(hash, index, 1, sink, input)),
    blobChunks,
  })
  options.signal.addEventListener('abort', close, { once: true })
  if (options.signal.aborted) close()

  const serve = async (message: IncomingRequest, controller: AbortController): Promise<void> => {
    let timer = setTimeout(() => controller.abort(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs)
    const touch = (): void => { clearTimeout(timer); timer = setTimeout(() => controller.abort(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs) }
    const requestSignal = AbortSignal.any([signal, controller.signal])
    // Streamed chunks: each send is awaited before the next chunk is read (per-request backpressure).
    const stream = (type: 'chunk-response' | 'blob-chunk-response'): ChunkSink => async (index, bytes) => {
      requestSignal.throwIfAborted(); allowed()
      await send({ type, id: message.id, index, bytes }); touch()
    }
    try {
      allowed(); requestSignal.throwIfAborted()
      let response: Reply | undefined
      if (message.type === 'manifest-request') response = { type: 'manifest-response', id: message.id, manifest: await awaitOwnedTask(requestSignal, () => local.manifest(message.reference, { signal: requestSignal })) }
      else if (message.type === 'chunks-request') await awaitOwnedTask(requestSignal, () => local.chunks!(message.reference, message.start, message.count, stream('chunk-response'), { signal: requestSignal }))
      else if (message.type === 'blob-info-request') {
        const index = await awaitOwnedTask(requestSignal, () => local.blobIndex!(message.hash, { signal: requestSignal }))
        response = { type: 'blob-info-response', id: message.id, bytes: index === null ? null : index.bytes, nodes: index === null ? [] : index.nodes }
      } else if (message.type === 'blob-chunks-request') await awaitOwnedTask(requestSignal, () => local.blobChunks!(message.hash, message.start, message.count, stream('blob-chunk-response'), { signal: requestSignal }))
      else response = { type: 'retain-response', id: message.id, receipt: await awaitOwnedTask(requestSignal, () => options.content.retain(message.reference, { signal: requestSignal })) }
      if (response !== undefined) { requestSignal.throwIfAborted(); allowed(); await send(response) }
    } catch {
      if (!requestSignal.aborted && !signal.aborted) await send({ type: 'error', id: message.id, code: options.authorize() ? 'CONTENT_UNAVAILABLE' : 'CONTENT_FORBIDDEN' }).catch(() => undefined)
    } finally { clearTimeout(timer); if (active.get(message.id) === controller) active.delete(message.id) }
  }
  return { close, async handle(message) {
    allowed(); assertContentWireMessage(message)
    if (message.type === 'cancel') { active.get(message.id)?.abort(new Error('CONTENT_REQUEST_CANCELLED')); return }
    if (message.type === 'manifest-request' || message.type === 'chunks-request' || message.type === 'retain-request' || message.type === 'blob-info-request' || message.type === 'blob-chunks-request') {
      check(!active.has(message.id), 'CONTENT_REQUEST_DUPLICATE')
      if (active.size >= CONTENT_NETWORK_LIMITS.active) { await send({ type: 'error', id: message.id, code: 'CONTENT_BUSY' }); return }
      const controller = new AbortController(); active.set(message.id, controller)
      // Never block the channel's incoming pump on work that may itself request
      // content from this peer. There is no secondary request/writer queue.
      void serve(message, controller).catch(() => close())
      return
    }
    const waiter = pending.get(message.id)
    if (waiter === undefined) return // Authenticated late responses after cancellation are harmless.
    check(message.type === 'error' || message.type === RESPONSE[waiter.action], 'CONTENT_RESPONSE_INVALID')
    if (message.type === 'error') { pending.delete(message.id); waiter.cleanup(); waiter.reject(new Error(message.code)); return }
    const stream = waiter.stream
    if (stream === undefined) { pending.delete(message.id); waiter.cleanup(); waiter.resolve(message); return }
    check((message.type === 'chunk-response' || message.type === 'blob-chunk-response') && message.index === stream.next, 'CONTENT_RESPONSE_INVALID')
    stream.next++; waiter.touch()
    // Hand off synchronously, before the request settles; verification runs off the pump.
    try { const handed = stream.onChunk(message.index, message.bytes); if (handed instanceof Promise) handed.catch(() => undefined) } catch { /* Sink errors belong to the puller. */ }
    if (stream.next === stream.end) { pending.delete(message.id); waiter.cleanup(); waiter.resolve(message) }
  } }
}

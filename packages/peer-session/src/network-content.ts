import { check, encodeRecord } from '@chronolog/authority'
import { computeCasHash } from '@chronolog/records'
import {
  assertContentManifest, assertContentReference, assertContentRetention, CONTENT_CHUNK_BYTES,
  MAX_BLOB_BYTES, MAX_BLOB_CHUNKS, MAX_CONTENT_CHUNKS, MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, MAX_CONTENT_MANIFEST_BYTES,
  type ApplicationContent, type ContentManifest, type ContentOptions, type ContentReference, type ContentRetention,
} from './content.js'
import { awaitOwnedTask } from './lifetime.js'

export const CONTENT_NETWORK_LIMITS = Object.freeze({ pending: 4, active: 4, timeoutMs: 30_000,
  chunkBytes: MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, chunkBase64Characters: 4 * Math.ceil(MAX_CONTENT_ENCRYPTED_CHUNK_BYTES / 3),
  messageBytes: MAX_CONTENT_MANIFEST_BYTES + 4096 })
type Action = 'manifest' | 'chunk' | 'retain' | 'blob-info' | 'blob-chunk'
export type ContentWireMessage =
  | { readonly type: 'manifest-request'; readonly id: string; readonly reference: ContentReference }
  | { readonly type: 'chunk-request'; readonly id: string; readonly reference: ContentReference; readonly index: number }
  | { readonly type: 'retain-request'; readonly id: string; readonly reference: ContentReference }
  | { readonly type: 'blob-info-request'; readonly id: string; readonly hash: string }
  | { readonly type: 'blob-chunk-request'; readonly id: string; readonly hash: string; readonly index: number }
  | { readonly type: 'manifest-response'; readonly id: string; readonly manifest: ContentManifest | null }
  | { readonly type: 'chunk-response'; readonly id: string; readonly bytes: string | null }
  | { readonly type: 'retain-response'; readonly id: string; readonly receipt: ContentRetention }
  | { readonly type: 'blob-info-response'; readonly id: string; readonly bytes: number | null }
  | { readonly type: 'blob-chunk-response'; readonly id: string; readonly bytes: string | null }
  | { readonly type: 'error'; readonly id: string; readonly code: 'CONTENT_UNAVAILABLE' | 'CONTENT_FORBIDDEN' | 'CONTENT_BUSY' }
  | { readonly type: 'cancel'; readonly id: string }
type IncomingRequest = Extract<ContentWireMessage, { type: 'manifest-request' | 'chunk-request' | 'retain-request' | 'blob-info-request' | 'blob-chunk-request' }>
type Reply = Extract<ContentWireMessage, { type: 'manifest-response' | 'chunk-response' | 'retain-response' | 'blob-info-response' | 'blob-chunk-response' | 'error' }>
interface Pending { readonly action: Action; resolve(value: Reply): void; reject(error: unknown): void; cleanup(): void }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
function fields(value: Record<string, unknown>, keys: readonly string[]): void {
  check(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'CONTENT_WIRE_INVALID')
}
function base64(bytes: Uint8Array): string {
  let binary = ''
  for (let index = 0; index < bytes.length; index += 8192) binary += String.fromCharCode(...bytes.subarray(index, index + 8192))
  return btoa(binary)
}
function decoded(value: string): Uint8Array {
  check(value.length > 0 && value.length <= CONTENT_NETWORK_LIMITS.chunkBase64Characters && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value), 'CONTENT_WIRE_CHUNK_INVALID')
  const binary = atob(value)
  check(binary.length <= CONTENT_NETWORK_LIMITS.chunkBytes && btoa(binary) === value, 'CONTENT_WIRE_CHUNK_INVALID')
  return Uint8Array.from(binary, character => character.charCodeAt(0))
}
/** Validate bounds before encoding, base64 decoding, hashing or allocating an object-sized buffer. */
export function assertContentWireMessage(input: unknown): asserts input is ContentWireMessage {
  check(input !== null && typeof input === 'object' && !Array.isArray(input), 'CONTENT_WIRE_INVALID')
  const value = input as Record<string, unknown>
  check(typeof value.id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value.id), 'CONTENT_WIRE_INVALID')
  switch (value.type) {
    case 'manifest-request': case 'retain-request':
      fields(value, ['type', 'id', 'reference']); assertContentReference(value.reference); break
    case 'chunk-request':
      fields(value, ['type', 'id', 'reference', 'index']); assertContentReference(value.reference)
      check(Number.isSafeInteger(value.index) && Number(value.index) >= 0 && Number(value.index) < MAX_CONTENT_CHUNKS && Number(value.index) < Math.ceil(value.reference.bytes / CONTENT_CHUNK_BYTES), 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'blob-info-request':
      fields(value, ['type', 'id', 'hash']); check(digest(value.hash), 'CONTENT_WIRE_INVALID'); break
    case 'blob-chunk-request':
      fields(value, ['type', 'id', 'hash', 'index'])
      check(digest(value.hash) && Number.isSafeInteger(value.index) && Number(value.index) >= 0 && Number(value.index) < MAX_BLOB_CHUNKS, 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'manifest-response':
      fields(value, ['type', 'id', 'manifest']); if (value.manifest !== null) assertContentManifest(value.manifest); break
    case 'chunk-response':
      fields(value, ['type', 'id', 'bytes']); check(value.bytes === null || typeof value.bytes === 'string', 'CONTENT_WIRE_CHUNK_INVALID')
      if (typeof value.bytes === 'string') decoded(value.bytes); break
    case 'blob-info-response':
      fields(value, ['type', 'id', 'bytes'])
      check(value.bytes === null || (Number.isSafeInteger(value.bytes) && Number(value.bytes) >= 0 && Number(value.bytes) <= MAX_BLOB_BYTES), 'CONTENT_WIRE_INVALID'); break
    case 'blob-chunk-response':
      fields(value, ['type', 'id', 'bytes']); check(value.bytes === null || typeof value.bytes === 'string', 'CONTENT_WIRE_CHUNK_INVALID')
      if (typeof value.bytes === 'string') check(decoded(value.bytes).length <= CONTENT_CHUNK_BYTES, 'CONTENT_WIRE_CHUNK_INVALID'); break
    case 'retain-response':
      fields(value, ['type', 'id', 'receipt']); assertContentRetention(value.receipt); break
    case 'error':
      fields(value, ['type', 'id', 'code']); check(['CONTENT_UNAVAILABLE', 'CONTENT_FORBIDDEN', 'CONTENT_BUSY'].includes(String(value.code)), 'CONTENT_WIRE_INVALID'); break
    case 'cancel': fields(value, ['type', 'id']); break
    default: throw new Error('CONTENT_WIRE_INVALID')
  }
  check(encodeRecord(input).length <= CONTENT_NETWORK_LIMITS.messageBytes, 'CONTENT_WIRE_LIMIT')
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
  const send = async (message: ContentWireMessage): Promise<void> => {
    allowed(); assertContentWireMessage(message)
    try { await awaitOwnedTask(signal, () => options.send(message)); allowed() }
    catch (error) { close(); throw error }
  }
  const cancel = (id: string): void => { if (!signal.aborted && options.authorize()) void send({ type: 'cancel', id }).catch(() => undefined) }
  const sendRequest = (action: Action, build: (id: string) => IncomingRequest, input: ContentOptions): Promise<Reply> => {
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
      const timer = setTimeout(() => finish(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs)
      const cleanup = (): void => { clearTimeout(timer); requestSignal?.removeEventListener('abort', abort) }
      pending.set(id, { action, resolve, reject, cleanup })
      requestSignal?.addEventListener('abort', abort, { once: true })
      void send(message).catch(error => {
        const waiter = pending.get(id)
        if (waiter !== undefined) { pending.delete(id); cleanup(); reject(error) }
      })
    })
  }
  const detach = options.content.attachSource(`network:${options.peerId}:${crypto.randomUUID()}`, {
    async manifest(reference, input = {}) {
      assertContentReference(reference)
      const response = await sendRequest('manifest', id => ({ type: 'manifest-request', id, reference: { ...reference } }), input)
      check(response.type === 'manifest-response', 'CONTENT_RESPONSE_INVALID')
      return response.manifest
    },
    async chunk(reference, index, input = {}) {
      assertContentReference(reference)
      const response = await sendRequest('chunk', id => ({ type: 'chunk-request', id, reference: { ...reference }, index }), input)
      check(response.type === 'chunk-response', 'CONTENT_RESPONSE_INVALID')
      if (response.bytes === null) return null
      const bytes = decoded(response.bytes), manifest = await local.manifest(reference, input), expected = manifest?.chunks[index]
      check(expected !== undefined && bytes.length === expected.bytes && computeCasHash(bytes, []) === expected.hash, 'CONTENT_CHUNK_INVALID')
      allowed(); input.signal?.throwIfAborted(); return bytes
    },
    async retained(reference, input = {}) {
      assertContentReference(reference)
      const response = await sendRequest('retain', id => ({ type: 'retain-request', id, reference: { ...reference } }), input)
      check(response.type === 'retain-response', 'CONTENT_RESPONSE_INVALID')
      await options.content.verifyRetention(reference, response.receipt, options.peerId)
      allowed(); input.signal?.throwIfAborted(); return response.receipt
    },
    async blobInfo(hash, input = {}) {
      check(digest(hash), 'CONTENT_BLOB_INVALID')
      const response = await sendRequest('blob-info', id => ({ type: 'blob-info-request', id, hash }), input)
      check(response.type === 'blob-info-response', 'CONTENT_RESPONSE_INVALID')
      allowed(); input.signal?.throwIfAborted()
      return response.bytes === null ? null : { hash, bytes: response.bytes }
    },
    async blobChunk(hash, index, input = {}) {
      check(digest(hash), 'CONTENT_BLOB_INVALID')
      const response = await sendRequest('blob-chunk', id => ({ type: 'blob-chunk-request', id, hash, index }), input)
      check(response.type === 'blob-chunk-response', 'CONTENT_RESPONSE_INVALID')
      if (response.bytes === null) return null
      const bytes = decoded(response.bytes)
      check(bytes.length <= CONTENT_CHUNK_BYTES, 'CONTENT_BLOB_INVALID')
      allowed(); input.signal?.throwIfAborted(); return bytes
    },
  })
  options.signal.addEventListener('abort', close, { once: true })
  if (options.signal.aborted) close()

  const serve = async (message: IncomingRequest, controller: AbortController): Promise<void> => {
    const timer = setTimeout(() => controller.abort(new Error('CONTENT_REQUEST_TIMEOUT')), CONTENT_NETWORK_LIMITS.timeoutMs)
    const requestSignal = AbortSignal.any([signal, controller.signal])
    try {
      allowed(); requestSignal.throwIfAborted()
      let response: Reply
      if (message.type === 'manifest-request') response = { type: 'manifest-response', id: message.id, manifest: await awaitOwnedTask(requestSignal, () => local.manifest(message.reference, { signal: requestSignal })) }
      else if (message.type === 'chunk-request') {
        const bytes = await awaitOwnedTask(requestSignal, () => local.chunk(message.reference, message.index, { signal: requestSignal }))
        response = { type: 'chunk-response', id: message.id, bytes: bytes === null ? null : base64(bytes) }
      } else if (message.type === 'blob-info-request') {
        const info = await awaitOwnedTask(requestSignal, () => local.blobInfo!(message.hash, { signal: requestSignal }))
        response = { type: 'blob-info-response', id: message.id, bytes: info === null ? null : info.bytes }
      } else if (message.type === 'blob-chunk-request') {
        const bytes = await awaitOwnedTask(requestSignal, () => local.blobChunk!(message.hash, message.index, { signal: requestSignal }))
        response = { type: 'blob-chunk-response', id: message.id, bytes: bytes === null ? null : base64(bytes) }
      } else response = { type: 'retain-response', id: message.id, receipt: await awaitOwnedTask(requestSignal, () => options.content.retain(message.reference, { signal: requestSignal })) }
      requestSignal.throwIfAborted(); allowed(); await send(response)
    } catch {
      if (!requestSignal.aborted && !signal.aborted) await send({ type: 'error', id: message.id, code: options.authorize() ? 'CONTENT_UNAVAILABLE' : 'CONTENT_FORBIDDEN' }).catch(() => undefined)
    } finally { clearTimeout(timer); if (active.get(message.id) === controller) active.delete(message.id) }
  }
  return { close, async handle(message) {
    allowed(); assertContentWireMessage(message)
    if (message.type === 'cancel') { active.get(message.id)?.abort(new Error('CONTENT_REQUEST_CANCELLED')); return }
    if (message.type === 'manifest-request' || message.type === 'chunk-request' || message.type === 'retain-request' || message.type === 'blob-info-request' || message.type === 'blob-chunk-request') {
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
    check(message.type === 'error' || message.type === `${waiter.action}-response`, 'CONTENT_RESPONSE_INVALID')
    pending.delete(message.id); waiter.cleanup()
    if (message.type === 'error') waiter.reject(new Error(message.code))
    else waiter.resolve(message)
  } }
}

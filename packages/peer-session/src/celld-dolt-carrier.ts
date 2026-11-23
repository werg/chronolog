import { decodePeerValue, encodePeerValue } from '@chronolog/peer-generation/control'
import type { SignedCelldWorkspacePublication } from './celld-workspace-publication.js'
import type { CelldPeerBinding, CelldPeerEndpoint, CelldPeerStream } from './celld-peer.js'

export type CelldDoltPublicationGrant =
  | { readonly kind: 'applied'; readonly head: string }
  | { readonly kind: 'staged'; readonly head: string }
  | { readonly kind: 'grant'; readonly id: string; readonly ref: string; readonly token: string; readonly branch?: string }
export type CelldWorkspaceHistoryRequest = 'grant' | 'push' | 'missing' | 'blob' | 'publish'
type RequestHeader = {
  readonly v: 1
  readonly kind: CelldWorkspaceHistoryRequest
  readonly digest?: string
  readonly proof: SignedCelldWorkspacePublication
  readonly size: number
}
type ReplyHeader =
  | { readonly v: 1; readonly kind: 'granted'; readonly value: CelldDoltPublicationGrant }
  | { readonly v: 1; readonly kind: 'bytes'; readonly size: number }
  | { readonly v: 1; readonly kind: 'refused'; readonly code: string }

const maxHeader = 4096
/** The native Dolt remote API accepts a single message up to this bound. */
const maxBody = 1 << 30
const code = /^[A-Z][A-Z0-9_]{0,127}$/u
const digest = /^[a-f0-9]{64}$/u
const head = /^[a-f0-9]{40}$/u

class CarrierReader {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>
  #rest: Uint8Array = new Uint8Array(0)

  constructor(stream: CelldPeerStream) { this.#reader = stream.readable.getReader() }

  async read(size: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(size) || size < 0 || size > maxBody) throw new Error('CELLD_DOLT_PACKET_LIMIT')
    const result = new Uint8Array(size)
    let at = 0
    while (at < size) {
      if (this.#rest.byteLength === 0) {
        const chunk = await this.#reader.read()
        if (chunk.done) throw new Error('CELLD_DOLT_PACKET_TRUNCATED')
        this.#rest = chunk.value
      }
      const count = Math.min(size - at, this.#rest.byteLength)
      result.set(this.#rest.subarray(0, count), at)
      this.#rest = this.#rest.subarray(count)
      at += count
    }
    return result
  }

  async header<T>(): Promise<T> {
    const prefix = await this.read(4)
    const size = new DataView(prefix.buffer).getUint32(0)
    if (size === 0 || size > maxHeader) throw new Error('CELLD_DOLT_HEADER_LIMIT')
    return decodePeerValue<T>(await this.read(size))
  }

  async eof(): Promise<void> {
    if (this.#rest.byteLength !== 0 || !(await this.#reader.read()).done)
      throw new Error('CELLD_DOLT_PACKET_TRAILING_BYTES')
  }

  release(): void { this.#reader.releaseLock() }
}

async function write(stream: CelldPeerStream, header: RequestHeader | ReplyHeader, body?: Uint8Array): Promise<void> {
  const encoded = encodePeerValue(header)
  if (encoded.byteLength > maxHeader) throw new Error('CELLD_DOLT_HEADER_LIMIT')
  if (body !== undefined && body.byteLength > maxBody) throw new Error('CELLD_DOLT_PACKET_LIMIT')
  const prefix = new Uint8Array(4)
  new DataView(prefix.buffer).setUint32(0, encoded.byteLength)
  const writer = stream.writable.getWriter()
  try {
    await writer.write(prefix)
    await writer.write(encoded)
    if (body !== undefined) await writer.write(body)
    await writer.close()
  } finally { writer.releaseLock() }
}

export interface AuthorizeDoltPublication {
  (input: {
    readonly peer: string
    readonly proof: SignedCelldWorkspacePublication
    readonly kind: CelldWorkspaceHistoryRequest
    readonly digest?: string
    readonly bytes: number
  }): Promise<{
    grant(): Promise<CelldDoltPublicationGrant>
    push(bytes: Uint8Array): Promise<Uint8Array>
    missing?(): Promise<readonly string[]>
    blob?(digest: string, bytes: Uint8Array): Promise<void>
    publish?(): Promise<string>
  }>
}

/** The receiver checks the proof and the authenticated Iroh peer before reading a pack. */
export async function serveCelldDoltPublication(stream: CelldPeerStream, authorize: AuthorizeDoltPublication): Promise<void> {
  const reader = new CarrierReader(stream)
  try {
    const request = await reader.header<RequestHeader>()
    if (request?.v !== 1 ||
      !['grant', 'push', 'missing', 'blob', 'publish'].includes(request.kind) ||
      !Number.isSafeInteger(request.size) || request.size < 0 || request.size > maxBody ||
      (request.kind !== 'blob' && request.digest !== undefined) ||
      (request.kind === 'blob' && (typeof request.digest !== 'string' || !digest.test(request.digest))) ||
      (request.kind === 'push' ? request.size === 0 : request.kind !== 'blob' && request.size !== 0) ||
      request.proof === null || typeof request.proof !== 'object') throw new Error('CELLD_DOLT_REQUEST_INVALID')
    if (request.proof.payload?.sourceNodeId !== stream.remoteNodeId)
      throw new Error('CELLD_WORKSPACE_PUBLICATION_SOURCE_MISMATCH')
    const handler = await authorize({
      peer: stream.remoteNodeId, proof: request.proof, kind: request.kind, bytes: request.size,
      ...(request.digest === undefined ? {} : { digest: request.digest }),
    })
    const bytes = request.kind === 'push' || request.kind === 'blob' ? await reader.read(request.size) : new Uint8Array(0)
    await reader.eof()
    if (request.kind === 'grant') {
      await write(stream, { v: 1, kind: 'granted', value: await handler.grant() })
      return
    }
    let result: Uint8Array
    if (request.kind === 'push') result = await handler.push(bytes)
    else if (request.kind === 'missing' && handler.missing) result = encodePeerValue(await handler.missing())
    else if (request.kind === 'publish' && handler.publish) result = encodePeerValue(await handler.publish())
    else if (request.kind === 'blob' && handler.blob && request.digest !== undefined) {
      await handler.blob(request.digest, bytes)
      result = new Uint8Array(0)
    } else throw new Error('CELLD_WORKSPACE_HISTORY_OPERATION_UNAVAILABLE')
    await write(stream, { v: 1, kind: 'bytes', size: result.byteLength }, result)
  } catch (error) {
    const nativeCode = (error as { code?: unknown } | null)?.code
    const message = typeof nativeCode === 'string' ? nativeCode : error instanceof Error ? error.message : ''
    try { await write(stream, { v: 1, kind: 'refused', code: code.test(message) ? message : 'CELLD_DOLT_PUBLICATION_REFUSED' }) }
    catch { /* The remote already closed or refused its receive direction. */ }
  } finally {
    reader.release()
    await stream.close().catch(() => undefined)
  }
}

/** One exact grant and the raw Dolt requests share the same signed Iroh scope. */
export function celldDoltPublicationPeer(binding: CelldPeerBinding, destination: CelldPeerEndpoint, input: SignedCelldWorkspacePublication) {
  const proof = structuredClone(input), endpoint = structuredClone(destination)
  const exchange = async (kind: CelldWorkspaceHistoryRequest, bytes?: Uint8Array, contentDigest?: string) => {
    const stream = await binding.connect(endpoint.nodeId, {
      ...(endpoint.addrs === undefined ? {} : { addrs: [...endpoint.addrs] }),
      ...(endpoint.relay === undefined ? {} : { relay: endpoint.relay }),
    })
    const reader = new CarrierReader(stream)
    let writer: Promise<void> | undefined
    try {
      if (stream.remoteNodeId !== endpoint.nodeId) throw new Error('CELLD_PEER_ENDPOINT_MISMATCH')
      writer = write(stream, { v: 1, kind, proof, size: bytes?.byteLength ?? 0,
        ...(contentDigest === undefined ? {} : { digest: contentDigest }),
      }, bytes)
      void writer.catch(() => stream.close().catch(() => undefined))
      const response = await reader.header<ReplyHeader>()
      if (response?.v !== 1) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      if (response.kind === 'refused') {
        if (!code.test(response.code)) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
        throw new Error(response.code)
      }
      let result: CelldDoltPublicationGrant | Uint8Array
      if (kind === 'grant' && response.kind === 'granted') result = response.value
      else if (kind !== 'grant' && response.kind === 'bytes') result = await reader.read(response.size)
      else throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      await reader.eof()
      await writer
      return result
    } finally {
      reader.release()
      await stream.close().catch(() => undefined)
      await writer?.catch(() => undefined)
    }
  }

  return Object.freeze({
    async grant() {
      const result = await exchange('grant')
      if (result instanceof Uint8Array || (result?.kind !== 'grant' && result?.kind !== 'staged' && result?.kind !== 'applied'))
        throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      return result
    },
    async push(bytes: Uint8Array) {
      const result = await exchange('push', bytes)
      if (!(result instanceof Uint8Array)) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      return result
    },
    async missing() {
      const result = await exchange('missing')
      if (!(result instanceof Uint8Array)) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      const hashes = decodePeerValue<unknown>(result)
      if (!Array.isArray(hashes) || hashes.some(hash => typeof hash !== 'string' || !digest.test(hash)) ||
          new Set(hashes).size !== hashes.length) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      return hashes as string[]
    },
    async blob(contentDigest: string, bytes: Uint8Array) {
      const result = await exchange('blob', bytes, contentDigest)
      if (!(result instanceof Uint8Array) || result.byteLength !== 0) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
    },
    async publish() {
      const result = await exchange('publish')
      if (!(result instanceof Uint8Array)) throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      const revision = decodePeerValue<unknown>(result)
      if (typeof revision !== 'string' || !head.test(revision) || revision !== proof.payload.proposedHead)
        throw new Error('CELLD_DOLT_RESPONSE_INVALID')
      return revision
    },
  })
}

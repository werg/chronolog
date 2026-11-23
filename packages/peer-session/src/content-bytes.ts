import type { ContentReference, ContentUpload } from './content.js'
import { awaitOwnedTask } from './lifetime.js'

export const CONTENT_CHUNK_BYTES = 65_536
export const MAX_CONTENT_BYTES = 128 * 1024 * 1024
export interface ContentPutBytesOptions { readonly mediaType?: string; readonly signal?: AbortSignal }
export interface ContentReadBytesOptions { readonly maxBytes: number; readonly signal?: AbortSignal }
interface ByteContent {
  stage(options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload>
  read(reference: ContentReference, options?: { readonly signal?: AbortSignal }): AsyncIterable<Uint8Array>
}

/** Shared by the native owner and the page facade; Worker messages stay one chunk each. */
export async function putContentBytes(content: Pick<ByteContent, 'stage'>, bytes: Uint8Array, options: ContentPutBytesOptions = {}): Promise<ContentReference> {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_CONTENT_BYTES) throw new Error('CONTENT_RANGE_INVALID')
  const signal = options.signal ?? new AbortController().signal
  signal.throwIfAborted()
  // The caller owns the input until settlement. Copy only the next bounded chunk.
  const staging = content.stage({ bytes: bytes.byteLength, ...(options.mediaType === undefined ? {} : { mediaType: options.mediaType }) })
  let upload: ContentUpload | undefined
  try {
    upload = await awaitOwnedTask(signal, () => staging)
    for (let offset = 0; offset < bytes.byteLength; offset += CONTENT_CHUNK_BYTES) {
      signal.throwIfAborted()
      const chunk = Uint8Array.from(bytes.subarray(offset, offset + CONTENT_CHUNK_BYTES))
      await awaitOwnedTask(signal, () => upload!.write(offset / CONTENT_CHUNK_BYTES, chunk))
    }
    const reference = await awaitOwnedTask(signal, () => upload!.commit())
    signal.throwIfAborted()
    return reference
  } catch (error) {
    // Cancellation releases the caller immediately. The owner serializes discard
    // after any already-started write/commit; late completions cannot escape cleanup.
    void staging.then(value => value.discard()).catch(() => undefined)
    throw error
  }
}

/** Allocate once, before fetching, under the caller's explicit byte ceiling. */
export async function readContentBytes(content: Pick<ByteContent, 'read'>, reference: ContentReference, options: ContentReadBytesOptions): Promise<Uint8Array> {
  if (!Number.isSafeInteger(options?.maxBytes) || options.maxBytes < 0 || options.maxBytes > MAX_CONTENT_BYTES) throw new Error('CONTENT_READ_LIMIT_INVALID')
  if (reference === null || typeof reference !== 'object' || !Number.isSafeInteger(reference.bytes) || reference.bytes < 0 || reference.bytes > MAX_CONTENT_BYTES) throw new Error('CONTENT_REFERENCE_INVALID')
  if (reference.bytes > options.maxBytes) throw new Error('CONTENT_READ_LIMIT_EXCEEDED')
  options.signal?.throwIfAborted()
  const result = new Uint8Array(reference.bytes)
  let offset = 0
  for await (const chunk of content.read(reference, options.signal === undefined ? {} : { signal: options.signal })) {
    options.signal?.throwIfAborted()
    if (!(chunk instanceof Uint8Array) || chunk.byteLength > CONTENT_CHUNK_BYTES || offset + chunk.byteLength > result.byteLength) throw new Error('CONTENT_CHUNK_SIZE_INVALID')
    result.set(chunk, offset); offset += chunk.byteLength
  }
  options.signal?.throwIfAborted()
  if (offset !== result.byteLength) throw new Error('CONTENT_INCOMPLETE')
  return result
}

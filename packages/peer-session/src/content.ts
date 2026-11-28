import {
  ContentAddressedStore,
  blobDagIndex,
  computeBlobDagHash,
  computeCasHash,
  encodeEncBlobManifest,
  putBlobDag,
  readBlobDag,
  statBlobDag,
  verifyBlobDagIndex,
  type BlobDagLeaf,
  type BytesStore,
} from '@chronolog/records'
import { encryptEpochPayload, decryptEpochPayload, type EncryptedEpochPayload } from '@chronolog/crypto'
import { bytesToHex, concatBytes, equalBytes, sha256, utf8 } from '@chronolog/canonical'
import { check, decodeRecord, encodeRecord, equalRecord, recordDigest, signRecord, verifyRecord, type Signed, type SigningIdentity } from '@chronolog/authority'
import {
  CONTENT_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_CONTENT_BYTES,
  isPublicBlobReference, isPrivateContentReference,
  putContentBytes, readContentBytes,
  type BlobGetOptions, type BlobInfo, type BlobPutOptions, type BlobReference,
  type ContentCacheStats, type ContentGetOptions, type ContentPruneResult,
  type ContentPutBytesOptions, type ContentPutOptions, type ContentReadBytesOptions,
  type ContentStreamPutOptions,
} from './content-bytes.js'
import { awaitOwnedTask } from './lifetime.js'
import { ChunkPuller, type ChunkSink, type RangeSource } from './content-pull.js'
export { CONTENT_CHUNK_BYTES, MAX_BLOB_BYTES, MAX_BLOB_CHUNKS, isPublicBlobReference, isPrivateContentReference } from './content-bytes.js'
export type {
  BlobGetOptions, BlobInfo, BlobPutOptions, BlobReference,
  ContentCacheStats, ContentGetOptions, ContentPruneResult,
  ContentPutBytesOptions, ContentPutOptions, ContentReadBytesOptions, ContentStreamPutOptions,
  PublicBlobReference,
} from './content-bytes.js'

export interface ContentAuthority {
  readonly applicationId: string
  isReader(publicKey: string): boolean
  currentEpoch(): number
  epochKey(epoch: number): Uint8Array | null
}

export const MAX_CONTENT_CHUNKS = MAX_CONTENT_BYTES / CONTENT_CHUNK_BYTES
/**
 * Binary encrypted chunk (stored and sent as-is): [format u8 = 1][epoch u64 BE][nonce 12][AES-GCM ciphertext+tag].
 * Exactly `CONTENT_CHUNK_HEADER_BYTES + plaintext + 16` bytes; no hex, JSON or base64 anywhere.
 */
export const CONTENT_CHUNK_HEADER_BYTES = 21
const CONTENT_CHUNK_FORMAT = 1, AES_GCM_TAG_BYTES = 16
export const MAX_CONTENT_ENCRYPTED_CHUNK_BYTES = CONTENT_CHUNK_BYTES + CONTENT_CHUNK_HEADER_BYTES + AES_GCM_TAG_BYTES
export const MAX_CONTENT_MANIFEST_BYTES = 256 * 1024
/** Bytes a single lazy pull keeps in flight ahead of its consumer (sliding window over all sources). */
export const CONTENT_FETCH_WINDOW_BYTES = 4 * 1024 * 1024
export interface ContentReference { readonly profile: 'authored-content-v1'; readonly applicationId: string; readonly id: string; readonly epoch: number; readonly bytes: number; readonly mediaType: string }
export interface ContentManifest { readonly stageId: string; readonly reference: Omit<ContentReference, 'id'>; readonly chunks: readonly { readonly hash: string; readonly bytes: number }[] }
export type ContentRetention = Signed<{ readonly reference: ContentReference; readonly peer: string; readonly storageId: string }>
export interface ContentOptions { readonly signal?: AbortSignal }
/** Interior nodes of a public blob DAG; enough to verify every leaf by its own hash. */
export interface BlobIndex { readonly hash: string; readonly bytes: number; readonly nodes: readonly Uint8Array[] }
export type { ChunkSink } from './content-pull.js'
export interface ContentSource {
  manifest(reference: ContentReference, options?: ContentOptions): Promise<ContentManifest | null>
  chunk(reference: ContentReference, index: number, options?: ContentOptions): Promise<Uint8Array | null>
  /** Stream chunks `start..start+count-1` in order to `onChunk` (null = not available here). */
  chunks?(reference: ContentReference, start: number, count: number, onChunk: ChunkSink, options?: ContentOptions): Promise<void>
  retained?(reference: ContentReference, options?: ContentOptions): Promise<ContentRetention>
  blobInfo?(hash: string, options?: ContentOptions): Promise<BlobInfo | null>
  blobChunk?(hash: string, index: number, options?: ContentOptions): Promise<Uint8Array | null>
  blobIndex?(hash: string, options?: ContentOptions): Promise<BlobIndex | null>
  /** Stream blob leaves `start..start+count-1` in order to `onChunk` (null = not available here). */
  blobChunks?(hash: string, start: number, count: number, onChunk: ChunkSink, options?: ContentOptions): Promise<void>
}
export interface ContentUpload {
  readonly id: string
  write(index: number, bytes: Uint8Array): Promise<void>
  progress(): Promise<{ readonly bytes: number; readonly storedBytes: number; readonly missingChunks: readonly number[] }>
  commit(): Promise<ContentReference>
  /** Release this upload's staging records; an already committed object remains independently retained. */
  discard(): Promise<void>
}
interface Stage { readonly stageId: string; readonly reference: Omit<ContentReference, 'id'>; readonly committed: ContentReference | null; readonly discarded: boolean }
const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const stageId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value)
function object(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'CONTENT_SHAPE_INVALID')
}
function assertReferenceBody(value: unknown): asserts value is Omit<ContentReference, 'id'> {
  object(value, ['profile', 'applicationId', 'epoch', 'bytes', 'mediaType'])
  check(value.profile === 'authored-content-v1' && digest(value.applicationId) && Number.isSafeInteger(value.epoch) && Number(value.epoch) >= 0 &&
    Number.isSafeInteger(value.bytes) && Number(value.bytes) >= 0 && Number(value.bytes) <= MAX_CONTENT_BYTES &&
    typeof value.mediaType === 'string' && value.mediaType.length > 0 && value.mediaType.length <= 256 && /^[\x20-\x7e]+$/u.test(value.mediaType), 'CONTENT_REFERENCE_INVALID')
}
export function assertContentReference(value: unknown): asserts value is ContentReference {
  object(value, ['profile', 'applicationId', 'id', 'epoch', 'bytes', 'mediaType'])
  check(digest(value.id), 'CONTENT_REFERENCE_INVALID')
  const { id: _id, ...body } = value
  assertReferenceBody(body)
}
export function assertContentManifest(value: unknown): asserts value is ContentManifest {
  object(value, ['stageId', 'reference', 'chunks'])
  check(stageId(value.stageId), 'CONTENT_MANIFEST_INVALID')
  assertReferenceBody(value.reference)
  check(Array.isArray(value.chunks) && value.chunks.length <= MAX_CONTENT_CHUNKS && value.chunks.length === Math.ceil(value.reference.bytes / CONTENT_CHUNK_BYTES), 'CONTENT_MANIFEST_INVALID')
  for (const chunk of value.chunks) {
    object(chunk, ['hash', 'bytes'])
    check(digest(chunk.hash) && Number.isSafeInteger(chunk.bytes) && Number(chunk.bytes) > 0 && Number(chunk.bytes) <= MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, 'CONTENT_MANIFEST_INVALID')
  }
  check(encodeRecord(value).length <= MAX_CONTENT_MANIFEST_BYTES, 'CONTENT_MANIFEST_INVALID')
}
export function assertContentRetention(value: unknown): asserts value is ContentRetention {
  object(value, ['payload', 'signer', 'signature'])
  check(digest(value.signer) && typeof value.signature === 'string' && /^[0-9a-f]{128}$/u.test(value.signature), 'CONTENT_RETENTION_INVALID')
  object(value.payload, ['reference', 'peer', 'storageId'])
  assertContentReference(value.payload.reference)
  check(value.payload.peer === value.signer && typeof value.payload.storageId === 'string' && value.payload.storageId.length > 0 && value.payload.storageId.length <= 256, 'CONTENT_RETENTION_INVALID')
}
export function assertBlobInfo(value: unknown): asserts value is BlobInfo {
  object(value, ['hash', 'bytes'])
  check(digest(value.hash) && Number.isSafeInteger(value.bytes) && Number(value.bytes) >= 0 && Number(value.bytes) <= MAX_BLOB_BYTES, 'CONTENT_BLOB_INVALID')
}
function body(reference: ContentReference): Omit<ContentReference, 'id'> { const { id: _id, ...rest } = reference; return rest }
function encodeChunk(payload: EncryptedEpochPayload): Uint8Array {
  const out = new Uint8Array(CONTENT_CHUNK_HEADER_BYTES + payload.ciphertext.length)
  out[0] = CONTENT_CHUNK_FORMAT
  new DataView(out.buffer).setBigUint64(1, payload.epoch)
  out.set(payload.nonce, 9); out.set(payload.ciphertext, CONTENT_CHUNK_HEADER_BYTES)
  return out
}
/** Parse a binary encrypted chunk as zero-copy views; the exact length binds it to its plaintext size. */
function envelope(bytes: Uint8Array, epoch: number, plaintextBytes: number): EncryptedEpochPayload {
  check(bytes instanceof Uint8Array && bytes.length === CONTENT_CHUNK_HEADER_BYTES + plaintextBytes + AES_GCM_TAG_BYTES && bytes[0] === CONTENT_CHUNK_FORMAT, 'CONTENT_CHUNK_INVALID')
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(1)
  check(value === BigInt(epoch), 'CONTENT_CHUNK_INVALID')
  return { epoch: value, nonce: bytes.subarray(9, CONTENT_CHUNK_HEADER_BYTES), ciphertext: bytes.subarray(CONTENT_CHUNK_HEADER_BYTES) }
}
const plainBytesAt = (reference: Omit<ContentReference, 'id'>, index: number): number => Math.min(CONTENT_CHUNK_BYTES, reference.bytes - index * CONTENT_CHUNK_BYTES)
/** Adapt a source to streamed range fetches; single-chunk sources are called once per index. */
function rangeOf(
  ranged: ((start: number, count: number, onChunk: ChunkSink, signal: AbortSignal) => Promise<void>) | undefined,
  single: (index: number, signal: AbortSignal) => Promise<Uint8Array | null>,
): RangeSource {
  return {
    async fetch(start, count, onChunk, signal) {
      if (ranged !== undefined) { await awaitOwnedTask(signal, () => ranged(start, count, onChunk, signal)); return }
      for (let index = start; index < start + count; index++) await onChunk(index, await awaitOwnedTask(signal, () => single(index, signal)))
    },
  }
}

interface ChunkReader { next(index: number): Promise<Uint8Array>; close(): void }
interface CacheEntry {
  readonly kind: 'public' | 'private'
  readonly key: string
  readonly bytes: number
  lastAccessMs: number
  pinned: boolean
  readonly reference?: ContentReference
}

/** Durable unified CAS-backed content (public chronolog-blob/v1 + epoch-encrypted chronolog-enc-blob/v1). */
export class ApplicationContent {
  readonly #sources = new Map<string, ContentSource>()
  readonly #reads = new Map<string, Set<AbortController>>()
  readonly #lifetime = new AbortController()
  readonly #prefix: string
  readonly #cas: ContentAddressedStore
  readonly #options: {
    readonly store: BytesStore
    readonly cas?: ContentAddressedStore
    readonly authority: ContentAuthority
    readonly identity: SigningIdentity
    readonly storageId: string
    readonly maxCacheBytes?: number
  }
  #cacheIndex: Map<string, CacheEntry> | null = null
  /** Last validated manifest per id, keyed by its exact stored bytes so a changed record is revalidated. */
  readonly #manifests = new Map<string, { readonly raw: Uint8Array; readonly manifest: ContentManifest }>()
  #tail: Promise<unknown> = Promise.resolve()
  constructor(options: {
    readonly store: BytesStore
    readonly cas?: ContentAddressedStore
    readonly authority: ContentAuthority
    readonly identity: SigningIdentity
    readonly storageId: string
    readonly maxCacheBytes?: number
  }) {
    check(typeof options.storageId === 'string' && options.storageId.length > 0 && options.storageId.length <= 256, 'CONTENT_STORAGE_ID_INVALID')
    this.#options = options
    this.#cas = options.cas ?? new ContentAddressedStore({ store: options.store })
    this.#prefix = `content/${options.authority.applicationId}`
  }
  get cas(): ContentAddressedStore {
    return this.#cas
  }
  #cacheEntryKey(kind: 'public' | 'private', key: string): string {
    return `${this.#prefix}/cache-entry/${kind}/${key}`
  }
  async #loadCacheIndex(): Promise<Map<string, CacheEntry>> {
    if (this.#cacheIndex !== null) return this.#cacheIndex
    const map = new Map<string, CacheEntry>()
    const entryPrefix = `${this.#prefix}/cache-entry/`
    const ingest = (entry: { readonly key: string; readonly value: Uint8Array }): void => {
      if (!entry.key.startsWith(entryPrefix) || entry.value.length === 0) return
      try {
        const item = decodeRecord<CacheEntry>(entry.value)
        if (item && typeof item.key === 'string' && (item.kind === 'public' || item.kind === 'private') && typeof item.bytes === 'number') {
          map.set(`${item.kind}:${item.key}`, { ...item, pinned: Boolean(item.pinned) })
        }
      } catch { /* ignore corrupt entry */ }
    }
    if (this.#options.store.iteratePrefix !== undefined) {
      for await (const entry of this.#options.store.iteratePrefix(entryPrefix)) ingest(entry)
    } else if (this.#options.store.iterateEntries !== undefined) {
      for await (const entry of this.#options.store.iterateEntries()) ingest(entry)
    } else if (this.#options.store.entries !== undefined) {
      for (const entry of await this.#options.store.entries()) ingest(entry)
    }
    this.#cacheIndex = map
    return map
  }
  async #saveCacheEntry(entry: CacheEntry): Promise<void> {
    await this.#options.store.put(this.#cacheEntryKey(entry.kind, entry.key), encodeRecord(entry), { durability: 'relaxed' })
  }
  async #touchCacheEntry(kind: 'public' | 'private', key: string, bytes: number, reference?: ContentReference): Promise<void> {
    const map = await this.#loadCacheIndex()
    const id = `${kind}:${key}`
    const prev = map.get(id)
    const next: CacheEntry = {
      kind,
      key,
      bytes,
      lastAccessMs: Date.now(),
      pinned: prev?.pinned ?? false,
      ...(reference !== undefined ? { reference } : prev?.reference !== undefined ? { reference: prev.reference } : {}),
    }
    map.set(id, next)
    await this.#saveCacheEntry(next)
  }
  async #dropCacheEntry(kind: 'public' | 'private', key: string): Promise<void> {
    const map = await this.#loadCacheIndex()
    if (map.delete(`${kind}:${key}`)) {
      await this.#remove(this.#cacheEntryKey(kind, key))
    }
  }
  #cacheIdOf(target: BlobReference | string): { readonly kind: 'public' | 'private'; readonly key: string } {
    if (typeof target === 'string') {
      check(digest(target), 'CONTENT_BLOB_INVALID')
      return { kind: 'public', key: target }
    }
    if (isPublicBlobReference(target)) {
      check(digest(target.hash), 'CONTENT_BLOB_INVALID')
      return { kind: 'public', key: target.hash }
    }
    if (isPrivateContentReference(target)) {
      const ref = this.#reference(target)
      return { kind: 'private', key: ref.id }
    }
    throw new Error('CONTENT_REFERENCE_INVALID')
  }
  #reader(): void { this.#lifetime.signal.throwIfAborted(); check(this.#options.authority.isReader(this.#options.identity.publicKey), 'CONTENT_READER_REQUIRED') }
  #reference(input: ContentReference): ContentReference {
    assertContentReference(input)
    check(input.applicationId === this.#options.authority.applicationId, 'CONTENT_SCOPE_INVALID')
    return { ...input }
  }
  #serial<T>(work: () => Promise<T>): Promise<T> {
    const task = this.#tail.then(() => { this.#lifetime.signal.throwIfAborted(); return work() })
    this.#tail = task.catch(() => undefined)
    return task
  }
  #scopeKey(key: string, options: ContentOptions): { signal: AbortSignal; release(): void } {
    this.#reader(); options.signal?.throwIfAborted()
    const controller = new AbortController()
    let reads = this.#reads.get(key)
    if (reads === undefined) { reads = new Set(); this.#reads.set(key, reads) }
    reads.add(controller)
    const signal = AbortSignal.any([this.#lifetime.signal, controller.signal, ...(options.signal === undefined ? [] : [options.signal])])
    signal.throwIfAborted()
    return { signal, release: () => { reads.delete(controller); if (reads.size === 0) this.#reads.delete(key) } }
  }
  #readScope(reference: ContentReference, options: ContentOptions): { signal: AbortSignal; release(): void } {
    return this.#scopeKey(reference.id, options)
  }
  #blobScope(hash: string, options: ContentOptions): { signal: AbortSignal; release(): void } {
    return this.#scopeKey(`blob:${hash}`, options)
  }
  attachSource(id: string, source: ContentSource): () => void {
    this.#lifetime.signal.throwIfAborted()
    check(typeof id === 'string' && id.length > 0 && id.length <= 256 && this.#sources.size < 8 && !this.#sources.has(id), 'CONTENT_SOURCE_LIMIT')
    this.#sources.set(id, source)
    let detached = false
    return () => { if (!detached) { detached = true; this.#sources.delete(id) } }
  }
  async stage(options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> {
    this.#reader()
    const id = crypto.randomUUID(), epoch = this.#options.authority.currentEpoch()
    const reference = { profile: 'authored-content-v1' as const, applicationId: this.#options.authority.applicationId, epoch, bytes: options.bytes, mediaType: options.mediaType ?? 'application/octet-stream' }
    assertReferenceBody(reference)
    check(this.#options.authority.epochKey(epoch) !== null, 'CONTENT_KEY_MISSING')
    await this.#serial(() => this.#options.store.put(`${this.#prefix}/stage/${id}`, encodeRecord({ stageId: id, reference, committed: null, discarded: false } satisfies Stage)))
    return this.resumeUpload(id)
  }
  async resumeUpload(id: string): Promise<ContentUpload> {
    this.#reader(); check(stageId(id), 'CONTENT_STAGE_INVALID')
    const key = `${this.#prefix}/stage/${id}`
    const readStage = async (): Promise<Stage> => {
      this.#reader()
      const raw = await this.#options.store.get(key); check(raw !== null, 'CONTENT_STAGE_MISSING')
      const stage = decodeRecord<Stage>(raw)
      object(stage, ['stageId', 'reference', 'committed', 'discarded']); assertReferenceBody(stage.reference)
      check(stage.stageId === id && stage.reference.applicationId === this.#options.authority.applicationId && typeof stage.discarded === 'boolean', 'CONTENT_STAGE_INVALID')
      if (stage.committed !== null) { assertContentReference(stage.committed); check(equalRecord(body(stage.committed), stage.reference), 'CONTENT_STAGE_INVALID') }
      check(!stage.discarded, 'CONTENT_STAGE_DISCARDED')
      return stage
    }
    const first = await readStage(), count = Math.ceil(first.reference.bytes / CONTENT_CHUNK_BYTES)
    return { id,
      write: (index, input) => {
        check(input instanceof Uint8Array && input.length <= CONTENT_CHUNK_BYTES, 'CONTENT_CHUNK_SIZE_INVALID')
        const bytes = input.slice()
        return this.#serial(async () => {
          const stage = await readStage()
          check(stage.committed === null && Number.isSafeInteger(index) && index >= 0 && index < count && bytes.length === Math.min(CONTENT_CHUNK_BYTES, stage.reference.bytes - index * CONTENT_CHUNK_BYTES), 'CONTENT_CHUNK_SIZE_INVALID')
          const epochKey = this.#options.authority.epochKey(stage.reference.epoch); check(epochKey !== null, 'CONTENT_KEY_MISSING')
          const aad = encodeRecord([this.#prefix, id, index]), existing = await this.#options.store.get(`${key}/chunk/${index}`)
          if (existing !== null) {
            const plaintext = await decryptEpochPayload(epochKey, envelope(existing, stage.reference.epoch, bytes.length), aad)
            check(equalBytes(plaintext, bytes), 'CONTENT_CHUNK_CONFLICT'); return
          }
          const encrypted = encodeChunk(await encryptEpochPayload(epochKey, BigInt(stage.reference.epoch), bytes, aad))
          await this.#options.store.put(`${key}/chunk/${index}`, encrypted)
        })
      },
      progress: () => this.#serial(async () => {
        const stage = await readStage(), missingChunks: number[] = []
        let storedBytes = 0
        for (let index = 0; index < count; index++) {
          const chunk = await this.#options.store.get(`${key}/chunk/${index}`)
          if (chunk === null) missingChunks.push(index)
          else { envelope(chunk, stage.reference.epoch, Math.min(CONTENT_CHUNK_BYTES, stage.reference.bytes - index * CONTENT_CHUNK_BYTES)); storedBytes += Math.min(CONTENT_CHUNK_BYTES, stage.reference.bytes - index * CONTENT_CHUNK_BYTES) }
        }
        return { bytes: stage.reference.bytes, storedBytes, missingChunks }
      }),
      commit: () => this.#serial(async () => {
        const stage = await readStage()
        if (stage.committed !== null) return structuredClone(stage.committed)
        const chunks: { hash: string; bytes: number }[] = []
        const encManifestChunks: { hash: string; bytes: number; plainBytes: number }[] = []
        const epochKey = this.#options.authority.epochKey(stage.reference.epoch); check(epochKey !== null, 'CONTENT_KEY_MISSING')
        for (let index = 0; index < count; index++) {
          const bytes = await this.#options.store.get(`${key}/chunk/${index}`); check(bytes !== null, 'CONTENT_INCOMPLETE')
          const plainBytes = Math.min(CONTENT_CHUNK_BYTES, stage.reference.bytes - index * CONTENT_CHUNK_BYTES)
          await decryptEpochPayload(epochKey, envelope(bytes, stage.reference.epoch, plainBytes), encodeRecord([this.#prefix, id, index]))
          const hash = await this.#cas.put(bytes, [], 'public', { cache: false })
          chunks.push({ hash, bytes: bytes.length })
          encManifestChunks.push({ hash, bytes: bytes.length, plainBytes })
        }
        const manifest: ContentManifest = { stageId: id, reference: stage.reference, chunks }
        const reference: ContentReference = { ...stage.reference, id: await recordDigest(manifest) }
        const encCas = encodeEncBlobManifest({
          format: 'chronolog-enc-blob/v1',
          applicationId: stage.reference.applicationId,
          epoch: stage.reference.epoch,
          bytes: stage.reference.bytes,
          mediaType: stage.reference.mediaType,
          stageId: id,
          chunks: encManifestChunks,
        })
        await this.#cas.put(encCas.bytes, encCas.links, 'public')
        await this.#options.store.put(`${this.#prefix}/manifest/${reference.id}`, encodeRecord(manifest))
        await this.#options.store.put(key, encodeRecord({ ...stage, committed: reference }))
        await this.#touchCacheEntry('private', reference.id, reference.bytes, reference)
        return reference
      }),
      discard: () => this.#serial(async () => {
        const raw = await this.#options.store.get(key)
        if (raw === null) return
        const stage = decodeRecord<Stage>(raw)
        // Persist the fence first, even on stores without a delete capability.
        await this.#options.store.put(key, encodeRecord({ ...stage, discarded: true }))
        for (let index = 0; index < count; index++) await this.#remove(`${key}/chunk/${index}`)
      }),
    }
  }
  async #remove(key: string): Promise<void> {
    if (this.#options.store.delete !== undefined) await this.#options.store.delete(key)
    else await this.#options.store.put(key, new Uint8Array())
  }
  async #validateManifest(manifest: ContentManifest, reference: ContentReference): Promise<void> {
    assertContentManifest(manifest)
    check(equalRecord(manifest.reference, body(reference)) && await recordDigest(manifest) === reference.id, 'CONTENT_MANIFEST_INVALID')
  }
  #rememberManifest(id: string, raw: Uint8Array, manifest: ContentManifest): void {
    this.#manifests.delete(id); this.#manifests.set(id, { raw, manifest })
    while (this.#manifests.size > 64) this.#manifests.delete(this.#manifests.keys().next().value!)
  }
  async #manifest(reference: ContentReference, signal: AbortSignal, localOnly = false): Promise<ContentManifest | null> {
    signal.throwIfAborted(); this.#reader()
    const raw = await awaitOwnedTask(signal, () => this.#options.store.get(`${this.#prefix}/manifest/${reference.id}`))
    if (raw !== null && raw.length > 0) {
      check(raw.length <= MAX_CONTENT_MANIFEST_BYTES, 'CONTENT_MANIFEST_INVALID')
      // Serving issues one manifest lookup per range request: skip re-validation of identical bytes.
      const known = this.#manifests.get(reference.id)
      if (known !== undefined && equalBytes(known.raw, raw)) { signal.throwIfAborted(); return known.manifest }
      const manifest = decodeRecord<ContentManifest>(raw); await this.#validateManifest(manifest, reference); signal.throwIfAborted()
      this.#rememberManifest(reference.id, raw, manifest)
      return manifest
    }
    this.#manifests.delete(reference.id)
    if (localOnly) return null
    let failure: unknown
    for (const source of [...this.#sources.values()]) {
      try {
        const candidate = await awaitOwnedTask(signal, () => source.manifest(reference, { signal }))
        if (candidate === null) continue
        assertContentManifest(candidate)
        const manifest = structuredClone(candidate)
        await this.#validateManifest(manifest, reference)
        await this.#serial(async () => { signal.throwIfAborted(); this.#reader(); await this.#options.store.put(`${this.#prefix}/manifest/${reference.id}`, encodeRecord(manifest)) })
        return manifest
      } catch (error) { signal.throwIfAborted(); failure = error }
    }
    if (failure !== undefined) throw failure instanceof Error ? failure : new Error('CONTENT_SOURCE_FAILED', { cause: failure })
    throw new Error('CONTENT_MANIFEST_MISSING')
  }
  /** A locally stored chunk. CAS is keyed by hash and verifies bytes loaded from the store, so no rehash here. */
  async #localChunk(reference: ContentReference, manifest: ContentManifest, index: number, signal: AbortSignal): Promise<Uint8Array | null> {
    signal.throwIfAborted(); this.#reader()
    const descriptor = manifest.chunks[index]; check(descriptor !== undefined, 'CONTENT_CHUNK_INDEX_INVALID')
    const storedNode = await awaitOwnedTask(signal, () => this.#cas.get(descriptor.hash, 'public', { cache: false }))
    if (storedNode === null || storedNode.bytes.length === 0) return null
    check(storedNode.bytes.length === descriptor.bytes, 'CONTENT_CHUNK_INVALID')
    envelope(storedNode.bytes, reference.epoch, plainBytesAt(reference, index))
    signal.throwIfAborted()
    return storedNode.bytes
  }
  /** Verify a remote chunk exactly once (envelope shape, then one hash inside the CAS write) and persist it. */
  async #acceptChunk(reference: ContentReference, manifest: ContentManifest, index: number, bytes: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
    const descriptor = manifest.chunks[index]; check(descriptor !== undefined, 'CONTENT_CHUNK_INDEX_INVALID')
    check(bytes instanceof Uint8Array && bytes.length === descriptor.bytes, 'CONTENT_CHUNK_INVALID')
    envelope(bytes, reference.epoch, plainBytesAt(reference, index))
    await this.#serial(async () => {
      signal.throwIfAborted(); this.#reader()
      try { await this.#cas.putVerified(descriptor.hash, bytes, [], 'public', { cache: false }) }
      catch (error) { throw error instanceof Error && error.message === 'CAS_HASH_MISMATCH' ? new Error('CONTENT_CHUNK_INVALID') : error }
    })
    return bytes
  }
  /** In-order chunk reader: local chunks directly, remote ones through one windowed multi-source puller. */
  #chunkReader(reference: ContentReference, manifest: ContentManifest, signal: AbortSignal, eager = false): ChunkReader {
    let puller: ChunkPuller | undefined
    return {
      next: async index => {
        if (puller === undefined) {
          const local = await this.#localChunk(reference, manifest, index, signal)
          if (local !== null) return local
          const sources = [...this.#sources.values()].map(source => rangeOf(
            source.chunks === undefined ? undefined : (start, count, sink, s) => source.chunks!(reference, start, count, sink, { signal: s }),
            (i, s) => source.chunk(reference, i, { signal: s })))
          if (sources.length === 0) throw new Error('CONTENT_CHUNK_MISSING')
          puller = new ChunkPuller({
            count: manifest.chunks.length, start: index, sources, signal, missing: 'CONTENT_CHUNK_MISSING',
            local: (i, s) => this.#localChunk(reference, manifest, i, s),
            accept: (i, bytes, s) => this.#acceptChunk(reference, manifest, i, bytes, s),
            windowChunks: CONTENT_FETCH_WINDOW_BYTES / CONTENT_CHUNK_BYTES,
            // Streaming reads slow-start so an early stop pulls about what was read; retention wants it all.
            ...(eager ? { initialWindow: CONTENT_FETCH_WINDOW_BYTES / CONTENT_CHUNK_BYTES } : {}),
          })
        }
        return puller.take(index)
      },
      close: () => puller?.close(),
    }
  }
  async *read(input: ContentReference, options: ContentOptions = {}): AsyncIterable<Uint8Array> {
    const reference = this.#reference(input), scope = this.#readScope(reference, options)
    let chunks: ChunkReader | undefined
    try {
      const manifest = await this.#manifest(reference, scope.signal); check(manifest !== null, 'CONTENT_MANIFEST_MISSING')
      const key = this.#options.authority.epochKey(reference.epoch); check(key !== null, 'CONTENT_KEY_MISSING')
      chunks = this.#chunkReader(reference, manifest, scope.signal)
      for (let index = 0; index < manifest.chunks.length; index++) {
        const bytes = await chunks.next(index)
        const plaintext = await decryptEpochPayload(key, envelope(bytes, reference.epoch, plainBytesAt(reference, index)), encodeRecord([this.#prefix, manifest.stageId, index]))
        scope.signal.throwIfAborted(); this.#reader(); yield plaintext
      }
    } finally { chunks?.close(); scope.release() }
  }
  async #receipt(reference: ContentReference, signal: AbortSignal): Promise<ContentRetention> {
    const receipt = await signRecord('content-retention', { reference, peer: this.#options.identity.publicKey, storageId: this.#options.storageId }, this.#options.identity)
    signal.throwIfAborted(); this.#reader(); return receipt
  }
  /** Transfer/check the entire encrypted object before claiming local retention. */
  async retain(input: ContentReference, options: ContentOptions = {}): Promise<ContentRetention> {
    const reference = this.#reference(input), scope = this.#readScope(reference, options)
    try {
      const manifest = await this.#manifest(reference, scope.signal); check(manifest !== null, 'CONTENT_MANIFEST_MISSING')
      const chunks = this.#chunkReader(reference, manifest, scope.signal, true)
      try { for (let index = 0; index < manifest.chunks.length; index++) await chunks.next(index) } finally { chunks.close() }
      return await this.#receipt(reference, scope.signal)
    } finally { scope.release() }
  }
  async verifyRetention(input: ContentReference, receipt: ContentRetention, expectedPeer?: string): Promise<void> {
    const reference = this.#reference(input)
    assertContentRetention(receipt)
    check(equalRecord(receipt.payload.reference, reference) && (expectedPeer === undefined || receipt.signer === expectedPeer) && this.#options.authority.isReader(receipt.signer), 'CONTENT_RETENTION_INVALID')
    await verifyRecord('content-retention', receipt, expectedPeer)
  }
  /** Ask attached sources to retain the object; these signed availability facts are not finality. */
  async retention(input: ContentReference, options: ContentOptions = {}): Promise<readonly ContentRetention[]> {
    const reference = this.#reference(input), scope = this.#readScope(reference, options)
    try {
      const receipts = new Map((await this.retained(reference)).map(receipt => [receipt.signer, receipt]))
      for (const source of [...this.#sources.values()]) {
        if (source.retained === undefined) continue
        const receipt = await awaitOwnedTask(scope.signal, () => source.retained!(reference, { signal: scope.signal }))
        await this.verifyRetention(reference, receipt)
        if (receipt.signer === this.#options.identity.publicKey || receipt.payload.storageId === this.#options.storageId) continue
        check(receipts.size < 8 || receipts.has(receipt.signer), 'CONTENT_RETENTION_LIMIT')
        receipts.set(receipt.signer, structuredClone(receipt))
        await this.#serial(async () => {
          scope.signal.throwIfAborted()
          const stored = new Map((await this.retained(reference)).map(value => [value.signer, value]))
          check(stored.size < 8 || stored.has(receipt.signer), 'CONTENT_RETENTION_LIMIT')
          stored.set(receipt.signer, structuredClone(receipt))
          await this.#options.store.put(`${this.#prefix}/retentions/${reference.id}`, encodeRecord([...stored.values()]))
        })
      }
      scope.signal.throwIfAborted()
      return await this.retained(reference)
    } finally { scope.release() }
  }
  async retained(input: ContentReference): Promise<readonly ContentRetention[]> {
    this.#reader(); const reference = this.#reference(input)
    const raw = await this.#options.store.get(`${this.#prefix}/retentions/${reference.id}`)
    if (raw === null || raw.length === 0) return []
    check(raw.length <= 16 * 1024, 'CONTENT_RETENTION_LIMIT')
    const receipts = decodeRecord<ContentRetention[]>(raw)
    check(Array.isArray(receipts) && receipts.length <= 8, 'CONTENT_RETENTION_LIMIT')
    for (const receipt of receipts) await this.verifyRetention(reference, receipt)
    return receipts.filter(receipt => receipt.signer !== this.#options.identity.publicKey && receipt.payload.storageId !== this.#options.storageId)
  }
  async discard(input: ContentReference): Promise<void> {
    this.#reader(); const reference = this.#reference(input)
    for (const read of this.#reads.get(reference.id) ?? []) read.abort(new Error('CONTENT_DISCARDED'))
    await this.#serial(async () => {
      const manifest = await this.#manifest(reference, this.#lifetime.signal, true)
      await this.#remove(`${this.#prefix}/manifest/${reference.id}`)
      await this.#remove(`${this.#prefix}/retentions/${reference.id}`)
      const chunkHashes = (manifest?.chunks ?? []).map(c => c.hash)
      for (const h of chunkHashes) this.#cas.unpin(h)
      if (chunkHashes.length > 0) await this.#cas.deleteNodes(chunkHashes, 'public')
      await this.#dropCacheEntry('private', reference.id)
    })
  }
  async #localBlobInfo(hash: string, signal: AbortSignal): Promise<BlobInfo | null> {
    signal.throwIfAborted(); this.#reader()
    const st = await awaitOwnedTask(signal, () => statBlobDag(this.#cas, hash, 'public'))
    if (st === null) return null
    signal.throwIfAborted()
    return { hash, bytes: st.bytes }
  }
  /** Verified leaf list of a local blob, or null when it is not (fully indexed) here. */
  async #localBlobIndex(hash: string, signal: AbortSignal): Promise<BlobIndex & { readonly leaves: readonly BlobDagLeaf[] } | null> {
    signal.throwIfAborted(); this.#reader()
    try { return await awaitOwnedTask(signal, () => blobDagIndex(this.#cas, hash, 'public')) }
    catch (error) { signal.throwIfAborted(); if (error instanceof Error && error.message.startsWith('CAS_BLOB_')) return null; throw error }
  }
  /** Pull every leaf of a verified blob index through the windowed puller; leaves are hashed once on arrival. */
  async #pullBlob(hash: string, bytes: number, leaves: readonly BlobDagLeaf[], interior: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly links: readonly string[] }[],
    first: ContentSource, cache: boolean, signal: AbortSignal): Promise<Uint8Array> {
    const ordered = [first, ...[...this.#sources.values()].filter(source => source !== first)]
    const sources = ordered.filter(source => source.blobChunks !== undefined || source.blobChunk !== undefined)
      .map(source => rangeOf(
        source.blobChunks === undefined ? undefined : (start, count, sink, s) => source.blobChunks!(hash, start, count, sink, { signal: s }),
        async (i, s) => source.blobChunk === undefined ? null : source.blobChunk(hash, i, { signal: s })))
    const assembled = new Uint8Array(bytes)
    const puller = new ChunkPuller({
      count: leaves.length, sources, signal, missing: 'CONTENT_BLOB_MISSING',
      windowChunks: CONTENT_FETCH_WINDOW_BYTES / CONTENT_CHUNK_BYTES, initialWindow: CONTENT_FETCH_WINDOW_BYTES / CONTENT_CHUNK_BYTES,
      local: async (i, s) => {
        const node = await awaitOwnedTask(s, () => this.#cas.get(leaves[i]!.hash, 'public', { cache: false }))
        return node !== null && node.links.length === 0 && node.bytes.length === leaves[i]!.bytes ? node.bytes : null
      },
      accept: async (i, chunk, s) => {
        const leaf = leaves[i]!
        check(chunk instanceof Uint8Array && chunk.byteLength === leaf.bytes, 'CONTENT_BLOB_INVALID')
        if (!cache) { check(computeCasHash(chunk, []) === leaf.hash, 'CONTENT_BLOB_INVALID'); return chunk }
        await this.#serial(async () => {
          s.throwIfAborted(); this.#reader()
          try { await this.#cas.putVerified(leaf.hash, chunk, [], 'public', { cache: false }) }
          catch (error) { throw error instanceof Error && error.message === 'CAS_HASH_MISMATCH' ? new Error('CONTENT_BLOB_INVALID') : error }
        })
        return chunk
      },
    })
    try {
      for (let index = 0; index < leaves.length; index++) assembled.set(await puller.take(index), index * CONTENT_CHUNK_BYTES)
    } finally { puller.close() }
    signal.throwIfAborted()
    if (cache) {
      await this.#serial(async () => {
        signal.throwIfAborted(); this.#reader()
        // Interior nodes bottom-up, root last: a stored root always means a complete local DAG.
        for (let index = interior.length - 1; index >= 0; index--) await this.#cas.putVerified(interior[index]!.hash, interior[index]!.bytes, interior[index]!.links, 'public')
        await this.#touchCacheEntry('public', hash, bytes)
      })
    }
    return assembled
  }
  async #storeLocalBlob(bytes: Uint8Array, signal: AbortSignal): Promise<BlobInfo> {
    let info!: BlobInfo
    await this.#serial(async () => {
      signal.throwIfAborted(); this.#reader()
      const stored = await putBlobDag(this.#cas, bytes, 'public')
      info = { hash: stored.hash, bytes: stored.bytes }
      await this.#touchCacheEntry('public', info.hash, info.bytes)
    })
    return info
  }
  /** Store bytes into unified Merkle-DAG CAS (chronolog-blob/v1) so peers and reducers share one hash space. */
  async putBlob(input: Uint8Array, options: BlobPutOptions = {}): Promise<BlobInfo> {
    this.#reader()
    check(input instanceof Uint8Array && input.byteLength <= MAX_BLOB_BYTES, 'CONTENT_RANGE_INVALID')
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    signal.throwIfAborted()
    const bytes = input.slice()
    return this.#storeLocalBlob(bytes, signal)
  }
  async hasBlob(hash: string): Promise<boolean> {
    this.#reader(); check(digest(hash), 'CONTENT_BLOB_INVALID')
    try {
      const data = await readBlobDag(this.#cas, hash, 'public', { maxBytes: MAX_BLOB_BYTES })
      return data !== null
    } catch {
      return false
    }
  }
  /** Retrieve a CAS chronolog-blob/v1 locally, falling back to connected peers and verifying the CAS root hash. */
  async getBlob(hash: string, options: BlobGetOptions = {}): Promise<Uint8Array | null> {
    check(digest(hash), 'CONTENT_BLOB_INVALID')
    const maxBytes = options.maxBytes ?? MAX_BLOB_BYTES
    check(Number.isSafeInteger(maxBytes) && maxBytes >= 0 && maxBytes <= MAX_BLOB_BYTES, 'CONTENT_READ_LIMIT_INVALID')
    if (options.expectedBytes !== undefined) {
      check(Number.isSafeInteger(options.expectedBytes) && options.expectedBytes >= 0 && options.expectedBytes <= MAX_BLOB_BYTES, 'CONTENT_BLOB_INVALID')
      check(options.expectedBytes <= maxBytes, 'CONTENT_READ_LIMIT_EXCEEDED')
    }
    const scope = this.#blobScope(hash, options)
    try {
      const localInfo = await this.#localBlobInfo(hash, scope.signal)
      if (localInfo !== null) {
        if (options.expectedBytes !== undefined) check(localInfo.bytes === options.expectedBytes, 'CONTENT_BLOB_INVALID')
        check(localInfo.bytes <= maxBytes, 'CONTENT_READ_LIMIT_EXCEEDED')
        // CAS nodes are addressed by hash and verified when loaded from the store: no whole-blob rehash.
        const assembled = await awaitOwnedTask(scope.signal, () => readBlobDag(this.#cas, hash, 'public', { maxBytes }))
        if (assembled !== null) { scope.signal.throwIfAborted(); return assembled }
      }
      if (options.localOnly === true) return null
      let failure: unknown
      for (const source of [...this.#sources.values()]) {
        try {
          if (source.blobIndex !== undefined) {
            const index = await awaitOwnedTask(scope.signal, () => source.blobIndex!(hash, { signal: scope.signal }))
            if (index === null) continue
            check(index !== null && typeof index === 'object' && index.hash === hash && Array.isArray(index.nodes) && index.nodes.length <= 64, 'CONTENT_BLOB_INVALID')
            assertBlobInfo({ hash: index.hash, bytes: index.bytes })
            if (options.expectedBytes !== undefined) check(index.bytes === options.expectedBytes, 'CONTENT_BLOB_INVALID')
            check(index.bytes <= maxBytes, 'CONTENT_READ_LIMIT_EXCEEDED')
            let verified: ReturnType<typeof verifyBlobDagIndex>
            try { verified = verifyBlobDagIndex(hash, index.bytes, index.nodes) } catch { throw new Error('CONTENT_BLOB_INVALID') }
            return await this.#pullBlob(hash, index.bytes, verified.leaves, verified.interior, source, options.cache !== false, scope.signal)
          }
          if (source.blobInfo === undefined || source.blobChunk === undefined) continue
          // Sources without an index: whole-blob verification after assembly.
          const info = await awaitOwnedTask(scope.signal, () => source.blobInfo!(hash, { signal: scope.signal }))
          if (info === null) continue
          assertBlobInfo(info)
          check(info.hash === hash, 'CONTENT_BLOB_INVALID')
          if (options.expectedBytes !== undefined) check(info.bytes === options.expectedBytes, 'CONTENT_BLOB_INVALID')
          check(info.bytes <= maxBytes, 'CONTENT_READ_LIMIT_EXCEEDED')
          const count = Math.ceil(info.bytes / CONTENT_CHUNK_BYTES)
          const assembled = new Uint8Array(info.bytes)
          for (let index = 0; index < count; index++) {
            const expectedLen = Math.min(CONTENT_CHUNK_BYTES, info.bytes - index * CONTENT_CHUNK_BYTES)
            const chunk = await awaitOwnedTask(scope.signal, () => source.blobChunk!(hash, index, { signal: scope.signal }))
            check(chunk instanceof Uint8Array && chunk.byteLength === expectedLen, 'CONTENT_BLOB_INVALID')
            assembled.set(chunk, index * CONTENT_CHUNK_BYTES)
          }
          check(computeBlobDagHash(assembled) === hash, 'CONTENT_BLOB_INVALID')
          scope.signal.throwIfAborted()
          if (options.cache !== false) await this.#storeLocalBlob(assembled, scope.signal)
          return assembled
        } catch (error) { scope.signal.throwIfAborted(); failure = error }
      }
      if (failure !== undefined) throw failure instanceof Error ? failure : new Error('CONTENT_SOURCE_FAILED', { cause: failure })
      return null
    } finally { scope.release() }
  }
  async deleteBlob(hash: string): Promise<void> {
    this.#reader(); check(digest(hash), 'CONTENT_BLOB_INVALID')
    for (const read of this.#reads.get(`blob:${hash}`) ?? []) read.abort(new Error('CONTENT_DISCARDED'))
    await this.#serial(async () => {
      this.#cas.unpin(hash)
      const nodes = await this.#cas.reachable([hash])
      if (nodes.size > 0) await this.#cas.deleteNodes(nodes, 'public')
      await this.#dropCacheEntry('public', hash)
    })
  }
  /** Serve only verified local bytes. Serving never recursively consults remote sources. */
  source(): ContentSource {
    const range = (count: number, start: number, length: number): void => {
      check(Number.isSafeInteger(start) && Number.isSafeInteger(length) && start >= 0 && length > 0 && start + length <= count, 'CONTENT_CHUNK_INDEX_INVALID')
    }
    const chunks = async (input: ContentReference, start: number, count: number, onChunk: ChunkSink, options: ContentOptions = {}): Promise<void> => {
      const reference = this.#reference(input), scope = this.#readScope(reference, options)
      try {
        range(Math.ceil(reference.bytes / CONTENT_CHUNK_BYTES), start, count)
        const manifest = await this.#manifest(reference, scope.signal, true)
        for (let index = start; index < start + count; index++) await onChunk(index, manifest === null ? null : await this.#localChunk(reference, manifest, index, scope.signal))
      } finally { scope.release() }
    }
    const blobChunks = async (hash: string, start: number, count: number, onChunk: ChunkSink, options: ContentOptions = {}): Promise<void> => {
      check(digest(hash), 'CONTENT_BLOB_INVALID')
      const scope = this.#blobScope(hash, options)
      try {
        check(Number.isSafeInteger(start) && Number.isSafeInteger(count) && start >= 0 && count > 0 && start + count <= MAX_BLOB_BYTES / CONTENT_CHUNK_BYTES, 'CONTENT_CHUNK_INDEX_INVALID')
        const index = await this.#localBlobIndex(hash, scope.signal)
        for (let i = start; i < start + count; i++) {
          const leaf = index?.leaves[i]
          const node = leaf === undefined ? null : await awaitOwnedTask(scope.signal, () => this.#cas.get(leaf.hash, 'public', { cache: false }))
          await onChunk(i, node === null || node.links.length !== 0 ? null : node.bytes)
        }
      } finally { scope.release() }
    }
    const one = async (run: (sink: ChunkSink) => Promise<void>): Promise<Uint8Array | null> => {
      let value: Uint8Array | null = null
      await run((_index, bytes) => { value = bytes })
      return value
    }
    return {
      manifest: async (input, options = {}) => {
        const reference = this.#reference(input), scope = this.#readScope(reference, options)
        try { return await this.#manifest(reference, scope.signal, true) } finally { scope.release() }
      },
      chunk: (input, index, options = {}) => one(sink => chunks(input, index, 1, sink, options)),
      chunks,
      retained: async (input, options = {}) => {
        const reference = this.#reference(input), scope = this.#readScope(reference, options)
        try {
          const manifest = await this.#manifest(reference, scope.signal, true); check(manifest !== null, 'CONTENT_MANIFEST_MISSING')
          for (let index = 0; index < manifest.chunks.length; index++) check(await this.#localChunk(reference, manifest, index, scope.signal) !== null, 'CONTENT_INCOMPLETE')
          return await this.#receipt(reference, scope.signal)
        } finally { scope.release() }
      },
      blobInfo: async (hash, options = {}) => {
        check(digest(hash), 'CONTENT_BLOB_INVALID')
        const scope = this.#blobScope(hash, options)
        try { return await this.#localBlobInfo(hash, scope.signal) } finally { scope.release() }
      },
      blobIndex: async (hash, options = {}) => {
        check(digest(hash), 'CONTENT_BLOB_INVALID')
        const scope = this.#blobScope(hash, options)
        try {
          const index = await this.#localBlobIndex(hash, scope.signal)
          return index === null ? null : { hash, bytes: index.bytes, nodes: index.nodes }
        } finally { scope.release() }
      },
      blobChunk: (hash, index, options = {}) => one(sink => blobChunks(hash, index, 1, sink, options)),
      blobChunks,
    }
  }
  putBytes(bytes: Uint8Array, options?: ContentPutBytesOptions): Promise<ContentReference> { return putContentBytes(this, bytes, options) }
  readBytes(reference: ContentReference, options: ContentReadBytesOptions): Promise<Uint8Array> { return readContentBytes(this, reference, options) }
  /**
   * Keyed-convergent deterministic encryption under the current epoch key:
   * identical plaintext uploaded by different readers in the same epoch produces
   * the exact same `ContentReference` and chunk hashes, while remaining opaque
   * to any party without the epoch key.
   */
  async #putPrivateConvergent(input: Uint8Array, options: ContentPutBytesOptions = {}): Promise<ContentReference> {
    this.#reader()
    check(input instanceof Uint8Array && input.byteLength <= MAX_CONTENT_BYTES, 'CONTENT_RANGE_INVALID')
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    signal.throwIfAborted()
    const bytes = input.slice()
    const epoch = this.#options.authority.currentEpoch()
    const mediaType = options.mediaType ?? 'application/octet-stream'
    const refBody: Omit<ContentReference, 'id'> = {
      profile: 'authored-content-v1',
      applicationId: this.#options.authority.applicationId,
      epoch,
      bytes: bytes.byteLength,
      mediaType,
    }
    assertReferenceBody(refBody)
    const epochKey = this.#options.authority.epochKey(epoch)
    check(epochKey !== null, 'CONTENT_KEY_MISSING')
    const plainDigest = await awaitOwnedTask(signal, () => sha256(bytes))
    const stageBytes = await awaitOwnedTask(signal, () =>
      sha256(concatBytes(utf8('chronolog/convergent-stage/v2:'), epochKey, utf8(this.#prefix), utf8(mediaType), plainDigest)),
    )
    const uuidHex = bytesToHex(stageBytes.subarray(0, 16))
    const id = `${uuidHex.slice(0, 8)}-${uuidHex.slice(8, 12)}-4${uuidHex.slice(13, 16)}-8${uuidHex.slice(17, 20)}-${uuidHex.slice(20, 32)}`
    const count = Math.ceil(bytes.byteLength / CONTENT_CHUNK_BYTES)
    const encryptedChunks: { hash: string; bytes: Uint8Array }[] = []
    for (let index = 0; index < count; index++) {
      signal.throwIfAborted()
      const plainChunk = bytes.subarray(index * CONTENT_CHUNK_BYTES, Math.min(bytes.byteLength, (index + 1) * CONTENT_CHUNK_BYTES))
      const nonceDigest = await awaitOwnedTask(signal, () =>
        sha256(concatBytes(utf8('chronolog/convergent-nonce/v2:'), epochKey, utf8(this.#prefix), plainDigest, utf8(`:${index}`))),
      )
      const encrypted = encodeChunk(await awaitOwnedTask(signal, () =>
        encryptEpochPayload(epochKey, BigInt(epoch), plainChunk, encodeRecord([this.#prefix, id, index]), nonceDigest.subarray(0, 12)),
      ))
      const hash = computeCasHash(encrypted, [])
      encryptedChunks.push({ hash, bytes: encrypted })
    }
    const manifest: ContentManifest = {
      stageId: id,
      reference: refBody,
      chunks: encryptedChunks.map(c => ({ hash: c.hash, bytes: c.bytes.length })),
    }
    const reference: ContentReference = { ...refBody, id: await recordDigest(manifest) }
    await this.#serial(async () => {
      signal.throwIfAborted(); this.#reader()
      const encManifestChunks: { hash: string; bytes: number; plainBytes: number }[] = []
      for (let index = 0; index < encryptedChunks.length; index++) {
        const chunk = encryptedChunks[index]!
        await this.#cas.put(chunk.bytes, [], 'public', { cache: false })
        encManifestChunks.push({
          hash: chunk.hash,
          bytes: chunk.bytes.length,
          plainBytes: Math.min(CONTENT_CHUNK_BYTES, bytes.byteLength - index * CONTENT_CHUNK_BYTES),
        })
      }
      const encCas = encodeEncBlobManifest({
        format: 'chronolog-enc-blob/v1',
        applicationId: refBody.applicationId,
        epoch: refBody.epoch,
        bytes: refBody.bytes,
        mediaType: refBody.mediaType,
        stageId: id,
        chunks: encManifestChunks,
      })
      await this.#cas.put(encCas.bytes, encCas.links, 'public')
      await this.#options.store.put(`${this.#prefix}/manifest/${reference.id}`, encodeRecord(manifest))
      await this.#touchCacheEntry('private', reference.id, reference.bytes, reference)
    })
    return reference
  }
  /** Stream an async iterable of Uint8Array chunks into private or public lazy-pull content without holding the entire file in memory. */
  async putStream(
    chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
    options: ContentStreamPutOptions = {},
  ): Promise<BlobReference> {
    const visibility = options.visibility ?? 'private'
    const mediaType = options.mediaType ?? 'application/octet-stream'
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    signal.throwIfAborted()
    if (visibility === 'private' && options.totalBytes !== undefined) {
      this.#reader()
      const total = options.totalBytes
      check(Number.isSafeInteger(total) && total >= 0 && total <= MAX_CONTENT_BYTES, 'CONTENT_RANGE_INVALID')
      const upload = await this.stage({ bytes: total, mediaType })
      let written = 0
      let chunkIndex = 0
      let buffer: Uint8Array = new Uint8Array(0)
      try {
        for await (const part of chunks) {
          signal.throwIfAborted()
          check(part instanceof Uint8Array, 'CONTENT_CHUNK_SIZE_INVALID')
          if (part.byteLength === 0) continue
          buffer = buffer.byteLength === 0 ? part.slice() : concatBytes(buffer, part)
          while (buffer.byteLength >= CONTENT_CHUNK_BYTES) {
            const slice = buffer.subarray(0, CONTENT_CHUNK_BYTES)
            await upload.write(chunkIndex++, slice)
            written += slice.byteLength
            buffer = buffer.subarray(CONTENT_CHUNK_BYTES)
          }
        }
        if (buffer.byteLength > 0) {
          await upload.write(chunkIndex++, buffer)
          written += buffer.byteLength
        }
        check(written === total, 'CONTENT_INCOMPLETE')
        return await upload.commit()
      } catch (error) {
        await upload.discard().catch(() => undefined)
        throw error
      }
    }
    const maxAllowed = visibility === 'public' ? MAX_BLOB_BYTES : MAX_CONTENT_BYTES
    const parts: Uint8Array[] = []
    let total = 0
    for await (const part of chunks) {
      signal.throwIfAborted()
      check(part instanceof Uint8Array, 'CONTENT_CHUNK_SIZE_INVALID')
      total += part.byteLength
      check(total <= maxAllowed, 'CONTENT_RANGE_INVALID')
      if (part.byteLength > 0) parts.push(part.slice())
    }
    const assembled = parts.length === 0 ? new Uint8Array(0) : concatBytes(...parts)
    return this.put(assembled, { visibility, mediaType, ...(options.signal === undefined ? {} : { signal: options.signal }) })
  }
  /** Stream verified chunks for either a private ContentReference or a public PublicBlobReference / SHA-256 hash. */
  async *readStream(target: BlobReference | string, options: ContentGetOptions = {}): AsyncIterable<Uint8Array> {
    if (isPrivateContentReference(target)) {
      const ref = this.#reference(target)
      if (options.maxBytes !== undefined) check(ref.bytes <= options.maxBytes, 'CONTENT_READ_LIMIT_EXCEEDED')
      for await (const chunk of this.read(ref, options.signal === undefined ? {} : { signal: options.signal })) {
        yield chunk
      }
      return
    }
    const hash = typeof target === 'string' ? target : isPublicBlobReference(target) ? target.hash : ''
    check(digest(hash), 'CONTENT_REFERENCE_INVALID')
    const expectedBytes = options.expectedBytes ?? (isPublicBlobReference(target) ? target.bytes : undefined)
    const bytes = await this.getBlob(hash, { ...options, ...(expectedBytes === undefined ? {} : { expectedBytes }) })
    if (bytes === null) throw new Error('CONTENT_BLOB_MISSING')
    for (let offset = 0; offset < bytes.byteLength; offset += CONTENT_CHUNK_BYTES) {
      yield bytes.subarray(offset, Math.min(bytes.byteLength, offset + CONTENT_CHUNK_BYTES))
    }
  }
  /** Pin a cached blob or private content item so `pruneCache()` will never evict it. */
  async pin(target: BlobReference | string): Promise<void> {
    this.#reader()
    const { kind, key } = this.#cacheIdOf(target)
    await this.#serial(async () => {
      const map = await this.#loadCacheIndex()
      const id = `${kind}:${key}`
      const existing = map.get(id)
      if (existing !== undefined) {
        existing.pinned = true
        existing.lastAccessMs = Date.now()
        await this.#saveCacheEntry(existing)
      } else {
        const created: CacheEntry = {
          kind,
          key,
          bytes: typeof target === 'string' ? 0 : target.bytes,
          lastAccessMs: Date.now(),
          pinned: true,
          ...(isPrivateContentReference(target) ? { reference: this.#reference(target) } : {}),
        }
        map.set(id, created)
        await this.#saveCacheEntry(created)
      }
      if (kind === 'public') this.#cas.pin(key)
    })
  }
  async unpin(target: BlobReference | string): Promise<void> {
    this.#reader()
    const { kind, key } = this.#cacheIdOf(target)
    await this.#serial(async () => {
      const map = await this.#loadCacheIndex()
      const existing = map.get(`${kind}:${key}`)
      if (existing !== undefined) {
        existing.pinned = false
        await this.#saveCacheEntry(existing)
      }
      if (kind === 'public') this.#cas.unpin(key)
    })
  }
  async isPinned(target: BlobReference | string): Promise<boolean> {
    this.#reader()
    const { kind, key } = this.#cacheIdOf(target)
    const map = await this.#loadCacheIndex()
    return map.get(`${kind}:${key}`)?.pinned === true
  }
  async stats(): Promise<ContentCacheStats> {
    this.#reader()
    const map = await this.#loadCacheIndex()
    let publicBlobs = 0
    let privateItems = 0
    let totalBytes = 0
    let pinnedCount = 0
    for (const entry of map.values()) {
      if (entry.kind === 'public') publicBlobs++
      else privateItems++
      totalBytes += entry.bytes
      if (entry.pinned) pinnedCount++
    }
    return {
      publicBlobs,
      privateItems,
      totalBytes,
      pinnedCount,
      maxCacheBytes: this.#options.maxCacheBytes ?? null,
    }
  }
  /** Evict oldest unpinned locally cached blobs/items down to `maxBytes` (LRU). */
  async pruneCache(options: { readonly maxBytes?: number } = {}): Promise<ContentPruneResult> {
    this.#reader()
    const limit = options.maxBytes ?? this.#options.maxCacheBytes
    check(limit !== undefined && Number.isSafeInteger(limit) && limit >= 0, 'CONTENT_CACHE_LIMIT_INVALID')
    const map = await this.#loadCacheIndex()
    let totalBytes = 0
    for (const entry of map.values()) totalBytes += entry.bytes
    if (totalBytes <= limit) {
      return { evictedCount: 0, evictedBytes: 0, remainingBytes: totalBytes }
    }
    const candidates = [...map.values()]
      .filter(e => !e.pinned)
      .sort((a, b) => a.lastAccessMs - b.lastAccessMs || a.key.localeCompare(b.key))
    let evictedCount = 0
    let evictedBytes = 0
    for (const entry of candidates) {
      if (totalBytes - evictedBytes <= limit) break
      if (entry.kind === 'public') {
        await this.deleteBlob(entry.key)
      } else if (entry.reference !== undefined) {
        await this.discard(entry.reference)
      } else {
        await this.#serial(() => this.#dropCacheEntry(entry.kind, entry.key))
      }
      evictedCount++
      evictedBytes += entry.bytes
    }
    return {
      evictedCount,
      evictedBytes,
      remainingBytes: Math.max(0, totalBytes - evictedBytes),
    }
  }
  /** Unified lazy-pull blob write: supports both public raw-SHA-256 blobs and private epoch-encrypted blobs. */
  async put(bytes: Uint8Array, options: ContentPutOptions = {}): Promise<BlobReference> {
    const visibility = options.visibility ?? 'private'
    const mediaType = options.mediaType ?? 'application/octet-stream'
    if (visibility === 'public') {
      check(typeof mediaType === 'string' && mediaType.length > 0 && mediaType.length <= 256 && /^[\x20-\x7e]+$/u.test(mediaType), 'CONTENT_REFERENCE_INVALID')
      const info = await this.putBlob(bytes, options.signal === undefined ? {} : { signal: options.signal })
      return { profile: 'chronolog-blob-v2', visibility: 'public', hash: info.hash, bytes: info.bytes, mediaType }
    }
    const putOpts: ContentPutBytesOptions = {
      mediaType,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    }
    return options.deduplicate === true ? this.#putPrivateConvergent(bytes, putOpts) : this.putBytes(bytes, putOpts)
  }
  /** Unified lazy-pull blob read: accepts a raw SHA-256 hex hash, a PublicBlobReference, or a private ContentReference. */
  async get(target: BlobReference | string, options: ContentGetOptions = {}): Promise<Uint8Array | null> {
    if (typeof target === 'string') {
      return this.getBlob(target, options)
    }
    if (isPublicBlobReference(target)) {
      return this.getBlob(target.hash, {
        ...options,
        expectedBytes: options.expectedBytes ?? target.bytes,
      })
    }
    if (isPrivateContentReference(target)) {
      try {
        return await this.readBytes(target, {
          maxBytes: options.maxBytes ?? target.bytes,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        })
      } catch (error) {
        if (error instanceof Error && (error.message === 'CONTENT_MANIFEST_MISSING' || error.message === 'CONTENT_CHUNK_MISSING')) {
          return null
        }
        throw error
      }
    }
    throw new Error('CONTENT_REFERENCE_INVALID')
  }
  async close(): Promise<void> { this.#lifetime.abort(new Error('CONTENT_CLOSED')); this.#sources.clear(); await this.#tail }
}

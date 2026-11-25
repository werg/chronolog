import type { BytesStore } from '@chronolog/records'
import { encryptEpochPayload, decryptEpochPayload, type EncryptedEpochPayload } from '@chronolog/crypto'
import { bytesToHex, sha256 } from '@chronolog/canonical'
import { check, decodeRecord, encodeRecord, equalRecord, recordDigest, signRecord, verifyRecord, type AuthorityProvider, type Signed, type SigningIdentity } from '@chronolog/authority'
import { CONTENT_CHUNK_BYTES, MAX_CONTENT_BYTES, putContentBytes, readContentBytes, type ContentPutBytesOptions, type ContentReadBytesOptions } from './content-bytes.js'
import { awaitOwnedTask } from './lifetime.js'
export { CONTENT_CHUNK_BYTES } from './content-bytes.js'
export type { ContentPutBytesOptions, ContentReadBytesOptions } from './content-bytes.js'

export const MAX_CONTENT_CHUNKS = MAX_CONTENT_BYTES / CONTENT_CHUNK_BYTES
/** Canonical encrypted-envelope bytes: 64 KiB plaintext, AES tag, hex encoding and bounded metadata. */
export const MAX_CONTENT_ENCRYPTED_CHUNK_BYTES = CONTENT_CHUNK_BYTES * 2 + 1024
export const MAX_CONTENT_MANIFEST_BYTES = 256 * 1024
export interface ContentReference { readonly profile: 'authored-content-v1'; readonly applicationId: string; readonly id: string; readonly epoch: number; readonly bytes: number; readonly mediaType: string }
export interface ContentManifest { readonly stageId: string; readonly reference: Omit<ContentReference, 'id'>; readonly chunks: readonly { readonly hash: string; readonly bytes: number }[] }
export type ContentRetention = Signed<{ readonly reference: ContentReference; readonly peer: string; readonly storageId: string }>
export interface ContentOptions { readonly signal?: AbortSignal }
export interface ContentSource {
  manifest(reference: ContentReference, options?: ContentOptions): Promise<ContentManifest | null>
  chunk(reference: ContentReference, index: number, options?: ContentOptions): Promise<Uint8Array | null>
  retained?(reference: ContentReference, options?: ContentOptions): Promise<ContentRetention>
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
function body(reference: ContentReference): Omit<ContentReference, 'id'> { const { id: _id, ...rest } = reference; return rest }
function envelope(bytes: Uint8Array, epoch: number, plaintextBytes: number): EncryptedEpochPayload {
  check(bytes.length > 0 && bytes.length <= MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, 'CONTENT_CHUNK_INVALID')
  const value = decodeRecord<EncryptedEpochPayload>(bytes)
  object(value, ['epoch', 'nonce', 'ciphertext'])
  check(value.epoch === BigInt(epoch) && value.nonce instanceof Uint8Array && value.nonce.length === 12 &&
    value.ciphertext instanceof Uint8Array && value.ciphertext.length === plaintextBytes + 16, 'CONTENT_CHUNK_INVALID')
  return value
}

/** Durable encrypted content is independent of operation execution, peer delivery and finality. */
export class ApplicationContent {
  readonly #sources = new Map<string, ContentSource>()
  readonly #reads = new Map<string, Set<AbortController>>()
  readonly #lifetime = new AbortController()
  readonly #prefix: string
  readonly #options: { readonly store: BytesStore; readonly authority: AuthorityProvider; readonly identity: SigningIdentity; readonly storageId: string }
  #tail: Promise<unknown> = Promise.resolve()
  constructor(options: { readonly store: BytesStore; readonly authority: AuthorityProvider; readonly identity: SigningIdentity; readonly storageId: string }) {
    check(typeof options.storageId === 'string' && options.storageId.length > 0 && options.storageId.length <= 256, 'CONTENT_STORAGE_ID_INVALID')
    this.#options = options
    this.#prefix = `content/${options.authority.descriptor.applicationId}`
  }
  #reader(): void { this.#lifetime.signal.throwIfAborted(); check(this.#options.authority.grant(this.#options.identity.publicKey)?.reader, 'CONTENT_READER_REQUIRED') }
  #reference(input: ContentReference): ContentReference {
    assertContentReference(input)
    check(input.applicationId === this.#options.authority.descriptor.applicationId, 'CONTENT_SCOPE_INVALID')
    return { ...input }
  }
  #serial<T>(work: () => Promise<T>): Promise<T> {
    const task = this.#tail.then(() => { this.#lifetime.signal.throwIfAborted(); return work() })
    this.#tail = task.catch(() => undefined)
    return task
  }
  #readScope(reference: ContentReference, options: ContentOptions): { signal: AbortSignal; release(): void } {
    this.#reader(); options.signal?.throwIfAborted()
    const controller = new AbortController()
    let reads = this.#reads.get(reference.id)
    if (reads === undefined) { reads = new Set(); this.#reads.set(reference.id, reads) }
    reads.add(controller)
    const signal = AbortSignal.any([this.#lifetime.signal, controller.signal, ...(options.signal === undefined ? [] : [options.signal])])
    signal.throwIfAborted()
    return { signal, release: () => { reads.delete(controller); if (reads.size === 0) this.#reads.delete(reference.id) } }
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
    const id = crypto.randomUUID(), epoch = this.#options.authority.currentMembership.epoch
    const reference = { profile: 'authored-content-v1' as const, applicationId: this.#options.authority.descriptor.applicationId, epoch, bytes: options.bytes, mediaType: options.mediaType ?? 'application/octet-stream' }
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
      check(stage.stageId === id && stage.reference.applicationId === this.#options.authority.descriptor.applicationId && typeof stage.discarded === 'boolean', 'CONTENT_STAGE_INVALID')
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
            check(equalRecord(plaintext, bytes), 'CONTENT_CHUNK_CONFLICT'); return
          }
          const encrypted = encodeRecord(await encryptEpochPayload(epochKey, BigInt(stage.reference.epoch), bytes, aad))
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
        const epochKey = this.#options.authority.epochKey(stage.reference.epoch); check(epochKey !== null, 'CONTENT_KEY_MISSING')
        for (let index = 0; index < count; index++) {
          const bytes = await this.#options.store.get(`${key}/chunk/${index}`); check(bytes !== null, 'CONTENT_INCOMPLETE')
          await decryptEpochPayload(epochKey, envelope(bytes, stage.reference.epoch, Math.min(CONTENT_CHUNK_BYTES, stage.reference.bytes - index * CONTENT_CHUNK_BYTES)), encodeRecord([this.#prefix, id, index]))
          const hash = bytesToHex(await sha256(bytes))
          await this.#options.store.put(`${this.#prefix}/chunk/${hash}`, bytes)
          chunks.push({ hash, bytes: bytes.length })
        }
        const manifest: ContentManifest = { stageId: id, reference: stage.reference, chunks }
        const reference: ContentReference = { ...stage.reference, id: await recordDigest(manifest) }
        await this.#options.store.put(`${this.#prefix}/manifest/${reference.id}`, encodeRecord(manifest))
        await this.#options.store.put(key, encodeRecord({ ...stage, committed: reference }))
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
  async #manifest(reference: ContentReference, signal: AbortSignal, localOnly = false): Promise<ContentManifest | null> {
    signal.throwIfAborted(); this.#reader()
    const raw = await awaitOwnedTask(signal, () => this.#options.store.get(`${this.#prefix}/manifest/${reference.id}`))
    if (raw !== null && raw.length > 0) {
      check(raw.length <= MAX_CONTENT_MANIFEST_BYTES, 'CONTENT_MANIFEST_INVALID')
      const manifest = decodeRecord<ContentManifest>(raw); await this.#validateManifest(manifest, reference); signal.throwIfAborted(); return manifest
    }
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
  async #chunk(reference: ContentReference, manifest: ContentManifest, index: number, signal: AbortSignal, localOnly = false): Promise<Uint8Array | null> {
    signal.throwIfAborted(); this.#reader()
    const descriptor = manifest.chunks[index]; check(descriptor !== undefined, 'CONTENT_CHUNK_INDEX_INVALID')
    const valid = async (bytes: Uint8Array): Promise<void> => {
      check(bytes instanceof Uint8Array && bytes.length === descriptor.bytes && bytes.length <= MAX_CONTENT_ENCRYPTED_CHUNK_BYTES && bytesToHex(await sha256(bytes)) === descriptor.hash, 'CONTENT_CHUNK_INVALID')
      envelope(bytes, reference.epoch, Math.min(CONTENT_CHUNK_BYTES, reference.bytes - index * CONTENT_CHUNK_BYTES))
    }
    const stored = await awaitOwnedTask(signal, () => this.#options.store.get(`${this.#prefix}/chunk/${descriptor.hash}`))
    if (stored !== null && stored.length > 0) { await valid(stored); signal.throwIfAborted(); return stored }
    if (localOnly) return null
    let failure: unknown
    for (const source of [...this.#sources.values()]) {
      try {
        const candidate = await awaitOwnedTask(signal, () => source.chunk(reference, index, { signal }))
        if (candidate === null) continue
        check(candidate instanceof Uint8Array && candidate.length <= MAX_CONTENT_ENCRYPTED_CHUNK_BYTES, 'CONTENT_CHUNK_INVALID')
        const bytes = candidate.slice()
        await valid(bytes)
        await this.#serial(async () => { signal.throwIfAborted(); this.#reader(); await this.#options.store.put(`${this.#prefix}/chunk/${descriptor.hash}`, bytes) })
        return bytes.slice()
      } catch (error) { signal.throwIfAborted(); failure = error }
    }
    if (failure !== undefined) throw failure instanceof Error ? failure : new Error('CONTENT_SOURCE_FAILED', { cause: failure })
    throw new Error('CONTENT_CHUNK_MISSING')
  }
  async *read(input: ContentReference, options: ContentOptions = {}): AsyncIterable<Uint8Array> {
    const reference = this.#reference(input), scope = this.#readScope(reference, options)
    try {
      const manifest = await this.#manifest(reference, scope.signal); check(manifest !== null, 'CONTENT_MANIFEST_MISSING')
      const key = this.#options.authority.epochKey(reference.epoch); check(key !== null, 'CONTENT_KEY_MISSING')
      for (let index = 0; index < manifest.chunks.length; index++) {
        const bytes = await this.#chunk(reference, manifest, index, scope.signal); check(bytes !== null, 'CONTENT_CHUNK_MISSING')
        const plaintext = await decryptEpochPayload(key, envelope(bytes, reference.epoch, Math.min(CONTENT_CHUNK_BYTES, reference.bytes - index * CONTENT_CHUNK_BYTES)), encodeRecord([this.#prefix, manifest.stageId, index]))
        scope.signal.throwIfAborted(); this.#reader(); yield plaintext
      }
    } finally { scope.release() }
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
      for (let index = 0; index < manifest.chunks.length; index++) await this.#chunk(reference, manifest, index, scope.signal)
      return await this.#receipt(reference, scope.signal)
    } finally { scope.release() }
  }
  async verifyRetention(input: ContentReference, receipt: ContentRetention, expectedPeer?: string): Promise<void> {
    const reference = this.#reference(input)
    assertContentRetention(receipt)
    check(equalRecord(receipt.payload.reference, reference) && (expectedPeer === undefined || receipt.signer === expectedPeer) && this.#options.authority.grant(receipt.signer)?.reader, 'CONTENT_RETENTION_INVALID')
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
      for (const chunk of manifest?.chunks ?? []) await this.#remove(`${this.#prefix}/chunk/${chunk.hash}`)
    })
  }
  /** Serve only verified local bytes. Serving never recursively consults remote sources. */
  source(): ContentSource {
    return {
      manifest: async (input, options = {}) => {
        const reference = this.#reference(input), scope = this.#readScope(reference, options)
        try { return await this.#manifest(reference, scope.signal, true) } finally { scope.release() }
      },
      chunk: async (input, index, options = {}) => {
        const reference = this.#reference(input), scope = this.#readScope(reference, options)
        try {
          const manifest = await this.#manifest(reference, scope.signal, true)
          check(Number.isSafeInteger(index) && index >= 0 && index < Math.ceil(reference.bytes / CONTENT_CHUNK_BYTES), 'CONTENT_CHUNK_INDEX_INVALID')
          return manifest === null ? null : await this.#chunk(reference, manifest, index, scope.signal, true)
        } finally { scope.release() }
      },
      retained: async (input, options = {}) => {
        const reference = this.#reference(input), scope = this.#readScope(reference, options)
        try {
          const manifest = await this.#manifest(reference, scope.signal, true); check(manifest !== null, 'CONTENT_MANIFEST_MISSING')
          for (let index = 0; index < manifest.chunks.length; index++) check(await this.#chunk(reference, manifest, index, scope.signal, true) !== null, 'CONTENT_INCOMPLETE')
          return await this.#receipt(reference, scope.signal)
        } finally { scope.release() }
      },
    }
  }
  putBytes(bytes: Uint8Array, options?: ContentPutBytesOptions): Promise<ContentReference> { return putContentBytes(this, bytes, options) }
  readBytes(reference: ContentReference, options: ContentReadBytesOptions): Promise<Uint8Array> { return readContentBytes(this, reference, options) }
  async close(): Promise<void> { this.#lifetime.abort(new Error('CONTENT_CLOSED')); this.#sources.clear(); await this.#tail }
}

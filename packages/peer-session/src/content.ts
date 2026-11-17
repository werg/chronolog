import {
  bytesDigest, type PeerReplica, type PeerStore, type Signed,
} from '@chronolog/peer-generation'
import { bytesToHex, canonicalJson, hexToBytes, importEd25519PublicKey, type EventPayload } from '@chronolog/protocol'
import { BoundedTasks } from './async.js'

export const CONTENT_CHUNK_BYTES = 65_536
const MAX_CONTENT_BYTES = 128 * 1024 * 1024, MAX_SOURCES = 8, MAX_RETENTIONS = 16
const CONTENT_PROFILE = 'peer-content-v1' as const
const RETENTION_DOMAIN = 'chronolog/peer-content/retained/v1'

/** A reference identifies encrypted content; possession never grants read access. */
export interface ContentReference {
  readonly profile: typeof CONTENT_PROFILE
  readonly applicationId: string
  readonly historyId: string
  readonly id: string
  readonly epoch: number
  readonly bytes: number
  readonly mediaType: string
}
export interface ContentManifest {
  readonly profile: typeof CONTENT_PROFILE
  readonly applicationId: string
  readonly historyId: string
  readonly stageId: string
  readonly epoch: number
  readonly bytes: number
  readonly mediaType: string
  readonly chunks: readonly ContentChunk[]
}
interface ContentChunk { readonly hash: string; readonly nonce: string; readonly bytes: number }
interface StagedChunk extends ContentChunk { readonly plaintextHash: string }
interface Stage extends Omit<ContentManifest, 'chunks'> { readonly committed: ContentReference | null }
export type ContentRetention = Signed<{
  readonly reference: ContentReference
  readonly peer: string
  readonly storageId: string
  readonly generation: string
  readonly controlRevision: number
  readonly retainedAt: number
}>
/** Providers carry encrypted bounded chunks. Hosted providers are an explicit attachment. */
export interface ContentSource {
  manifest(reference: ContentReference, options?: { readonly signal?: AbortSignal }): Promise<ContentManifest | null>
  chunk(reference: ContentReference, index: number, options?: { readonly signal?: AbortSignal }): Promise<Uint8Array | null>
  retained?(reference: ContentReference, options?: { readonly signal?: AbortSignal }): Promise<ContentRetention>
  observeRetention?(receipt: ContentRetention, options?: { readonly signal?: AbortSignal }): Promise<void>
}
export interface ContentUpload {
  readonly id: string
  /** Exact repeated writes are safe; an index cannot be replaced with different bytes. */
  write(index: number, bytes: Uint8Array): Promise<void>
  progress(): Promise<{ readonly bytes: number; readonly storedBytes: number; readonly missingChunks: readonly number[] }>
  commit(): Promise<ContentReference>
}

/**
 * The session's content owner. Staging and downloads use the same durable store,
 * independently of command delivery. Chunks are encrypted before persistence;
 * partial fetches resume from locally verified chunks, with one chunk in memory.
 */
export class ApplicationContent {
  readonly #replica: PeerReplica
  readonly #store: PeerStore
  readonly #storageId: string
  readonly #keys: ReadonlyMap<number, Uint8Array>
  readonly #prefix: string
  readonly #sources = new Map<string, ContentSource>()
  readonly #sourceTasks = new BoundedTasks(16, 'CONTENT_SOURCE_BUSY')
  readonly #lifetime = new AbortController()
  #pending: Promise<unknown> = Promise.resolve()
  #closed = false

  constructor(options: { readonly replica: PeerReplica; readonly store: PeerStore; readonly storageId: string; readonly epochKeys: ReadonlyMap<number, Uint8Array> }) {
    this.#replica = options.replica; this.#store = options.store; this.#storageId = options.storageId
    // The replica and content owner consult the same live key provider. Its
    // owner installs delivered epochs; this component never mutates that map.
    this.#keys = options.epochKeys
    this.#prefix = `peer-content/${this.#replica.descriptor.applicationId}/${this.#replica.descriptor.historyId}`
  }

  async stage(options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> {
    const control = this.#access(this.#replica.device.publicKey, true)
    integer(options.bytes, MAX_CONTENT_BYTES)
    const mediaType = options.mediaType ?? 'application/octet-stream'
    media(mediaType)
    const stage: Stage = { profile: CONTENT_PROFILE, applicationId: this.#replica.descriptor.applicationId,
      historyId: this.#replica.descriptor.historyId, stageId: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
      epoch: control.epoch, bytes: options.bytes, mediaType, committed: null }
    await this.#key(stage.epoch)
    await this.#store.put(this.#stageKey(stage.stageId), encode(stage))
    return this.#upload(stage.stageId)
  }

  async resume(id: string): Promise<ContentUpload> { await this.#stage(id); return this.#upload(id) }

  attachSource(peerId: string, source: ContentSource): () => void {
    this.#access(peerId)
    if (this.#sources.has(peerId) || this.#sources.size >= MAX_SOURCES) throw new Error('CONTENT_SOURCE_LIMIT')
    this.#sources.set(peerId, source)
    return () => { if (this.#sources.get(peerId) === source) this.#sources.delete(peerId) }
  }

  async *read(reference: ContentReference, options: { readonly offset?: number; readonly length?: number; readonly signal?: AbortSignal } = {}): AsyncIterable<Uint8Array> {
    const signal = this.#signal(options.signal)
    this.#access(this.#replica.device.publicKey); this.#reference(reference)
    const offset = options.offset ?? 0, length = options.length ?? reference.bytes - offset
    integer(offset, reference.bytes); integer(length, reference.bytes - offset)
    signal.throwIfAborted()
    const manifest = await this.#manifest(reference, signal)
    signal.throwIfAborted()
    if (manifest === null) throw new Error('CONTENT_UNAVAILABLE')
    for (let index = Math.floor(offset / CONTENT_CHUNK_BYTES); index * CONTENT_CHUNK_BYTES < offset + length; index++) {
      this.#access(this.#replica.device.publicKey); signal.throwIfAborted()
      const chunk = await this.#chunk(reference, manifest, index, signal)
      if (chunk === null) throw new Error('CONTENT_UNAVAILABLE')
      const plain = await this.#decrypt(manifest, index, chunk)
      this.#access(this.#replica.device.publicKey); signal.throwIfAborted()
      yield plain.slice(Math.max(0, offset - index * CONTENT_CHUNK_BYTES), Math.min(plain.length, offset + length - index * CONTENT_CHUNK_BYTES))
    }
  }

  /** Called only after the connection authenticated requester; rechecks current controls. */
  async serveManifest(requester: string, reference: ContentReference): Promise<ContentManifest | null> {
    this.#access(requester); this.#access(this.#replica.device.publicKey); this.#reference(reference)
    const bytes = await this.#store.get(`${this.#prefix}/manifest/${reference.id}`)
    const manifest = bytes === null ? null : await this.#verifyManifest(reference, decode<ContentManifest>(bytes))
    this.#access(requester); this.#access(this.#replica.device.publicKey)
    return manifest
  }

  async serveChunk(requester: string, reference: ContentReference, index: number): Promise<Uint8Array | null> {
    const manifest = await this.serveManifest(requester, reference)
    if (manifest === null) return null
    integer(index, manifest.chunks.length - 1)
    const bytes = await this.#store.get(this.#chunkKey(manifest.chunks[index]!.hash))
    if (bytes !== null) await this.#verifyChunk(manifest.chunks[index]!, bytes)
    this.#access(requester); this.#access(this.#replica.device.publicKey)
    return bytes
  }

  async retained(reference: ContentReference): Promise<ContentRetention> {
    this.#access(this.#replica.device.publicKey)
    const manifest = await this.serveManifest(this.#replica.device.publicKey, reference)
    if (manifest === null) throw new Error('CONTENT_NOT_RETAINED')
    for (let index = 0; index < manifest.chunks.length; index++) {
      const bytes = await this.serveChunk(this.#replica.device.publicKey, reference, index)
      if (bytes === null) throw new Error('CONTENT_NOT_RETAINED')
      await this.#decrypt(manifest, index, bytes)
    }
    const generation = this.#replica.generation
    const payload: ContentRetention['payload'] = { reference: structuredClone(reference), peer: this.#replica.device.publicKey,
      storageId: this.#storageId, generation: generation.id, controlRevision: generation.payload.controlRevision, retainedAt: Date.now() }
    const signature = await crypto.subtle.sign('Ed25519', this.#replica.device.privateKey, signedBytes(payload))
    this.#access(this.#replica.device.publicKey)
    return { payload, signature: bytesToHex(new Uint8Array(signature)) }
  }

  /** Fetch a complete copy, then make best-effort, cancellable retention announcements. */
  async retain(reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): Promise<ContentRetention> {
    const signal = this.#signal(options.signal)
    for await (const _chunk of this.read(reference, { signal })) { /* Persistence precedes each yielded chunk. */ }
    const receipt = await this.retained(reference)
    signal.throwIfAborted()
    for (const [peer, source] of this.#sources) {
      const announce = source.observeRetention?.bind(source)
      if (announce === undefined) continue
      await this.#source(peer, () => announce(receipt, { signal }), signal)
    }
    return receipt
  }

  async observeRetention(receipt: ContentRetention): Promise<void> {
    await this.#verifyRetention(receipt)
    await this.#mutate(async () => {
      const prior = await this.#retentions(receipt.payload.reference)
      const next = prior.filter(item => item.payload.peer !== receipt.payload.peer || item.payload.storageId !== receipt.payload.storageId)
      next.push(structuredClone(receipt))
      await this.#store.put(`${this.#prefix}/retention/${receipt.payload.reference.id}`, encode(next.slice(-MAX_RETENTIONS)))
    })
  }

  /** Past durable-copy observations, never a claim that a provider is reachable now. */
  async retention(reference: ContentReference): Promise<readonly ContentRetention[]> {
    this.#access(this.#replica.device.publicKey); this.#reference(reference)
    const result: ContentRetention[] = []
    for (const receipt of await this.#retentions(reference)) {
      try { await this.#verifyRetention(receipt); result.push(receipt) }
      catch { /* A removed reader is no longer an eligible content source. */ }
    }
    return result
  }

  close(): void {
    this.#closed = true; this.#lifetime.abort(new Error('CONTENT_CLOSED')); this.#sources.clear()
  }

  #signal(signal?: AbortSignal): AbortSignal {
    return signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, signal])
  }

  async #source<T>(peer: string, start: () => Promise<T>, signal: AbortSignal): Promise<T | null> {
    signal.throwIfAborted(); this.#access(this.#replica.device.publicKey)
    try { this.#access(peer) } catch { return null }
    // A cancelled observer stops promptly, while BoundedTasks retains capacity
    // until the provider actually settles, including noncooperative providers.
    const result = await this.#sourceTasks.run(async () => {
      try { return { value: await start() } }
      catch { return null }
    }, signal)
    signal.throwIfAborted(); this.#access(this.#replica.device.publicKey)
    try { this.#access(peer) } catch { return null }
    return result === null ? null : result.value
  }

  #access(peerId: string, write = false) {
    if (this.#closed) throw new Error('CONTENT_CLOSED')
    const bundle = this.#replica.authority, control = bundle.controls[this.#replica.generation.payload.controlRevision]!.payload
    const grant = control.grants.find(item => item.publicKey === peerId)
    if (grant?.reader !== true || write && grant.writer !== true) throw new Error('CONTENT_ACCESS_DENIED')
    return control
  }
  async #key(epoch: number): Promise<CryptoKey> {
    const bytes = this.#keys.get(epoch)?.slice()
    if (bytes?.length !== 32) throw new Error('CONTENT_KEY_UNAVAILABLE')
    const control = this.#replica.authority.controls.find(item => item.payload.epoch === epoch)?.payload
    if (control === undefined || await bytesDigest(bytes) !== control.keyDigest) throw new Error('CONTENT_KEY_MISMATCH')
    return crypto.subtle.importKey('raw', new Uint8Array(bytes), 'AES-GCM', false, ['encrypt', 'decrypt'])
  }
  #stageKey(id: string): string { return `${this.#prefix}/stage/${id}` }
  #chunkKey(hash: string): string { return `${this.#prefix}/chunk/${hash}` }
  async #stage(id: string): Promise<Stage> {
    if (!/^[0-9a-f]{32}$/u.test(id)) throw new Error('CONTENT_STAGE_INVALID')
    this.#access(this.#replica.device.publicKey, true)
    const bytes = await this.#store.get(this.#stageKey(id))
    if (bytes === null) throw new Error('CONTENT_STAGE_MISSING')
    const stage = decode<Stage>(bytes)
    if (stage.stageId !== id || stage.applicationId !== this.#replica.descriptor.applicationId || stage.historyId !== this.#replica.descriptor.historyId) throw new Error('CONTENT_STAGE_CORRUPT')
    if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch && stage.committed === null) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
    return stage
  }
  #upload(id: string): ContentUpload {
    return { id,
      write: (index, bytes) => this.#mutate(async () => {
        const stage = await this.#stage(id), count = Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES)
        integer(index, count - 1)
        const size = Math.min(CONTENT_CHUNK_BYTES, stage.bytes - index * CONTENT_CHUNK_BYTES)
        if (!(bytes instanceof Uint8Array) || bytes.length !== size) throw new Error('CONTENT_CHUNK_SIZE_INVALID')
        const plain = bytes.slice(), plaintextHash = await bytesDigest(plain), descriptorKey = `${this.#stageKey(id)}/${index}`
        const saved = await this.#store.get(descriptorKey)
        if (saved !== null) {
          if (decode<StagedChunk>(saved).plaintextHash !== plaintextHash) throw new Error('CONTENT_CHUNK_REUSED')
          return
        }
        if (stage.committed !== null) throw new Error('CONTENT_STAGE_COMMITTED')
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(stage, index) }, await this.#key(stage.epoch), plain))
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        const descriptor: StagedChunk = { hash: await bytesDigest(encrypted), nonce: bytesToHex(nonce), bytes: size, plaintextHash }
        await this.#store.put(this.#chunkKey(descriptor.hash), encrypted)
        await this.#store.put(descriptorKey, encode(descriptor))
      }),
      progress: async () => {
        const stage = await this.#stage(id), missingChunks: number[] = []; let storedBytes = 0
        for (let index = 0; index < Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES); index++) {
          const bytes = await this.#store.get(`${this.#stageKey(id)}/${index}`)
          if (bytes === null) missingChunks.push(index); else storedBytes += decode<StagedChunk>(bytes).bytes
        }
        return { bytes: stage.bytes, storedBytes, missingChunks }
      },
      commit: () => this.#mutate(async () => {
        const stage = await this.#stage(id)
        if (stage.committed !== null) return structuredClone(stage.committed)
        const chunks: ContentChunk[] = []
        for (let index = 0; index < Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES); index++) {
          const saved = await this.#store.get(`${this.#stageKey(id)}/${index}`)
          if (saved === null) throw new Error('CONTENT_STAGE_INCOMPLETE')
          const { hash, nonce, bytes } = decode<StagedChunk>(saved)
          const body = await this.#store.get(this.#chunkKey(hash))
          if (body === null) throw new Error('CONTENT_STAGE_INCOMPLETE')
          await this.#verifyChunk({ hash, nonce, bytes }, body)
          chunks.push({ hash, nonce, bytes })
        }
        const { committed: _committed, ...metadata } = stage
        const manifest: ContentManifest = { ...metadata, chunks }, contentId = await bytesDigest(encode(manifest))
        const reference: ContentReference = { profile: CONTENT_PROFILE, applicationId: stage.applicationId, historyId: stage.historyId,
          id: contentId, epoch: stage.epoch, bytes: stage.bytes, mediaType: stage.mediaType }
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        await this.#store.put(`${this.#prefix}/manifest/${contentId}`, encode(manifest))
        await this.#store.put(this.#stageKey(stage.stageId), encode({ ...stage, committed: reference }))
        return reference
      }),
    }
  }
  #reference(value: ContentReference): void {
    if (value === null || value.profile !== CONTENT_PROFILE || value.applicationId !== this.#replica.descriptor.applicationId ||
        value.historyId !== this.#replica.descriptor.historyId || !/^[0-9a-f]{64}$/u.test(value.id)) throw new Error('CONTENT_REFERENCE_INVALID')
    integer(value.epoch, Number.MAX_SAFE_INTEGER); integer(value.bytes, MAX_CONTENT_BYTES); media(value.mediaType)
    if (Object.keys(value).sort().join(',') !== 'applicationId,bytes,epoch,historyId,id,mediaType,profile') throw new Error('CONTENT_REFERENCE_INVALID')
  }
  async #verifyManifest(reference: ContentReference, manifest: ContentManifest): Promise<ContentManifest> {
    this.#reference(reference)
    if (manifest.profile !== CONTENT_PROFILE || manifest.applicationId !== reference.applicationId || manifest.historyId !== reference.historyId ||
        manifest.epoch !== reference.epoch || manifest.bytes !== reference.bytes || manifest.mediaType !== reference.mediaType ||
        !/^[0-9a-f]{32}$/u.test(manifest.stageId) || !Array.isArray(manifest.chunks) || manifest.chunks.length !== Math.ceil(reference.bytes / CONTENT_CHUNK_BYTES)) throw new Error('CONTENT_MANIFEST_INVALID')
    for (const [index, chunk] of (manifest.chunks as readonly ContentChunk[]).entries()) {
      if (!/^[0-9a-f]{64}$/u.test(chunk.hash) || !/^[0-9a-f]{24}$/u.test(chunk.nonce) || chunk.bytes !== Math.min(CONTENT_CHUNK_BYTES, reference.bytes - index * CONTENT_CHUNK_BYTES)) throw new Error('CONTENT_MANIFEST_INVALID')
    }
    if (await bytesDigest(encode(manifest)) !== reference.id) throw new Error('CONTENT_MANIFEST_HASH_MISMATCH')
    return structuredClone(manifest)
  }
  async #verifyChunk(chunk: ContentChunk, bytes: Uint8Array): Promise<void> {
    if (bytes.length !== chunk.bytes + 16 || await bytesDigest(bytes) !== chunk.hash) throw new Error('CONTENT_CHUNK_HASH_MISMATCH')
  }
  async #manifest(reference: ContentReference, signal: AbortSignal): Promise<ContentManifest | null> {
    const local = await this.serveManifest(this.#replica.device.publicKey, reference)
    if (local !== null) return local
    for (const [peer, source] of this.#sources) {
      const value = await this.#source(peer, () => source.manifest(reference, { signal }), signal)
      if (value === null) continue
      try {
        const manifest = await this.#verifyManifest(reference, value)
        signal.throwIfAborted(); this.#access(peer); this.#access(this.#replica.device.publicKey)
        await this.#store.put(`${this.#prefix}/manifest/${reference.id}`, encode(manifest))
        return manifest
      } catch { signal.throwIfAborted(); this.#access(this.#replica.device.publicKey) }
    }
    return null
  }
  async #chunk(reference: ContentReference, manifest: ContentManifest, index: number, signal: AbortSignal): Promise<Uint8Array | null> {
    const descriptor = manifest.chunks[index]!
    const local = await this.#store.get(this.#chunkKey(descriptor.hash))
    if (local !== null) { await this.#verifyChunk(descriptor, local); return local }
    for (const [peer, source] of this.#sources) {
      const value = await this.#source(peer, () => source.chunk(reference, index, { signal }), signal)
      if (value === null) continue
      try {
        await this.#verifyChunk(descriptor, value)
        await this.#decrypt(manifest, index, value)
        signal.throwIfAborted(); this.#access(peer); this.#access(this.#replica.device.publicKey)
        await this.#store.put(this.#chunkKey(descriptor.hash), value)
        return value
      } catch { signal.throwIfAborted(); this.#access(this.#replica.device.publicKey) }
    }
    return null
  }
  async #decrypt(manifest: ContentManifest, index: number, encrypted: Uint8Array): Promise<Uint8Array> {
    const chunk = manifest.chunks[index]!
    await this.#verifyChunk(chunk, encrypted)
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(hexToBytes(chunk.nonce)),
      additionalData: aad(manifest, index) }, await this.#key(manifest.epoch), new Uint8Array(encrypted)))
    if (plain.length !== chunk.bytes) throw new Error('CONTENT_CHUNK_SIZE_INVALID')
    return plain
  }
  async #retentions(reference: ContentReference): Promise<ContentRetention[]> {
    const bytes = await this.#store.get(`${this.#prefix}/retention/${reference.id}`)
    const result = bytes === null ? [] : decode<ContentRetention[]>(bytes)
    if (!Array.isArray(result) || result.length > MAX_RETENTIONS) throw new Error('CONTENT_RETENTION_CORRUPT')
    return result
  }
  async #verifyRetention(receipt: ContentRetention): Promise<void> {
    const value = receipt.payload
    this.#reference(value.reference); this.#access(value.peer); this.#access(this.#replica.device.publicKey)
    integer(value.retainedAt, Number.MAX_SAFE_INTEGER); integer(value.controlRevision, Number.MAX_SAFE_INTEGER)
    if (typeof value.storageId !== 'string' || value.storageId.length > 256 || !/^[0-9a-f]{128}$/u.test(receipt.signature) ||
        !this.#replica.authority.generations.some(generation => generation.id === value.generation && generation.payload.controlRevision === value.controlRevision)) throw new Error('CONTENT_RETENTION_INVALID')
    if (!await crypto.subtle.verify('Ed25519', await importEd25519PublicKey(hexToBytes(value.peer)), new Uint8Array(hexToBytes(receipt.signature)), signedBytes(value))) throw new Error('CONTENT_RETENTION_INVALID')
  }
  #mutate<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.#pending.then(operation)
    this.#pending = pending.catch(() => undefined)
    return pending
  }
}

function integer(value: number, max: number): void { if (!Number.isSafeInteger(value) || value < 0 || value > max) throw new Error('CONTENT_RANGE_INVALID') }
function media(value: string): void { if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/u.test(value) || value.length > 128) throw new Error('CONTENT_MEDIA_TYPE_INVALID') }
function encode(value: unknown): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(canonicalJson(value as EventPayload, { maxBytes: 262_144, maxNodes: 32_768, maxDepth: 16 }))
}
function decode<T>(bytes: Uint8Array): T { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as T }
function aad(value: Pick<ContentManifest, 'applicationId' | 'historyId' | 'stageId' | 'epoch'>, index: number): Uint8Array<ArrayBuffer> {
  return encode(['chronolog/peer-content/chunk/v1', value.applicationId, value.historyId, value.stageId, value.epoch, index])
}
function signedBytes(value: ContentRetention['payload']): Uint8Array<ArrayBuffer> { return encode([RETENTION_DOMAIN, value]) }

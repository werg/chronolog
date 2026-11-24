import type { BytesStore } from '@chronolog/records'
import {
  bytesDigest, type PeerReplica, type Signed,
} from '@chronolog/peer-generation'
import { bytesToHex, canonicalJson, hexToBytes, importEd25519PublicKey, type EventPayload } from '@chronolog/protocol'
import { awaitOwnedTask } from './lifetime.js'
import { CONTENT_CHUNK_BYTES, MAX_CONTENT_BYTES, putContentBytes, readContentBytes, type ContentPutBytesOptions, type ContentReadBytesOptions } from './content-bytes.js'

export { CONTENT_CHUNK_BYTES } from './content-bytes.js'
export type { ContentPutBytesOptions, ContentReadBytesOptions } from './content-bytes.js'
const MAX_SOURCES = 8, MAX_SOURCE_REQUESTS = 8, MAX_RETENTIONS = 16
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
interface Stage extends Omit<ContentManifest, 'chunks'> { readonly committed: ContentReference | null; readonly chunkLayout?: 'reference-v1' }
interface PruneRecord { readonly manifest: ContentManifest; readonly stageOwned: boolean; readonly legacyChunks: boolean }
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
  manifest(reference: ContentReference): Promise<ContentManifest | null>
  chunk(reference: ContentReference, index: number): Promise<Uint8Array | null>
  retained?(reference: ContentReference): Promise<ContentRetention>
  observeRetention?(receipt: ContentRetention): Promise<void>
}
interface AttachedSource { readonly source: ContentSource; readonly lifetime: AbortController }
export interface ContentUpload {
  readonly id: string
  /** Exact repeated writes are safe; an index cannot be replaced with different bytes. */
  write(index: number, bytes: Uint8Array): Promise<void>
  progress(): Promise<{ readonly bytes: number; readonly storedBytes: number; readonly missingChunks: readonly number[] }>
  commit(): Promise<ContentReference>
  /** Idempotently discard this local upload, including an already committed copy. */
  discard(): Promise<void>
}

/**
 * The session's content owner. Staging and downloads use the same durable store,
 * independently of command delivery. Chunks are encrypted before persistence;
 * partial fetches resume from locally verified chunks, with one chunk in memory.
 */
export class ApplicationContent {
  readonly #replica: PeerReplica
  readonly #store: BytesStore
  readonly #storageId: string
  readonly #keys: ReadonlyMap<number, Uint8Array>
  readonly #acquireKey: ((epoch: number) => Promise<void>) | undefined
  readonly #prefix: string
  readonly #sources = new Map<string, AttachedSource>()
  readonly #lifetime = new AbortController()
  #pending: Promise<unknown> = Promise.resolve()
  #sourceRequests = 0
  readonly #readers = new Map<string, Set<AbortController>>()
  readonly #prunes = new Map<string, Promise<void>>()
  readonly #evicting = new Map<string, number>()
  readonly #cryptoKeys = new WeakMap<Uint8Array, { readonly keyDigest: string; readonly key: CryptoKey }>()

  constructor(options: { readonly replica: PeerReplica; readonly store: BytesStore; readonly storageId: string; readonly epochKeys: ReadonlyMap<number, Uint8Array>; readonly acquireKey?: (epoch: number) => Promise<void> }) {
    this.#replica = options.replica; this.#store = options.store; this.#storageId = options.storageId
    this.#keys = options.epochKeys
    this.#acquireKey = options.acquireKey
    this.#prefix = `peer-content/${this.#replica.descriptor.applicationId}/${this.#replica.descriptor.historyId}`
  }

  async stage(options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> {
    const control = this.#access(this.#replica.device.publicKey, true)
    integer(options.bytes, MAX_CONTENT_BYTES)
    const mediaType = options.mediaType ?? 'application/octet-stream'
    media(mediaType)
    const stage: Stage = { profile: CONTENT_PROFILE, applicationId: this.#replica.descriptor.applicationId,
      historyId: this.#replica.descriptor.historyId, stageId: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
      epoch: control.epoch, bytes: options.bytes, mediaType, committed: null, chunkLayout: 'reference-v1' }
    await this.#key(stage.epoch)
    this.#access(this.#replica.device.publicKey, true)
    await this.#store.put(this.#stageKey(stage.stageId), encode(stage))
    this.#lifetime.signal.throwIfAborted()
    return this.#upload(stage.stageId)
  }

  async resume(id: string): Promise<ContentUpload> { await this.#stage(id); return this.#upload(id) }

  putBytes(bytes: Uint8Array, options: ContentPutBytesOptions = {}): Promise<ContentReference> {
    return putContentBytes(this, bytes, { ...options, signal: this.#signal(options.signal) })
  }

  readBytes(reference: ContentReference, options: ContentReadBytesOptions): Promise<Uint8Array> {
    return readContentBytes(this, reference, options)
  }

  /** Evict this device's copy only. A later explicit read may fetch it again. */
  async prune(reference: ContentReference): Promise<void> {
    this.#access(this.#replica.device.publicKey); this.#reference(reference)
    if (this.#store.delete === undefined) return Promise.reject(new Error('CONTENT_PRUNE_UNSUPPORTED'))
    const captured = structuredClone(reference), prior = this.#prunes.get(captured.id)
    if (prior !== undefined) return prior
    const release = this.#beginEviction(captured.id)
    const task = this.#mutate(() => this.#pruneLocal(captured)).finally(() => {
      this.#prunes.delete(captured.id); release()
    })
    this.#prunes.set(captured.id, task)
    return task
  }

  /** Idempotent cleanup by saved upload ID, including after an epoch change. */
  discard(id: string): Promise<void> { return this.#mutate(() => this.#discardStage(id)) }

  attachSource(peerId: string, source: ContentSource): () => void {
    this.#access(peerId)
    if (this.#sources.has(peerId) || this.#sources.size >= MAX_SOURCES) throw new Error('CONTENT_SOURCE_LIMIT')
    const attached = { source, lifetime: new AbortController() }
    this.#sources.set(peerId, attached)
    return () => {
      if (this.#sources.get(peerId) !== attached) return
      this.#sources.delete(peerId)
      attached.lifetime.abort(new Error('CONTENT_SOURCE_DETACHED'))
    }
  }

  async *read(reference: ContentReference, options: { readonly offset?: number; readonly length?: number; readonly signal?: AbortSignal } = {}): AsyncIterable<Uint8Array> {
    this.#access(this.#replica.device.publicKey); this.#reference(reference)
    reference = structuredClone(reference)
    const offset = options.offset ?? 0, length = options.length ?? reference.bytes - offset
    integer(offset, reference.bytes); integer(length, reference.bytes - offset)
    if (this.#evicting.has(reference.id)) throw new Error('CONTENT_PRUNED')
    const reader = new AbortController(), readers = this.#readers.get(reference.id) ?? new Set<AbortController>()
    readers.add(reader); this.#readers.set(reference.id, readers)
    const signal = AbortSignal.any([this.#signal(options.signal), reader.signal])
    try {
      signal.throwIfAborted()
      const manifest = await this.#manifest(reference, signal)
      if (manifest === null) throw new Error('CONTENT_UNAVAILABLE')
      const firstIndex = Math.floor(offset / CONTENT_CHUNK_BYTES)
      const lastIndex = length === 0 ? firstIndex - 1 : Math.floor((offset + length - 1) / CONTENT_CHUNK_BYTES)
      const PREFETCH = 2
      const inflight = new Map<number, Promise<Uint8Array | null>>()
      const startFetch = (idx: number) => {
        if (idx <= lastIndex && !inflight.has(idx)) {
          const task = this.#chunk(reference, manifest, idx, signal)
          void task.catch(() => undefined)
          inflight.set(idx, task)
        }
      }
      for (let i = firstIndex; i < firstIndex + PREFETCH && i <= lastIndex; i++) startFetch(i)
      for (let index = firstIndex; index <= lastIndex; index++) {
        this.#access(this.#replica.device.publicKey); signal.throwIfAborted()
        const task = inflight.get(index)!
        inflight.delete(index)
        const chunk = await task
        if (chunk === null) throw new Error('CONTENT_UNAVAILABLE')
        startFetch(index + PREFETCH)
        const plain = await this.#decrypt(manifest, index, chunk)
        this.#access(this.#replica.device.publicKey); signal.throwIfAborted()
        yield plain.slice(Math.max(0, offset - index * CONTENT_CHUNK_BYTES), Math.min(plain.length, offset + length - index * CONTENT_CHUNK_BYTES))
      }
      signal.throwIfAborted()
    } finally {
      reader.abort()
      readers.delete(reader)
      if (readers.size === 0) this.#readers.delete(reference.id)
    }
  }

  /** Called only after the connection authenticated requester; rechecks current controls. */
  async serveManifest(requester: string, reference: ContentReference): Promise<ContentManifest | null> {
    this.#access(requester); this.#access(this.#replica.device.publicKey); this.#reference(reference)
    if (this.#evicting.has(reference.id) || await this.#store.get(`${this.#prefix}/prune/${reference.id}`) !== null) throw new Error('CONTENT_PRUNED')
    const bytes = await this.#store.get(`${this.#prefix}/manifest/${reference.id}`)
    this.#access(requester)
    const manifest = bytes === null ? null : await this.#verifyManifest(reference, decode<ContentManifest>(bytes))
    this.#access(requester); this.#access(this.#replica.device.publicKey)
    return manifest
  }

  async serveChunk(requester: string, reference: ContentReference, index: number): Promise<Uint8Array | null> {
    const manifest = await this.serveManifest(requester, reference)
    if (manifest === null) return null
    integer(index, manifest.chunks.length - 1)
    const bytes = await this.#localChunk(reference, manifest.chunks[index]!.hash)
    this.#access(requester); this.#access(this.#replica.device.publicKey)
    if (bytes !== null) await this.#verifyChunk(manifest.chunks[index]!, bytes)
    this.#access(requester); this.#access(this.#replica.device.publicKey)
    return bytes
  }

  retained(reference: ContentReference): Promise<ContentRetention> {
    return this.#mutate(() => this.#retained(reference))
  }

  async #retained(reference: ContentReference): Promise<ContentRetention> {
    this.#access(this.#replica.device.publicKey)
    const manifest = await this.serveManifest(this.#replica.device.publicKey, reference)
    if (manifest === null) throw new Error('CONTENT_NOT_RETAINED')
    for (let index = 0; index < manifest.chunks.length; index++) {
      const descriptor = manifest.chunks[index]!
      const bytes = await this.#localChunk(reference, descriptor.hash)
      if (bytes === null) throw new Error('CONTENT_NOT_RETAINED')
      await this.#verifyChunk(descriptor, bytes)
      this.#access(this.#replica.device.publicKey)
    }
    return this.#signRetention(reference)
  }

  async #signRetention(reference: ContentReference): Promise<ContentRetention> {
    this.#access(this.#replica.device.publicKey)
    const generation = this.#replica.generation
    const payload: ContentRetention['payload'] = { reference: structuredClone(reference), peer: this.#replica.device.publicKey,
      storageId: this.#storageId, generation: generation.id, controlRevision: generation.payload.controlRevision, retainedAt: Date.now() }
    const signature = await crypto.subtle.sign('Ed25519', this.#replica.device.privateKey, signedBytes(payload))
    this.#access(this.#replica.device.publicKey)
    return { payload, signature: bytesToHex(new Uint8Array(signature)) }
  }

  /** Fetch a complete independent copy, then attempt to announce its durable retention. */
  async retain(reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): Promise<ContentRetention> {
    const signal = this.#signal(options.signal)
    for await (const _chunk of this.read(reference, options)) { /* Persistence precedes each yielded chunk. */ }
    const receipt = await this.retained(reference)
    signal.throwIfAborted()
    for (const [peer, attached] of [...this.#sources]) {
      const { source } = attached
      const observe = source.observeRetention?.bind(source)
      if (observe === undefined) continue
      try { await this.#sourceCall(peer, attached, () => observe(receipt), signal) }
      catch { signal.throwIfAborted() /* A lost observation never invalidates the retained local copy. */ }
    }
    signal.throwIfAborted()
    return receipt
  }

  async observeRetention(receipt: ContentRetention): Promise<void> {
    await this.#verifyRetention(receipt)
    await this.#mutate(async () => {
      const prior = await this.#retentions(receipt.payload.reference)
      const next = prior.filter(item => item.payload.peer !== receipt.payload.peer || item.payload.storageId !== receipt.payload.storageId)
      next.push(structuredClone(receipt))
      this.#access(receipt.payload.peer); this.#access(this.#replica.device.publicKey)
      await this.#store.put(`${this.#prefix}/retention/${receipt.payload.reference.id}`, encode(next.slice(-MAX_RETENTIONS)))
    })
  }

  /** Past durable-copy observations, never a claim that a provider is reachable now. */
  async retention(reference: ContentReference): Promise<readonly ContentRetention[]> {
    this.#access(this.#replica.device.publicKey); this.#reference(reference)
    const result: ContentRetention[] = []
    for (const receipt of await this.#retentions(reference)) {
      try { await this.#verifyRetention(receipt); result.push(receipt) }
      catch { this.#lifetime.signal.throwIfAborted() /* A removed reader is no longer an eligible content source. */ }
    }
    this.#access(this.#replica.device.publicKey)
    return result
  }

  close(): void {
    if (this.#lifetime.signal.aborted) return
    this.#lifetime.abort(new Error('CONTENT_CLOSED'))
    for (const attached of this.#sources.values()) attached.lifetime.abort(this.#lifetime.signal.reason)
    this.#sources.clear()
  }

  #signal(signal?: AbortSignal): AbortSignal {
    return signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, signal])
  }

  #sourceAccess(peer: string, attached: AttachedSource, signal: AbortSignal): void {
    signal.throwIfAborted(); attached.lifetime.signal.throwIfAborted()
    if (this.#sources.get(peer) !== attached) throw new Error('CONTENT_SOURCE_DETACHED')
    this.#access(peer); this.#access(this.#replica.device.publicKey)
  }

  async #sourceCall<T>(peer: string, attached: AttachedSource, call: () => Promise<T>, signal: AbortSignal): Promise<T> {
    this.#sourceAccess(peer, attached, signal)
    const lifetime = AbortSignal.any([signal, attached.lifetime.signal])
    const value = await this.#providerCall(lifetime, call)
    this.#sourceAccess(peer, attached, signal)
    return value
  }

  #providerCall<T>(signal: AbortSignal, call: () => Promise<T>): Promise<T> {
    return awaitOwnedTask(signal, () => {
      if (this.#sourceRequests >= MAX_SOURCE_REQUESTS) throw new Error('CONTENT_SOURCE_BUSY')
      this.#sourceRequests++
      let request: Promise<T>
      try { request = Promise.resolve(call()) }
      catch (error) { this.#sourceRequests--; throw error }
      // Abandoning a wait does not cancel provider I/O. Retain its slot until
      // the actual request settles, including after detachment or owner close.
      void request.then(() => { this.#sourceRequests-- }, () => { this.#sourceRequests-- })
      return request
    })
  }

  #access(peerId: string, write = false) {
    this.#lifetime.signal.throwIfAborted()
    const bundle = this.#replica.authority, control = bundle.controls[this.#replica.generation.payload.controlRevision]!.payload
    const grant = control.grants.find(item => item.publicKey === peerId)
    if (grant?.reader !== true || write && grant.writer !== true) throw new Error('CONTENT_ACCESS_DENIED')
    return control
  }
  async #key(epoch: number): Promise<CryptoKey> {
    const acquire = this.#acquireKey
    if (!this.#keys.has(epoch) && acquire !== undefined) await this.#providerCall(this.#lifetime.signal, () => acquire(epoch))
    this.#access(this.#replica.device.publicKey)
    const bytes = this.#keys.get(epoch)
    if (bytes?.length !== 32) throw new Error('CONTENT_KEY_UNAVAILABLE')
    const control = this.#replica.authority.controls.find(item => item.payload.epoch === epoch)?.payload
    if (control === undefined) throw new Error('CONTENT_KEY_MISMATCH')
    const cached = this.#cryptoKeys.get(bytes)
    if (cached !== undefined && cached.keyDigest === control.keyDigest) return cached.key
    if (await bytesDigest(bytes) !== control.keyDigest) throw new Error('CONTENT_KEY_MISMATCH')
    this.#access(this.#replica.device.publicKey)
    const imported = await crypto.subtle.importKey('raw', new Uint8Array(bytes), 'AES-GCM', false, ['encrypt', 'decrypt'])
    this.#cryptoKeys.set(bytes, { keyDigest: control.keyDigest, key: imported })
    return imported
  }
  #stageKey(id: string): string { return `${this.#prefix}/stage/${id}` }
  #chunkKey(hash: string, referenceId?: string): string { return `${this.#prefix}/chunk/${referenceId === undefined ? '' : referenceId + '/'}${hash}` }
  async #localChunk(reference: ContentReference, hash: string): Promise<Uint8Array | null> {
    // Legacy stores used the hash alone. New committed/downloaded chunks are
    // reference-scoped so two manifests sharing ciphertext can be pruned safely.
    return await this.#store.get(this.#chunkKey(hash, reference.id)) ?? await this.#store.get(this.#chunkKey(hash))
  }
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
      discard: () => this.discard(id),
      write: (index, bytes) => this.#mutate(async () => {
        const stage = await this.#stage(id), count = Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES)
        integer(index, count - 1)
        const size = Math.min(CONTENT_CHUNK_BYTES, stage.bytes - index * CONTENT_CHUNK_BYTES)
        if (!(bytes instanceof Uint8Array) || bytes.length !== size) throw new Error('CONTENT_CHUNK_SIZE_INVALID')
        const plain = bytes.slice(), plaintextHash = await bytesDigest(plain), descriptorKey = `${this.#stageKey(id)}/${index}`
        const saved = await this.#store.get(descriptorKey)
        if (saved !== null) {
          const descriptor = decode<StagedChunk>(saved)
          if (descriptor.plaintextHash !== plaintextHash) throw new Error('CONTENT_CHUNK_REUSED')
          if (stage.committed !== null) return
          const body = await this.#store.get(this.#chunkKey(descriptor.hash))
          if (body !== null) { await this.#verifyChunk(descriptor, body); return }
          // A durable descriptor precedes ciphertext. Reuse its nonce to repair
          // an interrupted write without orphaning a second encrypted chunk.
          const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(hexToBytes(descriptor.nonce)), additionalData: aad(stage, index) }, await this.#key(stage.epoch), plain))
          await this.#verifyChunk(descriptor, encrypted)
          if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
          await this.#store.put(this.#chunkKey(descriptor.hash), encrypted)
          return
        }
        if (stage.committed !== null) throw new Error('CONTENT_STAGE_COMMITTED')
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(stage, index) }, await this.#key(stage.epoch), plain))
        const descriptor: StagedChunk = { hash: await bytesDigest(encrypted), nonce: bytesToHex(nonce), bytes: size, plaintextHash }
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        await this.#store.put(descriptorKey, encode(descriptor))
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        await this.#store.put(this.#chunkKey(descriptor.hash), encrypted)
      }),
      progress: async () => {
        const stage = await this.#stage(id), missingChunks: number[] = []; let storedBytes = 0
        for (let index = 0; index < Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES); index++) {
          const bytes = await this.#store.get(`${this.#stageKey(id)}/${index}`)
          if (bytes === null) { missingChunks.push(index); continue }
          const descriptor = decode<StagedChunk>(bytes)
          const body = stage.committed === null ? await this.#store.get(this.#chunkKey(descriptor.hash)) : await this.#localChunk(stage.committed, descriptor.hash)
          if (body === null) missingChunks.push(index)
          else { await this.#verifyChunk(descriptor, body); storedBytes += descriptor.bytes }
        }
        this.#access(this.#replica.device.publicKey, true)
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
          chunks.push({ hash, nonce, bytes })
        }
        const { committed: _committed, chunkLayout: _chunkLayout, ...metadata } = stage
        const manifest: ContentManifest = { ...metadata, chunks }, contentId = await bytesDigest(encode(manifest))
        const reference: ContentReference = { profile: CONTENT_PROFILE, applicationId: stage.applicationId, historyId: stage.historyId,
          id: contentId, epoch: stage.epoch, bytes: stage.bytes, mediaType: stage.mediaType }
        for (const chunk of chunks) {
          const key = this.#chunkKey(chunk.hash, contentId), existing = await this.#store.get(key)
          const body = existing ?? await this.#store.get(this.#chunkKey(chunk.hash))
          if (body === null) throw new Error('CONTENT_STAGE_INCOMPLETE')
          await this.#verifyChunk(chunk, body)
          if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
          if (existing === null) await this.#store.put(key, body)
          // Move one bounded chunk at a time; retry derives the same content ID
          // and finds already-moved chunks even before the manifest is published.
          if (stage.chunkLayout === 'reference-v1') await this.#store.delete?.(this.#chunkKey(chunk.hash))
        }
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        await this.#store.put(`${this.#prefix}/manifest/${contentId}`, encode(manifest))
        if (stage.epoch !== this.#access(this.#replica.device.publicKey, true).epoch) throw new Error('CONTENT_STAGE_EPOCH_CHANGED')
        await this.#store.put(this.#stageKey(stage.stageId), encode({ ...stage, committed: reference }))
        this.#lifetime.signal.throwIfAborted()
        return reference
      }),
    }
  }
  #beginEviction(id: string): () => void {
    this.#evicting.set(id, (this.#evicting.get(id) ?? 0) + 1)
    for (const reader of this.#readers.get(id) ?? []) reader.abort(new Error('CONTENT_PRUNED'))
    return () => {
      const remaining = (this.#evicting.get(id) ?? 1) - 1
      if (remaining === 0) this.#evicting.delete(id); else this.#evicting.set(id, remaining)
    }
  }

  async #pruneLocal(reference: ContentReference, prepared?: ContentManifest): Promise<void> {
    const remove = this.#store.delete?.bind(this.#store)
    if (remove === undefined) throw new Error('CONTENT_PRUNE_UNSUPPORTED')
    const release = this.#beginEviction(reference.id)
    try {
      const journalKey = `${this.#prefix}/prune/${reference.id}`, manifestKey = `${this.#prefix}/manifest/${reference.id}`
      const journal = await this.#store.get(journalKey)
      let inventory = journal === null ? null : decode<PruneRecord>(journal)
      if (inventory === null) {
        const saved = await this.#store.get(manifestKey)
        const candidate = saved === null ? prepared : decode<ContentManifest>(saved)
        if (candidate !== undefined) {
          const manifest = await this.#verifyManifest(reference, candidate)
          const local = await this.#store.get(this.#stageKey(manifest.stageId))
          let stageOwned = false, legacyChunks = false
          if (local !== null) {
            const stage = decode<Stage>(local)
            stageOwned = stage.applicationId === manifest.applicationId && stage.historyId === manifest.historyId &&
              stage.stageId === manifest.stageId && stage.epoch === manifest.epoch && stage.bytes === manifest.bytes && stage.mediaType === manifest.mediaType &&
              (stage.committed?.id === reference.id || prepared !== undefined && stage.committed === null)
            if (stageOwned && stage.committed === null) {
              for (let index = 0; index < manifest.chunks.length; index++) {
                const item = await this.#store.get(`${this.#stageKey(manifest.stageId)}/${index}`)
                if (item === null || decode<StagedChunk>(item).hash !== manifest.chunks[index]!.hash) { stageOwned = false; break }
              }
            }
            // Legacy global chunks can be referenced by an unseen second
            // manifest. Only this version's private staging layout proves that
            // deleting a global staging chunk cannot break such a legacy alias.
            legacyChunks = stageOwned && stage.chunkLayout === 'reference-v1'
          }
          inventory = { manifest, stageOwned, legacyChunks }
          // A durable inventory preserves stage ownership even if deletion is
          // interrupted after some descriptors or the stage itself disappear.
          await this.#store.put(journalKey, encode(inventory))
        }
      }
      if (inventory !== null) {
        const manifest = await this.#verifyManifest(reference, inventory.manifest)
        if (typeof inventory.stageOwned !== 'boolean' || typeof inventory.legacyChunks !== 'boolean') throw new Error('CONTENT_PRUNE_CORRUPT')
        for (let index = 0; index < manifest.chunks.length; index++) {
          const hash = manifest.chunks[index]!.hash
          await remove(this.#chunkKey(hash, reference.id))
          if (inventory.legacyChunks) await remove(this.#chunkKey(hash))
          if (inventory.stageOwned) await remove(`${this.#stageKey(manifest.stageId)}/${index}`)
        }
        if (inventory.stageOwned) await remove(this.#stageKey(manifest.stageId))
      }
      await remove(`${this.#prefix}/retention/${reference.id}`)
      await remove(manifestKey)
      await remove(journalKey)
    } finally { release() }
  }

  async #discardStage(id: string): Promise<void> {
    const remove = this.#store.delete?.bind(this.#store)
    if (remove === undefined) throw new Error('CONTENT_PRUNE_UNSUPPORTED')
    if (!/^[0-9a-f]{32}$/u.test(id)) throw new Error('CONTENT_STAGE_INVALID')
    const saved = await this.#store.get(this.#stageKey(id))
    if (saved === null) return
    const stage = decode<Stage>(saved)
    if (stage.stageId !== id || stage.applicationId !== this.#replica.descriptor.applicationId || stage.historyId !== this.#replica.descriptor.historyId) throw new Error('CONTENT_STAGE_CORRUPT')
    if (stage.committed !== null) { await this.#pruneLocal(stage.committed); return }
    const chunks: ContentChunk[] = []
    for (let index = 0; index < Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES); index++) {
      const key = `${this.#stageKey(id)}/${index}`, descriptor = await this.#store.get(key)
      if (descriptor === null) continue
      const { hash, nonce, bytes } = decode<StagedChunk>(descriptor)
      chunks.push({ hash, nonce, bytes })
    }
    // A commit interrupted between manifest publication and stage publication
    // must also be removed. Its identity is deterministic from the descriptors.
    if (chunks.length === Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES)) {
      const { committed: _committed, chunkLayout: _chunkLayout, ...metadata } = stage
      const manifest: ContentManifest = { ...metadata, chunks }
      const reference: ContentReference = { profile: CONTENT_PROFILE, applicationId: stage.applicationId, historyId: stage.historyId,
        id: await bytesDigest(encode(manifest)), epoch: stage.epoch, bytes: stage.bytes, mediaType: stage.mediaType }
      await this.#pruneLocal(reference, manifest)
      return
    }
    // Keep descriptors until ciphertext deletion succeeds so retry stays possible.
    for (let index = 0; index < Math.ceil(stage.bytes / CONTENT_CHUNK_BYTES); index++) {
      const key = `${this.#stageKey(id)}/${index}`, descriptor = await this.#store.get(key)
      if (descriptor !== null && stage.chunkLayout === 'reference-v1') await remove(this.#chunkKey(decode<StagedChunk>(descriptor).hash))
      await remove(key)
    }
    await remove(this.#stageKey(id))
  }

  #reference(value: ContentReference): void {
    if (value === null || typeof value !== 'object' || value.profile !== CONTENT_PROFILE || value.applicationId !== this.#replica.descriptor.applicationId ||
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
    signal.throwIfAborted()
    if (local !== null) return local
    for (const [peer, attached] of [...this.#sources]) {
      try {
        const value = await this.#sourceCall(peer, attached, () => attached.source.manifest(reference), signal)
        if (value === null) continue
        const manifest = await this.#verifyManifest(reference, value)
        this.#sourceAccess(peer, attached, signal)
        await this.#mutate(async () => {
          this.#sourceAccess(peer, attached, signal)
          await this.#store.put(`${this.#prefix}/manifest/${reference.id}`, encode(manifest))
        })
        this.#sourceAccess(peer, attached, signal)
        return manifest
      } catch { signal.throwIfAborted() /* A missing or invalid optional provider does not break application history. */ }
    }
    return null
  }
  async #chunk(reference: ContentReference, manifest: ContentManifest, index: number, signal: AbortSignal): Promise<Uint8Array | null> {
    const descriptor = manifest.chunks[index]!
    const local = await this.#localChunk(reference, descriptor.hash)
    signal.throwIfAborted()
    if (local !== null) { await this.#verifyChunk(descriptor, local); signal.throwIfAborted(); return local }
    for (const [peer, attached] of [...this.#sources]) {
      try {
        const value = await this.#sourceCall(peer, attached, () => attached.source.chunk(reference, index), signal)
        if (value === null) continue
        await this.#verifyChunk(descriptor, value)
        await this.#decrypt(manifest, index, value)
        this.#sourceAccess(peer, attached, signal)
        await this.#mutate(async () => {
          this.#sourceAccess(peer, attached, signal)
          await this.#store.put(this.#chunkKey(descriptor.hash, reference.id), value)
        })
        this.#sourceAccess(peer, attached, signal)
        return value
      } catch { signal.throwIfAborted() /* Try another independently authorized source. */ }
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
    this.#access(value.peer); this.#access(this.#replica.device.publicKey)
  }
  #mutate<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.#pending.then(() => { this.#lifetime.signal.throwIfAborted(); return operation() })
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

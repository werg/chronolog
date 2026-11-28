import {
  assertCanonicalCbor,
  bytesToHex,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  equalBytes,
  hashDomainSync,
  hexToBytes,
  type CborValue,
} from '@chronolog/canonical'
import { deleteBytesMany, writeBytesMany, type BytesStore, type BytesStoreEntry } from './bytes-store.js'

export type CasPartition = 'public' | 'private'

export interface CasNode {
  readonly bytes: Uint8Array
  readonly links: readonly string[]
}

export interface CasOptions {
  readonly store: BytesStore
  readonly prefix?: string
  readonly maxCacheEntries?: number
  readonly maxChunkBytes?: number
}

const HEX32 = /^[0-9a-f]{64}$/u

function assertHashHex(hash: string): void {
  if (!HEX32.test(hash)) throw new Error(`CAS_HASH_INVALID: ${hash}`)
}

/**
 * Canonical encoding of an explicit-link CAS DAG node.
 * Node hash = hashDomainSync('cas', canonicalCbor([bytes, sortedUniqueLinkBytes])).
 */
export function encodeCasNode(bytes: Uint8Array, links: readonly string[] = []): Uint8Array {
  const unique = [...new Set(links)].sort()
  for (const hash of unique) assertHashHex(hash)
  const linkBytes: readonly CborValue[] = unique.map(h => hexToBytes(h))
  return encodeCanonicalCbor([bytes, linkBytes])
}

export function decodeCasNode(encoded: Uint8Array): CasNode {
  const decoded = assertCanonicalCbor(encoded, DEFAULT_DECODE_LIMITS)
  if (!Array.isArray(decoded) || decoded.length !== 2) throw new Error('CAS_NODE_INVALID')
  const [bytes, rawLinks] = (decoded as unknown) as readonly [CborValue, CborValue]
  if (!(bytes instanceof Uint8Array) || !Array.isArray(rawLinks)) throw new Error('CAS_NODE_INVALID')
  const links: string[] = []
  for (const item of rawLinks) {
    if (!(item instanceof Uint8Array) || item.length !== 32) throw new Error('CAS_NODE_LINK_INVALID')
    links.push(bytesToHex(item))
  }
  return { bytes: bytes.slice(), links }
}

export function hashCasNode(encoded: Uint8Array): string {
  return bytesToHex(hashDomainSync('cas', encoded))
}

export function computeCasHash(bytes: Uint8Array, links: readonly string[] = []): string {
  return hashCasNode(encodeCasNode(bytes, links))
}

/**
 * Pure content-addressed DAG store backed by BytesStore.
 * Supports:
 * - Synchronous in-memory cache + staged batch writes during suffix replay
 * - Public vs. private partition isolation (so public control ops never read private chunks)
 * - Exact mark-and-sweep GC over explicit node links
 */
export class ContentAddressedStore {
  readonly #store: BytesStore
  readonly #prefix: string
  readonly #maxCacheEntries: number
  readonly #maxChunkBytes: number
  readonly #cache = new Map<string, { readonly encoded: Uint8Array; readonly node: CasNode; readonly partitions: Set<CasPartition> }>()
  readonly #staged = new Map<string, { readonly encoded: Uint8Array; readonly node: CasNode; readonly partition: CasPartition }>()
  readonly #known = new Map<string, Set<CasPartition>>()
  readonly #pinned = new Set<string>()
  #inBatch = false

  constructor(options: CasOptions) {
    this.#store = options.store
    this.#prefix = options.prefix ?? 'cas/'
    this.#maxCacheEntries = options.maxCacheEntries ?? 4096
    this.#maxChunkBytes = options.maxChunkBytes ?? 4 * 1024 * 1024
  }

  #key(partition: CasPartition, hash: string): string {
    return `${this.#prefix}${partition === 'public' ? 'pub' : 'priv'}/${hash}`
  }

  #touchCache(hash: string, encoded: Uint8Array, node: CasNode, partition: CasPartition): void {
    const existing = this.#cache.get(hash)
    if (existing !== undefined) {
      existing.partitions.add(partition)
      this.#cache.delete(hash)
      this.#cache.set(hash, existing)
      return
    }
    this.#cache.set(hash, { encoded, node, partitions: new Set([partition]) })
    while (this.#cache.size > this.#maxCacheEntries) {
      const oldest = this.#cache.keys().next().value
      if (oldest === undefined) break
      this.#cache.delete(oldest)
    }
  }

  /** Preload persisted CAS entries from BytesStore into the in-memory index/cache. */
  async preload(): Promise<void> {
    if (this.#store.iteratePrefix !== undefined) {
      for await (const entry of this.#store.iteratePrefix(this.#prefix)) this.indexPersistedEntry(entry)
      return
    }
    if (this.#store.iterateEntries !== undefined) {
      for await (const entry of this.#store.iterateEntries()) this.indexPersistedEntry(entry)
      return
    }
    if (this.#store.entries !== undefined) {
      for (const entry of await this.#store.entries()) this.indexPersistedEntry(entry)
    }
  }

  /**
   * Index a single persisted BytesStore entry if it belongs to this CAS prefix.
   * Returns true if the key was a CAS entry (allowing single-pass hydration in ApplicationSession.open).
   */
  indexPersistedEntry(
    entry: BytesStoreEntry,
    options: { readonly verifyHash?: boolean; readonly preloadCache?: boolean } = {},
  ): boolean {
    if (!entry.key.startsWith(this.#prefix)) return false
    const rest = entry.key.slice(this.#prefix.length)
    let partition: CasPartition
    let hash: string
    if (rest.startsWith('pub/')) { partition = 'public'; hash = rest.slice(4) }
    else if (rest.startsWith('priv/')) { partition = 'private'; hash = rest.slice(5) }
    else return true
    if (!HEX32.test(hash)) return true
    const verifyHash = options.verifyHash ?? true
    if (verifyHash) {
      const verifiedHash = hashCasNode(entry.value)
      if (verifiedHash !== hash) throw new Error(`CAS_CORRUPT: ${hash}`)
    }
    const parts = this.#known.get(hash) ?? new Set<CasPartition>()
    parts.add(partition)
    this.#known.set(hash, parts)
    const shouldPreload = options.preloadCache ?? (partition === 'public' || this.#cache.size < this.#maxCacheEntries)
    if (shouldPreload) {
      const node = decodeCasNode(entry.value)
      this.#touchCache(hash, entry.value, node, partition)
    }
    return true
  }

  /** Begin a staged replay batch: synchronous puts stay in RAM until flushBatch(). */
  beginBatch(): void {
    if (this.#inBatch) throw new Error('CAS_BATCH_ALREADY_ACTIVE')
    this.#inBatch = true
  }

  /** Discard all uncommitted staged writes from the active batch. */
  rollbackBatch(): void {
    this.#staged.clear()
    this.#inBatch = false
  }

  /** Persist staged chunks (optionally filtered to a reachable set) to BytesStore in one flush. */
  async flushBatch(keepHashes?: ReadonlySet<string>): Promise<void> {
    if (!this.#inBatch) return
    const entries: BytesStoreEntry[] = []
    for (const [hash, item] of this.#staged) {
      if (keepHashes !== undefined && !keepHashes.has(hash)) continue
      const known = this.#known.get(hash)
      if (known?.has(item.partition)) continue
      entries.push({ key: this.#key(item.partition, hash), value: item.encoded })
    }
    for (let i = 0; i < entries.length; i += 128) {
      await writeBytesMany(this.#store, entries.slice(i, i + 128), { durability: 'relaxed' })
    }
    for (const [hash, item] of this.#staged) {
      if (keepHashes !== undefined && !keepHashes.has(hash)) continue
      const parts = this.#known.get(hash) ?? new Set<CasPartition>()
      parts.add(item.partition)
      this.#known.set(hash, parts)
      this.#touchCache(hash, item.encoded, item.node, item.partition)
    }
    this.#staged.clear()
    this.#inBatch = false
  }

  /** Synchronous put into staged RAM (or cache) for deterministic reducer execution. */
  putSync(bytes: Uint8Array, links: readonly string[] = [], partition: CasPartition = 'private'): string {
    if (bytes.byteLength > this.#maxChunkBytes) throw new Error('CAS_CHUNK_TOO_LARGE')
    const encoded = encodeCasNode(bytes, links)
    const hash = hashCasNode(encoded)
    const node: CasNode = { bytes: bytes.slice(), links: [...new Set(links)].sort() }
    this.#staged.set(hash, { encoded, node, partition })
    this.#touchCache(hash, encoded, node, partition)
    return hash
  }

  /** Async durable put (for seeding modules, syncing blobs from peers, or outside a batch). */
  async put(bytes: Uint8Array, links: readonly string[] = [], partition: CasPartition = 'private'): Promise<string> {
    if (bytes.byteLength > this.#maxChunkBytes) throw new Error('CAS_CHUNK_TOO_LARGE')
    const encoded = encodeCasNode(bytes, links)
    const hash = hashCasNode(encoded)
    const node: CasNode = { bytes: bytes.slice(), links: [...new Set(links)].sort() }
    if (!this.#known.get(hash)?.has(partition)) {
      await this.#store.put(this.#key(partition, hash), encoded, { durability: 'relaxed' })
      const parts = this.#known.get(hash) ?? new Set<CasPartition>()
      parts.add(partition)
      this.#known.set(hash, parts)
    }
    this.#touchCache(hash, encoded, node, partition)
    return hash
  }

  /** Put raw pre-encoded canonical CAS node bytes (verifying digest matches expectedHash). */
  async putRaw(expectedHash: string, encoded: Uint8Array, partition: CasPartition = 'private'): Promise<void> {
    assertHashHex(expectedHash)
    if (encoded.byteLength > this.#maxChunkBytes + 65_536) throw new Error('CAS_CHUNK_TOO_LARGE')
    const actual = hashCasNode(encoded)
    if (actual !== expectedHash) throw new Error(`CAS_HASH_MISMATCH: expected ${expectedHash}, got ${actual}`)
    const node = decodeCasNode(encoded)
    if (!equalBytes(encodeCasNode(node.bytes, node.links), encoded)) throw new Error('CAS_NODE_NOT_CANONICAL')
    await this.#store.put(this.#key(partition, expectedHash), encoded, { durability: 'relaxed' })
    const parts = this.#known.get(expectedHash) ?? new Set<CasPartition>()
    parts.add(partition)
    this.#known.set(expectedHash, parts)
    this.#touchCache(expectedHash, encoded, node, partition)
  }

  /** Batched put for peer/host CAS sync (single putMany per 128 chunks instead of N transactions). */
  async putManyVerified(
    items: readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: CasPartition }[],
  ): Promise<number> {
    const toWrite: BytesStoreEntry[] = []
    const stagedMeta: { hash: string; encoded: Uint8Array; node: CasNode; partition: CasPartition }[] = []
    for (const item of items) {
      if (this.hasSync(item.hash, item.partition)) continue
      assertHashHex(item.hash)
      let encoded: Uint8Array
      let node: CasNode
      if (hashCasNode(item.bytes) === item.hash) {
        if (item.bytes.byteLength > this.#maxChunkBytes + 65_536) throw new Error('CAS_CHUNK_TOO_LARGE')
        node = decodeCasNode(item.bytes)
        if (!equalBytes(encodeCasNode(node.bytes, node.links), item.bytes)) throw new Error('CAS_NODE_NOT_CANONICAL')
        encoded = item.bytes.slice()
      } else if (computeCasHash(item.bytes, []) === item.hash) {
        if (item.bytes.byteLength > this.#maxChunkBytes) throw new Error('CAS_CHUNK_TOO_LARGE')
        encoded = encodeCasNode(item.bytes, [])
        node = { bytes: item.bytes.slice(), links: [] }
      } else {
        throw new Error(`CAS_NODE_HASH_MISMATCH:${item.hash}`)
      }
      toWrite.push({ key: this.#key(item.partition, item.hash), value: encoded })
      stagedMeta.push({ hash: item.hash, encoded, node, partition: item.partition })
    }
    if (toWrite.length === 0) return 0
    for (let i = 0; i < toWrite.length; i += 128) {
      await writeBytesMany(this.#store, toWrite.slice(i, i + 128), { durability: 'relaxed' })
    }
    for (const meta of stagedMeta) {
      const parts = this.#known.get(meta.hash) ?? new Set<CasPartition>()
      parts.add(meta.partition)
      this.#known.set(meta.hash, parts)
      this.#touchCache(meta.hash, meta.encoded, meta.node, meta.partition)
    }
    return stagedMeta.length
  }

  /** Fault a known-on-disk CAS node back into the synchronous RAM LRU (demand paging for >16 MiB DBs). */
  async ensureLoaded(hash: string, allowedPartition: CasPartition | 'any' = 'any'): Promise<boolean> {
    if (!HEX32.test(hash)) return false
    if (this.getSync(hash, allowedPartition) !== null) return true
    const loaded = await this.get(hash, allowedPartition)
    return loaded !== null
  }

  /** Synchronous read from staged RAM + LRU cache (respecting partition visibility). */
  getSync(hash: string, allowedPartition: CasPartition | 'any' = 'any'): CasNode | null {
    assertHashHex(hash)
    const staged = this.#staged.get(hash)
    if (staged !== undefined && (allowedPartition === 'any' || staged.partition === allowedPartition)) {
      return { bytes: staged.node.bytes.slice(), links: [...staged.node.links] }
    }
    const cached = this.#cache.get(hash)
    if (cached !== undefined && (allowedPartition === 'any' || cached.partitions.has(allowedPartition))) {
      this.#cache.delete(hash)
      this.#cache.set(hash, cached)
      return { bytes: cached.node.bytes.slice(), links: [...cached.node.links] }
    }
    return null
  }

  /** Async read checking RAM cache first, then BytesStore (respecting partition visibility). */
  async get(hash: string, allowedPartition: CasPartition | 'any' = 'any'): Promise<CasNode | null> {
    const sync = this.getSync(hash, allowedPartition)
    if (sync !== null) return sync
    const partitions: readonly CasPartition[] = allowedPartition === 'any' ? ['public', 'private'] : [allowedPartition]
    for (const partition of partitions) {
      const raw = await this.#store.get(this.#key(partition, hash))
      if (raw === null) continue
      if (hashCasNode(raw) !== hash) throw new Error(`CAS_CORRUPT: ${hash}`)
      const node = decodeCasNode(raw)
      const parts = this.#known.get(hash) ?? new Set<CasPartition>()
      parts.add(partition)
      this.#known.set(hash, parts)
      this.#touchCache(hash, raw, node, partition)
      return { bytes: node.bytes.slice(), links: [...node.links] }
    }
    return null
  }

  /** Get raw canonical node bytes for peer replication. */
  async getRaw(hash: string, allowedPartition: CasPartition | 'any' = 'any'): Promise<Uint8Array | null> {
    assertHashHex(hash)
    const staged = this.#staged.get(hash)
    if (staged !== undefined && (allowedPartition === 'any' || staged.partition === allowedPartition)) {
      return staged.encoded.slice()
    }
    const cached = this.#cache.get(hash)
    if (cached !== undefined && (allowedPartition === 'any' || cached.partitions.has(allowedPartition))) {
      return cached.encoded.slice()
    }
    const partitions: readonly CasPartition[] = allowedPartition === 'any' ? ['public', 'private'] : [allowedPartition]
    for (const partition of partitions) {
      const raw = await this.#store.get(this.#key(partition, hash))
      if (raw !== null) return raw
    }
    return null
  }

  hasSync(hash: string, allowedPartition: CasPartition | 'any' = 'any'): boolean {
    if (!HEX32.test(hash)) return false
    const staged = this.#staged.get(hash)
    if (staged !== undefined && (allowedPartition === 'any' || staged.partition === allowedPartition)) return true
    const cached = this.#cache.get(hash)
    if (cached !== undefined && (allowedPartition === 'any' || cached.partitions.has(allowedPartition))) return true
    const known = this.#known.get(hash)
    if (known !== undefined && (allowedPartition === 'any' || known.has(allowedPartition))) return true
    return false
  }

  /** Walk all explicit DAG links reachable from rootHashes (in RAM or durable store). */
  async reachable(rootHashes: Iterable<string>): Promise<Set<string>> {
    const visited = new Set<string>()
    const queue: string[] = []
    for (const hash of rootHashes) {
      if (HEX32.test(hash) && !visited.has(hash)) { visited.add(hash); queue.push(hash) }
    }
    while (queue.length > 0) {
      const current = queue.pop()!
      const node = await this.get(current, 'any')
      if (node === null) continue
      for (const link of node.links) {
        if (!visited.has(link)) { visited.add(link); queue.push(link) }
      }
    }
    return visited
  }

  /** Pin a CAS root hash locally so mark-and-sweep GC preserves it and its transitive links. */
  pin(hash: string): void {
    assertHashHex(hash)
    this.#pinned.add(hash)
  }

  /** Remove a local pin from a CAS root hash. */
  unpin(hash: string): void {
    this.#pinned.delete(hash)
  }

  isPinned(hash: string): boolean {
    return this.#pinned.has(hash)
  }

  pinnedHashes(): readonly string[] {
    return [...this.#pinned].sort()
  }

  /**
   * Collect a bounded CAS subgraph reachable from rootHashes for single-round-trip peer replication.
   * Respects partition visibility (e.g. 'public' for unprivileged peers / blind hosts).
   */
  async collectSubgraph(
    rootHashes: Iterable<string>,
    options: {
      readonly allowedPartition?: CasPartition | 'any'
      readonly maxNodes?: number
      readonly maxBytes?: number
    } = {},
  ): Promise<readonly { readonly hash: string; readonly bytes: Uint8Array; readonly partition: CasPartition }[]> {
    const allowed = options.allowedPartition ?? 'any'
    const maxNodes = options.maxNodes ?? 256
    const maxBytes = options.maxBytes ?? 8 * 1024 * 1024
    const visited = new Set<string>()
    const queue: string[] = []
    for (const hash of rootHashes) {
      if (HEX32.test(hash) && !visited.has(hash)) {
        visited.add(hash)
        queue.push(hash)
      }
    }
    const out: { readonly hash: string; readonly bytes: Uint8Array; readonly partition: CasPartition }[] = []
    let totalBytes = 0
    while (queue.length > 0 && out.length < maxNodes) {
      const current = queue.shift()!
      const partitions: readonly CasPartition[] = allowed === 'any' ? ['public', 'private'] : [allowed]
      let chosenPartition: CasPartition | null = null
      let raw: Uint8Array | null = null
      for (const p of partitions) {
        const candidate = await this.getRaw(current, p)
        if (candidate !== null) {
          chosenPartition = p
          raw = candidate
          break
        }
      }
      if (raw === null || chosenPartition === null) continue
      if (out.length > 0 && totalBytes + raw.byteLength > maxBytes) break
      out.push({ hash: current, bytes: raw, partition: chosenPartition })
      totalBytes += raw.byteLength
      const node = decodeCasNode(raw)
      for (const link of node.links) {
        if (!visited.has(link)) {
          visited.add(link)
          queue.push(link)
        }
      }
    }
    return out
  }

  /** Delete specific unpinned CAS nodes from a partition (used for lazy-bulk LRU cache eviction). */
  async deleteNodes(hashes: Iterable<string>, partition: CasPartition): Promise<number> {
    if (this.#inBatch) throw new Error('CAS_DELETE_DURING_BATCH')
    const keys: string[] = []
    const dropped: string[] = []
    for (const hash of hashes) {
      if (!HEX32.test(hash) || this.#pinned.has(hash)) continue
      const parts = this.#known.get(hash)
      if (parts !== undefined && parts.has(partition)) {
        keys.push(this.#key(partition, hash))
        dropped.push(hash)
      }
    }
    if (keys.length === 0) return 0
    for (let i = 0; i < keys.length; i += 32) {
      await deleteBytesMany(this.#store, keys.slice(i, i + 32), { durability: 'relaxed' })
    }
    for (const hash of dropped) {
      const parts = this.#known.get(hash)
      if (parts !== undefined) {
        parts.delete(partition)
        if (parts.size === 0) this.#known.delete(hash)
      }
      const cached = this.#cache.get(hash)
      if (cached !== undefined) {
        cached.partitions.delete(partition)
        if (cached.partitions.size === 0) this.#cache.delete(hash)
      }
    }
    return dropped.length
  }

  /** Exact local mark-and-sweep GC preserving everything reachable from rootHashes + pinned roots, deleting in yielding batches. */
  async collectGarbage(rootHashes: Iterable<string>): Promise<{ readonly kept: number; readonly deleted: number }> {
    if (this.#inBatch) throw new Error('CAS_GC_DURING_BATCH')
    const allRoots = new Set<string>(this.#pinned)
    for (const h of rootHashes) allRoots.add(h)
    const keep = await this.reachable(allRoots)
    const keysToDelete: string[] = []
    const hashesToDrop: string[] = []
    for (const [hash, partitions] of [...this.#known.entries()]) {
      if (keep.has(hash)) continue
      for (const partition of partitions) {
        keysToDelete.push(this.#key(partition, hash))
      }
      hashesToDrop.push(hash)
    }
    for (let i = 0; i < keysToDelete.length; i += 32) {
      await deleteBytesMany(this.#store, keysToDelete.slice(i, i + 32), { durability: 'relaxed' })
      if (i + 32 < keysToDelete.length) {
        await new Promise<void>(resolve => setTimeout(resolve, 0))
      }
    }
    for (const hash of hashesToDrop) {
      this.#known.delete(hash)
      this.#cache.delete(hash)
    }
    return { kept: keep.size, deleted: keysToDelete.length }
  }

  listKnownHashes(partition?: CasPartition): readonly string[] {
    const out = new Set<string>()
    for (const [hash, parts] of this.#known) {
      if (partition === undefined || parts.has(partition)) out.add(hash)
    }
    for (const [hash, item] of this.#staged) {
      if (partition === undefined || item.partition === partition) out.add(hash)
    }
    return [...out].sort()
  }
}

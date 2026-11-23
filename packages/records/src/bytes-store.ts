/**
 * The single local byte-storage contract for identity, controls, journals and projections.
 * One owner serializes mutations. Each put atomically replaces one key and resolves only
 * after durable persistence. get and put must not expose mutable internal byte buffers.
 */
export interface BytesStoreEntry {
  readonly key: string
  readonly value: Uint8Array
}

export interface BytesStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, bytes: Uint8Array): Promise<void>
  /** Optional bounded-key batch, preserving input order. */
  getMany?(keys: readonly string[]): Promise<readonly (Uint8Array | null)[]>
  /** Optional deterministic snapshot enumeration for atomic encrypted device checkpoints. */
  entries?(): Promise<readonly BytesStoreEntry[]>
  /** Bounded-memory, deterministic snapshot under the single storage owner. Release the iterator when abandoning a read. */
  iterateEntries?(): AsyncIterable<BytesStoreEntry>
  /** Stage a stream and atomically publish only after it completes; false leaves an existing store untouched. */
  putStreamIfEmpty?(entries: AsyncIterable<BytesStoreEntry>): Promise<boolean>
  /** Atomically initialize an empty store; false leaves an existing store untouched. */
  putAllIfEmpty?(entries: readonly BytesStoreEntry[]): Promise<boolean>
}

/** Independent ephemeral storage for disposable peers and tests; not a durability claim. */
export class MemoryBytesStore implements BytesStore {
  readonly #values = new Map<string, Uint8Array>()
  readonly #quotaBytes: number
  readonly #maxValueBytes: number
  #usedBytes = 0
  constructor(options: { readonly quotaBytes?: number; readonly maxValueBytes?: number } = {}) {
    for (const limit of [options.quotaBytes, options.maxValueBytes]) {
      if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1)) throw new Error('BYTES_STORE_QUOTA_INVALID')
    }
    this.#quotaBytes = options.quotaBytes ?? Infinity
    this.#maxValueBytes = options.maxValueBytes ?? Infinity
  }
  async get(key: string): Promise<Uint8Array | null> { return this.#values.get(key)?.slice() ?? null }
  async put(key: string, bytes: Uint8Array): Promise<void> {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength > this.#maxValueBytes) throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
    const used = this.#usedBytes - (this.#values.get(key)?.byteLength ?? 0) + bytes.byteLength
    if (used > this.#quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
    this.#values.set(key, Uint8Array.from(bytes)); this.#usedBytes = used
  }
  async putAllIfEmpty(entries: readonly BytesStoreEntry[]): Promise<boolean> {
    const captured = entries.map(entry => ({ key: entry.key, value: Uint8Array.from(entry.value) }))
    if (new Set(captured.map(entry => entry.key)).size !== captured.length) throw new Error('BYTES_STORE_DUPLICATE_KEY')
    if (captured.some(entry => entry.value.byteLength > this.#maxValueBytes)) throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
    const bytes = captured.reduce((sum, entry) => sum + entry.value.byteLength, 0)
    if (bytes > this.#quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
    if (this.#values.size !== 0) return false
    for (const entry of captured) this.#values.set(entry.key, entry.value)
    this.#usedBytes = bytes
    return true
  }
  async *iterateEntries(): AsyncIterable<BytesStoreEntry> {
    // Values are immutable after put; retaining references captures a snapshot
    // without copying every payload up front.
    const snapshot = [...this.#values].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    for (const [key, value] of snapshot) yield { key, value: value.slice() }
  }
  async putStreamIfEmpty(entries: AsyncIterable<BytesStoreEntry>): Promise<boolean> {
    if (this.#values.size !== 0) return false
    const staged = new Map<string, Uint8Array>()
    let bytes = 0
    for await (const entry of entries) {
      if (staged.has(entry.key)) throw new Error('BYTES_STORE_DUPLICATE_KEY')
      if (!(entry.value instanceof Uint8Array) || entry.value.byteLength > this.#maxValueBytes) throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
      bytes += entry.value.length
      if (bytes > this.#quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
      staged.set(entry.key, Uint8Array.from(entry.value))
    }
    if (this.#values.size !== 0) return false
    for (const [key, value] of staged) this.#values.set(key, value)
    this.#usedBytes = bytes
    return true
  }
  async entries(): Promise<readonly BytesStoreEntry[]> {
    return [...this.#values.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => ({ key, value: value.slice() }))
  }
}

/** Bounded prefetch for owners reopening an authenticated journal. */
export async function readBytesMany(store: BytesStore, keys: readonly string[]): Promise<readonly (Uint8Array | null)[]> {
  return store.getMany === undefined ? Promise.all(keys.map(key => store.get(key))) : store.getMany(keys)
}

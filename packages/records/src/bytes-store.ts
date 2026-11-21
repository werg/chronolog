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
  /** Optional deterministic snapshot enumeration for atomic encrypted device checkpoints. */
  entries?(): Promise<readonly BytesStoreEntry[]>
  /** Atomically initialize an empty store; false leaves an existing store untouched. */
  putAllIfEmpty?(entries: readonly BytesStoreEntry[]): Promise<boolean>
}

/** Independent ephemeral storage for disposable peers and tests; not a durability claim. */
export class MemoryBytesStore implements BytesStore {
  readonly #values = new Map<string, Uint8Array>()
  async get(key: string): Promise<Uint8Array | null> { return this.#values.get(key)?.slice() ?? null }
  async put(key: string, bytes: Uint8Array): Promise<void> { this.#values.set(key, bytes.slice()) }
  async putAllIfEmpty(entries: readonly BytesStoreEntry[]): Promise<boolean> {
    const captured = entries.map(entry => ({ key: entry.key, value: entry.value.slice() }))
    if (new Set(captured.map(entry => entry.key)).size !== captured.length) throw new Error('BYTES_STORE_DUPLICATE_KEY')
    if (this.#values.size !== 0) return false
    for (const entry of captured) this.#values.set(entry.key, entry.value)
    return true
  }
  async entries(): Promise<readonly BytesStoreEntry[]> {
    return [...this.#values.entries()]
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, value]) => ({ key, value: value.slice() }))
  }
}

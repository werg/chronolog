/**
 * The single local byte-storage contract for identity, controls, journals and projections.
 * One owner serializes mutations. Each put atomically replaces one key and resolves only
 * after durable persistence. get and put must not expose mutable internal byte buffers.
 */
export interface BytesStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, bytes: Uint8Array): Promise<void>
}

/** Independent ephemeral storage for disposable peers and tests; not a durability claim. */
export class MemoryBytesStore implements BytesStore {
  readonly #values = new Map<string, Uint8Array>()
  async get(key: string): Promise<Uint8Array | null> { return this.#values.get(key)?.slice() ?? null }
  async put(key: string, bytes: Uint8Array): Promise<void> { this.#values.set(key, bytes.slice()) }
}

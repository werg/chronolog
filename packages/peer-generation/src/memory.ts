import type { PeerStore } from './control-types.js'

/** Independent ephemeral store for models and disposable applications, never a durability claim. */
export class MemoryPeerStore implements PeerStore {
  readonly #values = new Map<string, Uint8Array>()
  async get(key: string): Promise<Uint8Array | null> { return this.#values.get(key)?.slice() ?? null }
  async put(key: string, value: Uint8Array): Promise<void> { this.#values.set(key, value.slice()) }
}

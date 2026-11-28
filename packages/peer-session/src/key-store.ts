import type { BytesStore } from '@chronolog/records'
import { epochKeyCommitment } from '@chronolog/crypto'

/**
 * Key group ids. One store holds every symmetric secret a session derives or unseals:
 * - `epoch` — default-ring `$keys` epoch keys
 * - `ring:<name>` — compartment ring epoch keys
 * - `vault:<topic>:<vaultId>` (URI-encoded parts) — Private Capability Vault keys
 * - `tree-seed` — cached Key-Tagged TreeKEM node seeds (epoch 0, "commitment" = node pubKeyHash)
 * Other key families (for example future key groups) only need a new group id.
 */
export type KeyGroupId = string

export const EPOCH_KEY_GROUP = 'epoch'
export const TREE_SEED_GROUP = 'tree-seed'
const MAX_TREE_SEEDS = 256
const HEX32 = /^[0-9a-f]{64}$/u

export function ringKeyGroup(ring: string): KeyGroupId {
  return ring === 'default' ? EPOCH_KEY_GROUP : `ring:${ring}`
}

export function vaultKeyGroup(topic: string, vaultId: string): KeyGroupId {
  return `vault:${encodeURIComponent(topic)}:${encodeURIComponent(vaultId)}`
}

/** Parse a vault group id back into its topic and vault id (null for other groups). */
export function parseVaultKeyGroup(group: KeyGroupId): { readonly topic: string; readonly vaultId: string } | null {
  if (!group.startsWith('vault:')) return null
  const parts = group.slice('vault:'.length).split(':')
  if (parts.length !== 2) return null
  return { topic: decodeURIComponent(parts[0]!), vaultId: decodeURIComponent(parts[1]!) }
}

/**
 * Commitment-keyed symmetric key store: entries are `(group, epoch, commitment) -> 32-byte key`.
 *
 * Two members can concurrently author key material for the same `(group, epoch)` (for example two
 * offline rotations that both pick `currentEpoch + 1`); only one of them wins on the log. Keys are
 * therefore never overwritten by epoch alone: every candidate is kept under its commitment, and
 * callers select the key whose commitment matches the on-log `keyCommitment`.
 *
 * Persisted under `<prefix>/key/<group>/<epoch>/<commitment>`. `wipe()` zeroes every key in memory.
 */
export class KeyStore {
  readonly #store: BytesStore
  readonly #keyPrefix: string
  readonly #groups = new Map<KeyGroupId, Map<number, Map<string, Uint8Array>>>()
  /** `(group, epoch, attempt)` lockbox opens that already failed; never retried. */
  readonly #failed = new Set<string>()

  constructor(store: BytesStore, sessionPrefix: string) {
    this.#store = store
    this.#keyPrefix = `${sessionPrefix}/key/`
  }

  /** Store-key suffix (after `<sessionPrefix>/`) this store owns. */
  static readonly STORE_SEGMENT = 'key/'

  #storeKey(group: KeyGroupId, epoch: number, commitment: string): string {
    return `${this.#keyPrefix}${encodeURIComponent(group)}/${epoch}/${commitment}`
  }

  #epochMap(group: KeyGroupId, epoch: number, create: boolean): Map<string, Uint8Array> | undefined {
    let byEpoch = this.#groups.get(group)
    if (byEpoch === undefined) {
      if (!create) return undefined
      byEpoch = new Map()
      this.#groups.set(group, byEpoch)
    }
    let byCommitment = byEpoch.get(epoch)
    if (byCommitment === undefined && create) {
      byCommitment = new Map()
      byEpoch.set(epoch, byCommitment)
    }
    return byCommitment
  }

  #setInMemory(group: KeyGroupId, epoch: number, commitment: string, key: Uint8Array): boolean {
    const map = this.#epochMap(group, epoch, true)!
    if (map.has(commitment)) return false
    map.set(commitment, key.slice())
    return true
  }

  /**
   * Install a key candidate; returns its commitment. Idempotent per `(group, epoch, commitment)`;
   * never replaces a different candidate for the same epoch. `commitment` defaults to the
   * epoch-key commitment of `key` (tree seeds pass their node pubKeyHash instead).
   */
  async install(group: KeyGroupId, epoch: number, key: Uint8Array, commitment = epochKeyCommitment(key)): Promise<string> {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !Number.isSafeInteger(epoch) || epoch < 0 || !HEX32.test(commitment)) {
      throw new Error('EPOCH_KEY_INVALID')
    }
    if (group === TREE_SEED_GROUP) await this.#evictTreeSeeds(commitment)
    if (this.#setInMemory(group, epoch, commitment, key)) {
      await this.#store.put(this.#storeKey(group, epoch, commitment), key.slice())
    }
    return commitment
  }

  async #evictTreeSeeds(incoming: string): Promise<void> {
    const seeds = this.#epochMap(TREE_SEED_GROUP, 0, false)
    if (seeds === undefined || seeds.has(incoming) || seeds.size < MAX_TREE_SEEDS) return
    const oldest = seeds.keys().next().value
    if (oldest === undefined) return
    seeds.get(oldest)?.fill(0)
    seeds.delete(oldest)
    await this.#store.delete?.(this.#storeKey(TREE_SEED_GROUP, 0, oldest))
  }

  /**
   * The key for `(group, epoch)`: the candidate with `commitment` when one is given (undefined when
   * that exact key is not held), otherwise the first installed candidate. Returns the internal
   * buffer; copy before handing it to callers outside the session.
   */
  get(group: KeyGroupId, epoch: number, commitment?: string): Uint8Array | undefined {
    const map = this.#epochMap(group, epoch, false)
    if (map === undefined) return undefined
    if (commitment !== undefined) return map.get(commitment)
    return map.values().next().value
  }

  has(group: KeyGroupId, epoch: number, commitment?: string): boolean {
    return this.get(group, epoch, commitment) !== undefined
  }

  /** Every candidate for `(group, epoch)`, the one matching `preferred` first. */
  candidates(group: KeyGroupId, epoch: number, preferred?: string): Uint8Array[] {
    const map = this.#epochMap(group, epoch, false)
    if (map === undefined) return []
    const first = preferred === undefined ? undefined : map.get(preferred)
    const out = first === undefined ? [] : [first]
    for (const [commitment, key] of map) if (commitment !== preferred) out.push(key)
    return out
  }

  /** Epochs with at least one key in `group`, ascending. */
  epochs(group: KeyGroupId): number[] {
    const byEpoch = this.#groups.get(group)
    if (byEpoch === undefined) return []
    return [...byEpoch.entries()].filter(([, m]) => m.size > 0).map(([ep]) => ep).sort((a, b) => a - b)
  }

  /** Group ids currently holding keys whose id starts with `prefix`. */
  groups(prefix = ''): KeyGroupId[] {
    return [...this.#groups.keys()].filter(g => g.startsWith(prefix) && this.epochs(g).length > 0)
  }

  /** Live map of `commitment -> key` for `(group, epoch)` (used for TreeKEM node seed caches). */
  view(group: KeyGroupId, epoch: number): ReadonlyMap<string, Uint8Array> {
    return this.#epochMap(group, epoch, true)!
  }

  /** True when opening `attempt` (a caller-chosen lockbox tag) for `(group, epoch)` already failed. */
  isFailed(group: KeyGroupId, epoch: number, attempt: string): boolean {
    return this.#failed.has(`${group}\0${epoch}\0${attempt}`)
  }

  markFailed(group: KeyGroupId, epoch: number, attempt: string): void {
    this.#failed.add(`${group}\0${epoch}\0${attempt}`)
  }

  /** Load one persisted entry (`rest` = store key after `<sessionPrefix>/`); true if it added a key. */
  hydrate(rest: string, value: Uint8Array): boolean {
    if (!rest.startsWith(KeyStore.STORE_SEGMENT) || value.length !== 32) return false
    const parts = rest.slice(KeyStore.STORE_SEGMENT.length).split('/')
    if (parts.length !== 3) return false
    let group: string
    try { group = decodeURIComponent(parts[0]!) } catch { return false }
    const epoch = Number(parts[1])
    const commitment = parts[2]!
    if (group.length === 0 || !Number.isSafeInteger(epoch) || epoch < 0 || !HEX32.test(commitment)) return false
    // Epoch-key commitments are recomputed (a corrupt or substituted key never binds to a commitment).
    if (group !== TREE_SEED_GROUP && epochKeyCommitment(value) !== commitment) return false
    return this.#setInMemory(group, epoch, commitment, value)
  }

  /** Zero every key held in memory and forget them (persisted entries are untouched). */
  wipe(): void {
    for (const byEpoch of this.#groups.values()) {
      for (const byCommitment of byEpoch.values()) {
        for (const key of byCommitment.values()) key.fill(0)
        byCommitment.clear()
      }
      byEpoch.clear()
    }
    this.#groups.clear()
    this.#failed.clear()
  }

  /** Delete every persisted key entry under this session's prefix (ephemeral hosts call this on exit). */
  async purgePersisted(): Promise<void> {
    if (this.#store.iteratePrefix === undefined || this.#store.delete === undefined) return
    const keys: string[] = []
    for await (const entry of this.#store.iteratePrefix(this.#keyPrefix)) {
      entry.value.fill(0)
      keys.push(entry.key)
    }
    if (keys.length === 0) return
    if (this.#store.deleteMany !== undefined) await this.#store.deleteMany(keys)
    else for (const key of keys) await this.#store.delete(key)
  }
}

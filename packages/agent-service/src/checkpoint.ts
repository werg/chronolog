import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import type { DurableOperationStore } from '@chronolog/node-core'

import { validateConsumerId } from './event-source.js'

export interface ConsumerCheckpoint {
  readonly cursor: string | null
  readonly revision: string | null
  readonly state: Uint8Array
}

/**
 * State and processed cursor are exactly one durable replacement. The binding
 * names group/history, filter identity/version and reducer/handler version.
 * Delivery acknowledgments cannot commit or advance this checkpoint.
 */
export class CheckpointStore {
  readonly #key: string
  readonly #binding: Uint8Array
  readonly #store: DurableOperationStore
  readonly #maxStateBytes: number

  constructor(store: DurableOperationStore, options: {
    readonly id: string
    readonly binding: Uint8Array
    readonly maxStateBytes?: number
  }) {
    validateConsumerId(options.id)
    this.#key = `agent/checkpoint/${encodeURIComponent(options.id)}`
    this.#binding = options.binding.slice()
    this.#store = store
    this.#maxStateBytes = options.maxStateBytes ?? 8 * 1024 * 1024
    if (!Number.isSafeInteger(this.#maxStateBytes) || this.#maxStateBytes < 1 || this.#binding.length > 65_536) {
      throw new Error('CHECKPOINT_BOUNDS_INVALID')
    }
  }

  async load(): Promise<ConsumerCheckpoint | null> {
    const bytes = await this.#store.get(this.#key)
    if (bytes === null) return null
    const value = assertCanonicalCbor(bytes)
    if (!Array.isArray(value) || value.length !== 5 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
        (value[2] !== null && typeof value[2] !== 'string') || (value[3] !== null && typeof value[3] !== 'string') ||
        !(value[4] instanceof Uint8Array) || value[4].length > this.#maxStateBytes) throw new Error('CHECKPOINT_INVALID')
    if (!equalBytes(value[1], this.#binding)) throw new Error('CHECKPOINT_BINDING_MISMATCH')
    return { cursor: value[2], revision: value[3], state: value[4].slice() }
  }

  async commit(checkpoint: ConsumerCheckpoint): Promise<void> {
    if (checkpoint.state.length > this.#maxStateBytes ||
        (checkpoint.cursor !== null && (checkpoint.cursor.length === 0 || checkpoint.cursor.length > 16_384)) ||
        (checkpoint.revision !== null && (checkpoint.revision.length === 0 || checkpoint.revision.length > 16_384))) {
      throw new Error('CHECKPOINT_BOUNDS_EXCEEDED')
    }
    await this.#store.put(this.#key, encodeCanonicalCbor([
      1n, this.#binding, checkpoint.cursor, checkpoint.revision, checkpoint.state,
    ]))
  }
}

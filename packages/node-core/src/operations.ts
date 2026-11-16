import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'

import { Mutex } from './async.js'

/**
 * Node-local secrets and retry identities, never replicated. A successful put
 * atomically replaces one value and must survive process/device interruption.
 * The runtime must enforce one storage owner (daemon lock or browser Web Lock).
 */
export interface DurableOperationStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, value: Uint8Array): Promise<void>
}

interface PreparedOperation {
  readonly id: string
  readonly fingerprint: Uint8Array
  readonly payload: Uint8Array
}

/**
 * One resumable authoring lane. The exact prepared bytes are durable before
 * publication; an unfinished operation is completed before preparing another.
 * `apply` must recover an interrupted publication of the same bytes.
 */
export class DurableOperationJournal {
  readonly #store: DurableOperationStore
  readonly #prefix: string
  readonly #mutex = new Mutex()

  constructor(store: DurableOperationStore, namespace: string) {
    if (namespace.length === 0) throw new Error('OPERATION_NAMESPACE_REQUIRED')
    this.#store = store
    this.#prefix = namespace
  }

  async run(options: {
    readonly operationId: string
    readonly fingerprint: Uint8Array
    readonly prepare: () => Promise<Uint8Array>
    readonly apply: (payload: Uint8Array) => Promise<void>
  }): Promise<Uint8Array> {
    validateOperationId(options.operationId)
    return this.#mutex.run(async () => {
      const previous = await this.#completed(options.operationId)
      if (previous !== null) return matching(previous, options.fingerprint)

      const pending = await this.#pending()
      if (pending !== null) {
        if (pending.id === options.operationId) matching(pending, options.fingerprint)
        await this.#finish(pending, options.apply)
        if (pending.id === options.operationId) return pending.payload.slice()
      }

      const prepared: PreparedOperation = {
        id: options.operationId,
        fingerprint: options.fingerprint.slice(),
        payload: (await options.prepare()).slice(),
      }
      await this.#store.put(`${this.#prefix}/pending`, encode(prepared))
      await this.#finish(prepared, options.apply)
      return prepared.payload.slice()
    })
  }

  async recover(apply: (payload: Uint8Array) => Promise<void>): Promise<void> {
    await this.#mutex.run(async () => {
      const pending = await this.#pending()
      if (pending !== null) await this.#finish(pending, apply)
    })
  }

  async lookup(operationId: string): Promise<Uint8Array | null> {
    validateOperationId(operationId)
    const completed = await this.#completed(operationId)
    if (completed !== null) return completed.payload.slice()
    const pending = await this.#pending()
    return pending?.id === operationId ? pending.payload.slice() : null
  }

  async #finish(prepared: PreparedOperation, apply: (payload: Uint8Array) => Promise<void>): Promise<void> {
    const completed = await this.#completed(prepared.id)
    if (completed !== null) {
      matching(completed, prepared.fingerprint)
      if (!equalBytes(completed.payload, prepared.payload)) throw new Error('OPERATION_STORE_CONFLICT')
    } else {
      await apply(prepared.payload.slice())
      await this.#store.put(this.#key(prepared.id), encode(prepared))
    }
    // The completed receipt is durable first. A crash here safely repeats only
    // this clear, not authoring or publication.
    await this.#store.put(`${this.#prefix}/pending`, encodeCanonicalCbor(null))
  }

  async #pending(): Promise<PreparedOperation | null> {
    const bytes = await this.#store.get(`${this.#prefix}/pending`)
    return bytes === null ? null : decode(bytes)
  }

  async #completed(id: string): Promise<PreparedOperation | null> {
    const bytes = await this.#store.get(this.#key(id))
    const result = bytes === null ? null : decode(bytes)
    if (result !== null && result.id !== id) throw new Error('OPERATION_STORE_CONFLICT')
    return result
  }

  #key(id: string): string { return `${this.#prefix}/completed/${encodeURIComponent(id)}` }
}

export function validateOperationId(value: string): void {
  if (value.length === 0 || value.length > 512 || [...value].some((character) => character.charCodeAt(0) < 32)) {
    throw new Error('OPERATION_ID_INVALID')
  }
}

function matching(operation: PreparedOperation, fingerprint: Uint8Array): Uint8Array {
  if (!equalBytes(operation.fingerprint, fingerprint)) throw new Error('OPERATION_ID_CONFLICT')
  return operation.payload.slice()
}

function encode(operation: PreparedOperation): Uint8Array {
  return encodeCanonicalCbor([1n, operation.id, operation.fingerprint, operation.payload])
}

function decode(bytes: Uint8Array): PreparedOperation | null {
  const value = assertCanonicalCbor(bytes)
  if (value === null) return null
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || typeof value[1] !== 'string' ||
      !(value[2] instanceof Uint8Array) || !(value[3] instanceof Uint8Array)) throw new Error('OPERATION_STORE_INVALID')
  validateOperationId(value[1])
  return { id: value[1], fingerprint: value[2], payload: value[3] }
}

/** In-process conformance store. Production runtimes supply durable storage. */
export class MemoryOperationStore implements DurableOperationStore {
  readonly #values = new Map<string, Uint8Array>()
  async get(key: string): Promise<Uint8Array | null> { return this.#values.get(key)?.slice() ?? null }
  async put(key: string, value: Uint8Array): Promise<void> { this.#values.set(key, value.slice()) }
}

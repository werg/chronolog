import type { DeviceMetadataStore } from './device.js'

const TABLE = 'metadata'
const MAX_BYTES = 16 * 1024 * 1024

/** Browser-owned key/value metadata. No OPFS, SQL engine or long-lived lock. */
export class BrowserMetadataStore implements DeviceMetadataStore {
  readonly #database: IDBDatabase
  #closed = false

  private constructor(database: IDBDatabase) {
    this.#database = database
    database.onversionchange = () => { this.close() }
  }

  static open(name: string): Promise<BrowserMetadataStore> {
    if (typeof indexedDB === 'undefined') return Promise.reject(new Error('BROWSER_IDENTITY_STORAGE_UNAVAILABLE'))
    return new Promise((resolve, reject) => {
      let failed = false
      const request = indexedDB.open(`chronolog-metadata:${name}`, 1)
      request.onupgradeneeded = () => { request.result.createObjectStore(TABLE) }
      request.onerror = () => { reject(request.error ?? new Error('BROWSER_IDENTITY_STORAGE_UNAVAILABLE')) }
      request.onblocked = () => { failed = true; reject(new Error('BROWSER_IDENTITY_STORAGE_BLOCKED')) }
      request.onsuccess = () => {
        if (failed) request.result.close()
        else resolve(new BrowserMetadataStore(request.result))
      }
    })
  }

  get(key: string): Promise<Uint8Array | null> {
    return this.#transaction('readonly', table => {
      const request = table.get(key)
      return () => {
        if (request.result === undefined) return null
        if (!(request.result instanceof Uint8Array) || request.result.length > MAX_BYTES) throw new Error('BROWSER_METADATA_INVALID')
        return request.result.slice()
      }
    })
  }

  put(key: string, value: Uint8Array): Promise<void> {
    this.#validate(key, value)
    const captured = value.slice()
    return this.#transaction('readwrite', table => { table.put(captured, key); return () => undefined })
  }

  initialize(input: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<void> {
    const entries = input.map(({ key, value }) => { this.#validate(key, value); return { key, value: value.slice() } })
    if (entries.length === 0 || entries.length > 8 || new Set(entries.map(entry => entry.key)).size !== entries.length) {
      return Promise.reject(new Error('BROWSER_METADATA_INITIALIZATION_INVALID'))
    }
    return this.#transaction('readwrite', table => {
      // IndexedDB serializes these read/write transactions across tabs. Generate
      // the candidate key before entering, then insert all records or none.
      let remaining = entries.length, present = false
      for (const entry of entries) {
        const request = table.get(entry.key)
        request.onsuccess = () => {
          present ||= request.result !== undefined
          if (--remaining === 0 && !present) for (const candidate of entries) table.add(candidate.value, candidate.key)
        }
      }
      return () => undefined
    })
  }

  compareAndSwap(key: string, expected: Uint8Array | null, value: Uint8Array): Promise<boolean> {
    this.#validate(key, value)
    const before = expected?.slice() ?? null, after = value.slice()
    return this.#transaction('readwrite', table => {
      let written = false
      const request = table.get(key)
      request.onsuccess = () => {
        const current: unknown = request.result
        if (before === null ? current === undefined : current instanceof Uint8Array &&
          before.length === current.length && before.every((byte, index) => byte === current[index])) {
          table.put(after, key); written = true
        }
      }
      return () => written
    })
  }

  close(): void { if (!this.#closed) { this.#closed = true; this.#database.close() } }

  #validate(key: string, value: Uint8Array): void {
    if (!key || key.length > 4096 || value.length > MAX_BYTES) throw new Error('BROWSER_METADATA_LIMIT')
  }

  #transaction<T>(mode: IDBTransactionMode, enqueue: (table: IDBObjectStore) => () => T): Promise<T> {
    if (this.#closed) return Promise.reject(new Error('BROWSER_METADATA_CLOSED'))
    return new Promise((resolve, reject) => {
      const transaction = mode === 'readonly'
        ? this.#database.transaction(TABLE, mode)
        : this.#database.transaction(TABLE, mode, { durability: 'strict' })
      const value = enqueue(transaction.objectStore(TABLE))
      transaction.oncomplete = () => { try { resolve(value()) } catch (error) { reject(error) } }
      transaction.onabort = () => { reject(transaction.error ?? new Error('BROWSER_METADATA_ABORTED')) }
      transaction.onerror = () => { /* Abortion reports the terminal error. */ }
    })
  }
}

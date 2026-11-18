import type { BytesStore } from './bytes-store.js'
import { assertRecordKey, decodeRecordValue, encodeRecordValue, MAX_RECORD_ENVELOPE_BYTES, MAX_RECORD_VALUE_BYTES } from './record-envelope.js'

const TABLE = 'values'
const VERSION = 1

/** Transaction-complete, per-key atomic durable records; no signer or protocol state lives here. */
export class IndexedDbBytesStore implements BytesStore {
  readonly #database: IDBDatabase
  #pending: Promise<void> = Promise.resolve()
  #closing: Promise<void> | undefined
  #closed = false
  #invalid: Error | undefined

  private constructor(database: IDBDatabase) {
    this.#database = database
    database.onversionchange = () => {
      this.#invalid = new Error('INDEXEDDB_STORE_VERSION_CHANGED')
      database.close()
    }
  }

  static open(name: string): Promise<IndexedDbBytesStore> {
    if (typeof indexedDB === 'undefined') return Promise.reject(new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED'))
    return new Promise((resolve, reject) => {
      let blocked = false
      const request = indexedDB.open('chronolog-data:' + name, VERSION)
      request.onupgradeneeded = () => { request.result.createObjectStore(TABLE) }
      request.onerror = () => { reject(request.error ?? new Error('INDEXEDDB_STORE_OPEN_FAILED')) }
      request.onblocked = () => { blocked = true; reject(new Error('INDEXEDDB_STORE_BLOCKED')) }
      request.onsuccess = () => {
        if (blocked) request.result.close()
        else resolve(new IndexedDbBytesStore(request.result))
      }
    })
  }

  async get(key: string): Promise<Uint8Array | null> {
    assertRecordKey(key)
    return this.#enqueue(async () => {
      const raw = await this.#transaction('readonly', table => {
        const request = table.get(key)
        return () => request.result as unknown
      })
      if (raw === undefined) return null
      if (!(raw instanceof Uint8Array) || raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('INDEXEDDB_VALUE_CORRUPT')
      return decodeRecordValue(key, raw, 'INDEXEDDB_VALUE_CORRUPT')
    })
  }

  async put(key: string, input: Uint8Array): Promise<void> {
    assertRecordKey(key)
    if (input.length > MAX_RECORD_VALUE_BYTES) return Promise.reject(new Error('BYTES_STORE_VALUE_LIMIT'))
    const bytes = input.slice()
    return this.#enqueue(async () => {
      // Hash and encode outside the transaction: an await inside would auto-close it.
      const raw = await encodeRecordValue(key, bytes)
      await this.#transaction('readwrite', table => { table.put(raw, key); return () => undefined })
    })
  }

  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing
    this.#closed = true
    this.#closing = this.#pending.then(() => { this.#database.close() })
    return this.#closing
  }

  #enqueue<T>(work: () => Promise<T>): Promise<T> {
    if (this.#closed) return Promise.reject(new Error('INDEXEDDB_STORE_CLOSED'))
    if (this.#invalid !== undefined) return Promise.reject(this.#invalid)
    const task = this.#pending.then(() => {
      if (this.#invalid !== undefined) throw this.#invalid
      return work()
    })
    this.#pending = task.then(() => undefined, () => undefined)
    return task
  }

  #transaction<T>(mode: IDBTransactionMode, enqueue: (table: IDBObjectStore) => () => T): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction
      try { transaction = this.#database.transaction(TABLE, mode, { durability: 'strict' }) }
      catch (error) { reject(error); return }
      let value: () => T
      try { value = enqueue(transaction.objectStore(TABLE)) }
      catch (error) {
        try { transaction.abort() } catch { /* Preserve the original request failure. */ }
        reject(error); return
      }
      transaction.oncomplete = () => { try { resolve(value()) } catch (error) { reject(error) } }
      transaction.onabort = () => { reject(transaction.error ?? new Error('INDEXEDDB_TRANSACTION_ABORTED')) }
      transaction.onerror = () => { /* The abort event carries the transaction failure. */ }
    })
  }
}

/** Scratch-only conformance probe; never opens the device's actual database. */
export async function probeIndexedDbBytesStore(): Promise<boolean> {
  if (typeof indexedDB === 'undefined') return false
  const name = 'probe-' + crypto.randomUUID()
  let store: IndexedDbBytesStore | undefined
  try {
    store = await IndexedDbBytesStore.open(name)
    await store.put('probe', Uint8Array.of(0, 255))
    await store.close()
    store = undefined
    const reopened = await IndexedDbBytesStore.open(name)
    store = reopened
    const bytes = await reopened.get('probe')
    if (bytes?.length !== 2 || bytes[0] !== 0 || bytes[1] !== 255) throw new Error('INDEXEDDB_PROBE_FAILED')
    return true
  } finally {
    await store?.close()
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase('chronolog-data:' + name)
      request.onsuccess = () => { resolve() }
      request.onerror = () => { reject(request.error ?? new Error('INDEXEDDB_PROBE_CLEANUP_FAILED')) }
      request.onblocked = () => { reject(new Error('INDEXEDDB_PROBE_CLEANUP_BLOCKED')) }
    })
  }
}

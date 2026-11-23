import type { BytesStore, BytesStoreEntry } from './bytes-store.js'
import { assertRecordKey, decodeRecordValue, encodeRecordValue, MAX_RECORD_ENVELOPE_BYTES, MAX_RECORD_VALUE_BYTES } from './record-envelope.js'

const TABLE = 'values'
const STAGING = 'checkpoint-staging'
const VERSION = 2

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

  static open(name: string, { create = true } = {}): Promise<IndexedDbBytesStore> {
    if (typeof indexedDB === 'undefined') return Promise.reject(new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED'))
    return new Promise((resolve, reject) => {
      let blocked = false, missing = false
      const request = indexedDB.open('chronolog-data:' + name, VERSION)
      request.onupgradeneeded = event => {
        if (blocked) { request.transaction?.abort(); return }
        if (!create && event.oldVersion === 0) {
          missing = true
          request.transaction?.abort()
          return
        }
        if (!request.result.objectStoreNames.contains(TABLE)) request.result.createObjectStore(TABLE)
        if (!request.result.objectStoreNames.contains(STAGING)) request.result.createObjectStore(STAGING)
      }
      request.onerror = () => {
        reject(missing ? new Error('APPLICATION_DATA_STORAGE_MISSING') : request.error ?? new Error('INDEXEDDB_STORE_OPEN_FAILED'))
      }
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

  getMany(keys: readonly string[]): Promise<readonly (Uint8Array | null)[]> {
    const captured = [...keys]
    if (captured.length > 128) return Promise.reject(new Error('BYTES_STORE_BATCH_LIMIT'))
    for (const key of captured) assertRecordKey(key)
    return this.#enqueue(async () => {
      const raw = await this.#transaction('readonly', table => {
        const requests = captured.map(key => table.get(key))
        return () => requests.map(request => request.result as unknown)
      })
      return Promise.all(raw.map(async (value, index) => {
        if (value === undefined) return null
        if (!(value instanceof Uint8Array) || value.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('INDEXEDDB_VALUE_CORRUPT')
        return decodeRecordValue(captured[index]!, value, 'INDEXEDDB_VALUE_CORRUPT')
      }))
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

  async putAllIfEmpty(entries: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<boolean> {
    const captured = entries.map(entry => ({ key: entry.key, value: entry.value.slice() }))
    const seen = new Set<string>()
    for (const entry of captured) {
      assertRecordKey(entry.key)
      if (entry.value.length > MAX_RECORD_VALUE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
      if (seen.has(entry.key)) throw new Error('BYTES_STORE_DUPLICATE_KEY')
      seen.add(entry.key)
    }
    return this.#enqueue(async () => {
      const encoded: { key: string; value: Uint8Array }[] = []
      for (const entry of captured) encoded.push({ key: entry.key, value: await encodeRecordValue(entry.key, entry.value) })
      return this.#transaction('readwrite', table => {
        let initialized = false
        const count = table.count()
        count.onsuccess = () => {
          if (count.result !== 0) return
          for (const entry of encoded) table.add(entry.value, entry.key)
          initialized = true
        }
        return () => initialized
      })
    })
  }
  async *iterateEntries(): AsyncIterable<BytesStoreEntry> {
    // The storage contract has one mutation owner. Hold its queue across pages
    // so neither caller backpressure nor async hashing permits an interleaved put.
    let release!: () => void, started!: () => void
    const held = new Promise<void>(resolve => { release = resolve }), ready = new Promise<void>(resolve => { started = resolve })
    const owner = this.#enqueue(async () => { started(); await held })
    await Promise.race([ready, owner])
    try {
      let after: string | undefined
      for (;;) {
        const items = await this.#transaction('readonly', table => {
          const entries: { key: string; value: Uint8Array }[] = []
          let failure: Error | undefined, bytes = 0
          const request = table.openCursor(after === undefined ? undefined : IDBKeyRange.lowerBound(after, true))
          request.onsuccess = () => {
            const cursor = request.result
            if (cursor === null) return
            const key = cursor.key, raw: unknown = cursor.value
            if (typeof key !== 'string' || !(raw instanceof Uint8Array) || raw.length > MAX_RECORD_ENVELOPE_BYTES) {
              failure = new Error('INDEXEDDB_VALUE_CORRUPT'); return
            }
            entries.push({ key, value: raw }); bytes += raw.length
            if (entries.length < 64 && bytes < 1024 * 1024) cursor.continue()
          }
          return () => { if (failure !== undefined) throw failure; return entries }
        })
        if (items.length === 0) break
        for (const entry of items) {
          after = entry.key
          yield { key: entry.key, value: await decodeRecordValue(entry.key, entry.value, 'INDEXEDDB_VALUE_CORRUPT') }
        }
      }
    } finally { release(); await owner }
  }
  async entries(): Promise<readonly BytesStoreEntry[]> {
    const entries: BytesStoreEntry[] = []
    for await (const entry of this.iterateEntries()) entries.push(entry)
    return entries.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  }
  putStreamIfEmpty(entries: AsyncIterable<BytesStoreEntry>): Promise<boolean> {
    return this.#enqueue(async () => {
      const empty = await this.#transaction('readonly', table => { const count = table.count(); return () => count.result === 0 })
      if (!empty) return false
      const clear = () => this.#transaction('readwrite', table => { table.clear(); return () => undefined }, STAGING)
      await clear()
      try {
        for await (const entry of entries) {
          assertRecordKey(entry.key)
          const raw = await encodeRecordValue(entry.key, entry.value)
          await this.#transaction('readwrite', table => { table.add(raw, entry.key); return () => undefined }, STAGING)
        }
        // Staged envelopes stay on disk until the authenticated input ends.
        // Publish them in one IDB transaction, including the empty-store check.
        return await new Promise<boolean>((resolve, reject) => {
          const tx = this.#database.transaction([TABLE, STAGING], 'readwrite', { durability: 'strict' })
          const table = tx.objectStore(TABLE), staging = tx.objectStore(STAGING)
          let initialized = false
          const count = table.count()
          count.onsuccess = () => {
            if (count.result !== 0) return
            initialized = true
            const cursor = staging.openCursor()
            cursor.onsuccess = () => {
              const entry = cursor.result
              if (entry === null) { staging.clear(); return }
              table.add(entry.value, entry.key); entry.continue()
            }
          }
          tx.oncomplete = () => resolve(initialized)
          tx.onabort = () => reject(tx.error ?? new Error('INDEXEDDB_RESTORE_FAILED'))
        })
      } finally { await clear() }
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

  #transaction<T>(mode: IDBTransactionMode, enqueue: (table: IDBObjectStore) => () => T, name = TABLE): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction
      try { transaction = this.#database.transaction(name, mode, { durability: 'strict' }) }
      catch (error) { reject(error); return }
      let value: () => T
      try { value = enqueue(transaction.objectStore(name)) }
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

/**
 * Read-only existence inspection for a data database whose metadata/pin may
 * have been erased. Abort the version-0 upgrade rather than creating a
 * replacement; callers must fail closed when an orphaned data DB exists.
 */
export function inspectExistingIndexedDbRecords(name: string): Promise<boolean> {
  if (typeof indexedDB === 'undefined') return Promise.resolve(false)
  // Safari 17 and Chromium support enumeration. Prefer it: an OPFS-only
  // first data use must not open a second IndexedDB database, and no
  // versionchange transaction is needed to detect an orphaned journal.
  if (typeof indexedDB.databases === 'function') {
    return indexedDB.databases().then(databases =>
      databases.some(database => database.name === 'chronolog-data:' + name))
  }
  // Older IDB engines lack enumeration. Abort their version-0 open before
  // creating any new database, instead of taking absence as proof.
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('chronolog-data:' + name)
    let absent = false
    request.onupgradeneeded = event => {
      if (event.oldVersion === 0) {
        absent = true
        request.transaction?.abort()
      }
    }
    request.onerror = () => {
      if (absent && request.error?.name === 'AbortError') resolve(false)
      else reject(request.error ?? new Error('INDEXEDDB_INSPECTION_FAILED'))
    }
    request.onblocked = () => { reject(new Error('INDEXEDDB_INSPECTION_BLOCKED')) }
    request.onsuccess = () => {
      request.result.close()
      resolve(true)
    }
  })
}

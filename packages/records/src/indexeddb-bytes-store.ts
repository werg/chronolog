import type { BytesStore, BytesStoreChange, BytesStoreEntry, BytesStoreWriteOptions } from './bytes-store.js'
import {
  assertRecordKey,
  decodeRecordValueSync,
  encodeRecordValueSync,
  MAX_RECORD_ENVELOPE_BYTES,
  MAX_RECORD_VALUE_BYTES,
} from './record-envelope.js'

const TABLE = 'values'
const STAGING = 'checkpoint-staging'
const CHANGELOG = 'changelog'
const VERSION = 3

/** Multi-tab ACID IndexedDB BytesStore with atomic delta changelog and configurable durability. */
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
        if (!request.result.objectStoreNames.contains(CHANGELOG)) {
          request.result.createObjectStore(CHANGELOG, { autoIncrement: true })
        }
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
      const raw = await this.#readTx(TABLE, table => {
        const request = table.get(key)
        return () => request.result as unknown
      })
      if (raw === undefined) return null
      if (!(raw instanceof Uint8Array) || raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('INDEXEDDB_VALUE_CORRUPT')
      return decodeRecordValueSync(key, raw, 'INDEXEDDB_VALUE_CORRUPT')
    })
  }

  getMany(keys: readonly string[]): Promise<readonly (Uint8Array | null)[]> {
    const captured = [...keys]
    if (captured.length > 128) return Promise.reject(new Error('BYTES_STORE_BATCH_LIMIT'))
    for (const key of captured) assertRecordKey(key)
    return this.#enqueue(async () => {
      const raw = await this.#readTx(TABLE, table => {
        const requests = captured.map(key => table.get(key))
        return () => requests.map(request => request.result as unknown)
      })
      return raw.map((value, index) => {
        if (value === undefined) return null
        if (!(value instanceof Uint8Array) || value.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('INDEXEDDB_VALUE_CORRUPT')
        return decodeRecordValueSync(captured[index]!, value, 'INDEXEDDB_VALUE_CORRUPT')
      })
    })
  }

  async put(key: string, input: Uint8Array, options?: BytesStoreWriteOptions): Promise<void> {
    assertRecordKey(key)
    if (input.length > MAX_RECORD_VALUE_BYTES) return Promise.reject(new Error('BYTES_STORE_VALUE_LIMIT'))
    const raw = encodeRecordValueSync(key, input)
    const durability = options?.durability ?? 'relaxed'
    return this.#enqueue(async () => {
      await this.#writeTx([TABLE, CHANGELOG], durability, tx => {
        tx.objectStore(TABLE).put(raw, key)
        tx.objectStore(CHANGELOG).add({ key, deleted: false })
        return () => undefined
      })
    })
  }

  async putMany(entries: readonly BytesStoreEntry[], options?: BytesStoreWriteOptions): Promise<void> {
    if (entries.length === 0) return
    if (entries.length > 128) return Promise.reject(new Error('BYTES_STORE_BATCH_LIMIT'))
    const encoded: { key: string; value: Uint8Array }[] = []
    const seen = new Map<string, number>()
    for (const entry of entries) {
      assertRecordKey(entry.key)
      if (entry.value.length > MAX_RECORD_VALUE_BYTES) return Promise.reject(new Error('BYTES_STORE_VALUE_LIMIT'))
      const raw = encodeRecordValueSync(entry.key, entry.value)
      const prevIdx = seen.get(entry.key)
      if (prevIdx !== undefined) {
        encoded[prevIdx] = { key: entry.key, value: raw }
      } else {
        seen.set(entry.key, encoded.length)
        encoded.push({ key: entry.key, value: raw })
      }
    }
    const durability = options?.durability ?? 'relaxed'
    return this.#enqueue(async () => {
      await this.#writeTx([TABLE, CHANGELOG], durability, tx => {
        const table = tx.objectStore(TABLE)
        const log = tx.objectStore(CHANGELOG)
        for (const entry of encoded) {
          table.put(entry.value, entry.key)
          log.add({ key: entry.key, deleted: false })
        }
        return () => undefined
      })
    })
  }

  async delete(key: string, options?: BytesStoreWriteOptions): Promise<void> {
    assertRecordKey(key)
    const durability = options?.durability ?? 'relaxed'
    return this.#enqueue(() => this.#writeTx([TABLE, CHANGELOG], durability, tx => {
      tx.objectStore(TABLE).delete(key)
      tx.objectStore(CHANGELOG).add({ key, deleted: true })
      return () => undefined
    }))
  }

  async deleteMany(keys: readonly string[], options?: BytesStoreWriteOptions): Promise<void> {
    if (keys.length === 0) return
    const unique = [...new Set(keys)]
    for (const key of unique) assertRecordKey(key)
    const durability = options?.durability ?? 'relaxed'
    return this.#enqueue(async () => {
      for (let i = 0; i < unique.length; i += 128) {
        const chunk = unique.slice(i, i + 128)
        await this.#writeTx([TABLE, CHANGELOG], durability, tx => {
          const table = tx.objectStore(TABLE)
          const log = tx.objectStore(CHANGELOG)
          for (const key of chunk) {
            table.delete(key)
            log.add({ key, deleted: true })
          }
          return () => undefined
        })
      }
    })
  }

  async putAllIfEmpty(entries: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<boolean> {
    const encoded: { key: string; value: Uint8Array }[] = []
    const seen = new Set<string>()
    for (const entry of entries) {
      assertRecordKey(entry.key)
      if (entry.value.length > MAX_RECORD_VALUE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
      if (seen.has(entry.key)) throw new Error('BYTES_STORE_DUPLICATE_KEY')
      seen.add(entry.key)
      encoded.push({ key: entry.key, value: encodeRecordValueSync(entry.key, entry.value) })
    }
    return this.#enqueue(() => this.#writeTx([TABLE, CHANGELOG], 'strict', tx => {
      const table = tx.objectStore(TABLE)
      const log = tx.objectStore(CHANGELOG)
      let initialized = false
      const count = table.count()
      count.onsuccess = () => {
        if (count.result !== 0) return
        for (const entry of encoded) {
          table.add(entry.value, entry.key)
          log.add({ key: entry.key, deleted: false })
        }
        initialized = true
      }
      return () => initialized
    }))
  }

  async *iteratePrefix(prefix: string): AsyncIterable<BytesStoreEntry> {
    const upper = prefix + '\uffff'
    let after: string | undefined
    for (;;) {
      const items = await this.#enqueue(() => this.#readTx(TABLE, table => {
        const entries: { key: string; value: Uint8Array }[] = []
        let failure: Error | undefined, bytes = 0
        const range = after === undefined
          ? IDBKeyRange.bound(prefix, upper, false, true)
          : IDBKeyRange.bound(after, upper, true, true)
        const request = table.openCursor(range)
        request.onsuccess = () => {
          const cursor = request.result
          if (cursor === null) return
          const key = cursor.key, raw: unknown = cursor.value
          if (typeof key !== 'string' || !(raw instanceof Uint8Array) || raw.length > MAX_RECORD_ENVELOPE_BYTES) {
            failure = new Error('INDEXEDDB_VALUE_CORRUPT'); return
          }
          entries.push({ key, value: raw }); bytes += raw.length
          if (entries.length < 128 && bytes < 2 * 1024 * 1024) cursor.continue()
        }
        return () => { if (failure !== undefined) throw failure; return entries }
      }))
      if (items.length === 0) break
      for (const entry of items) {
        after = entry.key
        yield { key: entry.key, value: decodeRecordValueSync(entry.key, entry.value, 'INDEXEDDB_VALUE_CORRUPT') }
      }
    }
  }

  async *iterateEntries(): AsyncIterable<BytesStoreEntry> {
    let release!: () => void, started!: () => void
    const held = new Promise<void>(resolve => { release = resolve }), ready = new Promise<void>(resolve => { started = resolve })
    const owner = this.#enqueue(async () => { started(); await held })
    await Promise.race([ready, owner])
    try {
      let after: string | undefined
      for (;;) {
        const items = await this.#readTx(TABLE, table => {
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
            if (entries.length < 128 && bytes < 2 * 1024 * 1024) cursor.continue()
          }
          return () => { if (failure !== undefined) throw failure; return entries }
        })
        if (items.length === 0) break
        for (const entry of items) {
          after = entry.key
          yield { key: entry.key, value: decodeRecordValueSync(entry.key, entry.value, 'INDEXEDDB_VALUE_CORRUPT') }
        }
      }
    } finally { release(); await owner }
  }

  async latestChangeSeq(): Promise<number> {
    return this.#enqueue(() => this.#readTx(CHANGELOG, log => {
      let latest = 0
      const req = log.openKeyCursor(null, 'prev')
      req.onsuccess = () => {
        const cursor = req.result
        if (cursor !== null && typeof cursor.key === 'number') latest = cursor.key
      }
      return () => latest
    }))
  }

  async readChangesSince(afterSeq: number): Promise<{ readonly latestSeq: number; readonly changes: readonly BytesStoreChange[] }> {
    return this.#enqueue(() => this.#readTx(CHANGELOG, log => {
      const changes: BytesStoreChange[] = []
      let latestSeq = afterSeq
      const range = afterSeq > 0 ? IDBKeyRange.lowerBound(afterSeq, true) : undefined
      const req = log.openCursor(range)
      req.onsuccess = () => {
        const cursor = req.result
        if (cursor === null) return
        const seq = typeof cursor.key === 'number' ? cursor.key : 0
        const val = cursor.value as { readonly key?: unknown; readonly deleted?: unknown } | undefined
        if (seq > latestSeq) latestSeq = seq
        if (val && typeof val.key === 'string') {
          changes.push({ seq, key: val.key, deleted: val.deleted === true })
        }
        if (changes.length < 4096) cursor.continue()
      }
      return () => ({ latestSeq, changes })
    }))
  }

  async entries(): Promise<readonly BytesStoreEntry[]> {
    const entries: BytesStoreEntry[] = []
    for await (const entry of this.iterateEntries()) entries.push(entry)
    return entries.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  }

  putStreamIfEmpty(entries: AsyncIterable<BytesStoreEntry>): Promise<boolean> {
    return this.#enqueue(async () => {
      const empty = await this.#readTx(TABLE, table => { const count = table.count(); return () => count.result === 0 })
      if (!empty) return false
      const clear = () => this.#writeTx([STAGING], 'relaxed', tx => { tx.objectStore(STAGING).clear(); return () => undefined })
      await clear()
      try {
        for await (const entry of entries) {
          assertRecordKey(entry.key)
          const raw = encodeRecordValueSync(entry.key, entry.value)
          await this.#writeTx([STAGING], 'relaxed', tx => { tx.objectStore(STAGING).add(raw, entry.key); return () => undefined })
        }
        return await this.#writeTx([TABLE, STAGING, CHANGELOG], 'strict', tx => {
          const table = tx.objectStore(TABLE), staging = tx.objectStore(STAGING), log = tx.objectStore(CHANGELOG)
          let initialized = false
          const count = table.count()
          count.onsuccess = () => {
            if (count.result !== 0) return
            initialized = true
            const cursor = staging.openCursor()
            cursor.onsuccess = () => {
              const entry = cursor.result
              if (entry === null) { staging.clear(); return }
              table.add(entry.value, entry.key)
              if (typeof entry.key === 'string') log.add({ key: entry.key, deleted: false })
              entry.continue()
            }
          }
          return () => initialized
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

  #readTx<T>(storeName: string, enqueue: (table: IDBObjectStore) => () => T): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction
      try { transaction = this.#database.transaction(storeName, 'readonly') }
      catch (error) { reject(error); return }
      let value: () => T
      try { value = enqueue(transaction.objectStore(storeName)) }
      catch (error) {
        try { transaction.abort() } catch { /* Preserve the original request failure. */ }
        reject(error); return
      }
      transaction.oncomplete = () => { try { resolve(value()) } catch (error) { reject(error) } }
      transaction.onabort = () => { reject(transaction.error ?? new Error('INDEXEDDB_TRANSACTION_ABORTED')) }
      transaction.onerror = () => { /* The abort event carries the transaction failure. */ }
    })
  }

  #writeTx<T>(storeNames: readonly string[], durability: 'strict' | 'relaxed', enqueue: (tx: IDBTransaction) => () => T): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction
      try { transaction = this.#database.transaction([...storeNames], 'readwrite', { durability }) }
      catch (error) { reject(error); return }
      let value: () => T
      try { value = enqueue(transaction) }
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

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
/** Holds the pruned changelog floor and one acknowledged-seq cursor per reading store instance (tab). */
const CHANGELOG_META = 'changelog-meta'
const FLOOR_KEY = 'floor'
const CURSOR_PREFIX = 'cursor:'
const VERSION = 4
const DEFAULT_CHANGELOG_WINDOW = 65_536
const DEFAULT_CURSOR_TTL_MS = 24 * 60 * 60 * 1000

export interface IndexedDbBytesStoreOpenOptions {
  /** Fail with APPLICATION_DATA_STORAGE_MISSING instead of creating a fresh database. */
  readonly create?: boolean
  /** Maximum changelog entries retained behind the latest seq, even when a tab has not acknowledged them. */
  readonly changelogWindow?: number
  /** A tab cursor that has not polled `readChangesSince` for this long no longer holds back pruning. */
  readonly cursorTtlMs?: number
}

/** `readChangesSince` result; `reset` means the cursor fell below the pruned floor and the caller must fully rescan. */
export interface IndexedDbChangesResult {
  readonly latestSeq: number
  readonly changes: readonly BytesStoreChange[]
  readonly reset: boolean
}

/**
 * Multi-tab ACID IndexedDB BytesStore with atomic delta changelog and configurable durability.
 *
 * The changelog is pruned on every `readChangesSince` call: entries at or below
 * the minimum seq acknowledged by every live reading tab are deleted, and the
 * log never retains more than `changelogWindow` entries behind the latest seq.
 * A reader whose cursor fell below the pruned floor (window overflow, or a tab
 * frozen past `cursorTtlMs`) receives `reset: true` with no changes and must
 * rescan the store instead of applying deltas.
 */
export class IndexedDbBytesStore implements BytesStore {
  readonly #database: IDBDatabase
  readonly #cursorKey = CURSOR_PREFIX + crypto.randomUUID()
  readonly #changelogWindow: number
  readonly #cursorTtlMs: number
  #cursorRegistered = false
  #pending: Promise<void> = Promise.resolve()
  #closing: Promise<void> | undefined
  #closed = false
  #invalid: Error | undefined

  private constructor(database: IDBDatabase, changelogWindow: number, cursorTtlMs: number) {
    this.#database = database
    this.#changelogWindow = changelogWindow
    this.#cursorTtlMs = cursorTtlMs
    database.onversionchange = () => {
      this.#invalid = new Error('INDEXEDDB_STORE_VERSION_CHANGED')
      database.close()
    }
  }

  static open(name: string, {
    create = true, changelogWindow = DEFAULT_CHANGELOG_WINDOW, cursorTtlMs = DEFAULT_CURSOR_TTL_MS,
  }: IndexedDbBytesStoreOpenOptions = {}): Promise<IndexedDbBytesStore> {
    if (typeof indexedDB === 'undefined') return Promise.reject(new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED'))
    if (!Number.isSafeInteger(changelogWindow) || changelogWindow < 1 || !Number.isSafeInteger(cursorTtlMs) || cursorTtlMs < 0)
      return Promise.reject(new Error('INDEXEDDB_STORE_OPTIONS_INVALID'))
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
        if (!request.result.objectStoreNames.contains(CHANGELOG_META)) request.result.createObjectStore(CHANGELOG_META)
      }
      request.onerror = () => {
        reject(missing ? new Error('APPLICATION_DATA_STORAGE_MISSING') : request.error ?? new Error('INDEXEDDB_STORE_OPEN_FAILED'))
      }
      request.onblocked = () => { blocked = true; reject(new Error('INDEXEDDB_STORE_BLOCKED')) }
      request.onsuccess = () => {
        if (blocked) request.result.close()
        else resolve(new IndexedDbBytesStore(request.result, changelogWindow, cursorTtlMs))
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
          if (entries.length < 1024 && bytes < 8 * 1024 * 1024) cursor.continue()
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
            if (entries.length < 1024 && bytes < 8 * 1024 * 1024) cursor.continue()
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

  /** Latest assigned change seq; never below the pruned floor, even when the whole changelog was pruned. */
  async latestChangeSeq(): Promise<number> {
    return this.#enqueue(() => this.#readTx([CHANGELOG, CHANGELOG_META], tx => {
      let latest = 0
      const floor = tx.objectStore(CHANGELOG_META).get(FLOOR_KEY)
      const req = tx.objectStore(CHANGELOG).openKeyCursor(null, 'prev')
      req.onsuccess = () => {
        const cursor = req.result
        if (cursor !== null && typeof cursor.key === 'number') latest = cursor.key
      }
      return () => Math.max(latest, floorValue(floor.result))
    }))
  }

  /**
   * Read up to 4096 changes after `afterSeq`, acknowledge `afterSeq` for this
   * store instance, and prune entries every live reader has acknowledged (or
   * that fell outside the retention window). Returns `reset: true` when
   * `afterSeq` is below the pruned floor: deltas were lost and the caller must
   * rescan, then resume from `latestSeq`.
   */
  async readChangesSince(afterSeq: number): Promise<IndexedDbChangesResult> {
    if (!Number.isSafeInteger(afterSeq) || afterSeq < 0) return Promise.reject(new Error('BYTES_STORE_SEQ_INVALID'))
    const now = Date.now(), window = this.#changelogWindow, ttl = this.#cursorTtlMs, cursorKey = this.#cursorKey
    this.#cursorRegistered = true
    return this.#enqueue(() => this.#writeTx([CHANGELOG, CHANGELOG_META], 'relaxed', tx => {
      const log = tx.objectStore(CHANGELOG), meta = tx.objectStore(CHANGELOG_META)
      const changes: BytesStoreChange[] = []
      let result: IndexedDbChangesResult | undefined
      const floorRequest = meta.get(FLOOR_KEY)
      floorRequest.onsuccess = () => {
        const floor = floorValue(floorRequest.result)
        const last = log.openKeyCursor(null, 'prev')
        last.onsuccess = () => {
          const lastKey = last.result?.key
          const latest = Math.max(floor, typeof lastKey === 'number' ? lastKey : 0)
          if (afterSeq < floor) {
            // The deltas between afterSeq and floor are gone; after its rescan this reader is at `latest`.
            meta.put({ seq: latest, at: now }, cursorKey)
            result = { latestSeq: latest, changes, reset: true }
            return
          }
          let latestSeq = afterSeq
          const req = log.openCursor(IDBKeyRange.lowerBound(afterSeq, true))
          req.onsuccess = () => {
            const cursor = req.result
            if (cursor !== null) {
              const seq = typeof cursor.key === 'number' ? cursor.key : 0
              const val = cursor.value as { readonly key?: unknown; readonly deleted?: unknown } | undefined
              if (seq > latestSeq) latestSeq = seq
              if (val && typeof val.key === 'string') changes.push({ seq, key: val.key, deleted: val.deleted === true })
              if (changes.length < 4096) { cursor.continue(); return }
            }
            result = { latestSeq, changes, reset: false }
            meta.put({ seq: afterSeq, at: now }, cursorKey)
            prune(floor, latest)
          }
        }
      }
      const prune = (floor: number, latest: number): void => {
        let minAck = latest
        const cursors = meta.openCursor(IDBKeyRange.bound(CURSOR_PREFIX, CURSOR_PREFIX + '\uffff'))
        cursors.onsuccess = () => {
          const cursor = cursors.result
          if (cursor !== null) {
            const value = cursor.value as { readonly seq?: unknown; readonly at?: unknown } | undefined
            const seq = value?.seq, at = value?.at
            if (typeof seq !== 'number' || typeof at !== 'number' || at < now - ttl) cursor.delete()
            else if (seq < minAck) minAck = seq
            cursor.continue()
            return
          }
          const target = Math.min(latest, Math.max(minAck, latest - window))
          if (target <= floor) return
          log.delete(IDBKeyRange.upperBound(target))
          meta.put(target, FLOOR_KEY)
        }
      }
      return () => {
        if (result === undefined) throw new Error('INDEXEDDB_CHANGELOG_READ_FAILED')
        return result
      }
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
    this.#closing = this.#pending.then(async () => {
      // Release this tab's changelog cursor so it no longer holds back pruning.
      if (this.#cursorRegistered && this.#invalid === undefined) {
        try {
          await this.#writeTx([CHANGELOG_META], 'relaxed', tx => {
            tx.objectStore(CHANGELOG_META).delete(this.#cursorKey); return () => undefined
          })
        } catch { /* An expired cursor is evicted by the TTL instead. */ }
      }
      this.#database.close()
    })
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

  #readTx<T>(storeName: string, enqueue: (table: IDBObjectStore) => () => T): Promise<T>
  #readTx<T>(storeNames: readonly string[], enqueue: (tx: IDBTransaction) => () => T): Promise<T>
  #readTx<T>(storeNames: string | readonly string[], enqueue: ((table: IDBObjectStore) => () => T) | ((tx: IDBTransaction) => () => T)): Promise<T> {
    return new Promise((resolve, reject) => {
      let transaction: IDBTransaction
      try { transaction = this.#database.transaction(typeof storeNames === 'string' ? storeNames : [...storeNames], 'readonly') }
      catch (error) { reject(error); return }
      let value: () => T
      try {
        value = typeof storeNames === 'string'
          ? (enqueue as (table: IDBObjectStore) => () => T)(transaction.objectStore(storeNames))
          : (enqueue as (tx: IDBTransaction) => () => T)(transaction)
      }
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

function floorValue(value: unknown): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : 0
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

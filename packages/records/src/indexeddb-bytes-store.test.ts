import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IndexedDbBytesStore } from './indexeddb-bytes-store.js'

// Minimal in-memory IndexedDB covering exactly the surface IndexedDbBytesStore
// uses (fake-indexeddb is not a workspace dependency). Transactions run one at
// a time, requests execute asynchronously in FIFO order, and abort restores the
// scoped stores, which is enough to model several tabs sharing one database.

type Key = number | string
const compare = (a: Key, b: Key): number =>
  typeof a !== typeof b ? (typeof a === 'number' ? -1 : 1) : a < b ? -1 : a > b ? 1 : 0

class FakeKeyRange {
  constructor(readonly lower?: Key, readonly upper?: Key, readonly lowerOpen = false, readonly upperOpen = false) {}
  includes(key: Key): boolean {
    if (this.lower !== undefined) { const c = compare(key, this.lower); if (c < 0 || (c === 0 && this.lowerOpen)) return false }
    if (this.upper !== undefined) { const c = compare(key, this.upper); if (c > 0 || (c === 0 && this.upperOpen)) return false }
    return true
  }
  static bound(l: Key, u: Key, lo = false, uo = false) { return new FakeKeyRange(l, u, lo, uo) }
  static lowerBound(l: Key, open = false) { return new FakeKeyRange(l, undefined, open) }
  static upperBound(u: Key, open = false) { return new FakeKeyRange(undefined, u, false, open) }
}

interface StoreData { rows: Map<Key, unknown>; autoIncrement: boolean; next: number }
interface DbData { version: number; stores: Map<string, StoreData> }
const databases = new Map<string, DbData>()
let lock: Promise<void> = Promise.resolve()

class FakeRequest {
  result: unknown; error: unknown = null
  onsuccess: (() => void) | null = null
  onerror: (() => void) | null = null
}

class FakeTransaction {
  readonly #queue: Array<() => void> = []
  #aborted = false
  error: unknown = null
  oncomplete: (() => void) | null = null
  onabort: (() => void) | null = null
  onerror: (() => void) | null = null
  constructor(readonly db: DbData, readonly names: readonly string[]) {
    lock = lock.then(() => new Promise<void>(release => { setTimeout(() => { this.#run(release) }, 0) }))
  }
  #run(release: () => void): void {
    const snapshot = new Map(this.names.map(name => {
      const store = this.db.stores.get(name)!
      return [name, { rows: new Map(store.rows), next: store.next }] as const
    }))
    while (this.#queue.length > 0 && !this.#aborted) this.#queue.shift()!()
    if (this.#aborted) {
      for (const [name, saved] of snapshot) Object.assign(this.db.stores.get(name)!, saved)
      this.onabort?.()
    } else this.oncomplete?.()
    release()
  }
  request(exec: () => unknown): FakeRequest {
    const request = new FakeRequest()
    this.#queue.push(() => {
      try { request.result = exec(); request.onsuccess?.() }
      catch (error) { request.error = error; this.error = error; this.abort() }
    })
    return request
  }
  requeue(step: () => void): void { this.#queue.push(step) }
  abort(): void { this.#aborted = true; this.error ??= new DOMException('aborted', 'AbortError') }
  objectStore(name: string): FakeObjectStore {
    if (!this.names.includes(name)) throw new DOMException(name, 'NotFoundError')
    return new FakeObjectStore(this, this.db.stores.get(name)!)
  }
}

class FakeObjectStore {
  constructor(readonly tx: FakeTransaction, readonly data: StoreData) {}
  get(key: Key) { return this.tx.request(() => this.data.rows.get(key)) }
  count() { return this.tx.request(() => this.data.rows.size) }
  clear() { return this.tx.request(() => { this.data.rows.clear() }) }
  put(value: unknown, key: Key) {
    return this.tx.request(() => {
      this.data.rows.set(key, structuredClone(value))
      if (this.data.autoIncrement && typeof key === 'number') this.data.next = Math.max(this.data.next, key + 1)
      return key
    })
  }
  add(value: unknown, key?: Key) {
    return this.tx.request(() => {
      const k = key ?? this.data.next++
      if (this.data.rows.has(k)) throw new DOMException('exists', 'ConstraintError')
      this.data.rows.set(k, structuredClone(value))
      return k
    })
  }
  delete(target: Key | FakeKeyRange) {
    return this.tx.request(() => {
      for (const key of [...this.data.rows.keys()]) {
        if (target instanceof FakeKeyRange ? target.includes(key) : key === target) this.data.rows.delete(key)
      }
    })
  }
  openCursor(range?: FakeKeyRange | null, direction: 'next' | 'prev' = 'next') { return this.#cursor(range, direction) }
  openKeyCursor(range?: FakeKeyRange | null, direction: 'next' | 'prev' = 'next') { return this.#cursor(range, direction) }
  #cursor(range: FakeKeyRange | null | undefined, direction: 'next' | 'prev'): FakeRequest {
    let current: Key | undefined
    const advance = (): unknown => {
      const keys = [...this.data.rows.keys()]
        .filter(key => (range ?? new FakeKeyRange()).includes(key))
        .filter(key => current === undefined || (direction === 'next' ? compare(key, current) > 0 : compare(key, current) < 0))
        .sort((a, b) => direction === 'next' ? compare(a, b) : compare(b, a))
      if (keys.length === 0) return null
      current = keys[0]!
      const key = current
      return {
        key, value: this.data.rows.get(key),
        continue: () => { this.tx.requeue(() => { request.result = advance(); request.onsuccess?.() }) },
        delete: () => this.tx.request(() => { this.data.rows.delete(key) }),
      }
    }
    const request = this.tx.request(advance)
    return request
  }
}

class FakeDatabase {
  onversionchange: (() => void) | null = null
  constructor(readonly data: DbData) {}
  get objectStoreNames() { return { contains: (name: string) => this.data.stores.has(name) } }
  createObjectStore(name: string, options: { autoIncrement?: boolean } = {}) {
    this.data.stores.set(name, { rows: new Map(), autoIncrement: options.autoIncrement === true, next: 1 })
  }
  transaction(names: string | readonly string[]) {
    const list = typeof names === 'string' ? [names] : [...names]
    for (const name of list) if (!this.data.stores.has(name)) throw new DOMException(name, 'NotFoundError')
    return new FakeTransaction(this.data, list)
  }
  close(): void { /* nothing to release */ }
}

const fakeIndexedDb = {
  open(name: string, version: number) {
    const request = Object.assign(new FakeRequest(), {
      onupgradeneeded: null as ((event: { oldVersion: number }) => void) | null,
      onblocked: null as (() => void) | null,
      transaction: null as { abort(): void } | null,
    })
    setTimeout(() => {
      const existing = databases.get(name)
      const data: DbData = existing ?? { version: 0, stores: new Map() }
      request.result = new FakeDatabase(data)
      if (version > data.version) {
        let aborted = false
        request.transaction = { abort: () => { aborted = true } }
        request.onupgradeneeded?.({ oldVersion: data.version })
        if (aborted) { request.error = new DOMException('aborted', 'AbortError'); request.onerror?.(); return }
        data.version = version
        databases.set(name, data)
      }
      request.onsuccess?.()
    }, 0)
    return request
  },
}

const changelogRows = (name: string): number => databases.get('chronolog-data:' + name)!.stores.get('changelog')!.rows.size

describe('IndexedDbBytesStore changelog pruning', () => {
  let now = 1_000_000
  beforeEach(() => {
    databases.clear()
    vi.stubGlobal('indexedDB', fakeIndexedDb)
    vi.stubGlobal('IDBKeyRange', FakeKeyRange)
    vi.spyOn(Date, 'now').mockImplementation(() => now)
  })
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

  const bytes = (n: number) => Uint8Array.of(n)

  it('prunes entries every live tab acknowledged and keeps the latest seq', async () => {
    const a = await IndexedDbBytesStore.open('acked'), b = await IndexedDbBytesStore.open('acked')
    expect((await b.readChangesSince(0)).changes).toEqual([])
    await a.putMany([{ key: 'k1', value: bytes(1) }, { key: 'k2', value: bytes(2) }, { key: 'k3', value: bytes(3) }])
    const first = await a.readChangesSince(0)
    expect(first).toMatchObject({ latestSeq: 3, reset: false })
    expect(first.changes.map(change => change.key)).toEqual(['k1', 'k2', 'k3'])
    await a.readChangesSince(3)
    // b still acknowledges only seq 0, so nothing may be pruned yet.
    expect(changelogRows('acked')).toBe(3)
    const caughtUp = await b.readChangesSince(0)
    expect(caughtUp.changes.map(change => change.seq)).toEqual([1, 2, 3])
    await b.readChangesSince(3)
    expect(changelogRows('acked')).toBe(0)
    // A fully pruned changelog must not report seq 0 (which would replay as a reset).
    expect(await a.latestChangeSeq()).toBe(3)
    await a.put('k4', bytes(4))
    expect(await b.readChangesSince(3)).toEqual({ latestSeq: 4, changes: [{ seq: 4, key: 'k4', deleted: false }], reset: false })
    await a.close(); await b.close()
  })

  it('bounds retention and resets a reader whose cursor fell below the floor', async () => {
    const a = await IndexedDbBytesStore.open('window', { changelogWindow: 2 })
    const b = await IndexedDbBytesStore.open('window', { changelogWindow: 2 })
    await b.readChangesSince(0)
    for (let i = 1; i <= 5; i++) await a.put('k' + String(i), bytes(i))
    await a.readChangesSince(0)
    expect(changelogRows('window')).toBe(2)
    expect(await b.readChangesSince(0)).toEqual({ latestSeq: 5, changes: [], reset: true })
    expect(await b.readChangesSince(5)).toEqual({ latestSeq: 5, changes: [], reset: false })
    await a.close(); await b.close()
  })

  it('releases a closed tab cursor and evicts a cursor past its TTL', async () => {
    const a = await IndexedDbBytesStore.open('ttl', { cursorTtlMs: 1000 })
    const closed = await IndexedDbBytesStore.open('ttl', { cursorTtlMs: 1000 })
    const frozen = await IndexedDbBytesStore.open('ttl', { cursorTtlMs: 1000 })
    await closed.readChangesSince(0); await frozen.readChangesSince(0)
    await closed.close()
    for (let i = 1; i <= 3; i++) await a.put('k' + String(i), bytes(i))
    await a.readChangesSince(0); await a.readChangesSince(3)
    expect(changelogRows('ttl')).toBe(3)
    now += 1001
    await a.readChangesSince(3)
    expect(changelogRows('ttl')).toBe(0)
    expect(await frozen.readChangesSince(0)).toMatchObject({ latestSeq: 3, reset: true })
    await a.close(); await frozen.close()
  })

  it('rejects invalid cursors and retention options', async () => {
    const store = await IndexedDbBytesStore.open('invalid')
    await expect(store.readChangesSince(-1)).rejects.toThrow('BYTES_STORE_SEQ_INVALID')
    await expect(IndexedDbBytesStore.open('invalid', { changelogWindow: 0 })).rejects.toThrow('INDEXEDDB_STORE_OPTIONS_INVALID')
    await store.close()
  })
})

import { createRequire } from 'node:module'
import { Worker } from 'node:worker_threads'
import type { BytesStore, BytesStoreEntry } from './bytes-store.js'
import { nativeWorkerSource } from './native-worker.js'

export interface NativeBytesStoreOptions {
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}
interface Response { readonly id: number; readonly value?: unknown; readonly used: number; readonly error?: { readonly message: string; readonly code?: string } }

/** Stable SQLite in a dedicated worker. Await open() for acquisition and close() for release. */
export class NativeBytesStore implements BytesStore {
  readonly #worker: Worker
  readonly #requests = new Map<number, { resolve(value: unknown): void; reject(error: unknown): void }>()
  readonly #ready: Promise<void>
  readonly #maxValueBytes: number
  #pending: Promise<unknown> = Promise.resolve()
  #nextId = 0
  #usedBytes = 0
  #closed = false
  #closing: Promise<void> | undefined
  #failure: Error | undefined

  constructor(path: string, options: NativeBytesStoreOptions = {}) {
    if (path.length === 0) throw new Error('BYTES_STORE_PATH_REQUIRED')
    for (const value of [options.quotaBytes, options.maxValueBytes]) {
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) throw new Error('BYTES_STORE_QUOTA_INVALID')
    }
    this.#maxValueBytes = options.maxValueBytes ?? 128 * 1024 * 1024
    this.#worker = new Worker(nativeWorkerSource, { eval: true,
      workerData: { path, options, sqliteModule: createRequire(import.meta.url).resolve('better-sqlite3') } })
    this.#ready = new Promise((resolve, reject) => { this.#requests.set(0, { resolve: () => resolve(), reject }) })
    void this.#ready.catch(() => undefined)
    this.#worker.on('message', (response: Response) => {
      this.#usedBytes = response.used
      const request = this.#requests.get(response.id)
      this.#requests.delete(response.id)
      if (response.error === undefined) request?.resolve(response.value)
      else request?.reject(Object.assign(new Error(response.error.message), response.error.code === undefined ? {} : { code: response.error.code }))
      if (this.#requests.size === 0) this.#worker.unref()
    })
    this.#worker.on('error', (error: Error) => this.#fail(error))
    this.#worker.on('exit', code => { if (!this.#closed || this.#requests.size !== 0) this.#fail(new Error(`BYTES_STORE_WORKER_EXIT: ${code}`)) })
  }
  static async open(path: string, options: NativeBytesStoreOptions = {}): Promise<NativeBytesStore> {
    const store = new NativeBytesStore(path, options)
    try { await store.#ready; return store }
    catch (error) { await store.#worker.terminate(); throw error }
  }
  #fail(error: Error): void {
    this.#failure = error
    for (const request of this.#requests.values()) request.reject(error)
    this.#requests.clear()
  }
  async #request<T>(method: string, args: unknown = {}): Promise<T> {
    await this.#ready
    if (this.#failure !== undefined) throw this.#failure
    const id = ++this.#nextId
    return new Promise<T>((resolve, reject) => {
      this.#requests.set(id, { resolve: value => resolve(value as T), reject })
      this.#worker.ref()
      try { this.#worker.postMessage({ id, method, args }) }
      catch (error) { this.#requests.delete(id); if (this.#requests.size === 0) this.#worker.unref(); reject(error) }
    })
  }
  #enqueue<T>(work: () => Promise<T>): Promise<T> {
    if (this.#closed) return Promise.reject(new Error('BYTES_STORE_CLOSED'))
    const task = this.#pending.then(work)
    this.#pending = task.catch(() => undefined)
    return task
  }
  get(key: string): Promise<Uint8Array | null> { return this.#enqueue(() => this.#request('get', { key })) }
  getMany(keys: readonly string[]): Promise<readonly (Uint8Array | null)[]> {
    const captured = [...keys]
    return this.#enqueue(() => this.#request('getMany', { keys: captured }))
  }
  put(key: string, value: Uint8Array): Promise<void> {
    if (!(value instanceof Uint8Array) || value.length > this.#maxValueBytes) return Promise.reject(new Error('BYTES_STORE_VALUE_TOO_LARGE'))
    const copy = Uint8Array.from(value)
    return this.#enqueue(() => this.#request('put', { key, value: copy }))
  }
  delete(key: string): Promise<void> { return this.#enqueue(() => this.#request('delete', { key })) }
  async *iterateEntries(): AsyncIterable<BytesStoreEntry> {
    let release!: () => void, started!: () => void
    const held = new Promise<void>(resolve => { release = resolve }), ready = new Promise<void>(resolve => { started = resolve })
    const owner = this.#enqueue(async () => { started(); await held })
    await Promise.race([ready, owner])
    try {
      let after = ''
      for (;;) {
        const page = await this.#request<BytesStoreEntry[]>('page', { after })
        if (page.length === 0) break
        for (const entry of page) { after = entry.key; yield entry }
      }
    } finally { release(); await owner }
  }
  async entries(): Promise<readonly BytesStoreEntry[]> {
    const entries: BytesStoreEntry[] = []
    for await (const entry of this.iterateEntries()) entries.push(entry)
    return entries
  }
  putAllIfEmpty(entries: readonly BytesStoreEntry[]): Promise<boolean> {
    if (entries.some(entry => !(entry.value instanceof Uint8Array) || entry.value.length > this.#maxValueBytes)) return Promise.reject(new Error('BYTES_STORE_VALUE_TOO_LARGE'))
    const captured = entries.map(entry => ({ key: entry.key, value: Uint8Array.from(entry.value) }))
    return this.putStreamIfEmpty((async function* () { yield* captured })())
  }
  putStreamIfEmpty(entries: AsyncIterable<BytesStoreEntry>): Promise<boolean> {
    return this.#enqueue(async () => {
      if (!await this.#request<boolean>('restoreBegin')) return false
      try {
        for await (const entry of entries) await this.#request('restorePut', entry)
        await this.#request('restoreCommit')
        return true
      } catch (error) { await this.#request('restoreAbort'); throw error }
    })
  }
  checkpointWal(): Promise<void> { return this.#enqueue(() => this.#request('checkpoint')) }
  usageBytes(): number { if (this.#closed) throw new Error('BYTES_STORE_CLOSED'); return this.#usedBytes }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing
    this.#closed = true
    this.#closing = this.#pending.then(async () => {
      try { await this.#request('close') } finally { await this.#worker.terminate() }
    })
    return this.#closing
  }
}

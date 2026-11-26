import { Worker } from 'node:worker_threads'
import type { BytesStore, BytesStoreEntry } from './bytes-store.js'
import { nativeWorkerSource } from './native-worker.js'

export interface NativeBytesStoreOptions {
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}
interface Response { readonly id: number; readonly value?: unknown; readonly used: number; readonly error?: { readonly message: string; readonly code?: string } }
interface Reply { readonly value: unknown; readonly used: number }

/** Diagnostic view of the process-wide store pool. */
export interface NativeBytesStorePoolStatus {
  /** Worker thread serving every open store, or null when no store is open. */
  readonly threadId: number | null
  readonly stores: number
}

/**
 * One worker thread multiplexing every NativeBytesStore in the process by handle.
 * The worker starts with the first store and exits once the last store closes.
 */
class NativeStorePool {
  readonly worker: Worker
  readonly #requests = new Map<number, { resolve(reply: Reply): void; reject(error: unknown): void }>()
  readonly #ready: Promise<void>
  #nextId = 0
  #nextHandle = 0
  #stores = 0
  #terminating = false
  failure: Error | undefined

  constructor() {
    this.worker = new Worker(nativeWorkerSource, { eval: true })
    this.#ready = new Promise((resolve, reject) => { this.#requests.set(0, { resolve: () => resolve(), reject }) })
    void this.#ready.catch(() => undefined)
    this.worker.on('message', (response: Response) => {
      const request = this.#requests.get(response.id)
      this.#requests.delete(response.id)
      if (response.error === undefined) request?.resolve({ value: response.value, used: response.used })
      else request?.reject(Object.assign(new Error(response.error.message), response.error.code === undefined ? {} : { code: response.error.code }))
      if (this.#requests.size === 0) this.worker.unref()
    })
    this.worker.on('error', (error: Error) => this.#fail(error))
    this.worker.on('exit', code => { if (!this.#terminating || this.#requests.size !== 0) this.#fail(new Error(`BYTES_STORE_WORKER_EXIT: ${code}`)) })
  }
  get stores(): number { return this.#stores }
  acquire(): number { this.#stores++; return ++this.#nextHandle }
  release(): void {
    if (--this.#stores !== 0) return
    this.#terminating = true
    if (pool === this) pool = undefined
    void this.worker.terminate()
  }
  #fail(error: Error): void {
    this.failure ??= error
    if (pool === this) pool = undefined
    for (const request of this.#requests.values()) request.reject(error)
    this.#requests.clear()
  }
  async request(handle: number, method: string, args: unknown = {}): Promise<Reply> {
    await this.#ready
    if (this.failure !== undefined) throw this.failure
    const id = ++this.#nextId
    return new Promise<Reply>((resolve, reject) => {
      this.#requests.set(id, { resolve, reject })
      this.worker.ref()
      try { this.worker.postMessage({ id, handle, method, args }) }
      catch (error) { this.#requests.delete(id); if (this.#requests.size === 0) this.worker.unref(); reject(error) }
    })
  }
}
let pool: NativeStorePool | undefined

/**
 * Stable SQLite file served by the process-wide store pool worker.
 * Await open() for acquisition and close() for release; each store keeps its own file and exclusive lock.
 */
export class NativeBytesStore implements BytesStore {
  readonly #pool: NativeStorePool
  readonly #handle: number
  readonly #ready: Promise<void>
  readonly #maxValueBytes: number
  #pending: Promise<unknown> = Promise.resolve()
  #usedBytes = 0
  #closed = false
  #closing: Promise<void> | undefined

  constructor(path: string, options: NativeBytesStoreOptions = {}) {
    if (path.length === 0) throw new Error('BYTES_STORE_PATH_REQUIRED')
    for (const value of [options.quotaBytes, options.maxValueBytes]) {
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) throw new Error('BYTES_STORE_QUOTA_INVALID')
    }
    this.#maxValueBytes = options.maxValueBytes ?? 128 * 1024 * 1024
    const limits = {
      ...(options.quotaBytes === undefined ? {} : { quotaBytes: options.quotaBytes }),
      ...(options.maxValueBytes === undefined ? {} : { maxValueBytes: options.maxValueBytes }),
    }
    this.#pool = pool ??= new NativeStorePool()
    this.#handle = this.#pool.acquire()
    this.#ready = this.#pool.request(this.#handle, 'open', { path, options: limits }).then(
      reply => { this.#usedBytes = reply.used },
      error => { this.#pool.release(); throw error })
    void this.#ready.catch(() => undefined)
  }
  static async open(path: string, options: NativeBytesStoreOptions = {}): Promise<NativeBytesStore> {
    const store = new NativeBytesStore(path, options)
    await store.#ready
    return store
  }
  /** The shared worker and how many stores it currently serves. */
  static poolStatus(): NativeBytesStorePoolStatus {
    return Object.freeze({ threadId: pool?.worker.threadId ?? null, stores: pool?.stores ?? 0 })
  }
  async #request<T>(method: string, args: unknown = {}): Promise<T> {
    await this.#ready
    const reply = await this.#pool.request(this.#handle, method, args)
    this.#usedBytes = reply.used
    return reply.value as T
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
  putMany(entries: readonly BytesStoreEntry[]): Promise<void> {
    if (entries.length === 0) return Promise.resolve()
    if (entries.length > 128) return Promise.reject(new Error('BYTES_STORE_BATCH_LIMIT'))
    const captured: BytesStoreEntry[] = []
    for (const entry of entries) {
      if (!(entry.value instanceof Uint8Array) || entry.value.length > this.#maxValueBytes) return Promise.reject(new Error('BYTES_STORE_VALUE_TOO_LARGE'))
      captured.push({ key: entry.key, value: Uint8Array.from(entry.value) })
    }
    return this.#enqueue(() => this.#request('putMany', { entries: captured }))
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
      try { await this.#ready } catch { return }
      try { await this.#request('close') } finally { this.#pool.release() }
    })
    return this.#closing
  }
}

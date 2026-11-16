import { assertEventTopic, type EffectiveEvent, type EventBatch, type EventReadOptions } from '@chronolog/protocol'

export interface ProjectionIdentity {
  readonly groupId: string
  readonly historyId: string
  readonly filterVersion: string
  readonly reducerVersion: string
}

export interface ProjectionCheckpoint<State> {
  readonly version: 1
  readonly generation: number
  readonly identity: ProjectionIdentity
  readonly topics: readonly string[] | null
  readonly cursor: string
  readonly revision: string
  readonly state: State
}

/** One atomic compare-and-set of the whole state/cursor record. */
export interface ProjectionStore<State> {
  load(key: string): Promise<ProjectionCheckpoint<State> | null>
  commit(key: string, expectedGeneration: number | null, checkpoint: ProjectionCheckpoint<State>): Promise<void>
}

export interface ProjectionEventSource {
  read(options?: EventReadOptions): Promise<EventBatch>
  subscribe(options?: EventReadOptions & { readonly signal?: AbortSignal }): AsyncIterable<EventBatch>
}

export interface DurableProjectionOptions<State> {
  readonly key: string
  readonly identity: ProjectionIdentity
  readonly topics?: readonly string[]
  readonly source: ProjectionEventSource
  readonly store: ProjectionStore<State>
  readonly initial: () => State
  /** Pure application code; never run external effects in a replay reducer. */
  readonly reduce: (state: State, event: EffectiveEvent) => State
  readonly batchTransactions?: number
}

export class ProjectionConflictError extends Error {
  constructor() { super('Projection checkpoint changed; reopen from the committed state and cursor'); this.name = 'ProjectionConflictError' }
}

/** Durable final-event projection. Checkpoints are caches, never history-pruning authority. */
export class DurableProjection<State> {
  readonly #options: DurableProjectionOptions<State>
  readonly #topics: readonly string[] | null
  #running = false

  constructor(options: DurableProjectionOptions<State>) {
    for (const value of [options.key, options.identity.groupId, options.identity.historyId, options.identity.filterVersion, options.identity.reducerVersion]) if (typeof value !== 'string' || !value || value.length > 2048) throw new TypeError('Projection identities must be bounded nonempty strings')
    if (options.topics !== undefined) options.topics.forEach(assertEventTopic)
    this.#topics = options.topics === undefined ? null : [...new Set(options.topics)].sort()
    this.#options = { ...options, identity: { ...options.identity } }
    if (options.batchTransactions !== undefined && (!Number.isSafeInteger(options.batchTransactions) || options.batchTransactions < 1 || options.batchTransactions > 128)) throw new TypeError('Projection batch bound must be from 1 to 128')
  }

  async catchUp(options: { readonly signal?: AbortSignal } = {}): Promise<ProjectionCheckpoint<State>> {
    this.#begin()
    try {
      let { stored, current } = await this.#restore()
      for (;;) {
        options.signal?.throwIfAborted()
        const batch = await this.#options.source.read(this.#readOptions(current))
        options.signal?.throwIfAborted()
        current = await this.#apply(stored, current, batch)
        stored = current
        if (!batch.hasMore) return structuredClone(current)
      }
    } finally { this.#running = false }
  }

  /** Pulling the next checkpoint is backpressure. Every yielded pair is already committed. */
  follow(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ProjectionCheckpoint<State>> {
    const self = this
    return { async *[Symbol.asyncIterator]() {
      self.#begin()
      const controller = new AbortController()
      const signal = options.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, options.signal])
      try {
        let { stored, current } = await self.#restore()
        for await (const batch of self.#options.source.subscribe({ ...self.#readOptions(current), signal })) {
          signal.throwIfAborted()
          current = await self.#apply(stored, current, batch)
          stored = current
          yield structuredClone(current)
        }
      } finally { controller.abort(); self.#running = false }
    } }
  }

  async #restore(): Promise<{ stored: ProjectionCheckpoint<State> | null; current: ProjectionCheckpoint<State> | null }> {
    const stored = await this.#options.store.load(this.#options.key)
    if (stored !== null && (!Number.isSafeInteger(stored.generation) || stored.generation < 1)) throw new Error('Projection checkpoint generation is corrupt; repair or remove this cache')
    const matches = stored !== null && stored.version === 1 && typeof stored.identity === 'object' && stored.identity !== null &&
      ['groupId', 'historyId', 'filterVersion', 'reducerVersion'].every((field) =>
        stored.identity[field as keyof ProjectionIdentity] === this.#options.identity[field as keyof ProjectionIdentity]) &&
      JSON.stringify(stored.topics) === JSON.stringify(this.#topics)
    // A changed filter/reducer starts from genesis. Its old cursor is never reused.
    return { stored, current: matches ? stored : null }
  }

  #readOptions(current: ProjectionCheckpoint<State> | null): EventReadOptions {
    return { ...(current === null ? {} : { cursor: current.cursor }), ...(this.#topics === null ? {} : { topics: this.#topics }), limit: this.#options.batchTransactions ?? 32 }
  }

  async #apply(stored: ProjectionCheckpoint<State> | null, current: ProjectionCheckpoint<State> | null, batch: EventBatch): Promise<ProjectionCheckpoint<State>> {
    if (current?.cursor === batch.scannedThrough) {
      if (batch.hasMore) throw new Error('Projection source reported more history without scan progress')
      if (current.revision === batch.revision) return current
    }
    if (typeof batch.scannedThrough !== 'string' || batch.scannedThrough.length === 0) throw new Error('Projection batch has no durable continuation')
    let state = structuredClone(current === null ? this.#options.initial() : current.state)
    if (current?.cursor !== batch.scannedThrough) {
      for (const transaction of batch.transactions) for (const event of transaction.events) state = this.#options.reduce(state, structuredClone(event))
    }
    const generation = (stored?.generation ?? 0) + 1
    if (!Number.isSafeInteger(generation)) throw new Error('Projection checkpoint generation exhausted')
    const checkpoint: ProjectionCheckpoint<State> = {
      version: 1, generation, identity: { ...this.#options.identity }, topics: this.#topics,
      cursor: batch.scannedThrough, revision: batch.revision, state,
    }
    // Never publish processed progress before this atomic state/cursor commit.
    await this.#options.store.commit(this.#options.key, stored?.generation ?? null, structuredClone(checkpoint))
    return checkpoint
  }

  #begin(): void {
    if (this.#running) throw new ProjectionConflictError()
    this.#running = true
  }
}

/** Browser durable store: one IndexedDB transaction commits projection and cursor together. */
export class IndexedDbProjectionStore<State> implements ProjectionStore<State> {
  readonly #database: Promise<IDBDatabase>
  #closed = false

  constructor(name: string, factory: IDBFactory = globalThis.indexedDB) {
    if (factory === undefined) throw new Error('IndexedDB is unavailable; provide another atomic projection store')
    if (!name || name.length > 512) throw new TypeError('Projection database name must be bounded and nonempty')
    this.#database = new Promise((resolve, reject) => {
      let blocked = false
      const request = factory.open(name, 1)
      request.onupgradeneeded = () => { request.result.createObjectStore('checkpoints') }
      request.onerror = () => reject(request.error)
      request.onblocked = () => { blocked = true; reject(new Error('Projection database upgrade is blocked')) }
      request.onsuccess = () => {
        if (this.#closed || blocked) { request.result.close(); reject(new Error('Projection store is closed')); return }
        request.result.onversionchange = () => { this.#closed = true; request.result.close() }
        resolve(request.result)
      }
    })
  }

  async load(key: string): Promise<ProjectionCheckpoint<State> | null> {
    const database = await this.#db()
    return new Promise((resolve, reject) => {
      const transaction = database.transaction('checkpoints', 'readonly')
      const request = transaction.objectStore('checkpoints').get(key)
      transaction.oncomplete = () => resolve(request.result === undefined ? null : structuredClone(request.result as ProjectionCheckpoint<State>))
      transaction.onabort = transaction.onerror = () => reject(transaction.error ?? new Error('Projection read failed'))
    })
  }

  async commit(key: string, expectedGeneration: number | null, checkpoint: ProjectionCheckpoint<State>): Promise<void> {
    const database = await this.#db()
    return new Promise((resolve, reject) => {
      const transaction = database.transaction('checkpoints', 'readwrite', { durability: 'strict' })
      const store = transaction.objectStore('checkpoints')
      const request = store.get(key)
      let conflict = false
      request.onsuccess = () => {
        const previous = request.result as ProjectionCheckpoint<State> | undefined
        if ((previous?.generation ?? null) !== expectedGeneration) { conflict = true; transaction.abort(); return }
        try { store.put(structuredClone(checkpoint), key) }
        catch { transaction.abort() }
      }
      transaction.oncomplete = () => resolve()
      transaction.onabort = transaction.onerror = () => reject(conflict ? new ProjectionConflictError() : transaction.error ?? new Error('Projection checkpoint commit failed'))
    })
  }

  async close(): Promise<void> { this.#closed = true; (await this.#database).close() }
  async #db(): Promise<IDBDatabase> { if (this.#closed) throw new Error('Projection store is closed'); return this.#database }
}

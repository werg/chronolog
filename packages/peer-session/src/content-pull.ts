/**
 * Windowed, multi-source chunk puller for lazy content transfer.
 *
 * The consumer takes chunks strictly in order; the puller keeps up to `windowChunks` chunks ahead
 * of it in flight as range requests of `batchChunks`, spread over every source that has not failed
 * that chunk (at most `perSource` concurrent requests each). Sources stream each chunk to
 * `onChunk` as it is read, so one request yields many chunks with no per-chunk round trip.
 * A chunk a source lacks (null), mis-delivers (rejected by `accept`) or never sends (request
 * error) is retried on the next source; busy sources are retried after their own work drains.
 */

/** Receives each chunk of a range in order; a returned promise is awaited by the producer (backpressure). */
export type ChunkSink = (index: number, bytes: Uint8Array | null) => void | Promise<void>
export interface RangeSource {
  fetch(start: number, count: number, onChunk: ChunkSink, signal: AbortSignal): Promise<void>
}
export interface PullOptions {
  readonly count: number
  /** First index the consumer will take (earlier chunks are already handled). */
  readonly start?: number
  readonly sources: readonly RangeSource[]
  /** Already-local verified chunk, or null. */
  readonly local: (index: number, signal: AbortSignal) => Promise<Uint8Array | null>
  /** Verify (and usually persist) one remote chunk; throws on invalid bytes. Returns the chunk to hand out. */
  readonly accept: (index: number, bytes: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>
  readonly signal: AbortSignal
  readonly windowChunks?: number
  /** Window before slow start grows it (default 1; whole-object pulls pass `windowChunks`). */
  readonly initialWindow?: number
  readonly batchChunks?: number
  readonly perSource?: number
  readonly missing: string
}

export const CONTENT_PULL_DEFAULTS = Object.freeze({ windowChunks: 64, batchChunks: 8, perSource: 8 })
const BUSY = new Set(['CONTENT_BUSY', 'CONTENT_REQUEST_LIMIT'])
const MAX_BUSY_RETRIES = 1000

interface Slot { resolve(bytes: Uint8Array): void; reject(error: unknown): void; promise: Promise<Uint8Array>; settled: boolean }
function slot(): Slot {
  let resolve!: (bytes: Uint8Array) => void, reject!: (error: unknown) => void
  const promise = new Promise<Uint8Array>((yes, no) => { resolve = yes; reject = no })
  void promise.catch(() => undefined)
  const value: Slot = {
    promise, settled: false,
    resolve: bytes => { if (!value.settled) { value.settled = true; resolve(bytes) } },
    reject: error => { if (!value.settled) { value.settled = true; reject(error) } },
  }
  return value
}

export class ChunkPuller {
  readonly #options: PullOptions
  readonly #window: number
  readonly #batch: number
  readonly #perSource: number
  readonly #controller = new AbortController()
  readonly #signal: AbortSignal
  readonly #slots = new Map<number, Slot>()
  /** Indices waiting for a (re)fetch, with the sources that already failed them. */
  readonly #queue: Array<{ index: number; excluded: Set<number>; failure: unknown; busy: number }> = []
  readonly #inflight: number[]
  /** Per-source concurrency, lowered to what the source accepted when it reports busy. */
  readonly #cap: number[]
  readonly #used: number[]
  #scanned = 0
  #consumed = 0
  /** Slow start: the window doubles with every take, so a consumer that stops early pulls ~what it read. */
  #open = 1
  #failed: unknown = undefined
  #retryTimer: ReturnType<typeof setTimeout> | undefined

  constructor(options: PullOptions) {
    this.#options = options
    this.#window = Math.max(1, options.windowChunks ?? CONTENT_PULL_DEFAULTS.windowChunks)
    this.#batch = Math.max(1, Math.min(this.#window, options.batchChunks ?? CONTENT_PULL_DEFAULTS.batchChunks))
    this.#perSource = Math.max(1, options.perSource ?? CONTENT_PULL_DEFAULTS.perSource)
    this.#inflight = options.sources.map(() => 0)
    this.#scanned = this.#consumed = options.start ?? 0
    this.#open = Math.max(1, Math.min(this.#window, options.initialWindow ?? 1))
    this.#cap = options.sources.map(() => this.#perSource)
    this.#used = options.sources.map(() => 0)
    this.#signal = AbortSignal.any([options.signal, this.#controller.signal])
    this.#signal.addEventListener('abort', this.#onAbort, { once: true })
  }

  readonly #onAbort = (): void => this.close(this.#signal.reason)

  /** Resolve chunk `index` (taken in increasing order) and slide the window past it. */
  async take(index: number): Promise<Uint8Array> {
    this.#signal.throwIfAborted()
    if (this.#failed !== undefined) throw this.#failed instanceof Error ? this.#failed : new Error(this.#options.missing, { cause: this.#failed })
    this.#consumed = Math.max(this.#consumed, index)
    this.#pump()
    this.#open = Math.min(this.#window, this.#open * 2)
    const target = this.#slotFor(index)
    try { return await target.promise } finally { this.#slots.delete(index); this.#consumed = Math.max(this.#consumed, index + 1) }
  }

  close(reason: unknown = new Error('CONTENT_PULL_CLOSED')): void {
    if (this.#retryTimer !== undefined) clearTimeout(this.#retryTimer)
    this.#signal.removeEventListener('abort', this.#onAbort)
    if (!this.#controller.signal.aborted) this.#controller.abort(reason)
    for (const value of this.#slots.values()) value.reject(reason)
  }

  #slotFor(index: number): Slot {
    let value = this.#slots.get(index)
    if (value === undefined) { value = slot(); this.#slots.set(index, value) }
    return value
  }

  #fail(error: unknown): void {
    if (this.#failed !== undefined) return
    this.#failed = error
    this.close(error)
  }

  /** Scan newly windowed indices (local first), then dispatch queued misses as range requests. */
  #pump(): void {
    if (this.#signal.aborted || this.#failed !== undefined) return
    const limit = Math.min(this.#options.count, this.#consumed + this.#open)
    if (this.#scanned < limit) {
      const start = this.#scanned, end = limit
      this.#scanned = limit
      void this.#scan(start, end).catch(error => this.#fail(error))
    }
    this.#dispatch()
  }

  async #scan(start: number, end: number): Promise<void> {
    for (let index = start; index < end; index++) {
      const target = this.#slotFor(index)
      const local = await this.#options.local(index, this.#signal)
      this.#signal.throwIfAborted()
      if (local !== null) target.resolve(local)
      else this.#queue.push({ index, excluded: new Set(), failure: undefined, busy: 0 })
      // Dispatch as soon as a full batch (or the end of the scan) is queued.
      if (this.#queue.length >= this.#batch || index === end - 1) this.#dispatch()
    }
  }

  #pickSource(excluded: ReadonlySet<number>): number {
    let best = -1
    for (let source = 0; source < this.#inflight.length; source++) {
      if (excluded.has(source) || this.#inflight[source]! >= this.#cap[source]!) continue
      // Least loaded first; ties go to the source used least so far (spread across peers).
      if (best < 0 || this.#inflight[source]! < this.#inflight[best]! ||
        (this.#inflight[source] === this.#inflight[best] && this.#used[source]! < this.#used[best]!)) best = source
    }
    return best
  }

  #dispatch(): void {
    if (this.#signal.aborted || this.#failed !== undefined) return
    this.#queue.sort((x, y) => x.index - y.index)
    let blocked = 0
    while (this.#queue.length > blocked) {
      const head = this.#queue[blocked]!
      if (head.excluded.size >= this.#options.sources.length) {
        this.#queue.splice(blocked, 1)
        const error = head.failure ?? new Error(this.#options.missing)
        this.#slotFor(head.index).reject(error); this.#fail(error); return
      }
      const source = this.#pickSource(head.excluded)
      if (source < 0) { blocked++; continue }
      // Contiguous run of queued indices this source may serve.
      let run = 1
      while (run < this.#batch && blocked + run < this.#queue.length) {
        const item = this.#queue[blocked + run]!
        if (item.index !== head.index + run || item.excluded.has(source)) break
        run++
      }
      const items = this.#queue.splice(blocked, run)
      void this.#request(source, items)
    }
  }

  async #request(source: number, items: Array<{ index: number; excluded: Set<number>; failure: unknown; busy: number }>): Promise<void> {
    this.#inflight[source]!++; this.#used[source]!++
    const start = items[0]!.index, pending = new Map(items.map(item => [item.index, item]))
    const accepted: Promise<void>[] = []
    let failure: unknown
    try {
      await this.#options.sources[source]!.fetch(start, items.length, (index, bytes) => {
        const item = pending.get(index)
        if (item === undefined || this.#signal.aborted) return
        pending.delete(index)
        if (bytes === null) { item.excluded.add(source); this.#queue.push(item); return }
        accepted.push(this.#options.accept(index, bytes, this.#signal).then(
          value => { this.#slotFor(index).resolve(value) },
          error => { if (!this.#signal.aborted) { item.excluded.add(source); item.failure = error; this.#queue.push(item) } },
        ))
      }, this.#signal)
    } catch (error) { failure = error }
    await Promise.all(accepted)
    this.#inflight[source]!--
    if (this.#signal.aborted) return
    const busy = failure instanceof Error && BUSY.has(failure.message)
    for (const item of pending.values()) {
      if (busy && ++item.busy <= MAX_BUSY_RETRIES) { this.#queue.push(item); continue }
      item.excluded.add(source)
      if (failure !== undefined) item.failure = failure
      this.#queue.push(item)
    }
    if (!busy) this.#cap[source] = Math.min(this.#perSource, this.#cap[source]! + 1)
    else if (pending.size > 0) {
      this.#cap[source] = Math.max(1, this.#inflight[source]!)
      if (this.#inflight[source] === 0) {
        // Every slot is held by other work: back off briefly instead of spinning.
        if (this.#retryTimer === undefined) this.#retryTimer = setTimeout(() => { this.#retryTimer = undefined; this.#dispatch() }, 10)
        return
      }
    }
    this.#dispatch()
  }
}

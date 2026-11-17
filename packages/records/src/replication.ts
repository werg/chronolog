import { DEFAULT_MAX_RECORD_BYTES, type FeedCrypto, type FeedRecord, verifyFeedRecord } from './feed-codec.js'
import type { FeedAppendResult, FeedStorePort } from './store.js'

/** A connection carries exact signed records. Its current peer never becomes their author. */
export interface FeedLink {
  readonly identity: string
  /** Retained availability only; neither head is a finality or trust decision. */
  head(feed: string): Promise<bigint>
  evidenceHead(): Promise<bigint>
  read(feed: string, after: bigint, limit: number): Promise<readonly Uint8Array[]>
  /** Dense, append-only positions belonging to this connection's evidence log. */
  readEvidence(after: bigint, limit: number): Promise<readonly Uint8Array[]>
  /** Payload delivery is independent of ledger/header synchronization. */
  readPayload(hash: string): Promise<Uint8Array | null>
  /** Wake-up hints only. Every hint is resolved with retained range reads. */
  watch(signal?: AbortSignal): AsyncIterable<void>
}

export interface IngestFeedOptions {
  readonly store: FeedStorePort
  readonly crypto: FeedCrypto
  readonly feed?: string
  readonly maxRecordBytes?: number
  readonly onStored?: (record: FeedRecord, result: FeedAppendResult) => void
}

/** Shared ingestion for native pull streams, browser links, and in-process links. */
export async function ingestFeedBytes(raw: Uint8Array, options: IngestFeedOptions): Promise<FeedAppendResult> {
  const record = await verifyFeedRecord(raw, options.crypto, options.maxRecordBytes ?? DEFAULT_MAX_RECORD_BYTES)
  if (options.feed !== undefined && record.author !== options.feed) throw new Error('FEED_RANGE_AUTHOR_MISMATCH')
  const result = await options.store.append(record)
  if (result.kind === 'appended' || result.kind === 'fork') options.onStored?.(record, result)
  return result
}

/** Pull a captured finite prefix; later appends belong to a subsequent pass. */
export async function pullFeed(
  link: FeedLink, feed: string, through: bigint, options: Omit<IngestFeedOptions, 'feed'>,
  signal?: AbortSignal, batchSize = 64,
): Promise<void> {
  assertFeedPosition(through)
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 4096) throw new Error('FEED_RANGE_INVALID')
  for (;;) {
    signal?.throwIfAborted()
    const before = await options.store.head(feed)
    signal?.throwIfAborted()
    if (before.sequence >= through) return
    const limit = Number(through - before.sequence < BigInt(batchSize) ? through - before.sequence : BigInt(batchSize))
    const batch = await remoteRead(() => link.read(feed, before.sequence, limit), signal)
    if (batch.length > limit) throw new Error('FEED_RANGE_TOO_LARGE')
    if (batch.length === 0) throw new Error('FEED_RANGE_TARGET_UNAVAILABLE')
    for (const raw of batch) {
      signal?.throwIfAborted()
      const result = await ingestFeedBytes(raw, { ...options, feed })
      signal?.throwIfAborted()
      if (result.kind === 'out_of_order') throw new Error('FEED_RANGE_NOT_CONTIGUOUS')
    }
    const after = await options.store.head(feed)
    if (after.sequence <= before.sequence) throw new Error('FEED_RANGE_NO_PROGRESS')
    if (after.sequence < through && batch.length < limit) throw new Error('FEED_RANGE_TARGET_UNAVAILABLE')
  }
}

/**
 * Captures every requested head before copying bytes. Evidence cursors advance
 * only after durable append; they are private to this exact connection.
 */
export async function pullFeedLink(
  link: FeedLink, feeds: readonly string[], cursor: { evidenceAfter: bigint },
  options: Omit<IngestFeedOptions, 'feed'> & { readonly onEvidenceStored?: () => void }, signal?: AbortSignal,
): Promise<void> {
  const wanted = [...new Set(feeds)], targets: Array<{ feed: string; through: bigint }> = []
  const evidenceThrough = await remoteRead(() => link.evidenceHead(), signal)
  assertFeedPosition(evidenceThrough); assertFeedPosition(cursor.evidenceAfter)
  if (evidenceThrough < cursor.evidenceAfter) throw new Error('FEED_EVIDENCE_HEAD_REGRESSED')
  for (const feed of wanted) {
    const through = await remoteRead(() => link.head(feed), signal)
    assertFeedPosition(through)
    targets.push({ feed, through })
  }
  for (const { feed, through } of targets) await pullFeed(link, feed, through, options, signal)
  while (cursor.evidenceAfter < evidenceThrough) {
    const remaining = evidenceThrough - cursor.evidenceAfter, limit = Number(remaining < 64n ? remaining : 64n)
    const batch = await remoteRead(() => link.readEvidence(cursor.evidenceAfter, limit), signal)
    if (batch.length > limit) throw new Error('FEED_RANGE_TOO_LARGE')
    if (batch.length === 0) throw new Error('FEED_RANGE_TARGET_UNAVAILABLE')
    for (const bytes of batch) {
      signal?.throwIfAborted()
      // Never race a durable write against cancellation and close its store
      // while its commit is still in flight.
      const result = await options.store.putEvidence(bytes)
      cursor.evidenceAfter += 1n
      if (result.kind === 'appended') options.onEvidenceStored?.()
      signal?.throwIfAborted()
    }
    if (cursor.evidenceAfter < evidenceThrough && batch.length < limit) throw new Error('FEED_RANGE_TARGET_UNAVAILABLE')
  }
  signal?.throwIfAborted()
}

export function assertFeedPosition(value: unknown): asserts value is bigint {
  if (typeof value !== 'bigint' || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('FEED_POSITION_INVALID')
}

/** Bound waiting on a disconnected source without abandoning any local write. */
function remoteRead<T>(read: () => Promise<T>, signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted()
  if (signal === undefined) return read()
  return new Promise<T>((resolve, reject) => {
    const aborted = (): void => { reject(signal.reason); signal.removeEventListener('abort', aborted) }
    signal.addEventListener('abort', aborted, { once: true })
    void Promise.resolve().then(() => { signal.throwIfAborted(); return read() }).then(resolve, reject)
      .finally(() => signal.removeEventListener('abort', aborted))
  })
}

/** Shared consumer for adapters whose connection API supplies a live pull stream. */
export async function consumeFeed(
  records: AsyncIterable<Uint8Array>, options: IngestFeedOptions, signal?: AbortSignal,
): Promise<void> {
  for await (const raw of records) {
    if (signal?.aborted) return
    const result = await ingestFeedBytes(raw, options)
    if (result.kind === 'out_of_order') throw new Error('FEED_RANGE_NOT_CONTIGUOUS')
  }
}

export class ChangeSignal {
  readonly #waiters = new Set<() => void>()
  #version = 0
  #closed = false

  get version(): number { return this.#version }
  notify(): void { this.#version += 1; for (const waiter of [...this.#waiters]) waiter() }
  close(): void { this.#closed = true; this.notify() }

  wait(version: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      const done = (): void => {
        this.#waiters.delete(done)
        signal?.removeEventListener('abort', done)
        resolve()
      }
      this.#waiters.add(done)
      signal?.addEventListener('abort', done, { once: true })
      if (this.#closed || signal?.aborted === true || this.#version !== version) done()
    })
  }

  async *watch(signal?: AbortSignal): AsyncIterable<void> {
    while (!this.#closed && signal?.aborted !== true) {
      const version = this.#version
      yield undefined
      await this.wait(version, signal)
    }
  }
}

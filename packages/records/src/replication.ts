import { DEFAULT_MAX_RECORD_BYTES, type FeedCrypto, type FeedRecord, verifyFeedRecord } from './feed-codec.js'
import type { FeedAppendResult, FeedStorePort } from './store.js'

/** A connection carries exact signed records. Its current peer never becomes their author. */
export interface FeedLink {
  readonly identity: string
  read(feed: string, after: bigint, limit: number): Promise<readonly Uint8Array[]>
  /** Wake-up hints only. Every hint is resolved with retained range reads. */
  readEvidence(after: bigint, limit: number): Promise<readonly Uint8Array[]>
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

/** Pull complete retained batches from a connection; the durable head is the resume cursor. */
export async function pullFeed(
  link: FeedLink, feed: string, options: Omit<IngestFeedOptions, 'feed'>,
  signal?: AbortSignal, batchSize = 64,
): Promise<void> {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 4096) throw new Error('FEED_RANGE_INVALID')
  while (signal?.aborted !== true) {
    const before = await options.store.head(feed)
    const batch = await link.read(feed, before.sequence, batchSize)
    if (batch.length > batchSize) throw new Error('FEED_RANGE_TOO_LARGE')
    if (batch.length === 0) return
    for (const raw of batch) {
      if (signal?.aborted) return
      const result = await ingestFeedBytes(raw, { ...options, feed })
      if (result.kind === 'out_of_order') throw new Error('FEED_RANGE_NOT_CONTIGUOUS')
    }
    const after = await options.store.head(feed)
    if (after.sequence <= before.sequence) throw new Error('FEED_RANGE_NO_PROGRESS')
    if (batch.length < batchSize) return
  }
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

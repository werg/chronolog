import { assertCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, type CborValue } from '@chronolog/canonical'

import { feedRecordId, type FeedCrypto, type FeedRecord, verifyFeedRecord } from './feed-codec.js'
import type { TransportRecord } from './types.js'

export type Awaitable<T> = T | Promise<T>

/** Private local state, never part of peer replication. Resolve put only after durable replacement. */
export interface AtomicBytesStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, bytes: Uint8Array): Promise<void>
}

export type FeedAppendResult =
  | { readonly kind: 'appended'; readonly record: TransportRecord }
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'fork'; readonly record: TransportRecord }
  | { readonly kind: 'out_of_order'; readonly head: bigint }

export interface FeedHead { readonly sequence: bigint; readonly id: string | null }
export interface FeedStorePort {
  head(author: string): Awaitable<FeedHead>
  append(record: FeedRecord, receivedAtMs?: number): Awaitable<FeedAppendResult>
  get(id: string): Awaitable<TransportRecord | undefined>
  after(index: bigint, limit: number): Awaitable<readonly { readonly index: bigint; readonly record: TransportRecord }[]>
  feedAfter(author: string, sequence: bigint, limit: number): Awaitable<readonly { readonly sequence: bigint; readonly raw: Uint8Array }[]>
  heads(): Awaitable<ReadonlyMap<string, bigint>>
  count(): Awaitable<number>
  close(): Awaitable<void>
}

/** Shared feed-continuity decision; storage adapters apply it inside their single-writer append. */
export function classifyFeedAppend(record: FeedRecord, head: FeedHead, existingId?: string): 'append' | 'duplicate' | 'fork' | 'out_of_order' {
  if (existingId !== undefined) return existingId === record.id ? 'duplicate' : 'fork'
  return record.sequence === head.sequence + 1n && record.previous === head.id ? 'append' : 'out_of_order'
}

export function toTransportRecord(record: FeedRecord, receivedAtMs: number): TransportRecord {
  return {
    id: record.id, author: record.author, sequence: record.sequence,
    ...(record.previous === null ? {} : { previous: record.previous }),
    receivedAtMs, payload: record.payload.slice(),
  }
}

interface StoredRecord { readonly record: FeedRecord; readonly receivedAtMs: number }

/**
 * Portable durable feed store. Immutable record objects are written first, then
 * one atomic manifest publication makes an append visible. A crash before that
 * publication leaves an unreachable object, never a visible partial append.
 * Each runtime must hold exclusive ownership of the backing bytes store.
 */
export class DurableFeedStore implements FeedStorePort {
  readonly #bytes: AtomicBytesStore
  readonly #crypto: FeedCrypto
  readonly #records: StoredRecord[] = []
  readonly #forks: StoredRecord[] = []
  readonly #byId = new Map<string, StoredRecord>()
  readonly #byAuthor = new Map<string, StoredRecord[]>()
  #pending: Promise<unknown> = Promise.resolve()
  #closed = false

  private constructor(bytes: AtomicBytesStore, crypto: FeedCrypto) { this.#bytes = bytes; this.#crypto = crypto }

  static async open(bytes: AtomicBytesStore, crypto: FeedCrypto): Promise<DurableFeedStore> {
    const store = new DurableFeedStore(bytes, crypto)
    const manifest = await bytes.get('feed/manifest')
    if (manifest === null) return store
    const decoded = assertCanonicalCbor(manifest, DEFAULT_DECODE_LIMITS)
    if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== 1n || !Array.isArray(decoded[1]) || !Array.isArray(decoded[2])) {
      throw new Error('FEED_STORE_MANIFEST_INVALID')
    }
    for (const [items, forks] of [[decoded[1], false], [decoded[2], true]] as const) {
      for (const value of items as readonly CborValue[]) {
        if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string' || typeof value[1] !== 'bigint' ||
            value[1] < 0n || value[1] > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('FEED_STORE_MANIFEST_INVALID')
        const raw = await bytes.get(objectKey(value[0]))
        if (raw === null) throw new Error('FEED_STORE_RECORD_MISSING')
        const record = await verifyFeedRecord(raw, crypto)
        if (record.id !== value[0]) throw new Error('FEED_STORE_RECORD_MISMATCH')
        const item = { record, receivedAtMs: Number(value[1]) }
        if (forks) store.#forks.push(item)
        else {
          if (classifyFeedAppend(record, store.head(record.author), store.#byAuthor.get(record.author)?.[Number(record.sequence - 1n)]?.record.id) !== 'append') {
            throw new Error('FEED_STORE_CONTINUITY_INVALID')
          }
          store.#remember(item)
        }
      }
    }
    return store
  }

  head(author: string): FeedHead {
    const last = this.#byAuthor.get(author)?.at(-1)?.record
    return last === undefined ? { sequence: 0n, id: null } : { sequence: last.sequence, id: last.id }
  }

  append(input: FeedRecord, receivedAtMs = Date.now()): Promise<FeedAppendResult> {
    const raw = input.raw.slice()
    const task = this.#pending.then(async (): Promise<FeedAppendResult> => {
      if (this.#closed) throw new Error('FEED_STORE_CLOSED')
      if (!Number.isSafeInteger(receivedAtMs) || receivedAtMs < 0) throw new Error('FEED_RECEIVED_AT_INVALID')
      const record = await verifyFeedRecord(raw, this.#crypto)
      if (record.id !== input.id) throw new Error('FEED_STORE_RECORD_MISMATCH')
      const head = this.head(record.author)
      const existing = this.#byAuthor.get(record.author)?.[Number(record.sequence - 1n)]?.record.id
      const kind = classifyFeedAppend(record, head, existing)
      if (kind === 'duplicate') return { kind }
      if (kind === 'out_of_order') return { kind, head: head.sequence }
      const item = { record, receivedAtMs }
      const records = kind === 'append' ? [...this.#records, item] : this.#records
      const forks = kind === 'fork' && !this.#forks.some((fork) => fork.record.id === record.id) ? [...this.#forks, item] : this.#forks
      await this.#bytes.put(objectKey(record.id), record.raw)
      await this.#bytes.put('feed/manifest', encodeCanonicalCbor([1n, manifestRows(records), manifestRows(forks)]))
      if (kind === 'append') this.#remember(item)
      else if (forks !== this.#forks) this.#forks.push(item)
      return { kind: kind === 'append' ? 'appended' : 'fork', record: toTransportRecord(record, receivedAtMs) }
    })
    this.#pending = task.catch(() => undefined)
    return task
  }

  get(id: string): TransportRecord | undefined {
    const stored = this.#byId.get(id)
    return stored === undefined ? undefined : toTransportRecord(stored.record, stored.receivedAtMs)
  }

  after(index: bigint, limit: number): readonly { readonly index: bigint; readonly record: TransportRecord }[] {
    assertRange(index, limit)
    return this.#records.slice(Number(index), Number(index) + limit)
      .map((item, offset) => ({ index: index + BigInt(offset) + 1n, record: toTransportRecord(item.record, item.receivedAtMs) }))
  }

  feedAfter(author: string, sequence: bigint, limit: number): readonly { readonly sequence: bigint; readonly raw: Uint8Array }[] {
    assertRange(sequence, limit)
    return (this.#byAuthor.get(author) ?? []).slice(Number(sequence), Number(sequence) + limit)
      .map(({ record }) => ({ sequence: record.sequence, raw: record.raw.slice() }))
  }

  heads(): ReadonlyMap<string, bigint> { return new Map([...this.#byAuthor].map(([author, rows]) => [author, BigInt(rows.length)])) }
  count(): number { return this.#records.length }
  forkedAuthors(): readonly string[] { return [...new Set(this.#forks.map(({ record }) => record.author))].sort() }
  async close(): Promise<void> { await this.#pending; this.#closed = true }

  #remember(item: StoredRecord): void {
    this.#records.push(item)
    this.#byId.set(item.record.id, item)
    const author = this.#byAuthor.get(item.record.author) ?? []
    author.push(item)
    this.#byAuthor.set(item.record.author, author)
  }
}

function manifestRows(items: readonly StoredRecord[]): CborValue {
  return items.map((item) => [item.record.id, BigInt(item.receivedAtMs)])
}

function objectKey(id: string): string {
  // Validate both the ID syntax and canonical digest representation before use as a key.
  const match = /^%([A-Za-z0-9+/]{43}=)\.sha256$/u.exec(id)
  if (match === null) throw new Error('FEED_STORE_RECORD_ID_INVALID')
  const digest = Uint8Array.from(atob(match[1]!), (character) => character.charCodeAt(0))
  if (feedRecordId(digest) !== id) throw new Error('FEED_STORE_RECORD_ID_INVALID')
  return `feed/object/${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
}

function assertRange(after: bigint, limit: number): void {
  if (after < 0n || after > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(limit) || limit < 1 || limit > 4096) {
    throw new Error('FEED_RANGE_INVALID')
  }
}

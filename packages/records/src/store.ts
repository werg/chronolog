import { assertCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, type CborValue } from '@chronolog/canonical'

import { feedRecordId, type FeedCrypto, type FeedRecord, verifyFeedRecord } from './feed-codec.js'
import type { ImmutableEvidence, TransportRecord } from './types.js'
import { payloadHash, validatePayloadHash, verifyPayloadHash } from './payload.js'

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
  getPayload(hash: string): Awaitable<Uint8Array | null>
  putPayload(bytes: Uint8Array): Awaitable<string>
  after(index: bigint, limit: number): Awaitable<readonly { readonly index: bigint; readonly record: TransportRecord }[]>
  /** Durable conflicting records, replayed independently of the accepted feed prefix. */
  forksAfter(index: bigint, limit: number): Awaitable<readonly { readonly index: bigint; readonly record: TransportRecord }[]>
  feedAfter(author: string, sequence: bigint, limit: number): Awaitable<readonly { readonly sequence: bigint; readonly raw: Uint8Array }[]>
  heads(): Awaitable<ReadonlyMap<string, bigint>>
  count(): Awaitable<number>
  putEvidence(bytes: Uint8Array): Awaitable<{ readonly kind: 'appended' | 'duplicate'; readonly index: bigint; readonly evidence: ImmutableEvidence }>
  evidenceAfter(index: bigint, limit: number): Awaitable<readonly { readonly index: bigint; readonly evidence: ImmutableEvidence }[]>
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
  readonly #payloads = new Map<string, Uint8Array>()
  readonly #evidence: ImmutableEvidence[] = []
  readonly #evidenceIndex = new Map<string, number>()
  #pending: Promise<unknown> = Promise.resolve()
  #closed = false

  private constructor(bytes: AtomicBytesStore, crypto: FeedCrypto) { this.#bytes = bytes; this.#crypto = crypto }

  static async open(bytes: AtomicBytesStore, crypto: FeedCrypto): Promise<DurableFeedStore> {
    const store = new DurableFeedStore(bytes, crypto)
    const manifest = await bytes.get('feed/manifest')
    if (manifest === null) return store
    const decoded = assertCanonicalCbor(manifest, DEFAULT_DECODE_LIMITS)
    if (!Array.isArray(decoded) || decoded.length !== 4 || decoded[0] !== 1n || !Array.isArray(decoded[1]) || !Array.isArray(decoded[2]) || !Array.isArray(decoded[3])) {
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
          await store.#remember(item)
        }
      }
    }
    for (const id of decoded[3] as readonly CborValue[]) {
      if (typeof id !== 'string' || store.#evidenceIndex.has(id)) throw new Error('FEED_STORE_MANIFEST_INVALID')
      const raw = await bytes.get(objectKey(id))
      if (raw === null) throw new Error('FEED_STORE_EVIDENCE_MISSING')
      if (feedRecordId(await crypto.sha256(raw)) !== id) throw new Error('FEED_STORE_EVIDENCE_MISMATCH')
      store.#evidenceIndex.set(id, store.#evidence.length)
      store.#evidence.push({ id, bytes: raw.slice() })
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
      await this.#bytes.put('feed/manifest', encodeCanonicalCbor([1n, manifestRows(records), manifestRows(forks), this.#evidence.map((item) => item.id)]))
      if (kind === 'append') await this.#remember(item)
      else if (forks !== this.#forks) this.#forks.push(item)
      return { kind: kind === 'append' ? 'appended' : 'fork', record: toTransportRecord(record, receivedAtMs) }
    })
    this.#pending = task.catch(() => undefined)
    return task
  }

  putEvidence(input: Uint8Array): Promise<{ readonly kind: 'appended' | 'duplicate'; readonly index: bigint; readonly evidence: ImmutableEvidence }> {
    const bytes = input.slice()
    const task = this.#pending.then(async () => {
      if (this.#closed) throw new Error('FEED_STORE_CLOSED')
      if (bytes.length > 64 * 1024 * 1024) throw new Error('FEED_RECORD_TOO_LARGE')
      const id = feedRecordId(await this.#crypto.sha256(bytes))
      const existing = this.#evidenceIndex.get(id)
      if (existing !== undefined) return { kind: 'duplicate' as const, index: BigInt(existing + 1), evidence: { id, bytes: bytes.slice() } }
      const evidence = { id, bytes }
      await this.#bytes.put(objectKey(id), bytes)
      await this.#bytes.put('feed/manifest', encodeCanonicalCbor([
        1n, manifestRows(this.#records), manifestRows(this.#forks), [...this.#evidence.map((item) => item.id), id],
      ]))
      this.#evidenceIndex.set(id, this.#evidence.length)
      this.#evidence.push(evidence)
      return { kind: 'appended' as const, index: BigInt(this.#evidence.length), evidence: { id, bytes: bytes.slice() } }
    })
    this.#pending = task.catch(() => undefined)
    return task
  }

  evidenceAfter(index: bigint, limit: number): readonly { readonly index: bigint; readonly evidence: ImmutableEvidence }[] {
    assertRange(index, limit)
    return this.#evidence.slice(Number(index), Number(index) + limit)
      .map((item, offset) => ({ index: index + BigInt(offset) + 1n, evidence: { id: item.id, bytes: item.bytes.slice() } }))
  }

  get(id: string): TransportRecord | undefined {
    const stored = this.#byId.get(id)
    return stored === undefined ? undefined : toTransportRecord(stored.record, stored.receivedAtMs)
  }

  async getPayload(hash: string): Promise<Uint8Array | null> {
    validatePayloadHash(hash)
    const bytes = this.#payloads.get(hash) ?? await this.#bytes.get(`feed/payload/${hash}`)
    if (bytes === null) return null
    await verifyPayloadHash(hash, bytes)
    return bytes.slice()
  }

  async putPayload(input: Uint8Array): Promise<string> {
    if (this.#closed) throw new Error('FEED_STORE_CLOSED')
    const bytes = input.slice()
    if (bytes.length > 64 * 1024 * 1024) throw new Error('FEED_RECORD_TOO_LARGE')
    const hash = await payloadHash(bytes)
    if (!this.#payloads.has(hash)) await this.#bytes.put(`feed/payload/${hash}`, bytes)
    return hash
  }

  after(index: bigint, limit: number): readonly { readonly index: bigint; readonly record: TransportRecord }[] {
    assertRange(index, limit)
    return this.#records.slice(Number(index), Number(index) + limit)
      .map((item, offset) => ({ index: index + BigInt(offset) + 1n, record: toTransportRecord(item.record, item.receivedAtMs) }))
  }

  forksAfter(index: bigint, limit: number): readonly { readonly index: bigint; readonly record: TransportRecord }[] {
    assertRange(index, limit)
    return this.#forks.slice(Number(index), Number(index) + limit)
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

  async #remember(item: StoredRecord): Promise<void> {
    this.#payloads.set(await payloadHash(item.record.payload), item.record.payload)
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

// A durable store of signed, hash-chained author feeds in one SQLite file.
//
// Each record is signed by its author's Ed25519 key and names its
// predecessor's id, so a feed is a verifiable chain. The store only appends
// the next record of a feed (sequence = head + 1, previous = head id): feeds
// never have gaps. A second, different record at an existing sequence is a
// fork; it is kept as evidence and never appended.
import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto'
import { DatabaseSync, type StatementSync } from 'node:sqlite'

import {
  DEFAULT_MAX_RECORD_BYTES, FeedRecordError, decodeSignedFeedRecord, encodeSignedFeedRecord,
  feedIdFromPublicKey, publicKeyFromFeedId, feedRecordId, feedSigningBytes, classifyFeedAppend,
  type FeedRecord, type FeedCrypto,
} from '@chronolog/records'
import type { ImmutableEvidence, TransportRecord } from './types.js'

export { DEFAULT_MAX_RECORD_BYTES, FeedRecordError, feedIdFromPublicKey, publicKeyFromFeedId }
export type { FeedRecord }

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

/** The native key-file adapter's only dependency on the SSB key representation. */
export interface FeedKeys {
  readonly id: string
  readonly private: string
}

export type AppendResult =
  | { readonly kind: 'appended'; readonly record: TransportRecord }
  | { readonly kind: 'duplicate' }
  | { readonly kind: 'fork'; readonly record: TransportRecord }
  | { readonly kind: 'out_of_order'; readonly head: bigint }

function recordId(raw: Uint8Array): string {
  return feedRecordId(createHash('sha256').update(raw).digest())
}

function privateKeyObject(keys: FeedKeys): KeyObject {
  const secret = Buffer.from(keys.private.replace(/\.ed25519$/u, ''), 'base64')
  if (secret.length !== 64 && secret.length !== 32) throw new FeedRecordError('FEED_PRIVATE_KEY_INVALID')
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, secret.subarray(0, 32)]), format: 'der', type: 'pkcs8' })
}

const publicKeyCache = new Map<string, KeyObject>()
function publicKeyObject(feedId: string): KeyObject {
  let key = publicKeyCache.get(feedId)
  if (key === undefined) {
    key = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, publicKeyFromFeedId(feedId)]), format: 'der', type: 'spki' })
    if (publicKeyCache.size > 4_096) publicKeyCache.clear()
    publicKeyCache.set(feedId, key)
  }
  return key
}

export const nativeFeedCrypto: FeedCrypto = {
  sha256: (bytes) => createHash('sha256').update(bytes).digest(),
  verify: (publicKey, bytes, signature) => verify(null, bytes, publicKeyObject(feedIdFromPublicKey(publicKey)), signature),
}

export function createFeedRecord(
  keys: FeedKeys, sequence: bigint, previous: string | null, timestampMs: bigint, payload: Uint8Array,
): FeedRecord {
  const fields = { author: keys.id, sequence, previous, timestampMs, payload: payload.slice() }
  const raw = encodeSignedFeedRecord(fields, sign(null, feedSigningBytes(fields), privateKeyObject(keys)))
  return { ...fields, id: recordId(raw), raw }
}

export function decodeFeedRecord(raw: Uint8Array, maxRecordBytes = DEFAULT_MAX_RECORD_BYTES): FeedRecord {
  const decoded = decodeSignedFeedRecord(raw, maxRecordBytes)
  if (!verify(null, decoded.signingBytes, publicKeyObject(decoded.author), decoded.signature)) {
    throw new FeedRecordError('FEED_RECORD_SIGNATURE_INVALID')
  }
  const { author, sequence, previous, timestampMs, payload } = decoded
  return { id: recordId(decoded.raw), author, sequence, previous, timestampMs, payload, raw: decoded.raw }
}

interface RecordRow {
  readonly local_index: number | bigint
  readonly id: string
  readonly author: string
  readonly sequence: number | bigint
  readonly previous: string | null
  readonly received_at: number | bigint
  readonly payload: Uint8Array
}

export class FeedStore {
  readonly #database: DatabaseSync
  readonly #statements: {
    readonly head: StatementSync
    readonly insert: StatementSync
    readonly byId: StatementSync
    readonly bySequence: StatementSync
    readonly after: StatementSync
    readonly feedAfter: StatementSync
    readonly heads: StatementSync
    readonly count: StatementSync
    readonly fork: StatementSync
    readonly forks: StatementSync
    readonly maxIndex: StatementSync
    readonly evidenceById: StatementSync
    readonly evidenceInsert: StatementSync
    readonly evidenceAfter: StatementSync
    readonly payloadByHash: StatementSync
    readonly detachedPayloadByHash: StatementSync
    readonly putPayload: StatementSync
  }

  /**
   * Opens the store and takes an exclusive lock on the file for the life of
   * the connection; a second owner fails with FEED_STORE_IN_USE.
   */
  constructor(path: string) {
    this.#database = new DatabaseSync(path)
    try {
      this.#database.exec('PRAGMA busy_timeout = 0')
      this.#database.exec('PRAGMA locking_mode = EXCLUSIVE')
      this.#database.exec('PRAGMA journal_mode = WAL')
      this.#database.exec('PRAGMA synchronous = FULL')
      this.#database.exec('BEGIN EXCLUSIVE')
      this.#database.exec(`
        CREATE TABLE IF NOT EXISTS records (
          local_index INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE,
          author TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          previous TEXT,
          timestamp_ms INTEGER NOT NULL,
          received_at INTEGER NOT NULL,
          payload BLOB NOT NULL,
          payload_hash TEXT NOT NULL,
          raw BLOB NOT NULL,
          UNIQUE (author, sequence)
        );
        CREATE INDEX IF NOT EXISTS records_payload_hash ON records (payload_hash);
        CREATE TABLE IF NOT EXISTS payloads (
          hash TEXT PRIMARY KEY,
          bytes BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
          local_index INTEGER PRIMARY KEY AUTOINCREMENT,
          id TEXT NOT NULL UNIQUE,
          raw BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS forks (
          id TEXT PRIMARY KEY,
          author TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          raw BLOB NOT NULL,
          received_at INTEGER NOT NULL
        );
      `)
      this.#database.exec('COMMIT')
    } catch (error) {
      try { this.#database.close() } catch { /* already failed */ }
      if (/locked|busy/iu.test(error instanceof Error ? error.message : '')) {
        throw new Error('FEED_STORE_IN_USE', { cause: error })
      }
      throw error
    }
    const prepare = (sql: string): StatementSync => {
      const statement = this.#database.prepare(sql)
      statement.setReadBigInts(true)
      return statement
    }
    const columns = 'local_index, id, author, sequence, previous, received_at, payload'
    this.#statements = {
      head: prepare('SELECT sequence, id FROM records WHERE author = ? ORDER BY sequence DESC LIMIT 1'),
      insert: prepare(`INSERT INTO records (id, author, sequence, previous, timestamp_ms, received_at, payload, payload_hash, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING local_index`),
      byId: prepare(`SELECT ${columns} FROM records WHERE id = ?`),
      bySequence: prepare('SELECT id FROM records WHERE author = ? AND sequence = ?'),
      after: prepare(`SELECT ${columns} FROM records WHERE local_index > ? ORDER BY local_index LIMIT ?`),
      feedAfter: prepare('SELECT sequence, raw FROM records WHERE author = ? AND sequence > ? ORDER BY sequence LIMIT ?'),
      heads: prepare('SELECT author, max(sequence) AS sequence FROM records GROUP BY author'),
      count: prepare('SELECT count(*) AS count FROM records'),
      fork: prepare('INSERT OR IGNORE INTO forks (id, author, sequence, raw, received_at) VALUES (?, ?, ?, ?, ?)'),
      forks: prepare('SELECT DISTINCT author FROM forks ORDER BY author'),
      maxIndex: prepare('SELECT coalesce(max(local_index), 0) AS local_index FROM records'),
      evidenceById: prepare('SELECT local_index FROM evidence WHERE id = ?'),
      evidenceInsert: prepare('INSERT INTO evidence (id, raw) VALUES (?, ?) RETURNING local_index'),
      evidenceAfter: prepare('SELECT local_index, id, raw FROM evidence WHERE local_index > ? ORDER BY local_index LIMIT ?'),
      payloadByHash: prepare('SELECT payload AS bytes FROM records WHERE payload_hash = ? LIMIT 1'),
      detachedPayloadByHash: prepare('SELECT bytes FROM payloads WHERE hash = ?'),
      putPayload: prepare('INSERT OR IGNORE INTO payloads (hash, bytes) VALUES (?, ?)'),
    }
  }

  head(author: string): { readonly sequence: bigint; readonly id: string | null } {
    const row = this.#statements.head.get(author) as { sequence: bigint; id: string } | undefined
    return row === undefined ? { sequence: 0n, id: null } : { sequence: row.sequence, id: row.id }
  }

  /** Append the author's next record. Durable when this returns. */
  append(record: FeedRecord, receivedAtMs = Date.now()): AppendResult {
    const existing = this.#statements.bySequence.get(record.author, record.sequence) as { id: string } | undefined
    const head = this.head(record.author)
    const disposition = classifyFeedAppend(record, head, existing?.id)
    if (disposition === 'duplicate') return { kind: 'duplicate' }
    if (disposition === 'fork') {
      this.#statements.fork.run(record.id, record.author, record.sequence, record.raw, receivedAtMs)
      return { kind: 'fork', record: toTransportRecord(record, receivedAtMs) }
    }
    if (disposition === 'out_of_order') {
      return { kind: 'out_of_order', head: head.sequence }
    }
    this.#statements.insert.get(
      record.id, record.author, record.sequence, record.previous, record.timestampMs, receivedAtMs,
      record.payload, createHash('sha256').update(record.payload).digest('hex'), record.raw,
    )
    return { kind: 'appended', record: toTransportRecord(record, receivedAtMs) }
  }

  get(id: string): TransportRecord | undefined {
    const row = this.#statements.byId.get(id) as RecordRow | undefined
    return row === undefined ? undefined : rowRecord(row)
  }

  getPayload(hash: string): Uint8Array | null {
    if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('PAYLOAD_HASH_INVALID')
    const row = (this.#statements.payloadByHash.get(hash) ?? this.#statements.detachedPayloadByHash.get(hash)) as
      { bytes: Uint8Array } | undefined
    if (row === undefined) return null
    if (createHash('sha256').update(row.bytes).digest('hex') !== hash) throw new Error('PAYLOAD_HASH_MISMATCH')
    return new Uint8Array(row.bytes)
  }

  putPayload(input: Uint8Array): string {
    if (input.length > DEFAULT_MAX_RECORD_BYTES) throw new Error('FEED_RECORD_TOO_LARGE')
    const bytes = input.slice(), hash = createHash('sha256').update(bytes).digest('hex')
    if (this.#statements.payloadByHash.get(hash) === undefined) this.#statements.putPayload.run(hash, bytes)
    return hash
  }

  /** Records in local arrival order after `localIndex`, with their indexes. */
  after(localIndex: bigint, limit: number): { readonly index: bigint; readonly record: TransportRecord }[] {
    return (this.#statements.after.all(localIndex, limit) as unknown as RecordRow[])
      .map((row) => ({ index: BigInt(row.local_index), record: rowRecord(row) }))
  }

  /** Signed bytes of one feed after `sequence`, in order. */
  feedAfter(author: string, sequence: bigint, limit: number): { readonly sequence: bigint; readonly raw: Uint8Array }[] {
    return (this.#statements.feedAfter.all(author, sequence, limit) as unknown as { sequence: bigint; raw: Uint8Array }[])
      .map((row) => ({ sequence: row.sequence, raw: Uint8Array.from(row.raw) }))
  }

  heads(): ReadonlyMap<string, bigint> {
    const rows = this.#statements.heads.all() as unknown as { author: string; sequence: bigint }[]
    return new Map(rows.map((row) => [row.author, row.sequence]))
  }

  count(): number {
    return Number((this.#statements.count.get() as { count: bigint }).count)
  }

  maxLocalIndex(): bigint {
    return BigInt((this.#statements.maxIndex.get() as { local_index: bigint }).local_index)
  }

  forkedAuthors(): readonly string[] {
    return (this.#statements.forks.all() as unknown as { author: string }[]).map((row) => row.author)
  }

  putEvidence(input: Uint8Array): { readonly kind: 'appended' | 'duplicate'; readonly index: bigint; readonly evidence: ImmutableEvidence } {
    if (input.length > DEFAULT_MAX_RECORD_BYTES) throw new FeedRecordError('FEED_RECORD_TOO_LARGE')
    const bytes = input.slice()
    const id = recordId(bytes)
    const existing = this.#statements.evidenceById.get(id) as { local_index: bigint } | undefined
    if (existing !== undefined) return { kind: 'duplicate', index: existing.local_index, evidence: { id, bytes } }
    const row = this.#statements.evidenceInsert.get(id, bytes) as { local_index: bigint }
    return { kind: 'appended', index: row.local_index, evidence: { id, bytes } }
  }

  evidenceAfter(after: bigint, limit: number): readonly { readonly index: bigint; readonly evidence: ImmutableEvidence }[] {
    if (after < 0n || !Number.isSafeInteger(limit) || limit < 1 || limit > 4096) throw new Error('FEED_RANGE_INVALID')
    const rows = this.#statements.evidenceAfter.all(after, limit) as unknown as { local_index: bigint; id: string; raw: Uint8Array }[]
    return rows.map((row) => ({ index: row.local_index, evidence: { id: row.id, bytes: Uint8Array.from(row.raw) } }))
  }

  close(): void {
    this.#database.close()
  }
}

function toTransportRecord(record: FeedRecord, receivedAtMs: number): TransportRecord {
  return {
    id: record.id,
    author: record.author,
    sequence: record.sequence,
    ...(record.previous === null ? {} : { previous: record.previous }),
    receivedAtMs,
    payload: Uint8Array.from(record.payload),
  }
}

function rowRecord(row: RecordRow): TransportRecord {
  return {
    id: row.id,
    author: row.author,
    sequence: BigInt(row.sequence),
    ...(row.previous === null ? {} : { previous: row.previous }),
    receivedAtMs: Number(row.received_at),
    payload: Uint8Array.from(row.payload),
  }
}

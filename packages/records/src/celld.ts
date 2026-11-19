import type { BytesStore } from './bytes-store.js'
import { sqliteByteLimits, validateSqliteByteKey, type SqliteBytesStoreOptions } from './sqlite-byte-limits.js'

export type CelldBytesStoreOptions = SqliteBytesStoreOptions

type SqlValue = string | number | Uint8Array | null

/** Managed SQLite storage of a single celld Durable Object or SQLite facet. */
export interface CelldBytesStorage {
  readonly sql: {
    exec(query: string, ...bindings: SqlValue[]): { toArray(): Record<string, unknown>[] }
  }
  transactionSync<T>(operation: () => T): T
}

interface Entry {
  readonly key: string
  readonly value: Uint8Array
}

/** Atomic records for the owning object's current activation. */
export class CelldBytesStore implements BytesStore {
  readonly #limits: ReturnType<typeof sqliteByteLimits>
  #closed = false

  constructor(private readonly storage: CelldBytesStorage, options: CelldBytesStoreOptions = {}) {
    this.#limits = sqliteByteLimits(options)
    this.storage.transactionSync(() => {
      this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS chronolog_records (
        key TEXT PRIMARY KEY, value BLOB NOT NULL
      ) STRICT`).toArray()
      this.storage.sql.exec(`CREATE TABLE IF NOT EXISTS chronolog_record_usage (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0)
      ) STRICT`).toArray()
      this.storage.sql.exec(`
        INSERT INTO chronolog_record_usage
        SELECT 1, (SELECT coalesce(sum(length(value)), 0) FROM chronolog_records)
        WHERE NOT EXISTS (SELECT 1 FROM chronolog_record_usage WHERE singleton = 1)
      `).toArray()
    })
  }

  async get(key: string): Promise<Uint8Array | null> {
    this.#assertOpen()
    validateSqliteByteKey(key)
    return this.#read(key)
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.#validate(key, value)
    this.storage.transactionSync(() => this.#write([{ key, value }]))
  }

  /** Persist a device signer and its immutable binding together. */
  async initialize(entries: readonly Entry[]): Promise<void> {
    this.#assertOpen()
    if (entries.length === 0 || entries.length > 8 || new Set(entries.map(({ key }) => key)).size !== entries.length) {
      throw new Error('BYTES_STORE_INITIALIZATION_INVALID')
    }
    for (const { key, value } of entries) this.#validate(key, value)
    this.storage.transactionSync(() => {
      if (entries.every(({ key }) => this.#size(key) === null)) this.#write(entries)
    })
  }

  async compareAndSwap(key: string, expected: Uint8Array | null, value: Uint8Array): Promise<boolean> {
    this.#validate(key, value)
    return this.storage.transactionSync(() => {
      const current = this.#read(key)
      const matches = expected === null
        ? current === null
        : current !== null && expected.byteLength === current.byteLength &&
          expected.every((byte, index) => byte === current[index])
      if (matches) this.#write([{ key, value }])
      return matches
    })
  }

  usageBytes(): number {
    this.#assertOpen()
    const value = this.storage.sql.exec('SELECT used_bytes FROM chronolog_record_usage WHERE singleton = 1')
      .toArray()[0]?.used_bytes
    return readNonnegativeBytes(value)
  }

  close(): void { this.#closed = true }

  #assertOpen(): void { if (this.#closed) throw new Error('BYTES_STORE_CLOSED') }

  #validate(key: string, value: Uint8Array): void {
    this.#assertOpen()
    validateSqliteByteKey(key)
    if (!(value instanceof Uint8Array) || value.byteLength > this.#limits.maxValueBytes) {
      throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
    }
  }

  #read(key: string): Uint8Array | null {
    const row = this.storage.sql.exec('SELECT value FROM chronolog_records WHERE key = ?', key).toArray()[0]
    if (!row) return null
    if (row.value instanceof Uint8Array) return Uint8Array.from(row.value)
    if (row.value instanceof ArrayBuffer) return new Uint8Array(row.value.slice(0))
    throw new Error('BYTES_STORE_VALUE_CORRUPT')
  }

  #size(key: string): number | null {
    const row = this.storage.sql.exec('SELECT length(value) AS size FROM chronolog_records WHERE key = ?', key)
      .toArray()[0]
    return row ? readNonnegativeBytes(row.size) : null
  }

  #write(entries: readonly Entry[]): void {
    const used = entries.reduce((bytes, { key, value }) =>
      bytes - (this.#size(key) ?? 0) + value.byteLength, this.usageBytes())
    if (used > this.#limits.quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
    for (const { key, value } of entries) {
      this.storage.sql.exec(
        'INSERT INTO chronolog_records VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
        key, value,
      ).toArray()
    }
    this.storage.sql.exec('UPDATE chronolog_record_usage SET used_bytes = ? WHERE singleton = 1', used).toArray()
  }
}

function readNonnegativeBytes(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    throw new Error('BYTES_STORE_USAGE_CORRUPT')
  return value
}

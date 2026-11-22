import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import type { BytesStore } from './bytes-store.js'

export interface NativeBytesStoreOptions {
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}

/**
 * One native storage owner for records, authority state, outboxes and local
 * consumer checkpoints. Each durable atomic key replacement shares the
 * same BytesStore contract. SQLite holds the exclusive writer fence until close (also
 * across processes); a process crash releases it without a stale lock file.
 */
export class NativeBytesStore implements BytesStore {
  readonly #database: DatabaseSync
  readonly #quotaBytes: number
  readonly #maxValueBytes: number
  #usedBytes = 0
  #closed = false

  constructor(path: string, options: NativeBytesStoreOptions = {}) {
    this.#quotaBytes = options.quotaBytes ?? 256 * 1024 * 1024
    this.#maxValueBytes = options.maxValueBytes ?? 128 * 1024 * 1024
    for (const value of [this.#quotaBytes, this.#maxValueBytes]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error('BYTES_STORE_QUOTA_INVALID')
    }
    if (path.length === 0) throw new Error('BYTES_STORE_PATH_REQUIRED')
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
    this.#database = new DatabaseSync(path)
    try {
      // In WAL mode an exclusive connection retains its file lock after the
      // initial commit, fencing every process until the owner closes.
      this.#database.exec('PRAGMA busy_timeout = 0')
      this.#database.exec('PRAGMA locking_mode = EXCLUSIVE')
      this.#database.exec('PRAGMA journal_mode = WAL')
      this.#database.exec('PRAGMA synchronous = FULL')
      this.#database.exec('BEGIN EXCLUSIVE')
      this.#database.exec(`CREATE TABLE IF NOT EXISTS stored_bytes (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
      )`)
      this.#database.exec('COMMIT')
      // An exclusive owner accounts once on reopen. Appending one value must
      // not scan every retained body merely to enforce its storage quota.
      this.#usedBytes = (this.#database.prepare('SELECT coalesce(sum(length(value)), 0) AS bytes FROM stored_bytes').get() as { bytes: number }).bytes
    } catch (error) {
      try { this.#database.close() } catch { /* failed opening */ }
      if (/locked|busy/iu.test(error instanceof Error ? error.message : '')) {
        throw new Error('BYTES_STORE_IN_USE', { cause: error })
      }
      throw error
    }
  }

  async get(key: string): Promise<Uint8Array | null> {
    this.#assertOpen()
    validateKey(key)
    const row = this.#database.prepare('SELECT value FROM stored_bytes WHERE key = ?').get(key) as
      { value: Uint8Array } | undefined
    return row === undefined ? null : Uint8Array.from(row.value)
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.#assertOpen()
    validateKey(key)
    if (!(value instanceof Uint8Array) || value.byteLength > this.#maxValueBytes) throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
    this.#database.exec('BEGIN IMMEDIATE')
    try {
      const previous = this.#database.prepare('SELECT length(value) AS bytes FROM stored_bytes WHERE key = ?').get(key) as
        { bytes: number } | undefined
      const used = this.#usedBytes - (previous?.bytes ?? 0) + value.byteLength
      if (used > this.#quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
      this.#database.prepare('INSERT INTO stored_bytes (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        .run(key, value)
      this.#database.exec('COMMIT')
      this.#usedBytes = used
    } catch (error) {
      this.#database.exec('ROLLBACK')
      throw error
    }
  }

  async putAllIfEmpty(entries: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<boolean> {
    this.#assertOpen()
    let bytes = 0
    const seen = new Set<string>()
    for (const entry of entries) {
      validateKey(entry.key)
      if (!(entry.value instanceof Uint8Array) || entry.value.byteLength > this.#maxValueBytes) throw new Error('BYTES_STORE_VALUE_TOO_LARGE')
      if (seen.has(entry.key)) throw new Error('BYTES_STORE_DUPLICATE_KEY')
      seen.add(entry.key); bytes += entry.value.byteLength
    }
    if (bytes > this.#quotaBytes) throw new Error('BYTES_STORE_QUOTA_EXCEEDED')
    this.#database.exec('BEGIN IMMEDIATE')
    try {
      if ((this.#database.prepare('SELECT count(*) AS count FROM stored_bytes').get() as { count: number }).count !== 0) {
        this.#database.exec('COMMIT'); return false
      }
      const insert = this.#database.prepare('INSERT INTO stored_bytes (key, value) VALUES (?, ?)')
      for (const entry of entries) insert.run(entry.key, entry.value)
      this.#database.exec('COMMIT'); this.#usedBytes = bytes; return true
    } catch (error) { this.#database.exec('ROLLBACK'); throw error }
  }
  async entries(): Promise<readonly { readonly key: string; readonly value: Uint8Array }[]> {
    this.#assertOpen()
    const rows = this.#database.prepare('SELECT key, value FROM stored_bytes ORDER BY key ASC').all() as
      { key: string; value: Uint8Array }[]
    return rows.map(row => ({ key: row.key, value: Uint8Array.from(row.value) }))
  }

  /** Flush WAL frames cleanly into the main database file before external snapshot/backup. */
  checkpointWal(): void {
    this.#assertOpen()
    this.#database.exec('PRAGMA wal_checkpoint(TRUNCATE)')
  }

  usageBytes(): number {
    this.#assertOpen()
    return this.#usedBytes
  }

  close(): void {
    if (this.#closed) return
    this.#database.close()
    this.#closed = true
  }

  #assertOpen(): void { if (this.#closed) throw new Error('BYTES_STORE_CLOSED') }
}

function validateKey(key: string): void {
  if (key.length === 0 || key.length > 2048 || [...key].some((character) => character.charCodeAt(0) < 32)) throw new Error('BYTES_STORE_KEY_INVALID')
}

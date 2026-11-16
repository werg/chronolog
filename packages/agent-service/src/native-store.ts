import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import type { DurableOperationStore } from '@chronolog/node-core'

export interface NativeAgentStoreOptions {
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}

/**
 * One native storage owner for records, authority state, outboxes and local
 * consumer checkpoints. This implements the same atomic bytes port used by
 * DurableFeedStore. SQLite holds the exclusive writer fence until close (also
 * across processes); a process crash releases it without a stale lock file.
 */
export class NativeAgentStore implements DurableOperationStore {
  readonly #database: DatabaseSync
  readonly #quotaBytes: number
  readonly #maxValueBytes: number
  #closed = false

  constructor(path: string, options: NativeAgentStoreOptions = {}) {
    this.#quotaBytes = options.quotaBytes ?? 256 * 1024 * 1024
    this.#maxValueBytes = options.maxValueBytes ?? 128 * 1024 * 1024
    for (const value of [this.#quotaBytes, this.#maxValueBytes]) {
      if (!Number.isSafeInteger(value) || value < 1) throw new Error('AGENT_STORE_QUOTA_INVALID')
    }
    if (path.length === 0) throw new Error('AGENT_STORE_PATH_REQUIRED')
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
    this.#database = new DatabaseSync(path)
    try {
      // Match the native FeedStore durability/fencing contract. In WAL mode an
      // exclusive connection retains its file lock after the initial commit.
      this.#database.exec('PRAGMA busy_timeout = 0')
      this.#database.exec('PRAGMA locking_mode = EXCLUSIVE')
      this.#database.exec('PRAGMA journal_mode = WAL')
      this.#database.exec('PRAGMA synchronous = FULL')
      this.#database.exec('BEGIN EXCLUSIVE')
      this.#database.exec(`CREATE TABLE IF NOT EXISTS agent_values (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
      )`)
      this.#database.exec('COMMIT')
    } catch (error) {
      try { this.#database.close() } catch { /* failed opening */ }
      if (/locked|busy/iu.test(error instanceof Error ? error.message : '')) {
        throw new Error('AGENT_STORE_IN_USE', { cause: error })
      }
      throw error
    }
  }

  async get(key: string): Promise<Uint8Array | null> {
    this.#assertOpen()
    validateKey(key)
    const row = this.#database.prepare('SELECT value FROM agent_values WHERE key = ?').get(key) as
      { value: Uint8Array } | undefined
    return row === undefined ? null : Uint8Array.from(row.value)
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.#assertOpen()
    validateKey(key)
    if (!(value instanceof Uint8Array) || value.byteLength > this.#maxValueBytes) throw new Error('AGENT_STORE_VALUE_TOO_LARGE')
    this.#database.exec('BEGIN IMMEDIATE')
    try {
      const used = this.usageBytes()
      const previous = this.#database.prepare('SELECT length(value) AS bytes FROM agent_values WHERE key = ?').get(key) as
        { bytes: number } | undefined
      if (used - (previous?.bytes ?? 0) + value.byteLength > this.#quotaBytes) throw new Error('AGENT_STORE_QUOTA_EXCEEDED')
      this.#database.prepare('INSERT INTO agent_values (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        .run(key, value)
      this.#database.exec('COMMIT')
    } catch (error) {
      this.#database.exec('ROLLBACK')
      throw error
    }
  }

  usageBytes(): number {
    this.#assertOpen()
    return (this.#database.prepare('SELECT coalesce(sum(length(value)), 0) AS bytes FROM agent_values').get() as { bytes: number }).bytes
  }

  close(): void {
    if (this.#closed) return
    this.#database.close()
    this.#closed = true
  }

  #assertOpen(): void { if (this.#closed) throw new Error('AGENT_STORE_CLOSED') }
}

function validateKey(key: string): void {
  if (key.length === 0 || key.length > 2048 || [...key].some((character) => character.charCodeAt(0) < 32)) throw new Error('AGENT_STORE_KEY_INVALID')
}

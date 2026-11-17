// A node's own control state in one SQLite file: the rebuildable control
// index (snapshot plus journal) and the non-rebuildable validator signing
// cutoffs. SQLite provides atomicity and durability, replacing the JSON
// snapshot, line journal and cutoff files with their crash-safety code.
import { existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { ControlStore } from './control-store.js'
import {
  decodeControlStoreSnapshot,
  encodeControlStoreJournalEntry,
  encodeControlStoreSnapshot,
  decodeControlStoreJournal,
} from './persistence.js'
import type {
  ControlStoreJournalEntry,
  ControlStorePersistence,
  ControlStoreSnapshot,
  ValidatorCutoffState,
} from './types.js'

/** One SQLite file of node-local state, shared by the persistence adapters. */
export class NodeStateDatabase {
  readonly database: DatabaseSync

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true })
    this.database = new DatabaseSync(path)
    this.database.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS control_snapshot (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        body TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS control_journal (
        sequence INTEGER PRIMARY KEY,
        entry TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS validator_cutoffs (
        validator_id BLOB PRIMARY KEY,
        accepted_above_ms INTEGER NOT NULL
      );
    `)
  }

  close(): void { this.database.close() }
}

export interface SqliteControlStorePersistenceOptions {
  /** Compact the journal into a fresh snapshot after this many entries. */
  readonly compactAfterEntries?: number
  /** Coalesce journal appends for this long before one durable commit. */
  readonly flushDelayMs?: number
}

export class SqliteControlStorePersistence implements ControlStorePersistence {
  readonly #database: DatabaseSync
  readonly #compactAfterEntries: number
  readonly #flushDelayMs: number
  #pending: ControlStoreJournalEntry[] = []
  #pendingSnapshot: (() => ControlStoreSnapshot) | null = null
  #journalEntries = 0
  #timer: ReturnType<typeof setTimeout> | undefined

  constructor(state: NodeStateDatabase, options: SqliteControlStorePersistenceOptions = {}) {
    this.#database = state.database
    this.#compactAfterEntries = options.compactAfterEntries ?? 1_024
    this.#flushDelayMs = options.flushDelayMs ?? 100
    if (!Number.isSafeInteger(this.#compactAfterEntries) || this.#compactAfterEntries < 1) {
      throw new RangeError('CONTROL_STORE_INVALID_COMPACTION_INTERVAL')
    }
  }

  load(): ControlStoreSnapshot | null {
    this.flush()
    const row = this.#database.prepare('SELECT body FROM control_snapshot WHERE singleton = 1').get() as { body: string } | undefined
    return row === undefined ? null : decodeControlStoreSnapshot(row.body)
  }

  save(snapshot: ControlStoreSnapshot): void {
    this.#pending = []
    this.#transaction(() => {
      this.#database.prepare('INSERT OR REPLACE INTO control_snapshot (singleton, body) VALUES (1, ?)').run(encodeControlStoreSnapshot(snapshot))
      this.#database.exec('DELETE FROM control_journal')
    })
    this.#journalEntries = 0
  }

  loadJournal(): readonly ControlStoreJournalEntry[] {
    const rows = this.#database.prepare('SELECT entry FROM control_journal ORDER BY sequence').all() as { entry: string }[]
    this.#journalEntries = rows.length
    return decodeControlStoreJournal(rows.map((row) => row.entry).join(''))
  }

  journalPresent(): boolean {
    return this.#journalEntries > 0
  }

  appendJournal(entry: ControlStoreJournalEntry): boolean {
    this.#pending.push(entry)
    this.#journalEntries += 1
    this.#schedule()
    return this.#journalEntries >= this.#compactAfterEntries
  }

  requestSave(snapshot: () => ControlStoreSnapshot): void {
    this.#pendingSnapshot = snapshot
    this.#schedule()
  }

  flush(): void {
    if (this.#timer !== undefined) {
      clearTimeout(this.#timer)
      this.#timer = undefined
    }
    const snapshot = this.#pendingSnapshot
    this.#pendingSnapshot = null
    if (snapshot !== null) {
      this.save(snapshot())
      return
    }
    if (this.#pending.length === 0) return
    const entries = this.#pending
    this.#transaction(() => {
      const insert = this.#database.prepare('INSERT OR REPLACE INTO control_journal (sequence, entry) VALUES (?, ?)')
      for (const entry of entries) insert.run(entry.sequence, encodeControlStoreJournalEntry(entry))
    })
    this.#pending = []
  }

  loadValidatorCutoffs(): readonly ValidatorCutoffState[] {
    const rows = this.#database.prepare('SELECT validator_id, accepted_above_ms FROM validator_cutoffs ORDER BY validator_id')
    rows.setReadBigInts(true)
    return (rows.all() as { validator_id: Uint8Array; accepted_above_ms: bigint }[])
      .map((row) => ({ validatorId: Uint8Array.from(row.validator_id), acceptedAboveMs: row.accepted_above_ms }))
  }

  /** Durable before it returns; a cutoff never moves backwards. */
  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    this.#transaction(() => this.#raiseCutoff(cutoff))
  }

  #raiseCutoff(cutoff: ValidatorCutoffState): void {
    const current = this.#database.prepare('SELECT accepted_above_ms FROM validator_cutoffs WHERE validator_id = ?')
    current.setReadBigInts(true)
    const row = current.get(cutoff.validatorId) as { accepted_above_ms: bigint } | undefined
    if (row !== undefined && cutoff.acceptedAboveMs < row.accepted_above_ms) {
      throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
    }
    if (row?.accepted_above_ms === cutoff.acceptedAboveMs) return
    this.#database.prepare('INSERT OR REPLACE INTO validator_cutoffs (validator_id, accepted_above_ms) VALUES (?, ?)')
      .run(cutoff.validatorId, cutoff.acceptedAboveMs)
  }

  #transaction(operation: () => void): void {
    this.#database.exec('BEGIN IMMEDIATE')
    try {
      operation()
      this.#database.exec('COMMIT')
    } catch (error) {
      this.#database.exec('ROLLBACK')
      throw error
    }
  }

  #schedule(): void {
    if (this.#timer !== undefined) return
    this.#timer = setTimeout(() => {
      this.#timer = undefined
      this.flush()
    }, this.#flushDelayMs)
    this.#timer.unref?.()
  }
}

/**
 * Reads the effective control index (snapshot plus journal) from a node-state
 * file without writing to it. For inspection tools; null when absent.
 */
export function readNodeStateControlSnapshot(path: string): ControlStoreSnapshot | null {
  if (!existsSync(path)) return null
  const database = new DatabaseSync(path, { readOnly: true })
  try {
    const row = database.prepare('SELECT body FROM control_snapshot WHERE singleton = 1').get() as { body: string } | undefined
    const snapshot = row === undefined ? null : decodeControlStoreSnapshot(row.body)
    const rows = database.prepare('SELECT entry FROM control_journal ORDER BY sequence').all() as { entry: string }[]
    const journal = decodeControlStoreJournal(rows.map((entry) => entry.entry).join(''))
    if (snapshot === null && journal.length === 0) return null
    return new ControlStore({ load: () => snapshot, save: () => {}, loadJournal: () => journal }).snapshot()
  } finally { database.close() }
}

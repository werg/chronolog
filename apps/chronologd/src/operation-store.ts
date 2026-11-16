import type { DatabaseSync } from 'node:sqlite'

import type { DurableOperationStore } from '@chronolog/node-core'

/** Shares the daemon's FULL-synchronous node-state SQLite database. */
export class SqliteOperationStore implements DurableOperationStore {
  readonly #database: DatabaseSync

  constructor(database: DatabaseSync) {
    this.#database = database
    database.exec(`CREATE TABLE IF NOT EXISTS local_operations (
      operation_key TEXT PRIMARY KEY,
      body BLOB NOT NULL
    )`)
  }

  async get(key: string): Promise<Uint8Array | null> {
    const row = this.#database.prepare('SELECT body FROM local_operations WHERE operation_key = ?').get(key) as
      { readonly body: Uint8Array } | undefined
    return row === undefined ? null : Uint8Array.from(row.body)
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    this.#database.prepare('INSERT INTO local_operations (operation_key, body) VALUES (?, ?) ON CONFLICT(operation_key) DO UPDATE SET body = excluded.body')
      .run(key, value)
  }
}

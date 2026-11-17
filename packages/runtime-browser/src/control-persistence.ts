import {
  decodeControlStoreSnapshot, encodeControlStoreSnapshot,
  type ControlStorePersistence, type ControlStoreSnapshot, type ValidatorCutoffState,
} from '@chronolog/control-store/browser'
import type { DatabaseLike, StatementLike } from '@chronolog/materializer-doltlite/browser'

/**
 * Private control state in an independent OPFS SQL database. Synchronous FULL
 * commits complete before admission cutoffs or control changes are acknowledged.
 * A failed commit retains the previous SQLite transaction; no async write-behind
 * participates in validator signing decisions.
 */
export class BrowserControlPersistence implements ControlStorePersistence {
  readonly #database: DatabaseLike

  constructor(database: DatabaseLike) {
    this.#database = database
    try { database.exec(`
      PRAGMA journal_mode = DELETE;
      PRAGMA synchronous = FULL;
      CREATE TABLE IF NOT EXISTS private_control_snapshot (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), body TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS private_validator_cutoffs (
        validator_id BLOB PRIMARY KEY, accepted_above_ms INTEGER NOT NULL
      );
    `) } catch (error) { database.close(); throw error }
  }

  load(): ControlStoreSnapshot | null {
    const row = this.#statement('SELECT body FROM private_control_snapshot WHERE singleton = 1', (statement) => statement.get()) as { body: string } | undefined
    return row === undefined ? null : decodeControlStoreSnapshot(row.body)
  }

  save(snapshot: ControlStoreSnapshot): void {
    this.#transaction(() => this.#statement(
      'INSERT OR REPLACE INTO private_control_snapshot(singleton,body) VALUES(1,?)',
      (statement) => { statement.run(encodeControlStoreSnapshot(snapshot)) },
    ))
  }

  loadValidatorCutoffs(): readonly ValidatorCutoffState[] {
    return this.#statement('SELECT validator_id, accepted_above_ms FROM private_validator_cutoffs', (statement) => {
      statement.setReadBigInts?.(true)
      return statement.all().map((value) => {
        const row = value as { validator_id: Uint8Array; accepted_above_ms: bigint }
        if (!(row.validator_id instanceof Uint8Array) || row.validator_id.length !== 32 || typeof row.accepted_above_ms !== 'bigint') {
          throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_INVALID')
        }
        return { validatorId: row.validator_id.slice(), acceptedAboveMs: row.accepted_above_ms }
      })
    })
  }

  saveValidatorCutoff(cutoff: ValidatorCutoffState): void {
    if (cutoff.validatorId.length !== 32 || cutoff.acceptedAboveMs < 0n) throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_INVALID')
    this.#transaction(() => {
      const previous = this.#statement('SELECT accepted_above_ms FROM private_validator_cutoffs WHERE validator_id = ?', (statement) => {
        statement.setReadBigInts?.(true)
        return statement.get(cutoff.validatorId) as { accepted_above_ms: bigint } | undefined
      })
      if (previous !== undefined && cutoff.acceptedAboveMs < previous.accepted_above_ms) throw new Error('CONTROL_STORE_VALIDATOR_CUTOFF_REGRESSION')
      this.#statement('INSERT OR REPLACE INTO private_validator_cutoffs(validator_id,accepted_above_ms) VALUES(?,?)',
        (statement) => { statement.run(cutoff.validatorId, cutoff.acceptedAboveMs) })
    })
  }

  close(): void { this.#database.close() }

  #transaction(operation: () => void): void {
    this.#database.exec('BEGIN IMMEDIATE')
    try { operation(); this.#database.exec('COMMIT') }
    catch (error) { if (this.#database.inTransaction) this.#database.exec('ROLLBACK'); throw error }
  }

  #statement<T>(sql: string, operation: (statement: StatementLike) => T): T {
    const statement = this.#database.prepare(sql)
    try { return operation(statement) } finally { statement.finalize?.() }
  }
}

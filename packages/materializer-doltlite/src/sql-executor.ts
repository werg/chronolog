import type { SqlStatement, SqlTransactionProgram, SqlValue } from '@chronolog/protocol'

import { isOperationalSqliteError, SqlProfileError, sqlitePrimaryCode, withProfiledStatement } from './sql-profile.js'
import type { DatabaseLike, SqlRuntimeLimits, StatementLike } from './types.js'

/** A deterministic reason a transaction is rejected; recorded in the log. */
export class SqlRejection extends Error {
  constructor(readonly code: string, readonly statementIndex: number) {
    super(`${code} (statement ${statementIndex})`)
    this.name = 'SqlRejection'
  }
}

export interface DeterministicContext {
  /** The value of 'now': the transaction's signed author timestamp. */
  readonly authorTimestampMs: bigint
  /** Seeds random()/randomblob(); derived from the transaction id. */
  readonly txId: Uint8Array
}

const SQLITE_CONSTRAINT = 19
const SQLITE_CONSTRAINT_FUNCTION = 19 | (4 << 8)
const SQLITE_TOOBIG = 18
const SQLITE_MISMATCH = 20
const SQLITE_RANGE = 25
const ASSERT_PREFIX = 'chronolog_assert:'

/**
 * Execute a transaction program as ordinary SQLite statements with the
 * engine's non-SQL inputs pinned to the transaction. Throws SqlRejection for
 * a deterministic failure; any other error is operational and stops replay.
 * Must run synchronously: the pinned clock and PRNG are process-global.
 */
export function executeTransactionProgram(
  database: DatabaseLike,
  program: SqlTransactionProgram,
  context: DeterministicContext,
  limits: Partial<SqlRuntimeLimits> = {},
): void {
  database.setDeterministicContext(context.authorTimestampMs, prngSeed(context.txId))
  try {
    resetChangeCounter(database)
    for (const [index, statement] of program.statements.entries()) {
      executeStatement(database, statement, index, limits)
    }
  } finally {
    database.clearDeterministicContext()
  }
}

function executeStatement(
  database: DatabaseLike,
  statement: SqlStatement,
  index: number,
  limits: Partial<SqlRuntimeLimits>,
): void {
  try {
    withProfiledStatement(database, statement.sql, 'consensus', (prepared) => {
      prepared.run(bindingArray(prepared, statement, index))
    }, limits)
  } catch (error) {
    throw rejectionFor(error, index)
  }
}

/** Positional values for every parameter SQLite found in the statement. */
function bindingArray(prepared: StatementLike, statement: SqlStatement, index: number): unknown[] {
  const count = prepared.parameterCount
  const values: unknown[] = new Array<unknown>(count)
  const bound = new Array<boolean>(count).fill(false)
  for (const binding of statement.bindings) {
    const position = binding.parameter.kind === 'index'
      ? binding.parameter.index
      : prepared.parameterIndex(binding.parameter.name)
    if (position < 1 || position > count || bound[position - 1] === true) throw new SqlRejection('binding', index)
    values[position - 1] = toDatabaseValue(binding.value)
    bound[position - 1] = true
  }
  if (bound.some((value) => !value)) throw new SqlRejection('binding', index)
  return values
}

export function toDatabaseValue(value: SqlValue): unknown {
  switch (value.kind) {
    case 'null': return null
    case 'integer': return value.value
    // A one-element Float64Array binds as an exact REAL even when integral.
    case 'real': return Float64Array.of(value.value)
    case 'text': return value.value
    case 'blob': return Buffer.from(value.value.buffer, value.value.byteOffset, value.value.byteLength)
  }
}

function rejectionFor(error: unknown, index: number): Error {
  if (error instanceof SqlRejection) return error
  if (error instanceof SqlProfileError) {
    switch (error.code) {
      case 'SQL_STEP_LIMIT': return new SqlRejection('step_limit', index)
      case 'SQL_PROFILE_VIOLATION': return new SqlRejection('denied', index)
      case 'SQL_STATEMENT_TOO_LARGE': return new SqlRejection('too_large', index)
      default: return new SqlRejection('prepare', index)
    }
  }
  if (isOperationalSqliteError(error)) return error instanceof Error ? error : new Error(String(error))
  const extended = sqliteExtendedCode(error)
  const message = error instanceof Error ? error.message : ''
  const assertAt = message.indexOf(ASSERT_PREFIX)
  if (extended === SQLITE_CONSTRAINT_FUNCTION && assertAt >= 0) {
    return new SqlRejection(`assert:${message.slice(assertAt + ASSERT_PREFIX.length)}`, index)
  }
  switch (sqlitePrimaryCode(error)) {
    case SQLITE_CONSTRAINT: return new SqlRejection('constraint', index)
    case SQLITE_TOOBIG: return new SqlRejection('too_large', index)
    case SQLITE_MISMATCH: return new SqlRejection('mismatch', index)
    case SQLITE_RANGE: return new SqlRejection('binding', index)
    case null: return error instanceof Error ? error : new Error(String(error))
    default: return new SqlRejection('error', index)
  }
}

function sqliteExtendedCode(error: unknown): number | null {
  if (typeof error !== 'object' || error === null) return null
  const value = (error as Record<string, unknown>).sqliteExtendedCode ?? (error as Record<string, unknown>).errcode
  return typeof value === 'number' ? value : null
}

/** A nonzero 32-bit PRNG seed from the transaction id. */
export function prngSeed(txId: Uint8Array): number {
  let seed = 0
  for (let index = 0; index < Math.min(4, txId.length); index += 1) seed = (seed * 256 + txId[index]!) >>> 0
  return seed === 0 ? 1 : seed
}

/**
 * changes() reports the last completed INSERT/UPDATE/DELETE on the
 * connection, which differs between incremental execution and replay. A
 * no-op DELETE resets it to 0 before the transaction's first statement.
 */
function resetChangeCounter(database: DatabaseLike): void {
  database.prepare('DELETE FROM chronolog_execution_manifest WHERE 0').run()
}

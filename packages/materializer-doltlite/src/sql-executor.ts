import { isPlatformOp, type SqlStatement, type SqlTransactionProgram } from '@chronolog/protocol'

import { cachedInternalStatement, PlatformRejection, PlatformSession, toDatabaseValue, writeProtectedTables, lifecycleTriggerNames } from './platform/session.js'
import { isOperationalSqliteError, SqlProfileError, sqlitePrimaryCode, withProfiledStatement, type SqlAuthorizationOptions } from './sql-profile.js'
import type { DatabaseLike, SqlRuntimeLimits, StatementLike } from './types.js'

export { toDatabaseValue }

/** A deterministic reason a transaction is rejected; recorded in the log. */
export class SqlRejection extends Error {
  /** `statementIndex` is the failing step, or null for whole-transaction checks. */
  constructor(readonly code: string, readonly statementIndex: number | null) {
    super(statementIndex === null ? code : `${code} (step ${statementIndex})`)
    this.name = 'SqlRejection'
  }
}

export interface DeterministicContext {
  /** The value of 'now': the transaction's signed author timestamp. */
  readonly authorTimestampMs: bigint
  /** Seeds random()/randomblob(); derived from the transaction id. */
  readonly txId: Uint8Array
  /** The signing key: chronolog_actor() and the owner of new rows. */
  readonly actor: Uint8Array
  /** Binds sealed ciphertext to this replication group. */
  readonly groupId: Uint8Array
}

const SQLITE_CONSTRAINT = 19
const SQLITE_CONSTRAINT_FUNCTION = 19 | (4 << 8)
const SQLITE_TOOBIG = 18
const SQLITE_MISMATCH = 20
const SQLITE_RANGE = 25
const ASSERT_PREFIX = 'chronolog_assert:'
const POLICY_PREFIX = 'chronolog_policy:'

/**
 * Execute a transaction program as its signer: SQL steps as ordinary SQLite
 * statements, platform operations through trusted platform code, with the
 * engine's non-SQL inputs pinned to the transaction. A transaction that
 * changed the schema is reconciled before it may commit. Throws SqlRejection
 * for a deterministic failure; any other error is operational and stops
 * replay. Must run synchronously: the pinned context is process-global.
 */
export function executeTransactionProgram(
  database: DatabaseLike,
  program: SqlTransactionProgram,
  context: DeterministicContext,
  limits: Partial<SqlRuntimeLimits> = {},
): void {
  const platform = new PlatformSession(database, { actor: context.actor, txId: context.txId, groupId: context.groupId, limits })
  // Before the context: it assigns a first-time signer its principal id, which
  // the context pins as chronolog_actor_id().
  const { actorId, schemaAdmin: signerIsSchemaAdmin, schemaVersion: schemaBefore } = platform.begin()
  database.setDeterministicContext(context.authorTimestampMs, prngSeed(context.txId), context.actor, actorId, context.txId)
  try {
    resetChangeCounter(database)
    let schemaAdmin = signerIsSchemaAdmin
    // Reconcile right after every statement that changed the schema, so a new
    // table is owner-checked from the next statement on (§3).
    let reconciledVersion = schemaBefore
    const reconcileIfChanged = (index: number | null): void => {
      if (schemaVersion(database) === reconciledVersion) return
      try {
        platform.reconcile()
      } catch (error) {
        throw rejectionFor(error, index)
      }
      reconciledVersion = schemaVersion(database)
    }
    for (const [index, step] of program.steps.entries()) {
      if (isPlatformOp(step)) {
        try {
          platform.execute(step, index)
        } catch (error) {
          throw rejectionFor(error, index)
        }
        schemaAdmin = platform.isSchemaAdmin()
      } else {
        executeStatement(database, step, index, limits, { schemaAdmin, writeProtectedTables: writeProtectedTables(database), lifecycleTriggers: lifecycleTriggerNames(database) })
      }
      reconcileIfChanged(index)
    }
    reconcileIfChanged(null)
  } finally {
    database.clearDeterministicContext()
  }
}

function executeStatement(
  database: DatabaseLike,
  statement: SqlStatement,
  index: number,
  limits: Partial<SqlRuntimeLimits>,
  authorization: SqlAuthorizationOptions,
): void {
  try {
    withProfiledStatement(database, statement.sql, 'consensus', (prepared) => {
      prepared.run(bindingArray(prepared, statement, index))
    }, limits, authorization)
  } catch (error) {
    throw rejectionFor(error, index)
  }
}

/** SQLite's schema cookie; every DDL statement changes it. */
function schemaVersion(database: DatabaseLike): number {
  const row = cachedInternalStatement(database, 'PRAGMA schema_version').get()
  if (row === undefined || Array.isArray(row)) throw new Error('MATERIALIZER_SCHEMA_VERSION_UNAVAILABLE')
  return Number(row.schema_version)
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

function rejectionFor(error: unknown, index: number | null): Error {
  if (error instanceof SqlRejection) return error
  if (error instanceof PlatformRejection) return new SqlRejection(error.code, index)
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
  // Only platform triggers can call chronolog_policy_violation (§4).
  const policyAt = message.indexOf(POLICY_PREFIX)
  if (extended === SQLITE_CONSTRAINT_FUNCTION && policyAt >= 0) {
    return new SqlRejection(`policy:${message.slice(policyAt + POLICY_PREFIX.length)}`, index)
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

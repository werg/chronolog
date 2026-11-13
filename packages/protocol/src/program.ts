import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { protocolInvariant } from './errors.js'
import {
  isPlatformOp,
  platformOpFromCanonicalCbor,
  platformOpToCanonicalCbor,
  type PlatformOp,
} from './platform.js'
import {
  assertKnownIntegerKeys,
  expectArray,
  expectMap,
  expectUint64,
  expectVersion,
  integerMap,
  required,
} from './schema.js'
import {
  sqlStatement,
  sqlStatementFromCanonicalCbor,
  sqlStatementToCanonicalCbor,
  type SqlStatement,
} from './sql.js'

/** One step of a transaction program: an ordinary SQLite statement or a platform operation. */
export type ProgramStep = SqlStatement | PlatformOp

/** Steps executed in order as the signer; any failure rejects the whole transaction. */
export interface SqlTransactionProgram {
  readonly version: 2
  readonly steps: readonly ProgramStep[]
}

export const MAX_SQL_PROGRAM_STEPS = 256

export function isSqlStatementStep(step: ProgramStep): step is SqlStatement {
  return !isPlatformOp(step)
}

/** A program from statements, platform operations, or SQL text with parameters. */
export function sqlProgram(...steps: readonly (ProgramStep | string)[]): SqlTransactionProgram {
  const program: SqlTransactionProgram = {
    version: 2,
    steps: steps.map((step) => typeof step === 'string' ? sqlStatement(step) : step),
  }
  assertValidSqlTransactionProgram(program)
  return program
}

function stepToCbor(step: ProgramStep): CborValue {
  return isPlatformOp(step) ? [1n, platformOpToCanonicalCbor(step)] : [0n, sqlStatementToCanonicalCbor(step)]
}

function stepFromCbor(value: CborValue, name: string): ProgramStep {
  const tuple = expectArray(value, name)
  protocolInvariant(tuple.length === 2, 'SCHEMA_INVALID', `${name} has invalid arity`)
  const kind = expectUint64(tuple[0] ?? null, `${name}.kind`)
  if (kind === 0n) return sqlStatementFromCanonicalCbor(tuple[1] ?? null, `${name}.statement`)
  protocolInvariant(kind === 1n, 'SCHEMA_INVALID', `${name} has an unknown kind`)
  return platformOpFromCanonicalCbor(tuple[1] ?? null, `${name}.platform_op`)
}

export function assertValidSqlTransactionProgram(value: SqlTransactionProgram): void {
  protocolInvariant(value.version === 2, 'UNSUPPORTED_VERSION', 'Unsupported SQL transaction program version')
  protocolInvariant((value.steps as unknown) instanceof Array && value.steps.length > 0, 'SCHEMA_INVALID', 'SQL transaction program requires a step')
  protocolInvariant(value.steps.length <= MAX_SQL_PROGRAM_STEPS, 'SCHEMA_INVALID', 'SQL transaction program has too many steps')
  for (const step of value.steps) stepToCbor(step)
}

export function sqlTransactionProgramToCanonicalCbor(value: SqlTransactionProgram): CborValue {
  assertValidSqlTransactionProgram(value)
  return integerMap([[0, 2n], [1, value.steps.map(stepToCbor)]])
}

export function sqlTransactionProgramFromCanonicalCbor(value: CborValue): SqlTransactionProgram {
  const map = expectMap(value, 'sql_transaction_program')
  assertKnownIntegerKeys(map, [0, 1], 'sql_transaction_program')
  expectVersion(map, 2n, 'sql_transaction_program')
  const program: SqlTransactionProgram = {
    version: 2,
    steps: expectArray(required(map, 1, 'sql_transaction_program.steps'), 'sql_transaction_program.steps')
      .map((step, index) => stepFromCbor(step, `sql_transaction_program.steps[${index}]`)),
  }
  assertValidSqlTransactionProgram(program)
  return program
}

export function encodeSqlTransactionProgram(value: SqlTransactionProgram): Uint8Array {
  return encodeCanonicalCbor(sqlTransactionProgramToCanonicalCbor(value))
}

export function decodeSqlTransactionProgram(bytes: Uint8Array): SqlTransactionProgram {
  return sqlTransactionProgramFromCanonicalCbor(assertCanonicalCbor(bytes))
}

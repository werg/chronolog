import { utf8 } from '@chronolog/protocol'

import type {
  DatabaseLike,
  NativeSecurityConfiguration,
  SqlRuntimeLimits,
  StatementLike,
} from './types.js'

const SQLITE_OK = 0
const SQLITE_DENY = 1
const SQLITE_AUTH = 23
const SQLITE_INTERRUPT = 9

const OPERATIONAL_SQLITE_CODES: ReadonlySet<number> = new Set([
  2, // SQLITE_INTERNAL
  3, // SQLITE_PERM
  4, // SQLITE_ABORT
  5, // SQLITE_BUSY
  6, // SQLITE_LOCKED
  7, // SQLITE_NOMEM
  8, // SQLITE_READONLY
  9, // SQLITE_INTERRUPT (deterministic budget interrupts are wrapped earlier)
  10, // SQLITE_IOERR
  11, // SQLITE_CORRUPT
  12, // SQLITE_NOTFOUND
  13, // SQLITE_FULL
  14, // SQLITE_CANTOPEN
  15, // SQLITE_PROTOCOL
  17, // SQLITE_SCHEMA after automatic reprepare failed
  21, // SQLITE_MISUSE
  24, // SQLITE_FORMAT
  26, // SQLITE_NOTADB
])

const ACTION = {
  CREATE_INDEX: 1,
  CREATE_TABLE: 2,
  CREATE_TEMP_INDEX: 3,
  CREATE_TEMP_TABLE: 4,
  CREATE_TEMP_TRIGGER: 5,
  CREATE_TEMP_VIEW: 6,
  CREATE_TRIGGER: 7,
  CREATE_VIEW: 8,
  DELETE: 9,
  DROP_INDEX: 10,
  DROP_TABLE: 11,
  DROP_TEMP_INDEX: 12,
  DROP_TEMP_TABLE: 13,
  DROP_TEMP_TRIGGER: 14,
  DROP_TEMP_VIEW: 15,
  DROP_TRIGGER: 16,
  DROP_VIEW: 17,
  INSERT: 18,
  PRAGMA: 19,
  READ: 20,
  SELECT: 21,
  TRANSACTION: 22,
  UPDATE: 23,
  ATTACH: 24,
  DETACH: 25,
  ALTER_TABLE: 26,
  REINDEX: 27,
  ANALYZE: 28,
  CREATE_VTABLE: 29,
  DROP_VTABLE: 30,
  FUNCTION: 31,
  SAVEPOINT: 32,
  RECURSIVE: 33,
} as const

export const SQLITE_LIMIT_CATEGORY = {
  LENGTH: 0,
  SQL_LENGTH: 1,
  COLUMN: 2,
  EXPR_DEPTH: 3,
  COMPOUND_SELECT: 4,
  VDBE_OP: 5,
  FUNCTION_ARG: 6,
  ATTACHED: 7,
  LIKE_PATTERN_LENGTH: 8,
  VARIABLE_NUMBER: 9,
  TRIGGER_DEPTH: 10,
  WORKER_THREADS: 11,
} as const

export const DEFAULT_SQL_RUNTIME_LIMITS: Readonly<SqlRuntimeLimits> = {
  maxSqlBytes: 1_000_000,
  maxVmSteps: 1_000_000,
  progressGranularity: 1_000,
  maxValueBytes: 16 * 1024 * 1024,
  maxResultRows: 10_000,
}

/** Included in the execution-manifest platform digest on every runtime. */
export const SQL_PROFILE_VERSION = 'chronolog-portable-sql-policy-v2'

/**
 * Read-only pragmas whose answers describe replicated SQL state. Build and
 * connection catalogs are separate: native and WASM share SQL semantics while
 * compiling different host adapters and diagnostic registrations.
 */
export const READ_ONLY_PRAGMAS: ReadonlySet<string> = new Set([
  'foreign_key_list', 'index_info', 'index_list', 'index_xinfo',
  'table_info', 'table_list', 'table_xinfo',
  // SQLite runs quick_check itself while executing ALTER TABLE ... ADD COLUMN.
  'quick_check',
])

const LOCAL_DIAGNOSTIC_PRAGMAS: ReadonlySet<string> = new Set([
  'collation_list', 'compile_options', 'function_list', 'module_list', 'pragma_list',
])

/**
 * The consensus block-list: functions whose result depends on connection
 * history, physical storage, Dolt history or the host. Everything else in
 * the pinned engine is allowed; the clock and PRNG are pinned per transaction.
 */
export const CONSENSUS_DENIED_FUNCTIONS: ReadonlySet<string> = new Set([
  'load_extension', 'total_changes', 'sqlite_offset', 'active_branch',
  'sqlite_compileoption_get', 'sqlite_compileoption_used', 'sqlite_source_id',
])

/** Virtual-table modules that read physical storage rather than SQL state. */
export const CONSENSUS_DENIED_MODULES: ReadonlySet<string> = new Set(['dbstat', 'sqlite_dbpage', 'sqlite_stmt'])

/** Local SQL is not replayed, so only external effects and Dolt control are denied. */
export const FORBIDDEN_LOCAL_READ_FUNCTIONS: ReadonlySet<string> = new Set([
  'active_branch',
  'load_extension',
])

export type SqlAuthorizationMode =
  | 'internal_bootstrap'
  | 'consensus'
  /** Trusted platform operations: may write chronolog_* objects. App triggers they fire stay under consensus rules. */
  | 'platform'
  | 'local_read'

export interface SqlAuthorizationOptions {
  /** The signer is an admin of the `group` collective and may run DDL. */
  readonly schemaAdmin?: boolean
  /**
   * Lower-case names of tables that carry no owner checks (virtual tables and
   * sqlite-vec chunk tables). App SQL may write them only from app triggers,
   * which fire on owner-checked writes to registered tables.
   */
  readonly writeProtectedTables?: ReadonlySet<string>
  /**
   * Lower-case names of SQLite shadow tables (owned by virtual-table modules).
   * Local reads let a module prepare its own writes to them (R-tree prepares
   * them on connect); defensive mode keeps them read-only to app SQL, and
   * writes to the virtual tables themselves stay denied.
   */
  readonly shadowTables?: ReadonlySet<string>
}

/**
 * Whether the statement is being prepared (app SQL, including trigger bodies,
 * is authorized then) or stepped (only SQL that virtual-table modules prepare
 * internally is authorized then).
 */
interface StatementPhase { stepping: boolean }

/** Pragmas FTS5 and R-tree read internally; never available to app SQL. */
const MODULE_INTERNAL_PRAGMAS: ReadonlySet<string> = new Set(['data_version', 'page_size'])

/** Raises a policy rejection; callable only from chronolog_* triggers and views. */
export const POLICY_VIOLATION_FUNCTION = 'chronolog_policy_violation'
/** The owner column every registered table carries. */
export const OWNER_COLUMN = 'chronolog_owner'

/** Names owned by SQLite, Dolt or Chronolog rather than the application. */
export function isReservedSchemaObjectName(value: string): boolean {
  const key = asciiLower(value)
  return key.startsWith('chronolog_') || key.startsWith('sqlite_') || key.startsWith('dolt_') ||
    key.startsWith('doltlite_') || key.startsWith('pragma_') || CONSENSUS_DENIED_MODULES.has(key)
}

export class SqlProfileError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'SqlProfileError'
  }
}

export function normalizeSqlRuntimeLimits(input: Partial<SqlRuntimeLimits> = {}): SqlRuntimeLimits {
  const limits = { ...DEFAULT_SQL_RUNTIME_LIMITS, ...input }
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new SqlProfileError(`SQL_INVALID_LIMIT_${name.toUpperCase()}`)
    }
  }
  if (limits.progressGranularity > limits.maxVmSteps) {
    throw new SqlProfileError('SQL_INVALID_LIMIT_PROGRESS_GRANULARITY')
  }
  return limits
}

/** Apply and verify connection-local sqlite3_limit values. */
export function configureSqliteLimits(
  database: DatabaseLike,
  input: Partial<SqlRuntimeLimits> = {},
): ReadonlyMap<number, number> {
  const limits = normalizeSqlRuntimeLimits(input)
  const requested = new Map<number, number>([
    [SQLITE_LIMIT_CATEGORY.LENGTH, limits.maxValueBytes],
    [SQLITE_LIMIT_CATEGORY.SQL_LENGTH, limits.maxSqlBytes],
    [SQLITE_LIMIT_CATEGORY.COLUMN, 256],
    [SQLITE_LIMIT_CATEGORY.EXPR_DEPTH, 100],
    [SQLITE_LIMIT_CATEGORY.COMPOUND_SELECT, 32],
    [SQLITE_LIMIT_CATEGORY.VDBE_OP, limits.maxVmSteps],
    [SQLITE_LIMIT_CATEGORY.FUNCTION_ARG, 64],
    [SQLITE_LIMIT_CATEGORY.ATTACHED, 0],
    [SQLITE_LIMIT_CATEGORY.LIKE_PATTERN_LENGTH, 10_000],
    [SQLITE_LIMIT_CATEGORY.VARIABLE_NUMBER, 1_000],
    [SQLITE_LIMIT_CATEGORY.TRIGGER_DEPTH, 16],
    [SQLITE_LIMIT_CATEGORY.WORKER_THREADS, 0],
  ])
  const applied = new Map<number, number>()
  for (const [category, requestedValue] of requested) {
    database.setLimit(category, requestedValue)
    const actual = database.setLimit(category, -1)
    if (actual !== requestedValue) throw new SqlProfileError('SQL_NATIVE_LIMIT_MISMATCH')
    applied.set(category, actual)
  }
  return applied
}

/** Fail startup if the native connection did not apply every security bit. */
export function assertNativeSecurityConfiguration(config: NativeSecurityConfiguration): void {
  if (
    !config.defensive ||
    !config.trustedSchema ||
    !config.loadExtension ||
    !config.dqsDml ||
    !config.dqsDdl ||
    !config.qpsg ||
    !config.ftsTokenizer ||
    !config.writableSchema ||
    !config.extendedResultCodes ||
    !config.attachCreate ||
    !config.attachWrite ||
    !config.reverseScanOrder ||
    !config.fpDigits
  ) {
    throw new SqlProfileError('SQL_NATIVE_SECURITY_CONFIGURATION_FAILED')
  }
}

export function prepareProfiledStatement(
  database: DatabaseLike,
  sql: string,
  mode: SqlAuthorizationMode,
  inputLimits: Partial<SqlRuntimeLimits> = {},
  authorization: SqlAuthorizationOptions = {},
): StatementLike {
  const limits = normalizeSqlRuntimeLimits(inputLimits)
  validateSqlSource(sql, limits)
  if (mode === 'consensus' || mode === 'local_read') assertProfilePragma(sql, mode)
  return withProfileControls(database, mode, limits, authorization, () => {
    let statement: StatementLike
    try {
      statement = database.prepare(sql)
    } catch (error) {
      if (isSqlAuthorizationError(error) || isDeniedFeatureError(error, mode)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
      if (isOperationalSqliteError(error)) throw error
      throw new SqlProfileError('SQL_PREPARE_FAILED')
    }
    validateSingleStatement(sql, statement)
    return statement
  })
}

/**
 * Keep authorizer and budget installed through prepare and step. This matters
 * because sqlite3_step() may reprepare after a schema change.
 */
export function withProfiledStatement<T>(
  database: DatabaseLike,
  sql: string,
  mode: SqlAuthorizationMode,
  operation: (statement: StatementLike) => T,
  inputLimits: Partial<SqlRuntimeLimits> = {},
  authorization: SqlAuthorizationOptions = {},
): T {
  const limits = normalizeSqlRuntimeLimits(inputLimits)
  validateSqlSource(sql, limits)
  if (mode === 'consensus' || mode === 'local_read') assertProfilePragma(sql, mode)
  const phase: StatementPhase = { stepping: false }
  return withProfileControls(database, mode, limits, authorization, () => {
    let statement: StatementLike
    try {
      statement = database.prepare(sql)
    } catch (error) {
      if (isSqlAuthorizationError(error) || isDeniedFeatureError(error, mode)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
      if (isOperationalSqliteError(error)) throw error
      throw new SqlProfileError('SQL_PREPARE_FAILED')
    }
    try {
      validateSingleStatement(sql, statement)
      phase.stepping = true
      return operation(statement)
    } finally {
      statement.finalize?.()
    }
  }, phase)
}

export function withAuthorizer<T>(
  database: DatabaseLike,
  mode: SqlAuthorizationMode,
  operation: () => T,
  authorization: SqlAuthorizationOptions = {},
): T {
  database.setAuthorizer(createAuthorizer(mode, authorization))
  try {
    return operation()
  } catch (error) {
    if (isSqlAuthorizationError(error)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
    throw error
  } finally {
    database.setAuthorizer(null)
  }
}

export function withExecutionBudget<T>(
  database: DatabaseLike,
  operation: () => T,
  inputLimits: Partial<SqlRuntimeLimits> = {},
): T {
  const limits = normalizeSqlRuntimeLimits(inputLimits)
  let callbacks = 0
  const maximumCallbacks = Math.max(1, Math.ceil(limits.maxVmSteps / limits.progressGranularity))
  let budgetExceeded = false
  database.setProgressHandler(limits.progressGranularity, () => {
    callbacks += 1
    budgetExceeded = callbacks >= maximumCallbacks
    return budgetExceeded
  })
  try {
    return operation()
  } catch (error) {
    if (budgetExceeded && sqlitePrimaryCode(error) === SQLITE_INTERRUPT) {
      throw new SqlProfileError('SQL_STEP_LIMIT')
    }
    throw error
  } finally {
    database.setProgressHandler(0, null)
  }
}

function withProfileControls<T>(
  database: DatabaseLike,
  mode: SqlAuthorizationMode,
  limits: SqlRuntimeLimits,
  authorization: SqlAuthorizationOptions,
  operation: () => T,
  phase: StatementPhase = { stepping: false },
): T {
  database.setAuthorizer(createAuthorizer(mode, authorization, phase))
  try {
    return withExecutionBudget(database, operation, limits)
  } catch (error) {
    if (isSqlAuthorizationError(error)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
    throw error
  } finally {
    database.setAuthorizer(null)
  }
}

const DDL_ACTIONS: ReadonlySet<number> = new Set([
  ACTION.CREATE_INDEX, ACTION.CREATE_TABLE, ACTION.CREATE_TRIGGER, ACTION.CREATE_VIEW,
  ACTION.DROP_INDEX, ACTION.DROP_TABLE, ACTION.DROP_TRIGGER, ACTION.DROP_VIEW,
  ACTION.CREATE_VTABLE, ACTION.DROP_VTABLE, ACTION.ALTER_TABLE,
])

/**
 * One authorizer per prepared statement. It is stateful only to remember
 * which tables the statement drops: DROP TABLE reports a DROP_TRIGGER for
 * each of the table's triggers, including its platform triggers.
 */
function createAuthorizer(mode: SqlAuthorizationMode, options: SqlAuthorizationOptions = {}, phase: StatementPhase = { stepping: false }) {
  const droppedTables = new Set<string>()
  return (
    action: number,
    arg1: string | null,
    arg2: string | null,
    databaseName: string | null,
    triggerOrView: string | null,
  ): number => {
    const objectName = asciiLower(arg1)
    const secondaryName = asciiLower(arg2)
    const database = asciiLower(databaseName)
    const caller = asciiLower(triggerOrView)
    if (mode === 'internal_bootstrap') {
      return action === ACTION.ATTACH || action === ACTION.DETACH ? SQLITE_DENY : SQLITE_OK
    }
    // Platform code is trusted, and so are the platform's own triggers and
    // views it runs. App triggers fired by a platform statement are compiled
    // inside it; they get exactly the consensus rules.
    const platform = mode === 'platform' && (caller === '' || caller.startsWith('chronolog_'))
    if (platform) {
      return action === ACTION.ATTACH || action === ACTION.DETACH || action === ACTION.TRANSACTION ? SQLITE_DENY : SQLITE_OK
    }
    if (action === ACTION.SELECT || action === ACTION.RECURSIVE) return SQLITE_OK
    if (action === ACTION.FUNCTION) {
      const functionName = secondaryName || objectName
      if (isDoltName(functionName)) return SQLITE_DENY
      // Only platform triggers and views may raise a policy rejection.
      if (functionName === POLICY_VIOLATION_FUNCTION) return caller.startsWith('chronolog_') ? SQLITE_OK : SQLITE_DENY
      if (mode === 'local_read') return FORBIDDEN_LOCAL_READ_FUNCTIONS.has(functionName) ? SQLITE_DENY : SQLITE_OK
      if (functionName.startsWith('pragma_')) {
        return READ_ONLY_PRAGMAS.has(functionName.slice('pragma_'.length)) ? SQLITE_OK : SQLITE_DENY
      }
      return CONSENSUS_DENIED_FUNCTIONS.has(functionName) ? SQLITE_DENY : SQLITE_OK
    }
    if (action === ACTION.PRAGMA) {
      if (isReadOnlyPragma(objectName, mode)) return SQLITE_OK
      // A virtual-table module's own query (no caller, no value set). App SQL
      // cannot issue these: inside views and triggers the caller is set, and
      // top-level SQL naming them (PRAGMA statements and pragma_* table
      // functions) is refused by its text before it is prepared
      // (assertProfilePragma), since data_version differs between replicas.
      const moduleInternal = caller === '' && secondaryName === '' && MODULE_INTERNAL_PRAGMAS.has(objectName)
      return moduleInternal ? SQLITE_OK : SQLITE_DENY
    }
    if (action === ACTION.READ) {
      // SQLite may omit the database name on follow-on READ callbacks.
      if (database !== '' && database !== 'main' && database !== 'temp') return SQLITE_DENY
      // Dolt system tables expose per-replica history (commit hashes, times).
      if (mode !== 'local_read' && (isDoltName(objectName) || CONSENSUS_DENIED_MODULES.has(objectName))) return SQLITE_DENY
      if (mode !== 'local_read' && objectName.startsWith('pragma_') && !READ_ONLY_PRAGMAS.has(objectName.slice('pragma_'.length))) return SQLITE_DENY
      return SQLITE_OK
    }
    if (mode === 'local_read') {
      const moduleShadowWrite = (action === ACTION.INSERT || action === ACTION.UPDATE || action === ACTION.DELETE) &&
        caller === '' && database === 'main' && options.shadowTables?.has(objectName) === true
      return moduleShadowWrite ? SQLITE_OK : SQLITE_DENY
    }
    // ── consensus writes ──
    if (action === ACTION.INSERT || action === ACTION.UPDATE || action === ACTION.DELETE) {
      // SQLite maintains its own catalogs (sqlite_schema, sqlite_sequence,
      // sqlite_stat1, the temp catalog) while executing DDL and DML.
      if (objectName.startsWith('sqlite_')) return database === 'main' || database === 'temp' ? SQLITE_OK : SQLITE_DENY
      if (database !== 'main') return SQLITE_DENY
      // Tables without owner checks: app SQL writes them only from app triggers.
      // Writes their modules make while the statement runs are their own.
      if (options.writeProtectedTables?.has(objectName) === true && !phase.stepping && (caller === '' || caller.startsWith('chronolog_'))) {
        return SQLITE_DENY
      }
      return isReservedSchemaObjectName(objectName) ? SQLITE_DENY : SQLITE_OK
    }
    // The first ANALYZE creates SQLite's own statistics table; any writer may ANALYZE.
    // AUTOINCREMENT (including sqlite-vec's shadow tables) creates sqlite_sequence.
    if (action === ACTION.CREATE_TABLE && (objectName === 'sqlite_stat1' || objectName === 'sqlite_stat4' || objectName === 'sqlite_sequence')) {
      return database === 'main' ? SQLITE_OK : SQLITE_DENY
    }
    // All other DDL, including triggers, is for schema administrators only.
    if (DDL_ACTIONS.has(action) && options.schemaAdmin !== true) return SQLITE_DENY
    if (
      action === ACTION.CREATE_TABLE || action === ACTION.CREATE_INDEX ||
      action === ACTION.CREATE_VIEW || action === ACTION.CREATE_TRIGGER ||
      action === ACTION.DROP_TABLE || action === ACTION.DROP_INDEX ||
      action === ACTION.DROP_VIEW || action === ACTION.DROP_TRIGGER
    ) {
      if (database !== 'main') return SQLITE_DENY
      // CREATE INDEX reports the table as arg2; implicit autoindexes are SQLite's own.
      if (action === ACTION.CREATE_INDEX && objectName.startsWith('sqlite_autoindex_')) {
        return isReservedSchemaObjectName(secondaryName) ? SQLITE_DENY : SQLITE_OK
      }
      // Dropping an application table drops its platform triggers with it.
      if (action === ACTION.DROP_TRIGGER && objectName.startsWith('chronolog_') && droppedTables.has(secondaryName)) return SQLITE_OK
      if (isReservedSchemaObjectName(objectName)) return SQLITE_DENY
      if (action === ACTION.DROP_TABLE) droppedTables.add(objectName)
      const onTable = action === ACTION.CREATE_INDEX || action === ACTION.CREATE_TRIGGER ||
        action === ACTION.DROP_INDEX || action === ACTION.DROP_TRIGGER
      return onTable && secondaryName !== '' && isReservedSchemaObjectName(secondaryName) ? SQLITE_DENY : SQLITE_OK
    }
    if (action === ACTION.CREATE_VTABLE || action === ACTION.DROP_VTABLE) {
      if (database !== 'main' || isReservedSchemaObjectName(objectName)) return SQLITE_DENY
      return CONSENSUS_DENIED_MODULES.has(secondaryName) ? SQLITE_DENY : SQLITE_OK
    }
    // SQLITE_ALTER_TABLE reports the database and table through arg1/arg2,
    // and DROP COLUMN reports the dropped column as the third argument.
    if (action === ACTION.ALTER_TABLE) {
      if (database === OWNER_COLUMN) return SQLITE_DENY
      return objectName === 'main' && !isReservedSchemaObjectName(secondaryName) ? SQLITE_OK : SQLITE_DENY
    }
    // Both only rebuild derived structures (indexes, sqlite_stat1) from table contents.
    if (action === ACTION.REINDEX || action === ACTION.ANALYZE) return SQLITE_OK
    // Temporary objects, transaction control, savepoints, ATTACH/DETACH and
    // unknown future action codes fail closed.
    return SQLITE_DENY
  }
}

function isDoltName(value: string): boolean {
  return value.startsWith('dolt_') || value.startsWith('doltlite_')
}

function asciiLower(value: string | null): string {
  if (value === null) return ''
  let result = ''
  for (const character of value) {
    const code = character.charCodeAt(0)
    result += code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : character
  }
  return result
}

/**
 * A top-level PRAGMA statement must name a read-only pragma, plainly. The
 * authorizer cannot tell such a statement from a virtual-table module's own
 * pragma query, so it is checked by its text. Anything this does not
 * recognize is refused.
 */
function assertProfilePragma(sql: string, mode: SqlAuthorizationMode): void {
  let rest = sql
  for (;;) {
    const skipped = rest.replace(/^(?:\s+|--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/)/u, '')
    if (skipped === rest) break
    rest = skipped
  }
  // Table-valued forms (pragma_data_version, …) reach the authorizer as
  // PRAGMA actions too. Identifiers cannot be split by comments or escapes,
  // so naming one anywhere in the text is refused (quotes stripped).
  const unquoted = asciiLower(sql).replace(/["`[\]]/gu, '')
  for (const pragma of MODULE_INTERNAL_PRAGMAS) {
    if (unquoted.includes(`pragma_${pragma}`)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
  }
  rest = rest.replace(/^EXPLAIN(?:\s+QUERY\s+PLAN)?\s+/iu, '')
  if (!/^PRAGMA\b/iu.test(rest)) return
  const match = /^PRAGMA\s+(?:main\s*\.\s*)?([A-Za-z_]+)\s*(?:\(\s*[^()]*\)\s*)?;?\s*$/iu.exec(rest)
  if (match === null || !isReadOnlyPragma(match[1]!.toLowerCase(), mode)) throw new SqlProfileError('SQL_PROFILE_VIOLATION')
}

function isReadOnlyPragma(name: string, mode: SqlAuthorizationMode): boolean {
  return READ_ONLY_PRAGMAS.has(name) || mode === 'local_read' && LOCAL_DIAGNOSTIC_PRAGMAS.has(name)
}

/**
 * Some host builds omit a forbidden diagnostic entirely (e.g. WASM omits
 * load_extension). SQLite resolves names before the authorizer sees them, so
 * absence or a wrong argument count must produce the same policy rejection as
 * an existing denied name. Both errors can precede authorizer callbacks.
 * Use the parser's resolved error name; do not scan SQL literals or aliases.
 */
function isDeniedFeatureError(error: unknown, mode: SqlAuthorizationMode): boolean {
  if (mode === 'internal_bootstrap' || !(error instanceof Error)) return false
  const arity = /\bwrong number of arguments to function ([A-Za-z_][A-Za-z_0-9]*)\(\)/iu.exec(error.message)
  if (arity !== null) return isDeniedFunction(asciiLower(arity[1]!), mode)
  const match = /\bno such (function|table):\s*(?:(?:main|temp)\.)?([A-Za-z_][A-Za-z_0-9]*)\b/iu.exec(error.message)
  if (match === null) return false
  const name = asciiLower(match[2]!)
  if (match[1]!.toLowerCase() === 'function') return isDeniedFunction(name, mode)
  return mode !== 'local_read' && (isDoltName(name) || CONSENSUS_DENIED_MODULES.has(name) ||
    name.startsWith('pragma_') && !READ_ONLY_PRAGMAS.has(name.slice('pragma_'.length)))
}

function isDeniedFunction(name: string, mode: SqlAuthorizationMode): boolean {
  if (isDoltName(name)) return true
  return mode === 'local_read' ? FORBIDDEN_LOCAL_READ_FUNCTIONS.has(name) : CONSENSUS_DENIED_FUNCTIONS.has(name)
}

function validateSqlSource(sql: string, limits: SqlRuntimeLimits): void {
  if (sql.includes('\0')) throw new SqlProfileError('SQL_INVALID_SOURCE')
  let bytes: Uint8Array
  try {
    bytes = utf8(sql)
  } catch {
    throw new SqlProfileError('SQL_INVALID_SOURCE')
  }
  if (bytes.length > limits.maxSqlBytes) throw new SqlProfileError('SQL_STATEMENT_TOO_LARGE')
}

function validateSingleStatement(sql: string, statement: StatementLike): void {
  if (!Number.isSafeInteger(statement.tailOffset) || statement.tailOffset < 0) {
    throw new SqlProfileError('SQL_STATEMENT_TAIL_UNAVAILABLE')
  }
  if (utf8(statement.sourceSQL).length !== statement.tailOffset) {
    throw new SqlProfileError('SQL_STATEMENT_TAIL_INVALID')
  }
  const tail = sql.slice(statement.sourceSQL.length)
  if (!isTriviaOnly(tail)) throw new SqlProfileError('SQL_MULTIPLE_STATEMENTS')
}

function isTriviaOnly(text: string): boolean {
  let index = 0
  while (index < text.length) {
    const character = text[index]!
    if (/\s/u.test(character) || character === ';') {
      index += 1
      continue
    }
    if (character === '-' && text[index + 1] === '-') {
      index += 2
      while (index < text.length && text[index] !== '\n' && text[index] !== '\r') index += 1
      continue
    }
    if (character === '/' && text[index + 1] === '*') {
      const end = text.indexOf('*/', index + 2)
      if (end < 0) return false
      index = end + 2
      continue
    }
    return false
  }
  return true
}

function isSqlAuthorizationError(error: unknown): boolean {
  const primary = sqlitePrimaryCode(error)
  if (primary === SQLITE_AUTH) return true
  return typeof error === 'object' && error !== null &&
    'message' in error && typeof (error as { message?: unknown }).message === 'string' &&
    /authoriz|not authorized/u.test((error as { message: string }).message)
}

export function sqlitePrimaryCode(error: unknown): number | null {
  if (typeof error !== 'object' || error === null) return null
  for (const property of ['sqliteCode', 'errcode', 'sqliteExtendedCode'] as const) {
    const value = (error as Record<string, unknown>)[property]
    if (typeof value === 'number' && Number.isInteger(value)) return value & 0xff
  }
  return null
}

/** True when the failure is local/environmental and must abort replay. */
export function isOperationalSqliteError(error: unknown): boolean {
  const primary = sqlitePrimaryCode(error)
  return primary !== null && OPERATIONAL_SQLITE_CODES.has(primary)
}

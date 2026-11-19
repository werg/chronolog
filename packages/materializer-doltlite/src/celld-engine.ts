import { equalBytes } from '@chronolog/canonical'
import type { ExecutionLimits, SqlStatement } from '@chronolog/protocol'
import { digestEngineManifest, normalizeEngineManifest } from './engine-manifest.js'
import { createDoltLiteExecutionManifest } from './manifest.js'
import { toDatabaseValue } from './platform/session.js'
import { NativeSqlRejection, SqlProfileError, normalizeSqlRuntimeLimits } from './sql-profile.js'
import type { DatabaseLike, MaterializerBackendInfo, SqlEngine, SqlRuntimeLimits, StatementLike } from './types.js'

type SqlValue = bigint | number | string | Uint8Array | Float64Array | null
type Binding = ({ readonly index: number } | { readonly name: string }) & { readonly value: SqlValue }
type Statement = { readonly sql: string; readonly bindings: readonly Binding[] }
type QueryOptions = { readonly maxRows: number; readonly limits: Partial<SqlRuntimeLimits> }
type QueryResult = { readonly columns: readonly string[]; readonly rows: readonly (readonly SqlValue[])[] }
type StepResult = {
  readonly result: { readonly outcome: 'accepted' } | { readonly outcome: 'rejected'; readonly code: string }
  readonly changes: bigint
  readonly lastInsertRowid: bigint
  readonly transactionRolledBack: boolean
}
type StorageTransaction = { commit(): void; rollback(): void }
type Snapshot = { readonly ref: string; readonly hash: string }
type PinnedProgram = {
  step(statement: Statement, options: { readonly mode: 'consensus' | 'platform'; readonly schemaAdmin?: boolean }): StepResult
  close(): void
}

/** Synchronous capabilities from a single application-owned celld Dolt store. */
export interface CelldSqlStorage {
  beginTransactionSync(): StorageTransaction
  readonly dolt: {
    programEngineProfile(): {
      readonly engineDigest: string
      readonly sqliteVec: boolean
      readonly manifest: {
        readonly execProfile: string
        readonly doltliteVersion: string
        readonly doltliteReleaseSha256: string
        readonly sqliteVersion: string
        readonly sqliteVecVersion: string
        readonly sqliteVecSourceSha256: string
        readonly fts5: boolean
        readonly json1: boolean
        readonly rtree: boolean
        readonly dynamicExtensions: boolean
      }
    }
    beginProgramTransaction(): StorageTransaction
    pinTransactionProgram(context: {
      readonly nowMs: bigint; readonly seed: number; readonly actor?: Uint8Array;
      readonly actorId?: bigint; readonly transactionId?: Uint8Array; readonly limits: SqlRuntimeLimits
    }): PinnedProgram
    runPlatformTransactionStatement(statement: Statement, options: { readonly limits: SqlRuntimeLimits }): StepResult
    queryPlatformTransaction(sql: string, bindings: readonly Binding[], options: QueryOptions): QueryResult
    query(sql: string, bindings: readonly Binding[], options: QueryOptions): QueryResult
    queryAt(hash: string, sql: string, bindings: readonly Binding[], options: QueryOptions): QueryResult
    triggerUsesIgnore(sql: string): boolean
    hashOf(ref?: string): string
    checkout(name: string): string
    reset(options: { readonly hard: true; readonly to: string }): string
    commit(message: string): string
    readonly branch: {
      create(name: string, options: { readonly from?: string }): void
      force(name: string, from: string): void
      delete(name: string, options: { readonly force: true }): void
      list(): Array<{ name: string; hash: string }>
      current(): string
    }
  }
}

const openWriters = new WeakSet<CelldSqlStorage>()

/** Supply celld's exact execution profile to the common Chronolog reducer. */
export function createCelldSqlEngine(storage: CelldSqlStorage, options: {
  readonly limits?: Partial<ExecutionLimits>
} = {}): SqlEngine {
  const readBackend = (): MaterializerBackendInfo => {
    if (typeof storage.dolt.programEngineProfile !== 'function') throw new Error('MATERIALIZER_CELLD_PROFILE_UNAVAILABLE')
    const { engineDigest, sqliteVec, manifest } = storage.dolt.programEngineProfile()
    if (!/^[0-9a-f]{64}$/u.test(engineDigest) || manifest?.execProfile !== 'celld-spec10-v6' ||
        !manifest.fts5 || !manifest.json1 || !manifest.rtree || manifest.dynamicExtensions || !sqliteVec) {
      throw new Error('MATERIALIZER_CELLD_PROFILE_UNAVAILABLE')
    }
    const nativeManifest = normalizeEngineManifest({
      doltliteVersion: manifest.doltliteVersion,
      doltliteSourceSha256: manifest.doltliteReleaseSha256,
      sqliteVecVersion: manifest.sqliteVecVersion,
      sqliteVecSourceSha256: manifest.sqliteVecSourceSha256,
      chronologPatchProfile: `${manifest.execProfile}/${engineDigest}/sqlite_vec`,
      fts5: manifest.fts5, json1: manifest.json1, rtree: manifest.rtree, dynamicExtensions: manifest.dynamicExtensions,
    })
    return { engine: 'doltlite', version: nativeManifest.doltliteVersion, sqliteVersion: manifest.sqliteVersion,
      vecVersion: nativeManifest.sqliteVecVersion, nativeManifest, engineDigest: digestEngineManifest(nativeManifest),
      securityConfigured: true }
  }
  const captured = readBackend()
  const executionManifest = createDoltLiteExecutionManifest({ engineDigest: captured.engineDigest,
    ...(options.limits === undefined ? {} : { limits: options.limits }) })
  const limits = normalizeSqlRuntimeLimits(executionManifest.limits)
  return Object.freeze({
    executionManifest,
    openDatabase({ readOnly = false }: { readonly path: string; readonly readOnly?: boolean }) {
      const backend = readBackend()
      if (!equalBytes(backend.engineDigest, captured.engineDigest)) throw new Error('MATERIALIZER_CELLD_ENGINE_CHANGED')
      if (!readOnly && openWriters.has(storage)) throw new Error('MATERIALIZER_CELLD_WRITER_IN_USE')
      if (!readOnly) openWriters.add(storage)
      return { backend, database: new CelldDatabase(storage, readOnly, limits, () => { if (!readOnly) openWriters.delete(storage) }) }
    },
  })
}

function unavailable(): never { throw new Error('MATERIALIZER_CELLD_REQUIRES_NATIVE_SQL_PROFILE') }

class CelldDatabase implements DatabaseLike {
  readonly #transactions: StorageTransaction[] = []
  #program: PinnedProgram | null = null
  #snapshot: Snapshot | null = null
  #closed = false

  constructor(
    private readonly storage: CelldSqlStorage,
    private readonly readOnly: boolean,
    private readonly limits: SqlRuntimeLimits,
    private readonly release: () => void,
  ) {}

  readonly nativeProfile: NonNullable<DatabaseLike['nativeProfile']> = {
    executeConsensus: (source: SqlStatement, schemaAdmin: boolean) => {
      const program = this.#program
      if (!program) throw new Error('MATERIALIZER_CELLD_CONTEXT_REQUIRED')
      const bindings = source.bindings.map(({ parameter, value }) => ({
        ...(parameter.kind === 'index' ? { index: parameter.index } : { name: parameter.name }),
        value: sqlValue(toDatabaseValue(value)),
      }))
      const result = this.#step(program.step({ sql: source.sql, bindings }, { mode: 'consensus', schemaAdmin }))
      return result.result.outcome === 'rejected' ? result.result.code : null
    },
    prepare: (sql, mode, limits) => this.#statement(sql, mode, limits),
  }

  get inTransaction(): boolean { return this.#transactions.length > 0 }
  configureSecurity = unavailable
  setAuthorizer = unavailable
  setProgressHandler = unavailable
  setLimit = unavailable
  interrupt = unavailable

  exec(sql: string): void {
    this.#writable()
    switch (sql.trim().toUpperCase()) {
      case 'BEGIN IMMEDIATE':
        if (this.inTransaction) throw new Error('MATERIALIZER_CELLD_TRANSACTION_ALREADY_OPEN')
        this.#transactions.push(this.storage.dolt.beginProgramTransaction())
        return
      case 'SAVEPOINT CHRONOLOG_PROGRAM':
        if (this.#transactions.length !== 1) throw new Error('MATERIALIZER_CELLD_TRANSACTION_REQUIRED')
        this.#transactions.push(this.storage.beginTransactionSync())
        return
      case 'ROLLBACK TO SAVEPOINT CHRONOLOG_PROGRAM':
        if (this.#transactions.length !== 2) throw new Error('MATERIALIZER_CELLD_SAVEPOINT_REQUIRED')
        this.#transactions[1]!.rollback()
        this.#transactions.pop()
        this.#transactions.push(this.storage.beginTransactionSync())
        return
      case 'RELEASE SAVEPOINT CHRONOLOG_PROGRAM':
        if (this.#transactions.length !== 2) throw new Error('MATERIALIZER_CELLD_SAVEPOINT_REQUIRED')
        this.#transactions[1]!.commit()
        this.#transactions.pop()
        return
      case 'COMMIT':
        if (this.#transactions.length !== 1) throw new Error('MATERIALIZER_CELLD_TRANSACTION_REQUIRED')
        this.#transactions[0]!.commit()
        this.#transactions.pop()
        return
      case 'ROLLBACK':
        this.#rollback()
        return
      default:
        this.prepare(sql).run()
    }
  }

  prepare(sql: string): StatementLike { return this.#statement(sql, 'trusted', this.limits) }

  #statement(sql: string, mode: 'trusted' | 'platform' | 'local_read', limits: SqlRuntimeLimits): StatementLike {
    this.#assertOpen()
    let columns: readonly string[] = []
    let arrays = false
    const all = (...parameters: unknown[]) => {
      const result = this.#query(sql, positional(parameters), limits, mode)
      columns = result.columns
      return result.rows.map((row) => arrays ? [...row] : Object.fromEntries(columns.map((column, index) => [column, row[index]])))
    }
    return {
      run: (...parameters: unknown[]) => {
        if (mode === 'local_read') throw new SqlProfileError('SQL_PROFILE_VIOLATION')
        return this.#run({ sql, bindings: positional(parameters) }, limits)
      },
      get: (...parameters: unknown[]) => all(...parameters)[0],
      all,
      columns: () => columns.map((name) => ({ name })),
      setReturnArrays: (enabled) => { arrays = enabled },
      sourceSQL: sql,
      get tailOffset(): never { return unavailable() },
      get parameterCount(): never { return unavailable() },
      parameterIndex: unavailable,
    }
  }

  #query(sql: string, bindings: readonly Binding[], limits: SqlRuntimeLimits, mode: 'trusted' | 'platform' | 'local_read'): QueryResult {
    this.#assertOpen()
    const options = { limits, maxRows: limits.maxResultRows }
    if (this.readOnly) return this.storage.dolt.queryAt(this.#pinnedSnapshot().hash, sql, bindings, options)
    if (this.inTransaction) {
      if (mode === 'local_read') throw new Error('MATERIALIZER_CELLD_LOCAL_READER_REQUIRED')
      return this.storage.dolt.queryPlatformTransaction(sql, bindings, options)
    }
    if (mode === 'platform') throw new Error('MATERIALIZER_CELLD_TRANSACTION_REQUIRED')
    return this.storage.dolt.query(sql, bindings, options)
  }

  #run(statement: Statement, limits: SqlRuntimeLimits): StepResult {
    this.#writable()
    const ownsTransaction = !this.inTransaction
    if (ownsTransaction) this.exec('BEGIN IMMEDIATE')
    try {
      const result = this.#step(this.#program === null
        ? this.storage.dolt.runPlatformTransactionStatement(statement, { limits })
        : this.#program.step(statement, { mode: 'platform' }))
      if (result.result.outcome === 'rejected') throw new NativeSqlRejection(result.result.code)
      if (ownsTransaction) this.exec('COMMIT')
      return result
    } catch (error) {
      if (ownsTransaction && this.inTransaction) this.#rollback()
      throw error
    }
  }

  #step(result: StepResult): StepResult {
    if (result.transactionRolledBack) {
      this.#program = null
      this.#rollback()
    }
    return result
  }

  #rollback(): void {
    this.clearDeterministicContext()
    while (this.#transactions.length > 0) {
      this.#transactions.at(-1)!.rollback()
      this.#transactions.pop()
    }
  }

  setDeterministicContext(nowMs: bigint, seed: number, actor?: Uint8Array | null, actorId?: bigint | null, transactionId?: Uint8Array | null): void {
    this.#writable()
    if (!this.inTransaction || this.#program !== null) throw new Error('MATERIALIZER_CELLD_CONTEXT_STATE')
    this.#program = this.storage.dolt.pinTransactionProgram({ nowMs, seed, limits: this.limits,
      ...(actor == null ? {} : { actor }), ...(actorId == null ? {} : { actorId }),
      ...(transactionId == null ? {} : { transactionId }) })
  }

  clearDeterministicContext(): void {
    this.#program?.close()
    this.#program = null
  }

  triggerUsesIgnore(sql: string): boolean { this.#assertOpen(); return this.storage.dolt.triggerUsesIgnore(sql) }
  doltCommit(message: string): string { this.#writable(); return this.storage.dolt.commit(message) }
  doltBranch(name: string, from?: string): void {
    this.#writable()
    this.storage.dolt.branch.create(name, from === undefined ? {} : { from })
  }
  doltCheckout(name: string): void {
    this.#assertOpen()
    if (this.readOnly) {
      this.#snapshot = { ref: name, hash: this.storage.dolt.hashOf(name) }
    } else {
      this.storage.dolt.checkout(name)
    }
  }
  doltResetHard(to: string): void { this.#writable(); this.storage.dolt.reset({ hard: true, to }) }
  doltForceBranch(name: string, ref: string): void { this.#writable(); this.storage.dolt.branch.force(name, ref) }
  doltDeleteBranch(name: string): void { this.#writable(); this.storage.dolt.branch.delete(name, { force: true }) }
  doltHashOf(ref = 'HEAD'): string {
    this.#assertOpen()
    if (!this.readOnly) return this.storage.dolt.hashOf(ref)
    const snapshot = this.#pinnedSnapshot()
    if (ref !== 'HEAD' && ref !== snapshot.ref && ref !== snapshot.hash) throw new Error('MATERIALIZER_CELLD_SNAPSHOT_REF_MISMATCH')
    return snapshot.hash
  }
  doltVersion(): string { this.#assertOpen(); return this.storage.dolt.programEngineProfile().manifest.doltliteVersion }
  doltBranches(): Array<{ name: string; hash: string }> { this.#writable(); return this.storage.dolt.branch.list() }
  doltActiveBranch(): string { this.#writable(); return this.storage.dolt.branch.current() }

  close(): void {
    if (this.#closed) return
    try { this.#rollback() } finally { this.#closed = true; this.release() }
  }

  #pinnedSnapshot(): Snapshot {
    if (this.#snapshot === null) throw new Error('MATERIALIZER_CELLD_SNAPSHOT_REQUIRED')
    return this.#snapshot
  }
  #assertOpen(): void { if (this.#closed) throw new Error('MATERIALIZER_CLOSED') }
  #writable(): void {
    this.#assertOpen()
    if (this.readOnly) throw new Error('MATERIALIZER_CELLD_READ_ONLY')
  }
}

function sqlValue(value: unknown): SqlValue {
  if (value === null || typeof value === 'number' || typeof value === 'bigint' || typeof value === 'string' ||
      value instanceof Uint8Array || value instanceof Float64Array) return value
  throw new TypeError('MATERIALIZER_CELLD_INVALID_SQL_VALUE')
}

function positional(parameters: readonly unknown[]): Binding[] {
  return parameters.map((value, index) => ({ index: index + 1, value: sqlValue(value) }))
}

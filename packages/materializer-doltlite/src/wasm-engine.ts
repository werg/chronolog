import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { assertNativeSecurityConfiguration, configureSqliteLimits } from './sql-profile.js'
import type {
  DatabaseLike, DoltBranchInfoLike, MaterializerBackendInfo, NativeEngineManifest,
  NativeSecurityConfiguration, MaterializerOptions, StatementLike,
} from './types.js'

type Authorizer = Parameters<DatabaseLike['setAuthorizer']>[0]
type OpenedDatabase = ReturnType<NonNullable<MaterializerOptions['openDatabase']>>
interface WasmApi {
  alloc(bytes: number): number
  dealloc(pointer: number): void
  heap8u(): Uint8Array
  peekPtr(pointer: number): number
  xCall(name: string, ...args: (number | bigint)[]): number
}
interface SqliteApi {
  sqlite3_open_v2(path: string, output: number, flags: number, vfs: string): number
  sqlite3_close_v2(database: number): number
  sqlite3_exec(database: number, sql: string, callback: number, context: number, error: number): number
  sqlite3_get_autocommit(database: number): number
  sqlite3_errmsg(database: number): string
  sqlite3_extended_errcode(database: number): number
  sqlite3_prepare_v3(database: number, sql: number, bytes: number, flags: number, output: number, tail: number): number
  sqlite3_finalize(statement: number): number
  sqlite3_step(statement: number): number
  sqlite3_reset(statement: number): number
  sqlite3_clear_bindings(statement: number): number
  sqlite3_sql(statement: number): string
  sqlite3_column_count(statement: number): number
  sqlite3_column_name(statement: number, index: number): string
  sqlite3_column_type(statement: number, index: number): number
  sqlite3_column_int64(statement: number, index: number): bigint
  sqlite3_column_double(statement: number, index: number): number
  sqlite3_column_text(statement: number, index: number): string
  sqlite3_column_blob(statement: number, index: number): number
  sqlite3_column_bytes(statement: number, index: number): number
  sqlite3_bind_parameter_count(statement: number): number
  sqlite3_bind_parameter_name(statement: number, index: number): string | null
  sqlite3_bind_int64(statement: number, index: number, value: bigint): number
  sqlite3_bind_double(statement: number, index: number, value: number): number
  sqlite3_bind_text(statement: number, index: number, pointer: number, length: number, destroy: number): number
  sqlite3_bind_blob(statement: number, index: number, pointer: number, length: number, destroy: number): number
  sqlite3_changes64(database: number): bigint
  sqlite3_last_insert_rowid(database: number): bigint
  sqlite3_set_authorizer(database: number, callback: ((context: number, action: number, a: string | 0, b: string | 0, c: string | 0, d: string | 0) => number) | null, context: number): number
  sqlite3_progress_handler(database: number, steps: number, callback: (() => number) | null, context: number): void
  sqlite3_limit(database: number, category: number, value: number): number
  sqlite3_interrupt(database: number): void
}

/** Only the stable public C/JS API of the built SQLite/DoltLite WASM artifact. */
export interface ChronologWasmModule {
  readonly capi: SqliteApi
  readonly wasm: WasmApi
  installOpfsSAHPoolVfs?(options: {
    readonly name: string; readonly directory: string; readonly initialCapacity: number
  }): Promise<OpfsSqlitePool>
}

export interface OpfsSqlitePool {
  readonly vfsName: string
  /** Release owned handles without deleting durable data; all SQL must be closed first. */
  pauseVfs(): unknown
}

export interface WasmBuildManifest {
  readonly format: 1
  readonly toolchain: 'emscripten-4.0.20'
  readonly nativeManifest: NativeEngineManifest
  readonly runtimeVersions: { readonly doltlite: string; readonly sqlite: string; readonly vec: string }
  readonly portabilityPatches: readonly ['chunk-store-optional-sector-size-v1', 'chunk-store-optional-has-moved-v1', 'vfs-identity-forwarding-v1']
  readonly deterministicSourceSha256: string
  readonly wasmSha256: string
  readonly wasmBytes: number
}

const SECURITY: NativeSecurityConfiguration = {
  defensive: true, trustedSchema: true, loadExtension: true, dqsDml: true, dqsDdl: true,
  qpsg: true, ftsTokenizer: true, writableSchema: true, extendedResultCodes: true,
  attachCreate: true, attachWrite: true, reverseScanOrder: true, fpDigits: true,
}

const PATCH_PROFILE = 'authorizer-progress-limits-tailoffset-dolt-refs-static-vec-dolt-compat-real-empty-blob-bind-' +
  'deterministic-context-assert-parameters-actor-policy-trigger-lint-actor-id-vec-innocuous-row-key-exact-values-tx-id-v8'

/** Verify the actual module bytes before instantiation; unavailable profiles fail closed. */
export function verifyWasmBuild(bytes: Uint8Array, manifest: WasmBuildManifest): void {
  if (manifest.format !== 1 || manifest.toolchain !== 'emscripten-4.0.20' || bytes.length !== manifest.wasmBytes ||
      bytesToHex(sha256Sync(bytes)) !== manifest.wasmSha256) throw new Error('WASM_ENGINE_BUILD_MISMATCH')
  if (manifest.portabilityPatches?.length !== 3 || manifest.portabilityPatches[0] !== 'chunk-store-optional-sector-size-v1' ||
      manifest.portabilityPatches[1] !== 'chunk-store-optional-has-moved-v1' || manifest.portabilityPatches[2] !== 'vfs-identity-forwarding-v1') {
    throw new Error('WASM_ENGINE_PORTABILITY_PROFILE_UNSUPPORTED')
  }
  if (manifest.nativeManifest.doltliteVersion !== '0.11.29' || manifest.nativeManifest.sqliteVecVersion !== '0.1.9' ||
      manifest.nativeManifest.chronologPatchProfile !== PATCH_PROFILE) throw new Error('WASM_ENGINE_PROFILE_UNSUPPORTED')
}

/** Create a synchronous engine factory after the Worker has loaded its one WASM instance. */
export function createWasmEngineFactory(module: ChronologWasmModule, manifest: WasmBuildManifest, vfs: string): (options: { path?: string }) => OpenedDatabase {
  withBytes(module.wasm, utf8(vfs), (pointer) => {
    const rc = module.wasm.xCall('chronolog_wasm_init', pointer)
    if (rc !== 0) throw new Error(`WASM_ENGINE_VFS_UNAVAILABLE:${vfs}:${rc}`)
  })
  const descriptor = `chronolog-engine-manifest-v1\n${stableJson(manifest.nativeManifest)}`
  const engineDigest = sha256Sync(utf8(descriptor))
  return (options) => {
    if (options.path === undefined || options.path === ':memory:') throw new Error('MATERIALIZER_PERSISTENT_PATH_REQUIRED')
    const database = new WasmDatabase(module, options.path)
    try {
      const security = database.configureSecurity()
      assertNativeSecurityConfiguration(security)
      configureSqliteLimits(database)
      database.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON; PRAGMA trusted_schema = OFF')
      if (Number(database.scalar('PRAGMA recursive_triggers')) !== 1) throw new Error('MATERIALIZER_RECURSIVE_TRIGGERS_UNAVAILABLE')
      const backend: MaterializerBackendInfo = {
        engine: 'doltlite', version: database.doltVersion(),
        sqliteVersion: String(database.scalar('SELECT sqlite_version()')),
        vecVersion: String(database.scalar('SELECT vec_version()')),
        nativeManifest: structuredClone(manifest.nativeManifest), engineDigest: engineDigest.slice(), securityConfigured: true,
      }
      if (backend.version !== manifest.runtimeVersions.doltlite || backend.sqliteVersion !== manifest.runtimeVersions.sqlite ||
          backend.vecVersion !== manifest.runtimeVersions.vec) throw new Error('WASM_ENGINE_VERSION_MISMATCH')
      return { database, backend, security }
    } catch (error) { database.close(); throw error }
  }
}

export class WasmDatabase implements DatabaseLike {
  readonly module: ChronologWasmModule
  readonly pointer: number
  readonly #statements = new Set<WasmStatement>()
  #closed = false

  constructor(module: ChronologWasmModule, path: string) {
    this.module = module
    const output = module.wasm.alloc(4)
    try {
      module.wasm.heap8u().fill(0, output, output + 4)
      const rc = module.capi.sqlite3_open_v2(path, output, 2 | 4, 'chronolog')
      this.pointer = module.wasm.peekPtr(output)
      if (rc !== 0) {
        const error = this.error(rc)
        if (this.pointer !== 0) module.capi.sqlite3_close_v2(this.pointer)
        throw error
      }
    } finally { module.wasm.dealloc(output) }
  }

  get inTransaction(): boolean { this.assertOpen(); return this.module.capi.sqlite3_get_autocommit(this.pointer) === 0 }
  exec(sql: string): void { this.assertOpen(); this.check(this.module.capi.sqlite3_exec(this.pointer, sql, 0, 0, 0)) }
  prepare(sql: string): StatementLike {
    this.assertOpen()
    const statement = new WasmStatement(this, sql, () => { this.#statements.delete(statement) })
    this.#statements.add(statement)
    return statement
  }
  close(): void {
    if (this.#closed) return
    for (const statement of [...this.#statements]) statement.finalize()
    this.check(this.module.capi.sqlite3_close_v2(this.pointer))
    this.#closed = true
  }
  configureSecurity(): NativeSecurityConfiguration { this.check(this.module.wasm.xCall('chronolog_wasm_security', this.pointer)); return { ...SECURITY } }
  triggerUsesIgnore(sql: string): boolean { return withBytes(this.module.wasm, utf8(sql), (pointer) => this.module.wasm.xCall('chronolog_wasm_trigger', pointer) !== 0) }
  setAuthorizer(callback: Authorizer): void {
    this.check(this.module.capi.sqlite3_set_authorizer(this.pointer,
      callback === null ? null : (_context, action, a, b, c, d) => callback(action, a || null, b || null, c || null, d || null), 0))
  }
  setProgressHandler(steps: number, callback: (() => boolean) | null): void {
    this.module.capi.sqlite3_progress_handler(this.pointer, steps, callback === null ? null : () => callback() ? 1 : 0, 0)
  }
  setLimit(category: number, value: number): number { return this.module.capi.sqlite3_limit(this.pointer, category, value) }
  interrupt(): void { this.module.capi.sqlite3_interrupt(this.pointer) }
  setDeterministicContext(unixMs: bigint, seed: number, actor: Uint8Array | null = null, actorId: bigint | null = null, transactionId: Uint8Array | null = null): void {
    if (unixMs < 0n || unixMs > 253402300799999n || (actor !== null && (actor.length < 1 || actor.length > 64)) ||
        (actorId !== null && (actorId < 1n || actorId > (1n << 63n) - 1n)) ||
        (transactionId !== null && transactionId.length === 0)) throw new Error('WASM_DETERMINISTIC_CONTEXT_INVALID')
    const withActor = (actorPointer: number): void => {
      const apply = (transactionPointer: number): void => {
        this.module.wasm.xCall('chronolog_wasm_context', this.pointer, unixMs, seed >>> 0, actorPointer, actor?.length ?? 0,
          actorId === null ? 0 : 1, actorId ?? 0n, transactionPointer, transactionId?.length ?? 0)
      }
      if (transactionId === null) apply(0)
      else withBytes(this.module.wasm, transactionId, apply)
    }
    if (actor === null) withActor(0)
    else withBytes(this.module.wasm, actor, withActor)
  }
  clearDeterministicContext(): void { this.module.wasm.xCall('chronolog_wasm_clear') }
  doltCommit(message: string): string { return String(this.scalar("SELECT dolt_commit('-A', '-m', ?)", message)) }
  doltBranch(name: string, from?: string): void { this.scalar(from === undefined ? 'SELECT dolt_branch(?)' : 'SELECT dolt_branch(?, ?)', ...from === undefined ? [name] : [name, from]) }
  doltCheckout(branch: string): void { this.scalar('SELECT dolt_checkout(?)', branch) }
  doltResetHard(ref: string): void { this.scalar("SELECT dolt_reset('--hard', ?)", ref) }
  doltForceBranch(name: string, ref: string): void { this.scalar("SELECT dolt_branch('-f', ?, ?)", name, ref) }
  doltDeleteBranch(name: string): void { this.scalar("SELECT dolt_branch('-D', ?)", name) }
  doltHashOf(ref = 'HEAD'): string { return String(this.scalar('SELECT DOLT_HASHOF_DB(?)', ref)) }
  doltVersion(): string { return String(this.scalar('SELECT dolt_version()')) }
  doltBranches(): DoltBranchInfoLike[] {
    const statement = this.prepare('SELECT name, hash FROM dolt_branches')
    try { return statement.all().map((row) => { const value = row as Record<string, unknown>; return { name: String(value.name), hash: String(value.hash) } }) }
    finally { statement.finalize?.() }
  }
  doltActiveBranch(): string { return String(this.scalar('SELECT active_branch()')) }
  scalar(sql: string, ...parameters: unknown[]): unknown {
    const statement = this.prepare(sql)
    try { statement.setReturnArrays?.(true); return (statement.get(...parameters) as unknown[] | undefined)?.[0] }
    finally { statement.finalize?.() }
  }
  check(code: number): void { if (code !== 0) throw this.error(code) }
  error(code: number): Error {
    const extended = this.pointer === 0 ? code : this.module.capi.sqlite3_extended_errcode(this.pointer)
    return Object.assign(new Error(this.pointer === 0 ? `SQLite error ${code}` : this.module.capi.sqlite3_errmsg(this.pointer)), {
      sqliteCode: code & 0xff, sqliteExtendedCode: extended || code,
    })
  }
  assertOpen(): void { if (this.#closed) throw new Error('WASM_DATABASE_CLOSED') }
}

class WasmStatement implements StatementLike {
  readonly sourceSQL: string
  readonly tailOffset: number
  readonly parameterCount: number
  readonly #database: WasmDatabase
  readonly #pointer: number
  readonly #onClose: () => void
  #arrays = false
  #bigints = false
  #closed = false

  constructor(database: WasmDatabase, sql: string, onClose: () => void) {
    this.#database = database
    this.#onClose = onClose
    const { capi, wasm } = database.module
    const pointers = wasm.alloc(8)
    try {
      wasm.heap8u().fill(0, pointers, pointers + 8)
      const bytes = utf8(sql)
      const prepared = withBytes(wasm, bytes, (pointer) => {
        const rc = capi.sqlite3_prepare_v3(database.pointer, pointer, bytes.length, 0, pointers, pointers + 4)
        const statement = wasm.peekPtr(pointers)
        if (rc !== 0) { if (statement !== 0) capi.sqlite3_finalize(statement); throw database.error(rc) }
        return { statement, tail: wasm.peekPtr(pointers + 4) - pointer }
      })
      if (prepared.statement === 0) throw new Error('SQL_EMPTY_STATEMENT')
      this.#pointer = prepared.statement
      this.tailOffset = prepared.tail
      this.sourceSQL = capi.sqlite3_sql(this.#pointer)
      this.parameterCount = capi.sqlite3_bind_parameter_count(this.#pointer)
    } finally { wasm.dealloc(pointers) }
  }

  finalize(): void {
    if (this.#closed) return
    this.#closed = true
    this.#database.module.capi.sqlite3_finalize(this.#pointer)
    this.#onClose()
  }
  setReturnArrays(enabled: boolean): void { this.#arrays = enabled }
  setReadBigInts(enabled: boolean): void { this.#bigints = enabled }
  columns(): Array<{ name: string | null }> {
    this.#assertOpen()
    const capi = this.#database.module.capi
    return Array.from({ length: capi.sqlite3_column_count(this.#pointer) }, (_, index) => ({ name: capi.sqlite3_column_name(this.#pointer, index) }))
  }
  parameterIndex(name: string): number {
    for (let index = 1; index <= this.parameterCount; index += 1) if (this.#database.module.capi.sqlite3_bind_parameter_name(this.#pointer, index) === name) return index
    return 0
  }
  run(...parameters: unknown[]): { changes: number | bigint; lastInsertRowid: number | bigint } {
    this.#bind(parameters)
    const capi = this.#database.module.capi
    try {
      let code: number
      do { code = capi.sqlite3_step(this.#pointer) } while (code === 100)
      if (code !== 101) throw this.#database.error(code)
      return { changes: Number(capi.sqlite3_changes64(this.#database.pointer)), lastInsertRowid: capi.sqlite3_last_insert_rowid(this.#database.pointer) }
    } finally { capi.sqlite3_reset(this.#pointer) }
  }
  get(...parameters: unknown[]): Record<string, unknown> | unknown[] | undefined {
    this.#bind(parameters)
    const capi = this.#database.module.capi
    try {
      const code = capi.sqlite3_step(this.#pointer)
      if (code === 101) return undefined
      if (code !== 100) throw this.#database.error(code)
      return this.#row()
    } finally { capi.sqlite3_reset(this.#pointer) }
  }
  all(...parameters: unknown[]): Array<Record<string, unknown> | unknown[]> {
    this.#bind(parameters)
    const capi = this.#database.module.capi
    const rows: Array<Record<string, unknown> | unknown[]> = []
    try {
      for (;;) {
        const code = capi.sqlite3_step(this.#pointer)
        if (code === 101) return rows
        if (code !== 100) throw this.#database.error(code)
        rows.push(this.#row())
      }
    } finally { capi.sqlite3_reset(this.#pointer) }
  }

  #bind(parameters: unknown[]): void {
    this.#assertOpen()
    const values: unknown[] = parameters.length === 1 && Array.isArray(parameters[0]) ? parameters[0] : parameters
    if (values.length !== this.parameterCount) throw new Error('SQL_PARAMETER_COUNT_MISMATCH')
    const { capi, wasm } = this.#database.module
    capi.sqlite3_reset(this.#pointer)
    this.#database.check(capi.sqlite3_clear_bindings(this.#pointer))
    values.forEach((value, offset) => {
      const index = offset + 1
      let result: number
      // Upstream's JS capi adapter declares bind_null as void. The C result
      // remains significant, so call the public WASM export directly here.
      if (value === null) result = wasm.xCall('sqlite3_bind_null', this.#pointer, index)
      else if (typeof value === 'bigint') result = capi.sqlite3_bind_int64(this.#pointer, index, value)
      else if (value instanceof Float64Array && value.length === 1) result = capi.sqlite3_bind_double(this.#pointer, index, value[0]!)
      else if (typeof value === 'number') result = Number.isSafeInteger(value) ? capi.sqlite3_bind_int64(this.#pointer, index, BigInt(value)) : capi.sqlite3_bind_double(this.#pointer, index, value)
      else if (typeof value === 'string') {
        const bytes = utf8(value)
        result = withBytes(wasm, bytes, (pointer) => capi.sqlite3_bind_text(this.#pointer, index, pointer, bytes.length, -1))
      } else if (value instanceof Uint8Array) {
        result = withBytes(wasm, value, (pointer) => capi.sqlite3_bind_blob(this.#pointer, index, pointer, value.length, -1))
      } else throw new Error('SQL_UNSUPPORTED_PARAMETER_TYPE')
      this.#database.check(result)
    })
  }

  #row(): Record<string, unknown> | unknown[] {
    const { capi, wasm } = this.#database.module
    const columns = this.columns()
    const values = columns.map((_column, index): unknown => {
      switch (capi.sqlite3_column_type(this.#pointer, index)) {
        case 1: { const integer = capi.sqlite3_column_int64(this.#pointer, index); return this.#bigints ? integer : Number(integer) }
        case 2: return capi.sqlite3_column_double(this.#pointer, index)
        case 3: return capi.sqlite3_column_text(this.#pointer, index)
        case 4: { const pointer = capi.sqlite3_column_blob(this.#pointer, index); return wasm.heap8u().slice(pointer, pointer + capi.sqlite3_column_bytes(this.#pointer, index)) }
        case 5: return null
        default: throw new Error('SQL_UNSUPPORTED_RESULT_TYPE')
      }
    })
    return this.#arrays ? values : Object.fromEntries(columns.map((column, index) => [column.name!, values[index]]))
  }
  #assertOpen(): void { this.#database.assertOpen(); if (this.#closed) throw new Error('WASM_STATEMENT_CLOSED') }
}

function withBytes<T>(wasm: WasmApi, bytes: Uint8Array, operation: (pointer: number) => T): T {
  const pointer = wasm.alloc(bytes.length + 1)
  try { wasm.heap8u().set(bytes, pointer); wasm.heap8u()[pointer + bytes.length] = 0; return operation(pointer) }
  finally { wasm.dealloc(pointer) }
}

function stableJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(',')}}`
  }
  throw new Error('WASM_ENGINE_MANIFEST_INVALID')
}

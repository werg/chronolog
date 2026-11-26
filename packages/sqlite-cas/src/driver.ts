import createSqliteCasWasm from '../wasm/sqlite-cas.mjs'
import type {
  SqliteBuiltinDriver,
  SqliteDbHandle,
  SqliteDdlAllowlist,
  SqliteExecOptions,
  SqliteExecResult,
  SqliteQueryResult,
} from '@chronolog/materializer'

export const SQLITE_CAS_BUILTIN_ID = 'sqlite-cas@1#sha256-bbc4674a5dd1d11962a8227ce5f1118e2e6ed7d00163ea92f1f35781caf46936'
import type { JsonValue } from '@chronolog/protocol'
import { MerklePageFile } from './merkle-pages.js'

const SQLITE_OK = 0
const SQLITE_IOERR = 10
const SQLITE_IOERR_SHORT_READ = 522
const SQLITE_ROW = 100
const SQLITE_DONE = 101

const SQLITE_INTEGER = 1
const SQLITE_FLOAT = 2
const SQLITE_TEXT = 3
const SQLITE_BLOB = 4
const SQLITE_NULL = 5

const SQLITE_CREATE_INDEX = 1
const SQLITE_CREATE_TABLE = 2
const SQLITE_CREATE_VIEW = 8
const SQLITE_DROP_INDEX = 10
const SQLITE_DROP_TABLE = 11
const SQLITE_DROP_VIEW = 17
const SQLITE_ALTER_TABLE = 26
const SQLITE_REINDEX = 27
const SQLITE_CREATE_VTABLE = 29
const SQLITE_DROP_VTABLE = 30

interface EmscriptenSqliteModule {
  HEAPU8: Uint8Array
  UTF8ToString(ptr: number): string
  stringToUTF8(str: string, outPtr: number, maxBytes: number): void
  lengthBytesUTF8(str: string): number
  getValue(ptr: number, type: string): number
  _malloc(size: number): number
  _free(ptr: number): void
  _chronolog_init(): number
  _chronolog_set_context(actorPtr: number, opIdPtr: number, opTimeMs: number): void
  _chronolog_set_mode(mode: number): void
  _chronolog_open(): number
  _chronolog_close(db: number): number
  _chronolog_errmsg(db: number): number
  _chronolog_changes(db: number): number
  _chronolog_last_insert_rowid(db: number): number
  _chronolog_reset_rowid(db: number): void
  _chronolog_prepare(db: number, sqlPtr: number, requireSingle: number, outStmtPtr: number, outTailPtr: number): number
  _chronolog_step(stmt: number): number
  _chronolog_finalize(stmt: number): number
  _chronolog_bind_null(stmt: number, idx: number): number
  _chronolog_bind_int64(stmt: number, idx: number, val: number): number
  _chronolog_bind_double(stmt: number, idx: number, val: number): number
  _chronolog_bind_text(stmt: number, idx: number, ptr: number, len: number): number
  _chronolog_bind_blob(stmt: number, idx: number, ptr: number, len: number): number
  _chronolog_column_count(stmt: number): number
  _chronolog_column_name(stmt: number, idx: number): number
  _chronolog_column_type(stmt: number, idx: number): number
  _chronolog_column_double(stmt: number, idx: number): number
  _chronolog_column_text(stmt: number, idx: number): number
  _chronolog_column_bytes(stmt: number, idx: number): number
  _chronolog_column_blob(stmt: number, idx: number): number
  _chronolog_validate_expr(db: number, sqlPtr: number): number
  _casHooks: {
    read(offset: number, bufPtr: number, amt: number): number
    write(offset: number, bufPtr: number, amt: number): number
    truncate(size: number): number
    filesize(): number
    ddlAuthorize(action: number, arg1: string, arg2: string): number
  }
}

export interface CreateSqliteCasDriverOptions {
  /** Optional static pre-compiled WebAssembly.Module (for Cloudflare Workers / strict CSP). */
  readonly wasmModule?: WebAssembly.Module
}

function allocCString(mod: EmscriptenSqliteModule, text: string): number {
  const len = mod.lengthBytesUTF8(text) + 1
  const ptr = mod._malloc(len)
  mod.stringToUTF8(text, ptr, len)
  return ptr
}

function withCString<T>(mod: EmscriptenSqliteModule, text: string, fn: (ptr: number) => T): T {
  const ptr = allocCString(mod, text)
  try { return fn(ptr) } finally { mod._free(ptr) }
}

function quoteIdent(name: string): string {
  if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(name)) throw new Error(`SQLITE_INVALID_IDENT:${name}`)
  return `"${name}"`
}

let defaultDriverPromise: Promise<SqliteBuiltinDriver> | null = null

export async function createSqliteCasDriver(options: CreateSqliteCasDriverOptions = {}): Promise<SqliteBuiltinDriver> {
  if (options.wasmModule === undefined && defaultDriverPromise !== null) {
    return defaultDriverPromise
  }
  const init = async (): Promise<SqliteBuiltinDriver> => {
    const manifestMod = { default: { builtinId: SQLITE_CAS_BUILTIN_ID } }
    const wasmConfig: Record<string, unknown> = {
      locateFile: (path: string) => new URL(`../wasm/${path}`, import.meta.url).href,
    }
    if (options.wasmModule !== undefined) {
      const staticMod = options.wasmModule
      wasmConfig.instantiateWasm = (imports: WebAssembly.Imports, receiveInstance: (inst: WebAssembly.Instance) => void) => {
        const instance = new WebAssembly.Instance(staticMod, imports)
        receiveInstance(instance)
        return instance.exports
      }
    }
    const factory = createSqliteCasWasm as (moduleArg?: Record<string, unknown>) => Promise<EmscriptenSqliteModule>
    const mod = await factory(wasmConfig)
    let activeFile: MerklePageFile | null = null
    let missingCasError: Error | null = null
    let activeDdl: {
      allow: SqliteDdlAllowlist
      createdTables: Set<string>
      droppedTables: Set<string>
      createdIndexes: Set<string>
      createdViews: Set<string>
    } | null = null

    mod._casHooks = {
      read(offset, bufPtr, amt) {
        if (activeFile === null) return SQLITE_IOERR
        try {
          const dest = mod.HEAPU8.subarray(bufPtr, bufPtr + amt)
          const full = activeFile.readInto(offset, dest)
          return full ? SQLITE_OK : SQLITE_IOERR_SHORT_READ
        } catch (err) {
          missingCasError = err instanceof Error ? err : new Error(String(err))
          return SQLITE_IOERR
        }
      },
      write(offset, bufPtr, amt) {
        if (activeFile === null) return SQLITE_IOERR
        const src = mod.HEAPU8.subarray(bufPtr, bufPtr + amt)
        activeFile.writeFrom(offset, src)
        return SQLITE_OK
      },
      truncate(size) {
        if (activeFile === null) return SQLITE_IOERR
        activeFile.truncate(size)
        return SQLITE_OK
      },
      filesize() {
        return activeFile === null ? 0 : activeFile.byteLength
      },
      ddlAuthorize(action, arg1, arg2) {
        if (activeDdl === null) return 0
        const { allow, createdTables, droppedTables, createdIndexes, createdViews } = activeDdl
        if (action === SQLITE_CREATE_TABLE || action === SQLITE_CREATE_VTABLE) {
          if (allow.createTable !== true) return 0
          createdTables.add(arg1)
          return 1
        }
        if (action === SQLITE_ALTER_TABLE) {
          return (createdTables.has(arg2) || (allow.alterTable?.includes(arg2) ?? false)) ? 1 : 0
        }
        if (action === SQLITE_DROP_TABLE || action === SQLITE_DROP_VTABLE) {
          const ok = createdTables.has(arg1) || (allow.dropTable?.includes(arg1) ?? false)
          if (ok) { createdTables.delete(arg1); droppedTables.add(arg1) }
          return ok ? 1 : 0
        }
        if (action === SQLITE_CREATE_INDEX || action === SQLITE_DROP_INDEX) {
          const ok = createdTables.has(arg2) || (allow.indexOn?.includes(arg2) ?? false)
          if (ok && action === SQLITE_CREATE_INDEX) createdIndexes.add(arg1)
          return ok ? 1 : 0
        }
        if (action === SQLITE_REINDEX) {
          return createdIndexes.has(arg1) ? 1 : 0
        }
        if (action === SQLITE_CREATE_VIEW) {
          if (allow.createView !== true) return 0
          createdViews.add(arg1)
          return 1
        }
        if (action === SQLITE_DROP_VIEW) {
          return (createdViews.has(arg1) || (allow.dropView?.includes(arg1) ?? false)) ? 1 : 0
        }
        return 0
      },
    }

    const initRc = mod._chronolog_init()
    if (initRc !== SQLITE_OK) throw new Error(`SQLITE_CAS_INIT_FAILED:${initRc}`)

    const throwIfMissing = (): void => {
      if (missingCasError !== null) {
        const err = missingCasError
        missingCasError = null
        throw err
      }
    }

    const bindParams = (stmt: number, params: readonly JsonValue[]): void => {
      for (let i = 0; i < params.length; i++) {
        const idx = i + 1
        const val = params[i]
        let rc: number
        if (val === null || val === undefined) {
          rc = mod._chronolog_bind_null(stmt, idx)
        } else if (typeof val === 'boolean') {
          rc = mod._chronolog_bind_int64(stmt, idx, val ? 1 : 0)
        } else if (typeof val === 'number') {
          rc = Number.isSafeInteger(val)
            ? mod._chronolog_bind_int64(stmt, idx, val)
            : mod._chronolog_bind_double(stmt, idx, val)
        } else if (typeof val === 'string') {
          const len = mod.lengthBytesUTF8(val)
          const ptr = allocCString(mod, val)
          try { rc = mod._chronolog_bind_text(stmt, idx, ptr, len) } finally { mod._free(ptr) }
        } else {
          const json = JSON.stringify(val)
          const len = mod.lengthBytesUTF8(json)
          const ptr = allocCString(mod, json)
          try { rc = mod._chronolog_bind_text(stmt, idx, ptr, len) } finally { mod._free(ptr) }
        }
        if (rc !== SQLITE_OK) throw new Error(`SQLITE_BIND_FAILED:${rc}`)
      }
    }

    const readRow = (stmt: number, colCount: number): JsonValue[] => {
      const row: JsonValue[] = []
      for (let i = 0; i < colCount; i++) {
        const type = mod._chronolog_column_type(stmt, i)
        if (type === SQLITE_NULL) row.push(null)
        else if (type === SQLITE_INTEGER || type === SQLITE_FLOAT) row.push(mod._chronolog_column_double(stmt, i))
        else if (type === SQLITE_TEXT) row.push(mod.UTF8ToString(mod._chronolog_column_text(stmt, i)))
        else if (type === SQLITE_BLOB) {
          const len = mod._chronolog_column_bytes(stmt, i)
          const ptr = mod._chronolog_column_blob(stmt, i)
          const bytes = mod.HEAPU8.slice(ptr, ptr + len)
          let hex = ''
          for (const b of bytes) hex += b.toString(16).padStart(2, '0')
          row.push(hex)
        } else row.push(null)
      }
      return row
    }

    return {
      builtinId: manifestMod.default.builtinId,
      openDb(openOpts): SqliteDbHandle {
        missingCasError = null
        const pageFile = new MerklePageFile({
          dbRoot: openOpts.dbRoot,
          cas: openOpts.cas,
          partition: openOpts.partition,
          onMissingCas: openOpts.onMissingCas,
        })
        activeFile = pageFile

        withCString(mod, openOpts.actor, actorPtr => {
          withCString(mod, openOpts.opId, opIdPtr => {
            mod._chronolog_set_context(actorPtr, opIdPtr, Number(openOpts.opTimeMs))
          })
        })

        const db = mod._chronolog_open()
        throwIfMissing()
        if (db === 0) throw new Error('SQLITE_CAS_OPEN_FAILED')

        let closed = false
        const ensureOpen = (): void => {
          if (closed) throw new Error('SQLITE_HANDLE_CLOSED')
          activeFile = pageFile
        }

        const runSql = (
          sql: string,
          params: readonly JsonValue[],
          modeNum: number,
          ddl: SqliteDdlAllowlist | undefined,
          requireSingle: boolean,
        ): { readonly columns: string[]; readonly rows: JsonValue[][]; readonly changes: number; readonly lastInsertRowid: number; readonly createdTables: string[]; readonly droppedTables: string[] } => {
          ensureOpen()
          mod._chronolog_set_mode(modeNum)
          const createdTables = new Set<string>()
          const droppedTables = new Set<string>()
          activeDdl = modeNum === 1 ? { allow: ddl ?? {}, createdTables, droppedTables, createdIndexes: new Set(), createdViews: new Set() } : null

          const outStmtPtr = mod._malloc(4)
          const outTailPtr = mod._malloc(4)
          let sqlPtr = allocCString(mod, sql)
          const baseSqlPtr = sqlPtr
          const columns: string[] = []
          const rows: JsonValue[][] = []
          let isFirstStmt = true
          try {
            while (true) {
              const rc = mod._chronolog_prepare(db, sqlPtr, requireSingle ? 1 : 0, outStmtPtr, outTailPtr)
              throwIfMissing()
              if (rc !== SQLITE_OK) {
                const msg = mod.UTF8ToString(mod._chronolog_errmsg(db))
                throw new Error(`SQLITE_PREPARE_ERROR(${rc}): ${msg}`)
              }
              const stmt = mod.getValue(outStmtPtr, 'i32')
              const tailPtr = mod.getValue(outTailPtr, 'i32')
              if (stmt === 0) break
              try {
                if (isFirstStmt && params.length > 0) bindParams(stmt, params)
                isFirstStmt = false
                const colCount = mod._chronolog_column_count(stmt)
                if (colCount > 0 && columns.length === 0) {
                  for (let i = 0; i < colCount; i++) columns.push(mod.UTF8ToString(mod._chronolog_column_name(stmt, i)))
                }
                while (true) {
                  const stepRc = mod._chronolog_step(stmt)
                  throwIfMissing()
                  if (stepRc === SQLITE_ROW) {
                    rows.push(readRow(stmt, colCount))
                    continue
                  }
                  if (stepRc === SQLITE_DONE) break
                  const msg = mod.UTF8ToString(mod._chronolog_errmsg(db))
                  throw new Error(`SQLITE_STEP_ERROR(${stepRc}): ${msg}`)
                }
              } finally {
                mod._chronolog_finalize(stmt)
              }
              if (tailPtr === 0 || mod.HEAPU8[tailPtr] === 0) break
              sqlPtr = tailPtr
            }
            return {
              columns,
              rows,
              changes: mod._chronolog_changes(db),
              lastInsertRowid: mod._chronolog_last_insert_rowid(db),
              createdTables: [...createdTables].sort(),
              droppedTables: [...droppedTables].sort(),
            }
          } finally {
            activeDdl = null
            mod._free(baseSqlPtr)
            mod._free(outStmtPtr)
            mod._free(outTailPtr)
          }
        }

        return {
          exec(sql: string, params: readonly JsonValue[] = [], opts: SqliteExecOptions = {}): SqliteExecResult {
            if (openOpts.readOnly) throw new Error('SQLITE_READ_ONLY')
            const mode = opts.mode ?? 'admin'
            const modeNum = mode === 'admin' ? 0 : mode === 'user' ? 1 : 2
            const res = runSql(sql, params, modeNum, opts.ddl, false)
            return {
              changes: res.changes,
              lastInsertRowid: res.lastInsertRowid,
              createdTables: res.createdTables,
              droppedTables: res.droppedTables,
            }
          },
          query(sql: string, params: readonly JsonValue[] = []): SqliteQueryResult {
            const res = runSql(sql, params, 2, undefined, true)
            return { columns: res.columns, rows: res.rows }
          },
          validateExpr(table: string, sqlOp: 'INSERT' | 'UPDATE' | 'DELETE', expr: string): void {
            ensureOpen()
            if (expr.includes(';')) throw new Error('RLS_EXPR_SEMICOLON_FORBIDDEN')
            const qTable = quoteIdent(table)
            // Build a single read-only SELECT referencing NEW/OLD aliases mapped to table columns
            const info = runSql(`PRAGMA table_info(${qTable})`, [], 0, undefined, true)
            if (info.rows.length === 0) throw new Error(`RLS_TABLE_NOT_FOUND:${table}`)
            const aliasClauses =
              sqlOp === 'INSERT' ? `FROM ${qTable} AS NEW`
              : sqlOp === 'DELETE' ? `FROM ${qTable} AS OLD`
              : `FROM ${qTable} AS OLD JOIN ${qTable} AS NEW ON 1=1`
            const testSql = `SELECT 1 ${aliasClauses} WHERE (${expr})`
            const rc = withCString(mod, testSql, ptr => mod._chronolog_validate_expr(db, ptr))
            throwIfMissing()
            if (rc !== SQLITE_OK) {
              const msg = mod.UTF8ToString(mod._chronolog_errmsg(db))
              throw new Error(`RLS_EXPR_INVALID(${rc}): ${msg}`)
            }
          },
          commit(): string {
            ensureOpen()
            if (openOpts.readOnly) throw new Error('SQLITE_READ_ONLY')
            // Closing flushes SQLite's page cache cleanly to our MerklePageFile before computing dbRoot
            mod._chronolog_close(db)
            closed = true
            throwIfMissing()
            return pageFile.commit()
          },
          close(): void {
            if (!closed) {
              activeFile = pageFile
              mod._chronolog_close(db)
              closed = true
            }
            if (activeFile === pageFile) activeFile = null
          },
        }
      },
    }
  }

  if (options.wasmModule === undefined) {
    defaultDriverPromise = init().catch(err => { defaultDriverPromise = null; throw err })
    return defaultDriverPromise
  }
  return init()
}

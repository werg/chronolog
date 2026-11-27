import {
  createOverlayCas,
  createSqliteCasDriver,
  diffMerkleDbRoots,
  type MerkleDbDiff,
} from 'chronolog-db'
import { ContentAddressedStore, MemoryBytesStore, type CasPartition } from '@chronolog/records'
import type { JsonValue } from '@chronolog/protocol'
import type { SqliteBuiltinDriver, SqliteDbHandle, SqliteExecOptions, SqliteExecResult, SqliteQueryResult } from '@chronolog/materializer'

export interface TableRowDiff {
  readonly table: string
  readonly keyColumns: readonly string[]
  readonly inserted: readonly Record<string, JsonValue>[]
  readonly updated: readonly {
    readonly key: Record<string, JsonValue>
    readonly before: Record<string, JsonValue>
    readonly after: Record<string, JsonValue>
  }[]
  readonly deleted: readonly Record<string, JsonValue>[]
}

export interface SqlBranchDiff {
  readonly baseRoot: string | null
  readonly branchRoot: string | null
  readonly merkle: MerkleDbDiff
  readonly tables: readonly TableRowDiff[]
}

export interface SqlBranchProposal {
  readonly topic: string
  readonly baseRoot: string | null
  readonly branchRoot: string | null
  readonly statements: readonly { readonly sql: string; readonly params: readonly JsonValue[] }[]
  readonly preconditions: readonly JsonValue[]
  readonly diff: SqlBranchDiff
}

export interface SqlBranch {
  readonly topic: string
  readonly baseRoot: string | null
  exec(sql: string, params?: readonly JsonValue[], options?: SqliteExecOptions): SqliteExecResult
  query(sql: string, params?: readonly JsonValue[]): SqliteQueryResult
  commitBranch(): string
  diff(): SqlBranchDiff
  toProposal(options?: { readonly withRowGuards?: boolean }): SqlBranchProposal
  close(): void
}

function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`
}

function listUserTables(db: SqliteDbHandle): string[] {
  const res = db.query(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_rls_%' AND name NOT LIKE '_chronolog_%' ORDER BY name",
    [],
  )
  return res.rows.map(r => (typeof r[0] === 'string' ? r[0] : ''))
}

function readTableSnapshot(db: SqliteDbHandle, table: string): {
  readonly columns: readonly string[]
  readonly pkColumns: readonly string[]
  readonly rows: readonly Record<string, JsonValue>[]
} {
  const qTable = quoteIdent(table)
  const res = db.query(`SELECT * FROM ${qTable}`, [])
  const cols = res.columns
  const pkCols: string[] = []
  try {
    const info = db.query(`PRAGMA table_info(${qTable})`, [])
    const pkEntries = info.rows
      .filter(r => Number(r[5]) > 0)
      .sort((a, b) => Number(a[5]) - Number(b[5]))
      .map(r => (typeof r[1] === 'string' ? r[1] : ''))
    pkCols.push(...pkEntries)
  } catch { /* ignore */ }
  const keyCols = pkCols.length > 0 ? pkCols : (cols.length > 0 ? [cols[0]!] : [])
  const rows = res.rows.map(row => {
    const obj: Record<string, JsonValue> = {}
    for (let i = 0; i < cols.length; i++) obj[cols[i]!] = row[i] ?? null
    return obj
  })
  return { columns: cols, pkColumns: keyCols, rows }
}

/**
 * Open a zero-copy O(1) SQLite branch backed by an in-memory OverlayCas.
 * Mutations stay strictly isolated in RAM, can be diffed against baseRoot by table & row,
 * and can be exported as a guarded proposal for human approval or direct submission.
 */
export function openSqlBranch(options: {
  readonly topic: string
  readonly baseRoot: string | null
  readonly cas: ContentAddressedStore
  readonly partition: CasPartition
  readonly driver: SqliteBuiltinDriver
  readonly actor: string
}): SqlBranch {
  const overlayCas = createOverlayCas(options.cas)
  const recordedStatements: { readonly sql: string; readonly params: readonly JsonValue[] }[] = []
  let closed = false
  let currentBranchRoot: string | null = options.baseRoot

  let db: SqliteDbHandle | null = null
  const openCurrentDb = (): SqliteDbHandle => {
    if (db === null) {
      db = options.driver.openDb({
        dbRoot: currentBranchRoot,
        cas: overlayCas,
        partition: options.partition,
        actor: options.actor,
        opId: '0'.repeat(64),
        opTimeMs: BigInt(Date.now()),
        readOnly: false,
        onMissingCas: (hash) => { throw new Error(`SQL_BRANCH_MISSING_CAS:${hash}`) },
      })
    }
    return db
  }

  const ensureOpen = (): void => {
    if (closed) throw new Error('SQL_BRANCH_CLOSED')
  }

  const commitBranch = (): string => {
    ensureOpen()
    if (db !== null) {
      currentBranchRoot = db.commit()
      db = null
    }
    return currentBranchRoot ?? ''
  }

  const computeDiff = (): SqlBranchDiff => {
    ensureOpen()
    const branchRoot = commitBranch() || null
    const merkle = diffMerkleDbRoots(overlayCas, options.baseRoot, branchRoot, 'any')
    if (merkle.totalChangedPages === 0) {
      return { baseRoot: options.baseRoot, branchRoot, merkle, tables: [] }
    }

    const baseDb = options.driver.openDb({
      dbRoot: options.baseRoot,
      cas: options.cas,
      partition: options.partition,
      actor: options.actor,
      opId: '0'.repeat(64),
      opTimeMs: 0n,
      readOnly: true,
      onMissingCas: (hash) => { throw new Error(`SQL_BRANCH_MISSING_CAS:${hash}`) },
    })
    const branchDb = options.driver.openDb({
      dbRoot: branchRoot,
      cas: overlayCas,
      partition: options.partition,
      actor: options.actor,
      opId: '0'.repeat(64),
      opTimeMs: 0n,
      readOnly: true,
      onMissingCas: (hash) => { throw new Error(`SQL_BRANCH_MISSING_CAS:${hash}`) },
    })

    try {
      const baseTables = new Set(options.baseRoot === null ? [] : listUserTables(baseDb))
      const branchTables = new Set(branchRoot === null ? [] : listUserTables(branchDb))
      const allTables = [...new Set([...baseTables, ...branchTables])].sort()
      const tableDiffs: TableRowDiff[] = []

      for (const table of allTables) {
        const beforeSnap = baseTables.has(table)
          ? readTableSnapshot(baseDb, table)
          : { columns: [] as string[], pkColumns: [] as string[], rows: [] as Record<string, JsonValue>[] }
        const afterSnap = branchTables.has(table)
          ? readTableSnapshot(branchDb, table)
          : { columns: [] as string[], pkColumns: [] as string[], rows: [] as Record<string, JsonValue>[] }

        const keyColumns = afterSnap.pkColumns.length > 0 ? afterSnap.pkColumns : beforeSnap.pkColumns
        const keyFor = (row: Record<string, JsonValue>): string =>
          JSON.stringify(keyColumns.map(k => row[k] ?? null))
        const keyObjFor = (row: Record<string, JsonValue>): Record<string, JsonValue> => {
          const out: Record<string, JsonValue> = {}
          for (const k of keyColumns) out[k] = row[k] ?? null
          return out
        }

        const beforeMap = new Map<string, Record<string, JsonValue>>()
        for (const r of beforeSnap.rows) beforeMap.set(keyFor(r), r)
        const afterMap = new Map<string, Record<string, JsonValue>>()
        for (const r of afterSnap.rows) afterMap.set(keyFor(r), r)

        const inserted: Record<string, JsonValue>[] = []
        const updated: { key: Record<string, JsonValue>; before: Record<string, JsonValue>; after: Record<string, JsonValue> }[] = []
        const deleted: Record<string, JsonValue>[] = []

        for (const [k, afterRow] of afterMap) {
          const beforeRow = beforeMap.get(k)
          if (beforeRow === undefined) {
            inserted.push(afterRow)
          } else if (JSON.stringify(beforeRow) !== JSON.stringify(afterRow)) {
            updated.push({ key: keyObjFor(afterRow), before: beforeRow, after: afterRow })
          }
        }
        for (const [k, beforeRow] of beforeMap) {
          if (!afterMap.has(k)) deleted.push(beforeRow)
        }

        if (inserted.length > 0 || updated.length > 0 || deleted.length > 0) {
          tableDiffs.push({ table, keyColumns, inserted, updated, deleted })
        }
      }

      return { baseRoot: options.baseRoot, branchRoot, merkle, tables: tableDiffs }
    } finally {
      baseDb.close()
      branchDb.close()
    }
  }

  return {
    topic: options.topic,
    baseRoot: options.baseRoot,
    exec(sql, params = [], execOptions = { mode: 'user' }) {
      ensureOpen()
      const res = openCurrentDb().exec(sql, params, execOptions)
      recordedStatements.push({ sql, params: params.slice() })
      return res
    },
    query(sql, params = []) {
      ensureOpen()
      return openCurrentDb().query(sql, params)
    },
    commitBranch,
    diff: computeDiff,
    toProposal(proposalOpts = {}) {
      const diff = computeDiff()
      const preconditions: JsonValue[] = []
      if (proposalOpts.withRowGuards !== false) {
        for (const tbl of diff.tables) {
          for (const upd of tbl.updated) {
            if (typeof upd.before._last_op_id === 'string') {
              preconditions.push({
                kind: 'based_on_row',
                table: tbl.table,
                where: upd.key,
                lastOpId: upd.before._last_op_id,
              })
            } else {
              preconditions.push({
                kind: 'row_matches',
                table: tbl.table,
                where: upd.key,
                expect: upd.before,
              })
            }
          }
          for (const del of tbl.deleted) {
            const where: Record<string, JsonValue> = {}
            for (const k of tbl.keyColumns) where[k] = del[k] ?? null
            if (typeof del._last_op_id === 'string') {
              preconditions.push({
                kind: 'based_on_row',
                table: tbl.table,
                where,
                lastOpId: del._last_op_id,
              })
            }
          }
        }
      }
      return {
        topic: options.topic,
        baseRoot: options.baseRoot,
        branchRoot: diff.branchRoot,
        statements: recordedStatements.slice(),
        preconditions,
        diff,
      }
    },
    close() {
      if (closed) return
      closed = true
      if (db !== null) {
        db.close()
        db = null
      }
    },
  }
}

export interface FederatedSqlSource {
  readonly session: {
    query(name: string, input?: unknown): Promise<{ readonly value: unknown }>
  }
  readonly topic: string
  /** Optional allowlist of tables to mount from this source; defaults to all user tables. */
  readonly tables?: readonly string[]
}

/**
 * Execute a zero-trust read-only SQL query (including JOINs & CTEs) across multiple separate
 * encrypted Chronolog sessions locally without sharing encryption keys or exposing data to any host.
 * Each source's tables are mounted as "<alias>__<table>" in an ephemeral read-only sqlite-cas workspace.
 */
export async function queryFederatedSql(
  sources: Readonly<Record<string, FederatedSqlSource>>,
  sql: string,
  params: readonly JsonValue[] = [],
  options: { readonly format?: 'rows' | 'objects'; readonly driver?: SqliteBuiltinDriver } = {},
): Promise<{
  readonly columns: readonly string[]
  readonly rows: readonly (readonly JsonValue[])[] | readonly Record<string, JsonValue>[]
  readonly mountedTables: readonly string[]
}> {
  const driver = options.driver ?? await createSqliteCasDriver()
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const db = driver.openDb({
    dbRoot: null,
    cas,
    partition: 'private',
    actor: '0'.repeat(64),
    opId: '0'.repeat(64),
    opTimeMs: 0n,
    readOnly: false,
    onMissingCas: (h) => { throw new Error(`FEDERATED_SQL_MISSING:${h}`) },
  })

  const mountedTables: string[] = []
  try {
    for (const [alias, src] of Object.entries(sources)) {
      if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(alias)) {
        throw new Error(`FEDERATED_SQL_INVALID_ALIAS:${alias}`)
      }
      let tableNames: string[]
      if (src.tables !== undefined && src.tables.length > 0) {
        tableNames = [...src.tables]
      } else {
        const listed = (await src.session.query(src.topic, { kind: 'tables' })).value as {
          readonly tables?: readonly { readonly name: string; readonly type: string }[]
        }
        tableNames = (listed?.tables ?? []).filter(t => t.type === 'table').map(t => t.name)
      }

      for (const tbl of tableNames) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(tbl)) continue
        const data = (await src.session.query(src.topic, {
          sql: `SELECT * FROM ${quoteIdent(tbl)}`,
        })).value as SqliteQueryResult
        if (!data || !Array.isArray(data.columns) || data.columns.length === 0) continue
        const mountedName = `${alias}__${tbl}`
        const colDefs = data.columns.map((c: string) => quoteIdent(c)).join(', ')
        db.exec(`CREATE TABLE ${quoteIdent(mountedName)} (${colDefs})`, [], { mode: 'admin' })
        if (data.rows.length > 0) {
          const placeholders = data.columns.map(() => '?').join(', ')
          const insertSql = `INSERT INTO ${quoteIdent(mountedName)} VALUES (${placeholders})`
          for (const row of data.rows) {
            db.exec(insertSql, row, { mode: 'admin' })
          }
        }
        mountedTables.push(mountedName)
      }
    }

    const res = db.query(sql, params)
    if (options.format === 'objects') {
      const objRows = res.rows.map(row => {
        const obj: Record<string, JsonValue> = {}
        for (let i = 0; i < res.columns.length; i++) obj[res.columns[i]!] = row[i] ?? null
        return obj
      })
      return { columns: res.columns, rows: objRows, mountedTables }
    }
    return { columns: res.columns, rows: res.rows, mountedTables }
  } finally {
    db.close()
  }
}

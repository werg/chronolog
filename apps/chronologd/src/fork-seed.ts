// Builds the ordinary signed transactions that recreate a snapshot's
// application schema and rows in a forked group. Every replica of the fork
// replays them like any other transaction, so no special base-state import is
// needed. The plan is plain JSON so the operator can inspect it before seeding.
import { createHash } from 'node:crypto'

import { isReservedSchemaObjectName } from '@chronolog/materializer-doltlite'

/** Marker table written by every seed batch; makes seeding idempotent. */
export const FORK_SEED_TABLE = 'fork_seed'

/** A JSON-safe SQLite value: INTEGER as decimal text, BLOB as base64url. */
export type SeedValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: string }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: string }

export interface SeedStatement {
  readonly sql: string
  readonly bindings: readonly SeedValue[]
}

export interface SeedBatch {
  readonly batch: number
  readonly label: string
  /**
   * Ordinary transaction statements. The first asserts the batch has not been
   * applied (rejection code `assert:fork_seed_applied`); the last records it.
   */
  readonly statements: readonly SeedStatement[]
}

export const FORK_SEED_APPLIED_CODE = 'fork_seed_applied'


export interface ForkSeedPlan {
  readonly format: 'chronolog-fork-seed-v2'
  readonly sourceGroupId: string
  readonly snapshotManifestSha256: string
  readonly sourceRevision: string
  readonly batches: readonly SeedBatch[]
}

/** The subset of the native DoltLite/node:sqlite API used here. */
export interface ReadableDatabase {
  prepare(sql: string): {
    all(...parameters: unknown[]): unknown[]
    setReadBigInts?(enabled: boolean): void
    setReturnArrays?(enabled: boolean): void
  }
}

interface SchemaObject {
  readonly type: 'table' | 'index' | 'view' | 'trigger'
  readonly name: string
  readonly tableName: string
  readonly sql: string
}

interface TableShape {
  readonly name: string
  readonly columns: readonly string[]
  readonly primaryKey: readonly string[]
  readonly foreignKeys: readonly { readonly table: string; readonly from: readonly string[]; readonly to: readonly string[] }[]
}

const MAX_ROWS_PER_BATCH = 250
const MAX_BINDING_BYTES_PER_BATCH = 4 * 1024 * 1024

export function buildForkSeedPlan(
  source: ReadableDatabase,
  origin: { readonly sourceGroupId: string; readonly snapshotManifestSha256: string; readonly sourceRevision: bigint },
): ForkSeedPlan {
  const objects = applicationSchema(source)
  const tables = objects.filter((object) => object.type === 'table').map((object) => tableShape(source, object.name))
  const batches: SeedBatch[] = []
  const marker = (batch: number, label: string): SeedStatement => ({
    sql: `INSERT INTO ${FORK_SEED_TABLE} (batch, label) VALUES (?, ?)`,
    bindings: [{ kind: 'integer', value: String(batch) }, { kind: 'text', value: label }],
  })
  const guard = (condition: string): SeedStatement => ({
    sql: `SELECT chronolog_assert(${condition}, '${FORK_SEED_APPLIED_CODE}')`,
    bindings: [],
  })
  const notApplied = (batch: number): SeedStatement =>
    guard(`NOT EXISTS (SELECT 1 FROM ${FORK_SEED_TABLE} WHERE batch = ${batch})`)

  batches.push({
    batch: 1,
    label: 'schema: tables',
    statements: [
      guard(`NOT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = '${FORK_SEED_TABLE}')`),
      { sql: `CREATE TABLE ${FORK_SEED_TABLE} (batch INTEGER PRIMARY KEY, label TEXT NOT NULL) STRICT`, bindings: [] },
      ...objects.filter((object) => object.type === 'table').map((object) => ({ sql: object.sql, bindings: [] })),
      marker(1, 'schema: tables'),
    ],
  })

  for (const table of insertionOrder(tables)) {
    let pending: SeedStatement[] = []
    let bytes = 0
    let part = 1
    const flush = (): void => {
      if (pending.length === 0) return
      const batch = batches.length + 1
      const label = `rows: ${table.name} #${part}`
      batches.push({ batch, label, statements: [notApplied(batch), ...pending, marker(batch, label)] })
      pending = []
      bytes = 0
      part += 1
    }
    const insert = `INSERT INTO ${quote(table.name)} (${table.columns.map(quote).join(', ')}) VALUES (${table.columns.map(() => '?').join(', ')})`
    for (const row of tableRows(source, table)) {
      const bindings = row.map(seedValue)
      const rowBytes = bindings.reduce<number>((total, value) => total + seedValueBytes(value), 0)
      // Each batch is one transaction of at most 256 statements (guard + rows + marker).
      if (pending.length >= MAX_ROWS_PER_BATCH || (pending.length > 0 && bytes + rowBytes > MAX_BINDING_BYTES_PER_BATCH)) flush()
      pending.push({ sql: insert, bindings })
      bytes += rowBytes
    }
    flush()
  }

  const rest = objects.filter((object) => object.type !== 'table')
  if (rest.length > 0) {
    const batch = batches.length + 1
    batches.push({
      batch,
      label: 'schema: indexes, views, triggers',
      statements: [notApplied(batch), ...rest.map((object) => ({ sql: object.sql, bindings: [] })), marker(batch, 'schema: indexes, views, triggers')],
    })
  }
  return {
    format: 'chronolog-fork-seed-v2',
    sourceGroupId: origin.sourceGroupId,
    snapshotManifestSha256: origin.snapshotManifestSha256,
    sourceRevision: origin.sourceRevision.toString(10),
    batches,
  }
}

/**
 * Digest of every application table's rows in primary-key order, keyed by
 * table. Used to confirm a seeded fork holds exactly the snapshot's data.
 */
export function applicationTableDigests(database: ReadableDatabase): Record<string, string> {
  const result: Record<string, string> = {}
  for (const object of applicationSchema(database)) {
    if (object.type !== 'table') continue
    const table = tableShape(database, object.name)
    const hash = createHash('sha256')
    for (const row of tableRows(database, table)) hash.update(JSON.stringify(row.map(seedValue))).update('\n')
    result[table.name] = hash.digest('hex')
  }
  return result
}

function applicationSchema(database: ReadableDatabase): SchemaObject[] {
  const rows = query(database, 'SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY rowid')
  return rows.flatMap((row) => {
    const [type, name, tableName, sql] = row as [string, string, string, string]
    if (type !== 'table' && type !== 'index' && type !== 'view' && type !== 'trigger') return []
    if (isReservedSchemaObjectName(name) || isReservedSchemaObjectName(tableName)) return []
    // A source that was itself a fork carries its own seed markers; the new fork writes fresh ones.
    if (tableName.toLowerCase() === FORK_SEED_TABLE) return []
    if (type === 'table' && /^\s*CREATE\s+VIRTUAL\s+TABLE/iu.test(sql)) throw new Error(`FORK_SEED_VIRTUAL_TABLE_UNSUPPORTED:${name}`)
    return [{ type, name, tableName, sql }]
  })
}

function tableShape(database: ReadableDatabase, name: string): TableShape {
  const columns = query(database, `SELECT name, pk, hidden FROM pragma_table_xinfo(${literal(name)}) ORDER BY cid`)
    .map((row) => row as [string, bigint | number, bigint | number])
  const insertable = columns.filter(([, , hidden]) => Number(hidden) === 0).map(([column]) => column)
  const primaryKey = columns.filter(([, pk]) => Number(pk) > 0)
    .sort((left, right) => Number(left[1]) - Number(right[1])).map(([column]) => column)
  if (primaryKey.length === 0) throw new Error(`FORK_SEED_PRIMARY_KEY_REQUIRED:${name}`)
  const references = new Map<number, { table: string; from: string[]; to: string[] }>()
  for (const row of query(database, `SELECT id, "table", "from", "to" FROM pragma_foreign_key_list(${literal(name)}) ORDER BY id, seq`)) {
    const [id, table, from, to] = row as [bigint | number, string, string, string | null]
    const entry = references.get(Number(id)) ?? { table, from: [], to: [] }
    entry.from.push(from)
    entry.to.push(to ?? '')
    references.set(Number(id), entry)
  }
  return { name, columns: insertable, primaryKey, foreignKeys: [...references.values()] }
}

/** Parents before children; a foreign-key cycle between tables is refused. */
function insertionOrder(tables: readonly TableShape[]): TableShape[] {
  const byName = new Map(tables.map((table) => [table.name.toLowerCase(), table]))
  const ordered: TableShape[] = []
  const state = new Map<string, 'visiting' | 'done'>()
  const visit = (table: TableShape): void => {
    const key = table.name.toLowerCase()
    if (state.get(key) === 'done') return
    if (state.get(key) === 'visiting') throw new Error(`FORK_SEED_FOREIGN_KEY_CYCLE:${table.name}`)
    state.set(key, 'visiting')
    for (const reference of table.foreignKeys) {
      const parent = byName.get(reference.table.toLowerCase())
      if (parent !== undefined && parent !== table) visit(parent)
    }
    state.set(key, 'done')
    ordered.push(table)
  }
  for (const table of tables) visit(table)
  return ordered
}

/** Rows in primary-key order, with self-referencing rows after the rows they reference. */
function tableRows(database: ReadableDatabase, table: TableShape): unknown[][] {
  const rows = query(database, `SELECT ${table.columns.map(quote).join(', ')} FROM ${quote(table.name)} ORDER BY ${table.primaryKey.map(quote).join(', ')}`)
    .map((row) => row as unknown[])
  const selfReferences = table.foreignKeys.filter((reference) => reference.table.toLowerCase() === table.name.toLowerCase())
  if (selfReferences.length === 0) return rows
  const index = (column: string): number => {
    const position = table.columns.findIndex((candidate) => candidate.toLowerCase() === column.toLowerCase())
    if (position < 0) throw new Error(`FORK_SEED_FOREIGN_KEY_COLUMN_UNSUPPORTED:${table.name}.${column}`)
    return position
  }
  const keyOf = (row: unknown[], columns: readonly string[]): string => JSON.stringify(columns.map((column) => seedValue(row[index(column)])))
  const references = selfReferences.map((reference) => ({
    from: reference.from,
    to: reference.to.map((column, position) => column === '' ? table.primaryKey[position]! : column),
  }))
  const pending = new Map<string, unknown[]>()
  for (const reference of references) {
    for (const row of rows) pending.set(`${reference.to.join(',')}|${keyOf(row, reference.to)}`, row)
  }
  const emitted = new Set<unknown[]>()
  const ordered: unknown[][] = []
  const visiting = new Set<unknown[]>()
  const emit = (row: unknown[]): void => {
    if (emitted.has(row)) return
    if (visiting.has(row)) throw new Error(`FORK_SEED_FOREIGN_KEY_CYCLE:${table.name}`)
    visiting.add(row)
    for (const reference of references) {
      if (reference.from.some((column) => row[index(column)] === null)) continue
      const parent = pending.get(`${reference.to.join(',')}|${keyOf(row, reference.from)}`)
      if (parent !== undefined && parent !== row) emit(parent)
    }
    visiting.delete(row)
    emitted.add(row)
    ordered.push(row)
  }
  for (const row of rows) emit(row)
  return ordered
}

function seedValue(value: unknown): SeedValue {
  if (value === null) return { kind: 'null' }
  if (typeof value === 'bigint') return { kind: 'integer', value: value.toString(10) }
  // Rows are read with BigInt integers, so a JS number is always a REAL.
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('FORK_SEED_NONFINITE_REAL')
    return { kind: 'real', value }
  }
  if (typeof value === 'string') return { kind: 'text', value }
  if (value instanceof Uint8Array) return { kind: 'blob', value: Buffer.from(value).toString('base64url') }
  throw new Error('FORK_SEED_VALUE_UNSUPPORTED')
}

function seedValueBytes(value: SeedValue): number {
  if (value.kind === 'text') return Buffer.byteLength(value.value)
  if (value.kind === 'blob') return Math.ceil(value.value.length * 3 / 4)
  return 8
}

function query(database: ReadableDatabase, sql: string): unknown[] {
  const statement = database.prepare(sql)
  statement.setReadBigInts?.(true)
  statement.setReturnArrays?.(true)
  return statement.all()
}

function quote(identifier: string): string { return `"${identifier.replaceAll('"', '""')}"` }
function literal(value: string): string { return `'${value.replaceAll("'", "''")}'` }

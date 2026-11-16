import { decodeRowKey, type RowKeyPart } from '@chronolog/protocol'

import { OWNER_COLUMN, POLICY_VIOLATION_FUNCTION } from '../sql-profile.js'
import type { DatabaseLike } from '../types.js'
import { grantsToMeView, ownerIdsView, type OwnerOperation } from './schema.js'
import { closeReaderPolicySql, sealedWriteGuard } from './sealed.js'

/** The declaration every registered table's owner column must have. */
export const OWNER_COLUMN_TYPE = 'INTEGER'
export const OWNER_COLUMN_DEFAULT = 'chronolog_actor_id()'
export const OWNER_COLUMN_SQL = `${OWNER_COLUMN} ${OWNER_COLUMN_TYPE} NOT NULL DEFAULT (${OWNER_COLUMN_DEFAULT})`

export interface ColumnShape {
  readonly name: string
  readonly type: string
  readonly notNull: boolean
  readonly defaultValue: string | null
  /** Position in the primary key (1-based), or 0. */
  readonly primaryKey: number
  /** 0 for ordinary columns; generated and hidden columns are nonzero. */
  readonly hidden: number
}

export interface ForeignKeyShape {
  readonly table: string
  readonly from: readonly string[]
  readonly to: readonly (string | null)[]
  readonly onUpdate: string
  readonly onDelete: string
}

export interface TableShape {
  readonly name: string
  readonly columns: readonly ColumnShape[]
  readonly primaryKey: readonly string[]
  readonly foreignKeys: readonly ForeignKeyShape[]
  /** SQLite's INTEGER PRIMARY KEY alias; its implicit NOT NULL is not in table_xinfo. */
  readonly rowidPrimaryKey?: string
}

export function quoteIdentifier(name: string): string {
  return `"${name.replaceAll('"', '""')}"`
}

export function quoteText(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

type Row = Record<string, unknown>

function rows(database: DatabaseLike, sql: string, ...parameters: unknown[]): Row[] {
  return database.prepare(sql).all(...parameters).map((row) => {
    if (Array.isArray(row)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
    return row
  })
}

/** The schema's spelling of an ordinary main-schema table, matched case-insensitively. */
export function resolveTable(database: DatabaseLike, name: string): string | null {
  const row = rows(database, `SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name = ? COLLATE NOCASE`, name)[0]
  return row === undefined ? null : String(row.name)
}

export function tableShape(database: DatabaseLike, name: string): TableShape {
  const columns = rows(database, `SELECT name, type, "notnull" AS not_null, dflt_value, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid`, name)
    .map((row): ColumnShape => ({
      name: String(row.name),
      type: String(row.type),
      notNull: Number(row.not_null) === 1,
      defaultValue: typeof row.dflt_value === 'string' ? row.dflt_value : null,
      primaryKey: Number(row.pk),
      hidden: Number(row.hidden),
    }))
  const primaryKey = columns.filter((column) => column.primaryKey > 0)
    .sort((left, right) => left.primaryKey - right.primaryKey).map((column) => column.name)
  const grouped = new Map<number, { table: string; from: string[]; to: (string | null)[]; onUpdate: string; onDelete: string }>()
  for (const row of rows(database, `SELECT id, "table", "from", "to", on_update, on_delete FROM pragma_foreign_key_list(?) ORDER BY id, seq`, name)) {
    const id = Number(row.id)
    const entry = grouped.get(id) ?? { table: String(row.table), from: [], to: [], onUpdate: String(row.on_update), onDelete: String(row.on_delete) }
    entry.from.push(String(row.from))
    entry.to.push(typeof row.to === 'string' ? row.to : null)
    grouped.set(id, entry)
  }
  const singleIntegerKey = primaryKey.length === 1 && columns.find((column) => column.name === primaryKey[0])?.type.toUpperCase() === 'INTEGER'
  const rowidPrimaryKey = singleIntegerKey && !rows(database, 'SELECT origin FROM pragma_index_list(?)', name).some((row) => row.origin === 'pk')
    ? primaryKey[0] : undefined
  return { name, columns, primaryKey, foreignKeys: [...grouped.values()], ...(rowidPrimaryKey === undefined ? {} : { rowidPrimaryKey }) }
}

export function ownerColumn(shape: TableShape): ColumnShape | undefined {
  return shape.columns.find((column) => column.name.toLowerCase() === OWNER_COLUMN)
}

/** True when the owner column is declared exactly as `OWNER_COLUMN_SQL`. */
export function hasValidOwnerColumn(shape: TableShape): boolean {
  const column = ownerColumn(shape)
  return column !== undefined && column.name === OWNER_COLUMN && column.hidden === 0 &&
    column.type.toUpperCase() === OWNER_COLUMN_TYPE && column.notNull &&
    column.defaultValue !== null && normalizeDefault(column.defaultValue) === OWNER_COLUMN_DEFAULT
}

function normalizeDefault(value: string): string {
  let text = value.trim()
  while (text.startsWith('(') && text.endsWith(')')) text = text.slice(1, -1).trim()
  return text.replace(/\s+/gu, '').toLowerCase()
}

/** An FK that carries the owner: its columns include chronolog_owner, mapped to the parent's chronolog_owner. */
export function isOwnerComposite(foreignKey: ForeignKeyShape): boolean {
  return foreignKey.from.some((column, index) =>
    column.toLowerCase() === OWNER_COLUMN && foreignKey.to[index]?.toLowerCase() === OWNER_COLUMN)
}

const PASSIVE_ACTIONS: ReadonlySet<string> = new Set(['NO ACTION', 'RESTRICT'])

/**
 * Cross-owner references may not cascade: an owner-composite FK must be
 * ON UPDATE CASCADE (so a transfer carries the child) and may delete-cascade;
 * any other FK must be RESTRICT or NO ACTION. Returns the offending parent table.
 */
export function foreignKeyViolation(shape: TableShape): string | null {
  for (const foreignKey of shape.foreignKeys) {
    const onUpdate = foreignKey.onUpdate.toUpperCase()
    const onDelete = foreignKey.onDelete.toUpperCase()
    const valid = isOwnerComposite(foreignKey)
      ? onUpdate === 'CASCADE' && (onDelete === 'CASCADE' || PASSIVE_ACTIONS.has(onDelete))
      : PASSIVE_ACTIONS.has(onUpdate) && PASSIVE_ACTIONS.has(onDelete)
    if (!valid) return foreignKey.table
  }
  return null
}

/** Every row must have one unambiguous, non-NULL primary-key tuple. */
export function hasNonNullPrimaryKey(shape: TableShape): boolean {
  return shape.primaryKey.length > 0 && shape.primaryKey.length <= 64 && shape.primaryKey.every((name) =>
    shape.rowidPrimaryKey === name || shape.columns.find((column) => column.name === name)?.notNull === true)
}

/**
 * Lossless typed primary-key tuple. Owner components use stable owner keys,
 * never this materializer's principal ids, so fork remapping preserves keys.
 */
export function rowKeyExpression(alias: string, primaryKey: readonly string[]): string {
  return `chronolog_row_key(${primaryKey.map((column) => column.toLowerCase() === OWNER_COLUMN
    ? `(SELECT key FROM chronolog_principals WHERE id = ${alias}.${quoteIdentifier(column)})`
    : `${alias}.${quoteIdentifier(column)}`).join(', ')})`
}

/** Decode raw storage values; TEXT remains bytes, including embedded NUL/invalid UTF-8. */
export function parseRowKey(key: string): readonly RowKeyPart[] {
  try { return decodeRowKey(key) } catch { throw new Error('MATERIALIZER_ROW_KEY_INVALID') }
}

/** Indexed tuple lookup plus an exact typed-key check independent of collation. */
export function rowKeyFilter(alias: string, primaryKey: readonly string[]): string {
  const columns = primaryKey.map((column) => {
    const value = 'CASE WHEN ? THEN CAST(? AS TEXT) ELSE ? END'
    return `${alias}.${quoteIdentifier(column)} IS ${column.toLowerCase() === OWNER_COLUMN
      ? `(SELECT id FROM chronolog_principals WHERE key = (${value}))` : `(${value})`}`
  })
  return `${columns.join(' AND ')} AND ${rowKeyExpression(alias, primaryKey)} = ?`
}

export function rowKeyBindings(key: string, primaryKey: readonly string[]): unknown[] {
  const values = parseRowKey(key)
  if (values.length !== primaryKey.length) throw new Error('MATERIALIZER_ROW_KEY_INVALID')
  return [...values.flatMap((part) => {
    const value = part.kind === 'null' ? null : part.kind === 'real' ? Float64Array.of(part.value)
      : part.kind === 'text' || part.kind === 'blob' ? Buffer.from(part.value) : part.value
    return [part.kind === 'text' ? 1 : 0, value, value]
  }), key]
}

export type TriggerEvent = 'ins' | 'upd' | 'del' | 'life_ins'
export const PLATFORM_TRIGGER_EVENTS: readonly TriggerEvent[] = ['ins', 'upd', 'del', 'life_ins']

export function platformTriggerName(table: string, event: TriggerEvent): string {
  return event.startsWith('life_') ? `chronolog_l_${table}_${event.slice(5)}` : `chronolog_k_${table}_${event}`
}

export interface PlatformTrigger {
  readonly name: string
  readonly sql: string
}

/** The three generated BEFORE triggers that enforce row ownership on `shape` (§4). */
export function platformTriggers(shape: TableShape): readonly PlatformTrigger[] {
  const table = shape.name
  const tableText = quoteText(table)
  const owner = quoteIdentifier(OWNER_COLUMN)
  const oldKey = rowKeyExpression('OLD', shape.primaryKey)
  const newKey = rowKeyExpression('NEW', shape.primaryKey)
  const violation = (command: string): string => `SELECT ${POLICY_VIOLATION_FUNCTION}(${tableText}, '${command}')`
  const header = (event: TriggerEvent, timing: string): string =>
    `CREATE TRIGGER ${quoteIdentifier(platformTriggerName(table, event))} BEFORE ${timing} ON ${quoteIdentifier(table)} FOR EACH ROW BEGIN`
  const capColumns = shape.columns.filter((column) => column.hidden === 0 && column.name.toLowerCase() !== OWNER_COLUMN)
  const changed = capColumns.length === 0
    ? '0'
    : `EXISTS (SELECT 1 FROM (VALUES ${capColumns.map((column) =>
      `(${quoteText(column.name)}, NOT chronolog_value_equal(OLD.${quoteIdentifier(column.name)}, NEW.${quoteIdentifier(column.name)}))`).join(', ')}) ` +
      `WHERE column2 AND column1 NOT IN (SELECT value FROM json_each(g.columns)))`

  // Each trigger is a CASE chain: SQLite evaluates the WHEN arms in order and
  // stops at the first that holds, so the common case (the signer owns the
  // row) costs one comparison. It fails closed: an arm that is NULL does not
  // match, and only a matching arm yields 0; anything else is a violation.
  const ownedBy = (ownerSql: string, operation: OwnerOperation): string =>
    `EXISTS (SELECT 1 FROM ${ownerIdsView(operation)} WHERE id = ${ownerSql})`
  const insert = `${header('ins', 'INSERT')}
  ${violation('insert')} WHERE CASE
    WHEN NEW.${owner} = chronolog_actor_id() THEN 0
    WHEN ${ownedBy(`NEW.${owner}`, 'insert')} THEN 0
    WHEN EXISTS (SELECT 1 FROM ${grantsToMeView('insert')} AS g WHERE g.tbl = ${tableText} AND g.grantor = NEW.${owner} AND g.row_key IS NULL) THEN 0
    WHEN EXISTS (SELECT 1 FROM chronolog_exemptions AS e WHERE e.kind = 'seed' AND e.tbl = ${tableText}) THEN 0
    ELSE 1 END;
END`
  const update = `${header('upd', 'UPDATE')}
  ${violation('update')} WHERE CASE
    WHEN NEW.${owner} IS OLD.${owner} AND OLD.${owner} = chronolog_actor_id() THEN 0
    WHEN NEW.${owner} IS OLD.${owner} AND ${ownedBy(`OLD.${owner}`, 'update')} THEN 0
    WHEN NEW.${owner} IS OLD.${owner} AND EXISTS (SELECT 1 FROM ${grantsToMeView('update')} AS g WHERE g.tbl = ${tableText} AND g.grantor = OLD.${owner}
      AND (g.row_key IS NULL OR g.row_key = ${oldKey})
      AND (g.columns IS NULL OR NOT ${changed})) THEN 0
    WHEN EXISTS (SELECT 1 FROM chronolog_exemptions AS e WHERE e.kind = 'transfer' AND e.tbl = ${tableText}
      AND e.from_owner = OLD.${owner} AND e.to_owner = NEW.${owner} AND (e.row_key IS NULL OR e.row_key = ${oldKey})) THEN 0
    ELSE 1 END;
END`
  const remove = `${header('del', 'DELETE')}
  ${violation('delete')} WHERE CASE
    WHEN OLD.${owner} = chronolog_actor_id() THEN 0
    WHEN ${ownedBy(`OLD.${owner}`, 'delete')} THEN 0
    WHEN EXISTS (SELECT 1 FROM ${grantsToMeView('delete')} AS g WHERE g.tbl = ${tableText} AND g.grantor = OLD.${owner}
      AND (g.row_key IS NULL OR g.row_key = ${oldKey})) THEN 0
    ELSE 1 END;
END`
  // Invalidate before a DELETE/key/owner change can expose a replacement row
  // to application AFTER triggers. Only these exact generated callers have
  // column-scoped metadata privileges; application triggers never inherit them.
  const ownerKey = (alias: string): string => `(SELECT key FROM chronolog_principals WHERE id = ${alias}.${owner})`
  const revoke = `UPDATE chronolog_grants SET revoked_tx = chronolog_transaction_id()
    WHERE tbl = ${tableText} AND row_key = ${oldKey} AND revoked_tx IS NULL;`
  const cancel = (existing: boolean, next: boolean, condition = '1'): string => `UPDATE chronolog_transfers
    SET state = 'cancelled', closed_tx = chronolog_transaction_id() WHERE state = 'open' AND (
      ${existing ? `offer_id IN (SELECT offer_id FROM chronolog_transfer_scope WHERE tbl = ${tableText} AND row_key = ${oldKey}) OR` : ''}
      (tbl IS NULL AND from_owner IN (${[...(existing ? [ownerKey('OLD')] : []), ...(next ? [ownerKey('NEW')] : [])].join(', ')}))) AND (${condition});`
  const anyChange = `EXISTS (SELECT 1 FROM (VALUES ${shape.columns.filter((column) => column.hidden === 0).map((column) =>
    `(NOT chronolog_value_equal(OLD.${quoteIdentifier(column.name)}, NEW.${quoteIdentifier(column.name)}))`).join(', ')}) WHERE column1)`
  // A transfer may change an owner component of the PK without creating a
  // new row generation. Preserve its policy ID and explicit reader list.
  const ownershipOnly = `OLD.${owner} IS NOT NEW.${owner}${shape.primaryKey.filter((column) => column.toLowerCase() !== OWNER_COLUMN)
    .map((column) => ` AND chronolog_value_equal(OLD.${quoteIdentifier(column)}, NEW.${quoteIdentifier(column)})`).join('')}`
  const movePolicy = `UPDATE chronolog_reader_policies SET row_key = ${newKey}
    WHERE tbl = ${tableText} AND row_key = ${oldKey} AND closed_tx IS NULL AND (${oldKey} <> ${newKey}) AND (${ownershipOnly});`
  const updatePolicy = `${closeReaderPolicySql(table, oldKey, `${oldKey} <> ${newKey} AND NOT (${ownershipOnly})`)}\n    ${movePolicy}`
  const lifecycle = (event: TriggerEvent, timing: string, when: string, body: string): PlatformTrigger => ({
    name: platformTriggerName(table, event),
    sql: `CREATE TRIGGER ${quoteIdentifier(platformTriggerName(table, event))} AFTER ${timing} ON ${quoteIdentifier(table)} FOR EACH ROW WHEN ${when} BEGIN
    ${body}
END`,
  })
  return [
    { name: platformTriggerName(table, 'ins'), sql: insert },
    { name: platformTriggerName(table, 'upd'), sql: update.replace('\nEND', `\n    ${sealedWriteGuard(shape, oldKey)}\n    ${updatePolicy}\n    ${revoke.replace(' AND revoked_tx IS NULL;', ` AND revoked_tx IS NULL AND (${oldKey} <> ${newKey} OR OLD.${owner} IS NOT NEW.${owner});`)}\n    ${cancel(true, true, anyChange)}\nEND`) },
    { name: platformTriggerName(table, 'del'), sql: remove.replace('\nEND', `\n    ${closeReaderPolicySql(table, oldKey)}\n    ${revoke}\n    ${cancel(true, false)}\nEND`) },
    lifecycle('life_ins', 'INSERT', `NOT EXISTS (SELECT 1 FROM chronolog_exemptions WHERE kind = 'seed' AND tbl = ${tableText})`, cancel(false, true)),
  ]
}

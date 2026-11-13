import { createHash } from 'node:crypto'

import { chronologTriggerUsesIgnore } from '@dolthub/doltlite'
import {
  GROUP_COLLECTIVE_ID,
  platformObjectIdHashInput,
  type CollectiveRole,
  type PlatformOp,
  type SqlValue,
} from '@chronolog/protocol'

import { isReservedSchemaObjectName, OWNER_COLUMN, withProfiledStatement } from '../sql-profile.js'
import type { DatabaseLike, SqlRuntimeLimits, StatementLike } from '../types.js'
import { PLATFORM_VIEW_NAMES, ownerIdsView, type OwnerOperation } from './schema.js'
import {
  OWNER_COLUMN_SQL,
  foreignKeyViolation,
  hasValidOwnerColumn,
  isOwnerComposite,
  ownerColumn,
  platformTriggerName,
  platformTriggers,
  quoteIdentifier,
  resolveTable,
  rowKeyBindings,
  rowKeyExpression,
  rowKeyFilter,
  tableShape,
  type TableShape,
} from './tables.js'

/** A deterministic rejection raised by platform code; `code` is the full rejection code. */
export class PlatformRejection extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'PlatformRejection'
  }
}

const reject = (reason: string): never => { throw new PlatformRejection(`platform:${reason}`) }

/**
 * Platform tables a fork seeds verbatim from its source (§7), parents first.
 * The `group` collective is not seeded: the fork's genesis root administers it.
 */
export const SEEDABLE_PLATFORM_TABLES: readonly string[] = [
  'chronolog_collectives', 'chronolog_collective_members', 'chronolog_grants', 'chronolog_transfers',
]

export interface PlatformContext {
  /** The signing key of the transaction: chronolog_actor(). */
  readonly actor: Uint8Array
  readonly txId: Uint8Array
  readonly limits: Partial<SqlRuntimeLimits>
}

type Row = Record<string, unknown>

interface Collective {
  readonly kind: 'group' | 'team'
  readonly roles: Readonly<Record<OwnerOperation, CollectiveRole>>
}

interface Membership {
  readonly role: CollectiveRole
  readonly state: 'invited' | 'active' | 'left'
}

interface RowRef {
  readonly table: string
  readonly key: string
}

/**
 * Trusted, deterministic platform code for one transaction. Every write runs
 * as the signer: platform statements use the `platform` authorizer mode, but
 * chronolog_actor() stays the signer, and app triggers they fire are checked
 * like any other write.
 */
export class PlatformSession {
  readonly #database: DatabaseLike
  readonly #context: PlatformContext

  constructor(database: DatabaseLike, context: PlatformContext) {
    this.#database = database
    this.#context = context
  }

  /** The signer is an active admin of the `group` collective. */
  isSchemaAdmin(): boolean {
    return this.#isCollectiveAdmin(GROUP_COLLECTIVE_ID, this.#context.actor)
  }

  /**
   * Start a transaction: close fork seeding unless the signer is the genesis
   * root (seeding ends at the plan's EndSeeding step, or at the first
   * transaction by anyone else if that comes first),
   * give a first-time signer its principal id, and read whether the signer is
   * a schema admin and the schema cookie. One cached read, since it runs for
   * every transaction.
   */
  begin(): { readonly actorId: bigint; readonly schemaAdmin: boolean; readonly schemaVersion: number } {
    const row = cachedInternalStatement(this.#database, BEGIN_SQL).get(GROUP_COLLECTIVE_ID, this.#context.actor)
    if (row === undefined || Array.isArray(row)) throw new Error('MATERIALIZER_PLATFORM_STATE_MISSING')
    if (Number(row.seeding_open) === 1 && !sameBytes(asBytes(row.root_admin), this.#context.actor)) {
      this.#run('UPDATE chronolog_platform SET seeding_open = 0 WHERE singleton = 1')
    }
    const actorId = row.actor_id === null ? this.#principal(this.#context.actor) : BigInt(row.actor_id as number | bigint)
    return { actorId, schemaAdmin: Number(row.schema_admin) === 1, schemaVersion: Number(row.schema_version) }
  }

  execute(op: PlatformOp, stepIndex: number): void {
    switch (op.op) {
      case 'grant': return this.#grant(op, stepIndex)
      case 'revoke_grant': return this.#revokeGrant(op.grantId)
      case 'create_collective': return this.#createCollective(op, stepIndex)
      case 'accept_membership': return this.#acceptMembership(op.collectiveId)
      case 'leave': return this.#leave(op.collectiveId)
      case 'set_members': return this.#setMembers(op)
      case 'transfer_offer': return this.#transferOffer(op, stepIndex)
      case 'transfer_accept': return this.#transferAccept(op.offerId)
      case 'seed_rows': return this.#seedRows(op)
      case 'end_seeding': return this.#endSeeding()
    }
  }

  // ── tables ────────────────────────────────────────────────────────────────

  /**
   * Put a new application table under owner checks: add the owner column
   * (to an empty table), lint its foreign keys, and generate its triggers.
   * Run by reconciliation right after the statement that created the table;
   * only schema administrators can create tables.
   */
  #registerTable(name: string): void {
    let shape = tableShape(this.#database, name)
    if (shape.primaryKey.length === 0) reject('no_primary_key')
    if (ownerColumn(shape) === undefined) {
      // A non-constant DEFAULT can only be added to an empty table.
      if (this.#get(`SELECT EXISTS (SELECT 1 FROM ${quoteIdentifier(name)}) AS present`)?.present === 1) reject('table_not_empty')
      this.#run(`ALTER TABLE ${quoteIdentifier(name)} ADD COLUMN ${OWNER_COLUMN_SQL}`)
      shape = tableShape(this.#database, name)
    }
    if (!hasValidOwnerColumn(shape)) reject('owner_column_invalid')
    if (foreignKeyViolation(shape) !== null) reject('fk_action')
    // Rows written before registration must be ones the signer could have inserted.
    const foreign = this.#get(`
      SELECT 1 AS present FROM ${quoteIdentifier(name)}
       WHERE NOT coalesce(${quoteIdentifier(OWNER_COLUMN)} IN (SELECT id FROM ${ownerIdsView('insert')}), 0) LIMIT 1
    `)
    if (foreign !== undefined) reject('foreign_owner')
    for (const trigger of platformTriggers(shape)) this.#run(trigger.sql)
    this.#run('INSERT INTO chronolog_tables (name, registered_at_tx) VALUES (?, ?)', name, this.#context.txId)
  }

  #isRegistered(name: string): boolean {
    return this.#get('SELECT 1 AS present FROM chronolog_tables WHERE name = ?', name) !== undefined
  }

  #registered(requested: string): TableShape {
    const name = resolveTable(this.#database, requested)
    if (name === null || !this.#isRegistered(name)) reject('unregistered_table')
    return tableShape(this.#database, name!)
  }

  #registeredTables(): string[] {
    return this.#all('SELECT name FROM chronolog_tables ORDER BY name').map((row) => String(row.name))
  }

  // ── rows ──────────────────────────────────────────────────────────────────

  #findRow(shape: TableShape, values: readonly SqlValue[]): { readonly key: string; readonly owner: Uint8Array } | null {
    if (values.length !== shape.primaryKey.length) reject('row_key_arity')
    const row = this.#get(`
      SELECT ${rowKeyExpression('t', shape.primaryKey)} AS row_key, ${this.#ownerKeySql('t')} AS owner
        FROM ${quoteIdentifier(shape.name)} AS t
       WHERE ${shape.primaryKey.map((column) => `t.${quoteIdentifier(column)} = ?`).join(' AND ')}
    `, ...values.map(toDatabaseValue))
    return row === undefined ? null : { key: String(row.row_key), owner: asBytes(row.owner) }
  }

  #ownerOf(shape: TableShape, key: string): Uint8Array | null {
    const row = this.#get(`
      SELECT ${this.#ownerKeySql('t')} AS owner FROM ${quoteIdentifier(shape.name)} AS t
       WHERE ${rowKeyFilter('t', shape.primaryKey)}
    `, ...rowKeyBindings(key, shape.primaryKey))
    return row === undefined ? null : asBytes(row.owner)
  }

  // ── principals ────────────────────────────────────────────────────────────

  /** The principal id of `key`, assigned now if it has none (the next integer). */
  #principal(key: Uint8Array): bigint {
    const existing = this.#principalIfAny(key)
    if (existing !== null) return existing
    this.#run('INSERT INTO chronolog_principals (id, key) VALUES ((SELECT coalesce(max(id), 0) + 1 FROM chronolog_principals), ?)', key)
    return this.#principalIfAny(key) ?? reject('state_missing')
  }

  #principalIfAny(key: Uint8Array): bigint | null {
    const row = this.#get('SELECT id FROM chronolog_principals WHERE key = ?', key)
    return row === undefined ? null : BigInt(row.id as number | bigint)
  }

  /** The SQL that turns a row's owner id into its key. */
  #ownerKeySql(alias: string): string {
    return `(SELECT key FROM chronolog_principals WHERE id = ${alias}.${quoteIdentifier(OWNER_COLUMN)})`
  }

  // ── collectives ───────────────────────────────────────────────────────────

  #collective(id: Uint8Array): Collective | null {
    const row = this.#get('SELECT kind, insert_role, update_role, delete_role FROM chronolog_collectives WHERE collective_id = ?', id)
    if (row === undefined) return null
    return {
      kind: row.kind as Collective['kind'],
      roles: { insert: row.insert_role as CollectiveRole, update: row.update_role as CollectiveRole, delete: row.delete_role as CollectiveRole },
    }
  }

  #membership(collectiveId: Uint8Array, member: Uint8Array): Membership | null {
    const row = this.#get('SELECT role, state FROM chronolog_collective_members WHERE collective_id = ? AND member_key = ?', collectiveId, member)
    return row === undefined ? null : { role: row.role as CollectiveRole, state: row.state as Membership['state'] }
  }

  #isCollectiveAdmin(collectiveId: Uint8Array, member: Uint8Array): boolean {
    const membership = this.#membership(collectiveId, member)
    return membership !== null && membership.state === 'active' && membership.role === 'admin'
  }

  /** The signer may act as `owner`: its own key, or a collective it administers. */
  #administers(owner: Uint8Array): boolean {
    return sameBytes(owner, this.#context.actor) || this.#isCollectiveAdmin(owner, this.#context.actor)
  }

  #activeAdmins(collectiveId: Uint8Array): number {
    return Number(this.#get(`SELECT count(*) AS admins FROM chronolog_collective_members
      WHERE collective_id = ? AND role = 'admin' AND state = 'active'`, collectiveId)?.admins ?? 0)
  }

  #createCollective(op: Extract<PlatformOp, { op: 'create_collective' }>, stepIndex: number): void {
    const id = this.#objectId(stepIndex)
    if (op.invitees.some((key) => sameBytes(key, this.#context.actor))) reject('invalid_member')
    this.#run(`INSERT INTO chronolog_collectives (collective_id, kind, insert_role, update_role, delete_role, created_tx)
      VALUES (?, 'team', ?, ?, ?, ?)`, id, op.governance.insert, op.governance.update, op.governance.delete, this.#context.txId)
    this.#principal(id)
    this.#run(`INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
      VALUES (?, ?, 'admin', 'active', ?, NULL)`, id, this.#context.actor, this.#context.txId)
    for (const invitee of op.invitees) {
      this.#run(`INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
        VALUES (?, ?, 'member', 'invited', NULL, NULL)`, id, invitee)
    }
  }

  #acceptMembership(collectiveId: Uint8Array): void {
    if (this.#membership(collectiveId, this.#context.actor)?.state !== 'invited') reject('not_invited')
    this.#run(`UPDATE chronolog_collective_members SET state = 'active', joined_tx = ?, left_tx = NULL
      WHERE collective_id = ? AND member_key = ?`, this.#context.txId, collectiveId, this.#context.actor)
  }

  #leave(collectiveId: Uint8Array): void {
    const membership = this.#membership(collectiveId, this.#context.actor)
    if (membership === null || membership.state === 'left') reject('not_member')
    this.#run(`UPDATE chronolog_collective_members SET state = 'left', left_tx = ?
      WHERE collective_id = ? AND member_key = ?`, this.#context.txId, collectiveId, this.#context.actor)
    if (this.#activeAdmins(collectiveId) === 0) reject('last_admin')
  }

  #setMembers(op: Extract<PlatformOp, { op: 'set_members' }>): void {
    if (this.#collective(op.collectiveId) === null) reject('no_such_collective')
    if (!this.#isCollectiveAdmin(op.collectiveId, this.#context.actor)) reject('not_collective_admin')
    for (const change of op.changes) {
      const membership = this.#membership(op.collectiveId, change.member)
      if (change.role === 'remove') {
        if (membership === null || membership.state === 'left') reject('not_member')
        this.#run(`UPDATE chronolog_collective_members SET state = 'left', left_tx = ?
          WHERE collective_id = ? AND member_key = ?`, this.#context.txId, op.collectiveId, change.member)
      } else if (membership !== null && membership.state !== 'left') {
        this.#run('UPDATE chronolog_collective_members SET role = ? WHERE collective_id = ? AND member_key = ?',
          change.role, op.collectiveId, change.member)
      } else {
        // New members are invited; they join by accepting.
        this.#run(`INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
          VALUES (?, ?, ?, 'invited', NULL, NULL)
          ON CONFLICT (collective_id, member_key) DO UPDATE SET role = excluded.role, state = 'invited', joined_tx = NULL, left_tx = NULL`,
        op.collectiveId, change.member, change.role)
      }
    }
    if (this.#activeAdmins(op.collectiveId) === 0) reject('last_admin')
  }

  // ── grants ────────────────────────────────────────────────────────────────

  #grant(op: Extract<PlatformOp, { op: 'grant' }>, stepIndex: number): void {
    const shape = this.#registered(op.table)
    let columns: string[] | null = null
    if (op.columns !== undefined) {
      if (!op.operations.includes('update')) reject('invalid_grant')
      columns = op.columns.map((requested) => {
        const column = shape.columns.find((entry) => entry.hidden === 0 && entry.name.toLowerCase() === requested.toLowerCase())
        if (column === undefined || column.name.toLowerCase() === OWNER_COLUMN) reject('unknown_column')
        return column!.name
      })
    }
    let grantor: Uint8Array
    let rowKey: string | null = null
    if (op.rowKey !== undefined) {
      if (op.operations.includes('insert')) reject('invalid_grant')
      const row = this.#findRow(shape, op.rowKey) ?? reject('no_such_row')
      grantor = row.owner
      rowKey = row.key
      if (op.grantor !== undefined && !sameBytes(op.grantor, grantor)) reject('not_owner')
    } else {
      grantor = op.grantor ?? this.#context.actor
    }
    if (!this.#administers(grantor)) reject('not_owner')
    this.#run(`INSERT INTO chronolog_grants
      (grant_id, tbl, grantor, grantee_key, row_key, op_insert, op_update, op_delete, columns, created_tx, revoked_tx)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
    this.#objectId(stepIndex), shape.name, grantor, op.grantee, rowKey,
    flag(op.operations.includes('insert')), flag(op.operations.includes('update')), flag(op.operations.includes('delete')),
    columns === null ? null : JSON.stringify(columns), this.#context.txId)
  }

  #revokeGrant(grantId: Uint8Array): void {
    const row = this.#get('SELECT grantor, grantee_key, revoked_tx FROM chronolog_grants WHERE grant_id = ?', grantId) ?? reject('no_such_grant')
    if (row.revoked_tx !== null) reject('grant_revoked')
    // The grantor (or an admin of a grantor collective) revokes; the grantee may renounce.
    if (!this.#administers(asBytes(row.grantor)) && !sameBytes(asBytes(row.grantee_key), this.#context.actor)) reject('not_owner')
    this.#run('UPDATE chronolog_grants SET revoked_tx = ? WHERE grant_id = ?', this.#context.txId, grantId)
  }

  // ── transfers ─────────────────────────────────────────────────────────────

  #transferOffer(op: Extract<PlatformOp, { op: 'transfer_offer' }>, stepIndex: number): void {
    let from: Uint8Array
    let table: string | null = null
    let rowKey: string | null = null
    if (op.scope.kind === 'row') {
      const shape = this.#registered(op.scope.table)
      const row = this.#findRow(shape, op.scope.rowKey) ?? reject('no_such_row')
      from = row.owner
      table = shape.name
      rowKey = row.key
      if (op.fromOwner !== undefined && !sameBytes(op.fromOwner, from)) reject('not_owner')
    } else {
      from = op.fromOwner ?? this.#context.actor
    }
    if (!this.#administers(from)) reject('not_owner')
    if (sameBytes(from, op.toOwner)) reject('invalid_transfer')
    this.#run(`INSERT INTO chronolog_transfers (offer_id, tbl, row_key, from_owner, to_owner, carry, state, created_tx, closed_tx)
      VALUES (?, ?, ?, ?, ?, ?, 'open', ?, NULL)`,
    this.#objectId(stepIndex), table, rowKey, from, op.toOwner, flag(op.carry), this.#context.txId)
  }

  #transferAccept(offerId: Uint8Array): void {
    const offer = this.#get('SELECT tbl, row_key, from_owner, to_owner, carry, state FROM chronolog_transfers WHERE offer_id = ?', offerId) ??
      reject('no_such_offer')
    if (offer.state !== 'open') reject('offer_closed')
    const from = asBytes(offer.from_owner)
    const to = asBytes(offer.to_owner)
    if (!this.#administers(to)) reject('not_recipient')
    if (offer.tbl === null) this.#transferAll(from, to)
    else this.#transferRow(asText(offer.tbl), asText(offer.row_key), from, to, Number(offer.carry) === 1)
    this.#run(`UPDATE chronolog_transfers SET state = 'accepted', closed_tx = ? WHERE offer_id = ?`, this.#context.txId, offerId)
  }

  #transferRow(table: string, key: string, from: Uint8Array, to: Uint8Array, carry: boolean): void {
    if (!this.#isRegistered(table)) reject('offer_stale')
    const shape = tableShape(this.#database, table)
    const owner = this.#ownerOf(shape, key)
    if (owner === null || !sameBytes(owner, from)) reject('offer_stale')
    const fromId = this.#principal(from)
    const toId = this.#principal(to)
    const dependents = this.#dependents({ table, key }, fromId)
    if (!carry && dependents.length > 0) reject('has_dependents')
    const moved = [{ table, key }, ...dependents]
    // The exemption admits exactly these owner changes, from `from` to `to`.
    for (const row of moved) {
      this.#run(`INSERT INTO chronolog_exemptions (kind, tbl, row_key, from_owner, to_owner) VALUES ('transfer', ?, ?, ?, ?)`, row.table, row.key, fromId, toId)
    }
    try {
      const result = this.#run(`UPDATE ${quoteIdentifier(table)} SET ${quoteIdentifier(OWNER_COLUMN)} = ?
        WHERE ${rowKeyFilter(quoteIdentifier(table), shape.primaryKey)}`, toId, ...rowKeyBindings(key, shape.primaryKey))
      if (Number(result.changes) !== 1) reject('offer_stale')
    } finally {
      this.#run('DELETE FROM chronolog_exemptions')
    }
    // Row grants were given by the previous owner.
    for (const row of moved) {
      this.#run('UPDATE chronolog_grants SET revoked_tx = ? WHERE revoked_tx IS NULL AND tbl = ? AND row_key = ?', this.#context.txId, row.table, row.key)
    }
  }

  /** Same-owner rows reachable through owner-composite foreign keys (all ON UPDATE CASCADE). */
  #dependents(root: RowRef, owner: bigint): RowRef[] {
    const registered = this.#registeredTables().map((name) => tableShape(this.#database, name))
    const found: RowRef[] = []
    const seen = new Set<string>([`${root.table}\0${root.key}`])
    const pending: RowRef[] = [root]
    while (pending.length > 0) {
      const parent = pending.shift()!
      const parentShape = tableShape(this.#database, parent.table)
      for (const child of registered) {
        for (const foreignKey of child.foreignKeys) {
          if (!isOwnerComposite(foreignKey) || foreignKey.table.toLowerCase() !== parent.table.toLowerCase()) continue
          const referenced = foreignKey.to.map((column, index) => column ?? parentShape.primaryKey[index]!)
          const values = this.#get(`
            SELECT ${referenced.map((column, index) => `p.${quoteIdentifier(column)} AS v${index}`).join(', ')}
              FROM ${quoteIdentifier(parent.table)} AS p WHERE ${rowKeyFilter('p', parentShape.primaryKey)}
          `, ...rowKeyBindings(parent.key, parentShape.primaryKey))
          if (values === undefined) continue
          const children = this.#all(`
            SELECT ${rowKeyExpression('c', child.primaryKey)} AS row_key FROM ${quoteIdentifier(child.name)} AS c
             WHERE ${foreignKey.from.map((column) => `c.${quoteIdentifier(column)} IS ?`).join(' AND ')}
               AND c.${quoteIdentifier(OWNER_COLUMN)} = ?
             ORDER BY row_key
          `, ...referenced.map((_, index) => values[`v${index}`]), owner)
          for (const row of children) {
            const ref = { table: child.name, key: String(row.row_key) }
            const id = `${ref.table}\0${ref.key}`
            if (seen.has(id)) continue
            seen.add(id)
            found.push(ref)
            pending.push(ref)
          }
        }
      }
    }
    return found
  }

  /** The key-change path: every row `from` owns, in parent-before-child order. */
  #transferAll(from: Uint8Array, to: Uint8Array): void {
    const tables = this.#parentFirst(this.#registeredTables().map((name) => tableShape(this.#database, name)))
    const fromId = this.#principal(from)
    const toId = this.#principal(to)
    for (const shape of tables) {
      this.#run(`INSERT INTO chronolog_exemptions (kind, tbl, row_key, from_owner, to_owner) VALUES ('transfer', ?, NULL, ?, ?)`, shape.name, fromId, toId)
    }
    try {
      for (const shape of tables) {
        this.#run(`UPDATE ${quoteIdentifier(shape.name)} SET ${quoteIdentifier(OWNER_COLUMN)} = ? WHERE ${quoteIdentifier(OWNER_COLUMN)} = ?`, toId, fromId)
      }
    } finally {
      this.#run('DELETE FROM chronolog_exemptions')
    }
    this.#run('UPDATE chronolog_grants SET grantor = ? WHERE grantor = ? AND revoked_tx IS NULL', to, from)
  }

  #parentFirst(shapes: readonly TableShape[]): TableShape[] {
    const byName = new Map(shapes.map((shape) => [shape.name.toLowerCase(), shape]))
    const ordered: TableShape[] = []
    const state = new Map<string, 'visiting' | 'done'>()
    const visit = (shape: TableShape): void => {
      const key = shape.name.toLowerCase()
      if (state.get(key) === 'done') return
      if (state.get(key) === 'visiting') reject('fk_cycle')
      state.set(key, 'visiting')
      for (const foreignKey of shape.foreignKeys) {
        const parent = byName.get(foreignKey.table.toLowerCase())
        if (isOwnerComposite(foreignKey) && parent !== undefined && parent !== shape) visit(parent)
      }
      state.set(key, 'done')
      ordered.push(shape)
    }
    for (const shape of shapes) visit(shape)
    return ordered
  }

  // ── fork seeding ──────────────────────────────────────────────────────────

  /** Only the genesis root may seed, and only while seeding is open. */
  #assertSeeding(): void {
    const platform = this.#get('SELECT root_admin, seeding_open FROM chronolog_platform WHERE singleton = 1') ?? reject('state_missing')
    if (!sameBytes(asBytes(platform.root_admin), this.#context.actor)) reject('not_root')
    if (Number(platform.seeding_open) !== 1) reject('seed_closed')
  }

  /** The fork-seed plan's last step: no further SeedRows, even by the root. */
  #endSeeding(): void {
    this.#assertSeeding()
    this.#run('UPDATE chronolog_platform SET seeding_open = 0 WHERE singleton = 1')
  }

  #seedRows(op: Extract<PlatformOp, { op: 'seed_rows' }>): void {
    this.#assertSeeding()
    if (SEEDABLE_PLATFORM_TABLES.includes(op.table.toLowerCase())) return this.#seedPlatformRows(op)
    const shape = this.#registered(op.table)
    const columns = op.columns.map((requested) => {
      const column = shape.columns.find((entry) => entry.hidden === 0 && entry.name.toLowerCase() === requested.toLowerCase())
      return column?.name ?? reject('unknown_column')
    })
    const ownerIndex = columns.indexOf(OWNER_COLUMN)
    if (ownerIndex < 0) reject('invalid_seed')
    // Seeds name owners by key; ids are this group's own.
    const rows = op.rows.map((row) => {
      const owner = row[ownerIndex]!
      if (owner.kind !== 'blob' || owner.value.length !== 32) reject('invalid_seed')
      const values = row.map(toDatabaseValue)
      values[ownerIndex] = this.#principal((owner as Extract<SqlValue, { kind: 'blob' }>).value)
      return values
    })
    this.#run(`INSERT INTO chronolog_exemptions (kind, tbl, row_key, from_owner, to_owner) VALUES ('seed', ?, NULL, NULL, NULL)`, shape.name)
    try {
      const sql = `INSERT INTO ${quoteIdentifier(shape.name)} (${columns.map(quoteIdentifier).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`
      withProfiledStatement(this.#database, sql, 'platform', (statement) => {
        for (const values of rows) statement.run(...values)
      }, this.#context.limits)
    } finally {
      this.#run('DELETE FROM chronolog_exemptions')
    }
  }

  #seedPlatformRows(op: Extract<PlatformOp, { op: 'seed_rows' }>): void {
    const table = op.table.toLowerCase()
    const shape = tableShape(this.#database, table)
    const columns = op.columns.map((requested) =>
      shape.columns.find((entry) => entry.name.toLowerCase() === requested.toLowerCase())?.name ?? reject('unknown_column'))
    const collective = columns.indexOf('collective_id')
    for (const row of op.rows) {
      const value = collective < 0 ? undefined : row[collective]
      if (value?.kind === 'blob' && sameBytes(value.value, GROUP_COLLECTIVE_ID)) reject('invalid_seed')
    }
    const sql = `INSERT INTO ${quoteIdentifier(table)} (${columns.map(quoteIdentifier).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`
    withProfiledStatement(this.#database, sql, 'platform', (statement) => {
      for (const row of op.rows) statement.run(...row.map(toDatabaseValue))
    }, this.#context.limits)
    if (table === 'chronolog_collectives' && collective >= 0) {
      for (const row of op.rows) this.#principal((row[collective] as Extract<SqlValue, { kind: 'blob' }>).value)
    }
  }

  // ── reconciliation ────────────────────────────────────────────────────────

  /**
   * Run after every transaction that changed the schema (§3): every
   * application table is registered and carries current platform triggers, no
   * foreign chronolog_* trigger or view exists, and no app trigger uses
   * RAISE(IGNORE). Throws PlatformRejection with the bare rejection code.
   */
  reconcile(): void {
    const objects = this.#all(`SELECT l.name, l.type, s.sql FROM pragma_table_list AS l
      LEFT JOIN sqlite_schema AS s ON s.type = 'table' AND s.name = l.name WHERE l.schema = 'main'`)
    const tables = new Map<string, string>()
    const vecTables = new Map<string, number>()
    for (const object of objects) {
      const name = String(object.name)
      const sql = typeof object.sql === 'string' ? object.sql : ''
      if (object.type === 'table') tables.set(name.toLowerCase(), name)
      if (object.type === 'virtual') {
        const vectorColumns = vec0VectorColumns(sql)
        if (vectorColumns !== null) vecTables.set(name.toLowerCase(), vectorColumns)
      }
    }
    const registered = this.#registeredTables()
    const registeredKeys = new Set(registered.map((name) => name.toLowerCase()))

    for (const name of registered) {
      if (tables.has(name.toLowerCase())) continue
      // A renamed table takes its triggers along (SQLite rewrites their table),
      // so its insert trigger now names the new table: move the registration,
      // grants and open offers, and regenerate the triggers under the new name.
      const moved = this.#get(`SELECT tbl_name FROM sqlite_schema WHERE type = 'trigger' AND name = ?`, platformTriggerName(name, 'ins'))
      const renamedTo = moved === undefined ? undefined : tables.get(String(moved.tbl_name).toLowerCase())
      if (renamedTo !== undefined && !registeredKeys.has(renamedTo.toLowerCase())) {
        for (const event of ['ins', 'upd', 'del'] as const) this.#run(`DROP TRIGGER IF EXISTS ${quoteIdentifier(platformTriggerName(name, event))}`)
        for (const trigger of platformTriggers(tableShape(this.#database, renamedTo))) this.#run(trigger.sql)
        this.#run('UPDATE chronolog_tables SET name = ? WHERE name = ?', renamedTo, name)
        this.#run('UPDATE chronolog_grants SET tbl = ? WHERE tbl = ?', renamedTo, name)
        this.#run('UPDATE chronolog_transfers SET tbl = ? WHERE tbl = ?', renamedTo, name)
        registeredKeys.delete(name.toLowerCase())
        registeredKeys.add(renamedTo.toLowerCase())
        continue
      }
      // Dropping a registered table unregisters it and ends its grants and offers.
      this.#run('DELETE FROM chronolog_tables WHERE name = ?', name)
      this.#run('UPDATE chronolog_grants SET revoked_tx = ? WHERE tbl = ? AND revoked_tx IS NULL', this.#context.txId, name)
      this.#run(`UPDATE chronolog_transfers SET state = 'cancelled', closed_tx = ? WHERE tbl = ? AND state = 'open'`, this.#context.txId, name)
      registeredKeys.delete(name.toLowerCase())
    }

    // Every new application table is registered at once.
    for (const [key, name] of tables) {
      if (registeredKeys.has(key) || isReservedSchemaObjectName(name) || isVecChunkTable(this.#database, name, vecTables)) continue
      this.#registerTable(name)
      registeredKeys.add(key)
    }

    const expected = new Set<string>(PLATFORM_VIEW_NAMES)
    for (const key of registeredKeys) {
      const shape = tableShape(this.#database, tables.get(key)!)
      if (!hasValidOwnerColumn(shape) || shape.primaryKey.length === 0) throw new PlatformRejection('schema_unregistered')
      if (foreignKeyViolation(shape) !== null) throw new PlatformRejection('platform:fk_action')
      for (const trigger of platformTriggers(shape)) {
        expected.add(trigger.name.toLowerCase())
        const current = this.#get(`SELECT sql, tbl_name FROM sqlite_schema WHERE type = 'trigger' AND name = ?`, trigger.name)
        if (current === undefined || String(current.tbl_name).toLowerCase() !== key) throw new PlatformRejection('schema_unregistered')
        // A column added, renamed or dropped by an admin changes the generated SQL.
        if (String(current.sql) !== trigger.sql) {
          this.#run(`DROP TRIGGER ${quoteIdentifier(trigger.name)}`)
          this.#run(trigger.sql)
        }
      }
    }

    for (const object of this.#all(`SELECT type, name, sql FROM sqlite_schema WHERE type IN ('trigger', 'view')`)) {
      const name = String(object.name)
      if (name.toLowerCase().startsWith('chronolog_')) {
        if (!expected.has(name.toLowerCase())) throw new PlatformRejection('schema_unregistered')
      } else if (object.type === 'trigger' && typeof object.sql === 'string' && chronologTriggerUsesIgnore(object.sql)) {
        throw new PlatformRejection('trigger_ignore')
      }
    }
  }

  // ── statement helpers ─────────────────────────────────────────────────────

  #objectId(stepIndex: number): Uint8Array {
    return Uint8Array.from(createHash('sha256')
      .update(platformObjectIdHashInput(this.#context.txId, stepIndex))
      .digest())
  }

  #run(sql: string, ...parameters: unknown[]): { changes: number | bigint } {
    return withProfiledStatement(this.#database, sql, 'platform', (statement) => statement.run(...parameters), this.#context.limits)
  }

  #get(sql: string, ...parameters: unknown[]): Row | undefined {
    return withProfiledStatement(this.#database, sql, 'platform', (statement) => {
      const row = statement.get(...parameters)
      if (Array.isArray(row)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
      return row
    }, this.#context.limits)
  }

  #all(sql: string, ...parameters: unknown[]): Row[] {
    return withProfiledStatement(this.#database, sql, 'platform', (statement) => statement.all(...parameters).map((row) => {
      if (Array.isArray(row)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
      return row
    }), this.#context.limits)
  }
}

const BEGIN_SQL = `SELECT p.root_admin, p.seeding_open,
  (SELECT id FROM chronolog_principals WHERE key = ?2) AS actor_id,
  EXISTS (SELECT 1 FROM chronolog_collective_members
           WHERE collective_id = ?1 AND member_key = ?2 AND role = 'admin' AND state = 'active') AS schema_admin,
  (SELECT schema_version FROM pragma_schema_version) AS schema_version
  FROM chronolog_platform AS p WHERE p.singleton = 1`

const internalStatements = new WeakMap<DatabaseLike, Map<string, StatementLike>>()

/**
 * A prepared statement of fixed, trusted platform SQL, reused across
 * transactions. Use only for reads that run while no authorizer is installed
 * (SQLite may re-prepare it after a schema change).
 */
export function cachedInternalStatement(database: DatabaseLike, sql: string): StatementLike {
  let statements = internalStatements.get(database)
  if (statements === undefined) {
    statements = new Map()
    internalStatements.set(database, statements)
  }
  let statement = statements.get(sql)
  if (statement === undefined) {
    statement = database.prepare(sql)
    statements.set(sql, statement)
  }
  return statement
}

const shadowCache = new WeakMap<DatabaseLike, { readonly version: number; readonly tables: ReadonlySet<string> }>()

/** Lower-case names of SQLite shadow tables, cached per schema version; read while no authorizer is installed. */
export function shadowTables(database: DatabaseLike): ReadonlySet<string> {
  const version = Number((cachedInternalStatement(database, 'PRAGMA schema_version').get() as Row).schema_version)
  const cached = shadowCache.get(database)
  if (cached?.version === version) return cached.tables
  const rows = cachedInternalStatement(database, `SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'shadow'`).all() as Row[]
  const tables = new Set(rows.map((row) => String(row.name).toLowerCase()))
  shadowCache.set(database, { version, tables })
  return tables
}

const writeProtectedCache = new WeakMap<DatabaseLike, { readonly version: number; readonly tables: ReadonlySet<string> }>()

/**
 * Lower-case names of the tables that carry no owner checks: virtual tables
 * (FTS5, R-tree, sqlite-vec) and sqlite-vec's chunk tables. Cached per
 * schema version; read while no authorizer is installed.
 */
export function writeProtectedTables(database: DatabaseLike): ReadonlySet<string> {
  const version = Number((cachedInternalStatement(database, 'PRAGMA schema_version').get() as Row).schema_version)
  const cached = writeProtectedCache.get(database)
  if (cached?.version === version) return cached.tables
  const schema = cachedInternalStatement(database, `SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND sql IS NOT NULL`).all() as Row[]
  const vecTables = new Map<string, number>()
  const tables = new Set<string>()
  for (const row of schema) {
    const sql = String(row.sql)
    if (!/^\s*CREATE\s+VIRTUAL\s+TABLE/iu.test(sql)) continue
    tables.add(String(row.name).toLowerCase())
    const vectorColumns = vec0VectorColumns(sql)
    if (vectorColumns !== null) vecTables.set(String(row.name).toLowerCase(), vectorColumns)
  }
  for (const row of schema) {
    if (isVecChunkTable(database, String(row.name), vecTables)) tables.add(String(row.name).toLowerCase())
  }
  writeProtectedCache.set(database, { version, tables })
  return tables
}

/**
 * sqlite-vec's per-column vector tables are not marked as shadow tables (their
 * names contain `_`), so they are recognized by what vec0 creates: a table
 * named after an existing vec0 table, for one of its vector columns, with
 * exactly vec0's two columns. vec0 creates that name with the vec0 table, so
 * no other table can hold it. (The stored CREATE text is not compared: Dolt
 * re-serializes it on checkout.) Writes to them are denied outside app
 * triggers (§5).
 */
export function isVecChunkTable(database: DatabaseLike, name: string, vecTables: ReadonlyMap<string, number>): boolean {
  const match = /^(.+)_vector_chunks(\d\d)$/u.exec(name)
  if (match === null) return false
  const vectorColumns = vecTables.get(match[1]!.toLowerCase())
  if (vectorColumns === undefined || Number(match[2]) >= vectorColumns) return false
  const columns = cachedInternalStatement(database,
    `SELECT name, upper(type) AS type, "notnull" AS not_null, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid`).all(name) as Row[]
  return JSON.stringify(columns.map((column) => [column.name, column.type, Number(column.not_null), Number(column.pk), Number(column.hidden)])) ===
    JSON.stringify([['rowid', 'INTEGER', 0, 1, 0], ['vectors', 'BLOB', 1, 0, 0]])
}

/** The number of vector columns of a vec0 virtual table, or null if `sql` is not one. */
function vec0VectorColumns(sql: string): number | null {
  const match = /^\s*CREATE\s+VIRTUAL\s+TABLE\s+.*?\bUSING\s+vec0\s*\((.*)\)\s*$/isu.exec(sql)
  if (match === null) return null
  return [...match[1]!.matchAll(/\b(?:float|f32|int8|i8|bit)\s*\[/giu)].length
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

function flag(value: boolean): number { return value ? 1 : 0 }

function asText(value: unknown): string {
  if (typeof value !== 'string') throw new Error('MATERIALIZER_PLATFORM_CORRUPT_TEXT')
  return value
}

function asBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error('MATERIALIZER_PLATFORM_CORRUPT_BYTES')
  return Uint8Array.from(value)
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

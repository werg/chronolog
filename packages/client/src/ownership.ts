import {
  platformObjectId,
  platformOp,
  type CollectiveGovernance,
  type CollectiveRole,
  type GrantOperation,
  type MemberChange,
} from '@chronolog/protocol'
import type { TransactionRejection } from '@chronolog/rpc'

import type { DecodedLocalSqlResult, DecodedLocalSqlValue, LocalSqlInput } from './local-sql.js'

/*
 * Owner-controlled rows for application code (docs/design-owner-rows.md).
 *
 * Every row of an application table has a `chronolog_owner`: the key that
 * signed its insert, or a team. Only the owner, active team members the
 * team's governance allows, and grantees may change it; anything else
 * rejects the whole transaction with a `policy:<table>:<operation>` code.
 *
 * Keys and ids here are 32-byte Uint8Arrays: a node's signing key, a team id,
 * a grant id or a transfer offer id.
 */

/** The column that holds each row's owner (a principal id; see `ownerKeySql`). */
export const OWNER_COLUMN = 'chronolog_owner'

/**
 * SQL expression for the 32-byte key that owns a row, for local reads:
 * `SELECT n.*, ${ownerKeySql('n')} AS owner FROM notes AS n`, or
 * `WHERE ${ownerKeySql('n')} = ?` with your key bound.
 */
export function ownerKeySql(alias?: string): string {
  const column = alias === undefined ? OWNER_COLUMN : `${alias}.${OWNER_COLUMN}`
  return `(SELECT key FROM chronolog_principals WHERE id = ${column})`
}

/**
 * SQL expression for the owner value of a key bound to its `?`. Use it to
 * write a row owned by a team you may insert for:
 * `INSERT INTO notes (id, body, chronolog_owner) VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`.
 */
export const OWNER_FOR_KEY_SQL = '(SELECT id FROM chronolog_principals WHERE key = ?)'

// ── rejections ──────────────────────────────────────────────────────────────

export type OwnedOperation = 'insert' | 'update' | 'delete'

/** Why a transaction was rejected, parsed from its rejection code. */
export type RejectionReason =
  /** The signer may not insert, update or delete that row of `table`. */
  | { readonly kind: 'policy'; readonly table: string; readonly operation: OwnedOperation }
  /** A platform operation (grant, team, transfer, …) was refused; see `PlatformRejectionReason`. */
  | { readonly kind: 'platform'; readonly reason: string }
  /** A `chronolog_assert(condition, code)` failed. */
  | { readonly kind: 'assert'; readonly code: string }
  /** The transaction left a table without an owner column or primary key, or a foreign `chronolog_*` object. */
  | { readonly kind: 'schema'; readonly code: string }
  /** SQLite refused the statement: `constraint`, `denied`, `step_limit`, `error`, … */
  | { readonly kind: 'engine'; readonly code: string }

/** Codes a platform operation can be refused with (`platform:<reason>`). Not exhaustive across versions. */
export type PlatformRejectionReason =
  | 'not_owner' | 'not_recipient' | 'not_schema_admin' | 'not_collective_admin' | 'not_invited' | 'not_member'
  | 'last_admin' | 'no_such_table' | 'unregistered_table' | 'no_such_row' | 'no_such_grant' | 'grant_revoked'
  | 'no_such_collective' | 'no_such_offer' | 'offer_closed' | 'offer_stale' | 'has_dependents' | 'invalid_grant'
  | 'nullable_primary_key' | 'invalid_transfer' | 'invalid_member' | 'unknown_column' | 'row_key_arity' | 'fk_action' | 'seed_closed' | 'not_root'

const SCHEMA_CODES: ReadonlySet<string> = new Set(['schema_unregistered', 'trigger_ignore'])
const OWNED_OPERATIONS: ReadonlySet<string> = new Set(['insert', 'update', 'delete'])

export function parseRejectionCode(code: string): RejectionReason {
  if (code.startsWith('policy:')) {
    // The table name may itself contain ':', the operation never does.
    const rest = code.slice('policy:'.length)
    const split = rest.lastIndexOf(':')
    const operation = rest.slice(split + 1)
    if (split > 0 && OWNED_OPERATIONS.has(operation)) {
      return { kind: 'policy', table: rest.slice(0, split), operation: operation as OwnedOperation }
    }
  }
  if (code.startsWith('platform:')) return { kind: 'platform', reason: code.slice('platform:'.length) }
  if (code.startsWith('assert:')) return { kind: 'assert', code: code.slice('assert:'.length) }
  if (SCHEMA_CODES.has(code)) return { kind: 'schema', code }
  return { kind: 'engine', code }
}

/** Thrown by `TransactionHandle.accepted()` after an immutable rejection is applied locally. */
export class TransactionRejectedError extends Error {
  readonly code: string
  /** Index of the failing step, or null for whole-transaction checks. */
  readonly stepIndex: number | null
  readonly reason: RejectionReason

  constructor(readonly transactionId: string, rejection: TransactionRejection) {
    super(`Transaction ${transactionId} rejected: ${rejection.code}${rejection.statementIndex === null ? '' : ` (step ${rejection.statementIndex})`}`)
    this.name = 'TransactionRejectedError'
    this.code = rejection.code
    this.stepIndex = rejection.statementIndex
    this.reason = parseRejectionCode(rejection.code)
  }
}

/** The id of the grant, team or transfer offer created by step `stepIndex` of a transaction. */
export async function createdObjectId(transactionId: string, stepIndex: number): Promise<Uint8Array> {
  return platformObjectId(new TextEncoder().encode(transactionId), stepIndex)
}

// ── actions ─────────────────────────────────────────────────────────────────

/** Any team member may insert and update the team's rows; only team admins delete them. */
export const DEFAULT_TEAM_GOVERNANCE: CollectiveGovernance = Object.freeze({ insert: 'member', update: 'member', delete: 'admin' })

export interface ShareInput {
  readonly table: string
  /** The grantee's key. */
  readonly with: Uint8Array
  readonly operations: readonly GrantOperation[]
  /** Primary-key values of one row; omit to share every row the owner has in `table` (insert included). */
  readonly row?: readonly unknown[]
  /** Columns an update may change; omit for every column. Requires `update`. */
  readonly columns?: readonly string[]
  /** Share a team's rows instead of your own (you must be a team admin). */
  readonly owner?: Uint8Array
}

export interface OfferRowInput {
  readonly table: string
  readonly row: readonly unknown[]
  /** The new owner: a key or a team id. It takes effect when the recipient accepts. */
  readonly to: Uint8Array
  /** Move the row's same-owner children (owner-composite ON UPDATE CASCADE foreign keys) with it. */
  readonly carry?: boolean
}

export interface OfferAllInput {
  readonly to: Uint8Array
  /** Offer a team's rows instead of your own (you must be a team admin). */
  readonly from?: Uint8Array
}

export const ownershipSteps = Object.freeze({
  share: (input: ShareInput) => platformOp.grant({
    table: input.table,
    grantee: input.with,
    operations: GRANT_ORDER.filter((operation) => input.operations.includes(operation)),
    ...(input.row === undefined ? {} : { rowKey: input.row }),
    ...(input.columns === undefined ? {} : { columns: input.columns }),
    ...(input.owner === undefined ? {} : { grantor: input.owner }),
  }),
  createTeam: (input: { readonly governance?: CollectiveGovernance; readonly invite?: readonly Uint8Array[] } = {}) =>
    platformOp.createCollective({ governance: input.governance ?? DEFAULT_TEAM_GOVERNANCE, invitees: input.invite ?? [] }),
  invite: (teamId: Uint8Array, members: readonly Uint8Array[], role: CollectiveRole = 'member') =>
    platformOp.setMembers(teamId, members.map((member): MemberChange => ({ member, role }))),
  remove: (teamId: Uint8Array, members: readonly Uint8Array[]) =>
    platformOp.setMembers(teamId, members.map((member): MemberChange => ({ member, role: 'remove' }))),
  offerRow: (input: OfferRowInput) =>
    platformOp.transferRow({ table: input.table, rowKey: input.row, toOwner: input.to, carry: input.carry ?? false }),
  cancelOffer: (offerId: Uint8Array) => platformOp.cancelTransfer(offerId),
  offerAll: (input: OfferAllInput) =>
    platformOp.transferAll({ toOwner: input.to, ...(input.from === undefined ? {} : { fromOwner: input.from }) }),
})

const GRANT_ORDER: readonly GrantOperation[] = ['insert', 'update', 'delete']

// ── local-read queries ──────────────────────────────────────────────────────

/** A local-read query over the replicated ownership state, with a decoder for its rows. */
export interface OwnershipQuery<T> {
  readonly sql: string
  readonly parameters: readonly LocalSqlInput[]
  readonly decode: (result: DecodedLocalSqlResult) => readonly T[]
}

export interface TeamMembership {
  readonly teamId: Uint8Array
  readonly role: CollectiveRole
  readonly governance: CollectiveGovernance
}

export interface TeamMember {
  readonly key: Uint8Array
  readonly role: CollectiveRole
  readonly state: 'invited' | 'active'
}

export interface Grant {
  readonly grantId: Uint8Array
  readonly table: string
  /** Whose rows: a key or a team id. */
  readonly grantor: Uint8Array
  readonly grantee: Uint8Array
  /** Opaque versioned typed primary-key tuple (rk1:...), or null for the whole table. */
  readonly rowKey: string | null
  readonly operations: readonly GrantOperation[]
  /** Columns an update may change, or null for every column. */
  readonly columns: readonly string[] | null
}

export interface TransferOffer {
  readonly offerId: Uint8Array
  /** null with rowKey null: a snapshot of the sender's rows when the offer was created. */
  readonly table: string | null
  readonly rowKey: string | null
  readonly from: Uint8Array
  readonly to: Uint8Array
  readonly carry: boolean
}

const GRANT_COLUMNS = 'grant_id, tbl, grantor, grantee_key, row_key, op_insert, op_update, op_delete, columns'
const OFFER_COLUMNS = 'offer_id, tbl, row_key, from_owner, to_owner, carry'

export const ownershipQueries = Object.freeze({
  /** Teams `member` actively belongs to, with its role and each team's governance. */
  teams: (member: Uint8Array): OwnershipQuery<TeamMembership> => teamsQuery(member, 'active'),
  /** Teams that invited `member` and are waiting for it to accept. */
  invitations: (member: Uint8Array): OwnershipQuery<TeamMembership> => teamsQuery(member, 'invited'),
  /** Current and invited members of a team. */
  members: (teamId: Uint8Array): OwnershipQuery<TeamMember> => ({
    sql: `SELECT member_key, role, state FROM chronolog_collective_members
           WHERE collective_id = ? AND state <> 'left' ORDER BY member_key`,
    parameters: [teamId],
    decode: (result) => result.rows.map((row) => ({
      key: bytes(row[0]), role: text(row[1]) as CollectiveRole, state: text(row[2]) as TeamMember['state'],
    })),
  }),
  /** True when `member` is a schema administrator (an admin of the group collective). */
  schemaAdmin: (member: Uint8Array): OwnershipQuery<boolean> => ({
    sql: `SELECT EXISTS (SELECT 1 FROM chronolog_collective_members AS m
            JOIN chronolog_collectives AS c ON c.collective_id = m.collective_id
           WHERE c.kind = 'group' AND m.member_key = ? AND m.role = 'admin' AND m.state = 'active')`,
    parameters: [member],
    decode: (result) => result.rows.map((row) => row[0] === 1n),
  }),
  /** Live grants `grantee` has received. */
  grantsReceived: (grantee: Uint8Array): OwnershipQuery<Grant> => ({
    sql: `SELECT ${GRANT_COLUMNS} FROM chronolog_grants WHERE grantee_key = ? AND revoked_tx IS NULL ORDER BY tbl, grant_id`,
    parameters: [grantee],
    decode: decodeGrants,
  }),
  /** Live grants on rows `owner` (a key or a team id) owns. */
  grantsGiven: (owner: Uint8Array): OwnershipQuery<Grant> => ({
    sql: `SELECT ${GRANT_COLUMNS} FROM chronolog_grants WHERE grantor = ? AND revoked_tx IS NULL ORDER BY tbl, grant_id`,
    parameters: [owner],
    decode: decodeGrants,
  }),
  /** Open offers `member` may accept: to its key, or to a team it administers. */
  incomingOffers: (member: Uint8Array): OwnershipQuery<TransferOffer> => ({
    sql: `SELECT ${OFFER_COLUMNS} FROM chronolog_transfers
           WHERE state = 'open' AND (to_owner = ?1 OR to_owner IN (
             SELECT collective_id FROM chronolog_collective_members WHERE member_key = ?1 AND role = 'admin' AND state = 'active'))
           ORDER BY offer_id`,
    parameters: [member],
    decode: decodeOffers,
  }),
  /** Open offers of rows `owner` (a key or a team id) owns. */
  outgoingOffers: (owner: Uint8Array): OwnershipQuery<TransferOffer> => ({
    sql: `SELECT ${OFFER_COLUMNS} FROM chronolog_transfers WHERE state = 'open' AND from_owner = ? ORDER BY offer_id`,
    parameters: [owner],
    decode: decodeOffers,
  }),
})

function teamsQuery(member: Uint8Array, state: 'active' | 'invited'): OwnershipQuery<TeamMembership> {
  return {
    sql: `SELECT c.collective_id, m.role, c.insert_role, c.update_role, c.delete_role
            FROM chronolog_collective_members AS m
            JOIN chronolog_collectives AS c ON c.collective_id = m.collective_id
           WHERE m.member_key = ? AND m.state = '${state}' AND c.kind = 'team'
           ORDER BY c.collective_id`,
    parameters: [member],
    decode: (result) => result.rows.map((row) => ({
      teamId: bytes(row[0]),
      role: text(row[1]) as CollectiveRole,
      governance: { insert: text(row[2]) as CollectiveRole, update: text(row[3]) as CollectiveRole, delete: text(row[4]) as CollectiveRole },
    })),
  }
}

function decodeGrants(result: DecodedLocalSqlResult): readonly Grant[] {
  return result.rows.map((row) => ({
    grantId: bytes(row[0]),
    table: text(row[1]),
    grantor: bytes(row[2]),
    grantee: bytes(row[3]),
    rowKey: row[4] === null ? null : text(row[4]),
    operations: GRANT_ORDER.filter((_, index) => row[5 + index] === 1n),
    columns: row[8] === null ? null : (JSON.parse(text(row[8])) as string[]),
  }))
}

function decodeOffers(result: DecodedLocalSqlResult): readonly TransferOffer[] {
  return result.rows.map((row) => ({
    offerId: bytes(row[0]),
    table: row[1] === null ? null : text(row[1]),
    rowKey: row[2] === null ? null : text(row[2]),
    from: bytes(row[3]),
    to: bytes(row[4]),
    carry: row[5] === 1n,
  }))
}

function bytes(value: DecodedLocalSqlValue | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new TypeError('Expected a BLOB in ownership state')
  return value
}

function text(value: DecodedLocalSqlValue | undefined): string {
  if (typeof value !== 'string') throw new TypeError('Expected TEXT in ownership state')
  return value
}

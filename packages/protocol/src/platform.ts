import { domainSeparatedBytes, sha256 } from '@chronolog/canonical'

import { bytesToHex, concatBytes, utf8 } from './bytes.js'
import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { protocolInvariant } from './errors.js'
import {
  assertKnownIntegerKeys,
  expectArray,
  expectBytes,
  expectMap,
  expectString,
  expectUint64,
  integerMap,
  optional,
  required,
} from './schema.js'
import { sqlValueFromCanonicalCbor, sqlValueToCanonicalCbor, toSqlValue, type SqlValue } from './sql.js'
import { isSealedPlatformOp, sealedOp, sealedPlatformOpFromCanonicalCbor, sealedPlatformOpToCanonicalCbor, type SealedPlatformOp } from './sealed.js'

/**
 * Platform operations: typed steps of a transaction program that change the
 * row-ownership state (registered tables, collectives, grants, transfers).
 * Every replica executes them with the same trusted code, as the
 * transaction's signer. See docs/design-owner-rows.md §6.
 */

/** Node keys, collective ids, grant ids and offer ids are all 32 bytes. */
export const PLATFORM_ID_BYTES = 32
export const MAX_PLATFORM_NAME_BYTES = 128
export const MAX_PLATFORM_LIST_ENTRIES = 256
export const MAX_ROW_KEY_VALUES = 64
export const MAX_SEED_ROWS = 10_000

/** The `group` collective: created at genesis; its membership does not confer DDL rights. */
export const GROUP_COLLECTIVE_ID: Uint8Array = new Uint8Array(PLATFORM_ID_BYTES)

export type DdlOperation = 'create' | 'alter' | 'drop' | 'index' | 'trigger'
export type DdlScope = { readonly kind: 'namespace' | 'object'; readonly name: string }

export type GrantOperation = 'insert' | 'update' | 'delete'
export type CollectiveRole = 'member' | 'admin'

/** The least role a collective member needs to insert, update or delete the collective's rows. */
export interface CollectiveGovernance {
  readonly insert: CollectiveRole
  readonly update: CollectiveRole
  readonly delete: CollectiveRole
}

export interface MemberChange {
  readonly member: Uint8Array
  /** A new role (inviting the key if it is not an active member), or `remove`. */
  readonly role: CollectiveRole | 'remove'
}

export type TransferScope =
  | { readonly kind: 'row'; readonly table: string; readonly rowKey: readonly SqlValue[] }
  /** Snapshot of every row the owner holds when offered; changes invalidate acceptance. */
  | { readonly kind: 'all' }

type OwnershipPlatformOp =
  | {
    readonly op: 'grant'
    readonly table: string
    readonly grantee: Uint8Array
    /** Whose rows the grant covers; defaults to the signer. A row grant's grantor is the row's owner. */
    readonly grantor?: Uint8Array
    /** Primary-key values of one row; absent for a whole-table grant. */
    readonly rowKey?: readonly SqlValue[]
    readonly operations: readonly GrantOperation[]
    /** Columns an update may change; absent means every column. */
    readonly columns?: readonly string[]
  }
  | { readonly op: 'revoke_grant'; readonly grantId: Uint8Array }
  | { readonly op: 'grant_ddl'; readonly scope: DdlScope; readonly grantee: Uint8Array; readonly operations: readonly DdlOperation[] }
  | { readonly op: 'revoke_ddl'; readonly grantId: Uint8Array }
  | { readonly op: 'create_collective'; readonly governance: CollectiveGovernance; readonly invitees: readonly Uint8Array[] }
  | { readonly op: 'accept_membership'; readonly collectiveId: Uint8Array }
  | { readonly op: 'leave'; readonly collectiveId: Uint8Array }
  | { readonly op: 'set_members'; readonly collectiveId: Uint8Array; readonly changes: readonly MemberChange[] }
  | {
    readonly op: 'transfer_offer'
    readonly scope: TransferScope
    /** Defaults to the signer (a row offer: the row's owner). */
    readonly fromOwner?: Uint8Array
    readonly toOwner: Uint8Array
    /** Move same-owner dependents along owner-composite ON UPDATE CASCADE foreign keys. */
    readonly carry: boolean
  }
  | { readonly op: 'transfer_accept'; readonly offerId: Uint8Array }
  | { readonly op: 'transfer_cancel'; readonly offerId: Uint8Array }
  | {
    readonly op: 'seed_rows'
    readonly table: string
    /** Must include chronolog_owner: seeded rows keep their source owners. */
    readonly columns: readonly string[]
    readonly rows: readonly (readonly SqlValue[])[]
  }
  /** Closes fork seeding for good; the fork-seed plan ends with it. Genesis root only. */
  | { readonly op: 'end_seeding' }

export type PlatformOp = OwnershipPlatformOp | SealedPlatformOp
export type PlatformOpName = PlatformOp['op']
type OwnershipPlatformOpName = OwnershipPlatformOp['op']

const OP_CODES: readonly OwnershipPlatformOpName[] = [
  'grant', 'revoke_grant', 'create_collective', 'accept_membership',
  'leave', 'set_members', 'transfer_offer', 'transfer_accept', 'seed_rows', 'end_seeding', 'transfer_cancel', 'grant_ddl', 'revoke_ddl',
]
const DDL_OPERATIONS: readonly DdlOperation[] = ['create', 'alter', 'drop', 'index', 'trigger']
const OPERATION_BITS: Readonly<Record<GrantOperation, bigint>> = { insert: 1n, update: 2n, delete: 4n }
const GRANT_OPERATIONS: readonly GrantOperation[] = ['insert', 'update', 'delete']

export function isPlatformOp(value: unknown): value is PlatformOp {
  return isSealedPlatformOp(value) || (typeof value === 'object' && value !== null && 'op' in value &&
    OP_CODES.includes((value as { readonly op: OwnershipPlatformOpName }).op))
}

// ── builders ────────────────────────────────────────────────────────────────

const bytes = (value: Uint8Array): Uint8Array => Uint8Array.from(value)
const rowKey = (values: readonly unknown[]): SqlValue[] => values.map(toSqlValue)

/** Typed builders for every platform operation; each validates its input. */
export const platformOp = Object.freeze({
  ...sealedOp,
  grantDdl: (input: { readonly scope: DdlScope; readonly grantee: Uint8Array; readonly operations: readonly DdlOperation[] }): PlatformOp =>
    checked({ op: 'grant_ddl', scope: { ...input.scope }, grantee: bytes(input.grantee), operations: [...input.operations] }),
  revokeDdl: (grantId: Uint8Array): PlatformOp => checked({ op: 'revoke_ddl', grantId: bytes(grantId) }),
  grant: (input: {
    readonly table: string
    readonly grantee: Uint8Array
    readonly operations: readonly GrantOperation[]
    readonly grantor?: Uint8Array
    readonly rowKey?: readonly unknown[]
    readonly columns?: readonly string[]
  }): PlatformOp => checked({
    op: 'grant',
    table: input.table,
    grantee: bytes(input.grantee),
    operations: [...input.operations],
    ...(input.grantor === undefined ? {} : { grantor: bytes(input.grantor) }),
    ...(input.rowKey === undefined ? {} : { rowKey: rowKey(input.rowKey) }),
    ...(input.columns === undefined ? {} : { columns: [...input.columns] }),
  }),
  revokeGrant: (grantId: Uint8Array): PlatformOp => checked({ op: 'revoke_grant', grantId: bytes(grantId) }),
  createCollective: (input: { readonly governance: CollectiveGovernance; readonly invitees?: readonly Uint8Array[] }): PlatformOp =>
    checked({ op: 'create_collective', governance: { ...input.governance }, invitees: (input.invitees ?? []).map(bytes) }),
  acceptMembership: (collectiveId: Uint8Array): PlatformOp => checked({ op: 'accept_membership', collectiveId: bytes(collectiveId) }),
  leave: (collectiveId: Uint8Array): PlatformOp => checked({ op: 'leave', collectiveId: bytes(collectiveId) }),
  setMembers: (collectiveId: Uint8Array, changes: readonly MemberChange[]): PlatformOp => checked({
    op: 'set_members',
    collectiveId: bytes(collectiveId),
    changes: changes.map((change) => ({ member: bytes(change.member), role: change.role })),
  }),
  transferRow: (input: {
    readonly table: string
    readonly rowKey: readonly unknown[]
    readonly toOwner: Uint8Array
    readonly carry?: boolean
    readonly fromOwner?: Uint8Array
  }): PlatformOp => checked({
    op: 'transfer_offer',
    scope: { kind: 'row', table: input.table, rowKey: rowKey(input.rowKey) },
    toOwner: bytes(input.toOwner),
    carry: input.carry ?? false,
    ...(input.fromOwner === undefined ? {} : { fromOwner: bytes(input.fromOwner) }),
  }),
  transferAll: (input: { readonly toOwner: Uint8Array; readonly fromOwner?: Uint8Array }): PlatformOp => checked({
    op: 'transfer_offer',
    scope: { kind: 'all' },
    toOwner: bytes(input.toOwner),
    carry: true,
    ...(input.fromOwner === undefined ? {} : { fromOwner: bytes(input.fromOwner) }),
  }),
  acceptTransfer: (offerId: Uint8Array): PlatformOp => checked({ op: 'transfer_accept', offerId: bytes(offerId) }),
  cancelTransfer: (offerId: Uint8Array): PlatformOp => checked({ op: 'transfer_cancel', offerId: bytes(offerId) }),
  seedRows: (table: string, columns: readonly string[], rows: readonly (readonly unknown[])[]): PlatformOp =>
    checked({ op: 'seed_rows', table, columns: [...columns], rows: rows.map(rowKey) }),
  endSeeding: (): PlatformOp => checked({ op: 'end_seeding' }),
})

function checked(op: PlatformOp): PlatformOp {
  platformOpToCanonicalCbor(op)
  return op
}

// ── canonical CBOR ──────────────────────────────────────────────────────────

function nameToCbor(value: string, field: string): string {
  protocolInvariant(typeof value === 'string' && value.length > 0, 'SCHEMA_INVALID', `${field} cannot be empty`)
  protocolInvariant(!value.includes('\0'), 'SCHEMA_INVALID', `${field} cannot contain U+0000`)
  protocolInvariant(utf8(value).length <= MAX_PLATFORM_NAME_BYTES, 'SCHEMA_INVALID', `${field} is too long`)
  return value
}

function idToCbor(value: Uint8Array, field: string): Uint8Array {
  protocolInvariant(value instanceof Uint8Array && value.length === PLATFORM_ID_BYTES, 'SCHEMA_INVALID', `${field} must contain ${PLATFORM_ID_BYTES} bytes`)
  return Uint8Array.from(value)
}

function listToCbor<T>(values: readonly T[], field: string, encode: (value: T, index: number) => CborValue, minimum = 0): CborValue[] {
  protocolInvariant(isList(values), 'SCHEMA_INVALID', `${field} must be a list`)
  protocolInvariant(values.length >= minimum && values.length <= MAX_PLATFORM_LIST_ENTRIES, 'SCHEMA_INVALID', `${field} has an invalid number of entries`)
  return values.map(encode)
}

function uniqueBy<T>(values: readonly T[], key: (value: T) => string, field: string): void {
  const seen = new Set<string>()
  for (const value of values) {
    const entry = key(value)
    protocolInvariant(!seen.has(entry), 'SCHEMA_INVALID', `${field} contains a duplicate`)
    seen.add(entry)
  }
}

const hex = (value: Uint8Array): string => bytesToHex(value)
const isList = (value: unknown): boolean => Array.isArray(value)

function rowKeyToCbor(values: readonly SqlValue[], field: string): CborValue[] {
  protocolInvariant(isList(values) && values.length >= 1 && values.length <= MAX_ROW_KEY_VALUES, 'SCHEMA_INVALID', `${field} must have 1 to ${MAX_ROW_KEY_VALUES} values`)
  return values.map(sqlValueToCanonicalCbor)
}

function roleCode(role: CollectiveRole, field: string): bigint {
  protocolInvariant(role === 'member' || role === 'admin', 'SCHEMA_INVALID', `${field} must be member or admin`)
  return role === 'member' ? 0n : 1n
}

function roleFromCode(value: CborValue, field: string): CollectiveRole {
  const code = expectUint64(value, field)
  protocolInvariant(code <= 1n, 'SCHEMA_INVALID', `${field} must be member or admin`)
  return code === 0n ? 'member' : 'admin'
}

export function platformOpToCanonicalCbor(op: PlatformOp): CborValue {
  if (isSealedPlatformOp(op)) return sealedPlatformOpToCanonicalCbor(op)
  const code = OP_CODES.indexOf(op.op)
  protocolInvariant(code >= 0, 'SCHEMA_INVALID', 'Unknown platform operation')
  const entries: (readonly [number, CborValue | undefined])[] = [[0, BigInt(code)]]
  switch (op.op) {
    case 'grant_ddl': {
      protocolInvariant(op.scope.kind === 'namespace' || op.scope.kind === 'object', 'SCHEMA_INVALID', 'Unknown DDL scope')
      protocolInvariant(op.scope.kind !== 'namespace' || op.scope.name === 'main', 'SCHEMA_INVALID', 'Only the main namespace exists')
      protocolInvariant(isList(op.operations) && op.operations.length > 0, 'SCHEMA_INVALID', 'DDL operations cannot be empty')
      uniqueBy(op.operations, (value) => value, 'grant_ddl.operations')
      protocolInvariant(op.operations.every((operation) => DDL_OPERATIONS.includes(operation) &&
        (op.scope.kind === 'namespace' ? operation === 'create' : operation !== 'create')), 'SCHEMA_INVALID', 'Invalid DDL operation for scope')
      protocolInvariant(DDL_OPERATIONS.filter((operation) => op.operations.includes(operation)).every((operation, index) => op.operations[index] === operation),
        'SCHEMA_INVALID', 'DDL operations must be in create, alter, drop, index, trigger order')
      entries.push([1, [op.scope.kind === 'namespace' ? 0n : 1n, nameToCbor(op.scope.name, 'grant_ddl.scope')]],
        [2, idToCbor(op.grantee, 'grant_ddl.grantee')], [3, op.operations.map((operation) => BigInt(DDL_OPERATIONS.indexOf(operation)))])
      break
    }
    case 'revoke_ddl':
      entries.push([1, idToCbor(op.grantId, 'revoke_ddl.grant_id')])
      break
    case 'grant': {
      protocolInvariant(isList(op.operations) && op.operations.length > 0, 'SCHEMA_INVALID', 'grant.operations cannot be empty')
      uniqueBy(op.operations, (value) => value, 'grant.operations')
      let mask = 0n
      for (const operation of op.operations) {
        protocolInvariant(GRANT_OPERATIONS.includes(operation), 'SCHEMA_INVALID', 'grant.operations has an unknown operation')
        mask |= OPERATION_BITS[operation]
      }
      // The canonical form lists operations in insert, update, delete order.
      protocolInvariant(GRANT_OPERATIONS.filter((operation) => op.operations.includes(operation)).every((operation, index) => op.operations[index] === operation),
        'SCHEMA_INVALID', 'grant.operations must be in insert, update, delete order')
      if (op.columns !== undefined) uniqueBy(op.columns, (value) => value, 'grant.columns')
      entries.push(
        [1, nameToCbor(op.table, 'grant.table')],
        [2, idToCbor(op.grantee, 'grant.grantee')],
        [3, mask],
        [4, op.grantor === undefined ? undefined : idToCbor(op.grantor, 'grant.grantor')],
        [5, op.rowKey === undefined ? undefined : rowKeyToCbor(op.rowKey, 'grant.row_key')],
        [6, op.columns === undefined ? undefined : listToCbor(op.columns, 'grant.columns', (column) => nameToCbor(column, 'grant.columns'), 1)],
      )
      break
    }
    case 'revoke_grant':
      entries.push([1, idToCbor(op.grantId, 'revoke_grant.grant_id')])
      break
    case 'create_collective':
      uniqueBy(op.invitees, hex, 'create_collective.invitees')
      entries.push(
        [1, integerMap([
          [0, roleCode(op.governance.insert, 'governance.insert')],
          [1, roleCode(op.governance.update, 'governance.update')],
          [2, roleCode(op.governance.delete, 'governance.delete')],
        ])],
        [2, listToCbor(op.invitees, 'create_collective.invitees', (key) => idToCbor(key, 'create_collective.invitees'))],
      )
      break
    case 'accept_membership':
    case 'leave':
      entries.push([1, idToCbor(op.collectiveId, `${op.op}.collective_id`)])
      break
    case 'set_members':
      uniqueBy(op.changes, (change) => hex(change.member), 'set_members.changes')
      entries.push(
        [1, idToCbor(op.collectiveId, 'set_members.collective_id')],
        [2, listToCbor(op.changes, 'set_members.changes', (change) => [
          idToCbor(change.member, 'set_members.member'),
          change.role === 'remove' ? 2n : roleCode(change.role, 'set_members.role'),
        ], 1)],
      )
      break
    case 'transfer_offer': {
      protocolInvariant(typeof op.carry === 'boolean', 'SCHEMA_INVALID', 'transfer_offer.carry must be a boolean')
      let scope: CborValue
      if (op.scope.kind === 'all') {
        protocolInvariant(op.carry, 'SCHEMA_INVALID', 'A transfer of all rows always carries dependents')
        scope = [1n]
      } else {
        protocolInvariant(op.scope.kind === 'row', 'SCHEMA_INVALID', 'transfer_offer.scope is unknown')
        scope = [0n, nameToCbor(op.scope.table, 'transfer_offer.table'), rowKeyToCbor(op.scope.rowKey, 'transfer_offer.row_key')]
      }
      entries.push(
        [1, scope],
        [2, op.fromOwner === undefined ? undefined : idToCbor(op.fromOwner, 'transfer_offer.from_owner')],
        [3, idToCbor(op.toOwner, 'transfer_offer.to_owner')],
        [4, op.carry ? 1n : 0n],
      )
      break
    }
    case 'transfer_accept':
    case 'transfer_cancel':
      entries.push([1, idToCbor(op.offerId, `${op.op}.offer_id`)])
      break
    case 'seed_rows': {
      uniqueBy(op.columns, (value) => value.toLowerCase(), 'seed_rows.columns')
      protocolInvariant(isList(op.rows) && op.rows.length >= 1 && op.rows.length <= MAX_SEED_ROWS, 'SCHEMA_INVALID', 'seed_rows.rows has an invalid number of rows')
      entries.push(
        [1, nameToCbor(op.table, 'seed_rows.table')],
        [2, listToCbor(op.columns, 'seed_rows.columns', (column) => nameToCbor(column, 'seed_rows.columns'), 1)],
        [3, op.rows.map((row) => {
          protocolInvariant(isList(row) && row.length === op.columns.length, 'SCHEMA_INVALID', 'seed_rows row width must match its columns')
          return row.map(sqlValueToCanonicalCbor)
        })],
      )
      break
    }
    case 'end_seeding':
      break
  }
  return integerMap(entries)
}

const KNOWN_KEYS: Readonly<Record<OwnershipPlatformOpName, readonly number[]>> = {
  grant_ddl: [0, 1, 2, 3],
  revoke_ddl: [0, 1],
  grant: [0, 1, 2, 3, 4, 5, 6],
  revoke_grant: [0, 1],
  create_collective: [0, 1, 2],
  accept_membership: [0, 1],
  leave: [0, 1],
  set_members: [0, 1, 2],
  transfer_offer: [0, 1, 2, 3, 4],
  transfer_accept: [0, 1],
  transfer_cancel: [0, 1],
  seed_rows: [0, 1, 2, 3],
  end_seeding: [0],
}

export function platformOpFromCanonicalCbor(value: CborValue, name = 'platform_op'): PlatformOp {
  const map = expectMap(value, name)
  const code = expectUint64(required(map, 0, `${name}.op`), `${name}.op`)
  if (code >= 64n) return sealedPlatformOpFromCanonicalCbor(value, name)
  protocolInvariant(code < BigInt(OP_CODES.length), 'SCHEMA_INVALID', `${name} has an unknown operation`)
  const kind = OP_CODES[Number(code)]!
  assertKnownIntegerKeys(map, KNOWN_KEYS[kind], name)
  const text = (key: number, field: string): string => expectString(required(map, key, `${name}.${field}`), `${name}.${field}`)
  const id = (key: number, field: string): Uint8Array =>
    Uint8Array.from(expectBytes(required(map, key, `${name}.${field}`), `${name}.${field}`, PLATFORM_ID_BYTES))
  const optionalId = (key: number, field: string): Uint8Array | undefined => {
    const entry = optional(map, key)
    return entry === undefined ? undefined : Uint8Array.from(expectBytes(entry, `${name}.${field}`, PLATFORM_ID_BYTES))
  }
  const values = (entry: CborValue, field: string): SqlValue[] =>
    expectArray(entry, field).map((item, index) => sqlValueFromCanonicalCbor(item, `${field}[${index}]`))
  let op: PlatformOp
  switch (kind) {
    case 'grant_ddl': {
      const scope = expectArray(required(map, 1, `${name}.scope`), `${name}.scope`)
      protocolInvariant(scope.length === 2, 'SCHEMA_INVALID', 'Invalid DDL scope arity')
      const scopeKind = expectUint64(scope[0] ?? null, `${name}.scope.kind`)
      protocolInvariant(scopeKind <= 1n, 'SCHEMA_INVALID', 'Invalid DDL scope kind')
      const operations = expectArray(required(map, 3, `${name}.operations`), `${name}.operations`).map((entry) => {
        const code = expectUint64(entry, `${name}.operation`)
        protocolInvariant(code < BigInt(DDL_OPERATIONS.length), 'SCHEMA_INVALID', 'Unknown DDL operation')
        return DDL_OPERATIONS[Number(code)]!
      })
      op = { op: kind, scope: { kind: scopeKind === 0n ? 'namespace' : 'object', name: expectString(scope[1] ?? null, `${name}.scope.name`) },
        grantee: id(2, 'grantee'), operations }
      break
    }
    case 'revoke_ddl':
      op = { op: kind, grantId: id(1, 'grant_id') }
      break
    case 'grant': {
      const mask = expectUint64(required(map, 3, `${name}.operations`), `${name}.operations`)
      protocolInvariant(mask >= 1n && mask <= 7n, 'SCHEMA_INVALID', `${name}.operations is invalid`)
      const grantor = optionalId(4, 'grantor')
      const key = optional(map, 5)
      const columns = optional(map, 6)
      op = {
        op: kind,
        table: text(1, 'table'),
        grantee: id(2, 'grantee'),
        operations: GRANT_OPERATIONS.filter((operation) => (mask & OPERATION_BITS[operation]) !== 0n),
        ...(grantor === undefined ? {} : { grantor }),
        ...(key === undefined ? {} : { rowKey: values(key, `${name}.row_key`) }),
        ...(columns === undefined ? {} : { columns: expectArray(columns, `${name}.columns`).map((column) => expectString(column, `${name}.columns`)) }),
      }
      break
    }
    case 'revoke_grant':
      op = { op: kind, grantId: id(1, 'grant_id') }
      break
    case 'create_collective': {
      const governance = expectMap(required(map, 1, `${name}.governance`), `${name}.governance`)
      assertKnownIntegerKeys(governance, [0, 1, 2], `${name}.governance`)
      op = {
        op: kind,
        governance: {
          insert: roleFromCode(required(governance, 0, 'governance.insert'), 'governance.insert'),
          update: roleFromCode(required(governance, 1, 'governance.update'), 'governance.update'),
          delete: roleFromCode(required(governance, 2, 'governance.delete'), 'governance.delete'),
        },
        invitees: expectArray(required(map, 2, `${name}.invitees`), `${name}.invitees`)
          .map((key) => Uint8Array.from(expectBytes(key, `${name}.invitees`, PLATFORM_ID_BYTES))),
      }
      break
    }
    case 'accept_membership':
    case 'leave':
      op = { op: kind, collectiveId: id(1, 'collective_id') }
      break
    case 'set_members':
      op = {
        op: kind,
        collectiveId: id(1, 'collective_id'),
        changes: expectArray(required(map, 2, `${name}.changes`), `${name}.changes`).map((entry) => {
          const tuple = expectArray(entry, `${name}.change`)
          protocolInvariant(tuple.length === 2, 'SCHEMA_INVALID', `${name}.change has invalid arity`)
          const role = expectUint64(tuple[1] ?? null, `${name}.change.role`)
          protocolInvariant(role <= 2n, 'SCHEMA_INVALID', `${name}.change.role is unknown`)
          return {
            member: Uint8Array.from(expectBytes(tuple[0] ?? null, `${name}.change.member`, PLATFORM_ID_BYTES)),
            role: role === 0n ? 'member' as const : role === 1n ? 'admin' as const : 'remove' as const,
          }
        }),
      }
      break
    case 'transfer_offer': {
      const scope = expectArray(required(map, 1, `${name}.scope`), `${name}.scope`)
      const scopeKind = expectUint64(scope[0] ?? null, `${name}.scope.kind`)
      let decodedScope: TransferScope
      if (scopeKind === 1n) {
        protocolInvariant(scope.length === 1, 'SCHEMA_INVALID', `${name}.scope has invalid arity`)
        decodedScope = { kind: 'all' }
      } else {
        protocolInvariant(scopeKind === 0n && scope.length === 3, 'SCHEMA_INVALID', `${name}.scope is invalid`)
        decodedScope = {
          kind: 'row',
          table: expectString(scope[1] ?? null, `${name}.scope.table`),
          rowKey: values(scope[2] ?? null, `${name}.scope.row_key`),
        }
      }
      const carry = expectUint64(required(map, 4, `${name}.carry`), `${name}.carry`)
      protocolInvariant(carry <= 1n, 'SCHEMA_INVALID', `${name}.carry must be 0 or 1`)
      const fromOwner = optionalId(2, 'from_owner')
      op = {
        op: kind,
        scope: decodedScope,
        ...(fromOwner === undefined ? {} : { fromOwner }),
        toOwner: id(3, 'to_owner'),
        carry: carry === 1n,
      }
      break
    }
    case 'transfer_accept':
    case 'transfer_cancel':
      op = { op: kind, offerId: id(1, 'offer_id') }
      break
    case 'seed_rows':
      op = {
        op: kind,
        table: text(1, 'table'),
        columns: expectArray(required(map, 2, `${name}.columns`), `${name}.columns`).map((column) => expectString(column, `${name}.columns`)),
        rows: expectArray(required(map, 3, `${name}.rows`), `${name}.rows`).map((row, index) => values(row, `${name}.rows[${index}]`)),
      }
      break
    case 'end_seeding':
      op = { op: kind }
      break
  }
  platformOpToCanonicalCbor(op)
  return op
}

export function encodePlatformOp(op: PlatformOp): Uint8Array {
  return encodeCanonicalCbor(platformOpToCanonicalCbor(op))
}

export function decodePlatformOp(bytes: Uint8Array): PlatformOp {
  return platformOpFromCanonicalCbor(assertCanonicalCbor(bytes))
}

/** The hash preimage of the id of the grant, collective or offer created by step `stepIndex` of `txId`. */
export function platformObjectIdPreimage(txId: Uint8Array, stepIndex: number): Uint8Array {
  protocolInvariant(Number.isSafeInteger(stepIndex) && stepIndex >= 0 && stepIndex <= 0xffff_ffff, 'INTEGER_OUT_OF_RANGE', 'Step index is out of range')
  const index = new Uint8Array(4)
  new DataView(index.buffer).setUint32(0, stepIndex, false)
  const length = new Uint8Array(4)
  new DataView(length.buffer).setUint32(0, txId.length, false)
  return concatBytes(length, txId, index)
}

/** The 32-byte id of the grant, collective or offer created by step `stepIndex` of transaction `txId`. */
export async function platformObjectId(txId: Uint8Array, stepIndex: number): Promise<Uint8Array> {
  return sha256(platformObjectIdHashInput(txId, stepIndex))
}

/** The domain-separated bytes whose SHA-256 is the platform object id (for synchronous hashing). */
export function platformObjectIdHashInput(txId: Uint8Array, stepIndex: number): Uint8Array {
  return domainSeparatedBytes('platformObject', platformObjectIdPreimage(txId, stepIndex))
}

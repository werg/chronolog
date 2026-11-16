import { GROUP_COLLECTIVE_ID } from '@chronolog/protocol'

import type { DatabaseLike } from '../types.js'
import { SEALED_TABLES_SQL } from './sealed.js'

/**
 * Replicated platform state for owner-controlled rows
 * (docs/design-owner-rows.md §3). Transactions may read it; only platform
 * operations write it.
 */
export const PLATFORM_TABLES_SQL: readonly string[] = [
  `CREATE TABLE chronolog_platform (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    root_admin BLOB NOT NULL CHECK (length(root_admin) = 32),
    seeding_open INTEGER NOT NULL CHECK (seeding_open IN (0, 1))
  ) STRICT`,
  // Every owner as a small integer: row owner columns hold these ids, not
  // 32-byte keys. A key gets its id on first use (signing a transaction,
  // creating a collective, being seeded as an owner); ids never change.
  `CREATE TABLE chronolog_principals (
    id INTEGER PRIMARY KEY NOT NULL,
    key BLOB NOT NULL UNIQUE CHECK (length(key) = 32)
  ) STRICT`,
  `CREATE TABLE chronolog_tables (
    name TEXT PRIMARY KEY NOT NULL,
    registered_at_tx BLOB NOT NULL
  ) STRICT`,
  `CREATE TABLE chronolog_collectives (
    collective_id BLOB PRIMARY KEY NOT NULL CHECK (length(collective_id) = 32),
    kind TEXT NOT NULL CHECK (kind IN ('group', 'team')),
    insert_role TEXT NOT NULL CHECK (insert_role IN ('member', 'admin')),
    update_role TEXT NOT NULL CHECK (update_role IN ('member', 'admin')),
    delete_role TEXT NOT NULL CHECK (delete_role IN ('member', 'admin')),
    created_tx BLOB
  ) STRICT`,
  `CREATE TABLE chronolog_collective_members (
    collective_id BLOB NOT NULL REFERENCES chronolog_collectives (collective_id),
    member_key BLOB NOT NULL CHECK (length(member_key) = 32),
    role TEXT NOT NULL CHECK (role IN ('member', 'admin')),
    state TEXT NOT NULL CHECK (state IN ('invited', 'active', 'left')),
    joined_tx BLOB,
    left_tx BLOB,
    PRIMARY KEY (collective_id, member_key)
  ) STRICT`,
  `CREATE INDEX chronolog_collective_members_by_key ON chronolog_collective_members (member_key, state)`,
  `CREATE TABLE chronolog_grants (
    grant_id BLOB PRIMARY KEY NOT NULL CHECK (length(grant_id) = 32),
    tbl TEXT NOT NULL,
    grantor BLOB NOT NULL CHECK (length(grantor) = 32),
    grantee_key BLOB NOT NULL CHECK (length(grantee_key) = 32),
    row_key TEXT,
    op_insert INTEGER NOT NULL CHECK (op_insert IN (0, 1)),
    op_update INTEGER NOT NULL CHECK (op_update IN (0, 1)),
    op_delete INTEGER NOT NULL CHECK (op_delete IN (0, 1)),
    columns TEXT CHECK (columns IS NULL OR json_valid(columns)),
    created_tx BLOB NOT NULL,
    revoked_tx BLOB,
    CHECK (row_key IS NULL OR op_insert = 0)
  ) STRICT`,
  `CREATE INDEX chronolog_grants_by_grantee ON chronolog_grants (grantee_key, tbl)`,
  `CREATE INDEX chronolog_live_grants_by_row ON chronolog_grants (tbl, row_key)
    WHERE revoked_tx IS NULL AND row_key IS NOT NULL`,
  `CREATE TABLE chronolog_transfers (
    offer_id BLOB PRIMARY KEY NOT NULL CHECK (length(offer_id) = 32),
    tbl TEXT,
    row_key TEXT,
    from_owner BLOB NOT NULL CHECK (length(from_owner) = 32),
    to_owner BLOB NOT NULL CHECK (length(to_owner) = 32),
    carry INTEGER NOT NULL CHECK (carry IN (0, 1)),
    scope_digest BLOB NOT NULL CHECK (length(scope_digest) = 32),
    state TEXT NOT NULL CHECK (state IN ('open', 'accepted', 'cancelled')),
    created_tx BLOB NOT NULL,
    closed_tx BLOB,
    CHECK ((tbl IS NULL) = (row_key IS NULL))
  ) STRICT`,
  `CREATE INDEX chronolog_open_transfers_by_owner ON chronolog_transfers (tbl, from_owner)
    WHERE state = 'open'`,
  `CREATE TABLE chronolog_transfer_scope (
    offer_id BLOB NOT NULL REFERENCES chronolog_transfers (offer_id),
    tbl TEXT NOT NULL,
    row_key TEXT NOT NULL,
    PRIMARY KEY (offer_id, tbl, row_key)
  ) STRICT`,
  `CREATE INDEX chronolog_transfer_scope_by_row ON chronolog_transfer_scope (tbl, row_key)`,
  // Written and emptied inside one platform operation; always empty between steps.
  `CREATE TABLE chronolog_exemptions (
    kind TEXT NOT NULL CHECK (kind IN ('transfer', 'seed')),
    tbl TEXT NOT NULL,
    row_key TEXT,
    to_row_key TEXT,
    from_owner INTEGER,
    to_owner INTEGER,
    CHECK (kind = 'seed' OR (row_key IS NOT NULL AND to_row_key IS NOT NULL
      AND from_owner IS NOT NULL AND to_owner IS NOT NULL))
  ) STRICT`,
  ...SEALED_TABLES_SQL,
]

export type OwnerOperation = 'insert' | 'update' | 'delete'
export const OWNER_OPERATIONS: readonly OwnerOperation[] = ['insert', 'update', 'delete']

/** The actor's principal id plus those of the collectives whose governance lets the actor perform `operation`. */
export const ownerIdsView = (operation: OwnerOperation): string => `chronolog_my_owner_ids_${operation}`
/** Live grants to the actor for `operation`; `grantor` is a principal id; row_key is NULL for whole-table grants. */
export const grantsToMeView = (operation: OwnerOperation): string => `chronolog_grants_to_me_${operation}`

export const PLATFORM_VIEWS_SQL: readonly string[] = OWNER_OPERATIONS.flatMap((operation) => [
  `CREATE VIEW ${ownerIdsView(operation)} (id) AS
    SELECT chronolog_actor_id() WHERE chronolog_actor_id() IS NOT NULL
    UNION ALL
    SELECT p.id
      FROM chronolog_collectives AS c
      JOIN chronolog_collective_members AS m ON m.collective_id = c.collective_id
      JOIN chronolog_principals AS p ON p.key = c.collective_id
     WHERE m.member_key = chronolog_actor() AND m.state = 'active'
       AND (c.${operation}_role = 'member' OR m.role = 'admin')`,
  `CREATE VIEW ${grantsToMeView(operation)} (grant_id, tbl, grantor, grantor_key, row_key, columns) AS
    SELECT g.grant_id, g.tbl, p.id, g.grantor, g.row_key, g.columns
      FROM chronolog_grants AS g
      JOIN chronolog_principals AS p ON p.key = g.grantor
     WHERE g.grantee_key = chronolog_actor() AND g.revoked_tx IS NULL AND g.op_${operation} = 1`,
])

export const PLATFORM_VIEW_NAMES: ReadonlySet<string> = new Set(
  OWNER_OPERATIONS.flatMap((operation) => [ownerIdsView(operation), grantsToMeView(operation)]),
)

/**
 * Create the platform tables and views and the `group` collective,
 * administered by the root. Fork seeding starts open only in a fork.
 */
export function initializePlatform(database: DatabaseLike, rootAdministrator: Uint8Array, forkSeeding: boolean): void {
  if (rootAdministrator.length !== 32) throw new Error('MATERIALIZER_ROOT_ADMINISTRATOR_INVALID')
  for (const sql of [...PLATFORM_TABLES_SQL, ...PLATFORM_VIEWS_SQL]) database.exec(sql)
  database.prepare('INSERT INTO chronolog_platform (singleton, root_admin, seeding_open) VALUES (1, ?, ?)').run(rootAdministrator, forkSeeding ? 1 : 0)
  database.prepare(`
    INSERT INTO chronolog_collectives (collective_id, kind, insert_role, update_role, delete_role, created_tx)
    VALUES (?, 'group', 'admin', 'admin', 'admin', NULL)
  `).run(GROUP_COLLECTIVE_ID)
  database.prepare(`
    INSERT INTO chronolog_collective_members (collective_id, member_key, role, state, joined_tx, left_tx)
    VALUES (?, ?, 'admin', 'active', NULL, NULL)
  `).run(GROUP_COLLECTIVE_ID, rootAdministrator)
  // The group collective is principal 1 and the root administrator 2.
  database.prepare('INSERT INTO chronolog_principals (id, key) VALUES (1, ?), (2, ?)').run(GROUP_COLLECTIVE_ID, rootAdministrator)
}

export function readRootAdministrator(database: DatabaseLike): Uint8Array {
  const row = database.prepare('SELECT root_admin FROM chronolog_platform WHERE singleton = 1').get()
  if (row === undefined || Array.isArray(row) || !(row.root_admin instanceof Uint8Array)) throw new Error('MATERIALIZER_PLATFORM_STATE_MISSING')
  return Uint8Array.from(row.root_admin)
}

import {
  encodeSealedEnvelope,
  equalBytes,
  type SealedPlatformOp,
  type SqlValue,
} from '@chronolog/protocol'

import { OWNER_COLUMN, withProfiledStatement } from '../sql-profile.js'
import type { DatabaseLike, SqlRuntimeLimits } from '../types.js'
import { quoteIdentifier, quoteText, rowKeyBindings, rowKeyFilter, type TableShape } from './tables.js'

/** Reader keys and ciphertext are replicated; private keys and plaintext never enter this state. */
export const SEALED_TABLES_SQL: readonly string[] = [
  `CREATE TABLE chronolog_reader_keys (
    reader_key BLOB PRIMARY KEY NOT NULL CHECK (length(reader_key) = 32),
    hpke_public_key BLOB NOT NULL CHECK (length(hpke_public_key) = 32),
    updated_tx BLOB NOT NULL
  ) STRICT`,
  `CREATE TABLE chronolog_reader_policies (
    policy_id BLOB PRIMARY KEY NOT NULL CHECK (length(policy_id) = 32),
    tbl TEXT NOT NULL,
    row_key TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    created_tx BLOB NOT NULL,
    updated_tx BLOB NOT NULL,
    closed_tx BLOB
  ) STRICT`,
  `CREATE UNIQUE INDEX chronolog_reader_policy_active_row
     ON chronolog_reader_policies (tbl, row_key) WHERE closed_tx IS NULL`,
  `CREATE TABLE chronolog_policy_readers (
    policy_id BLOB NOT NULL REFERENCES chronolog_reader_policies (policy_id),
    reader_key BLOB NOT NULL CHECK (length(reader_key) = 32),
    hpke_public_key BLOB NOT NULL CHECK (length(hpke_public_key) = 32),
    PRIMARY KEY (policy_id, reader_key)
  ) STRICT`,
  `CREATE TABLE chronolog_sealed_values (
    policy_id BLOB NOT NULL REFERENCES chronolog_reader_policies (policy_id),
    slot TEXT NOT NULL,
    data_version INTEGER NOT NULL CHECK (data_version > 0),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    envelope BLOB NOT NULL,
    updated_tx BLOB NOT NULL,
    PRIMARY KEY (policy_id, slot)
  ) STRICT`,
  // Exact, ephemeral authorization for an encrypted app-column update. Never seeded.
  `CREATE TABLE chronolog_sealed_write_exemptions (
    tbl TEXT NOT NULL,
    row_key TEXT NOT NULL,
    col TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (tbl, row_key, col)
  ) STRICT`,
]

export const SEEDABLE_SEALED_TABLES: readonly string[] = [
  'chronolog_reader_keys', 'chronolog_reader_policies', 'chronolog_policy_readers', 'chronolog_sealed_values',
]

/** Closing the policy generation prevents permissions reviving after delete/reinsert or a PK change. */
export function closeReaderPolicySql(table: string, oldKey: string, condition = '1'): string {
  return `UPDATE chronolog_reader_policies SET closed_tx = chronolog_transaction_id()
    WHERE tbl = ${quoteText(table)} AND row_key = ${oldKey} AND closed_tx IS NULL AND (${condition});`
}

/** A sealed app column can only change through an exact, policy-checked sealed_put. */
export function sealedWriteGuard(shape: TableShape, oldKey: string): string {
  const columns = shape.columns.filter((column) => column.hidden === 0 && column.name.toLowerCase() !== OWNER_COLUMN && column.primaryKey === 0)
  if (columns.length === 0) return ''
  const tests = columns.map((column) => {
    const name = quoteIdentifier(column.name)
    return `(NOT chronolog_value_equal(OLD.${name}, NEW.${name})
      AND EXISTS (SELECT 1 FROM chronolog_reader_policies AS p
        JOIN chronolog_sealed_values AS v ON v.policy_id = p.policy_id
        WHERE p.tbl = ${quoteText(shape.name)} AND p.row_key = ${oldKey} AND p.closed_tx IS NULL AND v.slot = ${quoteText(column.name)})
      AND NOT EXISTS (SELECT 1 FROM chronolog_sealed_write_exemptions AS e
        WHERE e.tbl = ${quoteText(shape.name)} AND e.row_key = ${oldKey} AND e.col = ${quoteText(column.name)}
          AND chronolog_value_equal(e.value, NEW.${name})))`
  })
  return `SELECT chronolog_policy_violation(${quoteText(shape.name)}, 'update') WHERE ${tests.join(' OR ')};`
}

export class SealedRejection extends Error {
  constructor(reason: string) {
    super(`platform:${reason}`)
    this.name = 'SealedRejection'
  }
}

const reject = (reason: string): never => { throw new SealedRejection(reason) }
type Row = Record<string, unknown>

/** Row ownership stays in the existing platform session; this module adds no new owner/admin roles. */
export interface SealedOperationHost {
  readonly actor: Uint8Array
  readonly txId: Uint8Array
  readonly groupId: Uint8Array
  readonly limits: Partial<SqlRuntimeLimits>
  registered(table: string): TableShape
  findRow(shape: TableShape, values: readonly SqlValue[]): { readonly key: string; readonly owner: Uint8Array } | null
  ownerOf(shape: TableShape, key: string): Uint8Array | null
  administers(owner: Uint8Array): boolean
  objectId(stepIndex: number): Uint8Array
}

interface ReaderPolicy {
  readonly id: Uint8Array
  readonly table: string
  readonly rowKey: string
  readonly version: bigint
  readonly shape: TableShape
  readonly owner: Uint8Array
}

export class SealedSession {
  constructor(readonly database: DatabaseLike, readonly host: SealedOperationHost) {}

  execute(op: SealedPlatformOp, stepIndex: number): void {
    switch (op.op) {
      case 'register_reader_key': return this.registerKey(op.publicKey)
      case 'reader_policy': return this.setPolicy(op, stepIndex)
      case 'sealed_put': return this.put(op)
    }
  }

  private registerKey(publicKey: Uint8Array): void {
    this.run(`INSERT INTO chronolog_reader_keys (reader_key, hpke_public_key, updated_tx) VALUES (?, ?, ?)
      ON CONFLICT (reader_key) DO UPDATE SET hpke_public_key = excluded.hpke_public_key, updated_tx = excluded.updated_tx`,
    this.host.actor, publicKey, this.host.txId)
  }

  private setPolicy(op: Extract<SealedPlatformOp, { op: 'reader_policy' }>, stepIndex: number): void {
    const shape = this.host.registered(op.table)
    const row = this.host.findRow(shape, op.rowKey) ?? reject('no_such_row')
    if (!this.host.administers(row.owner)) reject('not_owner')
    const existing = this.get(`SELECT policy_id, version FROM chronolog_reader_policies
      WHERE tbl = ? AND row_key = ? AND closed_tx IS NULL`, shape.name, row.key)
    let id: Uint8Array
    let version: bigint
    if (existing === undefined) {
      if (op.expectedPolicyId !== undefined || op.expectedVersion !== 0n) reject('reader_policy_stale')
      id = this.host.objectId(stepIndex)
      version = 1n
      this.run(`INSERT INTO chronolog_reader_policies (policy_id, tbl, row_key, version, created_tx, updated_tx, closed_tx)
        VALUES (?, ?, ?, ?, ?, ?, NULL)`, id, shape.name, row.key, version, this.host.txId, this.host.txId)
    } else {
      id = bytes(existing.policy_id)
      version = integer(existing.version)
      if (op.expectedPolicyId === undefined || !equalBytes(id, op.expectedPolicyId) || op.expectedVersion !== version) reject('reader_policy_stale')
      if (version === MAX_VERSION) reject('reader_policy_version_exhausted')
      version += 1n
      this.run('UPDATE chronolog_reader_policies SET version = ?, updated_tx = ? WHERE policy_id = ?', version, this.host.txId, id)
      this.run('DELETE FROM chronolog_policy_readers WHERE policy_id = ?', id)
    }
    for (const reader of op.readers) {
      const key = this.get('SELECT hpke_public_key FROM chronolog_reader_keys WHERE reader_key = ?', reader)
      if (key === undefined) reject('reader_key_missing')
      this.run('INSERT INTO chronolog_policy_readers (policy_id, reader_key, hpke_public_key) VALUES (?, ?, ?)',
        id, reader, bytes(key!.hpke_public_key))
    }
  }

  private policy(id: Uint8Array): ReaderPolicy {
    const row = this.get('SELECT tbl, row_key, version, closed_tx FROM chronolog_reader_policies WHERE policy_id = ?', id)
    if (row === undefined) reject('no_such_reader_policy')
    if (row!.closed_tx !== null) reject('reader_policy_closed')
    const table = String(row!.tbl)
    const rowKey = String(row!.row_key)
    const shape = this.host.registered(table)
    const owner = this.host.ownerOf(shape, rowKey) ?? reject('reader_policy_stale')
    return { id, table, rowKey, version: integer(row!.version), shape, owner }
  }

  private put(op: Extract<SealedPlatformOp, { op: 'sealed_put' }>): void {
    const policy = this.policy(op.policyId)
    if (policy.version !== op.expectedPolicyVersion) reject('reader_policy_stale')
    const column = policy.shape.columns.find((entry) => entry.name === op.slot)
    if (column === undefined || column.hidden !== 0 || column.primaryKey !== 0 || column.name === OWNER_COLUMN || column.type.toUpperCase() !== 'BLOB') {
      reject('sealed_column_invalid')
    }
    const current = this.get('SELECT data_version FROM chronolog_sealed_values WHERE policy_id = ? AND slot = ?', policy.id, op.slot)
    const version = current === undefined ? 0n : integer(current.data_version)
    if (version !== op.expectedDataVersion) reject('sealed_value_stale')
    if (version === MAX_VERSION) reject('sealed_value_version_exhausted')
    const context = op.envelope.context
    if (!equalBytes(context.groupId, this.host.groupId) || !equalBytes(context.policyId, policy.id) ||
        context.policyVersion !== policy.version || context.slot !== op.slot || context.dataVersion !== version + 1n) reject('sealed_context_mismatch')
    const readers = this.all(`SELECT reader_key, hpke_public_key FROM chronolog_policy_readers WHERE policy_id = ? ORDER BY reader_key`, policy.id)
    if (readers.length === 0) reject('sealed_no_readers')
    if (readers.length !== op.envelope.wraps.length || readers.some((reader, index) => {
      const wrap = op.envelope.wraps[index]!
      return !equalBytes(bytes(reader.reader_key), wrap.readerId) || !equalBytes(bytes(reader.hpke_public_key), wrap.publicKey)
    })) reject('sealed_readers_mismatch')
    const encoded = encodeSealedEnvelope(op.envelope)
    this.run('INSERT INTO chronolog_sealed_write_exemptions (tbl, row_key, col, value) VALUES (?, ?, ?, ?)', policy.table, policy.rowKey, op.slot, encoded)
    try {
      // This is an ordinary app-row UPDATE. Platform and app triggers run as
      // the original signer, including column-scoped grants and app guards.
      const changed = this.run(`UPDATE ${quoteIdentifier(policy.table)} SET ${quoteIdentifier(op.slot)} = ?
        WHERE ${rowKeyFilter(quoteIdentifier(policy.table), policy.shape.primaryKey)}`,
      encoded, ...rowKeyBindings(policy.rowKey, policy.shape.primaryKey))
      if (Number(changed.changes) !== 1) reject('reader_policy_stale')
      const stillActive = this.get('SELECT version, closed_tx FROM chronolog_reader_policies WHERE policy_id = ?', policy.id)
      const actual = this.get(`SELECT ${quoteIdentifier(op.slot)} AS value FROM ${quoteIdentifier(policy.table)}
        WHERE ${rowKeyFilter(quoteIdentifier(policy.table), policy.shape.primaryKey)}`, ...rowKeyBindings(policy.rowKey, policy.shape.primaryKey))
      if (stillActive === undefined || stillActive.closed_tx !== null || integer(stillActive.version) !== policy.version ||
          !(actual?.value instanceof Uint8Array) || !equalBytes(actual.value, encoded)) reject('sealed_write_changed')
      this.run(`INSERT INTO chronolog_sealed_values (policy_id, slot, data_version, policy_version, envelope, updated_tx)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (policy_id, slot) DO UPDATE SET data_version = excluded.data_version,
        policy_version = excluded.policy_version, envelope = excluded.envelope, updated_tx = excluded.updated_tx`,
      policy.id, op.slot, version + 1n, policy.version, encoded, this.host.txId)
    } finally {
      this.run('DELETE FROM chronolog_sealed_write_exemptions')
    }
  }

  private run(sql: string, ...parameters: unknown[]): { readonly changes: number | bigint } {
    return withProfiledStatement(this.database, sql, 'platform', (statement) => statement.run(...parameters), this.host.limits)
  }

  private get(sql: string, ...parameters: unknown[]): Row | undefined {
    return withProfiledStatement(this.database, sql, 'platform', (statement) => {
      statement.setReadBigInts?.(true)
      const row = statement.get(...parameters)
      if (Array.isArray(row)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
      return row
    }, this.host.limits)
  }

  private all(sql: string, ...parameters: unknown[]): Row[] {
    return withProfiledStatement(this.database, sql, 'platform', (statement) => {
      statement.setReadBigInts?.(true)
      return statement.all(...parameters).map((row) => {
        if (Array.isArray(row)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
        return row
      })
    }, this.host.limits)
  }
}

const MAX_VERSION = 0x7fff_ffff_ffff_ffffn
function bytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error('MATERIALIZER_SEALED_BYTES_INVALID')
  return value
}
function integer(value: unknown): bigint {
  if ((typeof value !== 'number' && typeof value !== 'bigint') || (typeof value === 'number' && !Number.isSafeInteger(value))) throw new Error('MATERIALIZER_SEALED_INTEGER_INVALID')
  return BigInt(value)
}

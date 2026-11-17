import type { DatabaseLike, StoredExecutionManifest, TransactionLogRow } from './types.js'

/** The replicated transaction log; readable by transactions, written only by Chronolog. */
export const TRANSACTION_LOG_TABLE = 'chronolog_transactions' as const
export const EXECUTION_MANIFEST_TABLE = 'chronolog_execution_manifest' as const

/** Replicated system schema, also committed by the execution manifest digest. */
export const SYSTEM_LOG_SQL = `
    CREATE TABLE ${EXECUTION_MANIFEST_TABLE} (
      singleton_key INTEGER PRIMARY KEY NOT NULL CHECK (singleton_key = 1),
      manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
      canonical_manifest BLOB NOT NULL,
      publication_mode TEXT NOT NULL CHECK (publication_mode IN ('applied', 'live')),
      sql_policy TEXT NOT NULL CHECK (sql_policy IN ('authorized', 'data-only')),
      authorization_policy TEXT NOT NULL CHECK (authorization_policy IN ('transaction-grants', 'external-membership')),
      bootstrap_program BLOB NOT NULL,
      bootstrap_group_id BLOB NOT NULL
    ) STRICT;
    CREATE TABLE chronolog_peer_control (
      singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
      application_id BLOB NOT NULL CHECK (length(application_id) = 32),
      revision INTEGER NOT NULL,
      digest BLOB NOT NULL CHECK (length(digest) = 32)
    ) STRICT;
    CREATE TABLE ${TRANSACTION_LOG_TABLE} (
      tx_id BLOB PRIMARY KEY NOT NULL,
      order_index INTEGER NOT NULL UNIQUE,
      author_id BLOB NOT NULL,
      operation_id TEXT NOT NULL,
      author_timestamp_ms INTEGER NOT NULL,
      candidate_digest BLOB NOT NULL,
      canonical_candidate BLOB NOT NULL,
      outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'rejected')),
      rejection_code TEXT,
      failing_statement_index INTEGER,
      CHECK (
        (outcome = 'accepted' AND rejection_code IS NULL AND failing_statement_index IS NULL)
        OR (outcome = 'rejected' AND rejection_code IS NOT NULL)
      )
    ) STRICT;
    CREATE INDEX chronolog_operation_identity ON ${TRANSACTION_LOG_TABLE}(author_id, operation_id)
  `

export function initializeSystemLog(database: DatabaseLike): void {
  database.exec(SYSTEM_LOG_SQL)
}

export function insertExecutionManifest(database: DatabaseLike, manifest: StoredExecutionManifest): void {
  database.prepare(`
    INSERT INTO ${EXECUTION_MANIFEST_TABLE} (singleton_key, manifest_digest, canonical_manifest, publication_mode, sql_policy, authorization_policy, bootstrap_program, bootstrap_group_id) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
  `).run(manifest.manifestDigest, manifest.canonicalManifest, manifest.publicationMode, manifest.sqlPolicy, manifest.authorizationPolicy, manifest.bootstrapProgram, manifest.bootstrapGroupId)
}

export function readExecutionManifest(database: DatabaseLike): StoredExecutionManifest {
  const raw = database.prepare(`
    SELECT manifest_digest, canonical_manifest, publication_mode, sql_policy, authorization_policy, bootstrap_program, bootstrap_group_id FROM ${EXECUTION_MANIFEST_TABLE} WHERE singleton_key = 1
  `).get()
  if (raw === undefined || Array.isArray(raw)) throw new Error('DATABASE_MANIFEST_MISSING')
  if (raw.publication_mode !== 'applied' && raw.publication_mode !== 'live') throw new Error('DATABASE_PUBLICATION_MODE_INVALID')
  if (raw.sql_policy !== 'authorized' && raw.sql_policy !== 'data-only') throw new Error('DATABASE_SQL_POLICY_INVALID')
  if (raw.authorization_policy !== 'transaction-grants' && raw.authorization_policy !== 'external-membership') throw new Error('DATABASE_AUTHORIZATION_POLICY_INVALID')
  return { manifestDigest: asDigest(raw.manifest_digest), canonicalManifest: asBytes(raw.canonical_manifest),
    publicationMode: raw.publication_mode, sqlPolicy: raw.sql_policy, authorizationPolicy: raw.authorization_policy,
    bootstrapProgram: asBytes(raw.bootstrap_program), bootstrapGroupId: asBytes(raw.bootstrap_group_id) }
}

export function readSystemLog(database: DatabaseLike): TransactionLogRow[] {
  const statement = database.prepare(`
    SELECT tx_id, order_index, author_id, operation_id, author_timestamp_ms,
           candidate_digest, canonical_candidate, outcome, rejection_code, failing_statement_index
      FROM ${TRANSACTION_LOG_TABLE}
     ORDER BY order_index
  `)
  statement.setReadBigInts?.(true)
  return statement.all().map((raw) => {
    if (Array.isArray(raw)) throw new Error('MATERIALIZER_EXPECTED_OBJECT_ROW')
    const outcome = raw.outcome
    if (outcome !== 'accepted' && outcome !== 'rejected') throw new Error('MATERIALIZER_CORRUPT_OUTCOME')
    const txId = asBytes(raw.tx_id)
    const authorId = asBytes(raw.author_id)
    const authorTimestampMs = asBigint(raw.author_timestamp_ms)
    return {
      txId,
      operationId: asString(raw.operation_id),
      orderIndex: Number(raw.order_index),
      authorId,
      authorTimestampMs,
      candidateDigest: asBytes(raw.candidate_digest),
      canonicalCandidate: asBytes(raw.canonical_candidate),
      orderKey: { authorTimestampMs, authorId, txId },
      outcome,
      rejectionCode: raw.rejection_code === null ? null : asString(raw.rejection_code),
      failingStatementIndex: raw.failing_statement_index === null ? null : Number(asBigint(raw.failing_statement_index)),
    }
  })
}

export function insertSystemLogRow(database: DatabaseLike, row: Omit<TransactionLogRow, 'orderKey'>): void {
  database.prepare(`
    INSERT INTO ${TRANSACTION_LOG_TABLE} (
      tx_id, order_index, author_id, operation_id, author_timestamp_ms,
      candidate_digest, canonical_candidate, outcome, rejection_code, failing_statement_index
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    row.txId,
    BigInt(row.orderIndex),
    row.authorId,
    row.operationId,
    row.authorTimestampMs,
    row.candidateDigest,
    row.canonicalCandidate,
    row.outcome,
    row.rejectionCode,
    row.failingStatementIndex === null ? null : BigInt(row.failingStatementIndex),
  )
}

function asBytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error('MATERIALIZER_CORRUPT_BYTES')
  return Uint8Array.from(value)
}

function asDigest(value: unknown): Uint8Array {
  const bytes = asBytes(value)
  if (bytes.length !== 32) throw new Error('MATERIALIZER_CORRUPT_DIGEST')
  return bytes
}

function asString(value: unknown): string {
  if (typeof value !== 'string') throw new Error('MATERIALIZER_CORRUPT_TEXT')
  return value
}

function asBigint(value: unknown): bigint {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number' && Number.isSafeInteger(value)) return BigInt(value)
  throw new Error('MATERIALIZER_CORRUPT_INTEGER')
}

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  createExecutionManifest,
  encodeTransactionCore,
  sqlStatement,
  sqlValue,
  transactionDigest,
  utf8,
  type ExecutionLimits,
  type SqlStatement,
  type TransactionCore,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { readNativeEngineInfo } from './driver.js'
import { DeterministicMaterializer } from './materializer.js'
import type { AdmittedTransaction, LocalSqlValue } from './types.js'

const directories: string[] = []
afterEach(async () => Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))))

describe('replicated SQL materialization', () => {
  it('executes DDL and DML in order and keeps the state across reopen', async () => {
    const { path, manifest } = await fixture()
    let materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest, checkpointEvery: 1 })
    const bootstrap = await transaction(1n, 'bootstrap', [
      sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT'),
      sqlStatement('INSERT INTO accounts (id, value) VALUES (?, ?) RETURNING id', [2n, 'two']),
      sqlStatement('SELECT id, value FROM accounts ORDER BY id'),
    ], materializer.executionManifestDigest)
    await materializer.materialize([bootstrap])
    expect(materializer.outcome(bootstrap.txId)).toMatchObject({ outcome: 'accepted', rejectionCode: null, failingStatementIndex: null })
    materializer.close()

    materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest, checkpointEvery: 1 })
    expect(rows(materializer, 'SELECT id, value FROM accounts')).toEqual([['2', 'two']])
    materializer.close()
  })

  it('rejects with the assertion code, rolls back schema and data, and flips after a late predecessor', async () => {
    const { path, manifest } = await fixture()
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest, checkpointEvery: 1 })
    const digest = materializer.executionManifestDigest
    const setup = await transaction(1n, 'setup', [
      sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO accounts VALUES (1, 10)'),
    ], digest)
    const withdraw = await transaction(5n, 'withdraw', [
      sqlStatement('CREATE TABLE audit (note TEXT)'),
      sqlStatement("SELECT chronolog_assert((SELECT balance FROM accounts WHERE id = 1) >= :amount, 'insufficient_funds')", { amount: 50n }),
      sqlStatement('UPDATE accounts SET balance = balance - 50 WHERE id = 1'),
    ], digest)
    await materializer.materialize([setup, withdraw])
    expect(materializer.outcome(withdraw.txId)).toMatchObject({
      outcome: 'rejected', rejectionCode: 'assert:insufficient_funds', failingStatementIndex: 1,
    })
    expect(rows(materializer, "SELECT count(*) FROM sqlite_schema WHERE name = 'audit'")).toEqual([['0']])

    const deposit = await transaction(3n, 'deposit', [sqlStatement('UPDATE accounts SET balance = balance + 100 WHERE id = 1')], digest)
    const revision = await materializer.materialize([setup, deposit, withdraw])
    expect(revision?.outcomeChanges.map((change) => [new TextDecoder().decode(change.txId), change.previous, change.current]))
      .toEqual([['deposit', null, 'accepted'], ['withdraw', 'rejected', 'accepted']])
    expect(rows(materializer, 'SELECT balance FROM accounts')).toEqual([['60']])
    materializer.close()
  })

  it('pins now, random, localtime and connection counters to the transaction, identically under replay', async () => {
    const program: SqlStatement[] = [
      sqlStatement('CREATE TABLE IF NOT EXISTS probes (tx TEXT PRIMARY KEY, now TEXT, local TEXT, r INTEGER, blob BLOB, last_rowid INTEGER, changed INTEGER)'),
      sqlStatement(`INSERT INTO probes VALUES (:tx, datetime('now'), datetime('now', 'localtime'), random(), randomblob(8),
        last_insert_rowid(), changes())`, { tx: 'probe' }),
    ]
    const { path: first, manifest } = await fixture()
    const incremental = await DeterministicMaterializer.open({ path: first, executionManifest: manifest, checkpointEvery: 1 })
    const digest = incremental.executionManifestDigest
    const late = await transaction(2n, 'late', [sqlStatement('CREATE TABLE marker (id INTEGER PRIMARY KEY)'), sqlStatement('INSERT INTO marker VALUES (7)')], digest)
    const probe = await transaction(1_700_000_000_000n, 'probe', program, digest)
    await incremental.materialize([probe])
    // The late transaction sorts before the probe, so the probe is replayed after it.
    await incremental.materialize([late, probe])

    const { path: second } = await fixture()
    const fresh = await DeterministicMaterializer.open({ path: second, executionManifest: manifest, checkpointEvery: 1 })
    await fresh.materialize([late, probe])

    const probeRows = rows(incremental, 'SELECT now, local, r, hex(blob), last_rowid, changed FROM probes')
    expect(probeRows).toEqual(rows(fresh, 'SELECT now, local, r, hex(blob), last_rowid, changed FROM probes'))
    expect(probeRows[0]!.slice(0, 2)).toEqual(['2023-11-14 22:13:20', '2023-11-14 22:13:20'])
    expect(probeRows[0]![4]).toBe('0')
    expect(probeRows[0]![5]).toBe('0')
    expect(incremental.databaseContentHash).toBe(fresh.databaseContentHash)
    incremental.close()
    fresh.close()
  })

  it('accepts ordinary SQLite: aggregates, windows, NOCASE grouping, JSON, triggers, views and generated columns', async () => {
    const { path, manifest } = await fixture()
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest })
    const digest = materializer.executionManifestDigest
    const tx = await transaction(1n, 'ordinary', [
      sqlStatement('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, price REAL, doubled REAL GENERATED ALWAYS AS (price * 2))'),
      sqlStatement("INSERT INTO items (name, price) VALUES ('a', 1.5), ('A', 2.25), ('b', 3)"),
      sqlStatement('CREATE TABLE totals (name TEXT, total REAL, names TEXT, rank INTEGER)'),
      sqlStatement(`INSERT INTO totals SELECT name, sum(price), group_concat(name), rank() OVER (ORDER BY sum(price) DESC)
        FROM items GROUP BY name`),
      sqlStatement('CREATE TABLE log (message TEXT)'),
      sqlStatement("CREATE TRIGGER items_log AFTER INSERT ON items BEGIN INSERT INTO log VALUES ('added ' || NEW.name); END"),
      sqlStatement("CREATE VIEW cheap AS SELECT name FROM items WHERE price < 2"),
      sqlStatement('ALTER TABLE items ADD COLUMN note TEXT'),
      sqlStatement("INSERT INTO items (name, price) VALUES (json_extract('{\"n\":\"c\"}', '$.n'), 1.0)"),
    ], digest)
    await materializer.materialize([tx])
    expect(materializer.outcome(tx.txId)?.outcome).toBe('accepted')
    expect(rows(materializer, 'SELECT count(*) FROM totals')).toEqual([['2']])
    expect(rows(materializer, 'SELECT message FROM log')).toEqual([['added c']])
    expect(rows(materializer, 'SELECT doubled FROM items WHERE name = \'c\'')).toEqual([[2]])
    materializer.close()
  })

  it('rejects denied, malformed, unbound, over-budget and constraint-violating statements', async () => {
    const { path, manifest } = await fixture({ maxVmSteps: 5_000 })
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest })
    const digest = materializer.executionManifestDigest
    const setup = await transaction(1n, 'setup', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)')], digest)
    const cases: [string, SqlStatement, string][] = [
      ['attach', sqlStatement("ATTACH DATABASE ':memory:' AS other"), 'denied'],
      ['pragma', sqlStatement('PRAGMA writable_schema = 1'), 'denied'],
      ['log-write', sqlStatement('DELETE FROM chronolog_transactions'), 'denied'],
      ['temp', sqlStatement('CREATE TEMP TABLE scratch (x)'), 'denied'],
      ['dolt', sqlStatement("SELECT dolt_commit('-m', 'x')"), 'denied'],
      ['savepoint', sqlStatement('SAVEPOINT inner_sp'), 'denied'],
      ['total-changes', sqlStatement('SELECT total_changes()'), 'denied'],
      ['syntax', sqlStatement('SELEC 1'), 'prepare'],
      ['two-statements', sqlStatement('SELECT 1; SELECT 2'), 'prepare'],
      ['unbound', { sql: 'INSERT INTO t VALUES (?, ?)', bindings: [{ parameter: { kind: 'index', index: 1 }, value: sqlValue.integer(1) }] }, 'binding'],
      ['not-null', sqlStatement('INSERT INTO t (id) VALUES (1)'), 'constraint'],
      ['steps', sqlStatement('WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT count(*) FROM n'), 'step_limit'],
    ]
    const transactions = [setup]
    for (const [index, [name, statement]] of cases.entries()) {
      transactions.push(await transaction(BigInt(index + 2), name, [sqlStatement('SELECT 1'), statement], digest))
    }
    await materializer.materialize(transactions)
    for (const [index, [name, , code]] of cases.entries()) {
      expect([name, materializer.outcome(transactions[index + 1]!.txId)]).toEqual([name, expect.objectContaining({
        outcome: 'rejected', rejectionCode: code, failingStatementIndex: 1,
      })])
    }
    materializer.close()
  })

  it('lets a transaction depend on an earlier outcome through chronolog_transactions', async () => {
    const { path, manifest } = await fixture()
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest })
    const digest = materializer.executionManifestDigest
    const first = await transaction(1n, 'first', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY)')], digest)
    const second = await transaction(2n, 'second', [
      sqlStatement("SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE tx_id = ? AND outcome = 'accepted'), 'needs_first')", [utf8('first')]),
      sqlStatement('INSERT INTO t VALUES (1)'),
    ], digest)
    const orphan = await transaction(3n, 'orphan', [
      sqlStatement("SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE tx_id = ?), 'needs_missing')", [utf8('missing')]),
    ], digest)
    await materializer.materialize([first, second, orphan])
    expect(materializer.outcome(second.txId)?.outcome).toBe('accepted')
    expect(materializer.outcome(orphan.txId)?.rejectionCode).toBe('assert:needs_missing')
    materializer.close()
  })

  it('binds REAL, empty BLOB and named parameters exactly', async () => {
    const { path, manifest } = await fixture()
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest })
    const tx = await transaction(1n, 'values', [
      sqlStatement('CREATE TABLE v (a ANY, b ANY, c ANY, d ANY) STRICT'),
      sqlStatement('INSERT INTO v VALUES (:real, :int, :blob, :text)', {
        real: sqlValue.real(1), int: 1n, blob: new Uint8Array(0), text: 'é',
      }),
    ], materializer.executionManifestDigest)
    await materializer.materialize([tx])
    expect(rows(materializer, 'SELECT typeof(a), typeof(b), typeof(c), length(c), d FROM v')).toEqual([['real', 'integer', 'blob', '0', 'é']])
    materializer.close()
  })

  it('rejects a transaction authored for another execution manifest without running it', async () => {
    const { path, manifest } = await fixture()
    const materializer = await DeterministicMaterializer.open({ path, executionManifest: manifest })
    const tx = await transaction(1n, 'foreign', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY)')], new Uint8Array(32))
    await materializer.materialize([tx])
    expect(materializer.outcome(tx.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'manifest_mismatch', failingStatementIndex: null })
    materializer.close()
  })
})

function rows(materializer: DeterministicMaterializer, sql: string): unknown[][] {
  return materializer.localSql(sql).rows.map((row) => row.map(plain))
}

function plain(value: LocalSqlValue): unknown {
  return value.kind === 'null' ? null : value.value
}

async function fixture(limits: Partial<ExecutionLimits> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-sql-materializer-'))
  directories.push(directory)
  const native = readNativeEngineInfo()
  return {
    path: join(directory, 'application.db'),
    manifest: createExecutionManifest({ profile: 'chronolog-core-portable', engine: native.descriptor, engineDigest: native.digest, limits }),
  }
}

async function transaction(
  timestamp: bigint,
  id: string,
  statements: readonly SqlStatement[],
  executionManifestDigest: Uint8Array,
): Promise<AdmittedTransaction> {
  const core: TransactionCore = {
    groupId: bytes32(1), membershipRevision: bytes32(2), validationPolicy: bytes32(3), authorId: bytes32(4),
    authorTimestampMs: timestamp, nonce: bytes32(Number(timestamp % 200n) + 10), executionManifestDigest,
    program: { version: 1, statements },
  }
  const canonicalCandidate = encodeTransactionCore(core)
  return {
    txId: utf8(id),
    authorFeedSequence: timestamp,
    candidateDigest: await transactionDigest(canonicalCandidate),
    canonicalCandidate,
    core,
  }
}
function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }

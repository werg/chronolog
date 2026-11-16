import {
  sqlStatement,
  sqlValue,
  utf8,
  type ExecutionLimits,
  type ProgramStep,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { DeterministicMaterializer } from './materializer.js'
import { MaterializerFixture, ROOT_KEY, admitted, rows } from './test-fixtures.js'
import type { AdmittedTransaction } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

describe('replicated SQL materialization', () => {
  it('executes DDL and DML in order and keeps the state across reopen', async () => {
    const { path, manifest } = await fixture()
    let materializer = await open(path, manifest, 1)
    const bootstrap = await transaction(1n, 'bootstrap', [
      sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT'),
      sqlStatement('INSERT INTO accounts (id, value) VALUES (?, ?) RETURNING id', [2n, 'two']),
      sqlStatement('SELECT id, value FROM accounts ORDER BY id'),
    ], materializer.executionManifestDigest)
    await materializer.materialize([bootstrap])
    expect(materializer.outcome(bootstrap.txId)).toMatchObject({ outcome: 'accepted', rejectionCode: null, failingStatementIndex: null })
    materializer.close()

    materializer = await open(path, manifest, 1)
    expect(rows(materializer, 'SELECT id, value FROM accounts')).toEqual([['2', 'two']])
    materializer.close()
  })

  it('rejects with the assertion code, rolls back schema and data, and flips after a late predecessor', async () => {
    const { path, manifest } = await fixture()
    const materializer = await open(path, manifest, 1)
    const digest = materializer.executionManifestDigest
    const setup = await transaction(1n, 'setup', [
      sqlStatement('CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO accounts (id, balance) VALUES (1, 10)'),
    ], digest)
    const withdraw = await transaction(5n, 'withdraw', [
      sqlStatement('CREATE TABLE audit (id INTEGER PRIMARY KEY, note TEXT)'),
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
    const program: ProgramStep[] = [
      sqlStatement(`INSERT INTO probes (tx, now, local, r, blob, last_rowid, changed) VALUES (:tx, datetime('now'), datetime('now', 'localtime'),
        random(), randomblob(8), last_insert_rowid(), changes())`, { tx: 'probe' }),
    ]
    const { path: first, manifest } = await fixture()
    const incremental = await open(first, manifest, 1)
    const digest = incremental.executionManifestDigest
    const setup = await transaction(1n, 'setup', [
      sqlStatement('CREATE TABLE probes (tx TEXT PRIMARY KEY NOT NULL, now TEXT, local TEXT, r INTEGER, blob BLOB, last_rowid INTEGER, changed INTEGER)'),
    ], digest)
    const late = await transaction(2n, 'late', [
      sqlStatement('CREATE TABLE marker (id INTEGER PRIMARY KEY)'), sqlStatement('INSERT INTO marker (id) VALUES (7)'),
    ], digest)
    const probe = await transaction(1_700_000_000_000n, 'probe', program, digest)
    await incremental.materialize([setup, probe])
    // The late transaction sorts before the probe, so the probe is replayed after it.
    await incremental.materialize([setup, late, probe])

    const { path: second } = await fixture()
    const fresh = await open(second, manifest, 1)
    await fresh.materialize([setup, late, probe])

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
    const materializer = await open(path, manifest)
    const digest = materializer.executionManifestDigest
    const tx = await transaction(1n, 'ordinary', [
      sqlStatement('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE, price REAL, doubled REAL GENERATED ALWAYS AS (price * 2))'),
      sqlStatement("INSERT INTO items (name, price) VALUES ('a', 1.5), ('A', 2.25), ('b', 3)"),
      sqlStatement('CREATE TABLE totals (name TEXT PRIMARY KEY NOT NULL, total REAL, names TEXT, rank INTEGER)'),
      sqlStatement(`INSERT INTO totals (name, total, names, rank) SELECT name, sum(price), group_concat(name), rank() OVER (ORDER BY sum(price) DESC)
        FROM items GROUP BY name`),
      sqlStatement('CREATE TABLE log (id INTEGER PRIMARY KEY, message TEXT)'),
      sqlStatement("CREATE TRIGGER items_log AFTER INSERT ON items BEGIN INSERT INTO log (message) VALUES ('added ' || NEW.name); END"),
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
    const materializer = await open(path, manifest)
    const digest = materializer.executionManifestDigest
    const setup = await transaction(1n, 'setup', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)')], digest)
    const cases: [string, ProgramStep, string][] = [
      ['attach', sqlStatement("ATTACH DATABASE ':memory:' AS other"), 'denied'],
      ['pragma', sqlStatement('PRAGMA writable_schema = 1'), 'denied'],
      ['log-write', sqlStatement('DELETE FROM chronolog_transactions'), 'denied'],
      ['temp', sqlStatement('CREATE TEMP TABLE scratch (x)'), 'denied'],
      ['dolt', sqlStatement("SELECT dolt_commit('-m', 'x')"), 'denied'],
      ['savepoint', sqlStatement('SAVEPOINT inner_sp'), 'denied'],
      ['total-changes', sqlStatement('SELECT total_changes()'), 'denied'],
      ['syntax', sqlStatement('SELEC 1'), 'prepare'],
      ['two-statements', sqlStatement('SELECT 1; SELECT 2'), 'prepare'],
      ['unbound', { sql: 'INSERT INTO t (id, v) VALUES (?, ?)', bindings: [{ parameter: { kind: 'index', index: 1 }, value: sqlValue.integer(1) }] }, 'binding'],
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
    const materializer = await open(path, manifest)
    const digest = materializer.executionManifestDigest
    const first = await transaction(1n, 'first', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY)')], digest)
    const second = await transaction(2n, 'second', [
      sqlStatement("SELECT chronolog_assert(EXISTS (SELECT 1 FROM chronolog_transactions WHERE tx_id = ? AND outcome = 'accepted'), 'needs_first')", [utf8('first')]),
      sqlStatement('INSERT INTO t (id) VALUES (1)'),
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
    const materializer = await open(path, manifest)
    const tx = await transaction(1n, 'values', [
      sqlStatement('CREATE TABLE v (id INTEGER PRIMARY KEY, a ANY, b ANY, c ANY, d ANY) STRICT'),
      sqlStatement('INSERT INTO v (a, b, c, d) VALUES (:real, :int, :blob, :text)', {
        real: sqlValue.real(1), int: 1n, blob: new Uint8Array(0), text: 'é',
      }),
    ], materializer.executionManifestDigest)
    await materializer.materialize([tx])
    expect(rows(materializer, 'SELECT typeof(a), typeof(b), typeof(c), length(c), d FROM v')).toEqual([['real', 'integer', 'blob', '0', 'é']])
    materializer.close()
  })

  it('rejects a transaction authored for another execution manifest without running it', async () => {
    const { path, manifest } = await fixture()
    const materializer = await open(path, manifest)
    const tx = await transaction(1n, 'foreign', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY)')], new Uint8Array(32))
    await materializer.materialize([tx])
    expect(materializer.outcome(tx.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'manifest_mismatch', failingStatementIndex: null })
    materializer.close()
  })
})

async function fixture(limits: Partial<ExecutionLimits> = {}) {
  const directory = await fixtures.directory()
  const { createDoltLiteExecutionManifest } = await import('./manifest.js')
  return { path: `${directory}/application.db`, manifest: createDoltLiteExecutionManifest({ limits }) }
}

function open(path: string, manifest: Awaited<ReturnType<typeof fixture>>['manifest'], checkpointEvery?: number): Promise<DeterministicMaterializer> {
  return DeterministicMaterializer.open({
    path, executionManifest: manifest, rootAdministrator: ROOT_KEY, ...(checkpointEvery === undefined ? {} : { checkpointEvery }),
  })
}

async function transaction(
  timestamp: bigint,
  id: string,
  steps: readonly ProgramStep[],
  executionManifestDigest: Uint8Array,
): Promise<AdmittedTransaction> {
  return admitted(timestamp, id, steps, executionManifestDigest)
}

import {
  sqlStatement,
  sqlValue,
  utf8,
  type ExecutionLimits,
  type ProgramStep,
} from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'
import type { MaterializedApplicationSnapshot } from '@chronolog/materializer'

import { DeterministicMaterializer } from './native.js'
import { DeterministicMaterializer as PortableMaterializer } from './materializer.js'
import { openDatabase } from './driver.js'
import { createDoltLiteMaterializationRuntime } from './runtime-adapter.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, rows } from './test-fixtures.js'
import type { MaterializerOptions, ReplayProposal } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

function snapshotData(snapshot: MaterializedApplicationSnapshot) {
  return { view: snapshot.view, revision: snapshot.revision, orderLength: snapshot.orderLength,
    finalRevision: snapshot.finalRevision, finalOrderLength: snapshot.finalOrderLength,
    transactions: Array.from({ length: snapshot.orderLength }, (_, index) => snapshot.transactionAt(index)) }
}

describe('replicated SQL materialization', () => {
  it('pins the validated history profile when the caller mutates or deletes its options', async () => {
    const path = `${await fixtures.directory()}/application.db`
    const { createDoltLiteExecutionManifest } = await import('./manifest.js')
    const options: MaterializerOptions = { path, executionManifest: createDoltLiteExecutionManifest({ profile: 'chronolog-peer-sql-v1' }), rootAdministrator: ROOT_KEY,
      openDatabase, historyProfile: 'peer-generation-v1' }
    const materializer = await PortableMaterializer.open(options)
    try {
      Object.assign(options, { historyProfile: 'chronological' })
      expect(materializer.historyProfile).toBe('peer-generation-v1')
      expect(() => materializer.captureApplication({ view: 'final' })).toThrow('FINALITY_UNSUPPORTED')
      Reflect.deleteProperty(options, 'historyProfile')
      expect(createDoltLiteMaterializationRuntime(materializer).historyProfile).toBe('peer-generation-v1')
      expect(() => materializer.captureRead({ view: 'final' })).toThrow('FINALITY_UNSUPPORTED')
    } finally { materializer.close() }
  })

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
    const runtime = createDoltLiteMaterializationRuntime(materializer)
    const held = runtime.queries.captureRead!({ view: 'local' })
    const before = runtime.queries.captureApplication({ view: 'local' })
    expect(snapshotData(held)).toEqual(snapshotData(before))
    expect(snapshotData(before).transactions).toEqual([
      { txId: setup.txId, canonicalCandidate: setup.canonicalCandidate, outcome: 'accepted', rejectionCode: null, failingStatementIndex: null },
      { txId: withdraw.txId, canonicalCandidate: withdraw.canonicalCandidate,
        outcome: 'rejected', rejectionCode: 'assert:insufficient_funds', failingStatementIndex: 1 },
    ])
    expect(runtime.queries.captureApplication().transactionAt(0)).toBeNull()
    const deposit = await transaction(3n, 'deposit', [sqlStatement('UPDATE accounts SET balance = balance + 100 WHERE id = 1')], digest)
    try {
      const revision = await materializer.materialize([setup, deposit, withdraw])
      expect(revision?.outcomeChanges.map((change) => [new TextDecoder().decode(change.txId), change.previous, change.current]))
        .toEqual([['deposit', null, 'accepted'], ['withdraw', 'rejected', 'accepted']])
      expect(rows(materializer, 'SELECT balance FROM accounts')).toEqual([['60']])
      expect(snapshotData(held)).toEqual(snapshotData(before))
      expect(held.query('SELECT balance FROM accounts')).toMatchObject({
        revision: before.revision, orderLength: before.orderLength, rows: [[{ kind: 'integer', value: '10' }]],
      })
      const detached = runtime.queries.captureApplication({ view: 'local' })
      expect(snapshotData(detached).transactions).toEqual([setup, deposit, withdraw].map(entry => ({
        txId: entry.txId, canonicalCandidate: entry.canonicalCandidate, outcome: 'accepted', rejectionCode: null, failingStatementIndex: null,
      })))
      const entry = detached.transactionAt(0)!
      entry.txId.fill(0)
      entry.canonicalCandidate.fill(0)
      expect(detached.transactionAt(0))
        .toEqual({ txId: setup.txId, canonicalCandidate: setup.canonicalCandidate, outcome: 'accepted', rejectionCode: null, failingStatementIndex: null })
      await materializer.publishFinal(3)
      expect(snapshotData(held)).toEqual(snapshotData(before))
    } finally { held.release() }
    const final = runtime.queries.captureApplication()
    expect(final).toMatchObject({ view: 'final', revision: 1n, orderLength: 3, finalRevision: 1n, finalOrderLength: 3 })
    materializer.close()
    const reopened = await open(path, manifest, 1)
    try { expect(snapshotData(reopened.captureApplication())).toEqual(snapshotData(final)) } finally { reopened.close() }
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

  it('blocks an unavailable execution manifest without inventing a SQL rejection', async () => {
    const { path, manifest } = await fixture()
    const materializer = await open(path, manifest)
    const tx = await transaction(1n, 'foreign', [sqlStatement('CREATE TABLE t (id INTEGER PRIMARY KEY)')], new Uint8Array(32))
    await expect(materializer.materialize([tx])).rejects.toThrow('MATERIALIZER_EXECUTION_MANIFEST_UNAVAILABLE')
    expect(materializer.outcome(tx.txId)).toBeNull()
    expect(materializer.orderLength).toBe(0)
    materializer.close()
  })

  it('rejects a provider order that contradicts the signed author timestamps', async () => {
    const { path, manifest } = await fixture()
    const materializer = await open(path, manifest)
    const digest = materializer.executionManifestDigest
    const create = await transaction(50n, 'create', [sqlStatement('CREATE TABLE ordered (id INTEGER PRIMARY KEY)')], digest)
    const insert = await transaction(1n, 'insert', [sqlStatement('INSERT INTO ordered (id) VALUES (1)')], digest)
    await expect(materializer.materialize([create, insert])).rejects.toThrow('ORDER_NOT_CHRONOLOGICAL')
    expect(materializer.orderLength).toBe(0)
    await materializer.materialize([insert, create])
    expect(materializer.outcome(insert.txId)?.outcome).toBe('rejected')
    expect(materializer.outcome(create.txId)?.outcome).toBe('accepted')
    expect(rows(materializer, 'SELECT id FROM ordered')).toEqual([])
    materializer.close()
  })

  it('rolls back and redoes provisional SQL while retaining timestamp order and the final prefix', async () => {
    const { path, manifest } = await fixture()
    let materializer = await open(path, manifest, 1)
    const digest = materializer.executionManifestDigest
    const setup = await transaction(1n, 'setup', [sqlStatement('CREATE TABLE drafts (id INTEGER PRIMARY KEY, value TEXT)')], digest)
    const first = await transaction(2n, 'first', [sqlStatement("INSERT INTO drafts (id, value) VALUES (1, 'first')")], digest)
    const second = await transaction(3n, 'second', [sqlStatement("INSERT INTO drafts (id, value) VALUES (1, 'second')")], digest)
    await materializer.materialize([setup, first, second])
    await materializer.publishFinal(1)
    expect(materializer.outcome(first.txId)?.outcome).toBe('accepted')
    expect(materializer.outcome(second.txId)?.outcome).toBe('rejected')
    const captured = materializer.captureRead({ view: 'local' })
    const removed = await materializer.materialize([setup, second])
    expect(materializer.outcome(second.txId)?.outcome).toBe('accepted')
    expect(materializer.outcome(first.txId)).toBeNull()
    expect(materializer.proposalIdAt(1)).toEqual(second.txId)
    expect(materializer.proposalIdAt(2)).toBeNull()
    expect(removed?.outcomeChanges).toContainEqual({ txId: first.txId, previous: 'accepted', current: null,
      previousRejectionCode: null, currentRejectionCode: null })
    expect(captured.query('SELECT value FROM drafts').rows).toEqual([[{ kind: 'text', value: 'first' }]])
    captured.release()
    await materializer.materialize([setup, first, second])
    expect(materializer.outcome(first.txId)?.outcome).toBe('accepted')
    expect(materializer.outcome(second.txId)?.outcome).toBe('rejected')
    await expect(materializer.materialize([setup, second, first])).rejects.toThrow('ORDER_NOT_CHRONOLOGICAL')
    await materializer.materialize([setup, second])
    await materializer.publishFinal(2)
    materializer.close()
    materializer = await open(path, manifest, 1)
    expect(materializer.finalOrderLength).toBe(2)
    expect(rows(materializer, 'SELECT value FROM drafts')).toEqual([['second']])
    await expect(materializer.materialize([setup])).rejects.toThrow('FINAL_PREFIX_CHANGED')
    await expect(materializer.materialize([setup, first, second])).rejects.toThrow('FINAL_PREFIX_CHANGED')
    materializer.close()
  })

  it('reads a real final SQL prefix, keeps tentative work local, and reopens both views', async () => {
    const { path, manifest } = await fixture()
    let materializer = await open(path, manifest, 100)
    const digest = materializer.executionManifestDigest
    const create = await transaction(1n, 'create', [sqlStatement('CREATE TABLE views (id INTEGER PRIMARY KEY)')], digest)
    const first = await transaction(2n, 'first', [sqlStatement('INSERT INTO views (id) VALUES (1)')], digest)
    const second = await transaction(3n, 'second', [sqlStatement('INSERT INTO views (id) VALUES (2)')], digest)
    await materializer.materialize([create, first, second])
    await materializer.publishFinal(2)
    expect(materializer.localSql('SELECT count(*) FROM views').rows).toEqual([[{ kind: 'integer', value: '2' }]])
    expect(materializer.localSql('SELECT count(*) FROM views', [], { view: 'final' })).toMatchObject({
      view: 'final', orderLength: 2, rows: [[{ kind: 'integer', value: '1' }]],
    })
    expect(() => materializer.localSql('DELETE FROM views', [], { view: 'final' })).toThrow()
    materializer.close()
    materializer = await open(path, manifest, 100)
    expect(materializer.finalOrderLength).toBe(2)
    expect(materializer.localSql('SELECT id FROM views ORDER BY id', [], { view: 'final' }).rows).toEqual([[{ kind: 'integer', value: '1' }]])
    const late = await transaction(0n, 'late', [sqlStatement('SELECT 1')], digest)
    await expect(materializer.materialize([late, create, first, second])).rejects.toThrow('MATERIALIZER_FINAL_PREFIX_CHANGED')
    await materializer.publishFinal(3)
    expect(materializer.localSql('SELECT count(*) FROM views', [], { view: 'final' }).rows).toEqual([[{ kind: 'integer', value: '2' }]])
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
): Promise<ReplayProposal> {
  return replayProposal(timestamp, id, steps, executionManifestDigest)
}

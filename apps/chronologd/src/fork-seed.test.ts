import { DatabaseSync } from '@dolthub/doltlite'
import { openReadOnlyDatabase, type DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import { MaterializerFixture, admitted, rows, testKey } from '@chronolog/materializer-doltlite/testing'
import { platformObjectId, platformOp, sqlStatement, type ProgramStep } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import {
  FORK_SEED_APPLIED_CODE,
  applicationTableDigests,
  buildForkSeedPlan,
  platformTableDigests,
  seedStepToProgramStep,
  type ForkSeedPlan,
  type ReadableDatabase,
} from './fork-seed.js'

const ORIGIN = { sourceGroupId: 'source', snapshotManifestSha256: '00'.repeat(32), sourceRevision: 7n }
const SOURCE_ROOT = testKey(0x40)
const FORK_ROOT = testKey(0x50)
const ALICE = testKey(0x10)
const BOB = testKey(0x20)

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

class Writer {
  #clock = 1n
  readonly transactions: Awaited<ReturnType<typeof admitted>>[] = []
  constructor(readonly materializer: DeterministicMaterializer) {}

  async submit(author: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<{ readonly outcome: string; readonly txId: Uint8Array }> {
    const transaction = await admitted(this.#clock, `tx-${this.#clock}`, steps, this.materializer.executionManifestDigest, author)
    this.#clock += 1n
    this.transactions.push(transaction)
    await this.materializer.materialize(this.transactions)
    return { outcome: this.materializer.outcome(transaction.txId)!.rejectionCode ?? 'accepted', txId: transaction.txId }
  }

  async accepted(author: Uint8Array, ...steps: readonly (ProgramStep | string)[]): Promise<Uint8Array> {
    const result = await this.submit(author, ...steps)
    expect(result.outcome).toBe('accepted')
    return result.txId
  }
}

/** A source group with owned rows, a team, a grant, an index, a view and an app trigger. */
async function sourceGroup(): Promise<string> {
  const { materializer, path } = await fixtures.open({ rootAdministrator: SOURCE_ROOT })
  const writer = new Writer(materializer)
  await writer.accepted(SOURCE_ROOT,
    'CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES nodes(id), label TEXT NOT NULL) STRICT',
    `CREATE TABLE measurements (
      node INTEGER NOT NULL REFERENCES nodes(id), at INTEGER NOT NULL, value REAL, raw BLOB, note ANY,
      doubled REAL GENERATED ALWAYS AS (value * 2) VIRTUAL,
      PRIMARY KEY (node, at)
    ) STRICT`,
    'CREATE TABLE audit (id INTEGER PRIMARY KEY, message TEXT NOT NULL) STRICT',
    'CREATE INDEX measurements_value ON measurements (value)',
    'CREATE VIEW leaf_labels AS SELECT label FROM nodes WHERE id NOT IN (SELECT parent FROM nodes WHERE parent IS NOT NULL)',
    "CREATE TRIGGER nodes_audit AFTER INSERT ON nodes BEGIN INSERT INTO audit (id, message) VALUES (NEW.id, 'node ' || NEW.label); END")
  // Children have lower ids than their parents, so primary-key order alone would violate the self-reference.
  await writer.accepted(ALICE,
    "INSERT INTO nodes (id, parent, label) VALUES (10, NULL, 'root')",
    "INSERT INTO nodes (id, parent, label) VALUES (5, 10, 'child')",
    "INSERT INTO nodes (id, parent, label) VALUES (1, 5, 'grandchild')")
  await writer.accepted(BOB,
    "INSERT INTO measurements (node, at, value, raw, note) VALUES (1, 1, 1.0, x'00ff', 1)",
    "INSERT INTO measurements (node, at, value, raw, note) VALUES (1, 2, -0.0, NULL, 1.0)",
    "INSERT INTO measurements (node, at, value, raw, note) VALUES (5, 1, 0.1, x'', 'text')")
  const team = await writer.accepted(ALICE,
    platformOp.createCollective({ governance: { insert: 'member', update: 'member', delete: 'admin' }, invitees: [BOB] }),
    platformOp.grant({ table: 'nodes', grantee: BOB, operations: ['update'], rowKey: [5n], columns: ['label'] }))
  await writer.accepted(BOB, platformOp.acceptMembership(await platformObjectId(team, 0)))
  materializer.close()
  return path
}

function readOnly<T>(path: string, operation: (database: ReadableDatabase) => T): T {
  const database = openReadOnlyDatabase(path)
  try { return operation(database) } finally { database.close() }
}

async function seed(writer: Writer, plan: ForkSeedPlan): Promise<string[]> {
  const outcomes: string[] = []
  for (const batch of plan.batches) {
    outcomes.push((await writer.submit(FORK_ROOT, ...batch.steps.map(seedStepToProgramStep))).outcome)
  }
  return outcomes
}

describe('fork seed plan', () => {
  it('recreates tables, rows, owners, teams and grants exactly, and is idempotent', async () => {
    const sourcePath = await sourceGroup()
    const plan = readOnly(sourcePath, (database) => buildForkSeedPlan(database, ORIGIN))
    expect(plan.format).toBe('chronolog-fork-seed-v5')
    const { materializer, path: forkPath } = await fixtures.open({ rootAdministrator: FORK_ROOT, forkSeeding: true })
    const writer = new Writer(materializer)
    expect(await seed(writer, plan)).toEqual(plan.batches.map(() => 'accepted'))
    // Every batch first asserts it has not been applied.
    expect(await seed(writer, plan)).toEqual(plan.batches.map(() => `assert:${FORK_SEED_APPLIED_CODE}`))
    // The plan's last batch ends seeding: the root cannot seed again, though nobody else has written yet.
    expect(plan.batches.at(-1)!.label).toBe('end seeding')
    expect((await writer.submit(FORK_ROOT, seedStepToProgramStep(plan.batches[2]!.steps[1]!))).outcome).toBe('platform:seed_closed')

    // verify-fork: application tables (with owners) and ownership state match the source.
    const sourceTables = readOnly(sourcePath, applicationTableDigests)
    expect(Object.keys(sourceTables).sort()).toEqual(['audit', 'measurements', 'nodes'])
    expect(readOnly(forkPath, applicationTableDigests)).toEqual(sourceTables)
    expect(readOnly(forkPath, platformTableDigests)).toEqual(readOnly(sourcePath, platformTableDigests))

    // The trigger is created after the rows, so the copied audit rows are not duplicated.
    expect(rows(materializer, 'SELECT typeof(value), value, typeof(note) FROM measurements ORDER BY node, at'))
      .toEqual([['real', 1, 'integer'], ['real', 0, 'real'], ['real', 0.1, 'text']])
    expect(rows(materializer, 'SELECT label FROM leaf_labels')).toEqual([['grandchild']])
    // Owners survive: Alice still owns her nodes, and Bob's grant and team membership carry over.
    await writer.accepted(BOB, "UPDATE nodes SET label = 'child (bob)' WHERE id = 5")
    expect((await writer.submit(BOB, "UPDATE nodes SET label = 'x' WHERE id = 1")).outcome).toBe('policy:nodes:update')
    await writer.accepted(ALICE, "UPDATE nodes SET label = 'grandchild (alice)' WHERE id = 1")
    materializer.close()
   }, 120_000)

  it('splits large tables into batches that fit one transaction', async () => {
    const { materializer, path } = await fixtures.open({ rootAdministrator: SOURCE_ROOT })
    const writer = new Writer(materializer)
    await writer.accepted(SOURCE_ROOT, 'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL) STRICT',
      sqlStatement("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 501) INSERT INTO t (id, v) SELECT i, 'v' || i FROM n"))
    materializer.close()
    const plan = readOnly(path, (database) => buildForkSeedPlan(database, ORIGIN))
    expect(plan.batches.map((batch) => batch.label)).toEqual(['schema: tables', 'rows: t #1', 'rows: t #2', 'rows: t #3', 'end seeding'])
    // guard + one seed_rows step of 250 rows + marker
    const rowsStep = plan.batches[1]!.steps[1]!
    expect('platform' in rowsStep && rowsStep.platform === 'seed_rows' ? rowsStep.rows.length : 0).toBe(250)
  })

  it('refuses tables without a primary key and foreign-key cycles between tables', () => {
    const noKey = new DatabaseSync(':memory:') as unknown as ReadableDatabase & { exec(sql: string): void }
    noKey.exec('CREATE TABLE t (v TEXT)')
    expect(() => buildForkSeedPlan(noKey, ORIGIN)).toThrow('FORK_SEED_PRIMARY_KEY_REQUIRED:t')
    const cycle = new DatabaseSync(':memory:') as unknown as ReadableDatabase & { exec(sql: string): void }
    cycle.exec(`
      CREATE TABLE a (id INTEGER PRIMARY KEY, b INTEGER REFERENCES b(id)) STRICT;
      CREATE TABLE b (id INTEGER PRIMARY KEY, a INTEGER REFERENCES a(id)) STRICT;
    `)
    expect(() => buildForkSeedPlan(cycle, ORIGIN)).toThrow('FORK_SEED_FOREIGN_KEY_CYCLE')
  })
})

describe('native parameter binding', () => {
  it('binds exact REALs and empty BLOBs as such', () => {
    const db = new DatabaseSync(':memory:')
    const probe = db.prepare('SELECT typeof(?), typeof(?), typeof(?), length(?)')
    probe.setReturnArrays(true)
    // A one-element Float64Array is the exact-REAL form; a plain integral number stays INTEGER.
    expect(probe.all(Float64Array.of(1), 1, new Uint8Array(0), new Uint8Array(0))).toEqual([['real', 'integer', 'blob', 0]])
  })
})

import { DatabaseSync } from '@dolthub/doltlite'
import { describe, expect, it } from 'vitest'

import { applicationTableDigests, buildForkSeedPlan, FORK_SEED_APPLIED_CODE, FORK_SEED_TABLE, type ReadableDatabase, type SeedValue } from './fork-seed.js'

interface WritableDatabase extends ReadableDatabase {
  exec(sql: string): void
  prepare(sql: string): ReturnType<ReadableDatabase['prepare']> & { run(...parameters: unknown[]): unknown }
  close(): void
}

const ORIGIN = { sourceGroupId: 'source', snapshotManifestSha256: '00'.repeat(32), sourceRevision: 7n }

function database(): WritableDatabase {
  const db = new DatabaseSync(':memory:') as unknown as WritableDatabase
  db.exec('PRAGMA foreign_keys = ON')
  return db
}

function source(): WritableDatabase {
  const db = database()
  db.exec(`
    CREATE TABLE nodes (id INTEGER PRIMARY KEY, parent INTEGER REFERENCES nodes(id), label TEXT NOT NULL) STRICT;
    CREATE TABLE measurements (
      node INTEGER NOT NULL REFERENCES nodes(id), at INTEGER NOT NULL, value REAL, raw BLOB, note ANY,
      doubled REAL GENERATED ALWAYS AS (value * 2) VIRTUAL,
      PRIMARY KEY (node, at)
    ) STRICT;
    CREATE INDEX measurements_value ON measurements (value);
    CREATE VIEW leaf_labels AS SELECT label FROM nodes WHERE id NOT IN (SELECT parent FROM nodes WHERE parent IS NOT NULL);
    CREATE TABLE audit (id INTEGER PRIMARY KEY, message TEXT NOT NULL) STRICT;
    CREATE TRIGGER nodes_audit AFTER INSERT ON nodes BEGIN INSERT INTO audit (id, message) VALUES (NEW.id, 'node ' || NEW.label); END;
  `)
  // Children are inserted with ids lower than their parents so primary-key
  // order alone would violate the self-referencing foreign key.
  db.exec(`
    INSERT INTO nodes VALUES (10, NULL, 'root');
    INSERT INTO nodes VALUES (5, 10, 'child');
    INSERT INTO nodes VALUES (1, 5, 'grandchild');
    INSERT INTO measurements (node, at, value, raw, note) VALUES (1, 1, 1.0, x'00ff', 1);
    INSERT INTO measurements (node, at, value, raw, note) VALUES (1, 2, -0.0, NULL, 1.0);
    INSERT INTO measurements (node, at, value, raw, note) VALUES (5, 1, 0.1, x'', 'text');
  `)
  return db
}

function apply(target: WritableDatabase, plan: ReturnType<typeof buildForkSeedPlan>): void {
  for (const batch of plan.batches) {
    target.exec('BEGIN')
    for (const statement of batch.statements) target.prepare(statement.sql).run(statement.bindings.map(native))
    target.exec('COMMIT')
  }
}

function native(value: SeedValue): unknown {
  switch (value.kind) {
    case 'null': return null
    case 'integer': return BigInt(value.value)
    case 'real': return Float64Array.of(value.value)
    case 'text': return value.value
    case 'blob': return Buffer.from(value.value, 'base64url')
  }
}

describe('fork seed plan', () => {
  it('recreates every application table exactly, including REAL/-0.0, blobs and self-references', () => {
    const from = source()
    const plan = buildForkSeedPlan(from, ORIGIN)
    const to = database()
    apply(to, plan)
    // The trigger is created after the rows, so the copied audit rows are not duplicated.
    const digests = applicationTableDigests(from)
    expect(Object.keys(digests).sort()).toEqual(['audit', 'measurements', 'nodes'])
    // The seed marker table is excluded, so the fork's application tables match exactly.
    expect(applicationTableDigests(to)).toEqual(digests)
    const markers = to.prepare(`SELECT count(*) FROM ${FORK_SEED_TABLE}`)
    markers.setReturnArrays?.(true)
    expect((markers.all()[0] as unknown[])[0]).toBe(plan.batches.length)
    const typed = to.prepare('SELECT typeof(value), value, typeof(note) FROM measurements ORDER BY node, at')
    typed.setReturnArrays?.(true)
    // SQLite stores -0.0 as 0.0 in a REAL column; 1 and 1.0 keep their types in ANY.
    expect(typed.all()).toEqual([['real', 1, 'integer'], ['real', 0, 'real'], ['real', 0.1, 'text']])
    const view = to.prepare('SELECT label FROM leaf_labels')
    view.setReturnArrays?.(true)
    expect(view.all()).toEqual([['grandchild']])
  })

  it('is idempotent: every batch first asserts it has not been applied', () => {
    const plan = buildForkSeedPlan(source(), ORIGIN)
    const to = database()
    apply(to, plan)
    for (const batch of plan.batches) {
      expect(() => to.prepare(batch.statements[0]!.sql).run([])).toThrow(`chronolog_assert:${FORK_SEED_APPLIED_CODE}`)
    }
  })

  it('splits large tables into batches that fit one transaction', () => {
    const db = database()
    db.exec('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL) STRICT')
    const insert = db.prepare('INSERT INTO t VALUES (?, ?)')
    for (let id = 1; id <= 501; id += 1) insert.run(id, `v${id}`)
    const plan = buildForkSeedPlan(db, ORIGIN)
    expect(plan.batches.map((batch) => batch.label)).toEqual(['schema: tables', 'rows: t #1', 'rows: t #2', 'rows: t #3'])
    // guard + 250 rows + marker
    expect(plan.batches[1]!.statements).toHaveLength(252)
  })

  it('refuses tables without a primary key and foreign-key cycles between tables', () => {
    const noKey = database()
    noKey.exec('CREATE TABLE t (v TEXT)')
    expect(() => buildForkSeedPlan(noKey, ORIGIN)).toThrow('FORK_SEED_PRIMARY_KEY_REQUIRED:t')
    const cycle = database()
    cycle.exec(`
      CREATE TABLE a (id INTEGER PRIMARY KEY, b INTEGER REFERENCES b(id)) STRICT;
      CREATE TABLE b (id INTEGER PRIMARY KEY, a INTEGER REFERENCES a(id)) STRICT;
    `)
    expect(() => buildForkSeedPlan(cycle, ORIGIN)).toThrow('FORK_SEED_FOREIGN_KEY_CYCLE')
  })
})

describe('native parameter binding', () => {
  it('binds exact REALs and empty BLOBs as such', () => {
    const db = database()
    const probe = db.prepare('SELECT typeof(?), typeof(?), typeof(?), length(?)')
    probe.setReturnArrays?.(true)
    // A one-element Float64Array is the exact-REAL form; a plain integral number stays INTEGER.
    expect(probe.all(Float64Array.of(1), 1, new Uint8Array(0), new Uint8Array(0))).toEqual([['real', 'integer', 'blob', 0]])
  })
})

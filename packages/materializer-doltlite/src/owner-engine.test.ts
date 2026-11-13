import { DatabaseSync, chronologTriggerUsesIgnore } from '@dolthub/doltlite'
import { describe, expect, it } from 'vitest'

import { PLATFORM_TABLES_SQL, PLATFORM_VIEWS_SQL } from './platform/schema.js'
import { parseRowKey, platformTriggers, rowKeyBindings, rowKeyExpression, rowKeyFilter, tableShape } from './platform/tables.js'
import { assertNativeSecurityConfiguration } from './sql-profile.js'
import type { DatabaseLike } from './types.js'

/**
 * Regression tests for the engine behaviour owner-controlled rows rely on
 * (docs/design-owner-rows.md §11, 2026-11-13 spikes), on the pinned native
 * DoltLite build with the Chronolog patch.
 */

const ALICE = new Uint8Array(32).fill(0xaa)
const BOB = new Uint8Array(32).fill(0xbb)

function database(): DatabaseLike {
  const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
  assertNativeSecurityConfiguration(db.configureSecurity())
  db.exec('PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA recursive_triggers = ON')
  return db
}

function withActor<T>(db: DatabaseLike, actor: Uint8Array | null, operation: () => T, actorId: bigint | null = null): T {
  db.setDeterministicContext(1_700_000_000_000n, 1, actor, actorId)
  try { return operation() } finally { db.clearDeterministicContext() }
}

function hexOf(value: unknown): string {
  return value instanceof Uint8Array ? Buffer.from(value).toString('hex') : String(value)
}

function errorOf(operation: () => unknown): { message: string; extended: unknown } {
  try {
    operation()
  } catch (error) {
    return { message: (error as Error).message, extended: (error as { sqliteExtendedCode?: unknown }).sqliteExtendedCode }
  }
  throw new Error('expected an error')
}

describe('native chronolog_actor()', () => {
  it('returns the signer during execution and NULL otherwise', () => {
    const db = database()
    try {
      expect(db.prepare('SELECT chronolog_actor() AS a').get()).toEqual({ a: null })
      expect(withActor(db, ALICE, () => hexOf((db.prepare('SELECT chronolog_actor() AS a').get() as { a: unknown }).a))).toBe('aa'.repeat(32))
      expect(withActor(db, null, () => db.prepare('SELECT chronolog_actor() AS a').get())).toEqual({ a: null })
      expect(db.prepare('SELECT chronolog_actor() AS a').get()).toEqual({ a: null })
    } finally {
      db.close()
    }
  })

  it('pins chronolog_actor_id() to the signer\'s principal id during execution only', () => {
    const db = database()
    try {
      expect(db.prepare('SELECT chronolog_actor_id() AS a').get()).toEqual({ a: null })
      expect(withActor(db, ALICE, () => db.prepare('SELECT chronolog_actor_id() AS a').get(), 7n)).toEqual({ a: 7 })
      expect(withActor(db, ALICE, () => db.prepare('SELECT chronolog_actor_id() AS a').get())).toEqual({ a: null })
      expect(db.prepare('SELECT chronolog_actor_id() AS a').get()).toEqual({ a: null })
      expect(() => db.setDeterministicContext(1n, 1, ALICE, 0n)).toThrow(/positive/u)
    } finally {
      db.clearDeterministicContext()
      db.close()
    }
  })

  it('works as a column DEFAULT in CREATE TABLE and in ADD COLUMN on an empty table only', () => {
    const db = database()
    try {
      withActor(db, ALICE, () => {
        db.exec('CREATE TABLE n (id INTEGER PRIMARY KEY, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()))')
        db.prepare('INSERT INTO n (id) VALUES (1)').run()
        db.exec('CREATE TABLE m (id INTEGER PRIMARY KEY)')
        db.exec('ALTER TABLE m ADD COLUMN chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id())')
        db.prepare('INSERT INTO m (id) VALUES (1)').run()
        db.exec('CREATE TABLE k (id INTEGER PRIMARY KEY); INSERT INTO k VALUES (1)')
        expect(errorOf(() => db.exec('ALTER TABLE k ADD COLUMN chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id())')).message)
          .toMatch(/non-constant default/u)
      }, 5n)
      expect(db.prepare('SELECT n.chronolog_owner AS a, m.chronolog_owner AS b FROM n, m').get()).toEqual({ a: 5, b: 5 })
    } finally {
      db.close()
    }
  })
})

describe('native chronolog_policy_violation()', () => {
  it('fails with SQLITE_CONSTRAINT_FUNCTION and the policy message', () => {
    const db = database()
    try {
      expect(errorOf(() => db.prepare("SELECT chronolog_policy_violation('notes', 'update')").get()))
        .toEqual({ message: expect.stringContaining('chronolog_policy:notes:update') as string, extended: 19 | (4 << 8) })
      expect(errorOf(() => db.prepare("SELECT chronolog_policy_violation('', 'update')").get()).message).toMatch(/arguments must be text/u)
    } finally {
      db.close()
    }
  })

  it('reports the calling trigger or view to the authorizer, so it can be restricted to platform objects', () => {
    const db = database()
    try {
      db.exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
        CREATE TRIGGER chronolog_k_t_upd BEFORE UPDATE ON t BEGIN SELECT chronolog_policy_violation('t', 'update') WHERE 0; END;
        CREATE TRIGGER app_t BEFORE UPDATE ON t BEGIN SELECT chronolog_policy_violation('t', 'update') WHERE 0; END;
        CREATE VIEW chronolog_v AS SELECT chronolog_policy_violation('v', 'select') WHERE 0`)
      const callers: (string | null)[] = []
      db.setAuthorizer((action, _arg1, arg2, _database, caller) => {
        if (action === 31 && arg2 === 'chronolog_policy_violation') callers.push(caller)
        return 0
      })
      db.prepare("UPDATE t SET v = 'x'").run()
      db.prepare('SELECT * FROM chronolog_v').all()
      db.prepare("SELECT chronolog_policy_violation('direct', 'x') WHERE 0").all()
      db.setAuthorizer(null)
      expect(callers.sort()).toEqual([null, 'app_t', 'chronolog_k_t_upd', 'chronolog_v'].sort())
    } finally {
      db.close()
    }
  })
})

describe('RAISE(IGNORE)', () => {
  it('skips the row silently when not linted', () => {
    const db = database()
    try {
      db.exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'a');
        CREATE TRIGGER t_skip BEFORE UPDATE ON t BEGIN SELECT RAISE(IGNORE); END`)
      db.prepare("UPDATE t SET v = 'b'").run()
      expect(db.prepare('SELECT v FROM t').get()).toEqual({ v: 'a' })
    } finally {
      db.close()
    }
  })

  it('is found by SQLite\'s own tokenizer, ignoring strings, comments, case and identifiers', () => {
    expect(chronologTriggerUsesIgnore('CREATE TRIGGER x BEFORE UPDATE ON t BEGIN SELECT RAISE(IGNORE); END')).toBe(true)
    expect(chronologTriggerUsesIgnore('CREATE TRIGGER x BEFORE UPDATE ON t BEGIN SELECT raise /* c */ (\n ignore -- d\n); END')).toBe(true)
    expect(chronologTriggerUsesIgnore("CREATE TRIGGER x BEFORE UPDATE ON t BEGIN SELECT 'RAISE(IGNORE)'; END")).toBe(false)
    expect(chronologTriggerUsesIgnore("CREATE TRIGGER x BEFORE UPDATE ON t BEGIN SELECT RAISE(ABORT, 'ignore'); END")).toBe(false)
    expect(chronologTriggerUsesIgnore('SELECT "raise"("ignore")')).toBe(false)
    expect(chronologTriggerUsesIgnore('-- RAISE(IGNORE)\nSELECT 1')).toBe(false)
  })
})

describe('generated platform triggers', () => {
  it('check column caps on tables wider than the compound-select limit', () => {
    const db = database()
    try {
      for (const sql of [...PLATFORM_TABLES_SQL, ...PLATFORM_VIEWS_SQL]) db.exec(sql)
      db.prepare('INSERT INTO chronolog_principals (id, key) VALUES (1, ?), (2, ?)').run(ALICE, BOB)
      const columns = Array.from({ length: 40 }, (_, index) => `c${index} TEXT`).join(', ')
      withActor(db, ALICE, () => {
        db.exec(`CREATE TABLE wide (id INTEGER PRIMARY KEY, ${columns}, chronolog_owner INTEGER NOT NULL DEFAULT (chronolog_actor_id()))`)
        for (const trigger of platformTriggers(tableShape(db, 'wide'))) db.exec(trigger.sql)
        db.prepare('INSERT INTO wide (id) VALUES (1)').run()
      }, 1n)
      db.prepare(`INSERT INTO chronolog_grants (grant_id, tbl, grantor, grantee_key, row_key, op_insert, op_update, op_delete, columns, created_tx)
        VALUES (zeroblob(32), 'wide', ?, ?, NULL, 0, 1, 0, '["c39"]', x'00')`).run(ALICE, BOB)
      withActor(db, BOB, () => {
        db.prepare("UPDATE wide SET c39 = 'ok' WHERE id = 1").run()
        expect(errorOf(() => db.prepare("UPDATE wide SET c38 = 'no' WHERE id = 1").run()).message).toContain('chronolog_policy:wide:update')
      }, 2n)
      expect(db.prepare('SELECT c38, c39 FROM wide').get()).toEqual({ c38: null, c39: 'ok' })
    } finally {
      db.close()
    }
  })

  it('leave sqlite-vec chunk tables as ordinary tables, which reconciliation must accept by name', () => {
    const db = database()
    try {
      db.exec('CREATE VIRTUAL TABLE v USING vec0(e float[2])')
      const types = Object.fromEntries((db.prepare("SELECT name, type FROM pragma_table_list WHERE schema = 'main' AND name LIKE 'v%'").all() as { name: string; type: string }[])
        .map((row) => [row.name, row.type]))
      expect(types).toMatchObject({ v: 'virtual', v_rowids: 'shadow', v_chunks: 'shadow', v_vector_chunks00: 'table' })
    } finally {
      db.close()
    }
  })
})

describe('row keys', () => {
  it('parse back to the primary-key values quote() produced', () => {
    const db = database()
    try {
      db.exec("CREATE TABLE k (a, b, c, d, PRIMARY KEY (a, b, c, d))")
      db.prepare('INSERT INTO k VALUES (?, ?, ?, ?)').run(-42n, "it's, odd", Buffer.from([0, 255]), Float64Array.of(1.5))
      const key = String((db.prepare(`SELECT ${rowKeyExpression('k', ['a', 'b', 'c', 'd'])} AS key FROM k`).get() as { key: unknown }).key)
      expect(parseRowKey(key)).toEqual([-42n, "it's, odd", Buffer.from([0, 255]), Float64Array.of(1.5)])
      expect(db.prepare(`SELECT count(*) AS n FROM k WHERE ${rowKeyFilter('k', ['a', 'b', 'c', 'd'])}`).get(...rowKeyBindings(key, ['a', 'b', 'c', 'd'])))
        .toEqual({ n: 1 })
      expect(parseRowKey('NULL,7')).toEqual([null, 7n])
      expect(() => parseRowKey("1; DROP TABLE k")).toThrow('MATERIALIZER_ROW_KEY_INVALID')
    } finally {
      db.close()
    }
  })
})

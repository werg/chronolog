import { DatabaseSync } from '@dolthub/doltlite'
import { describe, expect, it } from 'vitest'

import type {
  SqlAuthorizationOptions,
  SqlProfileError} from './sql-profile.js';
import {
  assertNativeSecurityConfiguration,
  configureSqliteLimits,
  isOperationalSqliteError,
  prepareProfiledStatement,
  withProfiledStatement,
} from './sql-profile.js'
import { executeLocalSql } from './sql-values.js'
import type { DatabaseLike } from './types.js'

function database(): DatabaseLike {
  const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
  assertNativeSecurityConfiguration(db.configureSecurity())
  db.exec('PRAGMA foreign_keys = ON')
  db.exec('PRAGMA trusted_schema = OFF')
  db.exec(`
    CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT NOT NULL);
    INSERT INTO accounts VALUES (1, 'one'), (2, 'two');
    CREATE TABLE "DoltOn" (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO "DoltOn" VALUES (1, 'ordinary application table');
    CREATE TABLE chronolog_transactions (tx_id BLOB PRIMARY KEY, outcome TEXT NOT NULL);
    CREATE TABLE chronolog_materializer_metadata (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE chronolog_checkpoints (prefix_length INTEGER PRIMARY KEY);
  `)
  configureSqliteLimits(db)
  return db
}

type Mode = 'local_read' | 'consensus' | 'platform'
const ADMIN: SqlAuthorizationOptions = { schemaAdmin: true }

function expectProfileViolation(db: DatabaseLike, sql: string, mode: Mode = 'consensus', options: SqlAuthorizationOptions = ADMIN): void {
  expect(() => prepareProfiledStatement(db, sql, mode, {}, options), sql).toThrowError(
    expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_PROFILE_VIOLATION' }),
  )
}

function expectAllowed(db: DatabaseLike, sql: string, mode: Mode = 'consensus', options: SqlAuthorizationOptions = ADMIN): void {
  expect(() => prepareProfiledStatement(db, sql, mode, {}, options), sql).not.toThrow()
}

describe('SQL authorization block-list', () => {
  it('keeps host/build catalogs out of replicated SQL while preserving local diagnostics', () => {
    const db = database()
    try {
      for (const sql of [
        "SELECT sqlite_compileoption_used('OMIT_UTF16')",
        'SELECT sqlite_compileoption_get(0)',
        'SELECT sqlite_source_id()',
        'SELECT "SQLITE_COMPILEOPTION_GET" /* resolved function name */ (0)',
        'PRAGMA compile_options',
        'PRAGMA function_list',
        'PRAGMA module_list',
        'PRAGMA pragma_list',
        'PRAGMA collation_list',
        'SELECT * FROM pragma_compile_options',
        'SELECT * FROM pragma_function_list',
        'SELECT * FROM pragma_module_list',
        'SELECT * FROM pragma_pragma_list',
        'SELECT * FROM pragma_collation_list',
      ]) {
        expectProfileViolation(db, sql)
        expectAllowed(db, sql, 'local_read')
      }
      for (const sql of [
        'SELECT * FROM dbstat', 'SELECT * FROM sqlite_dbpage', 'SELECT * FROM sqlite_stmt',
      ]) expectProfileViolation(db, sql)
      for (const sql of [
        "SELECT name FROM pragma_table_info('accounts')",
        "SELECT name FROM pragma_table_xinfo('accounts')",
        "SELECT name FROM pragma_index_list('accounts')",
        "SELECT * FROM pragma_foreign_key_list('accounts')",
        'SELECT sqlite_version()',
        "SELECT 'sqlite_compileoption_get(0)' AS text",
        'SELECT 1 AS "sqlite_compileoption_get"',
        'WITH sqlite_compileoption_get(value) AS (VALUES(1)) SELECT value FROM sqlite_compileoption_get',
      ]) expectAllowed(db, sql)
    } finally { db.close() }
  })

  it('enforces the diagnostic boundary inside application views and platform-triggered SQL', () => {
    const db = database()
    try {
      db.exec(`CREATE VIEW host_build AS SELECT sqlite_compileoption_used('OMIT_UTF16') AS value;
        CREATE TRIGGER host_trigger AFTER UPDATE ON accounts BEGIN SELECT sqlite_source_id(); END;`)
      expectProfileViolation(db, 'SELECT value FROM host_build')
      expectAllowed(db, 'SELECT value FROM host_build', 'local_read')
      expectProfileViolation(db, 'UPDATE accounts SET value = value', 'platform')
    } finally { db.close() }
  })

  it('allows ordinary SQLite in consensus, including formerly gated functions', () => {
    const db = database()
    try {
      for (const sql of [
        "UPDATE accounts SET value = lower(value) WHERE sign(id) = 1",
        'UPDATE "DoltOn" SET value = upper(value) WHERE id = 1',
        "SELECT random(), randomblob(4), datetime('now'), changes(), last_insert_rowid(), printf('%.2f', 1.5)",
        'SELECT group_concat(value), sum(id), avg(id), total(id) FROM accounts GROUP BY value COLLATE NOCASE',
        'SELECT value, row_number() OVER (ORDER BY id) FROM accounts',
        "SELECT json_group_array(value) FROM accounts",
        'SELECT tx_id, outcome FROM chronolog_transactions',
        "SELECT name FROM pragma_table_info('accounts')",
        "PRAGMA table_info('accounts')",
        'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)',
        'CREATE INDEX accounts_value ON accounts (value)',
        'CREATE VIEW names AS SELECT value FROM accounts',
        "CREATE TRIGGER accounts_touch AFTER UPDATE ON accounts BEGIN SELECT RAISE(ABORT, 'no'); END",
        'ALTER TABLE accounts ADD COLUMN extra TEXT',
        'CREATE VIRTUAL TABLE docs USING fts5(body)',
        'WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v + 1 FROM n WHERE v < 5) SELECT count(*) FROM n',
      ]) {
        try { prepareProfiledStatement(db, sql, 'consensus', {}, ADMIN) } catch (error) { throw new Error(`denied: ${sql}: ${(error as { code?: string }).code ?? String(error)}`, { cause: error }) }
      }
    } finally {
      db.close()
    }
  })

  it('allows ANALYZE, which only rebuilds sqlite_stat1 from table contents', () => {
    const db = database()
    try {
      withProfiledStatement(db, 'ANALYZE', 'consensus', (statement) => statement.run())
    } finally {
      db.close()
    }
  })

  it('denies escapes from the database and the pinned engine', () => {
    const db = database()
    try {
      for (const sql of [
        "ATTACH DATABASE ':memory:' AS other",
        'DETACH DATABASE other',
        'BEGIN',
        'COMMIT',
        'SAVEPOINT nested',
        'PRAGMA writable_schema = 1',
        'PRAGMA foreign_keys = OFF',
        'CREATE TEMP TABLE scratch (x)',
        'CREATE TEMP VIEW scratch AS SELECT 1',
        'SELECT total_changes()',
        "SELECT load_extension('x')",
        "SELECT dolt_commit('-m', 'x')",
        'SELECT * FROM dolt_log',
        'CREATE VIRTUAL TABLE pages USING dbstat',
        'DELETE FROM chronolog_transactions',
        "INSERT INTO chronolog_materializer_metadata VALUES ('a', 'b')",
        'DROP TABLE chronolog_checkpoints',
        'CREATE INDEX hijack ON chronolog_transactions (outcome)',
        'CREATE TABLE chronolog_extra (id INTEGER)',
        'ALTER TABLE chronolog_transactions ADD COLUMN x',
      ]) expectProfileViolation(db, sql)
    } finally {
      db.close()
    }
  })

  it('limits DDL to schema administrators and protects platform objects', () => {
    const db = database()
    try {
      db.exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, chronolog_owner BLOB);
        CREATE TRIGGER chronolog_k_notes_upd BEFORE UPDATE ON notes BEGIN SELECT 1; END;
        CREATE VIEW chronolog_my_owner_ids_update AS SELECT 1 AS id`)
      for (const sql of [
        'CREATE TABLE t (id INTEGER PRIMARY KEY)',
        'CREATE INDEX notes_id ON notes (id)',
        'CREATE VIEW v AS SELECT 1',
        'CREATE TRIGGER app AFTER INSERT ON notes BEGIN SELECT 1; END',
        'CREATE VIRTUAL TABLE docs USING fts5(body)',
        'ALTER TABLE notes ADD COLUMN extra TEXT',
        'DROP TABLE notes',
      ]) {
        expectProfileViolation(db, sql, 'consensus', {})
        expectAllowed(db, sql, 'consensus', ADMIN)
      }
      expectAllowed(db, 'ANALYZE', 'consensus', {})
      for (const sql of [
        'DROP TRIGGER chronolog_k_notes_upd',
        'DROP VIEW chronolog_my_owner_ids_update',
        'CREATE TRIGGER chronolog_k_x BEFORE INSERT ON notes BEGIN SELECT 1; END',
        'ALTER TABLE notes DROP COLUMN chronolog_owner',
        "SELECT chronolog_policy_violation('notes', 'update')",
        'UPDATE chronolog_transactions SET outcome = 1',
      ]) expectProfileViolation(db, sql, 'consensus', ADMIN)
      // Dropping a table takes its platform triggers with it.
      expectAllowed(db, 'DROP TABLE notes', 'consensus', ADMIN)
      // Platform code may write and create chronolog_* objects.
      expectAllowed(db, 'UPDATE chronolog_transactions SET outcome = 1', 'platform', {})
      expectAllowed(db, 'CREATE TRIGGER chronolog_k_x BEFORE INSERT ON notes BEGIN SELECT 1; END', 'platform', {})
    } finally {
      db.close()
    }
  })

  it('compiles app triggers fired by platform statements under consensus rules', () => {
    const db = database()
    try {
      db.exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, chronolog_owner BLOB);
        CREATE TRIGGER app_forge AFTER UPDATE ON notes BEGIN DELETE FROM chronolog_transactions; END;`)
      expectProfileViolation(db, 'UPDATE notes SET chronolog_owner = NULL', 'platform', {})
      db.exec('DROP TRIGGER app_forge; CREATE TRIGGER app_touch AFTER UPDATE ON notes BEGIN SELECT 1; END')
      expectAllowed(db, 'UPDATE notes SET chronolog_owner = NULL', 'platform', {})
    } finally {
      db.close()
    }
  })

  it('keeps local reads read-only while allowing ambient functions', () => {
    const db = database()
    try {
      expectAllowed(db, "SELECT datetime('now'), random(), total_changes()", 'local_read')
      expectAllowed(db, 'SELECT * FROM chronolog_transactions', 'local_read')
      for (const sql of ['DELETE FROM accounts', 'CREATE TABLE x (id)', "SELECT load_extension('x')", 'PRAGMA writable_schema = 1']) {
        expectProfileViolation(db, sql, 'local_read')
      }
    } finally {
      db.close()
    }
  })

  it('uses the native UTF-8 tail offset without slicing a JS string by bytes', () => {
    const db = database()
    try {
      expect(() => prepareProfiledStatement(db, "SELECT 'é'; -- allowed trailing trivia", 'local_read')).not.toThrow()
      expect(() => prepareProfiledStatement(db, "SELECT 'é'; DELETE FROM accounts", 'local_read')).toThrowError(
        expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_MULTIPLE_STATEMENTS' }),
      )
      expect(() => prepareProfiledStatement(db, 'SELECT 1\0; DELETE FROM accounts', 'local_read')).toThrowError(
        expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_INVALID_SOURCE' }),
      )
    } finally {
      db.close()
    }
  })
})

describe('SQL resource and error boundaries', () => {
  it('turns a deterministic VM budget into a stable profile rejection', () => {
    const db = database()
    try {
      db.exec(`
        CREATE TABLE numbers (value INTEGER PRIMARY KEY);
        WITH RECURSIVE n(v) AS (VALUES(1) UNION ALL SELECT v + 1 FROM n WHERE v < 200)
        INSERT INTO numbers SELECT v FROM n;
      `)
      expect(() => executeLocalSql(
        db,
        'SELECT sum(a.value * b.value * c.value) FROM numbers a, numbers b, numbers c',
        [],
        { maxVmSteps: 1_000, progressGranularity: 100 },
      )).toThrowError(expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_STEP_LIMIT' }))
    } finally {
      db.close()
    }
  })

  it('enforces the local result row ceiling', () => {
    const db = database()
    try {
      expect(() => executeLocalSql(db, 'SELECT * FROM accounts ORDER BY id', [], { maxResultRows: 1 }))
        .toThrowError(expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_RESULT_LIMIT' }))
    } finally {
      db.close()
    }
  })

  it('classifies local operational SQLite failures numerically', () => {
    expect(isOperationalSqliteError(Object.assign(new Error('constraint'), { sqliteCode: 19 }))).toBe(false)
    for (const sqliteCode of [5, 6, 7, 9, 10, 11, 13, 14, 26]) {
      const error = Object.assign(new Error(`sqlite ${sqliteCode}`), { sqliteCode })
      expect(isOperationalSqliteError(error)).toBe(true)
    }
  })

  it('verifies defensive mode and disabled double-quoted string literals', () => {
    const db = database()
    try {
      expect(() => prepareProfiledStatement(db, 'SELECT "not a column"', 'local_read')).toThrowError(
        expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_PREPARE_FAILED' }),
      )
      db.exec('PRAGMA writable_schema = ON')
      const row = db.prepare('PRAGMA writable_schema').get()
      expect(Array.isArray(row) ? row[0] : row?.writable_schema).toBe(0)
    } finally {
      db.close()
    }
  })
})

import { DatabaseSync } from '@dolthub/doltlite'
import { describe, expect, it } from 'vitest'

import type {
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

function expectProfileViolation(db: DatabaseLike, sql: string, mode: 'local_read' | 'consensus' = 'consensus'): void {
  expect(() => prepareProfiledStatement(db, sql, mode)).toThrowError(
    expect.objectContaining<Partial<SqlProfileError>>({ code: 'SQL_PROFILE_VIOLATION' }),
  )
}

function expectAllowed(db: DatabaseLike, sql: string, mode: 'local_read' | 'consensus' = 'consensus'): void {
  expect(() => prepareProfiledStatement(db, sql, mode)).not.toThrow()
}

describe('SQL authorization block-list', () => {
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
        try { prepareProfiledStatement(db, sql, 'consensus') } catch (error) { throw new Error(`denied: ${sql}: ${(error as { code?: string }).code ?? String(error)}`, { cause: error }) }
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

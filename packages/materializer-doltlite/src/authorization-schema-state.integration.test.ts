import { DatabaseSync } from '@dolthub/doltlite'
import { program } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { initializePlatform } from './platform/schema.js'
import { PlatformSession, shadowTables, writeProtectedTables } from './platform/session.js'
import { executeTransactionProgram } from './sql-executor.js'
import { assertNativeSecurityConfiguration } from './sql-profile.js'
import { executeLocalSql } from './sql-values.js'
import { initializeSystemLog } from './system-log.js'
import { ROOT_KEY, testKey } from './test-fixtures.js'
import type { DatabaseLike } from './types.js'

function database(): DatabaseLike {
  const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
  assertNativeSecurityConfiguration(db.configureSecurity())
  db.exec('PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA recursive_triggers = ON')
  initializeSystemLog(db)
  initializePlatform(db, ROOT_KEY, false)
  return db
}

function execute(db: DatabaseLike, ...sql: readonly string[]): void {
  executeTransactionProgram(db, program(...sql), { actor: ROOT_KEY, txId: testKey(2), authorTimestampMs: 1n, groupId: testKey(3) })
}

function schemaVersion(db: DatabaseLike): number {
  return Number((db.prepare('PRAGMA schema_version').get() as { schema_version: unknown }).schema_version)
}

describe('authorization inventories after native schema rollback', () => {
  it('authorizes current lifecycle triggers when a rejected create\'s schema cookie is reused', () => {
    const db = database()
    try {
      db.exec('BEGIN; SAVEPOINT chronolog_program')
      expect(() => execute(db,
        'CREATE TABLE rejected_table (id INTEGER PRIMARY KEY)',
        'INSERT INTO rejected_table (id) VALUES (1)',
        "SELECT chronolog_assert(0, 'reject_creation')",
      )).toThrowError(expect.objectContaining({ code: 'assert:reject_creation', statementIndex: 2 }))
      const rejectedVersion = schemaVersion(db)
      db.exec('ROLLBACK TO SAVEPOINT chronolog_program; RELEASE SAVEPOINT chronolog_program')

      // Replace the schema without consulting the inventories at the rolled-back
      // cookie. Authorization must depend on current state, not prior lookups.
      db.exec('CREATE TABLE accepted_table (id INTEGER PRIMARY KEY)')
      new PlatformSession(db, { actor: ROOT_KEY, txId: testKey(4), groupId: testKey(3), limits: {} }).reconcile()
      expect(schemaVersion(db)).toBe(rejectedVersion)
      expect(() => execute(db, 'INSERT INTO accepted_table (id) VALUES (1)')).not.toThrow()
      expect(db.prepare('SELECT id FROM accepted_table').all()).toEqual([{ id: 1 }])
      expect(db.prepare("SELECT name FROM sqlite_schema WHERE name = 'rejected_table'").all()).toEqual([])
    } finally {
      db.close()
    }
  })

  it('still denies direct writes to a virtual table when a rejected create\'s schema cookie is reused', () => {
    const db = database()
    try {
      db.exec('BEGIN; SAVEPOINT chronolog_program')
      expect(() => execute(db,
        'CREATE VIRTUAL TABLE rejected_fts USING fts5(body)',
        "SELECT chronolog_assert(0, 'reject_creation')",
      )).toThrowError(expect.objectContaining({ code: 'assert:reject_creation', statementIndex: 1 }))
      const rejectedVersion = schemaVersion(db)
      db.exec('ROLLBACK TO SAVEPOINT chronolog_program; RELEASE SAVEPOINT chronolog_program')
      db.exec('CREATE VIRTUAL TABLE accepted_fts USING fts5(body)')
      expect(schemaVersion(db)).toBe(rejectedVersion)
      expect(() => execute(db, "INSERT INTO accepted_fts (rowid, body) VALUES (1, 'unauthorized')"))
        .toThrowError(expect.objectContaining({ code: 'denied', statementIndex: 0 }))
      expect(db.prepare('SELECT rowid FROM accepted_fts').all()).toEqual([])
      expect(writeProtectedTables(db)).toEqual(new Set(['accepted_fts']))
    } finally {
      db.close()
    }
  })

  it('reads current virtual-table shadow names when a schema cookie is reused', () => {
    const db = database()
    try {
      db.exec('BEGIN; SAVEPOINT chronolog_program; CREATE VIRTUAL TABLE rejected_fts USING fts5(body)')
      const rejectedVersion = schemaVersion(db)
      expect(shadowTables(db).has('rejected_fts_data')).toBe(true)
      db.exec('ROLLBACK TO SAVEPOINT chronolog_program; RELEASE SAVEPOINT chronolog_program')
      db.exec("CREATE VIRTUAL TABLE accepted_fts USING fts5(body); INSERT INTO accepted_fts (body) VALUES ('needle')")
      expect(schemaVersion(db)).toBe(rejectedVersion)
      const actual = db.prepare("SELECT name FROM pragma_table_list WHERE schema = 'main' AND type = 'shadow'").all()
        .map((row) => String((row as { name: unknown }).name).toLowerCase())
      expect(shadowTables(db)).toEqual(new Set(actual))
      expect(executeLocalSql(db, "SELECT rowid FROM accepted_fts WHERE accepted_fts MATCH 'needle'").rows)
        .toEqual([[{ kind: 'integer', value: '1' }]])
      expect(() => executeLocalSql(db, 'DELETE FROM accepted_fts_data')).toThrow()
    } finally {
      db.close()
    }
  })
})

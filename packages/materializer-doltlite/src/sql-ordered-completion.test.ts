import { DatabaseSync } from '@dolthub/doltlite'
import { compileSqlStatement, SqlCompilerError } from '@chronolog/compiler-sqlite'
import { encodeCanonicalSqlResult, type SqlResultMode } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { executeSqlObservation } from './sql-executor.js'
import { assertNativeSecurityConfiguration, configureSqliteLimits } from './sql-profile.js'
import type { DatabaseLike } from './types.js'

// The same visible rows, all tied on `k`. `v` has no affinity, so INTEGER
// and REAL values (including -0.0) are stored as written; `s` is NOCASE.
const ROWS = [
  "(1, 1, 'a')",
  "(1, 1.0, 'A')",
  "(1, 2, 'b')",
  "(1, 2.0, 'B')",
  "(1, 0, 'c')",
  "(1, 0.0, 'C')",
]

/**
 * Two replicas that agree on every visible row but inserted them in
 * opposite orders, so hidden rowids and therefore scan order differ.
 */
function replicas(rows: readonly string[] = ROWS): [DatabaseLike, DatabaseLike] {
  return [rows, [...rows].reverse()].map((order) => {
    const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
    assertNativeSecurityConfiguration(db.configureSecurity())
    db.exec('CREATE TABLE t (k INTEGER NOT NULL, v BLOB, s TEXT COLLATE NOCASE)')
    db.exec('CREATE TABLE u (k INTEGER NOT NULL, v BLOB, s TEXT COLLATE NOCASE)')
    for (const row of order) db.exec(`INSERT INTO t (k, v, s) VALUES ${row}; INSERT INTO u (k, v, s) VALUES ${row}`)
    configureSqliteLimits(db)
    return db
  }) as [DatabaseLike, DatabaseLike]
}

function raw(db: DatabaseLike, sql: string): string {
  const statement = db.prepare(sql)
  statement.setReturnArrays?.(true)
  statement.setReadBigInts?.(true)
  return JSON.stringify(statement.all(), (_key, value: unknown) =>
    typeof value === 'bigint' ? `${value}n` : Object.is(value, -0) ? '-0.0' : value)
}

function observe(db: DatabaseLike, sql: string, mode: SqlResultMode = 'ordered'): Uint8Array {
  return encodeCanonicalSqlResult(executeSqlObservation(db, { sql, bindings: [] }, mode, 1_000, 1 << 20))
}

function withReplicas(test: (left: DatabaseLike, right: DatabaseLike) => void, rows?: readonly string[]): void {
  const [left, right] = replicas(rows)
  try { test(left, right) } finally { left.close(); right.close() }
}

describe('ordered result tie completion', () => {
  it('shows that BINARY-only completion leaves INTEGER/REAL ties in scan order', () => {
    withReplicas((left, right) => {
      const binaryOnly = 'SELECT v FROM t ORDER BY k, 1 COLLATE BINARY'
      expect(raw(left, binaryOnly)).not.toBe(raw(right, binaryOnly))
      const limited = 'SELECT v FROM t ORDER BY k, 1 COLLATE BINARY LIMIT 1'
      expect(raw(left, limited)).toBe('[["0n"]]')
      expect(raw(right, limited)).toBe('[[0]]')
    })
  })

  it.each([
    'SELECT v FROM t ORDER BY k',
    'SELECT v FROM t ORDER BY k LIMIT 3',
    'SELECT v FROM t ORDER BY k LIMIT 1 OFFSET 2',
    'SELECT v, s FROM t ORDER BY s COLLATE NOCASE',
    'SELECT k, v + 0 AS w FROM t ORDER BY k',
    'SELECT * FROM t ORDER BY k',
    'SELECT * FROM t AS a ORDER BY k LIMIT 4',
    'SELECT a.* FROM t AS a JOIN u AS b ON a.k = b.k AND a.v = b.v AND a.s = b.s ORDER BY a.k',
    'SELECT v FROM t UNION ALL SELECT v FROM u ORDER BY 1',
    'SELECT v AS x FROM t UNION ALL VALUES (1.0) UNION ALL SELECT v FROM u ORDER BY x LIMIT 5',
  ])('produces identical ordered results for %s', (sql) => {
    withReplicas((left, right) => {
      expect(Buffer.from(observe(left, sql)).toString('hex')).toBe(Buffer.from(observe(right, sql)).toString('hex'))
    })
  })

  it('returns INTEGER before REAL within a BINARY tie and strips hidden compound columns', () => {
    withReplicas((left) => {
      const ordered = executeSqlObservation(left, {
        sql: 'SELECT v AS x FROM t UNION ALL SELECT v FROM u ORDER BY x LIMIT 4', bindings: [],
      }, 'ordered', 1_000, 1 << 20)
      expect(ordered.columns.map((column) => new TextDecoder().decode(column.nameUtf8))).toEqual(['x'])
      expect(ordered.rows.map((row) => row[0]!.kind)).toEqual(['integer', 'integer', 'real', 'real'])
    })
  })

  it('neutralizes the unobservable sign of REAL zero by normalizing results', () => {
    withReplicas((left, right) => {
      for (const probe of ["quote(v)", 'hex(v)', 'CAST(v AS TEXT)', "printf('%!.17g', v)", 'json_quote(v)', '1 / v']) {
        expect(raw(left, `SELECT ${probe} FROM t WHERE k = 2 ORDER BY v`))
          .toBe(raw(left, `SELECT ${probe} FROM t WHERE k = 2 ORDER BY v DESC`))
      }
      const sql = 'SELECT v FROM t WHERE k = 2 ORDER BY k'
      // Raw SQLite rows still differ in scan order; canonical results do not.
      expect(raw(left, sql)).not.toBe(raw(right, sql))
      expect(Buffer.from(observe(left, sql))).toEqual(Buffer.from(observe(right, sql)))
    }, ['(2, -0.0, NULL)', '(2, 0.0, NULL)'])
  })
})

describe('grouped and ordered aggregates over non-injective comparisons', () => {
  it.each([
    'SELECT v, count(*) FROM t GROUP BY v',
    'SELECT s, count(*) FROM t GROUP BY s',
    'SELECT CAST(s AS TEXT), count(*) FROM t GROUP BY CAST(s AS TEXT)',
    'SELECT group_concat(v ORDER BY v) FROM t',
    'SELECT group_concat(s ORDER BY s) FROM t',
    'SELECT group_concat(CAST(s AS TEXT) ORDER BY CAST(s AS TEXT)) FROM t',
    'SELECT group_concat(v ORDER BY v COLLATE BINARY) FROM t',
  ])('confirms %s depends on scan order and is rejected by the compiler', (sql) => {
    withReplicas((left, right) => {
      expect(raw(left, sql)).not.toBe(raw(right, sql))
    })
    let code: string | null = null
    try { compileSqlStatement({ sql, bindings: [] }, 'precondition') } catch (error) {
      code = error instanceof SqlCompilerError ? error.code : null
    }
    expect(['SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED', 'SQL_FUNCTION_TEMPORARILY_GATED']).toContain(code)
  })

  it.each([
    'SELECT group_concat(v ORDER BY v COLLATE BINARY, typeof(v)) FROM t',
    'SELECT group_concat(CAST(s AS TEXT) ORDER BY CAST(s AS TEXT) COLLATE BINARY) FROM t',
    'SELECT CAST(v AS INTEGER), count(*) FROM t GROUP BY CAST(v AS INTEGER)',
    'SELECT CAST(s AS TEXT) COLLATE BINARY, count(*) FROM t GROUP BY CAST(s AS TEXT) COLLATE BINARY',
    'SELECT typeof(v), count(*) FROM t GROUP BY typeof(v)',
  ])('admits %s and agrees across replicas', (sql) => {
    withReplicas((left, right) => {
      expect(Buffer.from(observe(left, sql, 'multiset'))).toEqual(Buffer.from(observe(right, sql, 'multiset')))
    })
  })

  it('ignores the sign of REAL zero in ordered group_concat text', () => {
    withReplicas((left, right) => {
      const sql = 'SELECT group_concat(v ORDER BY v COLLATE BINARY, typeof(v)) FROM t'
      expect(raw(left, sql)).toBe('[["0.0,0.0"]]')
      expect(Buffer.from(observe(left, sql, 'multiset'))).toEqual(Buffer.from(observe(right, sql, 'multiset')))
    }, ['(2, -0.0, NULL)', '(2, 0.0, NULL)'])
  })
})

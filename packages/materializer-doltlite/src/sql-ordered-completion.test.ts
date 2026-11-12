import { DatabaseSync } from '@dolthub/doltlite'
import { SqlCompilerError } from '@chronolog/compiler-sqlite'
import { encodeCanonicalSqlResult, type SqlResultMode } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import {
  compileSqlStatementForDatabase,
  type DeterministicSqlRejection,
  executeSqlBodyStatement,
  executeSqlObservation,
} from './sql-executor.js'
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
  return schemaReplicas([
    'CREATE TABLE t (k INTEGER NOT NULL, v BLOB, s TEXT COLLATE NOCASE)',
    'CREATE TABLE u (k INTEGER NOT NULL, v BLOB, s TEXT COLLATE NOCASE)',
  ], rows.map((row) => `INSERT INTO t (k, v, s) VALUES ${row}; INSERT INTO u (k, v, s) VALUES ${row}`))
}

function schemaReplicas(schema: readonly string[], inserts: readonly string[]): [DatabaseLike, DatabaseLike] {
  return [inserts, [...inserts].reverse()].map((order) => {
    const db = new DatabaseSync(':memory:') as unknown as DatabaseLike
    assertNativeSecurityConfiguration(db.configureSecurity())
    for (const statement of schema) db.exec(statement)
    for (const insert of order) db.exec(insert)
    configureSqliteLimits(db)
    return db
  }) as [DatabaseLike, DatabaseLike]
}

function compilerCode(db: DatabaseLike, sql: string): string | null {
  try { compileSqlStatementForDatabase(db, { sql, bindings: [] }, 'precondition') } catch (error) {
    return error instanceof SqlCompilerError ? error.code : String(error)
  }
  return null
}

function hex(bytes: Uint8Array): string { return Buffer.from(bytes).toString('hex') }

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
  using(replicas(rows), test)
}

function using(dbs: [DatabaseLike, DatabaseLike], test: (left: DatabaseLike, right: DatabaseLike) => void): void {
  const [left, right] = dbs
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
    // A group key or bare column outside an aggregate exposes the representative.
    'SELECT s, count(*) FROM t',
    "SELECT count(*) FROM t GROUP BY s HAVING s = 'a' COLLATE BINARY",
    // CAST inherits NOCASE, which the compound applies to every arm.
    'SELECT CAST(s AS INTEGER) FROM t UNION SELECT CAST(s AS TEXT) COLLATE BINARY FROM u',
    'SELECT 1 UNION ALL SELECT DISTINCT s FROM t',
  ])('confirms %s depends on scan order and is rejected against the schema', (sql) => {
    withReplicas((left, right) => {
      expect(raw(left, sql)).not.toBe(raw(right, sql))
      for (const db of [left, right]) {
        expect(['SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED', 'SQL_FUNCTION_TEMPORARILY_GATED']).toContain(compilerCode(db, sql))
      }
    })
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

  it('confirms ORDER BY over an unstable group key depends on scan order and is rejected', () => {
    withReplicas((left, right) => {
      const sql = 'SELECT count(*) FROM t GROUP BY s ORDER BY s COLLATE BINARY'
      expect(raw(left, sql)).not.toBe(raw(right, sql))
      expect(compilerCode(left, sql)).toBe('SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED')
    }, ["(1, 1, 'a')", "(1, 1, 'A')", "(1, 1, 'B')", "(1, 1, 'B')", "(1, 1, 'b')"])
  })
})

describe('schema-proven representatives', () => {
  // Visible rows agree; hidden rowids (scan order) differ. `n`, `t`, `b`
  // are STRICT; `name` has TEXT affinity and BINARY collation, so 1 and 1.0
  // are stored as distinct text; `pk.k` is a rowid alias.
  const SCHEMA = [
    'CREATE TABLE st (n INT, t TEXT, b BLOB) STRICT',
    'CREATE TABLE lt (name VARCHAR(10), tag TEXT COLLATE NOCASE, raw)',
    'CREATE TABLE pk (k INTEGER PRIMARY KEY, v TEXT)',
  ]
  const INSERTS = [
    "INSERT INTO st (n, t, b) VALUES (1, 'a', x'01')",
    "INSERT INTO st (n, t, b) VALUES (1.0, 'a', x'01')",
    "INSERT INTO st (n, t, b) VALUES (2, 'A', x'02')",
    "INSERT INTO st (n, t, b) VALUES (2, 'b', x'02')",
    "INSERT INTO lt (name, tag, raw) VALUES (1, 'a', 1)",
    "INSERT INTO lt (name, tag, raw) VALUES (1.0, 'A', 1.0)",
    "INSERT INTO lt (name, tag, raw) VALUES ('x', 'b', 2)",
    "INSERT INTO lt (name, tag, raw) VALUES (x'31', 'B', 2.0)",
    "INSERT INTO lt (name, tag, raw) VALUES ('x', 'b', 2)",
    "INSERT INTO pk (k, v) VALUES (1, 'one')",
    "INSERT INTO pk (k, v) VALUES (2.0, 'two')",
  ]
  const withSchemaReplicas = (test: (left: DatabaseLike, right: DatabaseLike) => void): void =>
    using(schemaReplicas(SCHEMA, INSERTS), test)

  it('stores only text or blob in a TEXT-affinity column, including ALTER TABLE defaults', () => {
    withSchemaReplicas((left) => {
      left.exec('ALTER TABLE lt ADD COLUMN extra TEXT DEFAULT 1.0')
      expect(raw(left, 'SELECT DISTINCT typeof(name), typeof(extra), extra FROM lt ORDER BY 1')).toBe(
        '[["blob","text","1.0"],["text","text","1.0"]]',
      )
    })
  })

  it.each([
    'SELECT n, count(*) FROM st GROUP BY n',
    'SELECT t, count(*) FROM st GROUP BY t',
    'SELECT b, count(*) FROM st GROUP BY b',
    'SELECT name, count(*) FROM lt GROUP BY name',
    'SELECT k, count(*) FROM pk GROUP BY k',
    'SELECT st.n, count(*) AS c FROM st JOIN pk ON pk.k = st.n GROUP BY st.n HAVING c > 0',
    'SELECT DISTINCT name FROM lt',
    'SELECT DISTINCT t, n FROM st',
    'SELECT min(name), max(name), min(n), max(t) FROM st, lt',
    'SELECT group_concat(name ORDER BY name) FROM lt',
    'SELECT group_concat(t ORDER BY t) FROM st',
    'SELECT group_concat(tag ORDER BY tag COLLATE BINARY) FROM lt',
    'SELECT n FROM st UNION SELECT k FROM pk',
    'SELECT name FROM lt INTERSECT SELECT t FROM st',
  ])('admits %s and agrees across replicas', (sql) => {
    withSchemaReplicas((left, right) => {
      expect(compilerCode(left, sql)).toBeNull()
      expect(hex(observe(left, sql, 'multiset'))).toBe(hex(observe(right, sql, 'multiset')))
    })
  })

  it.each([
    'SELECT tag, count(*) FROM lt GROUP BY tag',
    'SELECT raw, count(*) FROM lt GROUP BY raw',
    'SELECT group_concat(tag ORDER BY tag) FROM lt',
    'SELECT group_concat(raw ORDER BY raw) FROM lt',
  ])('shows the unproven neighbour %s diverges and stays gated', (sql) => {
    withSchemaReplicas((left, right) => {
      expect(raw(left, sql)).not.toBe(raw(right, sql))
      expect(compilerCode(left, sql)).not.toBeNull()
    })
  })

  it('completes SELECT * over a join from the catalog', () => {
    withSchemaReplicas((left, right) => {
      // Rows tie on the ORDER BY key and differ only in raw's storage class.
      for (const sql of [
        'SELECT * FROM lt JOIN st ON st.n = 1 ORDER BY lt.tag, st.n',
        'SELECT st.*, lt.* FROM st, lt ORDER BY st.n, lt.tag LIMIT 7',
        'SELECT * FROM pk, lt ORDER BY pk.k, lt.tag',
      ]) {
        expect(raw(left, sql)).not.toBe(raw(right, sql))
        expect(compilerCode(left, sql)).toBeNull()
        expect(hex(observe(left, sql))).toBe(hex(observe(right, sql)))
      }
      expect(compilerCode(left, 'SELECT * FROM lt JOIN st USING (b) ORDER BY 1'))
        .toBe('SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED')
    })
  })

  it('compiles each statement against the schema left by earlier statements', () => {
    withSchemaReplicas((left) => {
      const run = (sql: string, index: number) =>
        executeSqlBodyStatement(left, { sql, bindings: [] }, index, 1_000, 1 << 20)
      const grouped = 'SELECT n, count(*) FROM st GROUP BY n'
      expect(run(grouped, 0).result?.rows).toHaveLength(2)
      run('DROP TABLE st', 1)
      run('CREATE TABLE st (n ANY) STRICT', 2)
      expect(() => run(grouped, 3)).toThrowError(expect.objectContaining<Partial<DeterministicSqlRejection>>({
        code: 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED', statementIndex: 3,
      }))
      run('ALTER TABLE st RENAME TO st_any', 4)
      run('CREATE TABLE st (n INTEGER PRIMARY KEY)', 5)
      expect(run(grouped, 6).result?.rows).toEqual([])
    })
  })
})

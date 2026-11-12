import { describe, expect, it } from 'vitest'

import {
  compileSqlProgram,
  compileSqlStatement,
  completeOrderedResultSql,
  orderedSqlBindingValues,
  type SqlCatalog,
  type SqlCompilerError,
} from './sql-compiler.js'
import { createCoreExecutionManifest } from './manifest.js'

function catalog(tables: Record<string, string>, views: Record<string, string> = {}): SqlCatalog {
  const objects = new Map<string, { type: 'table' | 'view'; sql: string }>([
    ...Object.entries(tables).map(([name, sql]) => [name.toLowerCase(), { type: 'table' as const, sql }] as const),
    ...Object.entries(views).map(([name, sql]) => [name.toLowerCase(), { type: 'view' as const, sql }] as const),
  ])
  return { lookup: (name) => objects.get(name.toLowerCase()) ?? null }
}

/** Untyped columns: nothing is provable from this schema. */
const LOOSE = catalog({
  accounts: 'CREATE TABLE accounts (id, value)',
  archived_accounts: 'CREATE TABLE archived_accounts (id, value)',
  source: 'CREATE TABLE source (id, value)',
})

const PROVEN = catalog({
  s: 'CREATE TABLE s (id INTEGER PRIMARY KEY, n INT, t TEXT, b BLOB, r REAL, a ANY, ci TEXT COLLATE NOCASE, ' +
    'g INT AS (n + 1), ni INTEGER COLLATE NOCASE) STRICT',
  l: 'CREATE TABLE "l" (k INTEGER PRIMARY KEY, name VARCHAR(20), tag TEXT COLLATE NOCASE, num INTEGER, raw, ' +
    'real_value REAL, kd INT)',
  d: 'CREATE TABLE d (k INTEGER PRIMARY KEY DESC, v TEXT)',
  w: 'CREATE TABLE w (k INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID',
  p: 'CREATE TABLE p (k INTEGER, v TEXT, PRIMARY KEY (k))',
}, { v: 'CREATE VIEW v AS SELECT n FROM s' })

function compileCode(sql: string, sqlCatalog?: SqlCatalog): string {
  try {
    compileSqlStatement({ sql, bindings: [] }, 'body', sqlCatalog === undefined ? {} : { catalog: sqlCatalog })
    return 'accepted'
  } catch (error) {
    return (error as SqlCompilerError).code
  }
}

describe('deterministic SQL compiler', () => {
  it('does not let the core manifest advertise unavailable extension profiles', () => {
    const engineDigest = new Uint8Array(32)
    expect(createCoreExecutionManifest({ profile: 'test', engineDigest }).features).toEqual({
      decimal: true, json: true, vector: true, fts: false, spatial: false, wasm: false,
    })
    expect(() => createCoreExecutionManifest({
      profile: 'test', engineDigest, features: { fts: true },
    })).toThrowError(expect.objectContaining({ code: 'EXECUTION_FEATURE_UNAVAILABLE' }))
  })

  it('preserves exact source and SQLite parameter numbering', () => {
    const source = {
      sql: 'UPDATE accounts SET value = ?2 WHERE id = :id AND shard = ?',
      bindings: [
        { parameter: { kind: 'index' as const, index: 2 }, value: { kind: 'text' as const, utf8: new TextEncoder().encode('next') } },
        { parameter: { kind: 'name' as const, name: ':id' }, value: { kind: 'int64' as const, value: 7n } },
        { parameter: { kind: 'index' as const, index: 4 }, value: { kind: 'int64' as const, value: 3n } },
      ],
    }
    const compiled = compileSqlStatement(source, 'body')
    expect(compiled.source.sql).toBe(source.sql)
    expect(compiled.maximumParameterIndex).toBe(4)
    expect(orderedSqlBindingValues(compiled).map((value) => value.kind)).toEqual(['null', 'text', 'int64', 'int64'])
  })

  it('accepts sequential DDL, DML, SELECT, and RETURNING statement classes', () => {
    const compiled = compileSqlProgram({
      version: 1,
      preconditions: [{ id: 1, query: { sql: 'SELECT 1', bindings: [] }, resultMode: 'scalar', expectation: { kind: 'assert_true' } }],
      body: [
        { sql: 'CREATE TABLE accounts (id INTEGER PRIMARY KEY, value TEXT) STRICT', bindings: [] },
        { sql: 'INSERT INTO accounts VALUES (1, \'one\') RETURNING id', bindings: [] },
        { sql: 'SELECT id FROM accounts ORDER BY id', bindings: [] },
      ],
    })
    expect(compiled.body.map((item) => item.statementClass)).toEqual(['schema', 'insert', 'read'])
    expect(compiled.body[1]?.resultMode).toBe('multiset')
    expect(compiled.body[2]?.resultMode).toBe('ordered')
  })

  it('admits row-choice forms only with a syntactic at-most-one-row proof', () => {
    const statements = [
      'SELECT (SELECT 1 WHERE 1) LIMIT 1',
      "INSERT INTO accounts (id, value) SELECT 1, 'one' WHERE 1",
      "CREATE TABLE singleton_copy AS SELECT 1 AS id, 'one' AS value",
      "UPDATE accounts SET value = source.value FROM (SELECT 'next' AS value) AS source",
      "UPDATE OR ABORT accounts SET value = 'next' WHERE id = 1",
    ]
    expect(statements.map((sql) => compileSqlStatement({ sql, bindings: [] }, 'body').statementClass)).toEqual([
      'read', 'insert', 'schema', 'update', 'update',
    ])
  })

  it('admits representative- and peer-stable aggregate, compound, and window shapes', () => {
    const statements = [
      'SELECT DISTINCT typeof(value) FROM accounts',
      'SELECT typeof(value), count(*) FROM accounts GROUP BY typeof(value)',
      'SELECT min(typeof(value)), max(typeof(value)) FROM accounts',
      'SELECT typeof(value) FROM accounts UNION SELECT typeof(value) FROM archived_accounts',
      'SELECT rank() OVER (ORDER BY value), value FROM accounts',
      'SELECT dense_rank() OVER (ORDER BY value), value FROM accounts',
      'SELECT group_concat(value ORDER BY value COLLATE BINARY, typeof(value)) FROM accounts',
      "SELECT group_concat(CAST(value AS TEXT), ',' ORDER BY CAST(value AS TEXT) COLLATE BINARY) FROM accounts",
      'SELECT group_concat(typeof(value) ORDER BY typeof(value)) FROM accounts',
      'SELECT CAST(value AS INTEGER), count(*) FROM accounts GROUP BY CAST(value AS INTEGER)',
      'SELECT CAST(value AS TEXT) COLLATE BINARY, count(*) FROM accounts GROUP BY CAST(value AS TEXT) COLLATE BINARY',
      'SELECT DISTINCT CAST(value AS BLOB) FROM accounts',
    ]
    expect(statements.map((sql) => compileSqlStatement({ sql, bindings: [] }, 'body').statementClass)).toEqual(
      Array.from({ length: statements.length }, () => 'read'),
    )
  })

  it('adds binary and storage-class result-column ties after authored outer ordering', () => {
    const compiled = compileSqlStatement({
      sql: 'SELECT id, name FROM accounts ORDER BY name COLLATE NOCASE DESC NULLS LAST LIMIT 5',
      bindings: [],
    }, 'precondition')
    expect(completeOrderedResultSql(compiled, ['id', 'name'])).toEqual({
      sql: 'SELECT id, name FROM accounts ORDER BY name COLLATE NOCASE DESC NULLS LAST, 1 COLLATE BINARY, typeof(id), 2 COLLATE BINARY, typeof(name) LIMIT 5',
      visibleColumnCount: 2,
    })
  })

  it('re-addresses star columns and renumbers anonymous parameters in tie keys', () => {
    const star = compileSqlStatement({ sql: 'SELECT *, ? + 1 AS next FROM accounts AS a ORDER BY id', bindings: [
      { parameter: { kind: 'index', index: 1 }, value: { kind: 'int64', value: 1n } },
    ] }, 'precondition')
    expect(completeOrderedResultSql(star, ['id', 'value', 'next']).sql).toBe(
      'SELECT *, ? + 1 AS next FROM accounts AS a ORDER BY id, 1 COLLATE BINARY, typeof("a"."id"), ' +
      '2 COLLATE BINARY, typeof("a"."value"), 3 COLLATE BINARY, typeof(?1 + 1)',
    )
    const qualified = compileSqlStatement({
      sql: 'SELECT b.* FROM accounts AS a JOIN archived_accounts AS b ON a.id = b.id ORDER BY a.id', bindings: [],
    }, 'precondition')
    expect(completeOrderedResultSql(qualified, ['id']).sql).toBe(
      'SELECT b.* FROM accounts AS a JOIN archived_accounts AS b ON a.id = b.id ORDER BY a.id, 1 COLLATE BINARY, typeof("b"."id")',
    )
    expect(() => completeOrderedResultSql(star, ['id', 'ID', 'next'])).toThrowError(
      expect.objectContaining({ code: 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED' }),
    )
  })

  it('projects hidden storage-class ties through every UNION ALL arm', () => {
    const compiled = compileSqlStatement({
      sql: 'SELECT id AS key FROM accounts UNION ALL VALUES (1.0) UNION ALL SELECT value FROM archived_accounts ORDER BY key DESC',
      bindings: [],
    }, 'precondition')
    expect(completeOrderedResultSql(compiled, ['key'])).toEqual({
      sql: 'SELECT id AS key, typeof(id) FROM accounts UNION ALL VALUES (1.0, typeof(1.0)) ' +
        'UNION ALL SELECT value, typeof(value) FROM archived_accounts ORDER BY key DESC, 1 COLLATE BINARY, 2',
      visibleColumnCount: 1,
    })
  })

  it('keeps binary-only completion where ties are already identical or authored', () => {
    for (const sql of [
      'SELECT 1 UNION ALL SELECT 1.0 ORDER BY 1',
      'SELECT typeof(value) FROM accounts UNION SELECT typeof(value) FROM archived_accounts ORDER BY 1',
    ]) {
      expect(completeOrderedResultSql(compileSqlStatement({ sql, bindings: [] }, 'precondition'), ['c']).sql)
        .toBe(`${sql}, 1 COLLATE BINARY`)
    }
  })

  it('lowers ordered mutation syntax into private frozen-rowid operations', () => {
    const compiled = compileSqlStatement({
      sql: 'UPDATE accounts SET value = ? WHERE active = ? RETURNING id ORDER BY score DESC LIMIT ? OFFSET ?',
      bindings: [
        { parameter: { kind: 'index', index: 1 }, value: { kind: 'text', utf8: new TextEncoder().encode('next') } },
        { parameter: { kind: 'index', index: 2 }, value: { kind: 'int64', value: 1n } },
        { parameter: { kind: 'index', index: 3 }, value: { kind: 'int64', value: 2n } },
        { parameter: { kind: 'index', index: 4 }, value: { kind: 'int64', value: 1n } },
      ],
    }, 'body')
    expect(compiled.orderedMutation?.selectionSqlTemplate).toBe(
      'SELECT __chronolog_ordered_identity_columns__ FROM "accounts" WHERE active = ?2 ORDER BY score DESC, __chronolog_ordered_identity_order__ LIMIT ?3 OFFSET ?4',
    )
    expect(compiled.orderedMutation?.selectionMaximumParameterIndex).toBe(4)
    expect(compiled.orderedMutation?.mutationSqlTemplate).toBe(
      'UPDATE accounts SET value = ?1 WHERE __chronolog_ordered_target_predicate__ RETURNING id',
    )
  })

  it('preserves SQLite named-parameter tokens in ordered mutations', () => {
    const unicode = compileSqlStatement({
      sql: 'UPDATE accounts SET value = :nächster WHERE active = 1 ORDER BY score LIMIT 1',
      bindings: [{
        parameter: { kind: 'name', name: ':nächster' },
        value: { kind: 'text', utf8: new TextEncoder().encode('next') },
      }],
    }, 'body')
    expect(unicode.maximumParameterIndex).toBe(1)
    expect(unicode.orderedMutation?.selectionMaximumParameterIndex).toBe(0)
    expect(unicode.orderedMutation?.mutationSqlTemplate).toContain('SET value = ?1')

    const tcl = compileSqlStatement({
      sql: 'DELETE FROM accounts WHERE owner = $tenant::scope(primary) ORDER BY score LIMIT 1',
      bindings: [{
        parameter: { kind: 'name', name: '$tenant::scope(primary)' },
        value: { kind: 'int64', value: 7n },
      }],
    }, 'body')
    expect(tcl.parameters).toEqual([{
      index: 1,
      names: ['$tenant::scope(primary)'],
      referenced: true,
    }])
    expect(tcl.orderedMutation?.selectionSqlTemplate).toContain('owner = ?1')
    expect(tcl.orderedMutation?.selectionMaximumParameterIndex).toBe(1)
  })

  it.each([
    ['BEGIN', 'SQL_STATEMENT_PROHIBITED'],
    ['SELECT random()', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ["SELECT datetime('now')", 'SQL_AMBIENT_TIME_PROHIBITED'],
    ["SELECT datetime(?)", 'SQL_AMBIENT_TIME_PROHIBITED'],
    ["SELECT strftime('%s')", 'SQL_AMBIENT_TIME_PROHIBITED'],
    ["CREATE TABLE stamped (id INTEGER PRIMARY KEY, at TEXT DEFAULT (strftime('%Y-%m-%d')))", 'SQL_AMBIENT_TIME_PROHIBITED'],
    ['SELECT (SELECT id FROM accounts)', 'SQL_SCALAR_SUBQUERY_TEMPORARILY_GATED'],
    ['SELECT id FROM accounts LIMIT 1', 'SQL_UNORDERED_LIMIT_TEMPORARILY_GATED'],
    ['INSERT INTO accounts SELECT * FROM archived_accounts', 'SQL_INSERT_SELECT_TEMPORARILY_GATED'],
    ['UPDATE accounts SET value = source.value FROM source WHERE source.id = accounts.id', 'SQL_ORDER_SENSITIVE_UPDATE_TEMPORARILY_GATED'],
    ['CREATE TABLE copied AS SELECT id FROM accounts', 'SQL_CREATE_TABLE_AS_SELECT_TEMPORARILY_GATED'],
    ["UPDATE OR REPLACE accounts SET value = 'next'", 'SQL_ORDER_SENSITIVE_UPDATE_TEMPORARILY_GATED'],
    ['SELECT DISTINCT value FROM accounts', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT value, id FROM accounts GROUP BY value', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT min(value) FROM accounts', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT value FROM accounts UNION SELECT value FROM archived_accounts', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT row_number() OVER (ORDER BY value), value FROM accounts', 'SQL_WINDOW_TEMPORARILY_GATED'],
    ['SELECT group_concat(value ORDER BY id) FROM accounts', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT group_concat(value ORDER BY value) FROM accounts', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT group_concat(value ORDER BY value COLLATE BINARY) FROM accounts', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT group_concat(CAST(value AS TEXT) ORDER BY CAST(value AS TEXT)) FROM accounts', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT group_concat(typeof(value), id ORDER BY typeof(value)) FROM accounts', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT value, count(*) FROM accounts GROUP BY value', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT CAST(value AS TEXT), count(*) FROM accounts GROUP BY CAST(value AS TEXT)', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT CAST(value AS REAL), count(*) FROM accounts GROUP BY CAST(value AS REAL)', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT * FROM accounts JOIN archived_accounts USING (id) ORDER BY id', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT a.*, b.* FROM accounts AS a, (SELECT id FROM archived_accounts) AS b ORDER BY a.id', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT * FROM (SELECT id FROM accounts) ORDER BY id', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT id FROM accounts UNION SELECT id FROM archived_accounts ORDER BY id', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT typeof(id) FROM accounts UNION ALL SELECT * FROM archived_accounts ORDER BY 1', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT value COLLATE application_custom FROM accounts', 'SQL_COLLATION_NOT_REGISTERED'],
    ['CREATE TABLE custom_collation (value TEXT COLLATE application_custom)', 'SQL_COLLATION_NOT_REGISTERED'],
    ['CREATE VIRTUAL TABLE search_docs USING fts5(body)', 'SQL_VIRTUAL_TABLE_TEMPORARILY_GATED'],
    ['CREATE TEMP TABLE x (id)', 'SQL_TEMP_OBJECT_PROHIBITED'],
    ['DROP TABLE chronolog_transactions', 'SQL_PROTECTED_OBJECT_NAME'],
    ['SELECT * FROM dolt_log', 'SQL_PROTECTED_OBJECT_READ'],
    ['CREATE INDEX attack ON chronolog_transactions(outcome)', 'SQL_PROTECTED_OBJECT_WRITE'],
    ['CREATE TRIGGER attack AFTER INSERT ON accounts BEGIN DELETE FROM chronolog_transactions; END', 'SQL_PROTECTED_OBJECT_WRITE'],
    ['SELECT 1; SELECT 2', 'SQL_MULTIPLE_STATEMENTS'],
  ])('rejects %s with %s', (sql, code) => {
    expect(() => compileSqlStatement({ sql, bindings: [] }, 'body', { catalog: LOOSE })).toThrowError(
      expect.objectContaining<Partial<SqlCompilerError>>({ code }),
    )
  })

  it('admits deterministic JSON arrows and trigger RAISE while gating transaction rollback', () => {
    expect(compileSqlStatement({
      sql: "SELECT json('{\"id\":1}') ->> '$.id'",
      bindings: [],
    }, 'body').statementClass).toBe('read')
    expect(compileSqlStatement({
      sql: 'CREATE TRIGGER check_value BEFORE INSERT ON accounts BEGIN SELECT RAISE(ABORT, \'bad\'); END',
      bindings: [],
    }, 'body').statementClass).toBe('schema')
    expect(() => compileSqlStatement({
      sql: 'CREATE TRIGGER rollback_value BEFORE INSERT ON accounts BEGIN SELECT RAISE(ROLLBACK, \'bad\'); END',
      bindings: [],
    }, 'body')).toThrowError(expect.objectContaining({ code: 'SQL_RAISE_TEMPORARILY_GATED' }))
  })

  it('requires at least one effect-capable body statement', () => {
    expect(() => compileSqlProgram({
      version: 1,
      preconditions: [{ id: 1, query: { sql: 'SELECT 1', bindings: [] }, resultMode: 'scalar', expectation: { kind: 'assert_true' } }],
      body: [{ sql: 'SELECT 1', bindings: [] }],
    })).toThrowError(expect.objectContaining({ code: 'SQL_EFFECT_CAPABLE_STATEMENT_REQUIRED' }))
  })
})

describe('schema-proven representative stability', () => {
  it.each([
    // rowid alias, STRICT INT/BLOB, STRICT TEXT and TEXT affinity under BINARY
    'SELECT id, count(*) FROM s GROUP BY id',
    'SELECT n, count(*) FROM s GROUP BY n',
    'SELECT s.t, count(*) AS c FROM s GROUP BY s.t HAVING c > 1 ORDER BY c DESC, 1',
    'SELECT b, count(*) FROM s GROUP BY b',
    'SELECT name, count(*) FROM l GROUP BY name ORDER BY name',
    'SELECT k, count(*) FROM p GROUP BY k',
    'SELECT x.k, count(*) FROM l AS x JOIN s ON s.id = x.k GROUP BY x.k',
    'SELECT DISTINCT n, t FROM s',
    'SELECT min(n), max(t), min(k), max(name) FROM s, l',
    'SELECT n FROM s UNION SELECT k FROM l',
    'SELECT group_concat(n ORDER BY n) FROM s',
    'SELECT group_concat(name ORDER BY name) FROM l',
    // BINARY-injective columns under an explicit COLLATE BINARY
    'SELECT group_concat(tag ORDER BY tag COLLATE BINARY) FROM l',
    'SELECT ci COLLATE BINARY, count(*) FROM s GROUP BY ci COLLATE BINARY',
    // nothing outside aggregates; the HAVING alias names no column
    'SELECT count(*) AS c FROM l HAVING c > 0',
    'SELECT coalesce(max(k), 0) + 1 FROM l',
  ])('admits %s against the catalog', (sql) => {
    expect(compileCode(sql, PROVEN)).toBe('accepted')
    // A catalog never admits what admission rejects.
    expect(compileCode(sql)).toBe('accepted')
  })

  it.each([
    // Unproven column kinds: REAL/ANY/untyped, non-STRICT INTEGER affinity,
    // NOCASE collation, generated columns, and rowid aliases that are not.
    ['SELECT r, count(*) FROM s GROUP BY r', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT a, count(*) FROM s GROUP BY a', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT raw, count(*) FROM l GROUP BY raw', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT num, count(*) FROM l GROUP BY num', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT kd, count(*) FROM l GROUP BY kd', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT tag, count(*) FROM l GROUP BY tag', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT ci, count(*) FROM s GROUP BY ci', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT g, count(*) FROM s GROUP BY g', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT k, count(*) FROM d GROUP BY k', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT k, count(*) FROM w GROUP BY k', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT group_concat(real_value ORDER BY real_value) FROM l', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT group_concat(tag ORDER BY tag) FROM l', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    ['SELECT DISTINCT tag FROM l', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    // The compound applies the leftmost arm's NOCASE to the other arm's text.
    ['SELECT ni FROM s UNION SELECT t FROM s', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    // Resolution that the catalog cannot pin down.
    ['SELECT n, count(*) FROM v GROUP BY n', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT n, count(*) FROM missing GROUP BY n', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['WITH s AS (SELECT raw AS n FROM l) SELECT n, count(*) FROM s GROUP BY n', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT n, count(*) FROM (SELECT n FROM s) GROUP BY n', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT k, count(*) FROM p, w GROUP BY k', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT nope, count(*) FROM s GROUP BY nope', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT * FROM l JOIN v ON v.n = l.k ORDER BY l.k', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    // An unstable group key leaks through HAVING, the group ORDER BY, and
    // DISTINCT in any compound arm, not only through the projection.
    ["SELECT count(*) FROM l GROUP BY tag HAVING tag = 'a' COLLATE BINARY", 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT count(*) FROM l GROUP BY tag ORDER BY tag COLLATE BINARY', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT 1 UNION ALL SELECT DISTINCT tag FROM l', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
  ])('keeps %s gated against the catalog with %s', (sql, code) => {
    expect(compileCode(sql, PROVEN)).toBe(code)
  })

  it.each([
    // Stored bodies run against whatever schema exists later.
    ['CREATE VIEW grouped AS SELECT n, count(*) FROM s GROUP BY n', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['CREATE TRIGGER grouped AFTER INSERT ON s BEGIN SELECT group_concat(n ORDER BY n) FROM s; END', 'SQL_FUNCTION_TEMPORARILY_GATED'],
    // Admission rejects shapes no catalog can prove.
    ['SELECT r COLLATE NOCASE, count(*) FROM s GROUP BY r COLLATE NOCASE', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT * FROM l JOIN s USING (k) ORDER BY 1', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT * FROM l NATURAL JOIN s ORDER BY 1', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    ['SELECT * FROM l JOIN (SELECT 1 AS one) ORDER BY 1', 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED'],
    // Representative leaks that need no schema to see: a bare column of an
    // aggregate query, and an inherited collation in a compound arm.
    ['SELECT name, count(*) FROM l', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT count(*) FROM s GROUP BY n HAVING EXISTS (SELECT 1 FROM l WHERE raw = n)', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
    ['SELECT CAST(tag AS INTEGER) FROM l UNION SELECT CAST(tag AS TEXT) COLLATE BINARY FROM l', 'SQL_CANONICAL_REPRESENTATIVE_TEMPORARILY_GATED'],
  ])('rejects %s with or without a catalog', (sql, code) => {
    expect(compileCode(sql)).toBe(code)
    expect(compileCode(sql, PROVEN)).toBe(code)
  })

  it('defers schema proofs at admission and withdraws them against an unproving catalog', () => {
    for (const sql of [
      'SELECT value, count(*) FROM accounts GROUP BY value',
      'SELECT group_concat(value ORDER BY value) FROM accounts',
      'SELECT min(value) FROM accounts',
    ]) {
      expect(compileCode(sql)).toBe('accepted')
      expect(compileCode(sql, LOOSE)).not.toBe('accepted')
    }
    // Join stars need only the declared columns, whatever their types.
    const star = 'SELECT * FROM accounts JOIN source ON source.id = accounts.id ORDER BY accounts.id'
    expect(compileCode(star, LOOSE)).toBe('accepted')
    expect(compileCode(star, catalog({ accounts: 'CREATE TABLE accounts (id, value)' }))).toBe(
      'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED',
    )
    // Compiled for admission, completion never assumes a schema proof.
    const admitted = compileSqlStatement({ sql: 'SELECT n FROM s ORDER BY n', bindings: [] }, 'precondition')
    expect(completeOrderedResultSql(admitted, ['n']).sql).toBe('SELECT n FROM s ORDER BY n, 1 COLLATE BINARY, typeof(n)')
    const joined = compileSqlStatement({
      sql: 'SELECT * FROM accounts JOIN source ON source.id = accounts.id ORDER BY accounts.id', bindings: [],
    }, 'precondition')
    expect(() => completeOrderedResultSql(joined, ['id', 'value', 'id', 'value'])).toThrowError(
      expect.objectContaining({ code: 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED' }),
    )
  })

  it('expands join stars from the catalog and keeps binary-only ties for proven columns', () => {
    const joined = compileSqlStatement({
      sql: 'SELECT *, 1 AS one FROM l AS x JOIN p ON p.k = x.k ORDER BY x.k', bindings: [],
    }, 'precondition', { catalog: PROVEN })
    const names = ['k', 'name', 'tag', 'num', 'raw', 'real_value', 'kd', 'k', 'v', 'one']
    expect(completeOrderedResultSql(joined, names).sql).toBe(
      'SELECT *, 1 AS one FROM l AS x JOIN p ON p.k = x.k ORDER BY x.k, ' +
      names.map((name, index) => `${index + 1} COLLATE BINARY, typeof(${
        index === 9 ? '1' : `"${index < 7 ? 'x' : 'p'}"."${name}"`})`).join(', '),
    )
    // A prepared statement that disagrees with the catalog is not completed.
    expect(() => completeOrderedResultSql(joined, ['k', ...names.slice(2)])).toThrowError(
      expect.objectContaining({ code: 'SQL_ORDERED_RESULT_COMPLETION_TEMPORARILY_GATED' }),
    )
    const pinned = compileSqlStatement({ sql: 'SELECT n, t, k FROM s, l ORDER BY 1', bindings: [] }, 'precondition', { catalog: PROVEN })
    expect(completeOrderedResultSql(pinned, ['n', 't', 'k']).sql)
      .toBe('SELECT n, t, k FROM s, l ORDER BY 1, 1 COLLATE BINARY, 2 COLLATE BINARY, 3 COLLATE BINARY')
  })
})

import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import { DeterministicMaterializer as NativeMaterializer, createDoltLiteExecutionManifest } from '@chronolog/materializer-doltlite'
import { DeterministicMaterializer } from '@chronolog/materializer-doltlite/browser'
import { emit, sqlStatement, sqlValue } from '@chronolog/protocol'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { admitted, ROOT_KEY } from '../../materializer-doltlite/src/test-fixtures.js'
import { openDatabase as openNativeDatabase } from '../../materializer-doltlite/src/driver.js'
import { CONSENSUS_DENIED_FUNCTIONS } from '../../materializer-doltlite/src/sql-profile.js'
import { createWasmEngineFactory, verifyWasmBuild, type ChronologWasmModule, type WasmBuildManifest } from './wasm-engine.js'

const directory = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? 'artifacts/wasm')
const built = existsSync(join(directory, 'manifest.json'))
if (process.env.CHRONOLOG_REQUIRE_WASM === '1' && !built) throw new Error('Build the pinned engine with tools/build-wasm-engine.mjs first')

describe.skipIf(!built)('native/WASM deterministic engine qualification', () => {
  let factory: ReturnType<typeof createWasmEngineFactory>
  let nativeDirectory: string
  beforeAll(async () => {
    const bytes = new Uint8Array(readFileSync(join(directory, 'sqlite3.wasm')))
    const build = JSON.parse(readFileSync(join(directory, 'manifest.json'), 'utf8')) as WasmBuildManifest
    verifyWasmBuild(bytes, build)
    const compiled = await WebAssembly.compile(bytes)
    const { default: initialize } = await import(/* @vite-ignore */ pathToFileURL(join(directory, 'sqlite3.mjs')).href) as {
      default(this: void, options: unknown): Promise<ChronologWasmModule>
    }
    const module = await initialize({
      instantiateWasm(imports: WebAssembly.Imports, done: (instance: WebAssembly.Instance, module: WebAssembly.Module) => void) {
        const instance = new WebAssembly.Instance(compiled, imports)
        done(instance, compiled)
        return instance.exports
      },
      printErr() { /* OPFS is qualified separately in a real Worker. */ },
    })
    factory = createWasmEngineFactory(module, build, 'unix-none')
    nativeDirectory = await mkdtemp(join(tmpdir(), 'chronolog-wasm-'))
  })
  afterAll(async () => { if (nativeDirectory !== undefined) await rm(nativeDirectory, { recursive: true, force: true }) })

  it('executes identical histories, rejects assertions, replays a late predecessor, and reopens exact state', async () => {
    const executionManifest = createDoltLiteExecutionManifest()
    const options = { executionManifest, rootAdministrator: ROOT_KEY, checkpointEvery: 1 }
    const native = await NativeMaterializer.open({ ...options, path: join(nativeDirectory, 'replay.db') })
    let browser = await DeterministicMaterializer.open({ ...options, path: '/replay.db', openDatabase: factory })
    try {
      const digest = native.executionManifestDigest
      const setup = await admitted(1n, 'setup', [
        'CREATE TABLE balances (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)',
        'INSERT INTO balances (id, balance) VALUES (1, 10)',
        'CREATE TABLE probes (id INTEGER PRIMARY KEY, now TEXT, local TEXT, random INTEGER, blob BLOB, real REAL, integer INTEGER, empty BLOB, last_rowid INTEGER, changed INTEGER, vector_distance REAL)',
      ], digest)
      const late = await admitted(3n, 'late', ['UPDATE balances SET balance = balance + 100 WHERE id = 1'], digest)
      const spend = await admitted(5n, 'spend', [
        "SELECT chronolog_assert((SELECT balance FROM balances WHERE id=1)>=50, 'balance')",
        'UPDATE balances SET balance=balance-50 WHERE id=1',
      ], digest)
      const probe = await admitted(1_700_000_000_000n, 'probe', [sqlStatement(
        "INSERT INTO probes (id,now,local,random,blob,real,integer,empty,last_rowid,changed,vector_distance) VALUES (1,datetime('now'),datetime('now','localtime'),random(),randomblob(12),?,?,?,last_insert_rowid(),changes(),vec_distance_L2('[1.2,3.4]','[5.6,7.8]'))",
        [sqlValue.real(1), 9_223_372_036_854_775_807n, new Uint8Array()],
      )], digest)
      for (const history of [[setup, spend, probe], [setup, late, spend, probe]]) {
        const n = await native.materialize(history)
        const w = await browser.materialize(history)
        expect(w?.outcomeChanges).toEqual(n?.outcomeChanges)
        expect(browser.transactionLog()).toEqual(native.transactionLog())
        expect(browser.databaseContentHash).toBe(native.databaseContentHash)
        for (const query of ['SELECT * FROM balances', 'SELECT id,now,local,random,hex(blob),typeof(real),integer,typeof(empty),length(empty),last_rowid,changed,vector_distance FROM probes']) {
          expect(browser.localSql(query).rows).toEqual(native.localSql(query).rows)
        }
      }
      const hash = browser.databaseContentHash
      browser.close()
      browser = await DeterministicMaterializer.open({ ...options, path: '/replay.db', openDatabase: factory })
      expect(browser.databaseContentHash).toBe(hash)
      expect(browser.transactionLog()).toEqual(native.transactionLog())
    } finally { native.close(); browser.close() }
  })

  it('enforces the same ownership, denied SQL, budgets, trigger lint, and extension behavior', async () => {
    const executionManifest = createDoltLiteExecutionManifest({ limits: { maxVmSteps: 5_000 } })
    const options = { executionManifest, rootAdministrator: ROOT_KEY }
    const native = await NativeMaterializer.open({ ...options, path: join(nativeDirectory, 'enforcement.db') })
    const browser = await DeterministicMaterializer.open({ ...options, path: '/enforcement.db', openDatabase: factory })
    try {
      const digest = native.executionManifestDigest
      const other = new Uint8Array(32).fill(9)
      const programs = [
        await admitted(1n, 'setup', [
          'CREATE TABLE notes (id INTEGER PRIMARY KEY, value TEXT NOT NULL)',
          "INSERT INTO notes (id,value) VALUES(1,'root')",
          "SELECT vec_distance_L2('[1,2]','[1,4]')",
        ], digest),
        await admitted(2n, 'owner', ["UPDATE notes SET value='other' WHERE id=1"], digest, other),
        await admitted(3n, 'assert', ["SELECT chronolog_assert(0,'expected')"], digest),
        await admitted(4n, 'attach', ["ATTACH DATABASE ':memory:' AS other"], digest),
        await admitted(5n, 'multiple', ['SELECT 1; SELECT 2'], digest),
        await admitted(6n, 'ignore', ['CREATE TRIGGER bad AFTER UPDATE ON notes BEGIN SELECT RAISE(IGNORE); END'], digest),
        await admitted(7n, 'constraint', ['INSERT INTO notes(id) VALUES(2)'], digest),
        await admitted(8n, 'budget', ['WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n) SELECT count(*) FROM n'], digest),
        ...await Promise.all([
          "SELECT sqlite_compileoption_used('OMIT_UTF16')", 'SELECT sqlite_compileoption_get(0)', 'SELECT sqlite_source_id()',
          'SELECT * FROM pragma_compile_options', 'SELECT * FROM pragma_function_list', 'SELECT * FROM pragma_module_list',
          'SELECT * FROM pragma_pragma_list', 'SELECT * FROM pragma_collation_list', "SELECT load_extension('x')", 'SELECT load_extension(1,2,3)',
        ].map((sql, index) => admitted(BigInt(index + 9), `host-probe-${index}`, [sql], digest))),
      ]
      await native.materialize(programs)
      await browser.materialize(programs)
      expect(browser.transactionLog()).toEqual(native.transactionLog())
      expect(browser.databaseContentHash).toBe(native.databaseContentHash)
      expect(browser.outcome(programs[0]!.txId)?.outcome).toBe('accepted')
      expect(browser.outcome(programs[1]!.txId)?.outcome).toBe('rejected')
      for (const transaction of programs.slice(8)) expect(browser.outcome(transaction.txId)?.outcome).toBe('rejected')
      for (const query of ['UPDATE notes SET value=\'write\'', "SELECT dolt_commit('-m','write')", 'PRAGMA writable_schema=1']) {
        expect(() => native.localSql(query)).toThrow()
        expect(() => browser.localSql(query)).toThrow()
      }
      expect(browser.localSql('SELECT id,value FROM notes').rows).toEqual(native.localSql('SELECT id,value FROM notes').rows)
    } finally { native.close(); browser.close() }
  })

  it('matches the pinned native FTS5, JSON1, integer RTree and sqlite-vec diagnostics', () => {
    const native = openNativeDatabase({ path: join(nativeDirectory, 'extensions.db') }).database
    const browser = factory({ path: '/extensions.db' }).database
    const schema = `
      CREATE VIRTUAL TABLE docs USING fts5(body);
      INSERT INTO docs(rowid,body) VALUES(1,'hello world'),(2,'unrelated');
      CREATE VIRTUAL TABLE boxes USING rtree_i32(id,min_x,max_x);
      INSERT INTO boxes VALUES(1,0,10),(2,20,30);
      CREATE VIRTUAL TABLE vectors USING vec0(embedding int8[2]);
      INSERT INTO vectors(rowid,embedding) VALUES(1,vec_int8('[1,2]')),(2,vec_int8('[3,4]'));
    `
    try {
      native.exec(schema); browser.exec(schema)
      const catalog = (database: typeof native): string[] => {
        const statement = database.prepare('SELECT name,narg FROM pragma_function_list ORDER BY name,narg')
        try {
          return [...new Set(statement.all().map((row) => {
            const { name, narg } = row as { name: string; narg: number }
            return CONSENSUS_DENIED_FUNCTIONS.has(name) || name.startsWith('dolt_') ? '' : `${name}:${narg}`
          }))].filter(Boolean)
        } finally { statement.finalize?.() }
      }
      expect(catalog(browser)).toEqual(catalog(native))
      for (const sql of [
        "SELECT rowid FROM docs WHERE docs MATCH 'hello'",
        "SELECT json_extract('{\"value\":\"exact\"}', '$.value') AS value",
        'SELECT id FROM boxes WHERE min_x<=5 AND max_x>=5',
        "SELECT rowid,distance FROM vectors WHERE embedding MATCH vec_int8('[1,3]') AND k=2 ORDER BY distance",
      ]) {
        const n = native.prepare(sql); const w = browser.prepare(sql)
        try { expect(w.all()).toEqual(n.all()) } finally { n.finalize?.(); w.finalize?.() }
      }
      const vectors = [
        JSON.stringify(Array.from({ length: 64 }, (_, index) => (index % 3 === 0 ? 1e5 : 1e-3) * (index + 1))),
        JSON.stringify(Array.from({ length: 64 }, (_, index) => (index % 2 === 0 ? -1 : 1) / (index + 1))),
      ]
      const sql = 'SELECT vec_distance_L2(vec_f32(?),vec_f32(?)) AS l2, vec_distance_cosine(vec_f32(?),vec_f32(?)) AS cosine'
      const n = native.prepare(sql); const w = browser.prepare(sql)
      try { expect(w.get(...vectors, ...vectors)).toEqual(n.get(...vectors, ...vectors)) }
      finally { n.finalize?.(); w.finalize?.() }
    } finally { native.close(); browser.close() }
  })

  it('executes mixed SQL/events atomically and retains a read view across later accepted changes', async () => {
    const executionManifest = createDoltLiteExecutionManifest()
    const options = { executionManifest, rootAdministrator: ROOT_KEY, checkpointEvery: 1 }
    const native = await NativeMaterializer.open({ ...options, path: join(nativeDirectory, 'events.db') })
    const browser = await DeterministicMaterializer.open({ ...options, path: '/events.db', openDatabase: factory })
    try {
      const digest = native.executionManifestDigest
      const setup = await admitted(1n, 'events-schema', [
        'CREATE TABLE tasks(id INTEGER PRIMARY KEY, value TEXT NOT NULL)',
        "INSERT INTO tasks(id,value) VALUES(1,'initial')",
      ], digest)
      const accepted = await admitted(2n, 'events-mixed', [
        "UPDATE tasks SET value='accepted' WHERE id=1", emit('tasks.changed', { id: 1, value: 'accepted' }),
      ], digest)
      const rejected = await admitted(3n, 'events-rollback', [
        "UPDATE tasks SET value='rollback' WHERE id=1", emit('tasks.changed', { id: 1, value: 'rollback' }),
        "SELECT chronolog_assert(0,'rollback_sql_and_event')",
      ], digest)
      const successor = await admitted(4n, 'events-successor', [
        "UPDATE tasks SET value='successor' WHERE id=1", emit('tasks.changed', { id: 1, value: 'successor' }),
      ], digest)
      for (const engine of [native, browser]) {
        await engine.materialize([setup, accepted, rejected])
        await engine.publishFinal(3)
        expect(engine.outcome(accepted.txId)?.outcome).toBe('accepted')
        expect(engine.outcome(rejected.txId)?.outcome).toBe('rejected')
        const held = engine.captureRead({ view: 'final' })
        const captured = held.query('SELECT value FROM tasks').rows
        try {
          await engine.materialize([setup, accepted, rejected, successor])
          await engine.publishFinal(4)
          expect(held.query('SELECT value FROM tasks').rows).toEqual(captured)
          expect(engine.localSql('SELECT value FROM tasks').rows).not.toEqual(captured)
        } finally { held.release() }
        expect(() => held.query('SELECT value FROM tasks')).toThrow('SNAPSHOT_RELEASED')
      }
      expect(browser.transactionLog()).toEqual(native.transactionLog())
      expect(browser.databaseContentHash).toBe(native.databaseContentHash)
      expect(browser.localSql('SELECT value FROM tasks').rows).toEqual(native.localSql('SELECT value FROM tasks').rows)
    } finally { native.close(); browser.close() }
  })
})

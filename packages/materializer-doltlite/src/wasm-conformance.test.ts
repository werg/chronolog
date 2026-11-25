import { existsSync, readFileSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import { DeterministicMaterializer, createNativeSqlEngine, type SqlEngine } from '@chronolog/materializer-doltlite'
import { emit, encodeRowKey, encodeSealedEnvelope, platformObjectId, sealedOp, sqlStatement, sqlValue, utf8 } from '@chronolog/protocol'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { replayProposal, ROOT_KEY } from './test-fixtures.js'
import { generateX25519KeyPair, sealSealedValue } from '../../crypto/src/index.js'
import { REPLICATED_DENIED_FUNCTIONS } from './sql-profile.js'
import { createBrowserSqlEngine, verifyWasmBuild, type ChronologWasmModule, type WasmBuildManifest } from './wasm-engine.js'

const directory = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? 'artifacts/wasm')
const built = existsSync(join(directory, 'manifest.json'))
if (process.env.CHRONOLOG_REQUIRE_WASM === '1' && !built) throw new Error('Build the pinned engine with tools/build-wasm-engine.mjs first')

describe.skipIf(!built)('native/WASM deterministic engine qualification', () => {
  let browserEngine: SqlEngine
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
    browserEngine = createBrowserSqlEngine({ module, manifest: build, vfs: 'unix-none' })
    expect(browserEngine.executionManifest).toEqual(createNativeSqlEngine().executionManifest)
    nativeDirectory = await mkdtemp(join(tmpdir(), 'chronolog-wasm-'))
  })
  afterAll(async () => { if (nativeDirectory !== undefined) await rm(nativeDirectory, { recursive: true, force: true }) })

  it('executes identical histories, rejects assertions, replays a late predecessor, and reopens exact state', async () => {
    const engine = createNativeSqlEngine()
    const options = { engine, rootPrincipal: ROOT_KEY, checkpointEvery: 1 }
    const native = await DeterministicMaterializer.open({ ...options, path: join(nativeDirectory, 'replay.db') })
    let browser = await DeterministicMaterializer.open({ ...options, path: '/replay.db', engine: { ...browserEngine, executionManifest: engine.executionManifest } })
    try {
      const digest = native.executionManifestDigest
      const setup = await replayProposal(1n, 'setup', [
        'CREATE TABLE balances (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL)',
        'INSERT INTO balances (id, balance) VALUES (1, 10)',
        'CREATE TABLE probes (id INTEGER PRIMARY KEY, now TEXT, local TEXT, random INTEGER, blob BLOB, real REAL, integer INTEGER, empty BLOB, last_rowid INTEGER, changed INTEGER, vector_distance REAL, transaction_id BLOB)',
      ], digest)
      const late = await replayProposal(3n, 'late', ['UPDATE balances SET balance = balance + 100 WHERE id = 1'], digest)
      const spend = await replayProposal(5n, 'spend', [
        "SELECT chronolog_assert((SELECT balance FROM balances WHERE id=1)>=50, 'balance')",
        'UPDATE balances SET balance=balance-50 WHERE id=1',
      ], digest)
      const probe = await replayProposal(1_700_000_000_000n, 'probe', [sqlStatement(
        "INSERT INTO probes (id,now,local,random,blob,real,integer,empty,last_rowid,changed,vector_distance,transaction_id) VALUES (1,datetime('now'),datetime('now','localtime'),random(),randomblob(12),?,?,?,last_insert_rowid(),changes(),vec_distance_L2('[1.2,3.4]','[5.6,7.8]'),chronolog_transaction_id())",
        [sqlValue.real(1), 9_223_372_036_854_775_807n, new Uint8Array()],
      )], digest)
      for (const history of [[setup, spend, probe], [setup, late, spend, probe]]) {
        const n = await native.materialize(history)
        const w = await browser.materialize(history)
        expect(w?.outcomeChanges).toEqual(n?.outcomeChanges)
        expect(browser.transactionLog()).toEqual(native.transactionLog())
        expect(browser.databaseContentHash).toBe(native.databaseContentHash)
        for (const query of ['SELECT * FROM balances', 'SELECT id,now,local,random,hex(blob),typeof(real),integer,typeof(empty),length(empty),last_rowid,changed,vector_distance,hex(transaction_id) FROM probes']) {
          expect(browser.localSql(query).rows).toEqual(native.localSql(query).rows)
        }
        expect(browser.localSql('SELECT hex(transaction_id) FROM probes').rows)
          .toEqual([[{ kind: 'text', value: Buffer.from(probe.txId).toString('hex').toUpperCase() }]])
      }
      const hash = browser.databaseContentHash
      browser.close()
      browser = await DeterministicMaterializer.open({ ...options, path: '/replay.db', engine: { ...browserEngine, executionManifest: engine.executionManifest } })
      expect(browser.databaseContentHash).toBe(hash)
      expect(browser.transactionLog()).toEqual(native.transactionLog())
    } finally { native.close(); browser.close() }
  })

  it('enforces the same ownership, denied SQL, budgets, trigger lint, and extension behavior', async () => {
    const engine = createNativeSqlEngine({ limits: { maxVmSteps: 5_000 } })
    const options = { engine, rootPrincipal: ROOT_KEY }
    const native = await DeterministicMaterializer.open({ ...options, path: join(nativeDirectory, 'enforcement.db') })
    const browser = await DeterministicMaterializer.open({ ...options, path: '/enforcement.db', engine: { ...browserEngine, executionManifest: engine.executionManifest } })
    try {
      const digest = native.executionManifestDigest
      const other = new Uint8Array(32).fill(9)
      const programs = [
        await replayProposal(1n, 'setup', [
          'CREATE TABLE notes (id INTEGER PRIMARY KEY, value TEXT NOT NULL)',
          "INSERT INTO notes (id,value) VALUES(1,'root')",
          "SELECT vec_distance_L2('[1,2]','[1,4]')",
        ], digest),
        await replayProposal(2n, 'owner', ["UPDATE notes SET value='other' WHERE id=1"], digest, other),
        await replayProposal(3n, 'assert', ["SELECT chronolog_assert(0,'expected')"], digest),
        await replayProposal(4n, 'attach', ["ATTACH DATABASE ':memory:' AS other"], digest),
        await replayProposal(5n, 'multiple', ['SELECT 1; SELECT 2'], digest),
        await replayProposal(6n, 'ignore', ['CREATE TRIGGER bad AFTER UPDATE ON notes BEGIN SELECT RAISE(IGNORE); END'], digest),
        await replayProposal(7n, 'constraint', ['INSERT INTO notes(id) VALUES(2)'], digest),
        await replayProposal(8n, 'budget', ['WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n) SELECT count(*) FROM n'], digest),
        ...await Promise.all([
          "SELECT sqlite_compileoption_used('OMIT_UTF16')", 'SELECT sqlite_compileoption_get(0)', 'SELECT sqlite_source_id()',
          'SELECT * FROM pragma_compile_options', 'SELECT * FROM pragma_function_list', 'SELECT * FROM pragma_module_list',
          'SELECT * FROM pragma_pragma_list', 'SELECT * FROM pragma_collation_list', "SELECT load_extension('x')", 'SELECT load_extension(1,2,3)',
        ].map((sql, index) => replayProposal(BigInt(index + 9), `host-probe-${index}`, [sql], digest))),
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
    const native = createNativeSqlEngine().openDatabase({ path: join(nativeDirectory, 'extensions.db') }).database
    const browser = browserEngine.openDatabase({ path: '/extensions.db' }).database
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
            return REPLICATED_DENIED_FUNCTIONS.has(name) || name.startsWith('dolt_') ? '' : `${name}:${narg}`
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

  it('preserves exact row keys, storage-class comparisons and transaction context across engines', () => {
    const native = createNativeSqlEngine().openDatabase({ path: join(nativeDirectory, 'row-keys.db') }).database
    const browser = browserEngine.openDatabase({ path: '/row-keys.db' }).database
    try {
      for (const database of [native, browser]) {
        const key = database.prepare('SELECT chronolog_row_key(?) AS value')
        try {
          for (const value of [null, -(1n << 63n), (1n << 63n) - 1n, 'a\0one', 'a\0two', Uint8Array.of(97, 0, 255),
            sqlValue.real(1.5), sqlValue.real(1.5000000000000002)]) {
            const input = value !== null && typeof value === 'object' && 'kind' in value && value.kind === 'real'
              ? Float64Array.of(value.value) : value
            expect(key.get(input)).toEqual({ value: encodeRowKey([value]) })
          }
        } finally { key.finalize?.() }
        const exact = database.prepare("SELECT chronolog_value_equal('a' COLLATE NOCASE, 'A') AS collation, chronolog_value_equal(1, 1.0) AS numeric, chronolog_value_equal(x'31', '1') AS storage, chronolog_value_equal(NULL, NULL) AS nil")
        try { expect(exact.get()).toEqual({ collation: 0, numeric: 0, storage: 0, nil: 1 }) }
        finally { exact.finalize?.() }
        const transaction = database.prepare('SELECT hex(chronolog_transaction_id()) AS id')
        try {
          const bytes = Uint8Array.of(99, 0, 255, 1, 99).subarray(1, 4)
          database.setDeterministicContext(1n, 7, null, null, bytes)
          expect(transaction.get()).toEqual({ id: '00FF01' })
          database.clearDeterministicContext()
          expect(transaction.get()).toEqual({ id: '' })
          expect(() => database.setDeterministicContext(1n, 7, null, null, new Uint8Array())).toThrow()
        } finally { database.clearDeterministicContext(); transaction.finalize?.() }
      }
    } finally { native.close(); browser.close() }
  })

  it('enforces sealed writes and closes a deleted row policy identically across engines', async () => {
    const engine = createNativeSqlEngine()
    const options = { engine, rootPrincipal: ROOT_KEY }
    const native = await DeterministicMaterializer.open({ ...options, path: join(nativeDirectory, 'sealed-lifecycle.db') })
    const browser = await DeterministicMaterializer.open({ ...options, path: '/sealed-lifecycle.db', engine: { ...browserEngine, executionManifest: engine.executionManifest } })
    try {
      const digest = native.executionManifestDigest
      const reader = await generateX25519KeyPair()
      const rowKey = Uint8Array.of(0, 255, 1)
      const setup = await replayProposal(1n, 'sealed-schema', [
        'CREATE TABLE sealed_docs (id BLOB NOT NULL PRIMARY KEY, body BLOB) STRICT',
        sqlStatement('INSERT INTO sealed_docs (id) VALUES (?)', [rowKey]), sealedOp.registerReaderKey(reader.publicKeyBytes),
      ], digest)
      const policy = await replayProposal(2n, 'sealed-policy', [sealedOp.readerPolicy({
        table: 'sealed_docs', rowKey: [rowKey], expectedVersion: 0n, readers: [ROOT_KEY],
      })], digest)
      const policyId = await platformObjectId(policy.txId, 0)
      const envelopes = await Promise.all([1n, 2n].map(dataVersion => sealSealedValue({
        context: { groupId: setup.core.groupId, policyId, policyVersion: 1n, slot: 'body', dataVersion },
        plaintext: utf8('sealed body'), recipients: [{ readerId: ROOT_KEY, publicKey: reader.publicKeyBytes }],
      })))
      const write = await replayProposal(3n, 'sealed-write', [sealedOp.put({ policyId, expectedPolicyVersion: 1n,
        expectedDataVersion: 0n, slot: 'body', envelope: envelopes[0]!,
      })], digest)
      const overwrite = await replayProposal(4n, 'sealed-overwrite', ["UPDATE sealed_docs SET body = x'00'"], digest)
      const recreate = await replayProposal(5n, 'sealed-recreate', [
        'DELETE FROM sealed_docs', sqlStatement('INSERT INTO sealed_docs (id) VALUES (?)', [rowKey]),
      ], digest)
      const stale = await replayProposal(6n, 'sealed-closed', [sealedOp.put({ policyId, expectedPolicyVersion: 1n,
        expectedDataVersion: 1n, slot: 'body', envelope: envelopes[1]!,
      })], digest)
      const history: typeof setup[] = []
      for (const [transaction, rejection] of [[setup, null], [policy, null], [write, null],
        [overwrite, 'policy:sealed_docs:update'], [recreate, null], [stale, 'platform:reader_policy_closed']] as const) {
        history.push(transaction)
        for (const engine of [native, browser]) {
          await engine.materialize(history)
          expect(engine.outcome(transaction.txId)?.outcome).toBe(rejection === null ? 'accepted' : 'rejected')
          expect(engine.outcome(transaction.txId)?.rejectionCode ?? null).toBe(rejection)
          if (transaction === write || transaction === overwrite) {
            expect(engine.localSql('SELECT body FROM sealed_docs').rows)
              .toEqual([[{ kind: 'blob', value: encodeSealedEnvelope(envelopes[0]!) }]])
          }
        }
        expect(browser.transactionLog()).toEqual(native.transactionLog())
        expect(browser.databaseContentHash).toBe(native.databaseContentHash)
      }
      for (const engine of [native, browser]) {
        expect(engine.localSql('SELECT body FROM sealed_docs').rows).toEqual([[{ kind: 'null' }]])
        expect(engine.localSql('SELECT hex(closed_tx) FROM chronolog_reader_policies').rows)
          .toEqual([[{ kind: 'text', value: Buffer.from(recreate.txId).toString('hex').toUpperCase() }]])
      }
    } finally { native.close(); browser.close() }
  })

  it('executes mixed SQL/events atomically and retains a read view across later accepted changes', async () => {
    const engine = createNativeSqlEngine()
    const options = { engine, rootPrincipal: ROOT_KEY, checkpointEvery: 1 }
    const native = await DeterministicMaterializer.open({ ...options, path: join(nativeDirectory, 'events.db') })
    const browser = await DeterministicMaterializer.open({ ...options, path: '/events.db', engine: { ...browserEngine, executionManifest: engine.executionManifest } })
    try {
      const digest = native.executionManifestDigest
      const setup = await replayProposal(1n, 'events-schema', [
        'CREATE TABLE tasks(id INTEGER PRIMARY KEY, value TEXT NOT NULL)',
        "INSERT INTO tasks(id,value) VALUES(1,'initial')",
      ], digest)
      const accepted = await replayProposal(2n, 'events-mixed', [
        "UPDATE tasks SET value='accepted' WHERE id=1", emit('tasks.changed', { id: 1, value: 'accepted' }),
      ], digest)
      const rejected = await replayProposal(3n, 'events-rollback', [
        "UPDATE tasks SET value='rollback' WHERE id=1", emit('tasks.changed', { id: 1, value: 'rollback' }),
        "SELECT chronolog_assert(0,'rollback_sql_and_event')",
      ], digest)
      const successor = await replayProposal(4n, 'events-successor', [
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

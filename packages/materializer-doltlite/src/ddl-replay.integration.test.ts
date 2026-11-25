import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { afterEach, beforeAll, describe, expect, it } from 'vitest'
import { GROUP_COLLECTIVE_ID, emit, platformObjectId, platformOp, type ProgramStep } from '@chronolog/protocol'

import { DeterministicMaterializer } from './materializer.js'
import { createNativeSqlEngine } from './native.js'
import { MaterializerFixture, ROOT_KEY, replayProposal, rows, testKey } from './test-fixtures.js'
import { createNodeWasmSqlEngine, loadNodeWasmEngine } from './wasm-node.js'
import type { ReplayProposal, SqlEngine } from './types.js'

const fixtures = new MaterializerFixture()
const alice = testKey(11), bob = testKey(12)
const wasmDirectory = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? 'artifacts/wasm')
const wasmBuilt = existsSync(join(wasmDirectory, 'manifest.json'))
if (process.env.CHRONOLOG_REQUIRE_WASM === '1' && !wasmBuilt) throw new Error('SQL_ENGINE_UNAVAILABLE')
afterEach(async () => fixtures.cleanup())

for (const kind of ['native', 'wasm'] as const) describe.skipIf(kind === 'wasm' && !wasmBuilt)(`${kind} authored-time DDL replay`, () => {
  let engine: SqlEngine
  beforeAll(async () => {
    if (kind === 'native') engine = createNativeSqlEngine()
    else {
      const loaded = await loadNodeWasmEngine(wasmDirectory)
      engine = createNodeWasmSqlEngine({ module: loaded.module, manifest: loaded.manifest })
    }
  })
  async function open() {
    const path = join(await fixtures.directory(), 'ddl.db')
    const materializer = await DeterministicMaterializer.open({ engine, path, rootPrincipal: ROOT_KEY, checkpointEvery: 1 })
    const transactions: ReplayProposal[] = []
    const append = async (actor: Uint8Array, ...steps: readonly (ProgramStep | string)[]) => {
      const proposal = await replayProposal(BigInt(transactions.length + 1), `op-${transactions.length}`, steps, materializer.executionManifestDigest, actor)
      transactions.push(proposal)
      await materializer.materialize(transactions)
      return proposal
    }
    const expectAppend = async (outcome: string, actor: Uint8Array, ...steps: readonly (ProgramStep | string)[]) => {
      const proposal = await append(actor, ...steps)
      expect(materializer.outcome(proposal.txId)?.rejectionCode ?? 'accepted', steps.map(step => typeof step === 'string' ? step : 'sql' in step ? step.sql : step.op).join(' | ')).toBe(outcome)
      return proposal
    }
    return { materializer, path, transactions, append, expectAppend }
  }

  it('creates offline with namespace rights, owns new objects, and denies cross-object DDL and implicit role privileges', async () => {
    const f = await open()
    try {
      await f.expectAppend('accepted', ROOT_KEY,
        platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: alice, operations: ['create'] }),
        'CREATE TABLE other (id INTEGER PRIMARY KEY)')
      await f.expectAppend('accepted', alice,
        'CREATE TABLE mine (id INTEGER PRIMARY KEY, value TEXT)',
        "INSERT INTO mine (id, value) VALUES (1, 'offline')",
        'ALTER TABLE mine ADD COLUMN extra TEXT',
        'CREATE INDEX mine_value ON mine (value)',
        'CREATE TRIGGER mine_touch AFTER INSERT ON mine BEGIN SELECT 1; END')
      for (const sql of [
        'ALTER TABLE other ADD COLUMN stolen TEXT', 'DROP TABLE other',
        'CREATE INDEX stolen ON other (id)', 'CREATE TRIGGER stolen AFTER INSERT ON other BEGIN SELECT 1; END',
      ]) await f.expectAppend('denied', alice, sql)
      await f.expectAppend('denied', ROOT_KEY, 'ALTER TABLE mine ADD COLUMN stolen TEXT')
      await f.expectAppend('accepted', ROOT_KEY, platformOp.setMembers(GROUP_COLLECTIVE_ID, [{ member: bob, role: 'admin' }]))
      await f.expectAppend('accepted', bob, platformOp.acceptMembership(GROUP_COLLECTIVE_ID))
      await f.expectAppend('denied', bob, 'CREATE TABLE no_role_privilege (id INTEGER PRIMARY KEY)')
      expect(rows(f.materializer, 'SELECT value FROM mine')).toEqual([['offline']])
    } finally { f.materializer.close() }
  })

  it('re-reads grants each step and atomically rolls back DDL, DML, permission changes and emits', async () => {
    const f = await open()
    try {
      await f.expectAppend('accepted', ROOT_KEY, 'CREATE TABLE durable (id INTEGER PRIMARY KEY)')
      const failed = await f.expectAppend('assert:rollback', ROOT_KEY,
        platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: alice, operations: ['create'] }),
        'CREATE TABLE rolled_back (id INTEGER PRIMARY KEY)', 'INSERT INTO durable (id) VALUES (1)',
        emit('not-effective', { value: 1 }), "SELECT chronolog_assert(0, 'rollback')")
      expect(rows(f.materializer, "SELECT name FROM sqlite_schema WHERE name = 'rolled_back'")).toEqual([])
      expect(rows(f.materializer, 'SELECT id FROM durable')).toEqual([])
      expect(rows(f.materializer, 'SELECT grant_id FROM chronolog_ddl_grants')).toEqual([])
      expect(f.materializer.captureApplication().transactionAt(1)).toMatchObject({ txId: failed.txId, outcome: 'rejected' })
      await f.expectAppend('denied', alice, 'CREATE TABLE denied_after_rollback (id INTEGER PRIMARY KEY)')
      const granted = await f.expectAppend('accepted', ROOT_KEY,
        platformOp.grantDdl({ scope: { kind: 'object', name: 'durable' }, grantee: alice, operations: ['alter'] }))
      const grantId = await platformObjectId(granted.txId, 0)
      await f.expectAppend('accepted', alice, 'ALTER TABLE durable ADD COLUMN first TEXT')
      // A recipient can renounce. Its following statement sees the revoked state;
      // denial rolls back the renunciation too, along with the attempted DDL.
      await f.expectAppend('denied', alice, platformOp.revokeDdl(grantId), 'ALTER TABLE durable ADD COLUMN denied TEXT')
      await f.expectAppend('accepted', alice, 'ALTER TABLE durable ADD COLUMN second TEXT')
      await f.expectAppend('accepted', ROOT_KEY, platformOp.revokeDdl(grantId))
      await f.expectAppend('denied', alice, 'ALTER TABLE durable ADD COLUMN denied TEXT')
      await f.expectAppend('platform:not_ddl_owner', alice,
        platformOp.grantDdl({ scope: { kind: 'object', name: 'durable' }, grantee: bob, operations: ['drop'] }))
    } finally { f.materializer.close() }
  })

  it('derives late DDL outcome flips, preserves captured schemas, final prefixes and ordinary schema on reopen', async () => {
    const f = await open()
    let reopened: DeterministicMaterializer | undefined
    try {
      const digest = f.materializer.executionManifestDigest
      const insert = await replayProposal(20n, 'offline-insert', ["INSERT INTO late (id, value) VALUES (1, 'ready')"], digest)
      await f.materializer.materialize([insert])
      expect(f.materializer.outcome(insert.txId)?.outcome).toBe('rejected')
      const rejected = f.materializer.captureRead()
      const create = await replayProposal(10n, 'late-schema', ['CREATE TABLE late (id INTEGER PRIMARY KEY, value TEXT)'], digest)
      const change = await f.materializer.materialize([create, insert])
      expect(change?.outcomeChanges).toContainEqual(expect.objectContaining({ txId: insert.txId, previous: 'rejected', current: 'accepted' }))
      expect(() => rejected.query('SELECT * FROM late')).toThrow()
      rejected.release()
      const old = f.materializer.captureRead()
      const drop = await replayProposal(30n, 'drop-schema', ['DROP TABLE late'], digest)
      await f.materializer.materialize([create, insert, drop])
      expect(old.query('SELECT value FROM late').rows).toEqual([[{ kind: 'text', value: 'ready' }]])
      expect(() => f.materializer.localSql('SELECT value FROM late')).toThrow()
      await f.materializer.publishFinal(2)
      expect(f.materializer.localSql('SELECT value FROM late', [], { view: 'final' }).rows).toEqual(old.query('SELECT value FROM late').rows)
      await expect(f.materializer.publishFinal(1)).rejects.toThrow('FINAL_PREFIX_INVALID')
      await expect(f.materializer.materialize([insert, create, drop])).rejects.toThrow('ORDER_INVALID')
      await expect(f.materializer.materialize([create, drop])).rejects.toThrow('FINAL_PREFIX_CHANGED')
      const earlier = await replayProposal(5n, 'earlier', ['CREATE TABLE too_early (id INTEGER PRIMARY KEY)'], digest)
      await expect(f.materializer.materialize([earlier, create, insert, drop])).rejects.toThrow('FINAL_PREFIX_CHANGED')
      old.release()
      f.materializer.close()
      reopened = await DeterministicMaterializer.open({ engine, path: f.path, rootPrincipal: ROOT_KEY })
      expect(reopened.finalOrderLength).toBe(2)
      expect(() => reopened!.localSql('SELECT * FROM late')).toThrow()
      expect(reopened.localSql('SELECT value FROM late', [], { view: 'final' }).rows).toEqual([[{ kind: 'text', value: 'ready' }]])
      expect(rows(reopened, 'SELECT count(*) FROM chronolog_ddl_namespaces')).toEqual([['1']])
      expect(rows(reopened, "SELECT name FROM sqlite_schema WHERE name IN ('chronolog_peer_control', 'chronolog_execution_context', 'chronolog_attempt_generations')")).toEqual([])
    } finally { reopened?.close(); f.materializer.close() }
  })

  it('retains object authority through rename, revokes dropped-object grants, and authorizes view/virtual drop cascades', async () => {
    const f = await open()
    try {
      await f.expectAppend('accepted', ROOT_KEY,
        'CREATE TABLE names (id INTEGER PRIMARY KEY)', 'CREATE INDEX names_idx ON names (id)',
        'CREATE VIEW editable AS SELECT id FROM names',
        'CREATE TRIGGER editable_insert INSTEAD OF INSERT ON editable BEGIN INSERT INTO names (id) VALUES (NEW.id); END',
        'CREATE VIRTUAL TABLE search USING fts5(body)',
        platformOp.grantDdl({ scope: { kind: 'object', name: 'names' }, grantee: alice, operations: ['alter', 'drop'] }),
        platformOp.grantDdl({ scope: { kind: 'object', name: 'editable' }, grantee: alice, operations: ['drop'] }),
        platformOp.grantDdl({ scope: { kind: 'object', name: 'search' }, grantee: alice, operations: ['drop'] }))
      await f.expectAppend('accepted', alice, 'ALTER TABLE names RENAME TO renamed', 'ALTER TABLE renamed ADD COLUMN extra TEXT')
      await f.expectAppend('accepted', alice, 'DROP VIEW editable')
      await f.expectAppend('accepted', alice, 'DROP TABLE renamed')
      await f.expectAppend('accepted', alice, 'DROP TABLE search')
      expect(rows(f.materializer, "SELECT name FROM chronolog_ddl_objects")).toEqual([])
      expect(rows(f.materializer, "SELECT grant_id FROM chronolog_ddl_grants WHERE revoked_tx IS NULL")).toEqual([])
      await f.expectAppend('accepted', ROOT_KEY, 'CREATE TABLE renamed (id INTEGER PRIMARY KEY)')
      await f.expectAppend('denied', alice, 'DROP TABLE renamed')
    } finally { f.materializer.close() }
  })

  it('rejects reserved renames and preserves virtual-object ownership for ALTER grantees', async () => {
    const f = await open()
    try {
      await f.expectAppend('accepted', ROOT_KEY,
        'CREATE TABLE protected_names (id INTEGER PRIMARY KEY)',
        'CREATE VIRTUAL TABLE search_names USING fts5(body)',
        platformOp.grantDdl({ scope: { kind: 'object', name: 'search_names' }, grantee: alice, operations: ['alter'] }))
      for (const name of ['chronolog_forged', '_cf_forged', 'dolt_forged', 'pragma_forged']) {
        await f.expectAppend('denied', ROOT_KEY, `ALTER TABLE protected_names RENAME TO ${name}`)
      }
      await f.expectAppend('denied', alice, 'ALTER TABLE search_names RENAME TO chronolog_virtual_forged')
      await f.expectAppend('accepted', alice, 'ALTER TABLE search_names RENAME TO moved_search')
      await f.expectAppend('denied', alice, 'DROP TABLE moved_search')
      await f.expectAppend('accepted', ROOT_KEY, 'DROP TABLE moved_search')
      for (const sql of [
        'DELETE FROM chronolog_ddl_grants', 'DROP TABLE chronolog_ddl_objects',
        "UPDATE chronolog_ddl_namespaces SET owner = zeroblob(32)",
      ]) await f.expectAppend('denied', ROOT_KEY, sql)
      expect(rows(f.materializer, 'SELECT name FROM chronolog_ddl_objects')).toEqual([['protected_names']])
    } finally { f.materializer.close() }
  })

  it('validates every input comparator and stable identity, including retained prefixes and exact bigint ties', async () => {
    const f = await open()
    try {
      const digest = f.materializer.executionManifestDigest
      const time = 253_402_300_799_998n
      const a = await replayProposal(time, 'tie-a', [emit('tie', 'alice')], digest, alice)
      const b = await replayProposal(time, 'tie-b', [emit('tie', 'root')], digest, ROOT_KEY)
      await expect(f.materializer.materialize([b, a])).rejects.toThrow('ORDER_INVALID')
      await f.materializer.materialize([a, b])
      const revision = f.materializer.revision
      expect(await f.materializer.materialize([a, b])).toBeNull()
      await expect(f.materializer.materialize([b, a])).rejects.toThrow('ORDER_INVALID')
      await expect(f.materializer.materialize([a, a])).rejects.toThrow('ORDER_INVALID')
      await expect(f.materializer.materialize([{ ...a, txId: testKey(99) }, b])).rejects.toThrow('TRANSACTION_ID_INVALID')
      await expect(f.materializer.materialize([{ ...a, core: { ...a.core, authorTimestampMs: time - 1n } }, b])).rejects.toThrow('CANONICAL_CANDIDATE_MISMATCH')
      expect(f.materializer.revision).toBe(revision)
      expect(f.materializer.outcome(a.txId)?.orderKey.authorTimestampMs).toBe(time)
    } finally { f.materializer.close() }
  })

  it('accepts the pinned clock maximum and deterministically rejects +1 without blocking valid replay', async () => {
    const f = await open()
    try {
      const max = 253_402_300_799_999n
      const digest = f.materializer.executionManifestDigest
      const setup = await replayProposal(max - 3n, 'clock-schema', ['CREATE TABLE clock (id INTEGER PRIMARY KEY, now TEXT, proposal BLOB)'], digest)
      const valid = await replayProposal(max, 'clock-max', ["INSERT INTO clock (id, now, proposal) VALUES (1, datetime('now'), chronolog_transaction_id())"], digest)
      const invalid = await replayProposal(max + 1n, 'clock-out-of-range', ['INSERT INTO clock (id) VALUES (99)'], digest)
      await f.materializer.materialize([setup, valid, invalid])
      expect(f.materializer.outcome(valid.txId)?.outcome).toBe('accepted')
      expect(f.materializer.outcome(invalid.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'profile:timestamp-range', failingStatementIndex: null })
      expect(rows(f.materializer, 'SELECT id, now, proposal FROM clock')).toEqual([['1', '9999-12-31 23:59:59', valid.txId]])
      const lateValid = await replayProposal(max - 1n, 'clock-late-valid', ['INSERT INTO clock (id) VALUES (2)'], digest)
      await f.materializer.materialize([setup, lateValid, valid, invalid])
      expect(rows(f.materializer, 'SELECT id FROM clock ORDER BY id')).toEqual([['1'], ['2']])
      expect(f.materializer.outcome(invalid.txId)?.rejectionCode).toBe('profile:timestamp-range')
      expect(invalid.core.authorTimestampMs).toBe(max + 1n)
    } finally { f.materializer.close() }
  })

  it('does not reuse DDL authorization when a rollbackable schema cookie is reused', async () => {
    const f = await open()
    try {
      await f.expectAppend('accepted', ROOT_KEY,
        platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: alice, operations: ['create'] }),
        platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: bob, operations: ['create'] }))
      await f.expectAppend('assert:rollback', alice,
        'CREATE TABLE recycled (id INTEGER PRIMARY KEY)', "SELECT chronolog_assert(0, 'rollback')")
      await f.expectAppend('accepted', bob, 'CREATE TABLE recycled (id INTEGER PRIMARY KEY)')
      await f.expectAppend('denied', alice, 'ALTER TABLE recycled ADD COLUMN stolen TEXT')
      await f.expectAppend('accepted', bob, 'ALTER TABLE recycled ADD COLUMN owned TEXT')
      await f.expectAppend('denied', ROOT_KEY, 'DROP TABLE recycled')
    } finally { f.materializer.close() }
  })
})

import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { DeterministicMaterializer, createNativeSqlEngine } from './index.js'
import { replayProposal, ROOT_KEY } from './test-fixtures.js'
import { createNodeWasmSqlEngine, loadNodeWasmEngine, writeFileAtomicSync } from './wasm-node.js'

const wasmDir = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? 'artifacts/wasm')
const wasmBuilt = existsSync(join(wasmDir, 'manifest.json'))
if (process.env.CHRONOLOG_REQUIRE_WASM === '1' && !wasmBuilt) {
  throw new Error(`Expected built WASM engine in ${wasmDir}; run tools/build-wasm-engine.mjs first`)
}

describe('Node WASM SQL adapter contracts', () => {
  it('fails closed with SQL_ENGINE_UNAVAILABLE when verified WASM artifacts are absent', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'chronolog-wasm-missing-'))
    try {
      await expect(loadNodeWasmEngine(empty)).rejects.toMatchObject({ code: 'SQL_ENGINE_UNAVAILABLE' })
    } finally {
      rmSync(empty, { recursive: true, force: true })
    }
  })

  it('atomically persists bytes with fsyncSync via writeFileAtomicSync', () => {
    const dir = mkdtempSync(join(tmpdir(), 'chronolog-wasm-fs-'))
    try {
      const target = join(dir, 'nested', 'state.sqlite')
      writeFileAtomicSync(target, new Uint8Array([1, 2, 3, 4]))
      expect([...readFileSync(target)]).toEqual([1, 2, 3, 4])
      writeFileAtomicSync(target, new Uint8Array([9, 8, 7]))
      expect([...readFileSync(target)]).toEqual([9, 8, 7])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it.skipIf(!wasmBuilt)('persists real DoltLite SQL histories directly to host disk via chronolog-node-fs VFS and reopens identically', async () => {
    const loaded = await loadNodeWasmEngine(wasmDir)
    const engine = createNodeWasmSqlEngine({ module: loaded.module, manifest: loaded.manifest })
    expect(engine.executionManifest).toEqual(createNativeSqlEngine().executionManifest)

    const dir = mkdtempSync(join(tmpdir(), 'chronolog-wasm-node-persist-'))
    const dbPath = join(dir, 'app.db')
    try {
      const first = await DeterministicMaterializer.open({ engine, path: dbPath, rootPrincipal: ROOT_KEY, checkpointEvery: 1 })
      const digest = first.executionManifestDigest
      const p1 = await replayProposal(1n, 'init', [
        'CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL)',
        "INSERT INTO notes (id, body) VALUES (1, 'persisted-via-node-wasm')",
      ], digest)
      const p2 = await replayProposal(2n, 'update', [
        "INSERT INTO notes (id, body) VALUES (2, 'second-commit')",
      ], digest)
      await first.materialize([p1, p2])
      const firstRows = first.localSql('SELECT id, body FROM notes ORDER BY id')
      expect(firstRows.rows).toEqual([
        [{ kind: 'integer', value: '1' }, { kind: 'text', value: 'persisted-via-node-wasm' }],
        [{ kind: 'integer', value: '2' }, { kind: 'text', value: 'second-commit' }],
      ])
      const expectedHash = first.databaseContentHash
      const expectedLog = first.transactionLog()
      first.close()

      // Verify real host database file was written and fsynced on disk.
      expect(existsSync(dbPath)).toBe(true)
      expect(statSync(dbPath).size).toBeGreaterThan(0)

      // Reopen a brand-new materializer instance against the persisted host file.
      const reopened = await DeterministicMaterializer.open({ engine, path: dbPath, rootPrincipal: ROOT_KEY, checkpointEvery: 1 })
      try {
        const reopenedRows = reopened.localSql('SELECT id, body FROM notes ORDER BY id')
        expect(reopenedRows.rows).toEqual(firstRows.rows)
        expect(reopened.databaseContentHash).toBe(expectedHash)
        expect(reopened.transactionLog()).toEqual(expectedLog)
      } finally {
        reopened.close()
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

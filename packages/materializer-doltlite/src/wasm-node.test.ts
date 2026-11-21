import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import { loadNodeWasmEngine, writeFileAtomicSync } from './wasm-node.js'

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
})

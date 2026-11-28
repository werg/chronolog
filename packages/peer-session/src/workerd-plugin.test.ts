import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { build } from 'esbuild'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createWorkerdWasmPlugin } from './workerd-plugin.js'

let dir: string
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'chronolog-workerd-plugin-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

function write(path: string, contents: string | Uint8Array): string {
  const full = join(dir, path)
  mkdirSync(join(full, '..'), { recursive: true })
  writeFileSync(full, contents)
  return full
}

const wasmA = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1])
const wasmB = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 2])

describe('createWorkerdWasmPlugin', () => {
  it('resolves nested (pnpm-style) packages, hash-names colliding basenames, and stubs node:module', async () => {
    // The package lives only beside its importer: nothing under <root>/node_modules.
    write('pkgs/materializer/node_modules/@jitl/quickjs-ng-wasmfile-release-sync/package.json',
      JSON.stringify({ name: '@jitl/quickjs-ng-wasmfile-release-sync', version: '0.0.0', exports: { './wasm': './dist/emscripten-module.wasm' } }))
    write('pkgs/materializer/node_modules/@jitl/quickjs-ng-wasmfile-release-sync/dist/emscripten-module.wasm', wasmA)
    write('pkgs/materializer/src/index.js', `
      import quickjs from '@jitl/quickjs-ng-wasmfile-release-sync/wasm'
      import local from './emscripten-module.wasm'
      import { createRequire } from 'node:module'
      import { createRequire as bare } from 'module'
      export { quickjs, local, createRequire, bare }
    `)
    write('pkgs/materializer/src/emscripten-module.wasm', wasmB)

    const assets: Array<[string, string]> = []
    const outDir = join(dir, 'out/engine')
    const result = await build({
      entryPoints: [join(dir, 'pkgs/materializer/src/index.js')],
      outfile: join(outDir, 'worker.mjs'),
      bundle: true,
      platform: 'browser',
      format: 'esm',
      write: true,
      logLevel: 'silent',
      plugins: [createWorkerdWasmPlugin({ outDir, rootDir: dir, onAsset: (name, source) => assets.push([name, source]) })],
    })
    expect(result.errors).toEqual([])

    const names = assets.map(([name]) => name)
    expect(new Set(names).size).toBe(2)
    for (const name of names) expect(name).toMatch(/^emscripten-module\.[0-9a-f]{16}\.wasm$/u)
    expect(readdirSync(outDir).filter(f => f.endsWith('.wasm')).sort()).toEqual([...names].sort())

    const bySource = new Map(assets.map(([name, source]) => [source, name]))
    const nested = [...bySource].find(([source]) => source.includes('node_modules'))
    expect(nested).toBeDefined()
    expect(new Uint8Array(readFileSync(join(outDir, nested![1])))).toEqual(wasmA)
    const local = [...bySource].find(([source]) => !source.includes('node_modules'))
    expect(new Uint8Array(readFileSync(join(outDir, local![1])))).toEqual(wasmB)

    const bundle = readFileSync(join(outDir, 'worker.mjs'), 'utf8')
    for (const name of names) expect(bundle).toContain(`./${name}`)
    expect(bundle).toContain('node:module is unavailable in Cloudflare Workers')
  })

  it('fails with a clear error when a bare wasm specifier cannot be resolved', async () => {
    write('src/index.js', `import w from '@chronolog/peer-session/sqlite-cas.wasm'\nexport default w`)
    const result = await build({
      entryPoints: [join(dir, 'src/index.js')],
      outfile: join(dir, 'out/worker.mjs'),
      bundle: true,
      platform: 'browser',
      format: 'esm',
      logLevel: 'silent',
      write: false,
      plugins: [createWorkerdWasmPlugin({ outDir: join(dir, 'out'), rootDir: dir })],
    }).catch((error: { errors?: Array<{ text: string }> }) => error)
    expect(JSON.stringify(result)).toContain('cannot resolve @chronolog/peer-session/sqlite-cas.wasm')
  })
})

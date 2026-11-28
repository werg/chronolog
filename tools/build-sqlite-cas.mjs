/* global console, process */
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const workspace = resolve(import.meta.dirname, '..')
const pkgDir = join(workspace, 'packages/sqlite-cas')
const vendorDir = join(pkgDir, 'vendor')
const cDir = join(pkgDir, 'c')
const distDir = join(pkgDir, 'wasm')
mkdirSync(distDir, { recursive: true })

const emsdk = process.env.EMSDK ?? '/home/werg/emsdk'
const emcc = join(emsdk, 'upstream/emscripten/emcc')

const exportedFunctions = [
  '_malloc', '_free',
  '_chronolog_init', '_chronolog_set_context', '_chronolog_set_tx_meta', '_chronolog_set_mode',
  '_chronolog_open', '_chronolog_close', '_chronolog_errmsg',
  '_chronolog_changes', '_chronolog_last_insert_rowid', '_chronolog_reset_rowid',
  '_chronolog_prepare', '_chronolog_step', '_chronolog_finalize',
  '_chronolog_bind_null', '_chronolog_bind_int64', '_chronolog_bind_double',
  '_chronolog_bind_text', '_chronolog_bind_blob',
  '_chronolog_column_count', '_chronolog_column_name', '_chronolog_column_type',
  '_chronolog_column_double', '_chronolog_column_text', '_chronolog_column_bytes', '_chronolog_column_blob',
  '_chronolog_validate_expr',
]

const args = [
  '-O2',
  '-I', vendorDir,
  '-DSQLITE_CORE',
  '-DSQLITE_ENABLE_FTS5',
  '-DSQLITE_ENABLE_JSON1',
  '-DSQLITE_ENABLE_RTREE',
  '-DSQLITE_OMIT_LOAD_EXTENSION',
  '-DSQLITE_OMIT_DEPRECATED',
  '-DSQLITE_OMIT_SHARED_CACHE',
  '-DSQLITE_DQS=0',
  '-DSQLITE_DEFAULT_MEMSTATUS=0',
  '-DSQLITE_DEFAULT_PAGE_SIZE=4096',
  '-DSQLITE_THREADSAFE=0',
  '-DSQLITE_TEMP_STORE=3',
  '-DSQLITE_MAX_EXPR_DEPTH=256',
  '-sMODULARIZE=1',
  '-sEXPORT_ES6=1',
  '-sEXPORT_NAME=createSqliteCasWasm',
  '-sENVIRONMENT=web,worker,node',
  '-sALLOW_MEMORY_GROWTH=1',
  '-sINITIAL_MEMORY=16777216',
  '-sMAXIMUM_MEMORY=134217728',
  '-sSTACK_SIZE=2097152',
  '-sNO_EXIT_RUNTIME=1',
  `-sEXPORTED_FUNCTIONS=${JSON.stringify(exportedFunctions)}`,
  '-sEXPORTED_RUNTIME_METHODS=["UTF8ToString","stringToUTF8","lengthBytesUTF8","HEAPU8","HEAPU32","getValue","setValue"]',
  '-Wno-unused-function',
  '-Wno-deprecated-non-prototype',
  join(vendorDir, 'sqlite3.c'),
  join(vendorDir, 'sqlite-vec.c'),
  join(cDir, 'chronolog_sqlite_cas.c'),
  '-o', join(distDir, 'sqlite-cas.mjs'),
]

console.log('Compiling sqlite-cas.wasm with emcc...')
const res = spawnSync(emcc, args, { stdio: 'inherit', cwd: pkgDir })
if (res.error) throw res.error
if (res.status !== 0) process.exit(res.status ?? 1)

const mjsPath = join(distDir, 'sqlite-cas.mjs')
const mjsText = readFileSync(mjsPath, 'utf8').replaceAll('import("module")', 'import(["mod","ule"].join(""))')
writeFileSync(mjsPath, mjsText)

const wasmBytes = readFileSync(join(distDir, 'sqlite-cas.wasm'))
const sha256 = createHash('sha256').update(wasmBytes).digest('hex')
const manifest = {
  format: 1,
  builtinId: `sqlite-cas@1#sha256-${sha256}`,
  wasmSha256: sha256,
  wasmBytes: wasmBytes.byteLength,
}
writeFileSync(join(distDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
console.log('Built sqlite-cas.wasm:', manifest)

// Build the WASM engine from the same pinned sources and deterministic hooks as
// the native addon. No copied second implementation of consensus functions.
/* global console, process */
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, statSync, utimesSync, existsSync, chmodSync } from 'node:fs'
import { dirname, resolve, join } from 'node:path'
import { spawnSync } from 'node:child_process'

const workspace = resolve(import.meta.dirname, '..')
const arguments_ = process.argv.slice(2)
function option(name, fallback) {
  const index = arguments_.indexOf(name)
  if (index < 0) return fallback
  if (!arguments_[index + 1]) throw new Error(`Missing value for ${name}`)
  return resolve(arguments_[index + 1])
}
const emsdk = option('--emsdk', process.env.EMSDK)
if (!emsdk) throw new Error('Pass --emsdk with an installed Emscripten 4.0.20 SDK')
const output = option('--output', join(workspace, 'artifacts/wasm'))
const nativeRequire = createRequire(join(workspace, 'packages/materializer-doltlite/package.json'))
const nativeRoot = dirname(nativeRequire.resolve('@dolthub/doltlite'))
const source = join(nativeRoot, 'amalgamation/.source')
const wasmRoot = join(source, 'ext/wasm')
const emcc = join(emsdk, 'upstream/emscripten/emcc')
const env = { ...process.env, TMPDIR: join(output, 'tmp') }
mkdirSync(output, { recursive: true })
mkdirSync(env.TMPDIR, { recursive: true })

function run(command, args, cwd = workspace) {
  const result = spawnSync(command, args, { cwd, env, stdio: 'inherit' })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})`)
}
const compilerVersion = spawnSync(emcc, ['--version'], { env, encoding: 'utf8' })
if (compilerVersion.status !== 0 || !compilerVersion.stdout.includes('4.0.20')) throw new Error('WASM_TOOLCHAIN_VERSION_MISMATCH')
const nativeManifest = nativeRequire('@dolthub/doltlite').chronologNativeManifest()
if (nativeManifest.doltliteVersion !== '0.11.29' || nativeManifest.sqliteVecVersion !== '0.1.9') throw new Error('WASM_SOURCE_VERSION_MISMATCH')
const nativeProbe = new (nativeRequire('@dolthub/doltlite').DatabaseSync)(':memory:')
const runtimeVersions = nativeProbe.prepare('SELECT dolt_version() AS doltlite, sqlite_version() AS sqlite, vec_version() AS vec').get()
nativeProbe.close()

const addon = readFileSync(join(nativeRoot, 'src/addon.cpp'), 'utf8')
const start = addon.indexOf('// ── Deterministic engine inputs')
const end = addon.indexOf('extern "C" int doltliteInstallAutoExt(void);')
if (start < 0 || end <= start) throw new Error('WASM_DETERMINISTIC_SOURCE_ANCHOR_MISSING')
const deterministic = addon.slice(start, end)
const databaseSource = readFileSync(join(nativeRoot, 'src/database.cpp'), 'utf8')
const configStart = databaseSource.indexOf('Napi::Value Database::ConfigureSecurity(')
const configEnd = databaseSource.indexOf('// ── Internal query helpers', configStart)
const securitySource = databaseSource.slice(configStart, configEnd)
const settings = [...securitySource.matchAll(/APPLY_REQUIRED\("[^"]+",\s*(SQLITE_DBCONFIG_[A-Z0-9_]+),\s*([0-9]+)\)/gu)]
if (settings.length !== 12) throw new Error('WASM_SECURITY_SOURCE_ANCHOR_MISSING')
const security = settings.map((match) => `  { int applied = -1; int rc = sqlite3_db_config(db, ${match[1]}, ${match[2]}, &applied); if(rc != SQLITE_OK || applied != ${match[2]}) return rc == SQLITE_OK ? SQLITE_ERROR : rc; }`).join('\n')
const shim = `#include "sqlite3.h"
#include <emscripten/emscripten.h>
#include <cstring>
#include <ctime>
#include <string>
${deterministic}
extern "C" int doltliteInstallAutoExt(void);
extern "C" int sqlite3_vec_init(sqlite3*, char**, const sqlite3_api_routines*);
extern "C" int chronolog_sql_uses_raise_ignore(const char*);
extern "C" int sqlite3_wasm_extra_init(const char*) {
  int rc = doltliteInstallAutoExt();
  return rc == SQLITE_OK ? sqlite3_auto_extension(reinterpret_cast<void(*)(void)>(sqlite3_vec_init)) : rc;
}
extern "C" EMSCRIPTEN_KEEPALIVE int chronolog_wasm_init(const char* vfsName) {
  if(vfsName && *vfsName) {
    sqlite3_vfs* vfs = sqlite3_vfs_find(vfsName);
    if(!vfs) return SQLITE_NOTFOUND;
    int rc = sqlite3_vfs_register(vfs, 1); if(rc != SQLITE_OK) return rc;
  }
  return InstallDeterministicEngine() ? SQLITE_OK : SQLITE_ERROR;
}
extern "C" EMSCRIPTEN_KEEPALIVE int chronolog_wasm_security(sqlite3* db) {
${security}
  return sqlite3_extended_result_codes(db, 1);
}
extern "C" EMSCRIPTEN_KEEPALIVE void chronolog_wasm_context(sqlite3* db, sqlite3_int64 time, unsigned seed, const unsigned char* actor, int length, int hasActorId, sqlite3_int64 actorId) {
  chronologSetDeterministicContext(time, seed, actor, length, hasActorId, actorId);
  sqlite3_set_last_insert_rowid(db, 0);
}
extern "C" EMSCRIPTEN_KEEPALIVE void chronolog_wasm_clear(void) { chronologClearDeterministicContext(); }
extern "C" EMSCRIPTEN_KEEPALIVE int chronolog_wasm_trigger(const char* sql) { return chronolog_sql_uses_raise_ignore(sql); }
`
const shimPath = join(output, 'chronolog-wasm.cpp')
function writeIfChanged(path, text) {
  if (!existsSync(path) || readFileSync(path, 'utf8') !== text) writeFileSync(path, text)
}
writeIfChanged(shimPath, shim)
if (!existsSync(join(source, 'Makefile'))) run('./configure', [`--with-emsdk=${emsdk}`, '--disable-tcl', '--disable-readline'], source)
run('make', ['parse.h', 'opcodes.h'], source)
// Upstream exports assume its optional session extension. The native profile
// does not compile that extension; keep only functions present in this profile.
const exportSource = readFileSync(join(wasmRoot, 'api/EXPORTED_FUNCTIONS.c-pp'), 'utf8')
const exportsPath = join(output, 'EXPORTED_FUNCTIONS.c-pp')
writeIfChanged(exportsPath, exportSource.split('\n').filter((line) => !/^_sqlite3(?:_preupdate_|changegroup_|changeset_|session)/u.test(line)).join('\n'))
// configure generates makefiles; keep them from regenerating the already
// checksum-pinned released amalgamation/header as a side effect.
const makefileTime = statSync(join(source, 'Makefile')).mtimeMs
for (const file of ['sqlite3.h', 'doltlite.c']) {
  const path = join(nativeRoot, 'amalgamation', file)
  if (statSync(path).mtimeMs <= makefileTime) utimesSync(path, new Date(), new Date())
}
const nativeFlags = [
  '-DSQLITE_THREADSAFE=1', '-DSQLITE_TEMP_STORE=2', '-DSQLITE_USE_URI=1',
  '-DSQLITE_OMIT_DEPRECATED', '-DSQLITE_OMIT_UTF16',
  '-DSQLITE_OMIT_LOAD_EXTENSION', '-DSQLITE_WASM_ENABLE_C_TESTS',
  '-DSQLITE_ENABLE_FTS5', '-DSQLITE_ENABLE_JSON1', '-DSQLITE_ENABLE_RTREE',
  '-DSQLITE_ENABLE_COLUMN_METADATA', '-DDOLTLITE_PROLLY=1',
  '-DSQLITE_WASM_SPLIT_BUILD', '-DSQLITE_PRIVATE=', '-DSQLITE_EXTRA_INIT_MUTEXED=sqlite3_wasm_extra_init',
  '-DBLAKE3_NO_SSE2=1', '-DBLAKE3_NO_SSE41=1', '-DBLAKE3_NO_AVX2=1', '-DBLAKE3_NO_AVX512=1',
  `-DSQLITE_C=${join(nativeRoot, 'amalgamation/doltlite.c')}`,
].join(' ')
run('make', [
  'b-esm', 'jswasm/sqlite3-opfs-async-proxy.js', 'DOLTLITE_WASM=0', `bin.emcc=${emcc}`, 'bin.wasm-strip=true', 'bin.wasm-opt=',
  'emcc_opt=-O1', 'emcc_opt_full=-O1 -g2', 'emcc.environment.esm=web,worker,node',
  'emcc.flags=-sSTACK_SIZE=2097152 -sSTACK_OVERFLOW_CHECK=2',
  `sqlite3.c=${join(nativeRoot, 'amalgamation/doltlite.c')}`,
  `SQLITE_OPT=${nativeFlags}`,
  `EXPORTED_FUNCTIONS.api.in=${exportsPath}`,
  // The amalgamator elides os_unix's fcntl.h because os.c already includes it,
  // but os.c excludes that include under Emscripten. Supply the missing header.
  `cflags.common=-I. -I${join(nativeRoot, 'amalgamation')} -I${join(source, 'src')} -I${source} -include fcntl.h -include unistd.h -fPIC`,
  `sqlite3_wasm_extra_init.c=${shimPath}`,
  `sqlite3-wasm.c.in=api/sqlite3-wasm.c ${shimPath} ${join(nativeRoot, 'amalgamation/doltlite.c')} ${join(nativeRoot, 'amalgamation/doltlite_orig.c')} ${join(nativeRoot, 'amalgamation/sqlite_vec_static.c')}`,
], wasmRoot)
function copyArtifact(sourcePath, targetPath) {
  if (existsSync(targetPath)) chmodSync(targetPath, 0o644)
  copyFileSync(sourcePath, targetPath)
  chmodSync(targetPath, 0o644)
}
for (const file of ['sqlite3.mjs', 'sqlite3.wasm']) copyArtifact(join(wasmRoot, 'jswasm/esm', file), join(output, file))
copyArtifact(join(wasmRoot, 'jswasm/sqlite3-opfs-async-proxy.js'), join(output, 'sqlite3-opfs-async-proxy.js'))
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
writeFileSync(join(output, 'manifest.json'), JSON.stringify({
  format: 1, toolchain: 'emscripten-4.0.20', nativeManifest, runtimeVersions,
  deterministicSourceSha256: digest(deterministic), wasmSha256: digest(readFileSync(join(output, 'sqlite3.wasm'))),
  wasmBytes: statSync(join(output, 'sqlite3.wasm')).size,
}, null, 2) + '\n')
console.log(`Built Chronolog WASM engine in ${output}`)

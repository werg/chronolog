// Build the WASM engine from the same pinned sources and deterministic hooks as
// the native addon. No copied second implementation of consensus functions.
/* global console, process */
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, cpSync, rmSync, statSync, utimesSync, existsSync, chmodSync } from 'node:fs'
import { dirname, relative, resolve, join } from 'node:path'
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
const packageSource = join(nativeRoot, 'amalgamation/.source')
const source = join(output, 'source')
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
// pnpm's side-effect cache deduplicates generated copies as hardlinks. Running
// configure/make in that cache can make `cp tool/lempar.c .` copy onto itself,
// and would mutate files shared with other installations. Detach the source
// tree into this build's output and regenerate its location-specific config.
const sourceMarker = join(output, 'source-profile.json')
const sourceProfile = JSON.stringify({ version: 1, source: packageSource, sha256: nativeManifest.doltliteSourceSha256 })
if (!existsSync(sourceMarker) || readFileSync(sourceMarker, 'utf8') !== sourceProfile || !existsSync(source)) {
  rmSync(source, { recursive: true, force: true })
  const generated = new Set([
    'Makefile', 'config.status', 'config.log', 'config.defines', 'sqlite_cfg.h', '.target_source', 'tsrc',
    'ext/wasm/config.make', 'ext/wasm/bld', 'ext/wasm/jswasm', 'ext/wasm/c-pp', 'ext/wasm/version-info',
  ])
  cpSync(packageSource, source, { recursive: true,
    filter: (path) => !generated.has(relative(packageSource, path).split('\\').join('/')) })
  writeFileSync(sourceMarker, sourceProfile)
}
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
#include <cstdint>
#include <limits>
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
// The native hook wraps a VFS by copying its method table. Browser VFSes may
// key their state by the original sqlite3_vfs pointer, so forward that pointer
// explicitly for storage methods while preserving the shared clock hooks.
static int ChronologVfsOpen(sqlite3_vfs*, const char* name, sqlite3_file* file, int flags, int* out) { return g_baseVfs->xOpen(g_baseVfs, name, file, flags, out); }
static int ChronologVfsDelete(sqlite3_vfs*, const char* name, int sync) { return g_baseVfs->xDelete(g_baseVfs, name, sync); }
static int ChronologVfsAccess(sqlite3_vfs*, const char* name, int flags, int* out) { return g_baseVfs->xAccess(g_baseVfs, name, flags, out); }
static int ChronologVfsFullPath(sqlite3_vfs*, const char* name, int bytes, char* out) { return g_baseVfs->xFullPathname(g_baseVfs, name, bytes, out); }
static int ChronologVfsRandom(sqlite3_vfs*, int bytes, char* out) { return g_baseVfs->xRandomness(g_baseVfs, bytes, out); }
static int ChronologVfsSleep(sqlite3_vfs*, int micros) { return g_baseVfs->xSleep(g_baseVfs, micros); }
static int ChronologVfsError(sqlite3_vfs*, int bytes, char* out) { return g_baseVfs->xGetLastError(g_baseVfs, bytes, out); }
extern "C" EMSCRIPTEN_KEEPALIVE int chronolog_wasm_init(const char* vfsName) {
  if(vfsName && *vfsName) {
    sqlite3_vfs* vfs = sqlite3_vfs_find(vfsName);
    if(!vfs) return SQLITE_NOTFOUND;
    int rc = sqlite3_vfs_register(vfs, 1); if(rc != SQLITE_OK) return rc;
  }
  if(!InstallDeterministicEngine()) return SQLITE_ERROR;
  g_chronologVfs.xOpen = ChronologVfsOpen;
  g_chronologVfs.xDelete = ChronologVfsDelete;
  g_chronologVfs.xAccess = ChronologVfsAccess;
  g_chronologVfs.xFullPathname = ChronologVfsFullPath;
  g_chronologVfs.xRandomness = ChronologVfsRandom;
  g_chronologVfs.xSleep = ChronologVfsSleep;
  if(g_baseVfs->xGetLastError) g_chronologVfs.xGetLastError = ChronologVfsError;
  return SQLITE_OK;
}
extern "C" EMSCRIPTEN_KEEPALIVE int chronolog_wasm_security(sqlite3* db) {
${security}
  return sqlite3_extended_result_codes(db, 1);
}
extern "C" EMSCRIPTEN_KEEPALIVE void chronolog_wasm_context(sqlite3* db, sqlite3_int64 time, unsigned seed, const unsigned char* actor, int length, int hasActorId, sqlite3_int64 actorId, const unsigned char* transactionId, int transactionIdLength) {
  chronologSetDeterministicContext(time, seed, actor, length, hasActorId, actorId, transactionId, transactionIdLength);
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
// xSectorSize is optional in SQLite's VFS contract. DoltLite's chunk store
// bypasses SQLite's guarded helper in two places, which traps with the OPFS
// VFS. Preserve its exact behavior on native VFSes and use SQLite's standard
// default when this optional callback is absent. This changes storage I/O,
// not SQL or the deterministic execution profile.
const amalgamation = readFileSync(join(nativeRoot, 'amalgamation/doltlite.c'), 'utf8')
const sectorCall = 'cs->file.pFile->pMethods->xSectorSize(cs->file.pFile)'
if (amalgamation.split(sectorCall).length !== 3) throw new Error('WASM_SECTOR_SIZE_SOURCE_ANCHOR_MISSING')
// SQLITE_FCNTL_HAS_MOVED is also optional. The owned OPFS namespace cannot be
// replaced by another database owner; unsupported movement detection should
// continue with the ordinary size check instead of failing every read lock.
const movedCheck = 'rc = sqlite3OsFileControl(cs->file.pFile, SQLITE_FCNTL_HAS_MOVED, &bMoved);\n  if( rc!=SQLITE_OK ) return rc;'
if (amalgamation.split(movedCheck).length !== 2) throw new Error('WASM_HAS_MOVED_SOURCE_ANCHOR_MISSING')
const portableAmalgamation = join(output, 'doltlite-wasm.c')
writeIfChanged(portableAmalgamation, amalgamation
  .replaceAll(sectorCall, 'sqlite3OsSectorSize(cs->file.pFile)')
  .replace(movedCheck, movedCheck.replace('if( rc!=SQLITE_OK )', 'if( rc!=SQLITE_OK && rc!=SQLITE_NOTFOUND )')))
for (const header of ['sqlite3.h', 'sqlite3ext.h']) {
  const destination = join(output, header)
  const bytes = readFileSync(join(nativeRoot, 'amalgamation', header))
  if (!existsSync(destination) || !readFileSync(destination).equals(bytes)) {
    if (existsSync(destination)) chmodSync(destination, 0o644)
    writeFileSync(destination, bytes)
  }
}
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
for (const file of ['sqlite3.h', 'doltlite-wasm.c']) {
  const path = join(output, file)
  if (statSync(path).mtimeMs <= makefileTime) utimesSync(path, new Date(), new Date())
}
const nativeFlags = [
  '-DSQLITE_THREADSAFE=1', '-DSQLITE_TEMP_STORE=2', '-DSQLITE_USE_URI=1',
  '-DSQLITE_OMIT_DEPRECATED', '-DSQLITE_OMIT_UTF16',
  '-DSQLITE_OMIT_LOAD_EXTENSION',
  '-DSQLITE_ENABLE_FTS5', '-DSQLITE_ENABLE_JSON1', '-DSQLITE_ENABLE_RTREE',
  '-DSQLITE_ENABLE_COLUMN_METADATA', '-DDOLTLITE_PROLLY=1',
  '-DSQLITE_WASM_SPLIT_BUILD', '-DSQLITE_PRIVATE=', '-DSQLITE_EXTRA_INIT_MUTEXED=sqlite3_wasm_extra_init',
  '-DBLAKE3_NO_SSE2=1', '-DBLAKE3_NO_SSE41=1', '-DBLAKE3_NO_AVX2=1', '-DBLAKE3_NO_AVX512=1',
  `-DSQLITE_C=${portableAmalgamation}`,
].join(' ')
const buildArguments = [
  'b-esm', 'jswasm/sqlite3-opfs-async-proxy.js', 'DOLTLITE_WASM=0', `bin.emcc=${emcc}`, 'bin.wasm-strip=true', 'bin.wasm-opt=',
  'emcc_opt=-O1', 'emcc_opt_full=-O1 -g2', 'emcc.environment.esm=web,worker,node',
  'emcc.flags=-sSTACK_SIZE=2097152 -sSTACK_OVERFLOW_CHECK=2',
  `sqlite3.c=${portableAmalgamation}`,
  `SQLITE_OPT=${nativeFlags}`,
  `EXPORTED_FUNCTIONS.api.in=${exportsPath}`,
  // The amalgamator elides os_unix's fcntl.h because os.c already includes it,
  // but os.c excludes that include under Emscripten. Supply the missing header.
  `cflags.common=-I. -I${join(nativeRoot, 'amalgamation')} -I${join(source, 'src')} -I${source} -include fcntl.h -include unistd.h -fPIC`,
  `sqlite3_wasm_extra_init.c=${shimPath}`,
  `sqlite3-wasm.c.in=api/sqlite3-wasm.c ${shimPath} ${portableAmalgamation} ${join(nativeRoot, 'amalgamation/doltlite_orig.c')} ${join(nativeRoot, 'amalgamation/sqlite_vec_static.c')}`,
]
// Make does not track command-line flag changes. A recorded configuration
// invalidates the shim input so switching build flags cannot reuse stale WASM.
const configurationPath = join(output, 'build-configuration.json')
const configuration = JSON.stringify({ compiler: compilerVersion.stdout, arguments: buildArguments })
if (!existsSync(configurationPath) || readFileSync(configurationPath, 'utf8') !== configuration) {
  writeFileSync(configurationPath, configuration)
  utimesSync(shimPath, new Date(), new Date())
}
run('make', buildArguments, wasmRoot)
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
  portabilityPatches: ['chunk-store-optional-sector-size-v1', 'chunk-store-optional-has-moved-v1', 'vfs-identity-forwarding-v1'],
  deterministicSourceSha256: digest(deterministic), wasmSha256: digest(readFileSync(join(output, 'sqlite3.wasm'))),
  wasmBytes: statSync(join(output, 'sqlite3.wasm')).size,
}, null, 2) + '\n')
console.log(`Built Chronolog WASM engine in ${output}`)

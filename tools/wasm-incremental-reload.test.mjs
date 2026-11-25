import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { applyIncrementalReloadPatch, INCREMENTAL_RELOAD_PATCH } from './lib/wasm-incremental-reload.mjs';

const nativeRequire = createRequire(join(import.meta.dirname, '../packages/materializer-doltlite/package.json'));
const amalgamation = readFileSync(join(dirname(nativeRequire.resolve('@dolthub/doltlite')), 'amalgamation/doltlite.c'), 'utf8');

test('patches the pinned amalgamation at every anchored storage seam exactly once', () => {
  const patched = applyIncrementalReloadPatch(amalgamation);
  assert.equal(patched.split(`chronolog: ${INCREMENTAL_RELOAD_PATCH}`).length, 2);
  for (const definition of ['static int csReplayWalFrom(ChunkStore *cs, i64 resume){', 'int csReplayWal(ChunkStore *cs){\n  return csReplayWalFrom(cs, 0);',
    'static int csReloadFromDiskFull(ChunkStore *cs){', 'static int csReloadFromDisk(ChunkStore *cs){', 'static int csClassifyDiskChange(ChunkStore *cs){',
    'static int csStoreMirrorsDisk(ChunkStore *cs){', '&& !csStoreMirrorsDisk(&db->aDb[0].pBt->pBt->store) ){']) {
    assert.equal(patched.split(definition).length, 2, definition);
  }
  // A full replay still starts at the WAL origin; only the appended-tail path resumes.
  assert.match(patched, /static int csReplayWalFrom\(ChunkStore \*cs, i64 resume\)\{[\s\S]*?i64 lastBoundary = resume;[\s\S]*?pos = resume;\n {2}while\( pos < walSize \)\{/u);
  // Every fast path falls back to the original whole-store reload.
  assert.match(patched, /if\( handled \) return SQLITE_OK;\n {2}return csReloadFromDiskFull\(cs\);/u);
  // Header rewrites (GC/compaction), moves and shrinks are never treated as appends.
  assert.match(patched, /CS_MANIFEST_INDEX_OFFSET_OFF\)!=cs->index\.iIndexOffset/u);
});

test('fails closed when an anchored DoltLite source changes', () => {
  for (const anchor of ['  i64 lastBoundary = 0;\n', 'static int csReloadFromDisk(ChunkStore *cs){\n  ChunkStore tmp;',
    '  pos = 0;\n  while( pos < walSize ){', 'void doltliteGetSessionConflictsCatalog(sqlite3 *db, ProllyHash *pHash){',
    'int chunkStoreReadDiskBranchTip(ChunkStore *cs, const char *zName,\n                                ProllyHash *pTip, int *pFound){']) {
    assert.ok(amalgamation.includes(anchor), anchor);
    assert.throws(() => applyIncrementalReloadPatch(amalgamation.replace(anchor, `${anchor.slice(0, -1)} `)), /WASM_INCREMENTAL_RELOAD_/u);
  }
});

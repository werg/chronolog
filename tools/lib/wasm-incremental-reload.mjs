// WASM storage portability patch: chunk-store-incremental-reload-v1.
//
// DoltLite reloads its whole chunk store (header index plus a hash-verified
// replay of the entire append-only WAL) before every version-control write and
// whenever another connection on the same file has appended. Under the browser
// OPFS SAH-pool VFS each read is a synchronous host call, so one ordinary
// materializer append reread O(history) bytes ~15 times and stalled the owner.
//
// The browser/Node WASM owner is the only writer of its storage namespace (an
// exclusive owner lock), the chunk store is append-only between GC rewrites,
// and committed bytes below a published root boundary are never rewritten.
// This patch therefore:
//   - leaves the in-memory view unchanged when the file is byte-for-byte the
//     size this connection last synchronized and its header is unchanged; and
//   - replays only the appended suffix, resuming at the connection's last
//     committed boundary, when the file has grown.
// Every other case (moved file, rewritten header, shrink, uncommitted local
// staging or refs, recovered/damaged WAL) uses the original full reload. The
// patch changes storage I/O only; SQL semantics and the execution manifest are
// unchanged, exactly like the other portability patches.

export const INCREMENTAL_RELOAD_PATCH = 'chunk-store-incremental-reload-v1'

function replaceOnce(source, anchor, replacement, code) {
  const parts = source.split(anchor)
  if (parts.length !== 2) throw new Error(code)
  return parts[0] + replacement + parts[1]
}

const replayHeader = 'int csReplayWal(ChunkStore *cs){\n  i64 walSize;'
const replayTail = '\nreplay_error:\n  if( haveTmpRefs ) csFreeRefsState(&tmpRefs);\n  csRollbackReplayState(cs, &saved, nPendingBefore);\n  return rc;\n}\n'
const reloadHeader = 'static int csReloadFromDisk(ChunkStore *cs){\n  ChunkStore tmp;'

const preservingHeader = 'static int csReloadFromDiskPreservingLocalRefs(ChunkStore *cs){'
const preservingGuard = `  /* Reloading drops aRecent; never do that with uncommitted refs to it. */
  if( cs->staging.nRecentUncommitted > 0 ){
    return SQLITE_BUSY_SNAPSHOT;
  }
`

const incrementalReload = `/* chronolog: ${INCREMENTAL_RELOAD_PATCH} */
static int csReplayWalFrom(ChunkStore *cs, i64 resume);
static int csReloadFromDiskFull(ChunkStore *cs);

/* 1: the file is exactly the bytes this connection last committed or replayed
** (no move, no header rewrite, no append); 2: only appended bytes follow this
** connection's last committed boundary; 0: anything else. */
static int csClassifyDiskChange(ChunkStore *cs){
  u8 aHdr[CHUNK_MANIFEST_SIZE];
  i64 fileSize = 0;
  int bMoved = 0;
  int rc;
  if( cs->isMemory || cs->file.pFile==0 || cs->corruptMidStream
   || cs->wal.recoveredMidStream || cs->wal.iWalOffset<=0 ){
    return 0;
  }
  rc = sqlite3OsFileControl(cs->file.pFile, SQLITE_FCNTL_HAS_MOVED, &bMoved);
  if( rc==SQLITE_NOTFOUND ){ rc = SQLITE_OK; bMoved = 0; }
  if( rc!=SQLITE_OK || bMoved ) return 0;
  if( sqlite3OsFileSize(cs->file.pFile, &fileSize)!=SQLITE_OK ) return 0;
  if( fileSize < CHUNK_MANIFEST_SIZE ) return 0;
  if( sqlite3OsRead(cs->file.pFile, aHdr, CHUNK_MANIFEST_SIZE, 0)!=SQLITE_OK ){
    return 0;
  }
  /* GC and compaction rewrite the header; only a pure WAL append keeps it. */
  if( CS_READ_U32(aHdr + CS_MANIFEST_MAGIC_OFF)!=CHUNK_STORE_MAGIC
   || CS_READ_U32(aHdr + CS_MANIFEST_VERSION_OFF)!=CHUNK_STORE_VERSION
   || CS_READ_I64(aHdr + CS_MANIFEST_INDEX_OFFSET_OFF)!=cs->index.iIndexOffset
   || (i64)CS_READ_U32(aHdr + CS_MANIFEST_INDEX_SIZE_OFF)!=cs->index.nIndexSize
   || CS_READ_I64(aHdr + CS_MANIFEST_WAL_OFFSET_OFF)!=cs->wal.iWalOffset ){
    return 0;
  }
  if( fileSize<=cs->file.iFileSize ){
    return fileSize==cs->wal.iWalOffset + cs->wal.nWalData ? 1 : 0;
  }
  return 2;
}

/* The store's in-memory index and refs are exactly the committed on-disk state. */
static int csStoreMirrorsDisk(ChunkStore *cs){
  return !cs->bRefsStale
      && prollyHashCompare(&cs->refs.refsHash, &cs->refs.committedRefsHash)==0
      && csClassifyDiskChange(cs)==1;
}

/* Replay only the appended WAL suffix. iFileSize is the last committed root's
** aligned NEXT_OFF: a record boundary below which committed bytes are
** immutable until a GC rewrite (which changes the header). */
static int csReloadAppendedTail(ChunkStore *cs, int *pHandled){
  i64 resume;
  int rc;
  int change;
  SavedRefsState liveRefs;
  *pHandled = 0;
  if( cs->bRefsStale
   || prollyHashCompare(&cs->refs.refsHash, &cs->refs.committedRefsHash)!=0 ){
    return SQLITE_OK;
  }
  change = csClassifyDiskChange(cs);
  if( change==1 ){ *pHandled = 1; return SQLITE_OK; }
  if( change!=2 ) return SQLITE_OK;
  if( cs->staging.nPending>0 ) return SQLITE_OK;
  if( cs->staging.nRecent>0 ){
    /* This connection's own committed chunks live in its recent buffer, not
    ** its index. Fold them into the index exactly as a commit does when that
    ** buffer fills; the suffix replay below then dedupes against them. */
    ChunkStore mergeView = *cs;
    ChunkIndexEntry *aMerged = 0;
    int nMerged = 0;
    mergeView.staging.aPending = cs->staging.aRecent;
    mergeView.staging.nPending = cs->staging.nRecent;
    if( csMergeIndex(&mergeView, &aMerged, &nMerged)!=SQLITE_OK ) return SQLITE_OK;
    csReleaseIndexBuf(cs->index.aIndex, cs->index.aIndexMmapBase, cs->index.aIndexMmapSize);
    cs->index.aIndex = aMerged;
    cs->index.nIndex = nMerged;
    cs->index.aIndexMmapBase = 0;
    cs->index.aIndexMmapSize = 0;
    cs->staging.nRecent = 0;
    if( cs->staging.aRecentZeroTail ){
      memset(cs->staging.aRecentZeroTail, 0, cs->staging.nRecentAlloc * sizeof(i64));
    }
    csRecentHTClear(cs);
  }
  if( cs->index.nIndex==0 ) return SQLITE_OK;
  resume = cs->file.iFileSize - cs->wal.iWalOffset;
  if( resume<0 ) return SQLITE_OK;
  csDetachSavedRefsState(cs, &liveRefs);
  rc = csReplayWalFrom(cs, resume);
  if( rc!=SQLITE_OK || cs->wal.recoveredMidStream || cs->corruptMidStream ){
    /* The caller falls back to the original full reload, which replaces the
    ** whole store state; restore owned refs so they are freed exactly once. */
    csFreeRefsState(cs);
    csRestoreSavedRefsState(cs, &liveRefs);
    return SQLITE_OK;
  }
  csFreeSavedRefsState(&liveRefs);
  csMarkRefsCommitted(cs);
  *pHandled = 1;
  return SQLITE_OK;
}

static int csReloadFromDisk(ChunkStore *cs){
  int handled = 0;
  if( cs->staging.nRecentUncommitted > 0 ){
    return SQLITE_BUSY_SNAPSHOT;
  }
  (void)csReloadAppendedTail(cs, &handled);
  if( handled ) return SQLITE_OK;
  return csReloadFromDiskFull(cs);
}

static int csReloadFromDiskPreservingLocalRefs(ChunkStore *cs){`

/* A forced reload of an unchanged file re-derives exactly the in-memory index
** and committed refs; only refs state needs the reload's semantics. */
const unchangedForceRefresh = `${preservingGuard}  if( csClassifyDiskChange(cs)==1 ){
    if( cs->staging.nPending > 0
     && prollyHashCompare(&cs->refs.refsHash, &cs->refs.committedRefsHash)!=0 ){
      return SQLITE_OK;
    }
    if( cs->bRefsStale
     || prollyHashCompare(&cs->refs.refsHash, &cs->refs.committedRefsHash)!=0 ){
      return csRestoreCommittedRefsState(cs);
    }
    return SQLITE_OK;
  }
`

const diskTipOpen = `  rc = chunkStoreOpen(&tmp, cs->file.pVfs, cs->file.zFilename,
                      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_MAIN_DB);
  if( rc!=SQLITE_OK ) return rc;
  if( chunkStoreFindBranch(&tmp, zName, pTip)==SQLITE_OK ) *pFound = 1;`

/* The head CAS reads the committed on-disk tip through a throwaway full open.
** When the file is exactly this connection's last synchronized bytes, that tip
** is in the committed refs blob this connection already indexes. */
const unchangedDiskTip = `  if( csClassifyDiskChange(cs)==1 && !prollyHashIsEmpty(&cs->refs.committedRefsHash) ){
    if( !cs->bRefsStale
     && prollyHashCompare(&cs->refs.refsHash, &cs->refs.committedRefsHash)==0 ){
      if( chunkStoreFindBranch(cs, zName, pTip)==SQLITE_OK ) *pFound = 1;
      return SQLITE_OK;
    }else{
      u8 *refsData = 0;
      int nRefsData = 0;
      if( chunkStoreGet(cs, &cs->refs.committedRefsHash, &refsData, &nRefsData)==SQLITE_OK && refsData ){
        rc = csDeserializeRefsIntoTemp(&tmp, refsData, nRefsData);
        sqlite3_free(refsData);
        if( rc==SQLITE_OK && chunkStoreFindBranch(&tmp, zName, pTip)==SQLITE_OK ) *pFound = 1;
        csFreeRefsState(&tmp);
        if( rc==SQLITE_OK ) return SQLITE_OK;
        *pFound = 0;
      }
    }
  }
`

/* Reading the persisted merge-conflict catalog opened a second, full
** read-only connection per call (once per commit). The connection's own store
** answers identically when it mirrors the committed file. */
const conflictsDefinition = 'void doltliteGetSessionConflictsCatalog(sqlite3 *db, ProllyHash *pHash){'
const conflictsReopen = '  if( db->autoCommit && sqlite3_txn_state(db, "main")==SQLITE_TXN_NONE ){\n    sqlite3 *db2 = 0;'
const conflictsMirrored = '  if( db->autoCommit && sqlite3_txn_state(db, "main")==SQLITE_TXN_NONE\n   && !csStoreMirrorsDisk(&db->aDb[0].pBt->pBt->store) ){\n    sqlite3 *db2 = 0;'

/** Apply the incremental-reload storage patch to the pinned DoltLite amalgamation. */
export function applyIncrementalReloadPatch(amalgamation) {
  const start = amalgamation.indexOf(replayHeader)
  if (start < 0 || amalgamation.indexOf(replayHeader, start + 1) >= 0) throw new Error('WASM_INCREMENTAL_RELOAD_REPLAY_ANCHOR_MISSING')
  const end = amalgamation.indexOf(replayTail, start)
  if (end < 0) throw new Error('WASM_INCREMENTAL_RELOAD_REPLAY_TAIL_MISSING')
  let replay = amalgamation.slice(start, end + replayTail.length)
  replay = replaceOnce(replay, replayHeader, 'static int csReplayWalFrom(ChunkStore *cs, i64 resume){\n  i64 walSize;', 'WASM_INCREMENTAL_RELOAD_REPLAY_ANCHOR_MISSING')
  replay = replaceOnce(replay, '  i64 lastBoundary = 0;\n', '  i64 lastBoundary = resume;\n', 'WASM_INCREMENTAL_RELOAD_BOUNDARY_ANCHOR_MISSING')
  replay = replaceOnce(replay, '  pos = 0;\n  while( pos < walSize ){', '  pos = resume;\n  while( pos < walSize ){', 'WASM_INCREMENTAL_RELOAD_POSITION_ANCHOR_MISSING')
  replay += 'int csReplayWal(ChunkStore *cs){\n  return csReplayWalFrom(cs, 0);\n}\n'
  let patched = amalgamation.slice(0, start) + replay + amalgamation.slice(end + replayTail.length)
  patched = replaceOnce(patched, reloadHeader, 'static int csReloadFromDiskFull(ChunkStore *cs){\n  ChunkStore tmp;', 'WASM_INCREMENTAL_RELOAD_RELOAD_ANCHOR_MISSING')
  const preserving = patched.indexOf(preservingHeader)
  if (preserving < 0 || patched.indexOf(preservingHeader, preserving + 1) >= 0) throw new Error('WASM_INCREMENTAL_RELOAD_PRESERVING_ANCHOR_MISSING')
  const guard = patched.indexOf(preservingGuard, preserving)
  if (guard < 0 || guard > preserving + 400) throw new Error('WASM_INCREMENTAL_RELOAD_PRESERVING_GUARD_MISSING')
  patched = patched.slice(0, preserving) + incrementalReload + patched.slice(preserving + preservingHeader.length, guard) +
    unchangedForceRefresh + patched.slice(guard + preservingGuard.length)
  const tipDefinition = 'int chunkStoreReadDiskBranchTip(ChunkStore *cs, const char *zName,\n                                ProllyHash *pTip, int *pFound){'
  const tipStart = patched.indexOf(tipDefinition)
  if (tipStart < 0 || patched.indexOf(tipDefinition, tipStart + 1) >= 0 || tipStart < patched.indexOf('static int csClassifyDiskChange(ChunkStore *cs){')) throw new Error('WASM_INCREMENTAL_RELOAD_DISK_TIP_ANCHOR_MISSING')
  const tipOpen = patched.indexOf(diskTipOpen, tipStart)
  if (tipOpen < 0 || tipOpen > tipStart + 1200) throw new Error('WASM_INCREMENTAL_RELOAD_DISK_TIP_ANCHOR_MISSING')
  patched = patched.slice(0, tipOpen) + unchangedDiskTip + patched.slice(tipOpen)
  const conflicts = patched.indexOf(conflictsDefinition)
  if (conflicts < 0 || patched.indexOf(conflictsDefinition, conflicts + 1) >= 0 || conflicts < patched.indexOf('static int csStoreMirrorsDisk(ChunkStore *cs){')) throw new Error('WASM_INCREMENTAL_RELOAD_CONFLICTS_ANCHOR_MISSING')
  const reopen = patched.indexOf(conflictsReopen, conflicts)
  if (reopen < 0 || reopen > conflicts + 800) throw new Error('WASM_INCREMENTAL_RELOAD_CONFLICTS_ANCHOR_MISSING')
  return patched.slice(0, reopen) + conflictsMirrored + patched.slice(reopen + conflictsReopen.length)
}

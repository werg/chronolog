#include "sqlite3.h"
#include "sqlite-vec.h"
#include <emscripten/emscripten.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/*
 * Chronolog v2 SQLite-over-CAS WASM Engine
 * - Stock SQLite + FTS5 + sqlite-vec
 * - Minimal VFS delegating page I/O to host Merkle-paged CAS (4 KiB pages)
 * - Deterministic clock (VFS xCurrentTime = op_time(), localtime = fixed UTC)
 * - Disabled random()/randomblob()
 * - Kernel-bound actor(), op_id(), op_time() SQL scalar functions
 * - Three-mode sqlite3_set_authorizer: admin (0), user (1), readonly (2)
 */

/* Host JS callbacks installed on Module._casHooks */
EM_JS(int, js_cas_read, (double offset, void* buf, int amt), {
  return Module._casHooks.read(offset, buf, amt);
});
EM_JS(int, js_cas_write, (double offset, const void* buf, int amt), {
  return Module._casHooks.write(offset, buf, amt);
});
EM_JS(int, js_cas_truncate, (double size), {
  return Module._casHooks.truncate(size);
});
EM_JS(double, js_cas_filesize, (), {
  return Module._casHooks.filesize();
});
EM_JS(int, js_ddl_authorize, (int action, const char* arg1, const char* arg2), {
  return Module._casHooks.ddlAuthorize(action, arg1 ? UTF8ToString(arg1) : "", arg2 ? UTF8ToString(arg2) : "");
});

/* Override localtime/localtime_r in WASM libc so SQLite 'localtime' modifier is ALWAYS fixed UTC! */
struct tm* localtime_r(const time_t* timer, struct tm* result) {
  return gmtime_r(timer, result);
}
struct tm* localtime(const time_t* timer) {
  return gmtime(timer);
}

/* Kernel-bound execution context (never set from JS reducer arguments) */
static char g_actor[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static char g_op_id[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static sqlite3_int64 g_op_time_ms = 0;
static int g_auth_mode = 0; /* 0 = admin, 1 = user, 2 = readonly */

/* ── Minimal CAS VFS ──────────────────────────────────────────────────────── */

typedef struct {
  sqlite3_file base;
  int is_main;
} CasFile;

static int casClose(sqlite3_file* f) { (void)f; return SQLITE_OK; }
static int casRead(sqlite3_file* f, void* buf, int iAmt, sqlite3_int64 iOfst) {
  CasFile* cf = (CasFile*)f;
  if (!cf->is_main) { memset(buf, 0, (size_t)iAmt); return SQLITE_IOERR_SHORT_READ; }
  return js_cas_read((double)iOfst, buf, iAmt);
}
static int casWrite(sqlite3_file* f, const void* buf, int iAmt, sqlite3_int64 iOfst) {
  CasFile* cf = (CasFile*)f;
  if (!cf->is_main) return SQLITE_OK;
  return js_cas_write((double)iOfst, buf, iAmt);
}
static int casTruncate(sqlite3_file* f, sqlite3_int64 size) {
  CasFile* cf = (CasFile*)f;
  if (!cf->is_main) return SQLITE_OK;
  return js_cas_truncate((double)size);
}
static int casSync(sqlite3_file* f, int flags) { (void)f; (void)flags; return SQLITE_OK; }
static int casFileSize(sqlite3_file* f, sqlite3_int64* pSize) {
  CasFile* cf = (CasFile*)f;
  *pSize = cf->is_main ? (sqlite3_int64)js_cas_filesize() : 0;
  return SQLITE_OK;
}
static int casLock(sqlite3_file* f, int eLock) { (void)f; (void)eLock; return SQLITE_OK; }
static int casUnlock(sqlite3_file* f, int eLock) { (void)f; (void)eLock; return SQLITE_OK; }
static int casCheckReservedLock(sqlite3_file* f, int* pResOut) { (void)f; *pResOut = 0; return SQLITE_OK; }
static int casFileControl(sqlite3_file* f, int op, void* pArg) {
  (void)f;
  if (op == SQLITE_FCNTL_SIZE_HINT) return SQLITE_OK;
  if (op == SQLITE_FCNTL_PRAGMA) return SQLITE_NOTFOUND;
  (void)pArg;
  return SQLITE_NOTFOUND;
}
static int casSectorSize(sqlite3_file* f) { (void)f; return 4096; }
static int casDeviceCharacteristics(sqlite3_file* f) {
  (void)f;
  return SQLITE_IOCAP_ATOMIC4K | SQLITE_IOCAP_SAFE_APPEND | SQLITE_IOCAP_SEQUENTIAL;
}

static const sqlite3_io_methods g_cas_io = {
  1, casClose, casRead, casWrite, casTruncate, casSync, casFileSize,
  casLock, casUnlock, casCheckReservedLock, casFileControl, casSectorSize, casDeviceCharacteristics
};

static int vfsOpen(sqlite3_vfs* vfs, const char* zName, sqlite3_file* pFile, int flags, int* pOutFlags) {
  (void)vfs;
  CasFile* cf = (CasFile*)pFile;
  cf->base.pMethods = &g_cas_io;
  cf->is_main = (flags & SQLITE_OPEN_MAIN_DB) != 0 && zName != NULL && strcmp(zName, "cas.db") == 0;
  if (pOutFlags) *pOutFlags = flags;
  return SQLITE_OK;
}
static int vfsDelete(sqlite3_vfs* vfs, const char* zName, int syncDir) { (void)vfs; (void)zName; (void)syncDir; return SQLITE_OK; }
static int vfsAccess(sqlite3_vfs* vfs, const char* zName, int flags, int* pResOut) {
  (void)vfs; (void)flags;
  *pResOut = (zName && strcmp(zName, "cas.db") == 0 && js_cas_filesize() > 0) ? 1 : 0;
  return SQLITE_OK;
}
static int vfsFullPathname(sqlite3_vfs* vfs, const char* zName, int nOut, char* zOut) {
  (void)vfs;
  strncpy(zOut, zName ? zName : "cas.db", (size_t)(nOut - 1));
  zOut[nOut - 1] = '\0';
  return SQLITE_OK;
}
static int vfsRandomness(sqlite3_vfs* vfs, int nByte, char* zOut) {
  (void)vfs;
  /* Deterministic zero fill; SQL random() is separately disabled. */
  memset(zOut, 0, (size_t)nByte);
  return nByte;
}
static int vfsSleep(sqlite3_vfs* vfs, int microseconds) { (void)vfs; (void)microseconds; return 0; }
static int vfsCurrentTimeInt64(sqlite3_vfs* vfs, sqlite3_int64* piNow) {
  (void)vfs;
  /* Unix epoch 1970-01-01 00:00:00 UTC in Julian day milliseconds = 210866760000000 */
  *piNow = 210866760000000LL + g_op_time_ms;
  return SQLITE_OK;
}
static int vfsCurrentTime(sqlite3_vfs* vfs, double* prNow) {
  sqlite3_int64 ms = 0;
  vfsCurrentTimeInt64(vfs, &ms);
  *prNow = (double)ms / 86400000.0;
  return SQLITE_OK;
}

static sqlite3_vfs g_cas_vfs = {
  2,
  sizeof(CasFile),
  256,
  NULL,
  "chronolog-cas",
  NULL,
  vfsOpen,
  vfsDelete,
  vfsAccess,
  vfsFullPathname,
  NULL, NULL, NULL, NULL,
  vfsRandomness,
  vfsSleep,
  vfsCurrentTime,
  NULL,
  vfsCurrentTimeInt64
};

/* ── Deterministic SQL functions ──────────────────────────────────────────── */

static void fnActor(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  (void)argc; (void)argv;
  sqlite3_result_text(ctx, g_actor, 64, SQLITE_TRANSIENT);
}
static void fnOpId(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  (void)argc; (void)argv;
  sqlite3_result_text(ctx, g_op_id, 64, SQLITE_TRANSIENT);
}
static void fnOpTime(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  (void)argc; (void)argv;
  sqlite3_result_int64(ctx, g_op_time_ms);
}
static void fnDisabledRandom(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  (void)argc; (void)argv;
  sqlite3_result_error(ctx, "NONDETERMINISTIC_SQL_RANDOM_DISABLED", -1);
}

/* ── Three-mode authorizer ────────────────────────────────────────────────── */

static int startsWithNoCase(const char* s, const char* prefix) {
  if (!s || !prefix) return 0;
  return strncasecmp(s, prefix, strlen(prefix)) == 0;
}

static int isReservedTable(const char* name) {
  return startsWithNoCase(name, "_rls_") || startsWithNoCase(name, "sqlite_");
}

static int isAllowedVtab(const char* mod) {
  if (!mod) return 0;
  return strcasecmp(mod, "fts5") == 0 || strcasecmp(mod, "vec0") == 0;
}

static int chronologAuthorizer(
  void* userData,
  int action,
  const char* arg1,
  const char* arg2,
  const char* dbName,
  const char* triggerOrView
) {
  (void)userData;
  (void)dbName;

  /* Always forbid attach/detach/temp/random */
  if (action == SQLITE_ATTACH || action == SQLITE_DETACH ||
      action == SQLITE_CREATE_TEMP_TABLE || action == SQLITE_CREATE_TEMP_INDEX ||
      action == SQLITE_CREATE_TEMP_TRIGGER || action == SQLITE_CREATE_TEMP_VIEW ||
      action == SQLITE_DROP_TEMP_TABLE || action == SQLITE_DROP_TEMP_INDEX ||
      action == SQLITE_DROP_TEMP_TRIGGER || action == SQLITE_DROP_TEMP_VIEW) {
    return SQLITE_DENY;
  }
  if (action == SQLITE_FUNCTION && arg2 &&
      (strcasecmp(arg2, "random") == 0 || strcasecmp(arg2, "randomblob") == 0 ||
       strcasecmp(arg2, "sqlite_compileoption_used") == 0 || strcasecmp(arg2, "sqlite_compileoption_get") == 0)) {
    return SQLITE_DENY;
  }

  /* mode 2 = readonly: strictly SELECT, READ, FUNCTION, and read-only page_size/data_version (for vec0/fts5) */
  if (g_auth_mode == 2) {
    if (action == SQLITE_SELECT || action == SQLITE_READ || action == SQLITE_FUNCTION) {
      return SQLITE_OK;
    }
    if (action == SQLITE_PRAGMA && arg1 && arg2 == NULL &&
        (strcasecmp(arg1, "page_size") == 0 || strcasecmp(arg1, "data_version") == 0)) {
      return SQLITE_OK;
    }
    return SQLITE_DENY;
  }

  /* mode 0 = admin: allow DDL + DML + triggers (except unsafe pragmas/vtables) */
  if (g_auth_mode == 0) {
    if (action == SQLITE_CREATE_VTABLE || action == SQLITE_DROP_VTABLE) {
      return isAllowedVtab(arg2) ? SQLITE_OK : SQLITE_DENY;
    }
    if (action == SQLITE_PRAGMA) {
      if (arg1 && (
          strcasecmp(arg1, "table_info") == 0 || strcasecmp(arg1, "index_list") == 0 ||
          strcasecmp(arg1, "table_xinfo") == 0 || strcasecmp(arg1, "foreign_key_list") == 0 ||
          (arg2 == NULL && (strcasecmp(arg1, "page_size") == 0 || strcasecmp(arg1, "data_version") == 0)))) {
        return SQLITE_OK;
      }
      return SQLITE_DENY;
    }
    return SQLITE_OK;
  }

  /* mode 1 = user: DML allowed (excluding _rls_ writes; sqlite_master direct DML is blocked by DEFENSIVE=1), triggers ALWAYS forbidden, optional DDL allowlist */
  if (action == SQLITE_SELECT || action == SQLITE_READ || action == SQLITE_FUNCTION || action == SQLITE_RECURSIVE) {
    return SQLITE_OK;
  }
  if (action == SQLITE_INSERT || action == SQLITE_UPDATE || action == SQLITE_DELETE) {
    /* Allow triggers installed by admin (_rls_*) to read, never allow user SQL to mutate _rls_* tables;
       sqlite_master/sqlite_schema internal DDL writes are allowed here because DEFENSIVE=1 blocks direct user DML on them. */
    if (startsWithNoCase(arg1, "_rls_") && (!triggerOrView || !startsWithNoCase(triggerOrView, "_rls_"))) {
      return SQLITE_DENY;
    }
    if (startsWithNoCase(arg1, "sqlite_") && strcasecmp(arg1, "sqlite_master") != 0 && strcasecmp(arg1, "sqlite_schema") != 0) {
      return SQLITE_DENY;
    }
    return SQLITE_OK;
  }
  if (action == SQLITE_PRAGMA) {
    /* Allow read-only page_size and data_version pragmas required internally by FTS5 and sqlite-vec (vec0) during DML. */
    if (arg1 && arg2 == NULL &&
        (strcasecmp(arg1, "page_size") == 0 || strcasecmp(arg1, "data_version") == 0)) {
      return SQLITE_OK;
    }
    return SQLITE_DENY;
  }
  if (action == SQLITE_CREATE_TRIGGER || action == SQLITE_DROP_TRIGGER ||
      action == SQLITE_ANALYZE || action == SQLITE_TRANSACTION || action == SQLITE_SAVEPOINT) {
    return SQLITE_DENY;
  }
  if (action == SQLITE_REINDEX) {
    if (startsWithNoCase(arg1, "_rls_")) return SQLITE_DENY;
    return js_ddl_authorize(action, arg1, arg2) ? SQLITE_OK : SQLITE_DENY;
  }
  if (action == SQLITE_CREATE_VTABLE || action == SQLITE_DROP_VTABLE) {
    if (!isAllowedVtab(arg2) || isReservedTable(arg1)) return SQLITE_DENY;
    return js_ddl_authorize(action, arg1, arg2) ? SQLITE_OK : SQLITE_DENY;
  }
  if (action == SQLITE_CREATE_INDEX || action == SQLITE_DROP_INDEX) {
    if (startsWithNoCase(arg1, "_rls_") || isReservedTable(arg2)) return SQLITE_DENY;
    return js_ddl_authorize(action, arg1, arg2) ? SQLITE_OK : SQLITE_DENY;
  }
  if (action == SQLITE_CREATE_TABLE || action == SQLITE_DROP_TABLE || action == SQLITE_ALTER_TABLE ||
      action == SQLITE_CREATE_VIEW || action == SQLITE_DROP_VIEW) {
    if (isReservedTable(arg1) || isReservedTable(arg2)) return SQLITE_DENY;
    return js_ddl_authorize(action, arg1, arg2) ? SQLITE_OK : SQLITE_DENY;
  }
  return SQLITE_DENY;
}

/* ── Exported C API ───────────────────────────────────────────────────────── */

EMSCRIPTEN_KEEPALIVE int chronolog_init(void) {
  int rc = sqlite3_vfs_register(&g_cas_vfs, 1);
  if (rc != SQLITE_OK) return rc;
  return sqlite3_auto_extension((void(*)(void))sqlite3_vec_init);
}

EMSCRIPTEN_KEEPALIVE void chronolog_set_context(const char* actor, const char* opId, double opTimeMs) {
  if (actor && strlen(actor) == 64) { memcpy(g_actor, actor, 65); }
  if (opId && strlen(opId) == 64) { memcpy(g_op_id, opId, 65); }
  g_op_time_ms = (sqlite3_int64)opTimeMs;
}

EMSCRIPTEN_KEEPALIVE void chronolog_set_mode(int mode) {
  g_auth_mode = mode;
}

EMSCRIPTEN_KEEPALIVE sqlite3* chronolog_open(void) {
  sqlite3* db = NULL;
  int rc = sqlite3_open_v2("cas.db", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "chronolog-cas");
  if (rc != SQLITE_OK || !db) {
    if (db) sqlite3_close_v2(db);
    return NULL;
  }
  int applied = 0;
  sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, &applied);
  sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, &applied);
  sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, &applied);
  sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DML, 0, &applied);
  sqlite3_db_config(db, SQLITE_DBCONFIG_DQS_DDL, 0, &applied);
  sqlite3_extended_result_codes(db, 1);

  /* Register deterministic kernel-bound functions and disable random() */
  int detFlags = SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS;
  sqlite3_create_function_v2(db, "actor", 0, detFlags, NULL, fnActor, NULL, NULL, NULL);
  sqlite3_create_function_v2(db, "op_id", 0, detFlags, NULL, fnOpId, NULL, NULL, NULL);
  sqlite3_create_function_v2(db, "op_time", 0, detFlags, NULL, fnOpTime, NULL, NULL, NULL);
  sqlite3_create_function_v2(db, "random", 0, SQLITE_UTF8, NULL, fnDisabledRandom, NULL, NULL, NULL);
  sqlite3_create_function_v2(db, "randomblob", 1, SQLITE_UTF8, NULL, fnDisabledRandom, NULL, NULL, NULL);

  /* Configure deterministic in-memory journal & fixed 4 KiB page size BEFORE installing authorizer */
  g_auth_mode = 0;
  sqlite3_set_authorizer(db, NULL, NULL);
  rc = sqlite3_exec(db,
    "PRAGMA page_size = 4096;"
    "PRAGMA journal_mode = MEMORY;"
    "PRAGMA synchronous = OFF;"
    "PRAGMA temp_store = MEMORY;"
    "PRAGMA foreign_keys = ON;"
    "PRAGMA recursive_triggers = ON;",
    NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    sqlite3_close_v2(db);
    return NULL;
  }
  sqlite3_set_authorizer(db, chronologAuthorizer, NULL);
  sqlite3_set_last_insert_rowid(db, 0);
  return db;
}

EMSCRIPTEN_KEEPALIVE int chronolog_close(sqlite3* db) {
  if (!db) return SQLITE_OK;
  sqlite3_set_authorizer(db, NULL, NULL);
  return sqlite3_close_v2(db);
}

EMSCRIPTEN_KEEPALIVE const char* chronolog_errmsg(sqlite3* db) {
  return db ? sqlite3_errmsg(db) : "SQLITE_NULL_DB";
}

EMSCRIPTEN_KEEPALIVE int chronolog_changes(sqlite3* db) {
  return db ? sqlite3_changes(db) : 0;
}

EMSCRIPTEN_KEEPALIVE double chronolog_last_insert_rowid(sqlite3* db) {
  return db ? (double)sqlite3_last_insert_rowid(db) : 0.0;
}

EMSCRIPTEN_KEEPALIVE void chronolog_reset_rowid(sqlite3* db) {
  if (db) sqlite3_set_last_insert_rowid(db, 0);
}

/* Prepare a single statement; rejects if pzTail has trailing non-whitespace when requireSingle != 0. */
EMSCRIPTEN_KEEPALIVE int chronolog_prepare(sqlite3* db, const char* sql, int requireSingle, sqlite3_stmt** outStmt, const char** outTail) {
  const char* tail = NULL;
  sqlite3_stmt* stmt = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, &tail);
  if (rc != SQLITE_OK) {
    if (stmt) sqlite3_finalize(stmt);
    *outStmt = NULL;
    if (outTail) *outTail = NULL;
    return rc;
  }
  if (requireSingle && tail) {
    const char* p = tail;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ';') p++;
    if (*p != '\0') {
      if (stmt) sqlite3_finalize(stmt);
      *outStmt = NULL;
      if (outTail) *outTail = tail;
      return SQLITE_MISUSE;
    }
  }
  *outStmt = stmt;
  if (outTail) *outTail = tail;
  return SQLITE_OK;
}

EMSCRIPTEN_KEEPALIVE int chronolog_step(sqlite3_stmt* stmt) { return sqlite3_step(stmt); }
EMSCRIPTEN_KEEPALIVE int chronolog_finalize(sqlite3_stmt* stmt) { return sqlite3_finalize(stmt); }
EMSCRIPTEN_KEEPALIVE int chronolog_bind_null(sqlite3_stmt* s, int i) { return sqlite3_bind_null(s, i); }
EMSCRIPTEN_KEEPALIVE int chronolog_bind_int64(sqlite3_stmt* s, int i, double v) { return sqlite3_bind_int64(s, i, (sqlite3_int64)v); }
EMSCRIPTEN_KEEPALIVE int chronolog_bind_double(sqlite3_stmt* s, int i, double v) { return sqlite3_bind_double(s, i, v); }
EMSCRIPTEN_KEEPALIVE int chronolog_bind_text(sqlite3_stmt* s, int i, const char* t, int len) { return sqlite3_bind_text(s, i, t, len, SQLITE_TRANSIENT); }
EMSCRIPTEN_KEEPALIVE int chronolog_bind_blob(sqlite3_stmt* s, int i, const void* b, int len) { return sqlite3_bind_blob(s, i, b, len, SQLITE_TRANSIENT); }
EMSCRIPTEN_KEEPALIVE int chronolog_column_count(sqlite3_stmt* s) { return sqlite3_column_count(s); }
EMSCRIPTEN_KEEPALIVE const char* chronolog_column_name(sqlite3_stmt* s, int i) { return sqlite3_column_name(s, i); }
EMSCRIPTEN_KEEPALIVE int chronolog_column_type(sqlite3_stmt* s, int i) { return sqlite3_column_type(s, i); }
EMSCRIPTEN_KEEPALIVE double chronolog_column_double(sqlite3_stmt* s, int i) { return sqlite3_column_double(s, i); }
EMSCRIPTEN_KEEPALIVE const char* chronolog_column_text(sqlite3_stmt* s, int i) { return (const char*)sqlite3_column_text(s, i); }
EMSCRIPTEN_KEEPALIVE int chronolog_column_bytes(sqlite3_stmt* s, int i) { return sqlite3_column_bytes(s, i); }
EMSCRIPTEN_KEEPALIVE const void* chronolog_column_blob(sqlite3_stmt* s, int i) { return sqlite3_column_blob(s, i); }

/*
 * Validate that a user-authored RLS SQL expression is a single pure read-only SQL expression
 * using SQLite's own parser in mode=2 (readonly) with zero trailing statements.
 */
EMSCRIPTEN_KEEPALIVE int chronolog_validate_expr(sqlite3* db, const char* testSql) {
  int prev = g_auth_mode;
  g_auth_mode = 2;
  sqlite3_stmt* stmt = NULL;
  const char* tail = NULL;
  int rc = chronolog_prepare(db, testSql, 1, &stmt, &tail);
  if (stmt) sqlite3_finalize(stmt);
  g_auth_mode = prev;
  return rc;
}

import { digestEngineManifest, normalizeEngineManifest } from './engine-manifest.js'
import { assertNativeSecurityConfiguration, configureSqliteLimits } from './sql-profile.js'
import type { DatabaseLike, EngineBuildManifest, SqlEngine } from './types.js'

/** Both adapters enter the same verified SQL security and build-identity boundary. */
export function configureSqlDatabase(database: DatabaseLike, manifest: EngineBuildManifest): ReturnType<SqlEngine['openDatabase']> {
  try {
    for (const method of ['setAuthorizer', 'setProgressHandler', 'setLimit', 'interrupt', 'configureSecurity',
      'doltCommit', 'doltBranch', 'doltCheckout', 'doltResetHard', 'doltForceBranch', 'doltDeleteBranch',
      'doltHashOf', 'doltVersion', 'doltBranches', 'doltActiveBranch'] as const) {
      if (typeof database[method] !== 'function') throw new Error(`MATERIALIZER_ENGINE_API_MISSING:${method}`)
    }
    const nativeManifest = normalizeEngineManifest(manifest)
    const security = database.configureSecurity()
    assertNativeSecurityConfiguration(security)
    configureSqliteLimits(database)
    // REPLACE must run delete triggers so the shared ownership check also applies.
    database.exec('PRAGMA foreign_keys = ON; PRAGMA recursive_triggers = ON; PRAGMA trusted_schema = OFF')
    if (Number(scalar(database, 'PRAGMA recursive_triggers')) !== 1) throw new Error('MATERIALIZER_RECURSIVE_TRIGGERS_UNAVAILABLE')
    const sqliteVersion = scalar(database, 'SELECT sqlite_version()')
    if (typeof sqliteVersion !== 'string') throw new Error('MATERIALIZER_SQLITE_VERSION_UNAVAILABLE')
    let vecVersion: string | null = null
    try { const version = scalar(database, 'SELECT vec_version()'); if (typeof version === 'string') vecVersion = version }
    catch { /* An unavailable optional extension is represented explicitly. */ }
    return { database, security, backend: { engine: 'doltlite', version: database.doltVersion(), sqliteVersion,
      vecVersion, nativeManifest, engineDigest: digestEngineManifest(nativeManifest), securityConfigured: true } }
  } catch (error) { database.close(); throw error }
}

function scalar(database: DatabaseLike, sql: string): unknown {
  const statement = database.prepare(sql)
  try {
    const row = statement.get()
    return row === undefined ? undefined : Array.isArray(row) ? row[0] : Object.values(row)[0]
  } finally { statement.finalize?.() }
}

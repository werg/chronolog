import { digestEngineManifest, engineManifestDescriptor, normalizeEngineManifest } from './engine-manifest.js'
import { DatabaseSync, chronologNativeManifest, chronologTriggerUsesIgnore } from '@dolthub/doltlite'

import type {
  DatabaseLike,
  MaterializerBackendInfo,
  MaterializerOptions,
  EngineBuildManifest,
  SecurityConfiguration,
} from './types.js'
import { discoverPublishedRef } from './checkpoints.js'
import { readRootAdministrator } from './platform/schema.js'
import { assertNativeSecurityConfiguration, configureSqliteLimits } from './sql-profile.js'

export interface OpenedDatabase {
  readonly database: DatabaseLike
  readonly backend: MaterializerBackendInfo
  readonly security: SecurityConfiguration
}

export interface NativeEngineInfo {
  readonly manifest: EngineBuildManifest
  readonly descriptor: string
  readonly digest: Uint8Array
}

/** Read the linked native build identity before a database is opened. */
export function readNativeEngineInfo(): NativeEngineInfo {
  const manifest = normalizeEngineManifest(chronologNativeManifest())
  return {
    manifest,
    descriptor: engineManifestDescriptor(manifest),
    digest: digestEngineManifest(manifest),
  }
}

/**
 * Opens a materialized database read-only for offline inspection (fork seeding,
 * verification), positioned on the published revision when one exists. It
 * never participates in consensus execution.
 */
export function openReadOnlyDatabase(path: string): DatabaseLike {
  const database = nativeDatabase(path, true)
  try {
    assertNativeSecurityConfiguration(database.configureSecurity())
    const published = discoverPublishedRef(database)
    if (published !== null) database.doltCheckout(published.branchRef)
    return database
  } catch (error) {
    database.close()
    throw error
  }
}

/** The genesis root administrator stored in a materialized database, read offline. */
export function readMaterializedRootAdministrator(path: string): Uint8Array {
  const database = openReadOnlyDatabase(path)
  try {
    return readRootAdministrator(database)
  } finally {
    database.close()
  }
}

export function openDatabase(options: Pick<MaterializerOptions, 'path'>): OpenedDatabase {
  const path = options.path
  if (path === undefined || path === ':memory:') {
    throw new Error('MATERIALIZER_PERSISTENT_PATH_REQUIRED')
  }
  const database = nativeDatabase(path)
  try {
    assertNativeContract(database)
    const security = database.configureSecurity()
    assertNativeSecurityConfiguration(security)
    configureSqliteLimits(database)
    database.exec('PRAGMA foreign_keys = ON')
    // Part of the execution profile (manifest `recursiveTriggers`): REPLACE
    // deletions fire delete triggers, so the platform's delete check applies.
    database.exec('PRAGMA recursive_triggers = ON')
    database.exec('PRAGMA trusted_schema = OFF')
    if (readPragma(database, 'recursive_triggers') !== 1) throw new Error('MATERIALIZER_RECURSIVE_TRIGGERS_UNAVAILABLE')
    const native = readNativeEngineInfo()
    return {
      database,
      backend: {
        engine: 'doltlite',
        version: database.doltVersion(),
        sqliteVersion: readSqliteVersion(database),
        vecVersion: readOptionalScalar(database, 'SELECT vec_version() AS version'),
        nativeManifest: native.manifest,
        engineDigest: native.digest,
        securityConfigured: true,
      },
      security,
    }
  } catch (error) {
    database.close()
    throw error
  }
}

function readPragma(database: DatabaseLike, name: 'recursive_triggers'): number {
  const row = database.prepare(`PRAGMA ${name}`).get()
  if (row === undefined || Array.isArray(row)) throw new Error('MATERIALIZER_PRAGMA_UNAVAILABLE')
  return Number(row[name])
}

function readOptionalScalar(database: DatabaseLike, sql: string): string | null {
  try {
    const row = database.prepare(sql).get()
    if (row === undefined || Array.isArray(row) || typeof row.version !== 'string') return null
    return row.version
  } catch {
    return null
  }
}

function readSqliteVersion(database: DatabaseLike): string {
  const row = database.prepare('SELECT sqlite_version() AS version').get()
  if (row === undefined || Array.isArray(row) || typeof row.version !== 'string') {
    throw new Error('MATERIALIZER_SQLITE_VERSION_UNAVAILABLE')
  }
  return row.version
}

function assertNativeContract(database: DatabaseLike): void {
  const required = [
    'setAuthorizer',
    'setProgressHandler',
    'setLimit',
    'interrupt',
    'configureSecurity',
    'doltCommit',
    'doltBranch',
    'doltCheckout',
    'doltResetHard',
    'doltForceBranch',
    'doltDeleteBranch',
    'doltHashOf',
    'doltVersion',
    'doltBranches',
    'doltActiveBranch',
  ] as const
  for (const method of required) {
    if (typeof database[method] !== 'function') {
      throw new Error(`MATERIALIZER_NATIVE_API_MISSING:${method}`)
    }
  }
}

function nativeDatabase(path: string, readOnly = false): DatabaseLike {
  return Object.assign(new DatabaseSync(path, { readOnly }), { triggerUsesIgnore: chronologTriggerUsesIgnore }) as unknown as DatabaseLike
}

import { DatabaseSync, chronologNativeManifest, chronologTriggerUsesIgnore } from '@dolthub/doltlite'
import { digestEngineManifest, engineManifestDescriptor, normalizeEngineManifest } from './engine-manifest.js'
import { configureSqlDatabase } from './database.js'
import type { DatabaseLike, EngineBuildManifest, SqlEngine } from './types.js'

export interface NativeEngineInfo {
  readonly manifest: EngineBuildManifest
  readonly descriptor: string
  readonly digest: Uint8Array
}

/** Read the linked native build identity before a database is opened. */
export function readNativeEngineInfo(): NativeEngineInfo {
  const manifest = normalizeEngineManifest(chronologNativeManifest())
  return { manifest, descriptor: engineManifestDescriptor(manifest), digest: digestEngineManifest(manifest) }
}

export const openDatabase: SqlEngine['openDatabase'] = ({ path }) => {
  if (typeof path !== 'string' || path.length === 0 || path === ':memory:') throw new Error('MATERIALIZER_PERSISTENT_PATH_REQUIRED')
  const manifest = readNativeEngineInfo().manifest
  const database = Object.assign(new DatabaseSync(path), { triggerUsesIgnore: chronologTriggerUsesIgnore }) as unknown as DatabaseLike
  return configureSqlDatabase(database, manifest)
}

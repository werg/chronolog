import { sha256Sync, utf8 } from '@chronolog/canonical'
import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import type { EngineBuildManifest } from './types.js'

const strings = ['doltliteVersion', 'doltliteSourceSha256', 'sqliteVecVersion', 'sqliteVecSourceSha256', 'chronologPatchProfile'] as const
const flags = ['fts5', 'json1', 'rtree', 'dynamicExtensions'] as const

/** Capture the same closed build identity from the native addon or WASM artifact. */
export function normalizeEngineManifest(value: unknown): EngineBuildManifest {
  const invalid = (): never => { throw new Error('MATERIALIZER_ENGINE_MANIFEST_INVALID') }
  if (typeof value !== 'object' || value === null || Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== strings.length + flags.length) return invalid()
  const result: Record<string, string | boolean> = {}
  for (const key of [...strings, ...flags]) {
    const property = Object.getOwnPropertyDescriptor(value, key)
    if (property === undefined || !property.enumerable || !('value' in property)) return invalid()
    const item: unknown = property.value
    if (strings.some(field => field === key)) {
      if (typeof item !== 'string' || item.length < 1 || item.length > 1024) return invalid()
      result[key] = item
    } else {
      if (typeof item !== 'boolean') return invalid()
      result[key] = item
    }
  }
  for (const key of ['doltliteSourceSha256', 'sqliteVecSourceSha256'] as const) {
    if (!/^[0-9a-f]{64}$/u.test(result[key] as string)) return invalid()
  }
  return result as unknown as EngineBuildManifest
}

/** One versioned canonical descriptor, independent of the engine's host runtime. */
export function engineManifestDescriptor(manifest: EngineBuildManifest): string {
  const captured = normalizeEngineManifest(manifest)
  return `chronolog-engine-manifest-v1\n${canonicalJson(captured as unknown as EventPayload, { maxBytes: 4096, maxNodes: 16, maxDepth: 2 })}`
}

export function digestEngineManifest(manifest: EngineBuildManifest): Uint8Array {
  return sha256Sync(utf8(engineManifestDescriptor(manifest)))
}

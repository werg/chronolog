import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@chronolog/canonical'
import { digestEngineManifest, engineManifestDescriptor, normalizeEngineManifest } from './engine-manifest.js'
import type { EngineBuildManifest } from './types.js'

const manifest: EngineBuildManifest = {
  doltliteVersion: '0.11.29', doltliteSourceSha256: '01'.repeat(32),
  sqliteVecVersion: '0.1.9', sqliteVecSourceSha256: '23'.repeat(32),
  chronologPatchProfile: 'deterministic-test-v1', fts5: true, json1: true, rtree: true, dynamicExtensions: false,
}

describe('shared engine build identity', () => {
  it('has one stable descriptor and digest across native/WASM object key order', () => {
    const reordered = Object.fromEntries(Object.entries(manifest).reverse()) as unknown as EngineBuildManifest
    expect(engineManifestDescriptor(reordered)).toBe(engineManifestDescriptor(manifest))
    expect(bytesToHex(digestEngineManifest(manifest))).toBe('feb8271920aebc8abe32249317a2cc34ba718ca4519bab09010458b8088b812c')
    expect(digestEngineManifest(reordered)).toEqual(digestEngineManifest(manifest))
    expect(digestEngineManifest({ ...manifest, dynamicExtensions: true })).not.toEqual(digestEngineManifest(manifest))
  })

  it('captures a closed, bounded data-only build identity before engine construction', () => {
    const supplied = { ...manifest }, captured = normalizeEngineManifest(supplied)
    supplied.chronologPatchProfile = 'later-mutation'
    expect(captured.chronologPatchProfile).toBe(manifest.chronologPatchProfile)
    for (const invalid of [null, [], { ...manifest, extra: true }, { ...manifest, fts5: 1 },
      { ...manifest, doltliteSourceSha256: 'bad' }, { ...manifest, chronologPatchProfile: 'x'.repeat(1025) }]) {
      expect(() => normalizeEngineManifest(invalid)).toThrow('MATERIALIZER_ENGINE_MANIFEST_INVALID')
    }
    const accessor = { ...manifest }
    Object.defineProperty(accessor, 'fts5', { enumerable: true, get() { throw new Error('getter must not execute') } })
    expect(() => normalizeEngineManifest(accessor)).toThrow('MATERIALIZER_ENGINE_MANIFEST_INVALID')
  })
})

import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from './bytes-store.js'
import { ContentAddressedStore, computeCasHash } from './cas.js'

describe('ContentAddressedStore', () => {
  it('stores and verifies explicit-link DAG nodes with public/private partition isolation', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store })

    const leafPub = await cas.put(new TextEncoder().encode('public-module'), [], 'public')
    const leafPriv = await cas.put(new TextEncoder().encode('private-page'), [], 'private')
    const rootPriv = await cas.put(new TextEncoder().encode('root'), [leafPub, leafPriv], 'private')

    expect(leafPub).toBe(computeCasHash(new TextEncoder().encode('public-module')))
    expect(cas.getSync(leafPub, 'public')?.bytes).toEqual(new TextEncoder().encode('public-module'))
    expect(cas.getSync(leafPriv, 'public')).toBeNull()
    expect(await cas.get(leafPriv, 'public')).toBeNull()
    expect(cas.getSync(leafPriv, 'private')?.bytes).toEqual(new TextEncoder().encode('private-page'))
    expect(cas.getSync(rootPriv, 'any')?.links).toEqual([leafPub, leafPriv].sort())
  })

  it('supports staged replay batches with rollback and filtered flush', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store })

    cas.beginBatch()
    const discarded = cas.putSync(new Uint8Array([1, 2, 3]), [], 'private')
    expect(cas.getSync(discarded, 'private')).not.toBeNull()
    cas.rollbackBatch()
    // After rollback, nothing hit the durable store
    const cas2 = new ContentAddressedStore({ store })
    await cas2.preload()
    expect(await cas2.get(discarded, 'any')).toBeNull()

    cas.beginBatch()
    const keepLeaf = cas.putSync(new Uint8Array([10]), [], 'private')
    const dropLeaf = cas.putSync(new Uint8Array([20]), [], 'private')
    const keepRoot = cas.putSync(new Uint8Array([30]), [keepLeaf], 'private')
    const reachable = await cas.reachable([keepRoot])
    expect(reachable.has(keepLeaf)).toBe(true)
    expect(reachable.has(dropLeaf)).toBe(false)
    await cas.flushBatch(reachable)

    const reloaded = new ContentAddressedStore({ store })
    await reloaded.preload()
    expect((await reloaded.get(keepRoot, 'private'))?.bytes).toEqual(new Uint8Array([30]))
    expect((await reloaded.get(keepLeaf, 'private'))?.bytes).toEqual(new Uint8Array([10]))
    expect(await reloaded.get(dropLeaf, 'any')).toBeNull()
  })

  it('collects unreachable garbage while preserving explicit link graphs', async () => {
    const store = new MemoryBytesStore()
    const cas = new ContentAddressedStore({ store })

    const liveChild = await cas.put(new Uint8Array([1]), [], 'private')
    const liveRoot = await cas.put(new Uint8Array([2]), [liveChild], 'private')
    const deadChild = await cas.put(new Uint8Array([3]), [], 'private')
    const deadRoot = await cas.put(new Uint8Array([4]), [deadChild], 'private')

    const gc = await cas.collectGarbage([liveRoot])
    expect(gc).toEqual({ kept: 2, deleted: 2 })
    expect(await cas.get(liveRoot, 'any')).not.toBeNull()
    expect(await cas.get(liveChild, 'any')).not.toBeNull()
    expect(await cas.get(deadRoot, 'any')).toBeNull()
    expect(await cas.get(deadChild, 'any')).toBeNull()
  })
})

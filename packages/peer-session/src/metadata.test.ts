import { describe, expect, it, vi } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { updateDeviceMetadata } from './metadata.js'

describe('shared protocol metadata', () => {
  it('serializes transforms on one store and keeps unchanged records unwritten', async () => {
    const store = new MemoryBytesStore(), put = vi.spyOn(store, 'put')
    const increment = (current: Uint8Array | null) => Promise.resolve(Uint8Array.of((current?.[0] ?? 0) + 1))
    const results = await Promise.all([updateDeviceMetadata(store, 'control', increment), updateDeviceMetadata(store, 'control', increment)])
    expect(results.map(value => value[0])).toEqual([1, 2])
    await updateDeviceMetadata(store, 'control', async value => value!)
    expect(put).toHaveBeenCalledTimes(2)
  })

  it('revalidates after an atomic conflict and does not overwrite a newer learned record', async () => {
    const store = new MemoryBytesStore()
    await store.put('control', Uint8Array.of(1))
    const observations: number[] = []
    const shared = { get: (key: string) => store.get(key), put: vi.fn(),
      compareAndSwap: vi.fn(async () => { await store.put('control', Uint8Array.of(3)); return false }) }
    const selected = await updateDeviceMetadata(shared, 'control', async current => {
      observations.push(current![0]!)
      return Uint8Array.of(Math.max(current![0]!, 2))
    })
    expect(observations).toEqual([1, 3]); expect(selected).toEqual(Uint8Array.of(3))
    expect(shared.put).not.toHaveBeenCalled(); expect(shared.compareAndSwap).toHaveBeenCalledTimes(1)
  })

  it('releases failed metadata work without replaying its transform', async () => {
    const store = new MemoryBytesStore(), failed = vi.fn(async () => { throw new Error('INVALID_AUTHORITY') })
    await expect(updateDeviceMetadata(store, 'control', failed)).rejects.toThrow('INVALID_AUTHORITY')
    expect(failed).toHaveBeenCalledTimes(1)
    await expect(updateDeviceMetadata(store, 'control', async () => Uint8Array.of(1))).resolves.toEqual(Uint8Array.of(1))
  })
})

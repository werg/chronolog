import { describe, expect, it, vi } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/protocol'
import { MemoryBytesStore, type BytesStore } from '@chronolog/peer-generation'
import { openApplicationDevice } from './device.js'

describe('owned application device identities', () => {
  it('keeps protocol identity independent of lazy data storage and coalesces first use', async () => {
    const metadata = new MemoryBytesStore(), data = new MemoryBytesStore(), closed = vi.fn()
    const openStorage = vi.fn(async () => ({ store: data, close: closed }))
    const device = await openApplicationDevice({ store: metadata, create: true, openStorage })
    const identity = device.identity, storageId = device.storageId
    expect(openStorage).not.toHaveBeenCalled()
    expect(device.store).toBe(metadata)
    const first = device.openStorage(), second = device.openStorage()
    expect(first).toBe(second)
    expect((await first).store).toBe(data)
    expect(openStorage).toHaveBeenCalledTimes(1)
    expect(device.identity).toBe(identity); expect(device.storageId).toBe(storageId)
    await (await first).close(); await device.close(); await device.close()
    expect(closed).toHaveBeenCalledTimes(1)
    await expect(device.openStorage()).rejects.toThrow('APPLICATION_DEVICE_CLOSED')
    const resumed = await openApplicationDevice({ store: metadata, openStorage })
    expect(resumed.identity.publicKey).toBe(identity.publicKey)
    expect(resumed.storageId).toBe(storageId)
    await resumed.close()
    expect(openStorage).toHaveBeenCalledTimes(1)
  })

  it('never opens unused data storage and drains an opening resource before closing metadata', async () => {
    const unopened = vi.fn(), unused = await openApplicationDevice({ store: new MemoryBytesStore(), create: true,
      openStorage: unopened })
    await unused.close(); expect(unopened).not.toHaveBeenCalled()
    const order: string[] = [], metadata = new MemoryBytesStore()
    let release!: () => void
    const wait = new Promise<void>(resolve => { release = resolve })
    const opening = vi.fn(async () => { await wait; return { store: new MemoryBytesStore(), close() { order.push('data') } } })
    const device = await openApplicationDevice({ store: metadata, create: true, openStorage: opening, close() { order.push('metadata') } })
    const pending = device.openStorage(), checked = expect(pending).rejects.toThrow('APPLICATION_DEVICE_CLOSED')
    await vi.waitFor(() => { expect(opening).toHaveBeenCalledTimes(1) })
    const closing = device.close()
    expect(order).toEqual([])
    release(); await Promise.all([checked, closing])
    expect(order).toEqual(['data', 'metadata'])
  })

  it('retains the first storage failure without reopening or changing the signer', async () => {
    const openStorage = vi.fn(async () => { throw new Error('QUOTA_DENIED') })
    const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true, openStorage })
    const identity = device.identity
    await expect(device.openStorage()).rejects.toThrow('QUOTA_DENIED')
    await expect(device.openStorage()).rejects.toThrow('QUOTA_DENIED')
    expect(openStorage).toHaveBeenCalledTimes(1); expect(device.identity).toBe(identity)
    await device.close()
  })

  it('refuses lost or mismatched data storage without replacing the protocol identity', async () => {
    const metadata = new MemoryBytesStore(), data = new MemoryBytesStore()
    const original = await openApplicationDevice({ store: metadata, create: true, openStorage: () => ({ store: data, close() {} }) })
    await original.openStorage(); await original.close()
    const released = vi.fn(), empty = new MemoryBytesStore()
    const lost = await openApplicationDevice({ store: metadata, openStorage: () => ({ store: empty, close: released }) })
    expect(lost.identity.publicKey).toBe(original.identity.publicKey)
    await expect(lost.openStorage()).rejects.toThrow('APPLICATION_DATA_STORAGE_MISSING')
    expect(released).toHaveBeenCalledTimes(1)
    expect(await empty.get('peer-session/storage-binding/v1')).toBeNull()
    await lost.close(); expect(released).toHaveBeenCalledTimes(1)
    const replacement = await openApplicationDevice({ store: new MemoryBytesStore(), create: true,
      openStorage: () => ({ store: data, close() {} }) })
    await expect(replacement.openStorage()).rejects.toThrow('APPLICATION_DATA_STORAGE_BINDING_INVALID')
    await replacement.close()
  })

  it('uses the atomically retained identity when concurrent protocol owners create the same device', async () => {
    const store = new MemoryBytesStore()
    let tail: Promise<void> = Promise.resolve()
    const shared = { get: (key: string) => store.get(key), put: (key: string, value: Uint8Array) => store.put(key, value),
      initialize(entries: readonly { readonly key: string; readonly value: Uint8Array }[]) {
        const result = tail.then(async () => {
          const values = await Promise.all(entries.map(entry => store.get(entry.key)))
          if (values.every(value => value === null)) for (const entry of entries) await store.put(entry.key, entry.value)
        })
        tail = result; return result
      } }
    const [first, second] = await Promise.all([openApplicationDevice({ store: shared, create: true }), openApplicationDevice({ store: shared, create: true })])
    expect(first.identity.publicKey).toBe(second.identity.publicKey)
    expect(first.storageId).toBe(second.storageId)
    await first.close(); await second.close()
  })

  it('never recreates lost keys when the device storage binding already exists', async () => {
    const retained = new MemoryBytesStore()
    await openApplicationDevice({ store: retained, create: true })
    let writes = 0
    const damaged: BytesStore = { get: key => key === 'peer-session/device/v1' ? Promise.resolve(null) : retained.get(key),
      put: async () => { writes++ } }
    await expect(openApplicationDevice({ store: damaged })).rejects.toThrow('APPLICATION_DEVICE_KEYS_MISSING')
    await expect(openApplicationDevice({ store: damaged, create: true })).rejects.toThrow('APPLICATION_DEVICE_KEYS_MISSING')
    expect(writes).toBe(0)
  })

  it('verifies the signing private key when resuming the stored identity', async () => {
    const first = new MemoryBytesStore(), second = new MemoryBytesStore()
    await openApplicationDevice({ store: first, create: true }); await openApplicationDevice({ store: second, create: true })
    const original = assertCanonicalCbor((await first.get('peer-session/device/v1'))!), other = assertCanonicalCbor((await second.get('peer-session/device/v1'))!)
    if (!Array.isArray(original) || !Array.isArray(other)) throw new Error('fixture')
    await first.put('peer-session/device/v1', encodeCanonicalCbor(original.map((item, index) => index === 2 ? other[2]! : item)))
    await expect(openApplicationDevice({ store: first })).rejects.toThrow('APPLICATION_DEVICE_KEY_MISMATCH')
  })
})

import { describe, expect, it } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/protocol'
import { MemoryBytesStore, type BytesStore } from '@chronolog/peer-generation'
import { openApplicationDevice } from './device.js'

describe('owned application device identities', () => {
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

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { NativeBytesStore } from './native.js'

it('accounts incremental writes, replacements and failures under exclusive ownership across reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-bytes-')), path = join(directory, 'peer.sqlite')
  let store = new NativeBytesStore(path, { quotaBytes: 1024 })
  try {
    for (let index = 0; index < 64; index++) await store.put(`record/${index}`, new Uint8Array(16))
    expect(store.usageBytes()).toBe(1024)
    await expect(store.put('overflow', new Uint8Array(1))).rejects.toThrow('AGENT_STORE_QUOTA_EXCEEDED')
    expect(await store.get('overflow')).toBeNull()
    expect(store.usageBytes()).toBe(1024)
    await store.put('record/0', new Uint8Array(7))
    expect(store.usageBytes()).toBe(1015)
    expect(() => new NativeBytesStore(path)).toThrow('AGENT_STORE_IN_USE')
    store.close()
    store = new NativeBytesStore(path, { quotaBytes: 1024 })
    expect(store.usageBytes()).toBe(1015)
    await store.put('after-reopen', new Uint8Array(9))
    expect(store.usageBytes()).toBe(1024)
  } finally { store.close(); await rm(directory, { recursive: true, force: true }) }
})

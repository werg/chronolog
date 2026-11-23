import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { NativeBytesStore } from '@chronolog/records/native'
import { CONTENT_CHUNK_BYTES } from './content.js'
import { fixture } from './content-test-fixture.js'

it('durably reclaims native content quota across interrupted prune, close, and reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-content-prune-')), path = join(directory, 'content.sqlite')
  const f = await fixture()
  let store = await NativeBytesStore.open(path, { quotaBytes: 512 * 1024 })
  try {
    await store.put('application/keep', Uint8Array.of(7, 8, 9))
    let fail = false
    const content = f.openContent(0, {
      get: key => store.get(key), put: (key, bytes) => store.put(key, bytes),
      delete: async key => {
        if (fail && key.includes('/stage/')) { fail = false; throw new Error('interrupted deletion') }
        await store.delete(key)
      },
    })
    const body = new Uint8Array(CONTENT_CHUNK_BYTES * 3 + 31).fill(43)
    const ref = await content.putBytes(body, { mediaType: 'audio/ogg' })
    expect(await content.readBytes(ref, { maxBytes: body.length })).toEqual(body)
    expect(store.usageBytes()).toBeGreaterThan(body.length)
    fail = true
    await expect(content.prune(ref)).rejects.toThrow('interrupted deletion')
    content.close(); await store.close()
    store = await NativeBytesStore.open(path, { quotaBytes: 512 * 1024 })
    const reopened = f.openContent(0, store)
    await expect(reopened.readBytes(ref, { maxBytes: body.length })).rejects.toThrow('CONTENT_PRUNED')
    await reopened.prune(ref); await reopened.prune(ref)
    expect(await store.entries()).toEqual([{ key: 'application/keep', value: Uint8Array.of(7, 8, 9) }])
    expect(store.usageBytes()).toBe(3)
    reopened.close(); await store.close()
    store = await NativeBytesStore.open(path, { quotaBytes: 512 * 1024 })
    expect(store.usageBytes()).toBe(3)
    expect(await store.get('application/keep')).toEqual(Uint8Array.of(7, 8, 9))
    await expect(f.openContent(0, store).readBytes(ref, { maxBytes: body.length })).rejects.toThrow('CONTENT_UNAVAILABLE')
  } finally { await store.close(); await rm(directory, { recursive: true, force: true }) }
})

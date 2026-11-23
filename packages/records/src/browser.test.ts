import { describe, expect, it } from 'vitest'

import { OpfsBytesStore, type OpfsDirectory } from './browser.js'

function directory() {
  const values = new Map<string, Uint8Array>()
  let failClose = false
  const handles: OpfsDirectory = {
    async removeEntry(name) { if (!values.delete(name)) throw new DOMException('absent', 'NotFoundError') },
    async getFileHandle(name, options) {
      if (!values.has(name)) {
        if (!options?.create) throw new DOMException('absent', 'NotFoundError')
        values.set(name, new Uint8Array())
      }
      return {
        async getFile() { return { arrayBuffer: async () => values.get(name)!.slice().buffer } },
        async createWritable() {
          let staged = new Uint8Array()
          return {
            async write(bytes) { staged = new Uint8Array(bytes.slice(0)) },
            async close() {
              if (failClose) throw new DOMException('full', 'QuotaExceededError')
              values.set(name, staged.slice())
            },
            async abort() { staged = new Uint8Array() },
          }
        },
      }
    },
  }
  return { handles, values, failWrites: () => { failClose = true } }
}

describe('OPFS atomic bytes', () => {
  it('durably deletes only the selected value and remains idempotent across reopen', async () => {
    const { handles, values } = directory(), store = new OpfsBytesStore(handles)
    await store.put('media/transient', new Uint8Array(65536))
    await store.put('application/keep', Uint8Array.of(7))
    await store.delete('media/transient'); await store.delete('media/transient')
    expect(values.size).toBe(1)
    await store.close()
    const reopened = new OpfsBytesStore(handles)
    expect(await reopened.get('media/transient')).toBeNull()
    expect(await reopened.get('application/keep')).toEqual(Uint8Array.of(7))
    await reopened.close()
  })

  it('reopens exact committed values and makes private namespaces independent', async () => {
    const { handles } = directory()
    let store = new OpfsBytesStore(handles)
    await store.put('signer/private', Uint8Array.of(1, 2))
    await store.put('authority/current', Uint8Array.of(3))
    await store.close()
    store = new OpfsBytesStore(handles)
    expect(await store.get('signer/private')).toEqual(Uint8Array.of(1, 2))
    expect(await store.get('authority/current')).toEqual(Uint8Array.of(3))
    expect(await store.get('missing')).toBeNull()
  })

  it('keeps the previous value when publication fails and exposes quota failure', async () => {
    const { handles, failWrites } = directory()
    const store = new OpfsBytesStore(handles)
    await store.put('operation/1', Uint8Array.of(1))
    failWrites()
    await expect(store.put('operation/1', Uint8Array.of(2))).rejects.toMatchObject({ name: 'QuotaExceededError' })
    expect(await new OpfsBytesStore(handles).get('operation/1')).toEqual(Uint8Array.of(1))
    await expect(store.put('operation/2', Uint8Array.of(2))).rejects.toThrow()
    expect(await new OpfsBytesStore(handles).get('operation/2')).toBeNull()
  })

  it('detects corrupted committed bytes and snapshots caller input before asynchronous write', async () => {
    const { handles, values } = directory()
    const store = new OpfsBytesStore(handles)
    const input = Uint8Array.of(4)
    const pending = store.put('a', input)
    input[0] = 7
    await pending
    const captured = await store.get('a')
    expect(captured).toEqual(Uint8Array.of(4))
    captured![0] = 9
    expect(await store.get('a')).toEqual(Uint8Array.of(4))
    const key = [...values.keys()][0]!
    const damaged = values.get(key)!.slice()
    damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1
    values.set(key, damaged)
    await expect(store.get('a')).rejects.toThrow('OPFS_VALUE_CORRUPT')
  })
})

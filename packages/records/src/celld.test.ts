import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'

import { CelldBytesStore, CelldPrivateBytesStore, type CelldBytesStorage } from './celld.js'

const opened: DatabaseSync[] = []
afterEach(() => { for (const db of opened.splice(0)) db.close() })

function storage(): CelldBytesStorage {
  const db = new DatabaseSync(':memory:')
  opened.push(db)
  return {
    sql: {
      exec(query, ...bindings) {
        const statement = db.prepare(query)
        const rows = statement.all(...bindings)
        return { toArray: () => rows }
      },
    },
    transactionSync(operation) {
      db.exec('BEGIN IMMEDIATE')
      try {
        const result = operation()
        db.exec('COMMIT')
        return result
      } catch (error) {
        db.exec('ROLLBACK')
        throw error
      }
    },
  }
}

describe('celld record storage', () => {
  it('keeps initialization atomic, counts replacements, and refuses stale compare-and-swap after reopening', async () => {
    const sqlite = storage()
    const options = { quotaBytes: 5 }
    const store = new CelldBytesStore(sqlite, options)
    const original = Uint8Array.of(1, 2, 3)
    await store.initialize([{ key: 'signer', value: original }, { key: 'binding', value: Uint8Array.of(4) }])
    await store.initialize([{ key: 'signer', value: Uint8Array.of(9) }, { key: 'uncommitted', value: Uint8Array.of(9) }])
    expect(await store.get('uncommitted')).toBeNull()
    expect(await store.get('signer')).toEqual(original)
    expect(store.usageBytes()).toBe(4)

    await expect(store.put('oversize', Uint8Array.of(8, 8))).rejects.toThrow('BYTES_STORE_QUOTA_EXCEEDED')
    expect(await store.get('oversize')).toBeNull()
    store.close()
    const reopened = new CelldBytesStore(sqlite, options)
    expect(reopened.usageBytes()).toBe(4)
    expect(await reopened.compareAndSwap('signer', Uint8Array.of(9), Uint8Array.of())).toBe(false)
    expect(await reopened.compareAndSwap('signer', original, Uint8Array.of())).toBe(true)
    expect(await reopened.get('signer')).toEqual(Uint8Array.of())
    expect(reopened.usageBytes()).toBe(1)
    await expect(store.get('binding')).rejects.toThrow('BYTES_STORE_CLOSED')
  })

  it('stores none of a device initialization that exceeds the total quota', async () => {
    const store = new CelldBytesStore(storage(), { quotaBytes: 3 })
    await expect(store.initialize([
      { key: 'signer', value: Uint8Array.of(1, 2) },
      { key: 'binding', value: Uint8Array.of(3, 4) },
    ])).rejects.toThrow('BYTES_STORE_QUOTA_EXCEEDED')
    expect(await store.get('signer')).toBeNull()
    expect(await store.get('binding')).toBeNull()
    expect(store.usageBytes()).toBe(0)
  })

  it('retains private device records and their quota within the selected KV namespace', async () => {
    let committed = new Map<string, unknown>()
    const kvStorage = {
      kv: { get: (key: string) => committed.get(key), put: (key: string, value: unknown) => { committed.set(key, value) } },
      transactionSync<T>(operation: () => T): T {
        const previous = committed
        committed = new Map(previous)
        try { return operation() } catch (error) { committed = previous; throw error }
      },
    }
    const metadata = new CelldPrivateBytesStore(kvStorage, { quotaBytes: 4 })
    const other = new CelldPrivateBytesStore(kvStorage, { namespace: 'control' })
    const original = Uint8Array.of(1, 2, 3)
    await metadata.initialize([{ key: 'signer', value: original }, { key: 'binding', value: Uint8Array.of(4) }])
    original[0] = 99
    const decoded = await metadata.get('signer')
    decoded!.fill(99)
    expect(await metadata.get('signer')).toEqual(Uint8Array.of(1, 2, 3))
    expect(await other.get('signer')).toBeNull()
    await expect(metadata.put('overflow', Uint8Array.of(5))).rejects.toThrow('BYTES_STORE_QUOTA_EXCEEDED')
    metadata.close()
    const reopened = new CelldPrivateBytesStore(kvStorage)
    expect(reopened.usageBytes()).toBe(4)
    expect(await reopened.compareAndSwap('signer', original, Uint8Array.of())).toBe(false)
    expect(await reopened.compareAndSwap('signer', Uint8Array.of(1, 2, 3), Uint8Array.of())).toBe(true)
    expect(reopened.usageBytes()).toBe(1)
    expect(await reopened.get('overflow')).toBeNull()
  })
})

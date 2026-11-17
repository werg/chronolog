import type { BytesStore } from '@chronolog/records'
import type { DeviceMetadataStore } from './device.js'

const owners = new WeakMap<BytesStore, Map<string, Promise<void>>>()

/** Preserve one monotonic metadata record across async verification and tabs. */
export function updateDeviceMetadata(store: BytesStore, key: string,
  update: (current: Uint8Array | null) => Promise<Uint8Array>,
): Promise<Uint8Array> {
  let keys = owners.get(store)
  if (keys === undefined) { keys = new Map(); owners.set(store, keys) }
  const previous = keys.get(key) ?? Promise.resolve()
  const task = previous.then(async () => {
    const shared = store as DeviceMetadataStore
    for (let attempt = 0; attempt < 32; attempt++) {
      const current = await store.get(key), next = await update(current?.slice() ?? null)
      if (current !== null && same(current, next)) return next
      if (shared.compareAndSwap === undefined) {
        // Memory adapters share this per-key owner; native stores already have
        // exclusive process ownership. Browser metadata uses atomic IDB CAS.
        await store.put(key, next); return next
      }
      if (await shared.compareAndSwap(key, current, next)) return next
    }
    throw new Error('APPLICATION_METADATA_CONTENTION')
  })
  const settled = task.then(() => undefined, () => undefined)
  keys.set(key, settled)
  void settled.then(() => { if (keys.get(key) === settled) keys.delete(key) })
  return task
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index])
}

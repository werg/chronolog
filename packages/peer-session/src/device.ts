import { useDeviceStore } from './checkpoint-lifecycle.js'
import type { BytesStore } from '@chronolog/records'
import { createPeerIdentity, type PeerIdentity } from '@chronolog/peer-generation/control'
import { assertCanonicalCbor, encodeCanonicalCbor, exportEd25519PrivateKey, hexToBytes, importEd25519PrivateKey, importEd25519PublicKey } from '@chronolog/protocol'

export interface ApplicationDevice {
  readonly identity: PeerIdentity
  readonly storageId: string
  /** Small identity and verified-control metadata, independent of application data. */
  readonly store: BytesStore
  /** Acquire the application's durable store once, only when data is actually used. */
  openStorage(): Promise<ApplicationStorage>
  close(): void | Promise<void>
}
export interface ApplicationStorage { readonly store: BytesStore; close(): void | Promise<void> }
/** Shared browser metadata can initialize the signer and its binding atomically. */
export interface DeviceMetadataStore extends BytesStore {
  initialize?(entries: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<void>
  compareAndSwap?(key: string, expected: Uint8Array | null, value: Uint8Array): Promise<boolean>
}
import { assertDeviceNotRetired } from './checkpoint.js'
const DEVICE_KEY = 'peer-session/device/v1'
const DEVICE_BINDING = 'peer-session/device-binding/v1'
const STORAGE_BINDING = 'peer-session/storage-binding/v1'
const STORAGE_OPENED = 'peer-session/storage-opened/v1'
const claimed = new WeakSet<ApplicationDevice>()

/** Explicit setup can create once. Resume never replaces a missing or inconsistent signer. */
export async function openApplicationDevice(options: {
  readonly store: DeviceMetadataStore
  readonly create?: true
  readonly openStorage?: () => ApplicationStorage | Promise<ApplicationStorage>
  readonly close?: () => void | Promise<void>
}): Promise<ApplicationDevice> {
  const releaseOpening = useDeviceStore(options.store)
  try {
  await assertDeviceNotRetired(options.store)
  let raw = await options.store.get(DEVICE_KEY), binding = await options.store.get(DEVICE_BINDING)
  // Atomic initialization can commit between these separate metadata reads.
  // Its immutable binding confirms creation finished; check the signer again
  // before treating an earlier missing value as lost keys.
  if (raw === null && binding !== null) raw = await options.store.get(DEVICE_KEY)
  let identity: PeerIdentity, storageId: string
  if (raw === null) {
    if (binding !== null) throw new Error('APPLICATION_DEVICE_KEYS_MISSING')
    if (options.create !== true) throw new Error('APPLICATION_DEVICE_NOT_FOUND')
    const candidate = await createPeerIdentity(), candidateStorageId = crypto.randomUUID()
    const entries = [
      { key: DEVICE_BINDING, value: encodeCanonicalCbor([candidate.publicKey, candidateStorageId]) },
      { key: DEVICE_KEY, value: encodeCanonicalCbor([1n, candidate.publicKey,
        await exportEd25519PrivateKey(candidate.privateKey), candidateStorageId]) },
    ]
    if (options.store.initialize !== undefined) await options.store.initialize(entries)
    else for (const entry of entries) await options.store.put(entry.key, entry.value)
    // Another tab may have atomically created the same named device. Both use
    // the winning signer; neither creates a second identity for durable data.
    raw = await options.store.get(DEVICE_KEY); binding = await options.store.get(DEVICE_BINDING)
    if (raw === null) throw new Error(binding === null ? 'APPLICATION_DEVICE_NOT_FOUND' : 'APPLICATION_DEVICE_KEYS_MISSING')
  }
  {
    const value = assertCanonicalCbor(raw)
    if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || typeof value[1] !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(value[1]) || !(value[2] instanceof Uint8Array) || typeof value[3] !== 'string' ||
        value[3].length > 128 || value[3].length === 0) throw new Error('APPLICATION_DEVICE_INVALID')
    identity = { publicKey: value[1], privateKey: await importEd25519PrivateKey(value[2]) }; storageId = value[3]
    if (binding === null || !sameBytes(binding, encodeCanonicalCbor([identity.publicKey, storageId]))) throw new Error('APPLICATION_DEVICE_BINDING_INVALID')
    const proof = new TextEncoder().encode('chronolog/device-resume/v1')
    const signature = await crypto.subtle.sign('Ed25519', identity.privateKey, proof)
    if (!await crypto.subtle.verify('Ed25519', await importEd25519PublicKey(hexToBytes(identity.publicKey)), signature, proof)) {
      throw new Error('APPLICATION_DEVICE_KEY_MISMATCH')
    }
  }
  let closed = false, storage: ApplicationStorage | undefined
  let opening: Promise<ApplicationStorage> | undefined, closing: Promise<void> | undefined
  return Object.freeze({ identity: Object.freeze(identity), storageId, store: options.store,
    openStorage() {
      if (closed) return Promise.reject(new Error('APPLICATION_DEVICE_CLOSED'))
      return opening ??= Promise.resolve().then(async () => {
        if (closed) throw new Error('APPLICATION_DEVICE_CLOSED')
        const resource = options.openStorage === undefined ? { store: options.store, close() {} } : await options.openStorage()
        let releasing: Promise<void> | undefined
        const acquired: ApplicationStorage = Object.freeze({ store: resource.store,
          close: () => releasing ??= Promise.resolve().then(() => resource.close()) })
        storage = acquired
        try {
          if (closed) throw new Error('APPLICATION_DEVICE_CLOSED')
          const expected = encodeCanonicalCbor([identity.publicKey, storageId])
          const opened = await options.store.get(STORAGE_OPENED), retained = await acquired.store.get(STORAGE_BINDING)
          if (opened !== null && !sameBytes(opened, expected) || retained !== null && !sameBytes(retained, expected)) {
            throw new Error('APPLICATION_DATA_STORAGE_BINDING_INVALID')
          }
          if (opened !== null && retained === null) throw new Error('APPLICATION_DATA_STORAGE_MISSING')
          if (retained === null) await acquired.store.put(STORAGE_BINDING, expected)
          // Once this flag is durable, losing the data store is an explicit
          // failure, never a new empty replica claiming the old storage identity.
          if (opened === null) await options.store.put(STORAGE_OPENED, expected)
          if (closed) throw new Error('APPLICATION_DEVICE_CLOSED')
          return acquired
        } catch (error) {
          storage = undefined
          try { await acquired.close() } catch { /* Preserve the opening failure. */ }
          throw error
        }
      })
    },
    close() {
      if (closing !== undefined) return closing
      closed = true
      closing = (async () => {
        try { await opening?.catch(() => undefined); await storage?.close() }
        finally { await options.close?.() }
      })()
      return closing
    },
  })
  } finally { releaseOpening() }
}
export function claimApplicationDevice(device: ApplicationDevice): () => void {
  if (claimed.has(device)) throw new Error('APPLICATION_DEVICE_IN_USE')
  const release = useDeviceStore(device.store)
  claimed.add(device)
  return () => { claimed.delete(device); release() }
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]) }

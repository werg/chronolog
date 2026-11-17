import type { BytesStore } from '@chronolog/records'
import { createPeerIdentity, type PeerIdentity } from '@chronolog/peer-generation/control'
import { assertCanonicalCbor, encodeCanonicalCbor, exportEd25519PrivateKey, hexToBytes, importEd25519PrivateKey, importEd25519PublicKey } from '@chronolog/protocol'

export interface ApplicationDevice {
  readonly identity: PeerIdentity
  readonly storageId: string
  /** Small identity and verified-control metadata, independent of application data. */
  readonly store: BytesStore
  /** Acquire the application's durable store once, only when data is actually used. */
  openStorage(): Promise<BytesStore>
  close(): void | Promise<void>
}
export interface ApplicationStorage { readonly store: BytesStore; close(): void | Promise<void> }
/** Shared browser metadata can initialize the signer and its binding atomically. */
export interface DeviceMetadataStore extends BytesStore {
  initialize?(entries: readonly { readonly key: string; readonly value: Uint8Array }[]): Promise<void>
  compareAndSwap?(key: string, expected: Uint8Array | null, value: Uint8Array): Promise<boolean>
}
const DEVICE_KEY = 'peer-session/device/v1'
const DEVICE_BINDING = 'peer-session/device-binding/v1'
const claimed = new WeakSet<ApplicationDevice>()

/** Explicit setup can create once. Resume never replaces a missing or inconsistent signer. */
export async function openApplicationDevice(options: {
  readonly store: DeviceMetadataStore
  readonly create?: true
  readonly openStorage?: () => ApplicationStorage | Promise<ApplicationStorage>
  readonly close?: () => void | Promise<void>
}): Promise<ApplicationDevice> {
  let raw = await options.store.get(DEVICE_KEY), binding = await options.store.get(DEVICE_BINDING)
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
  let opening: Promise<BytesStore> | undefined, closing: Promise<void> | undefined
  return Object.freeze({ identity: Object.freeze(identity), storageId, store: options.store,
    openStorage() {
      if (closed) return Promise.reject(new Error('APPLICATION_DEVICE_CLOSED'))
      return opening ??= Promise.resolve().then(async () => {
        if (closed) throw new Error('APPLICATION_DEVICE_CLOSED')
        storage = options.openStorage === undefined ? { store: options.store, close() {} } : await options.openStorage()
        if (closed) throw new Error('APPLICATION_DEVICE_CLOSED')
        return storage.store
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
}
export function claimApplicationDevice(device: ApplicationDevice): () => void {
  if (claimed.has(device)) throw new Error('APPLICATION_DEVICE_IN_USE')
  claimed.add(device)
  return () => { claimed.delete(device) }
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]) }

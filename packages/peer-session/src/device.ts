import { useDeviceStore } from './checkpoint-lifecycle.js'
import { readBytesMany, type BytesStore } from '@chronolog/records'
import { createSigningIdentity, type SigningIdentity } from '@chronolog/authority'
import { assertCanonicalCbor, encodeCanonicalCbor, exportEd25519PrivateKey, hexToBytes, importEd25519PrivateKey, importEd25519PublicKey } from '@chronolog/protocol'
import { createPqWrapKeyPair, createWrapKeyPair, importWrapPrivateKey } from './wrap-keys.js'
import { assertDeviceNotRetired, DEVICE_RETIRED_KEY } from './checkpoint.js'

export interface DeviceWrapKey {
  readonly publicKey: string
  readonly privateKey: CryptoKey
}

export interface DevicePqWrapKey {
  readonly publicKey: string
  readonly secretKey: Uint8Array
}

export interface ApplicationDevice {
  readonly identity: SigningIdentity
  readonly wrapKey: DeviceWrapKey
  readonly pqWrapKey?: DevicePqWrapKey
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

const DEVICE_KEY = 'peer-session/device/v1'
const DEVICE_WRAP_KEY = 'peer-session/device-wrap-key/v1'
const DEVICE_PQ_WRAP_KEY = 'peer-session/device-pq-wrap-key/v1'
const DEVICE_BINDING = 'peer-session/device-binding/v1'
const STORAGE_BINDING = 'peer-session/storage-binding/v1'
const STORAGE_OPENED = 'peer-session/storage-opened/v1'
const claimed = new WeakSet<ApplicationDevice>()
/** Signing keys whose sign/verify self-test already passed in this process. */
const selfTested = new WeakSet<CryptoKey>()
const selfTestedStored = new Set<string>()

/** Explicit setup can create once. Resume never replaces a missing or inconsistent signer. */
export async function openApplicationDevice(options: {
  readonly store: DeviceMetadataStore
  readonly create?: true
  /** A host-managed signer is resolved on every activation and never serialized. */
  readonly managedSigner?: SigningIdentity
  /** Optional host-managed X25519 wrap key paired with managedSigner. */
  readonly managedWrapKey?: DeviceWrapKey
  /** Optional host-managed hybrid PQ X-Wing wrap key paired with managedSigner. */
  readonly managedPqWrapKey?: DevicePqWrapKey
  readonly openStorage?: () => ApplicationStorage | Promise<ApplicationStorage>
  readonly close?: () => void | Promise<void>
}): Promise<ApplicationDevice> {
  const releaseOpening = useDeviceStore(options.store)
  try {
    // One batched read for the retirement fence, signer, binding and wrap keys (one IDB transaction).
    const [retired, rawInitial, bindingInitial, wrapInitial, pqWrapInitial] = await readBytesMany(options.store, [DEVICE_RETIRED_KEY, DEVICE_KEY, DEVICE_BINDING, DEVICE_WRAP_KEY, DEVICE_PQ_WRAP_KEY])
    if (retired !== null) await assertDeviceNotRetired(options.store)
    const managedSigner = options.managedSigner && { ...options.managedSigner }
    // The sign/verify self-test runs once per key per process, not on every activation.
    if (managedSigner && !selfTested.has(managedSigner.privateKey)) {
      await verifyDeviceSigner(managedSigner)
      selfTested.add(managedSigner.privateKey)
    }
    let raw = rawInitial ?? null, binding = bindingInitial ?? null
    let wrapRawInitial = wrapInitial ?? null
    let pqWrapRawInitial = pqWrapInitial ?? null
    if (raw === null && binding !== null) raw = await options.store.get(DEVICE_KEY)
    let identity: SigningIdentity, storageId: string
    if (raw === null) {
      if (binding !== null) throw new Error('APPLICATION_DEVICE_KEYS_MISSING')
      if (options.create !== true) throw new Error('APPLICATION_DEVICE_NOT_FOUND')
      const candidate = managedSigner ?? await createSigningIdentity()
      const candidateStorageId = crypto.randomUUID()
      const record = managedSigner
        ? [2n, candidate.publicKey, candidateStorageId]
        : [1n, candidate.publicKey, await exportEd25519PrivateKey(candidate.privateKey), candidateStorageId]
      const entries = [
        { key: DEVICE_BINDING, value: encodeCanonicalCbor([candidate.publicKey, candidateStorageId]) },
        { key: DEVICE_KEY, value: encodeCanonicalCbor(record) },
      ]
      if (options.managedWrapKey === undefined) {
        const pair = await createWrapKeyPair()
        entries.push({ key: DEVICE_WRAP_KEY, value: encodeCanonicalCbor([1n, pair.publicKey, pair.privateKey]) })
      }
      if (options.managedPqWrapKey === undefined) {
        const pqPair = createPqWrapKeyPair()
        entries.push({ key: DEVICE_PQ_WRAP_KEY, value: encodeCanonicalCbor([1n, pqPair.publicKey, pqPair.secretKey]) })
      }
      if (options.store.initialize !== undefined) await options.store.initialize(entries)
      else for (const entry of entries) await options.store.put(entry.key, entry.value)
      const reread = await readBytesMany(options.store, [DEVICE_KEY, DEVICE_BINDING, DEVICE_WRAP_KEY, DEVICE_PQ_WRAP_KEY])
      raw = reread[0] ?? null; binding = reread[1] ?? null; wrapRawInitial = reread[2] ?? null; pqWrapRawInitial = reread[3] ?? null
      if (raw === null) throw new Error(binding === null ? 'APPLICATION_DEVICE_NOT_FOUND' : 'APPLICATION_DEVICE_KEYS_MISSING')
    }
    {
      const value = assertCanonicalCbor(raw)
      if (!Array.isArray(value) || typeof value[1] !== 'string' || !/^[0-9a-f]{64}$/u.test(value[1])) throw new Error('APPLICATION_DEVICE_INVALID')
      if (value[0] === 2n && value.length === 3 && validStorageId(value[2])) {
        if (managedSigner === undefined) throw new Error('APPLICATION_DEVICE_MANAGED_SIGNER_REQUIRED')
        if (managedSigner.publicKey !== value[1]) throw new Error('APPLICATION_DEVICE_KEY_MISMATCH')
        identity = managedSigner; storageId = value[2]
      } else if (value[0] === 1n && value.length === 4 && value[2] instanceof Uint8Array && validStorageId(value[3])) {
        if (managedSigner !== undefined) throw new Error('APPLICATION_DEVICE_STORAGE_MODE_MISMATCH')
        identity = { publicKey: value[1], privateKey: await importEd25519PrivateKey(value[2]) }; storageId = value[3]
        // Trust shortcut: the stored key pair was self-tested when this device created it; a
        // resumed device only checks it once per process run.
        const testKey = `${storageId}:${identity.publicKey}`
        if (!selfTestedStored.has(testKey)) { await verifyDeviceSigner(identity); selfTestedStored.add(testKey) }
      } else throw new Error('APPLICATION_DEVICE_INVALID')
      if (binding === null || !sameBytes(binding, encodeCanonicalCbor([identity.publicKey, storageId]))) throw new Error('APPLICATION_DEVICE_BINDING_INVALID')
    }

    // Resolve or lazily create the long-lived X25519 key-wrap key pair for HPKE epoch lockboxes.
    let wrapKey: DeviceWrapKey
    if (options.managedWrapKey !== undefined) {
      if (!/^[0-9a-f]{64}$/u.test(options.managedWrapKey.publicKey)) throw new Error('APPLICATION_DEVICE_WRAP_KEY_INVALID')
      wrapKey = Object.freeze({ ...options.managedWrapKey })
    } else {
      let wrapRaw = wrapRawInitial
      if (wrapRaw === null) {
        const pair = await createWrapKeyPair()
        const encoded = encodeCanonicalCbor([1n, pair.publicKey, pair.privateKey])
        if (options.store.compareAndSwap !== undefined) await options.store.compareAndSwap(DEVICE_WRAP_KEY, null, encoded)
        else await options.store.put(DEVICE_WRAP_KEY, encoded)
        wrapRaw = await options.store.get(DEVICE_WRAP_KEY)
      }
      if (wrapRaw === null) throw new Error('APPLICATION_DEVICE_WRAP_KEY_MISSING')
      const parsed = assertCanonicalCbor(wrapRaw)
      if (!Array.isArray(parsed) || parsed[0] !== 1n || typeof parsed[1] !== 'string' || !/^[0-9a-f]{64}$/u.test(parsed[1]) || !(parsed[2] instanceof Uint8Array)) {
        throw new Error('APPLICATION_DEVICE_WRAP_KEY_INVALID')
      }
      wrapKey = Object.freeze({ publicKey: parsed[1], privateKey: await importWrapPrivateKey(parsed[2]) })
    }

    // Resolve or lazily create the long-lived hybrid post-quantum X-Wing wrap key pair.
    let pqWrapKey: DevicePqWrapKey
    if (options.managedPqWrapKey !== undefined) {
      if (!/^[0-9a-f]{2432}$/u.test(options.managedPqWrapKey.publicKey) || options.managedPqWrapKey.secretKey.length !== 32) {
        throw new Error('APPLICATION_DEVICE_PQ_WRAP_KEY_INVALID')
      }
      pqWrapKey = Object.freeze({ publicKey: options.managedPqWrapKey.publicKey, secretKey: options.managedPqWrapKey.secretKey.slice() })
    } else {
      let pqRaw = pqWrapRawInitial
      if (pqRaw === null) {
        const pqPair = createPqWrapKeyPair()
        const encoded = encodeCanonicalCbor([1n, pqPair.publicKey, pqPair.secretKey])
        if (options.store.compareAndSwap !== undefined) await options.store.compareAndSwap(DEVICE_PQ_WRAP_KEY, null, encoded)
        else await options.store.put(DEVICE_PQ_WRAP_KEY, encoded)
        pqRaw = await options.store.get(DEVICE_PQ_WRAP_KEY)
      }
      if (pqRaw === null) throw new Error('APPLICATION_DEVICE_PQ_WRAP_KEY_MISSING')
      const parsed = assertCanonicalCbor(pqRaw)
      if (!Array.isArray(parsed) || parsed[0] !== 1n || typeof parsed[1] !== 'string' || !/^[0-9a-f]{2432}$/u.test(parsed[1]) || !(parsed[2] instanceof Uint8Array) || parsed[2].length !== 32) {
        throw new Error('APPLICATION_DEVICE_PQ_WRAP_KEY_INVALID')
      }
      pqWrapKey = Object.freeze({ publicKey: parsed[1], secretKey: parsed[2].slice() })
    }

    let closed = false, storage: ApplicationStorage | undefined
    let opening: Promise<ApplicationStorage> | undefined, closing: Promise<void> | undefined
    return Object.freeze({
      identity: Object.freeze(identity),
      wrapKey,
      pqWrapKey,
      storageId,
      store: options.store,
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
            const [opened, retained] = await Promise.all([options.store.get(STORAGE_OPENED), acquired.store.get(STORAGE_BINDING)])
            if (opened !== null && !sameBytes(opened, expected) || retained !== null && !sameBytes(retained, expected)) {
              throw new Error('APPLICATION_DATA_STORAGE_BINDING_INVALID')
            }
            if (opened !== null && retained === null) throw new Error('APPLICATION_DATA_STORAGE_MISSING')
            if (retained === null) await acquired.store.put(STORAGE_BINDING, expected)
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
function validStorageId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 128
}
export async function verifyDeviceSigner(identity: SigningIdentity): Promise<void> {
  if (!/^[0-9a-f]{64}$/u.test(identity.publicKey)) throw new Error('APPLICATION_DEVICE_KEY_MISMATCH')
  const proof = new TextEncoder().encode('chronolog/device-resume/v1')
  const signature = await crypto.subtle.sign('Ed25519', identity.privateKey, proof)
  if (!await crypto.subtle.verify('Ed25519', await importEd25519PublicKey(hexToBytes(identity.publicKey)), signature, proof)) {
    throw new Error('APPLICATION_DEVICE_KEY_MISMATCH')
  }
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]) }

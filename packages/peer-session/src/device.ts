import { createPeerIdentity, type PeerIdentity, type PeerStore } from '@chronolog/peer-generation'
import { assertCanonicalCbor, encodeCanonicalCbor, exportEd25519PrivateKey, hexToBytes, importEd25519PrivateKey, importEd25519PublicKey } from '@chronolog/protocol'

export interface ApplicationDevice {
  readonly identity: PeerIdentity
  readonly storageId: string
  readonly store: PeerStore
  close(): void | Promise<void>
}
const DEVICE_KEY = 'peer-session/device/v1'
const DEVICE_BINDING = 'peer-session/device-binding/v1'
const claimed = new WeakSet<ApplicationDevice>()

/** Explicit setup can create once. Resume never replaces a missing or inconsistent signer. */
export async function openApplicationDevice(options: {
  readonly store: PeerStore
  readonly create?: true
  readonly close?: () => void | Promise<void>
}): Promise<ApplicationDevice> {
  const raw = await options.store.get(DEVICE_KEY), binding = await options.store.get(DEVICE_BINDING)
  let identity: PeerIdentity, storageId: string
  if (raw === null) {
    if (binding !== null) throw new Error('APPLICATION_DEVICE_KEYS_MISSING')
    if (options.create !== true) throw new Error('APPLICATION_DEVICE_NOT_FOUND')
    identity = await createPeerIdentity()
    storageId = crypto.randomUUID()
    await options.store.put(DEVICE_BINDING, encodeCanonicalCbor([identity.publicKey, storageId]))
    await options.store.put(DEVICE_KEY, encodeCanonicalCbor([1n, identity.publicKey,
      await exportEd25519PrivateKey(identity.privateKey), storageId]))
  } else {
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
  let closed = false
  return Object.freeze({ identity: Object.freeze(identity), storageId, store: options.store,
    async close() { if (closed) return; closed = true; await options.close?.() },
  })
}
export function claimApplicationDevice(device: ApplicationDevice): () => void {
  if (claimed.has(device)) throw new Error('APPLICATION_DEVICE_IN_USE')
  claimed.add(device)
  return () => { claimed.delete(device) }
}
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]) }

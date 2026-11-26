import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

ed.hashes.sha512 = (message: Uint8Array) => sha512(message) as Uint8Array<ArrayBuffer>

/** Synchronous Ed25519 verification for pure deterministic QuickJS reducers. */
export function verifyEd25519Sync(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  try {
    return ed.verify(signature, message, publicKey)
  } catch {
    return false
  }
}

import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import { ProtocolError, concatBytes, protocolInvariant, utf8 } from '@chronolog/protocol'
import type { HpkeCiphertext } from './hpke.js'

export const KEY_BOX_SUITE_X25519 = 'hpke-x25519-aes256gcm' as const
export const KEY_BOX_SUITE_XWING = 'hpke-xwing-aes256gcm' as const
export type KeyBoxSuite = typeof KEY_BOX_SUITE_X25519 | typeof KEY_BOX_SUITE_XWING

export const XWING_PUBLIC_KEY_BYTES = 1216
export const XWING_SECRET_KEY_BYTES = 32
export const XWING_ENCAPSULATED_KEY_BYTES = 1120

/** IETF draft-connolly-cfrg-xwing-kem HPKE KEM ID = 0x647a, KDF = HKDF-SHA256 (0x0001), AEAD = AES-256-GCM (0x0002). */
const XWING_HPKE_SUITE_ID = concatBytes(utf8('HPKE'), Uint8Array.of(0x64, 0x7a, 0x00, 0x01, 0x00, 0x02))
const HPKE_VERSION = utf8('HPKE-v1')

export interface XWingKeyPair {
  readonly publicKey: Uint8Array
  readonly secretKey: Uint8Array
}

function source(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer
}

function deriveXWingTrafficKeys(sharedSecret: Uint8Array, info: Uint8Array): { readonly key: Uint8Array; readonly nonce: Uint8Array } {
  const ctx = concatBytes(HPKE_VERSION, XWING_HPKE_SUITE_ID, info)
  const key = Uint8Array.from(hkdf(sha256, sharedSecret, ctx, utf8('key'), 32))
  const nonce = Uint8Array.from(hkdf(sha256, sharedSecret, ctx, utf8('base_nonce'), 12))
  return { key, nonce }
}

/** Generate a hybrid post-quantum X-Wing (ML-KEM-768 + X25519) keypair with a 32-byte compact seed. */
export function generateXWingKeyPair(seed?: Uint8Array): XWingKeyPair {
  if (seed !== undefined) {
    protocolInvariant(seed.length === XWING_SECRET_KEY_BYTES, 'INVALID_KEY', 'X-Wing seed must be 32 bytes')
  }
  const pair = ml_kem768_x25519.keygen(seed)
  return {
    publicKey: Uint8Array.from(pair.publicKey),
    secretKey: Uint8Array.from(pair.secretKey),
  }
}

/** Deterministically derive the 1216-byte X-Wing public key from a 32-byte secret seed. */
export function xwingPublicKeyFromSeed(secretKey: Uint8Array): Uint8Array {
  protocolInvariant(secretKey.length === XWING_SECRET_KEY_BYTES, 'INVALID_KEY', 'X-Wing secret key must be 32 bytes')
  return Uint8Array.from(ml_kem768_x25519.keygen(secretKey).publicKey)
}

/** Seal a plaintext to an X-Wing (ML-KEM-768 + X25519) hybrid post-quantum recipient public key. */
export async function xwingSealBase(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<HpkeCiphertext> {
  protocolInvariant(recipientPublicKey.length === XWING_PUBLIC_KEY_BYTES, 'INVALID_KEY', 'X-Wing public key must be 1216 bytes')
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(recipientPublicKey)
  const { key, nonce } = deriveXWingTrafficKeys(sharedSecret, info)
  try {
    const aesKey = await globalThis.crypto.subtle.importKey('raw', source(key), 'AES-GCM', false, ['encrypt'])
    const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: source(nonce), additionalData: source(aad), tagLength: 128 },
      aesKey,
      source(plaintext),
    ))
    return { encapsulatedKey: Uint8Array.from(cipherText), ciphertext }
  } finally {
    sharedSecret.fill(0)
    key.fill(0)
    nonce.fill(0)
  }
}

/** Open an X-Wing (ML-KEM-768 + X25519) hybrid post-quantum ciphertext using the recipient's 32-byte seed. */
export async function xwingOpenBase(
  recipientSecretKey: Uint8Array,
  encapsulatedKey: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  protocolInvariant(recipientSecretKey.length === XWING_SECRET_KEY_BYTES, 'INVALID_KEY', 'X-Wing secret key must be 32 bytes')
  protocolInvariant(encapsulatedKey.length === XWING_ENCAPSULATED_KEY_BYTES, 'INVALID_KEY', 'X-Wing encapsulated key must be 1120 bytes')
  const sharedSecret = ml_kem768_x25519.decapsulate(encapsulatedKey, recipientSecretKey)
  const { key, nonce } = deriveXWingTrafficKeys(sharedSecret, info)
  try {
    const aesKey = await globalThis.crypto.subtle.importKey('raw', source(key), 'AES-GCM', false, ['decrypt'])
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: source(nonce), additionalData: source(aad), tagLength: 128 },
      aesKey,
      source(ciphertext),
    ))
  } catch {
    throw new ProtocolError('INVALID_SIGNATURE', 'X-Wing HPKE ciphertext authentication failed')
  } finally {
    sharedSecret.fill(0)
    key.fill(0)
    nonce.fill(0)
  }
}

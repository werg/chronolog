import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { ProtocolError, concatBytes, protocolInvariant, utf8 } from '@chronolog/protocol'
import { hpkeBaseKeySchedule, type HpkeCiphertext } from './hpke.js'

export const KEY_BOX_SUITE_X25519 = 'hpke-x25519-aes256gcm' as const
export const KEY_BOX_SUITE_XWING = 'hpke-xwing-aes256gcm' as const
export type KeyBoxSuite = typeof KEY_BOX_SUITE_X25519 | typeof KEY_BOX_SUITE_XWING

export const XWING_PUBLIC_KEY_BYTES = 1216
export const XWING_SECRET_KEY_BYTES = 32
export const XWING_ENCAPSULATED_KEY_BYTES = 1120

/**
 * RFC 9180 HPKE `suite_id` for X-Wing (draft-connolly-cfrg-xwing-kem, KEM ID 0x647a) with
 * HKDF-SHA256 (KDF 0x0001) and AES-256-GCM (AEAD 0x0002). X-Wing's 32-byte shared secret is the
 * HPKE KEM `shared_secret`; the standard `mode_base` key schedule then derives key and base nonce.
 */
const XWING_HPKE_SUITE_ID = concatBytes(utf8('HPKE'), Uint8Array.of(0x64, 0x7a, 0x00, 0x01, 0x00, 0x02))

export interface XWingKeyPair {
  readonly publicKey: Uint8Array
  readonly secretKey: Uint8Array
}

function source(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer
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

/** RFC 9180 HPKE `SealBase` to an X-Wing (ML-KEM-768 + X25519) hybrid post-quantum recipient public key. */
export async function xwingSealBase(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
): Promise<HpkeCiphertext> {
  protocolInvariant(recipientPublicKey.length === XWING_PUBLIC_KEY_BYTES, 'INVALID_KEY', 'X-Wing public key must be 1216 bytes')
  const { cipherText, sharedSecret } = ml_kem768_x25519.encapsulate(recipientPublicKey)
  const { key, nonce, exporterSecret } = await hpkeBaseKeySchedule(XWING_HPKE_SUITE_ID, sharedSecret, info)
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
    exporterSecret.fill(0)
  }
}

/** RFC 9180 HPKE `OpenBase` of an X-Wing (ML-KEM-768 + X25519) ciphertext using the recipient's 32-byte seed. */
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
  const { key, nonce, exporterSecret } = await hpkeBaseKeySchedule(XWING_HPKE_SUITE_ID, sharedSecret, info)
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
    exporterSecret.fill(0)
  }
}

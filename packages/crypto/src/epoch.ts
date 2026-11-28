import { hkdf } from '@noble/hashes/hkdf'
import { sha256 } from '@noble/hashes/sha256'
import {
  ProtocolError,
  bytesToHex,
  concatBytes,
  encodeCanonicalCbor,
  integerMap,
  protocolInvariant,
  utf8,
} from '@chronolog/protocol'

/** Bytes of the per-payload random HKDF salt (192 bits; also the envelope `nonce`). */
export const EPOCH_PAYLOAD_SALT_BYTES = 24

/**
 * An epoch-key encrypted payload. The only suite is `hkdf-aes-256-gcm`: a per-payload AES-256-GCM
 * subkey and IV are derived with HKDF-SHA256 from the epoch key and a random 192-bit salt (`nonce`),
 * and the plaintext is framed by `padPlaintext`.
 */
export interface EncryptedEpochPayload {
  readonly epoch: bigint
  /** 24-byte HKDF salt. */
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
}

export interface EncryptEpochOptions {
  /** Optional bucket padding in bytes (e.g. 256 -> power-of-2 buckets starting at 256 B). */
  readonly paddingBucketBytes?: number
}

function source(value: Uint8Array): ArrayBuffer {
  // A Node Buffer may be a small view into a larger shared allocation.
  return Uint8Array.from(value).buffer
}

const EPOCH_KEY_COMMITMENT_PREFIX = utf8('chronolog/epoch-key-commitment/v2:')

/** Public `$keys` commitment to a 32-byte epoch key: hex SHA-256(`chronolog/epoch-key-commitment/v2:` || key). */
export function epochKeyCommitment(epochKey: Uint8Array): string {
  protocolInvariant(epochKey.length === 32, 'INVALID_KEY', 'Epoch key must contain 32 bytes')
  return bytesToHex(sha256(concatBytes(EPOCH_KEY_COMMITMENT_PREFIX, epochKey)))
}

function payloadAad(epoch: bigint, associatedData: Uint8Array): Uint8Array {
  return encodeCanonicalCbor(integerMap([[0, 1n], [1, epoch], [2, associatedData]]))
}

const HKDF_SUBKEY_INFO_PREFIX = utf8('chronolog/hkdf-aes-256-gcm/v1:')

function deriveSubkeyAndIv(contentKey: Uint8Array, epoch: bigint, salt24: Uint8Array): { readonly key: Uint8Array; readonly iv: Uint8Array } {
  const epBytes = utf8(epoch.toString(10))
  const combinedInfo = new Uint8Array(HKDF_SUBKEY_INFO_PREFIX.length + epBytes.length)
  combinedInfo.set(HKDF_SUBKEY_INFO_PREFIX, 0)
  combinedInfo.set(epBytes, HKDF_SUBKEY_INFO_PREFIX.length)
  const okm = hkdf(sha256, contentKey, salt24, combinedInfo, 44)
  return { key: okm.subarray(0, 32), iv: okm.subarray(32, 44) }
}

/**
 * Power-of-two bucket padding for encrypted operation plaintexts:
 * - Tag `0x00` + raw bytes (when `paddingBucketBytes` is 0 / disabled)
 * - Tag `0x01` + u32 BE length + raw bytes + zero pad up to `max(bucketBytes, nextPow2(5 + len))`
 */
export function padPlaintext(plaintext: Uint8Array, paddingBucketBytes = 0): Uint8Array {
  if (!Number.isSafeInteger(paddingBucketBytes) || paddingBucketBytes <= 0) {
    const out = new Uint8Array(1 + plaintext.length)
    out[0] = 0x00
    out.set(plaintext, 1)
    return out
  }
  const minLen = 5 + plaintext.length
  let target = Math.max(16, paddingBucketBytes)
  while (target < minLen) target *= 2
  const out = new Uint8Array(target)
  out[0] = 0x01
  new DataView(out.buffer).setUint32(1, plaintext.length, false)
  out.set(plaintext, 5)
  return out
}

/** Reverse `padPlaintext` strictly (verifying zero padding bytes and bounds). */
export function unpadPlaintext(framed: Uint8Array): Uint8Array {
  protocolInvariant(framed.length >= 1, 'INVALID_SIGNATURE', 'Empty framed plaintext')
  const tag = framed[0]
  if (tag === 0x00) return framed.slice(1)
  protocolInvariant(tag === 0x01 && framed.length >= 5, 'INVALID_SIGNATURE', 'Invalid padded plaintext header')
  const len = new DataView(framed.buffer, framed.byteOffset, framed.byteLength).getUint32(1, false)
  protocolInvariant(5 + len <= framed.length, 'INVALID_SIGNATURE', 'Padded plaintext length out of range')
  for (let i = 5 + len; i < framed.length; i++) {
    protocolInvariant(framed[i] === 0, 'INVALID_SIGNATURE', 'Non-zero padding byte')
  }
  return framed.slice(5, 5 + len)
}

export async function encryptEpochPayload(
  contentKey: Uint8Array,
  epoch: bigint,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  explicitNonce?: Uint8Array,
  options: EncryptEpochOptions = {},
): Promise<EncryptedEpochPayload> {
  protocolInvariant(contentKey.length === 32, 'INVALID_KEY', 'Epoch content key must contain 32 bytes')
  let nonce: Uint8Array
  if (explicitNonce !== undefined) {
    protocolInvariant(explicitNonce.length === EPOCH_PAYLOAD_SALT_BYTES, 'SCHEMA_INVALID', 'Epoch payload salt must contain 24 bytes')
    nonce = explicitNonce.slice()
  } else {
    nonce = globalThis.crypto.getRandomValues(new Uint8Array(EPOCH_PAYLOAD_SALT_BYTES))
  }
  const aad = payloadAad(epoch, associatedData)
  const { key: subkey, iv } = deriveSubkeyAndIv(contentKey, epoch, nonce)
  const framed = padPlaintext(plaintext, options.paddingBucketBytes ?? 0)
  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey('raw', source(subkey), 'AES-GCM', false, ['encrypt'])
    const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: source(iv), additionalData: source(aad), tagLength: 128 },
      cryptoKey,
      source(framed),
    ))
    return { epoch, nonce, ciphertext }
  } finally {
    subkey.fill(0)
    iv.fill(0)
  }
}

export async function decryptEpochPayload(
  contentKey: Uint8Array,
  payload: EncryptedEpochPayload,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  protocolInvariant(contentKey.length === 32, 'INVALID_KEY', 'Epoch content key must contain 32 bytes')
  protocolInvariant(payload.nonce.length === EPOCH_PAYLOAD_SALT_BYTES, 'SCHEMA_INVALID', 'Epoch payload salt must contain 24 bytes')
  const aad = payloadAad(payload.epoch, associatedData)
  const { key: subkey, iv } = deriveSubkeyAndIv(contentKey, payload.epoch, payload.nonce)
  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey('raw', source(subkey), 'AES-GCM', false, ['decrypt'])
    const framed = new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: source(iv), additionalData: source(aad), tagLength: 128 },
      cryptoKey,
      source(payload.ciphertext),
    ))
    return unpadPlaintext(framed)
  } catch (error) {
    if (error instanceof ProtocolError) throw error
    throw new ProtocolError('INVALID_SIGNATURE', 'Epoch payload authentication failed')
  } finally {
    subkey.fill(0)
    iv.fill(0)
  }
}

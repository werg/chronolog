import {
  ProtocolError,
  encodeCanonicalCbor,
  integerMap,
  protocolInvariant,
} from '@chronolog/protocol'

export interface EncryptedEpochPayload {
  readonly epoch: bigint
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
}

function source(value: Uint8Array): ArrayBuffer {
  // A Node Buffer may be a small view into a larger shared allocation.
  return Uint8Array.from(value).buffer
}

/** Imported AES-GCM keys per raw epoch key (imports are async and comparatively expensive). */
const aesKeys = new Map<string, Promise<CryptoKey>>()
function aesKey(contentKey: Uint8Array): Promise<CryptoKey> {
  let id = ''
  for (const byte of contentKey) id += byte.toString(16).padStart(2, '0')
  let key = aesKeys.get(id)
  if (key === undefined) {
    if (aesKeys.size >= 256) aesKeys.clear()
    key = globalThis.crypto.subtle.importKey('raw', source(contentKey), 'AES-GCM', false, ['encrypt', 'decrypt'])
    aesKeys.set(id, key)
    key.catch(() => aesKeys.delete(id))
  }
  return key
}

function payloadAad(epoch: bigint, associatedData: Uint8Array): Uint8Array {
  return encodeCanonicalCbor(integerMap([[0, 1n], [1, epoch], [2, associatedData]]))
}

export async function encryptEpochPayload(
  contentKey: Uint8Array,
  epoch: bigint,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
  explicitNonce?: Uint8Array,
): Promise<EncryptedEpochPayload> {
  protocolInvariant(contentKey.length === 32, 'INVALID_KEY', 'Epoch content key must contain 32 bytes')
  const key = await aesKey(contentKey)
  let nonce: Uint8Array
  if (explicitNonce !== undefined) {
    protocolInvariant(explicitNonce.length === 12, 'SCHEMA_INVALID', 'Epoch payload nonce must contain 12 bytes')
    nonce = explicitNonce.slice()
  } else {
    nonce = globalThis.crypto.getRandomValues(new Uint8Array(12))
  }
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: source(nonce), additionalData: source(payloadAad(epoch, associatedData)), tagLength: 128 },
    key,
    source(plaintext),
  ))
  return { epoch, nonce, ciphertext }
}

export async function decryptEpochPayload(
  contentKey: Uint8Array,
  payload: EncryptedEpochPayload,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  protocolInvariant(contentKey.length === 32, 'INVALID_KEY', 'Epoch content key must contain 32 bytes')
  protocolInvariant(payload.nonce.length === 12, 'SCHEMA_INVALID', 'Epoch payload nonce must contain 12 bytes')
  try {
    const key = await aesKey(contentKey)
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: source(payload.nonce), additionalData: source(payloadAad(payload.epoch, associatedData)), tagLength: 128 },
      key,
      source(payload.ciphertext),
    ))
  } catch {
    throw new ProtocolError('INVALID_SIGNATURE', 'Epoch payload authentication failed')
  }
}

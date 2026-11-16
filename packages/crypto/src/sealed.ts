import {
  MAX_SEALED_PLAINTEXT_BYTES, MAX_SEALED_READERS, ProtocolError,
  assertCanonicalCbor, compareBytes, decodeSealedEnvelope, encodeCanonicalCbor,
  encodeSealedContext, encodeSealedEnvelope, equalBytes, protocolInvariant,
  sealedContextFromCanonicalCbor,
  type SealedContext, type SealedEnvelope, type SealedKeyWrap, type SealedRecipient,
} from '@chronolog/protocol'

import { hpkeOpenBase, hpkeSealBase } from './hpke.js'

// Buffer.slice() retains the backing pool. Copy exactly this view for WebCrypto.
function source(value: Uint8Array): ArrayBuffer { return Uint8Array.from(value).buffer }
const isList = (value: unknown): boolean => Array.isArray(value)

function payloadContext(context: SealedContext): Uint8Array {
  return encodeCanonicalCbor(['chronolog.sealed-value.v1', encodeSealedContext(context)])
}

function wrapContext(context: SealedContext, recipient: SealedRecipient): Uint8Array {
  return encodeCanonicalCbor([
    'chronolog.sealed-key-wrap.v1', encodeSealedContext(context), recipient.readerId, recipient.publicKey,
  ])
}

function copyContext(context: SealedContext): SealedContext {
  return sealedContextFromCanonicalCbor(assertCanonicalCbor(encodeSealedContext(context)))
}

function copyRecipients(recipients: readonly SealedRecipient[]): SealedRecipient[] {
  protocolInvariant(isList(recipients) && recipients.length > 0 && recipients.length <= MAX_SEALED_READERS,
    'SCHEMA_INVALID', 'Sealing requires 1 to 256 explicit readers')
  const sorted = recipients.map((recipient) => {
    protocolInvariant(recipient.readerId instanceof Uint8Array && recipient.readerId.length === 32 &&
      recipient.publicKey instanceof Uint8Array && recipient.publicKey.length === 32,
    'SCHEMA_INVALID', 'Sealed readers require a 32-byte id and a 32-byte HPKE public key')
    return { readerId: Uint8Array.from(recipient.readerId), publicKey: Uint8Array.from(recipient.publicKey) }
  }).sort((left, right) => compareBytes(left.readerId, right.readerId))
  for (let index = 1; index < sorted.length; index += 1) {
    protocolInvariant(!equalBytes(sorted[index - 1]!.readerId, sorted[index]!.readerId), 'SCHEMA_INVALID', 'Sealed reader ids must be unique')
  }
  return sorted
}

/**
 * Encrypt one value on the client with a fresh random AES-256-GCM key, wrapped
 * independently to every explicit reader using HPKE. The owner is not added.
 * Callers cannot supply/reuse the content key. The result is safe to replicate.
 */
export async function sealSealedValue(input: {
  readonly context: SealedContext
  readonly plaintext: Uint8Array
  readonly recipients: readonly SealedRecipient[]
}): Promise<SealedEnvelope> {
  protocolInvariant(input.plaintext instanceof Uint8Array && input.plaintext.length <= MAX_SEALED_PLAINTEXT_BYTES,
    'SCHEMA_INVALID', 'Sealed plaintext exceeds the 1 MiB value limit or is not bytes')
  // Take copies before the first await: callers must not change authenticated
  // context, readers or plaintext while WebCrypto is running.
  const context = copyContext(input.context)
  const recipients = copyRecipients(input.recipients)
  const plaintext = Uint8Array.from(input.plaintext)
  const contentKey = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12))
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', source(contentKey), 'AES-GCM', false, ['encrypt'])
    const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: source(nonce), additionalData: source(payloadContext(context)), tagLength: 128 },
      key, source(plaintext),
    ))
    const wraps: SealedKeyWrap[] = []
    for (const recipient of recipients) {
      const authenticated = wrapContext(context, recipient)
      const wrapped = await hpkeSealBase(recipient.publicKey, contentKey, authenticated, authenticated)
      wraps.push({ ...recipient, encapsulatedKey: wrapped.encapsulatedKey, ciphertext: wrapped.ciphertext })
    }
    const envelope: SealedEnvelope = { context, nonce, ciphertext, wraps }
    // Use the same bounds and canonical form that replicas enforce.
    return decodeSealedEnvelope(encodeSealedEnvelope(envelope))
  } finally {
    contentKey.fill(0)
    plaintext.fill(0)
  }
}

/**
 * Open only a value matching externally expected group, policy, policy version,
 * column and data version. Supplying the envelope's own context as the expected
 * context defeats substitution protection; use trusted row/revision metadata.
 */
export async function openSealedValue(input: {
  readonly envelope: SealedEnvelope
  readonly expectedContext: SealedContext
  readonly readerId: Uint8Array
  readonly recipientPrivateKey: CryptoKey
}): Promise<Uint8Array> {
  const envelope = decodeSealedEnvelope(encodeSealedEnvelope(input.envelope))
  const expected = encodeSealedContext(input.expectedContext)
  protocolInvariant(equalBytes(encodeSealedContext(envelope.context), expected), 'INVALID_SIGNATURE', 'Sealed value does not match the expected context')
  protocolInvariant(input.readerId instanceof Uint8Array && input.readerId.length === 32, 'INVALID_KEY', 'Sealed reader id must contain 32 bytes')
  const readerId = Uint8Array.from(input.readerId)
  const wrap = envelope.wraps.find((candidate) => equalBytes(candidate.readerId, readerId))
  protocolInvariant(wrap !== undefined, 'INVALID_KEY', 'Sealed value has no key wrap for this reader')
  const authenticated = wrapContext(envelope.context, wrap)
  const contentKey = await hpkeOpenBase(
    input.recipientPrivateKey, wrap.publicKey, wrap.encapsulatedKey, wrap.ciphertext, authenticated, authenticated,
  )
  try {
    protocolInvariant(contentKey.length === 32, 'INVALID_KEY', 'Sealed content key must contain 32 bytes')
    const key = await globalThis.crypto.subtle.importKey('raw', source(contentKey), 'AES-GCM', false, ['decrypt'])
    try {
      return new Uint8Array(await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: source(envelope.nonce), additionalData: source(payloadContext(envelope.context)), tagLength: 128 },
        key, source(envelope.ciphertext),
      ))
    } catch {
      throw new ProtocolError('INVALID_SIGNATURE', 'Sealed value authentication failed')
    }
  } finally {
    contentKey.fill(0)
  }
}

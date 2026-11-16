import {
  DOMAINS,
  assertCanonicalCbor,
  decodeEnvelope,
  encodeCanonicalCbor,
  encodeEnvelope,
  equalBytes,
  signDomain,
  verifyDomain,
  type CborValue,
  type Ed25519KeyPair,
  type EnvelopeMessageType,
  type ProtocolDomain,
} from '@chronolog/protocol'

import type { EnvelopeCipher, EnvelopeCipherResolver } from './types.js'

export interface SignedWireMessage {
  readonly type: Extract<EnvelopeMessageType, 'candidate' | 'attestation' | 'heartbeat'>
  readonly payload: Uint8Array
  readonly signer: Uint8Array
  readonly signature: Uint8Array
}

const WIRE_TYPES = ['candidate', 'attestation', 'heartbeat'] as const

function domainFor(type: SignedWireMessage['type']): ProtocolDomain {
  if (type === 'candidate') return DOMAINS.transaction
  if (type === 'attestation') return DOMAINS.attestation
  return DOMAINS.heartbeat
}

export async function encodeSignedEnvelope(
  groupRoute: Uint8Array,
  type: SignedWireMessage['type'],
  payload: Uint8Array,
  signer: Ed25519KeyPair,
  cipher?: EnvelopeCipher | EnvelopeCipherResolver,
): Promise<Uint8Array> {
  groupRoute = groupRoute.slice()
  return sealSignedMessage(groupRoute, await signWireMessage(type, payload, signer), cipher)
}

/** A publisher signs without knowing any reader key or retaining group history. */
export async function signWireMessage(type: SignedWireMessage['type'], payload: Uint8Array, signer: Ed25519KeyPair): Promise<Uint8Array> {
  payload = payload.slice()
  const publicKeyBytes = signer.publicKeyBytes.slice()
  const signature = await signDomain(domainFor(type), payload, signer.privateKey)
  return encodeCanonicalCbor([
    1n,
    BigInt(WIRE_TYPES.indexOf(type)),
    payload,
    publicKeyBytes,
    signature,
  ])
}

/** Wrap the original signed bytes in the group's current encryption epoch. */
export async function sealSignedMessage(groupRoute: Uint8Array, wire: Uint8Array, cipher?: EnvelopeCipher | EnvelopeCipherResolver): Promise<Uint8Array> {
  groupRoute = groupRoute.slice()
  wire = wire.slice()
  const { type } = await decodeSignedMessage(wire)
  const activeCipher = cipher === undefined ? undefined : isCipherResolver(cipher) ? cipher.current() : cipher
  const epochId = activeCipher?.epochId.slice() ?? null
  const envelopePayload = activeCipher === undefined
    ? wire
    : await activeCipher.seal(wire, envelopeAssociatedData(groupRoute, type, epochId!))
  return encodeEnvelope({ groupRoute, messageType: type, encryptionEpoch: epochId, payload: envelopePayload })
}

export async function decodeSignedEnvelope(
  encoded: Uint8Array,
  expectedGroupRoute: Uint8Array,
  cipher?: EnvelopeCipher | EnvelopeCipherResolver,
): Promise<SignedWireMessage> {
  encoded = encoded.slice()
  expectedGroupRoute = expectedGroupRoute.slice()
  const envelope = decodeEnvelope(encoded)
  if (!equalBytes(envelope.groupRoute, expectedGroupRoute)) throw wireError('WIRE_WRONG_GROUP')
  const payloadBytes = envelope.payload
  const activeCipher = envelope.encryptionEpoch === null || cipher === undefined
    ? undefined
    : isCipherResolver(cipher) ? cipher.resolve(envelope.encryptionEpoch) : cipher
  if ((envelope.encryptionEpoch === null) !== (cipher === undefined)) throw wireError('WIRE_ENCRYPTION_REQUIRED')
  // A key ring may receive the epoch later (a newly granted reader), so a
  // missing epoch there is distinguishable from a fixed cipher's mismatch.
  if (envelope.encryptionEpoch !== null && activeCipher === undefined && cipher !== undefined && isCipherResolver(cipher)) {
    throw wireError(WIRE_ENCRYPTION_EPOCH_UNAVAILABLE)
  }
  if (envelope.encryptionEpoch !== null && (activeCipher === undefined || !equalBytes(envelope.encryptionEpoch, activeCipher.epochId))) {
    throw wireError('WIRE_ENCRYPTION_EPOCH_UNKNOWN')
  }
  const wireBytes = activeCipher === undefined
    ? payloadBytes
    : await activeCipher.open(
      payloadBytes,
      envelopeAssociatedData(expectedGroupRoute, envelope.messageType as SignedWireMessage['type'], envelope.encryptionEpoch!),
    )
  const message = await decodeSignedMessage(wireBytes)
  if (message.type !== envelope.messageType) throw wireError('WIRE_TYPE_MISMATCH')
  return message
}

export async function decodeSignedMessage(wireBytes: Uint8Array): Promise<SignedWireMessage> {
  wireBytes = wireBytes.slice()
  const value = assertCanonicalCbor(wireBytes, { maxBytes: 2 * 1024 * 1024 })
  if (!Array.isArray(value) || value.length !== 5 || value[0] !== 1n) {
    throw wireError('WIRE_SCHEMA_INVALID')
  }
  const fields = value as readonly CborValue[]
  const typeIndex = fields[1]
  const payload = fields[2]
  const signer = fields[3]
  const signature = fields[4]
  if (
    typeof typeIndex !== 'bigint' ||
    typeIndex < 0n ||
    typeIndex >= BigInt(WIRE_TYPES.length) ||
    !(payload instanceof Uint8Array) ||
    !(signer instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  ) throw wireError('WIRE_SCHEMA_INVALID')
  const type = WIRE_TYPES[Number(typeIndex)]
  if (type === undefined) throw wireError('WIRE_TYPE_MISMATCH')
  if (!await verifyDomain(domainFor(type), payload, signature, signer)) {
    throw wireError('WIRE_SIGNATURE_INVALID')
  }
  return { type, payload, signer, signature }
}

function isCipherResolver(value: EnvelopeCipher | EnvelopeCipherResolver): value is EnvelopeCipherResolver {
  return 'current' in value && typeof value.current === 'function'
}

function envelopeAssociatedData(
  groupRoute: Uint8Array,
  type: SignedWireMessage['type'],
  epochId: Uint8Array,
): Uint8Array {
  return encodeCanonicalCbor([1n, groupRoute, BigInt(WIRE_TYPES.indexOf(type)), epochId])
}

export const WIRE_ENCRYPTION_EPOCH_UNAVAILABLE = 'WIRE_ENCRYPTION_EPOCH_UNAVAILABLE'

function wireError(code: string): Error {
  const error = new Error(code)
  error.name = 'ChronologWireError'
  return error
}

/** Public canonical encoding for protocol vectors and transport adapters. */
export function signedWireToCanonicalValue(message: SignedWireMessage): CborValue {
  return [
    1n,
    BigInt(WIRE_TYPES.indexOf(message.type)),
    message.payload,
    message.signer,
    message.signature,
  ]
}

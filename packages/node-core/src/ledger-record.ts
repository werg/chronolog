import { bytesToHex, sha256, sha256Sync } from '@chronolog/canonical'
import {
  assertCanonicalCbor, decodeEnvelope, encodeCanonicalCbor, equalBytes,
  type CborValue, type ChronologEnvelope,
} from '@chronolog/protocol'

/** Fits the existing public retained-record contract, including its metadata. */
export const MAX_LEDGER_RECORD_BYTES = 256 * 1024
/** Key wraps grow with the roster; this is an explicit bound, not constant-size governance. */
export const MAX_LEDGER_INLINE_PAYLOAD_BYTES = MAX_LEDGER_RECORD_BYTES - 512
export const MAX_LEDGER_PAYLOAD_BYTES = 1024 * 1024
export const MAX_LEDGER_EPOCH_BYTES = 32
const FORMAT = 'chronolog/ledger-record'

export type LedgerRecordKind = 'candidate' | 'capability' | 'epoch-manifest'

interface LedgerRecordFields {
  readonly groupRoute: Uint8Array
  /** The existing envelope's opaque epoch identifier, or null for cleartext. */
  readonly encryptionEpoch: Uint8Array | null
  /** Lowercase SHA-256 of the exact original envelope bytes. */
  readonly payloadHash: string
  readonly payloadLength: number
}

/** The kind in the certified descriptor is the only dispatch discriminator. */
export type LedgerRecord = LedgerRecordFields & (
  | { readonly kind: 'candidate'; readonly inlinePayload: null }
  | { readonly kind: 'capability' | 'epoch-manifest'; readonly inlinePayload: Uint8Array }
)

export type LedgerRecordErrorCode =
  | 'LEDGER_RECORD_INVALID' | 'LEDGER_RECORD_TOO_LARGE' | 'LEDGER_KIND_UNSUPPORTED'
  | 'LEDGER_PAYLOAD_TOO_LARGE' | 'LEDGER_CONTROL_TOO_LARGE' | 'LEDGER_PAYLOAD_LENGTH_INVALID'
  | 'LEDGER_PAYLOAD_HASH_INVALID' | 'LEDGER_PAYLOAD_DIGEST_MISMATCH'
  | 'LEDGER_PAYLOAD_METADATA_MISMATCH' | 'LEDGER_PAYLOAD_INLINE_INVALID' | 'LEDGER_PAYLOAD_UNAVAILABLE'

export class LedgerRecordError extends Error {
  constructor(readonly code: LedgerRecordErrorCode, detail?: string, cause?: unknown) {
    super(detail === undefined ? code : `${code}: ${detail}`, cause === undefined ? undefined : { cause })
    this.name = 'LedgerRecordError'
  }
}

/**
 * Prepare the small exact bytes for the ordinary ordered log. Persist a
 * detached payload before appending its descriptor; retry both exact values.
 * An order certificate authenticates the descriptor, not body availability or
 * application acceptance. The signed message inside the envelope remains the
 * application/governance authenticator and is verified by its normal consumer.
 */
export async function createLedgerRecord(envelopeBytes: Uint8Array): Promise<{
  readonly recordBytes: Uint8Array
  readonly record: LedgerRecord
  readonly detachedPayload: Uint8Array | null
}> {
  if (!(envelopeBytes instanceof Uint8Array)) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  checkPayloadLength(envelopeBytes.length)
  const payload = ownBytes(envelopeBytes, 'LEDGER_RECORD_INVALID')
  const envelope = envelopeMetadata(payload)
  if (!isKind(envelope.messageType)) throw new LedgerRecordError('LEDGER_KIND_UNSUPPORTED')
  if (envelope.messageType !== 'candidate' && payload.length > MAX_LEDGER_INLINE_PAYLOAD_BYTES) {
    throw new LedgerRecordError('LEDGER_CONTROL_TOO_LARGE', `governance envelopes must not exceed ${MAX_LEDGER_INLINE_PAYLOAD_BYTES} bytes`)
  }
  const fields: LedgerRecordFields = {
    groupRoute: ownBytes(envelope.groupRoute, 'LEDGER_RECORD_INVALID'),
    encryptionEpoch: envelope.encryptionEpoch === null ? null : ownBytes(envelope.encryptionEpoch, 'LEDGER_RECORD_INVALID'),
    payloadHash: bytesToHex(await sha256(payload)), payloadLength: payload.length,
  }
  const record = ownRecord(envelope.messageType === 'candidate'
    ? { ...fields, kind: 'candidate', inlinePayload: null }
    : { ...fields, kind: envelope.messageType, inlinePayload: payload })
  const recordBytes = encodeRecord(record)
  if (recordBytes.length > MAX_LEDGER_RECORD_BYTES) throw new LedgerRecordError('LEDGER_RECORD_TOO_LARGE')
  return { recordBytes, record, detachedPayload: record.kind === 'candidate' ? payload : null }
}

/**
 * Decode a bounded descriptor. Inline controls are checked immediately without
 * fetching application bytes. A malformed record is not a detached candidate
 * and must never be retried through the old envelope decoder as a fallback.
 */
export function decodeLedgerRecord(recordBytes: Uint8Array): LedgerRecord {
  if (!(recordBytes instanceof Uint8Array)) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  if (recordBytes.length > MAX_LEDGER_RECORD_BYTES) throw new LedgerRecordError('LEDGER_RECORD_TOO_LARGE')
  const exact = ownBytes(recordBytes, 'LEDGER_RECORD_INVALID')
  let value: CborValue
  try {
    value = assertCanonicalCbor(exact, { maxBytes: MAX_LEDGER_RECORD_BYTES, maxDepth: 4,
      maxItems: 8, maxTextBytes: 128, maxByteStringBytes: MAX_LEDGER_INLINE_PAYLOAD_BYTES })
  } catch (cause) { throw new LedgerRecordError('LEDGER_RECORD_INVALID', undefined, cause) }
  if (!Array.isArray(value) || value.length !== 8) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  const wire = value as readonly CborValue[]
  if (wire[0] !== 1n || wire[1] !== FORMAT || !isKind(wire[2]) || !(wire[3] instanceof Uint8Array) ||
      !(wire[4] === null || wire[4] instanceof Uint8Array) || typeof wire[5] !== 'string' ||
      typeof wire[6] !== 'bigint' || wire[6] < 1n || wire[6] > BigInt(MAX_LEDGER_PAYLOAD_BYTES) ||
      !(wire[7] === null || wire[7] instanceof Uint8Array)) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  const fields: LedgerRecordFields = { groupRoute: wire[3], encryptionEpoch: wire[4],
    payloadHash: wire[5], payloadLength: Number(wire[6]) }
  if (wire[2] === 'candidate') {
    if (wire[7] !== null) throw new LedgerRecordError('LEDGER_PAYLOAD_INLINE_INVALID')
    return ownRecord({ ...fields, kind: 'candidate', inlinePayload: null })
  }
  if (!(wire[7] instanceof Uint8Array)) throw new LedgerRecordError('LEDGER_PAYLOAD_INLINE_INVALID')
  return ownRecord({ ...fields, kind: wire[2], inlinePayload: wire[7] })
}

/** Verify detached bytes before parsing any application contents or decrypting. */
export async function verifyLedgerPayload(record: LedgerRecord, payloadBytes: Uint8Array): Promise<Uint8Array> {
  const expected = ownRecord(record)
  if (!(payloadBytes instanceof Uint8Array) || payloadBytes.length !== expected.payloadLength) {
    throw new LedgerRecordError('LEDGER_PAYLOAD_LENGTH_INVALID')
  }
  const payload = ownBytes(payloadBytes, 'LEDGER_RECORD_INVALID')
  if (bytesToHex(await sha256(payload)) !== expected.payloadHash) throw new LedgerRecordError('LEDGER_PAYLOAD_DIGEST_MISMATCH')
  verifyMetadata(expected, payload)
  return payload
}

/** Missing bytes are unavailable, never an instruction to skip an application position. */
export async function resolveLedgerPayload(record: LedgerRecord,
  getPayload: (hash: string) => Promise<Uint8Array | null>): Promise<Uint8Array> {
  // Own the descriptor before the provider can suspend or mutate its caller.
  const expected = ownRecord(record)
  if (expected.inlinePayload !== null) return verifyLedgerPayload(expected, expected.inlinePayload)
  const payload = await getPayload(expected.payloadHash)
  if (payload === null) throw new LedgerRecordError('LEDGER_PAYLOAD_UNAVAILABLE', expected.payloadHash)
  return verifyLedgerPayload(expected, payload)
}

function isKind(value: unknown): value is LedgerRecordKind {
  return value === 'candidate' || value === 'capability' || value === 'epoch-manifest'
}

function ownBytes(value: Uint8Array, code: LedgerRecordErrorCode): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new LedgerRecordError(code)
  // Uint8Array construction also copies a Node Buffer, whose slice is a view.
  return new Uint8Array(value)
}

function checkPayloadLength(length: number): void {
  if (!Number.isSafeInteger(length) || length < 1) throw new LedgerRecordError('LEDGER_PAYLOAD_LENGTH_INVALID')
  if (length > MAX_LEDGER_PAYLOAD_BYTES) throw new LedgerRecordError('LEDGER_PAYLOAD_TOO_LARGE')
}

function ownRecord(value: LedgerRecord): LedgerRecord {
  if (value === null || typeof value !== 'object' || !isKind(value.kind)) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  const groupRoute = ownBytes(value.groupRoute, 'LEDGER_RECORD_INVALID')
  if (groupRoute.length !== 32) throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  const encryptionEpoch = value.encryptionEpoch === null ? null : ownBytes(value.encryptionEpoch, 'LEDGER_RECORD_INVALID')
  if (encryptionEpoch !== null && (encryptionEpoch.length < 1 || encryptionEpoch.length > MAX_LEDGER_EPOCH_BYTES)) {
    throw new LedgerRecordError('LEDGER_RECORD_INVALID')
  }
  if (typeof value.payloadHash !== 'string' || !/^[0-9a-f]{64}$/u.test(value.payloadHash)) throw new LedgerRecordError('LEDGER_PAYLOAD_HASH_INVALID')
  checkPayloadLength(value.payloadLength)
  const fields: LedgerRecordFields = { groupRoute, encryptionEpoch, payloadHash: value.payloadHash, payloadLength: value.payloadLength }
  if (value.kind === 'candidate') {
    if (value.inlinePayload !== null) throw new LedgerRecordError('LEDGER_PAYLOAD_INLINE_INVALID')
    return { ...fields, kind: 'candidate', inlinePayload: null }
  }
  if (value.payloadLength > MAX_LEDGER_INLINE_PAYLOAD_BYTES) {
    throw new LedgerRecordError('LEDGER_CONTROL_TOO_LARGE', `governance envelopes must not exceed ${MAX_LEDGER_INLINE_PAYLOAD_BYTES} bytes`)
  }
  if (encryptionEpoch !== null) throw new LedgerRecordError('LEDGER_PAYLOAD_METADATA_MISMATCH', 'governance must be unencrypted')
  if (!(value.inlinePayload instanceof Uint8Array)) throw new LedgerRecordError('LEDGER_PAYLOAD_INLINE_INVALID')
  if (value.inlinePayload.length !== value.payloadLength) throw new LedgerRecordError('LEDGER_PAYLOAD_LENGTH_INVALID')
  const inlinePayload = ownBytes(value.inlinePayload, 'LEDGER_PAYLOAD_INLINE_INVALID')
  if (bytesToHex(sha256Sync(inlinePayload)) !== value.payloadHash) throw new LedgerRecordError('LEDGER_PAYLOAD_DIGEST_MISMATCH')
  const record: LedgerRecord = { ...fields, kind: value.kind, inlinePayload }
  verifyMetadata(record, inlinePayload)
  return record
}

function encodeRecord(record: LedgerRecord): Uint8Array {
  return encodeCanonicalCbor([1n, FORMAT, record.kind, record.groupRoute, record.encryptionEpoch,
    record.payloadHash, BigInt(record.payloadLength), record.inlinePayload])
}

function envelopeMetadata(payload: Uint8Array): ChronologEnvelope {
  try { return decodeEnvelope(payload) }
  catch (cause) { throw new LedgerRecordError('LEDGER_PAYLOAD_METADATA_MISMATCH', 'invalid envelope', cause) }
}

function verifyMetadata(record: LedgerRecord, payload: Uint8Array): void {
  const envelope = envelopeMetadata(payload)
  const epochMatches = record.encryptionEpoch === null ? envelope.encryptionEpoch === null
    : envelope.encryptionEpoch !== null && equalBytes(record.encryptionEpoch, envelope.encryptionEpoch)
  if (envelope.messageType !== record.kind || !equalBytes(envelope.groupRoute, record.groupRoute) || !epochMatches) {
    throw new LedgerRecordError('LEDGER_PAYLOAD_METADATA_MISMATCH')
  }
}

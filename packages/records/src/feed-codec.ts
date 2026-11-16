import {
  assertCanonicalCbor,
  concatBytes,
  DEFAULT_DECODE_LIMITS,
  encodeCanonicalCbor,
  utf8,
  type CborValue,
} from '@chronolog/canonical'

const RECORD_DOMAIN = utf8('chronolog/feed-record/v1\0')
export const DEFAULT_MAX_RECORD_BYTES = 64 * 1024 * 1024

export class FeedRecordError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'FeedRecordError'
  }
}

export interface FeedRecord {
  readonly id: string
  readonly author: string
  readonly sequence: bigint
  readonly previous: string | null
  readonly timestampMs: bigint
  readonly payload: Uint8Array
  /** Exact canonical signed bytes, preserved through every relay. */
  readonly raw: Uint8Array
}

export type FeedRecordFields = Pick<FeedRecord, 'author' | 'sequence' | 'previous' | 'timestampMs' | 'payload'>

export interface DecodedFeedRecord extends FeedRecordFields {
  readonly signature: Uint8Array
  readonly signingBytes: Uint8Array
  readonly raw: Uint8Array
}

export interface FeedCrypto {
  sha256(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>
  verify(publicKey: Uint8Array, bytes: Uint8Array, signature: Uint8Array): boolean | Promise<boolean>
}

export interface FeedSigner {
  readonly identity: string
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000))
  }
  return btoa(binary)
}

export function decodeBase64(value: string): Uint8Array {
  let bytes: Uint8Array
  try { bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0)) } catch {
    throw new FeedRecordError('FEED_BASE64_INVALID')
  }
  if (encodeBase64(bytes) !== value) throw new FeedRecordError('FEED_BASE64_INVALID')
  return bytes
}

export function feedIdFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new FeedRecordError('FEED_ID_INVALID')
  return `@${encodeBase64(publicKey)}.ed25519`
}

export function publicKeyFromFeedId(feedId: string): Uint8Array {
  const match = /^@([A-Za-z0-9+/]{43}=)\.ed25519$/u.exec(feedId)
  if (match === null) throw new FeedRecordError('FEED_ID_INVALID')
  try { return decodeBase64(match[1]!) } catch { throw new FeedRecordError('FEED_ID_INVALID') }
}

export function feedRecordId(digest: Uint8Array): string {
  if (digest.length !== 32) throw new FeedRecordError('FEED_RECORD_ID_INVALID')
  return `%${encodeBase64(digest)}.sha256`
}

function idHash(id: string): Uint8Array {
  const match = /^%([A-Za-z0-9+/]{43}=)\.sha256$/u.exec(id)
  if (match === null) throw new FeedRecordError('FEED_RECORD_ID_INVALID')
  try { return decodeBase64(match[1]!) } catch { throw new FeedRecordError('FEED_RECORD_ID_INVALID') }
}

function signedFields(record: FeedRecordFields): CborValue {
  if (record.sequence < 1n || (record.sequence === 1n) !== (record.previous === null)) {
    throw new FeedRecordError('FEED_RECORD_PREVIOUS_INVALID')
  }
  return [1n, publicKeyFromFeedId(record.author), record.sequence,
    record.previous === null ? null : idHash(record.previous), record.timestampMs, record.payload]
}

export function feedSigningBytes(record: FeedRecordFields): Uint8Array {
  return concatBytes(RECORD_DOMAIN, encodeCanonicalCbor(signedFields(record)))
}

export function encodeSignedFeedRecord(record: FeedRecordFields, signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) throw new FeedRecordError('FEED_RECORD_SIGNATURE_INVALID')
  return encodeCanonicalCbor([signedFields(record), signature])
}

/** Parse canonical record syntax without trusting its signature or identity. */
export function decodeSignedFeedRecord(raw: Uint8Array, maxRecordBytes = DEFAULT_MAX_RECORD_BYTES): DecodedFeedRecord {
  if (!Number.isSafeInteger(maxRecordBytes) || maxRecordBytes < 1) throw new FeedRecordError('FEED_RECORD_LIMIT_INVALID')
  if (raw.length > maxRecordBytes) throw new FeedRecordError('FEED_RECORD_TOO_LARGE')
  let decoded: CborValue
  try {
    decoded = assertCanonicalCbor(raw, { ...DEFAULT_DECODE_LIMITS, maxBytes: maxRecordBytes, maxBlobBytes: maxRecordBytes })
  } catch { throw new FeedRecordError('FEED_RECORD_MALFORMED') }
  if (!Array.isArray(decoded) || decoded.length !== 2) throw new FeedRecordError('FEED_RECORD_MALFORMED')
  const [fields, signature] = decoded as readonly CborValue[]
  if (!Array.isArray(fields) || fields.length !== 6 || !(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new FeedRecordError('FEED_RECORD_MALFORMED')
  }
  const [version, publicKey, sequence, previousHash, timestampMs, payload] = fields as readonly CborValue[]
  if (version !== 1n || !(publicKey instanceof Uint8Array) || publicKey.length !== 32 ||
      typeof sequence !== 'bigint' || sequence < 1n ||
      !(previousHash === null || (previousHash instanceof Uint8Array && previousHash.length === 32)) ||
      typeof timestampMs !== 'bigint' || !(payload instanceof Uint8Array)) {
    throw new FeedRecordError('FEED_RECORD_MALFORMED')
  }
  if ((sequence === 1n) !== (previousHash === null)) throw new FeedRecordError('FEED_RECORD_PREVIOUS_INVALID')
  const record = {
    author: feedIdFromPublicKey(publicKey), sequence,
    previous: previousHash === null ? null : feedRecordId(previousHash), timestampMs,
    payload: payload.slice(),
  }
  return { ...record, signature: signature.slice(), signingBytes: feedSigningBytes(record), raw: raw.slice() }
}

export async function createFeedRecord(
  signer: FeedSigner, crypto: FeedCrypto, sequence: bigint, previous: string | null,
  timestampMs: bigint, payload: Uint8Array,
): Promise<FeedRecord> {
  const fields = { author: signer.identity, sequence, previous, timestampMs, payload: payload.slice() }
  const raw = encodeSignedFeedRecord(fields, await signer.sign(feedSigningBytes(fields)))
  // An injected signer must not be able to accidentally publish another key's feed.
  return verifyFeedRecord(raw, crypto)
}

export async function verifyFeedRecord(raw: Uint8Array, crypto: FeedCrypto, maxRecordBytes = DEFAULT_MAX_RECORD_BYTES): Promise<FeedRecord> {
  const decoded = decodeSignedFeedRecord(raw, maxRecordBytes)
  if (!await crypto.verify(publicKeyFromFeedId(decoded.author), decoded.signingBytes, decoded.signature)) {
    throw new FeedRecordError('FEED_RECORD_SIGNATURE_INVALID')
  }
  const { author, sequence, previous, timestampMs, payload } = decoded
  return { id: feedRecordId(await crypto.sha256(decoded.raw)), author, sequence, previous, timestampMs, payload, raw: decoded.raw }
}

export const webFeedCrypto: FeedCrypto = {
  async sha256(bytes) {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes.slice().buffer))
  },
  async verify(publicKey, bytes, signature) {
    const key = await globalThis.crypto.subtle.importKey('raw', publicKey.slice().buffer, 'Ed25519', false, ['verify'])
    return globalThis.crypto.subtle.verify('Ed25519', key, signature.slice().buffer, bytes.slice().buffer)
  },
}

/** The private key remains in the owning runtime; only its signer crosses the core boundary. */
export function webFeedSigner(identity: string, privateKey: CryptoKey): FeedSigner {
  publicKeyFromFeedId(identity)
  return {
    identity,
    async sign(bytes) { return new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', privateKey, bytes.slice().buffer)) },
  }
}

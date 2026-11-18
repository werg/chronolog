import { assertCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, equalBytes, sha256, utf8 } from '@chronolog/canonical'

export const MAX_RECORD_VALUE_BYTES = 128 * 1024 * 1024
export const MAX_RECORD_ENVELOPE_BYTES = MAX_RECORD_VALUE_BYTES + 8192

export function assertRecordKey(key: string): void {
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096) throw new Error('OPFS_KEY_INVALID')
}

export async function recordFilename(key: string): Promise<string> {
  assertRecordKey(key)
  return 'value-' + [...await sha256(utf8(key))].map(value => value.toString(16).padStart(2, '0')).join('')
}

/** Both durable backends store the same bounded, authenticated logical record envelope. */
export async function encodeRecordValue(key: string, bytes: Uint8Array): Promise<Uint8Array> {
  assertRecordKey(key)
  if (bytes.length > MAX_RECORD_VALUE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
  const raw = encodeCanonicalCbor([1n, key, bytes, await sha256(bytes)])
  if (raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
  return raw
}

export async function decodeRecordValue(key: string, raw: Uint8Array, corruptionCode: string): Promise<Uint8Array> {
  assertRecordKey(key)
  if (raw.length === 0 || raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error(corruptionCode)
  try {
    const decoded = assertCanonicalCbor(raw, { ...DEFAULT_DECODE_LIMITS,
      maxBytes: MAX_RECORD_ENVELOPE_BYTES, maxBlobBytes: MAX_RECORD_VALUE_BYTES })
    if (!Array.isArray(decoded) || decoded.length !== 4 || decoded[0] !== 1n || decoded[1] !== key ||
        !(decoded[2] instanceof Uint8Array) || !(decoded[3] instanceof Uint8Array) ||
        !equalBytes(decoded[3], await sha256(decoded[2]))) throw new Error(corruptionCode)
    return decoded[2].slice()
  } catch {
    throw new Error(corruptionCode)
  }
}

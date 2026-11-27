import { assertCanonicalCbor, bytesToHex, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, equalBytes, sha256Sync, utf8 } from '@chronolog/canonical'

export const MAX_RECORD_VALUE_BYTES = 128 * 1024 * 1024
export const MAX_RECORD_ENVELOPE_BYTES = MAX_RECORD_VALUE_BYTES + 8192

export function assertRecordKey(key: string): void {
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096) throw new Error('OPFS_KEY_INVALID')
}

export function recordFilenameSync(key: string): string {
  assertRecordKey(key)
  return 'value-' + bytesToHex(sha256Sync(utf8(key)))
}

export async function recordFilename(key: string): Promise<string> {
  return recordFilenameSync(key)
}

/** Synchronous authenticated logical record envelope (zero async WebCrypto IPC overhead). */
export function encodeRecordValueSync(key: string, bytes: Uint8Array): Uint8Array {
  assertRecordKey(key)
  if (bytes.length > MAX_RECORD_VALUE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
  const raw = encodeCanonicalCbor([1n, key, bytes, sha256Sync(bytes)])
  if (raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
  return raw
}

export async function encodeRecordValue(key: string, bytes: Uint8Array): Promise<Uint8Array> {
  return encodeRecordValueSync(key, bytes)
}

export function decodeRecordEntrySync(raw: Uint8Array, corruptionCode: string): { key: string; value: Uint8Array } {
  if (raw.length === 0 || raw.length > MAX_RECORD_ENVELOPE_BYTES) throw new Error(corruptionCode)
  try {
    const decoded = assertCanonicalCbor(raw, { ...DEFAULT_DECODE_LIMITS,
      maxBytes: MAX_RECORD_ENVELOPE_BYTES, maxBlobBytes: MAX_RECORD_VALUE_BYTES })
    if (!Array.isArray(decoded) || decoded.length !== 4 || decoded[0] !== 1n || typeof decoded[1] !== 'string' ||
        !(decoded[2] instanceof Uint8Array) || !(decoded[3] instanceof Uint8Array) ||
        !equalBytes(decoded[3], sha256Sync(decoded[2]))) throw new Error(corruptionCode)
    assertRecordKey(decoded[1])
    return { key: decoded[1], value: decoded[2].slice() }
  } catch {
    throw new Error(corruptionCode)
  }
}

export function decodeRecordValueSync(key: string, raw: Uint8Array, corruptionCode: string): Uint8Array {
  assertRecordKey(key)
  const entry = decodeRecordEntrySync(raw, corruptionCode)
  if (entry.key !== key) throw new Error(corruptionCode)
  return entry.value
}

export async function decodeRecordValue(key: string, raw: Uint8Array, corruptionCode: string): Promise<Uint8Array> {
  return decodeRecordValueSync(key, raw, corruptionCode)
}

export async function decodeRecordEntry(raw: Uint8Array, corruptionCode: string): Promise<{ key: string; value: Uint8Array }> {
  return decodeRecordEntrySync(raw, corruptionCode)
}

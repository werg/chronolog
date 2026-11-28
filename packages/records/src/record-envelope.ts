import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'

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

const RECORD_FORMAT = 2
const keyEncoder = new TextEncoder()
const keyDecoder = new TextDecoder('utf-8', { fatal: true })
let crcTable: Uint32Array | undefined

/** CRC-32 (IEEE) — integrity check against storage corruption (not an adversarial MAC). */
export function crc32(bytes: Uint8Array): number {
  const table = crcTable ??= (() => {
    const t = new Uint32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      t[n] = c >>> 0
    }
    return t
  })()
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) crc = table[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

/**
 * Logical record envelope for raw browser stores (IndexedDB):
 *   u8 format (2) | u16 keyLen | key UTF-8 | u32 CRC-32(value) | value
 * The key binding catches misplaced values and the CRC catches torn/corrupt writes. Values in
 * this device's own store were authenticated at ingress (signed ops, hashed CAS nodes), so the
 * envelope does not re-hash them with SHA-256 on every read (trust shortcut, cold open).
 */
export function encodeRecordValueSync(key: string, bytes: Uint8Array): Uint8Array {
  assertRecordKey(key)
  if (bytes.length > MAX_RECORD_VALUE_BYTES) throw new Error('BYTES_STORE_VALUE_LIMIT')
  const keyBytes = keyEncoder.encode(key)
  if (keyBytes.length > 0xffff) throw new Error('OPFS_KEY_INVALID')
  const raw = new Uint8Array(1 + 2 + keyBytes.length + 4 + bytes.length)
  const view = new DataView(raw.buffer)
  raw[0] = RECORD_FORMAT
  view.setUint16(1, keyBytes.length)
  raw.set(keyBytes, 3)
  view.setUint32(3 + keyBytes.length, crc32(bytes))
  raw.set(bytes, 7 + keyBytes.length)
  return raw
}

export async function encodeRecordValue(key: string, bytes: Uint8Array): Promise<Uint8Array> {
  return encodeRecordValueSync(key, bytes)
}

export function decodeRecordEntrySync(raw: Uint8Array, corruptionCode: string): { key: string; value: Uint8Array } {
  if (raw.length < 7 || raw.length > MAX_RECORD_ENVELOPE_BYTES || raw[0] !== RECORD_FORMAT) throw new Error(corruptionCode)
  try {
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength)
    const keyLen = view.getUint16(1)
    if (7 + keyLen > raw.length) throw new Error(corruptionCode)
    const key = keyDecoder.decode(raw.subarray(3, 3 + keyLen))
    assertRecordKey(key)
    const value = raw.slice(7 + keyLen)
    if (view.getUint32(3 + keyLen) !== crc32(value)) throw new Error(corruptionCode)
    return { key, value }
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

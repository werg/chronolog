import { toSqlValue, sqlValueToCanonicalCbor, type SqlValue } from './sql.js'

/** Opaque, versioned keys shared with the native chronolog_row_key() function. */
export const ROW_KEY_PREFIX = 'rk1:'
export const MAX_ROW_KEY_PARTS = 64

/** TEXT stays as UTF-8 bytes so even SQLite text made from invalid UTF-8 is lossless. */
export type RowKeyPart =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: bigint }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text' | 'blob'; readonly value: Uint8Array }

/**
 * Encode values in their stored SQLite types. For a key containing
 * chronolog_owner, supply the owner's 32-byte key instead of its local id.
 * Resolve affinity/coercion with SQL before encoding an existing row.
 */
export function encodeRowKey(values: readonly unknown[]): string {
  if (values.length < 1 || values.length > MAX_ROW_KEY_PARTS) throw new Error('ROW_KEY_ARITY')
  const chunks: Uint8Array[] = [Uint8Array.of(0, values.length)]
  for (const input of values) {
    const value: SqlValue = toSqlValue(input)
    sqlValueToCanonicalCbor(value)
    if (value.kind === 'null') { chunks.push(Uint8Array.of(0)); continue }
    if (value.kind === 'integer' || value.kind === 'real') {
      const chunk = new Uint8Array(9)
      const view = new DataView(chunk.buffer)
      chunk[0] = value.kind === 'integer' ? 1 : 2
      if (value.kind === 'integer') view.setBigInt64(1, value.value, false)
      else view.setFloat64(1, value.value, false)
      chunks.push(chunk)
    } else {
      const bytes = value.kind === 'text' ? new TextEncoder().encode(value.value) : value.value
      const chunk = new Uint8Array(5 + bytes.length)
      chunk[0] = value.kind === 'text' ? 3 : 4
      new DataView(chunk.buffer).setUint32(1, bytes.length, false)
      chunk.set(bytes, 5)
      chunks.push(chunk)
    }
  }
  return ROW_KEY_PREFIX + chunks.map((chunk) => Array.from(chunk, (byte) => byte.toString(16).padStart(2, '0')).join('')).join('')
}

/** Decode the exact typed tuple, rejecting unknown versions, truncation and trailing data. */
export function decodeRowKey(key: string): readonly RowKeyPart[] {
  const fail = (): never => { throw new Error('ROW_KEY_INVALID') }
  if (!key.startsWith(ROW_KEY_PREFIX)) fail()
  const hex = key.slice(ROW_KEY_PREFIX.length)
  if (hex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(hex)) fail()
  const bytes = Uint8Array.from(hex.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16))
  const view = new DataView(bytes.buffer)
  let offset = 0
  const take = (length: number): number => {
    const start = offset
    if (length > bytes.length - offset) fail()
    offset += length
    return start
  }
  const count = view.getUint16(take(2), false)
  if (count < 1 || count > MAX_ROW_KEY_PARTS) fail()
  const values: RowKeyPart[] = []
  for (let index = 0; index < count; index += 1) {
    const kind = bytes[take(1)]
    if (kind === 0) values.push({ kind: 'null' })
    else if (kind === 1) values.push({ kind: 'integer', value: view.getBigInt64(take(8), false) })
    else if (kind === 2) {
      const value = view.getFloat64(take(8), false)
      if (Number.isNaN(value)) fail() // SQLite stores a NaN as NULL.
      values.push({ kind: 'real', value })
    } else if (kind === 3 || kind === 4) {
      const length = view.getUint32(take(4), false)
      const start = take(length)
      values.push({ kind: kind === 3 ? 'text' : 'blob', value: bytes.slice(start, start + length) })
    } else fail()
  }
  if (offset !== bytes.length) fail()
  return values
}

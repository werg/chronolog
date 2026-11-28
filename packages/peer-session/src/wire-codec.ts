/**
 * Compact binary codec for peer wire messages (Chronolog sync v3).
 *
 * A CBOR subset over plain JS values: null, booleans, safe integers, finite floats, bigint
 * (tag 48), strings, byte strings, arrays and string-keyed objects (undefined properties are
 * dropped). Messages are authenticated by the secure channel and individual facts carry their own
 * signatures, so this codec is not canonical; it is a single allocation-light pass each way.
 */

const BIGINT_TAG = 48
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

export interface WireDecodeLimits {
  readonly maxDepth: number
  readonly maxItems: number
}
const DEFAULT_LIMITS: WireDecodeLimits = { maxDepth: 32, maxItems: 1_000_000 }

class Writer {
  #buf = new Uint8Array(1024)
  #view = new DataView(this.#buf.buffer)
  #len = 0
  #ensure(extra: number): void {
    if (this.#len + extra <= this.#buf.length) return
    let size = this.#buf.length * 2
    while (size < this.#len + extra) size *= 2
    const next = new Uint8Array(size); next.set(this.#buf.subarray(0, this.#len))
    this.#buf = next; this.#view = new DataView(next.buffer)
  }
  head(major: number, value: number): void {
    this.#ensure(9)
    const m = major << 5
    if (value < 24) this.#buf[this.#len++] = m | value
    else if (value < 0x100) { this.#buf[this.#len++] = m | 24; this.#buf[this.#len++] = value }
    else if (value < 0x10000) { this.#buf[this.#len++] = m | 25; this.#view.setUint16(this.#len, value); this.#len += 2 }
    else if (value < 0x1_0000_0000) { this.#buf[this.#len++] = m | 26; this.#view.setUint32(this.#len, value); this.#len += 4 }
    else { this.#buf[this.#len++] = m | 27; this.#view.setBigUint64(this.#len, BigInt(value)); this.#len += 8 }
  }
  bytes(bytes: Uint8Array): void { this.#ensure(bytes.length); this.#buf.set(bytes, this.#len); this.#len += bytes.length }
  float(value: number): void { this.#ensure(9); this.#buf[this.#len++] = 0xfb; this.#view.setFloat64(this.#len, value); this.#len += 8 }
  byte(value: number): void { this.#ensure(1); this.#buf[this.#len++] = value }
  result(): Uint8Array { return this.#buf.slice(0, this.#len) }
}

function write(w: Writer, value: unknown, depth: number): void {
  if (depth > 64) throw new Error('WIRE_ENCODE_DEPTH')
  if (value === null || value === undefined) { w.byte(0xf6); return }
  if (value === false) { w.byte(0xf4); return }
  if (value === true) { w.byte(0xf5); return }
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value)) { if (value >= 0) w.head(0, value); else w.head(1, -1 - value); return }
    if (!Number.isFinite(value)) throw new Error('WIRE_ENCODE_NUMBER')
    w.float(value); return
  }
  if (typeof value === 'bigint') {
    w.head(6, BIGINT_TAG)
    const text = textEncoder.encode(value.toString())
    w.head(3, text.length); w.bytes(text); return
  }
  if (typeof value === 'string') { const text = textEncoder.encode(value); w.head(3, text.length); w.bytes(text); return }
  if (value instanceof Uint8Array) { w.head(2, value.length); w.bytes(value); return }
  if (Array.isArray(value)) { w.head(4, value.length); for (const item of value) write(w, item, depth + 1); return }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined)
    w.head(5, entries.length)
    for (const [key, item] of entries) {
      const text = textEncoder.encode(key); w.head(3, text.length); w.bytes(text)
      write(w, item, depth + 1)
    }
    return
  }
  throw new Error('WIRE_ENCODE_UNSUPPORTED')
}

export function encodeWireValue(value: unknown): Uint8Array {
  const w = new Writer(); write(w, value, 0); return w.result()
}

class Reader {
  #pos = 0
  #items = 0
  readonly #view: DataView
  constructor(readonly input: Uint8Array, readonly limits: WireDecodeLimits) {
    this.#view = new DataView(input.buffer, input.byteOffset, input.byteLength)
  }
  get done(): boolean { return this.#pos === this.input.length }
  #need(n: number): void { if (this.#pos + n > this.input.length) throw new Error('WIRE_DECODE_TRUNCATED') }
  #arg(additional: number): number {
    if (additional < 24) return additional
    if (additional === 24) { this.#need(1); return this.input[this.#pos++]! }
    if (additional === 25) { this.#need(2); const v = this.#view.getUint16(this.#pos); this.#pos += 2; return v }
    if (additional === 26) { this.#need(4); const v = this.#view.getUint32(this.#pos); this.#pos += 4; return v }
    if (additional === 27) {
      this.#need(8); const v = this.#view.getBigUint64(this.#pos); this.#pos += 8
      if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('WIRE_DECODE_RANGE')
      return Number(v)
    }
    throw new Error('WIRE_DECODE_INVALID')
  }
  #text(length: number): string {
    this.#need(length); const value = textDecoder.decode(this.input.subarray(this.#pos, this.#pos + length)); this.#pos += length; return value
  }
  value(depth: number): unknown {
    if (depth > this.limits.maxDepth) throw new Error('WIRE_DECODE_DEPTH')
    if (++this.#items > this.limits.maxItems) throw new Error('WIRE_DECODE_ITEMS')
    this.#need(1)
    const initial = this.input[this.#pos++]!, major = initial >> 5, additional = initial & 31
    if (major === 7) {
      if (additional === 20) return false
      if (additional === 21) return true
      if (additional === 22) return null
      if (additional === 27) { this.#need(8); const v = this.#view.getFloat64(this.#pos); this.#pos += 8; return v }
      throw new Error('WIRE_DECODE_INVALID')
    }
    const arg = this.#arg(additional)
    switch (major) {
      case 0: return arg
      case 1: return -1 - arg
      case 2: { this.#need(arg); const out = this.input.slice(this.#pos, this.#pos + arg); this.#pos += arg; return out }
      case 3: return this.#text(arg)
      case 4: {
        if (arg > this.input.length - this.#pos) throw new Error('WIRE_DECODE_TRUNCATED')
        const out = new Array<unknown>(arg)
        for (let i = 0; i < arg; i++) out[i] = this.value(depth + 1)
        return out
      }
      case 5: {
        if (arg > this.input.length - this.#pos) throw new Error('WIRE_DECODE_TRUNCATED')
        const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>
        for (let i = 0; i < arg; i++) {
          this.#need(1)
          const keyHead = this.input[this.#pos++]!
          if (keyHead >> 5 !== 3) throw new Error('WIRE_DECODE_KEY')
          const key = this.#text(this.#arg(keyHead & 31))
          if (key === '__proto__') throw new Error('WIRE_DECODE_KEY')
          out[key] = this.value(depth + 1)
        }
        return Object.assign({}, out)
      }
      case 6: {
        if (arg !== BIGINT_TAG) throw new Error('WIRE_DECODE_TAG')
        const inner = this.value(depth + 1)
        if (typeof inner !== 'string' || !/^-?\d{1,80}$/u.test(inner)) throw new Error('WIRE_DECODE_BIGINT')
        return BigInt(inner)
      }
      default: throw new Error('WIRE_DECODE_INVALID')
    }
  }
}

export function decodeWireValue(input: Uint8Array, limits: WireDecodeLimits = DEFAULT_LIMITS): unknown {
  const reader = new Reader(input, limits)
  const value = reader.value(0)
  if (!reader.done) throw new Error('WIRE_DECODE_TRAILING')
  return value
}

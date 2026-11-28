import type { BytesStore, BytesStoreEntry } from '@chronolog/records'
import { bytesToHex } from '@chronolog/protocol'
import { reserveCheckpointStore, retireDeviceStore } from './checkpoint-lifecycle.js'
import { deriveAesKey, validateMetadata } from './checkpoint-codec.js'
import { assertDeviceNotRetired, CHECKPOINT_FORMAT, DEVICE_RETIRED_KEY,
  type CheckpointMetadata, type CheckpointOutboxRecord } from './checkpoint.js'

const MAGIC = Uint8Array.of(67, 76, 67, 80, 2)
const BLOCK = 65_536, MAX_FRAME = 2 * 1024 * 1024
const text = new TextEncoder(), utf8 = new TextDecoder('utf-8', { fatal: true })
const fail = (code: string) => Object.assign(new Error(code), { code })

export interface CheckpointLimits {
  /** Optional application budget; streaming has no fixed aggregate size or entry cap. */
  readonly maxBytes?: number
  readonly maxEntries?: number
  /** A BytesStore value is yielded as one buffer; use this budget for untrusted imports. */
  readonly maxValueBytes?: number
}
export interface CheckpointSink {
  write(bytes: Uint8Array): void | Promise<void>
  /** Resolve only after every written byte is durable. */
  commit(metadata: CheckpointMetadata): void | Promise<void>
  abort?(reason: unknown): void | Promise<void>
}
export interface ExportCheckpointStreamOptions {
  readonly secret: Uint8Array | string
  readonly sink: CheckpointSink
  readonly applicationId?: string | null
  readonly deviceId?: string | null
  readonly outbox?: readonly CheckpointOutboxRecord[]
  readonly retireSource?: boolean
  readonly limits?: CheckpointLimits
  readonly sqlDatabase?: { readonly bytes: number; readonly chunks: AsyncIterable<Uint8Array> }
}
export interface RestoreCheckpointStreamOptions {
  readonly secret: Uint8Array | string
  readonly limits?: CheckpointLimits
  /** Stage SQL outside memory. commit is called only after the complete input authenticates. */
  readonly sqlSink?: CheckpointSink
}
function budget(limits: CheckpointLimits | undefined, name: keyof CheckpointLimits): number {
  const value = limits?.[name] ?? Number.MAX_SAFE_INTEGER
  if (!Number.isSafeInteger(value) || value < 0) throw fail('CHECKPOINT_LIMIT_INVALID')
  return value
}
function keyValid(key: unknown): asserts key is string {
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096 || [...key].some(c => c.charCodeAt(0) < 32) || key === DEVICE_RETIRED_KEY) throw fail('CHECKPOINT_CORRUPT')
}
function outboxRecord(value: unknown): asserts value is CheckpointOutboxRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).some(key => !['operationId', 'command', 'payloadHash', 'createdAt', 'status'].includes(key))) throw fail('CHECKPOINT_CORRUPT')
  validateMetadata({ format: CHECKPOINT_FORMAT, applicationId: null, deviceId: null, createdAt: '1970-01-01T00:00:00.000Z',
    entryCount: 0, hasSqlDatabase: false, outboxCount: 1, manifestSha256: '0'.repeat(64) }, [value as CheckpointOutboxRecord])
}
function sizeValid(size: unknown): asserts size is number {
  if (!Number.isSafeInteger(size) || (size as number) < 0) throw fail('CHECKPOINT_CORRUPT')
}
function join(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0))
  let offset = 0
  for (const part of parts) { out.set(part, offset); offset += part.length }
  return out
}
function uint(value: number): Uint8Array<ArrayBuffer> { const out = new Uint8Array(4); new DataView(out.buffer).setUint32(0, value); return out }
async function chain(previous: Uint8Array, frame: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', join(previous, frame)))
}
function jsonFrame(kind: number, value: unknown): Uint8Array<ArrayBuffer> { return join(Uint8Array.of(kind), text.encode(JSON.stringify(value))) }
function nonce(header: Uint8Array, index: number): Uint8Array<ArrayBuffer> {
  if (index >= 2 ** 32) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
  return join(header.subarray(27, 35), uint(index))
}
function metadata(options: ExportCheckpointStreamOptions, count: number, digest: Uint8Array, createdAt: string): CheckpointMetadata {
  return { format: CHECKPOINT_FORMAT, applicationId: options.applicationId ?? null, deviceId: options.deviceId ?? null,
    createdAt, entryCount: count, hasSqlDatabase: options.sqlDatabase !== undefined, outboxCount: options.outbox?.length ?? 0, manifestSha256: bytesToHex(digest) }
}

/** Stream authenticated binary frames; durable sink commit precedes source retirement. */
export async function exportDeviceCheckpointStream(store: BytesStore, options: ExportCheckpointStreamOptions): Promise<{ readonly metadata: CheckpointMetadata; readonly retiredSource: boolean }> {
  if (store.iterateEntries === undefined) throw fail('CHECKPOINT_ENUMERATION_UNSUPPORTED')
  const maxBytes = budget(options.limits, 'maxBytes'), maxEntries = budget(options.limits, 'maxEntries'), maxValue = budget(options.limits, 'maxValueBytes')
  const release = reserveCheckpointStore(store)
  try {
    await assertDeviceNotRetired(store)
    const secret = options.secret instanceof Uint8Array ? Uint8Array.from(options.secret) : options.secret
    const outbox = structuredClone(options.outbox ?? []), createdAt = new Date().toISOString()
    let digest = new Uint8Array(32), index = 0, count = 0, total = 0
    validateMetadata(metadata(options, 0, digest, createdAt), outbox)
    for (const record of outbox) outboxRecord(record)
    const header = join(MAGIC, Uint8Array.of(secret instanceof Uint8Array ? 1 : 0), Uint8Array.of(1), uint(secret instanceof Uint8Array ? 0 : 600_000),
      secret instanceof Uint8Array ? new Uint8Array(16) : crypto.getRandomValues(new Uint8Array(16)), crypto.getRandomValues(new Uint8Array(8)))
    const key = await deriveAesKey(secret, header.subarray(11, 27), ['encrypt'])
    let tag = new Uint8Array(16)
    await options.sink.write(header)
    const write = async (frame: Uint8Array, hash = true) => {
      if (frame.length > MAX_FRAME) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce(header, index++), additionalData: join(header, tag) }, key, join(frame)))
      tag = encrypted.slice(-16)
      await options.sink.write(join(uint(encrypted.length), encrypted))
      if (hash) digest = await chain(digest, frame)
    }
    for await (const entry of store.iterateEntries()) {
      if (entry.key === DEVICE_RETIRED_KEY) continue
      keyValid(entry.key)
      if (++count > maxEntries || entry.value.length > maxValue || total + entry.value.length > maxBytes) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
      total += entry.value.length
      await write(jsonFrame(1, { key: entry.key, bytes: entry.value.length }))
      for (let offset = 0; offset < entry.value.length; offset += BLOCK) await write(join(Uint8Array.of(2), entry.value.subarray(offset, offset + BLOCK)))
    }
    if (options.sqlDatabase !== undefined) {
      const sql = options.sqlDatabase
      sizeValid(sql.bytes)
      if (total + sql.bytes > maxBytes) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
      await write(jsonFrame(3, { bytes: sql.bytes }))
      let size = 0
      for await (const part of sql.chunks) {
        size += part.length
        if (size > sql.bytes) throw fail('CHECKPOINT_CORRUPT')
        for (let offset = 0; offset < part.length; offset += BLOCK) await write(join(Uint8Array.of(4), part.subarray(offset, offset + BLOCK)))
      }
      if (size !== sql.bytes) throw fail('CHECKPOINT_CORRUPT')
    }
    for (const record of outbox) await write(jsonFrame(6, record))
    const result = Object.freeze(metadata({ ...options, outbox }, count, digest, createdAt))
    await write(jsonFrame(5, { metadata: result }), false)
    await options.sink.commit(result)
    const retireSource = options.retireSource !== false
    if (retireSource) {
      await store.put(DEVICE_RETIRED_KEY, text.encode(JSON.stringify({ retiredAt: createdAt, manifestSha256: result.manifestSha256 })))
      retireDeviceStore(store)
    }
    return { metadata: result, retiredSource: retireSource }
  } catch (error) { try { await options.sink.abort?.(error) } catch { /* Preserve the failure. */ } throw error }
  finally { release() }
}

class StreamReader {
  readonly #iterator: AsyncIterator<Uint8Array>
  #part: Uint8Array = new Uint8Array()
  #offset = 0
  constructor(source: AsyncIterable<Uint8Array>) { this.#iterator = source[Symbol.asyncIterator]() }
  async read(size: number, eof = false): Promise<Uint8Array<ArrayBuffer> | null> {
    const bytes = new Uint8Array(size)
    let offset = 0
    while (offset < size) {
      if (this.#offset === this.#part.length) {
        const next = await this.#iterator.next()
        if (next.done === true) { if (eof && offset === 0) return null; throw fail('CHECKPOINT_CORRUPT') }
        if (!(next.value instanceof Uint8Array)) throw fail('CHECKPOINT_CORRUPT')
        this.#part = next.value; this.#offset = 0
        continue
      }
      const length = Math.min(size - offset, this.#part.length - this.#offset)
      bytes.set(this.#part.subarray(this.#offset, this.#offset + length), offset)
      offset += length; this.#offset += length
    }
    return bytes
  }
  async close(): Promise<void> { await this.#iterator.return?.() }
}

/** Authenticates the footer before atomic target publication; failed imports leave no identity. */
export async function restoreDeviceCheckpointStream(target: BytesStore, source: AsyncIterable<Uint8Array>, options: RestoreCheckpointStreamOptions): Promise<{
  readonly metadata: CheckpointMetadata; readonly restoredEntries: number; readonly sqlDatabaseBytes: Uint8Array | null; readonly outbox: readonly CheckpointOutboxRecord[]
}> {
  if (target.putStreamIfEmpty === undefined || target.iterateEntries === undefined) throw fail('CHECKPOINT_RESTORE_UNSUPPORTED')
  const maxBytes = budget(options.limits, 'maxBytes'), maxEntries = budget(options.limits, 'maxEntries'), maxValue = budget(options.limits, 'maxValueBytes')
  const release = reserveCheckpointStore(target), reader = new StreamReader(source)
  let result: { metadata: CheckpointMetadata; outbox: CheckpointOutboxRecord[] } | undefined, sqlDatabaseBytes: Uint8Array | null = null
  try {
    const header = (await reader.read(35))!
    if (!MAGIC.every((byte, index) => header[index] === byte)) throw fail('CHECKPOINT_FORMAT_UNSUPPORTED')
    const raw = header[5] === 1, iterations = new DataView(header.buffer).getUint32(7)
    if (header[5] !== 0 && !raw || header[6] !== 1 || (raw ? iterations !== 0 || header.subarray(11, 27).some(byte => byte !== 0) : iterations < 600_000 || iterations > 2_000_000)) throw fail('CHECKPOINT_CORRUPT')
    if (raw !== (options.secret instanceof Uint8Array)) throw fail('CHECKPOINT_KEY_MISMATCH')
    const secret = options.secret instanceof Uint8Array ? Uint8Array.from(options.secret) : options.secret
    const key = await deriveAesKey(secret, header.subarray(11, 27), ['decrypt'], iterations)
    let tag = new Uint8Array(16), digest = new Uint8Array(32), entrySum = 0n, index = 0, count = 0, total = 0, sqlSeen = false
    const nextFrame = async (): Promise<Uint8Array<ArrayBuffer>> => {
      const lengthBytes = (await reader.read(4))!, length = new DataView(lengthBytes.buffer).getUint32(0)
      if (length < 17 || length > MAX_FRAME + 16) throw fail('CHECKPOINT_CORRUPT')
      const encrypted = (await reader.read(length))!
      let frame: Uint8Array<ArrayBuffer>
      try { frame = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce(header, index++), additionalData: join(header, tag) }, key, encrypted)) }
      catch { throw fail('CHECKPOINT_DECRYPT_FAILED') }
      tag = encrypted.slice(-16)
      if (frame[0] !== 5) digest = await chain(digest, frame)
      return frame
    }
    const outbox: CheckpointOutboxRecord[] = []
    const entries = async function* (): AsyncGenerator<BytesStoreEntry> {
      for (;;) {
        const frame = await nextFrame()
        if (frame[0] === 5) {
          result = { metadata: (JSON.parse(utf8.decode(frame.subarray(1))) as { metadata: CheckpointMetadata }).metadata, outbox }
          if (result.metadata?.format !== CHECKPOINT_FORMAT) throw fail('CHECKPOINT_CORRUPT')
          validateMetadata(result.metadata, result.outbox)
          if (result.metadata.entryCount !== count || result.metadata.hasSqlDatabase !== sqlSeen || result.metadata.outboxCount !== result.outbox.length || result.metadata.manifestSha256 !== bytesToHex(digest)) throw fail('CHECKPOINT_INTEGRITY_MISMATCH')
          if (await reader.read(1, true) !== null) throw fail('CHECKPOINT_CORRUPT')
          if (sqlSeen) await options.sqlSink?.commit(result.metadata)
          return
        }
        if (frame[0] === 6) {
          if (outbox.length >= 1024) throw fail('CHECKPOINT_CORRUPT')
          const record: unknown = JSON.parse(utf8.decode(frame.subarray(1)))
          outboxRecord(record); outbox.push(record)
          continue
        }
        if (frame[0] !== 1 && frame[0] !== 3 || sqlSeen || outbox.length !== 0) throw fail('CHECKPOINT_CORRUPT')
        const entry = JSON.parse(utf8.decode(frame.subarray(1))) as { key?: string; bytes: number }
        sizeValid(entry.bytes)
        total += entry.bytes
        if (total > maxBytes) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
        const sql = frame[0] === 3
        if (sql) sqlSeen = true
        else { keyValid(entry.key); if (++count > maxEntries) throw fail('CHECKPOINT_LIMIT_EXCEEDED') }
        if ((!sql || options.sqlSink === undefined) && entry.bytes > maxValue) throw fail('CHECKPOINT_LIMIT_EXCEEDED')
        const value = sql && options.sqlSink !== undefined ? null : new Uint8Array(entry.bytes)
        let entryDigest = await chain(new Uint8Array(32), jsonFrame(1, { key: entry.key, bytes: entry.bytes }))
        let offset = 0
        while (offset < entry.bytes) {
          const part = await nextFrame()
          if (part[0] !== (sql ? 4 : 2) || part.length <= 1 || part.length > BLOCK + 1 || offset + part.length - 1 > entry.bytes || !sql && part.length - 1 !== Math.min(BLOCK, entry.bytes - offset)) throw fail('CHECKPOINT_CORRUPT')
          if (value === null) await options.sqlSink!.write(part.subarray(1))
          else value.set(part.subarray(1), offset)
          entryDigest = await chain(entryDigest, part)
          offset += part.length - 1
        }
        if (sql) sqlDatabaseBytes = value
        else { entrySum = (entrySum + BigInt('0x' + bytesToHex(entryDigest))) % (1n << 256n); yield { key: entry.key!, value: value! } }
      }
    }
    if (!await target.putStreamIfEmpty(entries())) throw fail('CHECKPOINT_TARGET_NOT_EMPTY')
    if (result === undefined) throw fail('CHECKPOINT_CORRUPT')
    let readbackSum = 0n, readbackCount = 0
    for await (const entry of target.iterateEntries()) {
      let readback = await chain(new Uint8Array(32), jsonFrame(1, { key: entry.key, bytes: entry.value.length }))
      for (let offset = 0; offset < entry.value.length; offset += BLOCK) readback = await chain(readback, join(Uint8Array.of(2), entry.value.subarray(offset, offset + BLOCK)))
      readbackSum = (readbackSum + BigInt('0x' + bytesToHex(readback))) % (1n << 256n)
      readbackCount++
    }
    if (readbackSum !== entrySum || readbackCount !== count) throw fail('CHECKPOINT_RESTORE_VERIFICATION_FAILED')
    return { metadata: Object.freeze(result.metadata), outbox: Object.freeze(result.outbox), restoredEntries: count, sqlDatabaseBytes }
  } catch (error) { try { await options.sqlSink?.abort?.(error) } catch { /* Preserve the failure. */ } throw error }
  finally { try { await reader.close() } finally { release() } }
}

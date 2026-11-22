import { reserveCheckpointStore, retireDeviceStore } from './checkpoint-lifecycle.js'
import type { BytesStore, BytesStoreEntry } from '@chronolog/records'
import { bytesToHex, hexToBytes } from '@chronolog/protocol'

export const CHECKPOINT_FORMAT = 'chronolog-device-checkpoint-v1'
export const DEVICE_RETIRED_KEY = 'peer-session/checkpoint-retired/v1'

export interface CheckpointMetadata {
  readonly format: typeof CHECKPOINT_FORMAT
  readonly applicationId: string | null
  readonly deviceId: string | null
  readonly createdAt: string
  readonly entryCount: number
  readonly hasSqlDatabase: boolean
  readonly outboxCount: number
  readonly manifestSha256: string
}

export interface CheckpointOutboxRecord {
  readonly operationId: string
  readonly command?: string
  readonly payloadHash?: string
  readonly createdAt: string
  readonly status?: string
}

export interface ExportCheckpointOptions {
  /** 32-byte raw AES-256-GCM key or passphrase string (derived via PBKDF2-SHA256). */
  readonly secret: Uint8Array | string
  readonly applicationId?: string | null
  readonly deviceId?: string | null
  /** Optional quiesced SQLite database bytes (read after WAL checkpoint, never raw sidecar copy). */
  readonly sqlDatabaseBytes?: Uint8Array | null
  /** Optional pending pre-submission outbox records to carry across sandbox replacement. */
  readonly outbox?: readonly CheckpointOutboxRecord[]
  /** Mark the exported source store retired (default: true) to prevent split-brain active copies. */
  readonly retireSource?: boolean
  /** Durably retain the encrypted checkpoint before retiring its source. Required for moves. */
  readonly persist?: (checkpoint: Readonly<{ bytes: Uint8Array; metadata: CheckpointMetadata }>) => void | Promise<void>
}

export interface ExportedCheckpoint {
  readonly bytes: Uint8Array
  readonly metadata: CheckpointMetadata
  readonly retiredSource: boolean
}

export interface RestoredCheckpoint {
  readonly metadata: CheckpointMetadata
  readonly sqlDatabaseBytes: Uint8Array | null
  readonly outbox: readonly CheckpointOutboxRecord[]
  readonly restoredEntries: number
}

const MAGIC = new Uint8Array([0x43, 0x4c, 0x43, 0x50, 0x01]) // "CLCP\x01"
const SALT_BYTES = 16
const IV_BYTES = 12
const PBKDF2_ITERATIONS = 100_000
const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true })
const MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024
const MAX_ENTRIES = 4096

function fail(code: string, message: string): Error {
  return Object.assign(new Error(message), { code })
}

async function deriveAesKey(secret: Uint8Array | string, salt: Uint8Array, usage: readonly KeyUsage[]): Promise<CryptoKey> {
  if (secret instanceof Uint8Array) {
    if (secret.byteLength !== 32) throw fail('CHECKPOINT_KEY_INVALID', 'Raw checkpoint encryption key must be exactly 32 bytes.')
    const copy = new Uint8Array(secret.byteLength)
    copy.set(secret)
    return crypto.subtle.importKey('raw', copy, { name: 'AES-GCM' }, false, [...usage])
  }
  if (typeof secret !== 'string' || secret.length < 12) {
    throw fail('CHECKPOINT_KEY_INVALID', 'Checkpoint passphrase must be at least 12 characters.')
  }
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'PBKDF2' }, false, ['deriveKey'])
  const saltCopy = new Uint8Array(salt.byteLength)
  saltCopy.set(salt)
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltCopy, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [...usage],
  )
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunk, bytes.length)))
  }
  return btoa(binary)
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value)
  if (btoa(binary) !== value) throw fail('CHECKPOINT_CORRUPT', 'Invalid base64 checkpoint data.')
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', copy)))
}

async function manifestDigest(entries: readonly BytesStoreEntry[], sqlBytes: Uint8Array | null, outbox: readonly CheckpointOutboxRecord[]): Promise<string> {
  const entryDigests = []
  for (const entry of entries) entryDigests.push([entry.key, await sha256Hex(entry.value), entry.value.byteLength])
  const sqlDigest = sqlBytes === null ? null : [await sha256Hex(sqlBytes), sqlBytes.byteLength] as const
  const canonical = JSON.stringify({ entries: entryDigests, sql: sqlDigest, outbox })
  return sha256Hex(encoder.encode(canonical))
}

function validateMetadata(metadata: CheckpointMetadata, outbox: readonly CheckpointOutboxRecord[]): void {
  if (typeof metadata.createdAt !== 'string' || !Number.isFinite(Date.parse(metadata.createdAt)) ||
      [metadata.applicationId, metadata.deviceId].some(id => id !== null && (typeof id !== 'string' || !/^[a-f0-9]{64}$/u.test(id))) ||
      typeof metadata.manifestSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(metadata.manifestSha256) || outbox.length > 1024) throw fail('CHECKPOINT_CORRUPT', 'Invalid checkpoint metadata.')
  const seen = new Set<string>()
  for (const entry of outbox) {
    if (!entry || typeof entry.operationId !== 'string' || !entry.operationId || entry.operationId.length > 512 ||
        [...entry.operationId].some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127) || seen.has(entry.operationId) ||
        typeof entry.createdAt !== 'string' || !Number.isFinite(Date.parse(entry.createdAt)) ||
        entry.command !== undefined && (typeof entry.command !== 'string' || !entry.command || entry.command.length > 128) ||
        entry.payloadHash !== undefined && (typeof entry.payloadHash !== 'string' || !/^[a-f0-9]{64}$/u.test(entry.payloadHash)) ||
        entry.status !== undefined && (typeof entry.status !== 'string' || entry.status.length > 128)) throw fail('CHECKPOINT_CORRUPT', 'Invalid retained outbox record.')
    seen.add(entry.operationId)
  }
}

/** Check whether a store has been retired by an earlier checkpoint export. */
export async function isDeviceRetired(store: BytesStore): Promise<{ readonly retired: boolean; readonly retiredAt?: string; readonly manifestSha256?: string }> {
  const raw = await store.get(DEVICE_RETIRED_KEY)
  if (raw === null) return { retired: false }
  try {
    const parsed = JSON.parse(decoder.decode(raw)) as { retiredAt?: string; manifestSha256?: string }
    return {
      retired: true,
      ...(typeof parsed.retiredAt === 'string' ? { retiredAt: parsed.retiredAt } : {}),
      ...(typeof parsed.manifestSha256 === 'string' ? { manifestSha256: parsed.manifestSha256 } : {}),
    }
  } catch {
    return { retired: true }
  }
}

/** Fail closed if a store was retired by an earlier checkpoint handoff. */
export async function assertDeviceNotRetired(store: BytesStore): Promise<void> {
  const status = await isDeviceRetired(store)
  if (status.retired) {
    throw fail('DEVICE_RETIRED_BY_CHECKPOINT', 'This local device store was retired when exported to a checkpoint. Resume from the restored target instance.')
  }
}

/**
 * Export a quiesced store under the local device/checkpoint fence
 * (Node SQLite, Browser IndexedDB/OPFS, or Serverless KV) and optionally retire the source store.
 */
export async function exportDeviceCheckpoint(store: BytesStore, options: ExportCheckpointOptions): Promise<ExportedCheckpoint> {
  if (options.retireSource !== false && typeof options.persist !== 'function') throw fail('CHECKPOINT_PERSISTENCE_REQUIRED', 'Durably persist the encrypted handoff before source retirement.')
  options = { ...options, secret: options.secret instanceof Uint8Array ? options.secret.slice() : options.secret }
  const release = reserveCheckpointStore(store)
  try {
  if (typeof store.entries !== 'function') {
    throw fail('CHECKPOINT_ENUMERATION_UNSUPPORTED', 'The supplied BytesStore does not support deterministic checkpoint enumeration.')
  }
  await assertDeviceNotRetired(store)
  const rawEntries = (await store.entries())
    .filter(entry => entry.key !== DEVICE_RETIRED_KEY)
    .map(entry => ({ key: entry.key, value: entry.value.slice() }))
    .sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
  const sqlBytes = options.sqlDatabaseBytes?.slice() ?? null
  const outbox = structuredClone(options.outbox ?? [])
  if (rawEntries.length > MAX_ENTRIES || rawEntries.reduce((size, entry) => size + entry.value.byteLength, sqlBytes?.byteLength ?? 0) > MAX_CHECKPOINT_BYTES / 2) {
    throw fail('CHECKPOINT_LIMIT_EXCEEDED', 'Checkpoint data exceeds the bounded handoff limit.')
  }
  const createdAt = new Date().toISOString()
  const manifestSha256 = await manifestDigest(rawEntries, sqlBytes, outbox)
  const metadata: CheckpointMetadata = Object.freeze({
    format: CHECKPOINT_FORMAT,
    applicationId: options.applicationId ?? null,
    deviceId: options.deviceId ?? null,
    createdAt,
    entryCount: rawEntries.length,
    hasSqlDatabase: sqlBytes !== null,
    outboxCount: outbox.length,
    manifestSha256,
  })
  validateMetadata(metadata, outbox)
  const plaintext = encoder.encode(JSON.stringify({
    metadata,
    entries: rawEntries.map(entry => ({ key: entry.key, value: encodeBase64(entry.value) })),
    sqlDatabaseBase64: sqlBytes === null ? null : encodeBase64(sqlBytes),
    outbox,
  }))

  if (plaintext.byteLength > MAX_CHECKPOINT_BYTES - 64) throw fail('CHECKPOINT_LIMIT_EXCEEDED', 'Encoded checkpoint exceeds the bounded handoff limit.')
  const isRawKey = options.secret instanceof Uint8Array
  const salt = isRawKey ? new Uint8Array(SALT_BYTES) : crypto.getRandomValues(new Uint8Array(SALT_BYTES))
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const key = await deriveAesKey(options.secret, salt, ['encrypt'])
  const aad = encoder.encode(CHECKPOINT_FORMAT)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext))

  // Wire layout: MAGIC(5) | FLAGS(1: bit0=rawKey) | SALT(16) | IV(12) | CIPHERTEXT+TAG
  const out = new Uint8Array(MAGIC.length + 1 + SALT_BYTES + IV_BYTES + ciphertext.byteLength)
  let offset = 0
  out.set(MAGIC, offset); offset += MAGIC.length
  out[offset++] = isRawKey ? 1 : 0
  out.set(salt, offset); offset += SALT_BYTES
  out.set(iv, offset); offset += IV_BYTES
  out.set(ciphertext, offset)

  await options.persist?.(Object.freeze({ bytes: out.slice(), metadata }))
  const retireSource = options.retireSource !== false
  if (retireSource) {
    retireDeviceStore(store)
    await store.put(DEVICE_RETIRED_KEY, encoder.encode(JSON.stringify({ retiredAt: createdAt, manifestSha256 })))
  }
  return Object.freeze({ bytes: out, metadata, retiredSource: retireSource })
  } finally { release() }
}

/**
 * Decrypt, authenticate, and restore an atomic device checkpoint into a clean target BytesStore.
 * Requires atomic empty-store initialization. Existing identity is never overwritten.
 */
export async function restoreDeviceCheckpoint(
  targetStore: BytesStore,
  encryptedBytes: Uint8Array,
  options: { readonly secret: Uint8Array | string },
): Promise<RestoredCheckpoint> {
  if (typeof targetStore.entries !== 'function' || typeof targetStore.putAllIfEmpty !== 'function') throw fail('CHECKPOINT_RESTORE_UNSUPPORTED', 'Restore requires atomic empty-store initialization and enumeration.')
  const release = reserveCheckpointStore(targetStore)
  try {
  const headerLength = MAGIC.length + 1 + SALT_BYTES + IV_BYTES
  if (!(encryptedBytes instanceof Uint8Array) || encryptedBytes.byteLength <= headerLength + 16 || encryptedBytes.byteLength > MAX_CHECKPOINT_BYTES) {
    throw fail('CHECKPOINT_CORRUPT', 'Encrypted checkpoint is truncated or invalid.')
  }
  for (let i = 0; i < MAGIC.length; i++) {
    if (encryptedBytes[i] !== MAGIC[i]) throw fail('CHECKPOINT_FORMAT_UNSUPPORTED', 'Unrecognized checkpoint header.')
  }
  let offset = MAGIC.length
  const flags = encryptedBytes[offset++]!
  if (flags !== 0 && flags !== 1) throw fail('CHECKPOINT_CORRUPT', 'Unrecognized checkpoint flags.')
  const expectRaw = (flags & 1) === 1
  if (expectRaw !== (options.secret instanceof Uint8Array)) {
    throw fail('CHECKPOINT_KEY_MISMATCH', expectRaw ? 'This checkpoint requires a 32-byte raw key.' : 'This checkpoint requires a passphrase.')
  }
  const salt = encryptedBytes.subarray(offset, offset + SALT_BYTES); offset += SALT_BYTES
  const iv = new Uint8Array(encryptedBytes.subarray(offset, offset + IV_BYTES)); offset += IV_BYTES
  const ciphertext = new Uint8Array(encryptedBytes.subarray(offset))
  const key = await deriveAesKey(options.secret, salt, ['decrypt'])
  const aad = encoder.encode(CHECKPOINT_FORMAT)
  let plaintext: ArrayBuffer
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext)
  } catch {
    throw fail('CHECKPOINT_DECRYPT_FAILED', 'Checkpoint authentication or decryption failed (wrong key or tampered bytes).')
  }
  let decoded: { metadata: CheckpointMetadata; entries: { key: string; value: string }[]; sqlDatabaseBase64: string | null; outbox: CheckpointOutboxRecord[] }
  try {
    decoded = JSON.parse(decoder.decode(new Uint8Array(plaintext))) as typeof decoded
    if (decoded?.metadata?.format !== CHECKPOINT_FORMAT || !Array.isArray(decoded.entries) || decoded.entries.length > MAX_ENTRIES ||
        !Array.isArray(decoded.outbox) || decoded.outbox.length > 1024 ||
        decoded.metadata.entryCount !== decoded.entries.length || decoded.metadata.outboxCount !== decoded.outbox.length ||
        decoded.metadata.hasSqlDatabase !== (decoded.sqlDatabaseBase64 !== null) ||
        !(decoded.sqlDatabaseBase64 === null || typeof decoded.sqlDatabaseBase64 === 'string')) throw new Error()
    validateMetadata(decoded.metadata, decoded.outbox)
    const seen = new Set<string>()
    for (const entry of decoded.entries) {
      if (!entry || typeof entry.key !== 'string' || entry.key.length === 0 || entry.key.length > 2048 ||
          [...entry.key].some(c => c.charCodeAt(0) < 32) || typeof entry.value !== 'string' || seen.has(entry.key) || entry.key === DEVICE_RETIRED_KEY) throw new Error()
      seen.add(entry.key)
    }
  } catch { throw fail('CHECKPOINT_CORRUPT', 'Decrypted checkpoint payload is malformed.') }
  let entries: BytesStoreEntry[], sqlDatabaseBytes: Uint8Array | null
  try {
    entries = decoded.entries.map(item => ({ key: item.key, value: decodeBase64(item.value) }))
      .sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
    sqlDatabaseBytes = decoded.sqlDatabaseBase64 === null ? null : decodeBase64(decoded.sqlDatabaseBase64)
  } catch { throw fail('CHECKPOINT_CORRUPT', 'Invalid encoded checkpoint data.') }
  const actualDigest = await manifestDigest(entries, sqlDatabaseBytes, decoded.outbox)
  if (actualDigest !== decoded.metadata.manifestSha256) {
    throw fail('CHECKPOINT_INTEGRITY_MISMATCH', 'Checkpoint manifest SHA-256 verification failed.')
  }
  if (!await targetStore.putAllIfEmpty(entries)) throw fail('CHECKPOINT_TARGET_NOT_EMPTY', 'Restore requires a fresh target; existing identity is never overwritten.')
  // Verify readback integrity on the restored store.
  if (typeof targetStore.entries === 'function') {
    const readback = [...await targetStore.entries()].sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0)
    const readbackDigest = await manifestDigest(readback, sqlDatabaseBytes, decoded.outbox)
    if (readbackDigest !== actualDigest) {
      throw fail('CHECKPOINT_RESTORE_VERIFICATION_FAILED', 'Restored store contents did not match the checkpoint manifest.')
    }
  }
  return Object.freeze({
    metadata: Object.freeze(decoded.metadata),
    sqlDatabaseBytes,
    outbox: Object.freeze(decoded.outbox),
    restoredEntries: entries.length,
  })
  } finally { release() }
}

export function generateCheckpointKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

export function encodeCheckpointKeyHex(key: Uint8Array): string {
  if (key.byteLength !== 32) throw fail('CHECKPOINT_KEY_INVALID', 'Checkpoint key must be 32 bytes.')
  return bytesToHex(key)
}

export function decodeCheckpointKeyHex(hex: string): Uint8Array {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/iu.test(hex)) {
    throw fail('CHECKPOINT_KEY_INVALID', 'Checkpoint key must be 64 hexadecimal characters.')
  }
  return hexToBytes(hex.toLowerCase())
}

import type { CheckpointMetadata, CheckpointOutboxRecord } from './checkpoint.js'
const PBKDF2_ITERATIONS = 600_000
const encoder = new TextEncoder()
function fail(code: string, message: string): Error { return Object.assign(new Error(message), { code }) }

export async function deriveAesKey(secret: Uint8Array | string, salt: Uint8Array, usage: readonly KeyUsage[], iterations = PBKDF2_ITERATIONS): Promise<CryptoKey> {
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
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltCopy, iterations },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [...usage],
  )
}

export function validateMetadata(metadata: CheckpointMetadata, outbox: readonly CheckpointOutboxRecord[]): void {
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

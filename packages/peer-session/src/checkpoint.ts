import type { BytesStore } from '@chronolog/records'
import { bytesToHex, hexToBytes } from '@chronolog/protocol'
import { exportDeviceCheckpointStream, restoreDeviceCheckpointStream, type CheckpointLimits } from './checkpoint-stream.js'

/** The one device checkpoint format: authenticated, chained AES-GCM frames (see checkpoint-stream.ts). */
export const CHECKPOINT_FORMAT = 'chronolog-device-checkpoint-v2'
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
  /** Optional caller budgets; use the streaming API to avoid whole-checkpoint allocations. */
  readonly limits?: CheckpointLimits
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

function fail(code: string, message: string): Error {
  return Object.assign(new Error(message), { code })
}

const decoder = new TextDecoder('utf-8', { fatal: true })

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
 * Export a quiesced store to an in-memory checkpoint (the streaming format, buffered) and
 * optionally retire the source store once `persist` has durably kept the bytes.
 */
export async function exportDeviceCheckpoint(store: BytesStore, options: ExportCheckpointOptions): Promise<ExportedCheckpoint> {
  if (options.retireSource !== false && typeof options.persist !== 'function') throw fail('CHECKPOINT_PERSISTENCE_REQUIRED', 'Durably persist the encrypted handoff before source retirement.')
  const chunks: Uint8Array[] = []
  let bytes: Uint8Array | undefined
  const sql = options.sqlDatabaseBytes === undefined || options.sqlDatabaseBytes === null ? null : Uint8Array.from(options.sqlDatabaseBytes)
  const result = await exportDeviceCheckpointStream(store, {
    secret: options.secret,
    ...(options.applicationId === undefined ? {} : { applicationId: options.applicationId }),
    ...(options.deviceId === undefined ? {} : { deviceId: options.deviceId }),
    ...(options.outbox === undefined ? {} : { outbox: options.outbox }),
    ...(options.limits === undefined ? {} : { limits: options.limits }),
    retireSource: options.retireSource !== false,
    ...(sql === null ? {} : { sqlDatabase: { bytes: sql.byteLength, chunks: (async function* () { yield sql })() } }),
    sink: {
      write(chunk) { chunks.push(Uint8Array.from(chunk)) },
      async commit(metadata) {
        let size = 0
        for (const chunk of chunks) size += chunk.byteLength
        const out = new Uint8Array(size)
        let offset = 0
        for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength }
        bytes = out
        await options.persist?.(Object.freeze({ bytes: out.slice(), metadata }))
      },
    },
  })
  return Object.freeze({ bytes: bytes!, metadata: result.metadata, retiredSource: result.retiredSource })
}

/**
 * Decrypt, authenticate, and restore an in-memory device checkpoint into a clean target store.
 * Requires atomic empty-store initialization. Existing identity is never overwritten.
 */
export async function restoreDeviceCheckpoint(
  targetStore: BytesStore,
  encryptedBytes: Uint8Array,
  options: { readonly secret: Uint8Array | string; readonly limits?: CheckpointLimits },
): Promise<RestoredCheckpoint> {
  if (!(encryptedBytes instanceof Uint8Array)) throw fail('CHECKPOINT_CORRUPT', 'Encrypted checkpoint is truncated or invalid.')
  const copy = Uint8Array.from(encryptedBytes)
  const restored = await restoreDeviceCheckpointStream(targetStore, (async function* () { yield copy })(), {
    secret: options.secret,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
  return Object.freeze({
    metadata: restored.metadata,
    sqlDatabaseBytes: restored.sqlDatabaseBytes,
    outbox: restored.outbox,
    restoredEntries: restored.restoredEntries,
  })
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

export { exportDeviceCheckpointStream, restoreDeviceCheckpointStream } from './checkpoint-stream.js'
export type { CheckpointLimits, CheckpointSink, ExportCheckpointStreamOptions, RestoreCheckpointStreamOptions } from './checkpoint-stream.js'

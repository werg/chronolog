import { TransactionRejectedError, type ChronologClient } from '@chronolog/client'
import { Mutex, validateOperationId, type DurableOperationStore } from '@chronolog/node-core/browser'
import {
  assertCanonicalCbor, assertEventTopic, bytesToHex, canonicalEventPayload, emit, encodeCanonicalCbor,
  equalBytes, program, sqlStatement, type CborValue, type ChangeProgram, type EventPayload,
} from '@chronolog/protocol'
import type { AgentClient } from '@tendriller/core'
import { assertFilePath, assertValid, type BlobUploadCompletion } from '@tendriller/core/contract'
import { RESOURCE_LIMITS } from '@tendriller/core/limits'

export interface FileUploadIntent {
  /** Persist before calling stage; the same identity becomes this path's revision. */
  readonly operationId: string
  readonly path: string
  readonly expectedRevision: string | null
  readonly mediaType: string
  readonly kind: 'file' | 'capture'
}
export interface StagedFileReference {
  readonly version: 1
  readonly path: string
  readonly revision: string
  readonly previousRevision: string | null
  readonly kind: 'file' | 'capture'
  readonly sha256: string
  readonly size: number
  readonly mediaType: string
  readonly availability: {
    readonly type: 'host-upload-completed'
    readonly locationId: string
    readonly observedAtMs: number
    readonly receipt: BlobUploadCompletion
    /** A host completion and a canonical reference establish no second copy. */
    readonly additionalDurableCopies: 'unknown'
  }
  readonly orphanPolicy: 'retain-under-host-policy'
}
interface StagedState extends FileUploadIntent {
  readonly sha256: string
  readonly size: number
  readonly availability: StagedFileReference['availability'] | null
}
const locks = new WeakMap<DurableOperationStore, Mutex>()
function storeLock(store: DurableOperationStore): Mutex {
  let lock = locks.get(store)
  if (lock === undefined) { lock = new Mutex(); locks.set(store, lock) }
  return lock
}

/**
 * Application recipe; immutable bytes stay on the existing host upload path.
 *
 *   const files = createBlobMetadataRecipe({ client, uploads: host.blobs, store,
 *     historyId, locationId: 'tendriller:my-page', retentionPolicy: 'accept-receipt-expiry' })
 *   await files.initialize({ operationId: 'file-schema-1', signal })
 *   await files.stage(bytes, { operationId, path: 'notes/report.pdf',
 *     expectedRevision: null, mediaType: 'application/pdf', kind: 'file' }, { signal })
 *   await files.commit(operationId, { signal })
 *
 * Keep the reviewed intent and exact bytes until stage succeeds. Its private
 * checkpoint then preserves the exact receipt independently of a lost metadata
 * response. It is an upload workflow checkpoint, not another application outbox;
 * Chronolog owns authored metadata retries and final accepted/rejected outcomes.
 *
 * With require-pin, inject an upload adapter that uses host.blobs.upload, then
 * host.blobs.pin with a stable `${cid}:pin` and the reviewed host guards, returning
 * the actual pin response as {status:'completed',blob}. A Chronolog reference does
 * not pin a host blob. accept-receipt-expiry records the actual expiry explicitly.
 *
 * A stale/rejected metadata update leaves its upload under that host policy.
 * Never delete it automatically: content deduplication may share the bytes with
 * another reference. Inspect staged(operationId) to make an explicit cleanup or
 * new guarded metadata decision. A receipt is evidence at observation time, not
 * a live availability check, independent replica receipt, or indefinite promise.
 *
 * Captures use kind:'capture' and the same content/reference flow. Every full
 * group reader sees paths, digests, receipts, and metadata; topic filtering does
 * not hide them. Private captures or agent memory need a private authorized store
 * and/or separate group. Do not place credentials or signed access URLs here.
 * Neither filesystem access nor network transfer occurs during SQL execution.
 */
export function createBlobMetadataRecipe(options: {
  readonly client: Pick<ChronologClient, 'groupId' | 'submit'>
  readonly uploads: Pick<AgentClient['blobs'], 'upload'>
  readonly store: DurableOperationStore
  readonly historyId: string
  readonly locationId: string
  readonly retentionPolicy: 'require-pin' | 'accept-receipt-expiry'
  readonly tablePrefix?: string
  readonly topic?: string
  readonly now?: () => number
}) {
  const { client, uploads, store, historyId, locationId, retentionPolicy } = options
  const now = options.now ?? Date.now, topic = options.topic ?? 'files'
  const prefix = options.tablePrefix ?? 'blob'
  validateOperationId(historyId); validateOperationId(locationId); assertEventTopic(topic)
  if (!/^[a-z][a-z0-9_]{0,47}$/.test(prefix)) throw new Error('BLOB_TABLE_PREFIX_INVALID')
  if (retentionPolicy !== 'require-pin' && retentionPolicy !== 'accept-receipt-expiry') throw new Error('BLOB_RETENTION_POLICY_INVALID')
  const heads = `${prefix}_files`, versions = `${prefix}_file_versions`
  const binding = encodeCanonicalCbor([1n, 'example/blob-metadata', client.groupId, historyId, locationId, retentionPolicy, prefix, topic])
  const keyPrefix = `example/blob-metadata/${encodeURIComponent(client.groupId)}/${encodeURIComponent(historyId)}`
  const key = (operationId: string): string => { validateOperationId(operationId); return `${keyPrefix}/${encodeURIComponent(operationId)}` }
  const encode = (value: StagedState): Uint8Array => encodeCanonicalCbor([1n, binding, value.operationId, value.path,
    value.expectedRevision, value.mediaType, value.kind, value.sha256, BigInt(value.size),
    value.availability === null ? null : canonicalEventPayload(value.availability)])
  const decode = (bytes: Uint8Array): StagedState => {
    const value = assertCanonicalCbor(bytes, { maxBytes: 65_536 })
    if (!Array.isArray(value) || value.length !== 10) throw new Error('BLOB_STAGE_INVALID')
    const row = value as readonly CborValue[]
    if (row[0] !== 1n || !(row[1] instanceof Uint8Array) || !equalBytes(row[1], binding) ||
        typeof row[2] !== 'string' || typeof row[3] !== 'string' || (row[4] !== null && typeof row[4] !== 'string') ||
        typeof row[5] !== 'string' || (row[6] !== 'file' && row[6] !== 'capture') || typeof row[7] !== 'string' || !/^[a-f0-9]{64}$/.test(row[7]) ||
        typeof row[8] !== 'bigint' || row[8] < 0n || row[8] > BigInt(RESOURCE_LIMITS.blob_bytes) || (row[9] !== null && typeof row[9] !== 'string')) {
      throw new Error('BLOB_STAGE_INVALID')
    }
    const state: StagedState = { operationId: row[2], path: row[3], expectedRevision: row[4], mediaType: row[5], kind: row[6], sha256: row[7], size: Number(row[8]),
      availability: row[9] === null ? null : JSON.parse(row[9]) as StagedFileReference['availability'] }
    validateIntent(state)
    if (state.availability !== null) {
      const evidence = state.availability
      if (evidence.type !== 'host-upload-completed' || evidence.locationId !== locationId || evidence.additionalDurableCopies !== 'unknown' ||
          !Number.isSafeInteger(evidence.observedAtMs) || evidence.observedAtMs < 0) throw new Error('BLOB_STAGE_INVALID')
      validateReceipt(evidence.receipt, state.sha256, state.size, state.mediaType)
    }
    return state
  }
  const load = async (operationId: string): Promise<StagedState | null> => {
    const bytes = await store.get(key(operationId))
    const state = bytes === null ? null : decode(bytes)
    if (state !== null && state.operationId !== operationId) throw new Error('BLOB_STAGE_INVALID')
    return state
  }
  const reference = (state: StagedState): StagedFileReference => {
    if (state.availability === null) throw new Error('BLOB_UPLOAD_NOT_STAGED')
    return { version: 1, path: state.path, revision: state.operationId, previousRevision: state.expectedRevision,
      kind: state.kind, sha256: state.sha256, size: state.size, mediaType: state.mediaType,
      availability: structuredClone(state.availability), orphanPolicy: 'retain-under-host-policy' }
  }
  const submitFinal = async (change: ChangeProgram, operationId: string, signal?: AbortSignal): Promise<string> => {
    const handle = await client.submit(change, { operationId, ...(signal === undefined ? {} : { signal }) })
    try {
      const result = await handle.final(signal === undefined ? {} : { signal })
      if (result.outcome.type === 'rejected') throw new TransactionRejectedError(handle.proposalId, result.outcome.rejection)
      return handle.proposalId
    } finally { handle.dispose() }
  }
  return Object.freeze({
    initialize(input: { readonly operationId: string; readonly signal?: AbortSignal }) {
      return submitFinal(program(
        sqlStatement(`CREATE TABLE ${heads} (path TEXT PRIMARY KEY, revision TEXT NOT NULL) STRICT`),
        sqlStatement(`CREATE TABLE ${versions} (revision TEXT PRIMARY KEY, path TEXT NOT NULL, previous_revision TEXT, sha256 TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL, kind TEXT NOT NULL, reference_json TEXT NOT NULL) STRICT`),
      ), input.operationId, input.signal)
    },
    async stage(bytes: Uint8Array, intent: FileUploadIntent, input: { readonly signal?: AbortSignal } = {}): Promise<StagedFileReference> {
      const signal = input.signal
      signal?.throwIfAborted()
      if (!(bytes instanceof Uint8Array) || bytes.length > RESOURCE_LIMITS.blob_bytes) throw new Error('BLOB_BYTES_INVALID')
      bytes = bytes.slice(); intent = structuredClone(intent); validateIntent(intent)
      const request: StagedState = { ...intent, sha256: await digest(bytes), size: bytes.length, availability: null }
      const uploadId = `blob_${await digest(encodeCanonicalCbor([binding, intent.operationId]))}`
      return storeLock(store).run(async () => {
        signal?.throwIfAborted()
        const previous = await load(intent.operationId)
        if (previous !== null && !equalBytes(encode({ ...previous, availability: null }), encode(request))) throw new Error('BLOB_OPERATION_ID_CONFLICT')
        if (previous !== null && previous.availability !== null) return reference(previous)
        if (previous === null) await store.put(key(intent.operationId), encode(request))
        const receipt = structuredClone(await uploads.upload(bytes, { cid: uploadId, name: intent.path.split('/').at(-1)!, type: intent.mediaType,
          ...(signal === undefined ? {} : { signal }) }))
        validateReceipt(receipt, request.sha256, request.size, request.mediaType)
        if (retentionPolicy === 'require-pin' && (receipt.blob.retention.expires_at !== null || !receipt.blob.retention.reasons.includes('pinned'))) {
          throw new Error('BLOB_RETENTION_NOT_PINNED')
        }
        const observedAtMs = now()
        if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0) throw new Error('BLOB_OBSERVATION_TIME_INVALID')
        const saved: StagedState = { ...request, availability: { type: 'host-upload-completed', locationId, observedAtMs,
          receipt, additionalDurableCopies: 'unknown' } }
        await store.put(key(intent.operationId), encode(saved))
        return reference(saved)
      })
    },
    async staged(operationId: string): Promise<StagedFileReference | null> {
      const state = await load(operationId)
      return state?.availability === null || state === null ? null : reference(state)
    },
    async commit(operationId: string, input: { readonly signal?: AbortSignal } = {}): Promise<string> {
      const signal = input.signal
      signal?.throwIfAborted()
      const state = await load(operationId)
      if (state === null) throw new Error('BLOB_UPLOAD_NOT_STAGED')
      const file = reference(state), encoded = canonicalEventPayload(file as unknown as EventPayload)
      const guard = state.expectedRevision === null
        ? sqlStatement(`SELECT chronolog_assert(NOT EXISTS(SELECT 1 FROM ${heads} WHERE path = ?), 'file_revision_changed')`, [state.path])
        : sqlStatement(`SELECT chronolog_assert(EXISTS(SELECT 1 FROM ${heads} WHERE path = ? AND revision = ?), 'file_revision_changed')`, [state.path, state.expectedRevision])
      const head = state.expectedRevision === null
        ? sqlStatement(`INSERT INTO ${heads} (path, revision) VALUES (?, ?)`, [state.path, state.operationId])
        : sqlStatement(`UPDATE ${heads} SET revision = ? WHERE path = ?`, [state.operationId, state.path])
      return submitFinal(program(guard,
        sqlStatement(`INSERT INTO ${versions} (revision, path, previous_revision, sha256, size, media_type, kind, reference_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [state.operationId, state.path, state.expectedRevision, state.sha256, state.size, state.mediaType, state.kind, encoded]),
        head, emit(topic, { type: 'file.committed', version: 1, reference: JSON.parse(encoded) as EventPayload }),
      ), state.operationId, signal)
    },
  })
}

function validateIntent(value: FileUploadIntent): void {
  validateOperationId(value.operationId); assertFilePath(value.path)
  if (value.expectedRevision !== null) validateOperationId(value.expectedRevision)
  if (value.expectedRevision === value.operationId || typeof value.mediaType !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(value.mediaType) ||
      (value.kind !== 'file' && value.kind !== 'capture')) throw new Error('BLOB_FILE_INTENT_INVALID')
}
async function digest(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))))
}
function validateReceipt(receipt: BlobUploadCompletion, digest: string, size: number, mediaType: string): void {
  assertValid('uploadCompletion', receipt)
  if (receipt.blob.sha256 !== digest || receipt.blob.size !== size || receipt.blob.type !== mediaType) throw new Error('BLOB_UPLOAD_RECEIPT_MISMATCH')
  const url = new URL(receipt.blob.url, 'https://relative-host.invalid')
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('BLOB_LOCATOR_CONTAINS_CREDENTIALS_OR_UNSUPPORTED_URL')
}

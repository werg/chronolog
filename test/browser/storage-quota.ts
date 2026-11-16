import { CheckpointStore, type ConsumerCheckpoint } from '@chronolog/agent-service/workers'
import { sha256 } from '@chronolog/canonical'
import { DurableOperationJournal } from '@chronolog/node-core/browser'
import { bytesToHex, equalBytes, utf8 } from '@chronolog/protocol'

import { OpfsBytesStore } from '../../packages/runtime-browser/src/opfs.js'

interface QuotaBucket {
  getDirectory(): Promise<FileSystemDirectoryHandle>
  estimate(): Promise<StorageEstimate>
}
interface QuotaBucketManager {
  open(name: string, options: { quota: number }): Promise<QuotaBucket>
  delete(name: string): Promise<void>
}

function requireCondition(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`STORAGE_QUOTA_QUALIFICATION_FAILED: ${message}`)
}

async function requireQuotaFailure(operation: () => Promise<unknown>) {
  try { await operation() } catch (error) {
    if (!(error instanceof DOMException) || error.name !== 'QuotaExceededError') {
      throw new Error('STORAGE_QUOTA_EXPECTED_BROWSER_QUOTA_ERROR', { cause: error })
    }
    return { name: error.name, message: error.message, code: error.code, isDomException: true }
  }
  throw new Error('STORAGE_QUOTA_EXPECTED_REJECTION')
}

function checkpointEvidence(value: ConsumerCheckpoint | null) {
  if (value === null) return null
  return { cursor: value.cursor, revision: value.revision, state: new TextDecoder().decode(value.state) }
}

function requireCheckpoint(actual: ConsumerCheckpoint | null, expected: ConsumerCheckpoint) {
  requireCondition(actual !== null && actual.cursor === expected.cursor && actual.revision === expected.revision &&
    equalBytes(actual.state, expected.state), 'checkpoint state, revision and cursor changed')
}

/**
 * A real browser allocation boundary, using the production stores unchanged.
 * The named bucket makes the limit small without exhausting the host disk.
 * It does not claim to exhaust the complete peer's default OPFS bucket.
 * Chromium uses the same mechanism in fs/script-tests/FileSystemBaseHandle-buckets.js.
 */
export async function qualifyStorageQuota() {
  if (typeof document !== 'undefined') throw new Error('STORAGE_QUOTA_WORKER_REQUIRED')
  const buckets = (navigator as unknown as { readonly storageBuckets?: QuotaBucketManager }).storageBuckets
  if (buckets === undefined || typeof buckets.open !== 'function' || typeof buckets.delete !== 'function') {
    throw new Error('STORAGE_QUOTA_BUCKETS_UNAVAILABLE_IN_WORKER')
  }
  const bucketName = `chronolog-quota-${crypto.randomUUID()}`, requestedQuotaBytes = 64 * 1024
  const bucket = await buckets.open(bucketName, { quota: requestedQuotaBytes })
  let store: OpfsBytesStore | undefined
  try {
    if (typeof bucket.getDirectory !== 'function' || typeof bucket.estimate !== 'function') {
      throw new Error('STORAGE_QUOTA_BUCKET_OPFS_UNAVAILABLE')
    }
    const estimates: Record<string, StorageEstimate> = { empty: await bucket.estimate() }
    requireCondition(estimates.empty!.quota === requestedQuotaBytes, 'bucket did not report the requested quota')
    store = new OpfsBytesStore(await bucket.getDirectory())
    const binding = utf8('storage-quota-checkpoint/v1')
    const makeCheckpoint = () => new CheckpointStore(store!, { id: 'projection', binding })
    const baseline: ConsumerCheckpoint = { cursor: 'cursor-before', revision: 'revision-before', state: utf8('baseline') }
    const updated: ConsumerCheckpoint = { cursor: 'cursor-after', revision: 'revision-after', state: utf8('small recovered update') }
    await makeCheckpoint().commit(baseline)
    estimates.checkpointBaseline = await bucket.estimate()
    const oversized = new Uint8Array(1024 * 1024).fill(0x61)
    const checkpointFailure = await requireQuotaFailure(() => makeCheckpoint().commit({ ...updated, state: oversized }))
    requireCheckpoint(await makeCheckpoint().load(), baseline)
    await store.close()
    store = new OpfsBytesStore(await bucket.getDirectory())
    const reopenedCheckpoint = await makeCheckpoint().load()
    requireCheckpoint(reopenedCheckpoint, baseline)
    estimates.checkpointFailureReopened = await bucket.estimate()
    await makeCheckpoint().commit(updated)
    requireCheckpoint(await makeCheckpoint().load(), updated)
    estimates.checkpointRecovered = await bucket.estimate()

    const namespace = 'quota-operations', originalId = 'original-small', rejectedId = 'rejected-large', newId = 'new-small'
    const originalPayload = utf8('original exact prepared operation'), newPayload = utf8('deliberate new operation')
    const originalFingerprint = await sha256(originalPayload), oversizedFingerprint = await sha256(oversized)
    const applyCounts = { original: 0, oversized: 0, exactRetry: 0, newOperation: 0 }
    let retryPrepareCount = 0
    let journal = new DurableOperationJournal(store, namespace)
    const originalResult = await journal.run({ operationId: originalId, fingerprint: originalFingerprint,
      prepare: async () => originalPayload,
      apply: async (payload) => {
        requireCondition(equalBytes(payload, originalPayload), 'original operation bytes changed')
        applyCounts.original += 1
      } })
    requireCondition(equalBytes(originalResult, originalPayload) && applyCounts.original === 1, 'original operation did not complete once')
    estimates.operationBaseline = await bucket.estimate()
    const operationFailure = await requireQuotaFailure(() => journal.run({ operationId: rejectedId, fingerprint: oversizedFingerprint,
      prepare: async () => oversized,
      apply: async () => { applyCounts.oversized += 1; throw new Error('STORAGE_QUOTA_APPLIED_BEFORE_DURABLE_PREPARATION') } }))
    requireCondition(applyCounts.oversized === 0 && await journal.lookup(rejectedId) === null,
      'failed preparation applied or retained an operation')
    await store.close()
    store = new OpfsBytesStore(await bucket.getDirectory())
    journal = new DurableOperationJournal(store, namespace)
    requireCondition(await journal.lookup(rejectedId) === null, 'failed preparation appeared after reopening')
    const exactRetry = await journal.run({ operationId: originalId, fingerprint: originalFingerprint,
      prepare: async () => { retryPrepareCount += 1; throw new Error('STORAGE_QUOTA_REAUTHORED_ACCEPTED_OPERATION') },
      apply: async () => { applyCounts.exactRetry += 1; throw new Error('STORAGE_QUOTA_REAPPLIED_ACCEPTED_OPERATION') } })
    requireCondition(equalBytes(exactRetry, originalPayload) && retryPrepareCount === 0 && applyCounts.exactRetry === 0,
      'accepted retry did not retain its original bytes')
    estimates.operationFailureReopened = await bucket.estimate()
    const newResult = await journal.run({ operationId: newId, fingerprint: await sha256(newPayload),
      prepare: async () => newPayload,
      apply: async (payload) => {
        requireCondition(equalBytes(payload, newPayload), 'new operation bytes changed')
        applyCounts.newOperation += 1
      } })
    requireCondition(equalBytes(newResult, newPayload) && applyCounts.newOperation === 1, 'new small operation did not complete once')
    requireCondition(await journal.lookup(rejectedId) === null, 'new operation reused the failed operation identity')
    requireCheckpoint(await makeCheckpoint().load(), updated)
    estimates.final = await bucket.estimate()
    return {
      passed: true,
      method: 'real named Storage Bucket quota with production OpfsBytesStore, CheckpointStore and DurableOperationJournal',
      boundary: 'dedicated Worker; controlled bucket; journal apply callback observed without a network transport',
      exclusions: ['full public peer default-bucket quota exhaustion', 'OS disk exhaustion or eviction', 'power loss'],
      bucketName, requestedQuotaBytes, oversizedPayloadBytes: oversized.length, estimates,
      checkpoint: { baseline: checkpointEvidence(baseline), failure: checkpointFailure,
        reopened: checkpointEvidence(reopenedCheckpoint), recovered: checkpointEvidence(updated) },
      journal: { originalId, rejectedId, newId, originalPayloadSha256: bytesToHex(originalFingerprint),
        retryPayloadSha256: bytesToHex(await sha256(exactRetry)), failure: operationFailure,
        rejectedLookupAfterReopen: null, retryPrepareCount, applyCounts },
    }
  } finally {
    try { await store?.close() } finally { await buckets.delete(bucketName) }
  }
}

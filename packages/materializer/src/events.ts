import { bytesToHex, sha256 } from '@chronolog/canonical'
import {
  assertCanonicalCbor, assertValidChangeProgram, createExecutionManifest, decodeTransactionCore,
  encodeCanonicalCbor, encodeTransactionCore, equalBytes, executionManifestArtifacts,
  isEmitStep, transactionDigest, transactionOrderKey, utf8,
} from '@chronolog/protocol'
import type { AdmittedTransaction } from './types.js'
import { publicationRequestForRevision, type ChronologMaterializationRuntime, type MaterializedTransactionOutcome, type MaterializedRevisionSnapshot } from './runtime.js'

export interface EventExecutionStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, value: Uint8Array): Promise<void>
}

/** A pinned SQL-absent execution profile; importing it never loads an SQL engine. */
export async function eventExecutionManifest() {
  return createExecutionManifest({
    profile: 'chronolog-events-v1', engine: 'none',
    engineDigest: await sha256(utf8('chronolog/events-only/v1')),
    platformDigest: await sha256(utf8('chronolog/change-program/v3;literal-events;operation-conflicts/v1')),
  })
}

export async function createEventMaterializationRuntime(options: {
  readonly store: EventExecutionStore
  readonly namespace: string
  readonly maxHistoryBytes?: number
}): Promise<ChronologMaterializationRuntime> {
  if (options.namespace.length === 0) throw new Error('EVENT_EXECUTION_NAMESPACE_REQUIRED')
  const manifest = await eventExecutionManifest()
  const artifacts = await executionManifestArtifacts(manifest)
  const digest = artifacts.executionManifestDigest
  const key = `event-execution/${options.namespace}`
  const quota = options.maxHistoryBytes ?? 64 * 1024 * 1024
  if (!Number.isSafeInteger(quota) || quota < 1024) throw new Error('EVENT_EXECUTION_QUOTA_INVALID')
  let revision = 0n, finalRevision = 0n, finalLength = 0
  let order: AdmittedTransaction[] = []
  let outcomes: MaterializedTransactionOutcome[] = []
  let closed = false
  let tail = Promise.resolve()
  const subscribers = new Set<(value: MaterializedRevisionSnapshot) => void>()
  const snapshot = (): MaterializedRevisionSnapshot => ({ revision, orderLength: order.length, executionManifestDigest: digest.slice() })
  const serial = async <T>(task: () => Promise<T>): Promise<T> => {
    const previous = tail
    let release!: () => void
    tail = new Promise<void>((resolve) => { release = resolve })
    await previous
    try { if (closed) throw new Error('EVENT_EXECUTION_CLOSED'); return await task() } finally { release() }
  }
  const encode = (next: readonly AdmittedTransaction[], rev: bigint, final: number, finalRev: bigint): Uint8Array => encodeCanonicalCbor([
    'chronolog/event-execution/v1', digest, rev, BigInt(final), finalRev,
    next.map((entry) => [entry.txId, entry.authorFeedSequence, entry.candidateDigest, entry.canonicalCandidate]),
  ])
  const evaluate = async (next: readonly AdmittedTransaction[]): Promise<MaterializedTransactionOutcome[]> => {
    const operations = new Set<string>(), transactions = new Set<string>(), proposals = new Set<string>()
    const result: MaterializedTransactionOutcome[] = []
    for (const [index, entry] of next.entries()) {
      const core = entry.core
      if (entry.txId.length === 0 || entry.authorFeedSequence < 0n || entry.authorFeedSequence > (1n << 63n) - 1n) {
        throw new Error('EVENT_EXECUTION_INPUT_INVALID')
      }
      if (!equalBytes(core.executionManifestDigest, digest)) throw new Error('EVENT_EXECUTION_PROFILE_UNAVAILABLE')
      if (!equalBytes(encodeTransactionCore(core), entry.canonicalCandidate) ||
          !equalBytes(await transactionDigest(entry.canonicalCandidate), entry.candidateDigest)) throw new Error('EVENT_EXECUTION_INPUT_INVALID')
      assertValidChangeProgram(core.program)
      const transactionId = bytesToHex(entry.txId), proposalId = bytesToHex(entry.candidateDigest)
      if (transactions.has(transactionId)) throw new Error('EVENT_EXECUTION_DUPLICATE_TRANSACTION')
      if (proposals.has(proposalId)) throw new Error('EVENT_EXECUTION_DUPLICATE_PROPOSAL')
      transactions.add(transactionId); proposals.add(proposalId)
      const operation = `${bytesToHex(core.authorId)}/${core.operationId}`
      const failing = core.program.steps.findIndex((step) => !isEmitStep(step))
      const code = operations.has(operation) ? 'operation_conflict' : failing >= 0 ? 'profile:sql-disabled' : null
      operations.add(operation)
      result.push({ txId: entry.txId.slice(), orderKey: transactionOrderKey(core, entry), orderIndex: index,
        outcome: code === null ? 'accepted' : 'rejected', rejectionCode: code,
        failingStatementIndex: code === 'profile:sql-disabled' ? failing : null })
    }
    return result
  }
  const persisted = await options.store.get(key)
  if (persisted !== null) {
    if (persisted.length > quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    const value = assertCanonicalCbor(persisted, { maxBytes: quota, maxByteStringBytes: quota, maxItems: quota })
    if (!Array.isArray(value) || value.length !== 6 || value[0] !== 'chronolog/event-execution/v1' ||
        !(value[1] instanceof Uint8Array) || !equalBytes(value[1], digest) || typeof value[2] !== 'bigint' ||
        typeof value[3] !== 'bigint' || typeof value[4] !== 'bigint' || !Array.isArray(value[5]) ||
        value[2] < 0n || value[3] < 0n || value[3] > BigInt(value[5].length) || value[4] < 0n) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    revision = value[2]; finalLength = Number(value[3]); finalRevision = value[4]
    order = value[5].map((row) => {
      if (!Array.isArray(row) || row.length !== 4 || !(row[0] instanceof Uint8Array) || typeof row[1] !== 'bigint' ||
          !(row[2] instanceof Uint8Array) || !(row[3] instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      return { txId: row[0], authorFeedSequence: row[1], candidateDigest: row[2], canonicalCandidate: row[3], core: decodeTransactionCore(row[3]) }
    })
    outcomes = await evaluate(order)
  }
  const persist = async (bytes: Uint8Array): Promise<void> => {
    if (bytes.length > quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    try { await options.store.put(key, bytes) }
    catch (error) {
      // Atomic storage may have committed before its acknowledgment was lost.
      // Continuing from the old in-memory order/finality could overwrite that
      // newer durable prefix. Reopen from storage before any further mutation.
      closed = true
      subscribers.clear()
      throw error
    }
  }
  return {
    coordinator: {
      materialize: async (input) => {
        const next = structuredClone(input) as AdmittedTransaction[]
        return serial(async () => {
          const nextOutcomes = await evaluate(next)
          for (let i = 0; i < finalLength; i++) if (next[i] === undefined || !sameIdentity(order[i]!, next[i]!)) throw new Error('EVENT_EXECUTION_FINAL_PREFIX_CHANGED')
          // A sealed batch can reorder or reject provisional work. Only the
          // final prefix is immutable; surviving proposals keep their identity.
          const previousById = new Map(order.map(entry => [bytesToHex(entry.txId), entry]))
          for (const entry of next) {
            const previous = previousById.get(bytesToHex(entry.txId))
            if (previous !== undefined && !sameIdentity(previous, entry)) throw new Error('EVENT_EXECUTION_IDENTITY_CONFLICT')
          }
          let difference = 0
          while (difference < order.length && difference < next.length && sameIdentity(order[difference]!, next[difference]!)) difference++
          if (difference === order.length && difference === next.length) return null
          const previousRevision = revision
          const nextRevision = revision + 1n
          const bytes = encode(next, nextRevision, finalLength, finalRevision)
          const contentHash = bytesToHex(await sha256(bytes))
          const changes = nextOutcomes.flatMap((current) => {
            const before = outcomes.find((value) => equalBytes(value.txId, current.txId))
            return before?.outcome === current.outcome && before.rejectionCode === current.rejectionCode ? [] : [{
              txId: current.txId.slice(), previous: before?.outcome ?? null, current: current.outcome,
              previousRejectionCode: before?.rejectionCode ?? null, currentRejectionCode: current.rejectionCode,
            }]
          })
          // The applied anchor and outcomes share the atomic durable record.
          await persist(bytes)
          order = next; outcomes = nextOutcomes; revision = nextRevision
          const result = { revision, previousRevision, orderLength: order.length, replayFromIndex: difference,
            replayedTransactions: order.length - difference, checkpointPrefix: difference, contentHash,
            manifestDigest: digest.slice(), earliestChangedOrderIndex: difference, outcomeChanges: changes }
          for (const subscriber of [...subscribers]) { try { subscriber(snapshot()) } catch { /* Observers cannot undo a committed outcome. */ } }
          return { revision: result, publication: publicationRequestForRevision(result) }
        })
      },
      publishFinal: (length) => serial(async () => {
        if (!Number.isSafeInteger(length) || length < finalLength || length > order.length) throw new Error('EVENT_EXECUTION_FINAL_PREFIX_INVALID')
        if (length === finalLength) return
        await persist(encode(order, revision, length, finalRevision + 1n))
        finalLength = length; finalRevision++
      }),
    },
    queries: {
      get revision() { return revision }, get orderLength() { return order.length },
      get finalRevision() { return finalRevision }, get finalOrderLength() { return finalLength },
      get executionManifestDigest() { return digest.slice() },
      localSql() { throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
      outcome(id) { return structuredClone(outcomes.find((entry) => equalBytes(entry.txId, id)) ?? null) },
      subscribe(subscriber) { subscribers.add(subscriber); return () => { subscribers.delete(subscriber) } },
      captureRead(input = {}) {
        const view = input.view ?? 'final'
        let released = false
        return { view, revision: view === 'final' ? finalRevision : revision, orderLength: view === 'final' ? finalLength : order.length,
          finalOrderLength: finalLength, query() { if (released) throw new Error('VIEW_RELEASED'); throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
          release() { released = true } }
      },
    },
    publications: {
      async publish(request) {
        if (closed) throw new Error('EVENT_EXECUTION_CLOSED')
        if (request.targetRevision !== revision || request.targetOrderLength !== order.length) throw new Error('EVENT_EXECUTION_PUBLICATION_MISMATCH')
        return { status: 'already_current', publicationKey: request.publicationKey, ...snapshot() }
      },
      async reconcile(expected) {
        if (closed) throw new Error('EVENT_EXECUTION_CLOSED')
        if (expected.targetOrderLength !== order.length || (expected.targetRevision !== undefined && expected.targetRevision !== revision)) throw new Error('EVENT_EXECUTION_RECONCILIATION_MISMATCH')
        return { status: 'reconciled', publicationKey: null, ...snapshot() }
      },
    },
    close() { closed = true; subscribers.clear() },
  }
}

function sameIdentity(left: AdmittedTransaction, right: AdmittedTransaction): boolean {
  return left.authorFeedSequence === right.authorFeedSequence && equalBytes(left.txId, right.txId) &&
    equalBytes(left.candidateDigest, right.candidateDigest) && equalBytes(left.canonicalCandidate, right.canonicalCandidate)
}

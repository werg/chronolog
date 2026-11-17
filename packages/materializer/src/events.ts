import { bytesToHex, sha256 } from '@chronolog/canonical'
import {
  assertCanonicalCbor, assertValidChangeProgram, createExecutionManifest, decodeTransactionCore,
  encodeCanonicalCbor, encodeTransactionCore, equalBytes, executionManifestArtifacts,
  isEmitStep, transactionDigest, transactionOrderKey, compareTransactionOrder, utf8,
} from '@chronolog/protocol'
import type { ReplayProposal } from './types.js'
import {
  publicationRequestForRevision, type AppliedApplicationSnapshot, type AppliedMaterializationRuntime,
  type AppliedReadHandle, type ChronologMaterializationRuntime, type MaterializationOutcomeChange,
  type MaterializedApplicationSnapshot, type MaterializedRevisionSnapshot, type MaterializedTransactionOutcome,
} from './runtime.js'

export interface EventExecutionStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, value: Uint8Array): Promise<void>
}

export interface EventMaterializationOptions {
  readonly store: EventExecutionStore
  readonly namespace: string
  readonly maxHistoryBytes?: number
}

/** One SQL-absent execution profile and timestamp comparator, independent of inclusion policy. */
export async function eventExecutionManifest() {
  return createExecutionManifest({
    profile: 'chronolog-events-v1', engine: 'none',
    engineDigest: await sha256(utf8('chronolog/events-only/v1')),
    platformDigest: await sha256(utf8('chronolog/change-program/v3;literal-events;operation-conflicts/v1;author-time-order/v1')),
  })
}

/** Applied events can be replayed in full; this runtime has no final view or finality state. */
export function createAppliedEventMaterializationRuntime(options: EventMaterializationOptions): Promise<AppliedMaterializationRuntime> {
  return openEventRuntime(options, false)
}

/** The live wrapper adds a durably pinned final prefix to the same replay engine. */
export function createEventMaterializationRuntime(options: EventMaterializationOptions): Promise<ChronologMaterializationRuntime> {
  return openEventRuntime(options, true)
}

interface FinalPrefix { length: number; revision: bigint }

function openEventRuntime(options: EventMaterializationOptions, live: false): Promise<AppliedMaterializationRuntime>
function openEventRuntime(options: EventMaterializationOptions, live: true): Promise<ChronologMaterializationRuntime>
async function openEventRuntime(options: EventMaterializationOptions, live: boolean): Promise<AppliedMaterializationRuntime | ChronologMaterializationRuntime> {
  if (options.namespace.length === 0) throw new Error('EVENT_EXECUTION_NAMESPACE_REQUIRED')
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest())
  const digest = artifacts.executionManifestDigest
  const key = `event-execution/${options.namespace}`
  const quota = options.maxHistoryBytes ?? 64 * 1024 * 1024
  if (!Number.isSafeInteger(quota) || quota < 1024) throw new Error('EVENT_EXECUTION_QUOTA_INVALID')
  let revision = 0n
  const finalPrefix: FinalPrefix | null = live ? { length: 0, revision: 0n } : null
  let order: ReplayProposal[] = []
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
  const encode = (next: readonly ReplayProposal[], rev: bigint, prefix: FinalPrefix | null): Uint8Array => encodeCanonicalCbor([
    'chronolog/event-execution/v2', digest, rev,
    next.map((entry) => [entry.txId, entry.candidateDigest, entry.canonicalCandidate]),
    ...(prefix === null ? [] : [BigInt(prefix.length), prefix.revision]),
  ])
  const evaluate = async (next: readonly ReplayProposal[]): Promise<MaterializedTransactionOutcome[]> => {
    const operations = new Set<string>(), transactions = new Set<string>(), proposals = new Set<string>()
    const result: MaterializedTransactionOutcome[] = []
    for (const [index, entry] of next.entries()) {
      const core = entry.core
      if (entry.txId.length === 0) throw new Error('EVENT_EXECUTION_INPUT_INVALID')
      if (!equalBytes(core.executionManifestDigest, digest)) throw new Error('EVENT_EXECUTION_PROFILE_UNAVAILABLE')
      if (!equalBytes(encodeTransactionCore(core), entry.canonicalCandidate) ||
          !equalBytes(await transactionDigest(entry.canonicalCandidate), entry.candidateDigest)) throw new Error('EVENT_EXECUTION_INPUT_INVALID')
      assertValidChangeProgram(core.program)
      const transactionId = bytesToHex(entry.txId), proposalId = bytesToHex(entry.candidateDigest)
      if (transactions.has(transactionId)) throw new Error('EVENT_EXECUTION_DUPLICATE_TRANSACTION')
      if (proposals.has(proposalId)) throw new Error('EVENT_EXECUTION_DUPLICATE_PROPOSAL')
      transactions.add(transactionId); proposals.add(proposalId)
      const orderKey = transactionOrderKey(core, entry.txId)
      if (index > 0 && compareTransactionOrder(result[index - 1]!.orderKey, orderKey) >= 0) {
        throw new Error('EVENT_EXECUTION_ORDER_NOT_CHRONOLOGICAL')
      }
      const operation = `${bytesToHex(core.authorId)}/${core.operationId}`
      const failing = core.program.steps.findIndex((step) => !isEmitStep(step))
      const code = operations.has(operation) ? 'operation_conflict' : failing >= 0 ? 'profile:sql-disabled' : null
      operations.add(operation)
      result.push({ txId: entry.txId.slice(), orderKey, orderIndex: index,
        outcome: code === null ? 'accepted' : 'rejected', rejectionCode: code,
        failingStatementIndex: code === 'profile:sql-disabled' ? failing : null })
    }
    return result
  }
  const persisted = await options.store.get(key)
  if (persisted !== null) {
    if (persisted.length > quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    const value = assertCanonicalCbor(persisted, { maxBytes: quota, maxByteStringBytes: quota, maxItems: quota })
    if (!Array.isArray(value) || value.length !== (live ? 6 : 4) || value[0] !== 'chronolog/event-execution/v2' ||
        !(value[1] instanceof Uint8Array) || !equalBytes(value[1], digest) || typeof value[2] !== 'bigint' ||
        value[2] < 0n || !Array.isArray(value[3])) throw new Error('EVENT_EXECUTION_STORE_INVALID')
    revision = value[2]
    if (finalPrefix !== null) {
      if (typeof value[4] !== 'bigint' || typeof value[5] !== 'bigint' ||
          value[4] < 0n || value[4] > BigInt(value[3].length) || value[5] < 0n) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      finalPrefix.length = Number(value[4]); finalPrefix.revision = value[5]
    }
    order = value[3].map((row) => {
      if (!Array.isArray(row) || row.length !== 3 || !(row[0] instanceof Uint8Array) ||
          !(row[1] instanceof Uint8Array) || !(row[2] instanceof Uint8Array)) throw new Error('EVENT_EXECUTION_STORE_INVALID')
      return { txId: row[0], candidateDigest: row[1], canonicalCandidate: row[2], core: decodeTransactionCore(row[2]) }
    })
    outcomes = await evaluate(order)
  }
  const persist = async (bytes: Uint8Array): Promise<void> => {
    if (bytes.length > quota) throw new Error('EVENT_EXECUTION_QUOTA_EXCEEDED')
    try { await options.store.put(key, bytes) }
    catch (error) {
      // Atomic storage may have committed before its acknowledgment was lost.
      // Reopen the newer durable state before allowing any further mutation.
      closed = true
      subscribers.clear()
      throw error
    }
  }
  const capture = (length = order.length, capturedRevision = revision): AppliedApplicationSnapshot => {
    if (closed) throw new Error('EVENT_EXECUTION_CLOSED')
    const selected = order, selectedOutcomes = outcomes
    return {
      revision: capturedRevision, orderLength: length,
      transactionAt(index) {
        if (!Number.isSafeInteger(index) || index < 0 || index >= length) return null
        const entry = selected[index]!
        return { txId: entry.txId.slice(), canonicalCandidate: entry.canonicalCandidate.slice(), outcome: selectedOutcomes[index]!.outcome }
      },
    }
  }
  const applied: AppliedMaterializationRuntime = {
    kind: 'applied',
    coordinator: {
      materialize: async (input) => {
        const next = structuredClone(input) as ReplayProposal[]
        return serial(async () => {
          const nextOutcomes = await evaluate(next)
          if (finalPrefix !== null) {
            for (let i = 0; i < finalPrefix.length; i++) if (next[i] === undefined || !sameIdentity(order[i]!, next[i]!)) throw new Error('EVENT_EXECUTION_FINAL_PREFIX_CHANGED')
          }
          // Selection may change; an original proposal's signed bytes never do.
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
          const bytes = encode(next, nextRevision, finalPrefix)
          const contentHash = bytesToHex(await sha256(bytes))
          const changes: MaterializationOutcomeChange[] = nextOutcomes.flatMap((current) => {
            const before = outcomes.find((value) => equalBytes(value.txId, current.txId))
            return before?.outcome === current.outcome && before.rejectionCode === current.rejectionCode ? [] : [{
              txId: current.txId.slice(), previous: before?.outcome ?? null, current: current.outcome,
              previousRejectionCode: before?.rejectionCode ?? null, currentRejectionCode: current.rejectionCode,
            }]
          })
          const selected = new Set(next.map(entry => bytesToHex(entry.txId)))
          for (const removed of outcomes) if (!selected.has(bytesToHex(removed.txId))) changes.push({
            txId: removed.txId.slice(), previous: removed.outcome, current: null,
            previousRejectionCode: removed.rejectionCode, currentRejectionCode: null,
          })
          await persist(bytes)
          order = next; outcomes = nextOutcomes; revision = nextRevision
          const result = { revision, previousRevision, orderLength: order.length, replayFromIndex: difference,
            replayedTransactions: order.length - difference, checkpointPrefix: difference, contentHash,
            manifestDigest: digest.slice(), earliestChangedOrderIndex: difference, outcomeChanges: changes }
          for (const subscriber of [...subscribers]) { try { subscriber(snapshot()) } catch { /* Observers cannot undo a committed outcome. */ } }
          return { revision: result, publication: publicationRequestForRevision(result) }
        })
      },
    },
    queries: {
      get revision() { return revision }, get orderLength() { return order.length },
      get executionManifestDigest() { return digest.slice() },
      proposalIdAt(index) { return order[index]?.txId.slice() ?? null },
      localSql() { throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
      outcome(id) { return structuredClone(outcomes.find((entry) => equalBytes(entry.txId, id)) ?? null) },
      subscribe(subscriber) { subscribers.add(subscriber); return () => { subscribers.delete(subscriber) } },
      captureApplication() { return capture() },
      captureRead() { return eventReadHandle(capture()) },
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
  if (finalPrefix === null) return applied
  const captureLive = (input: { readonly view?: 'local' | 'final' } = {}): MaterializedApplicationSnapshot => {
    const view = input.view ?? 'final'
    return { ...capture(view === 'final' ? finalPrefix.length : order.length, view === 'final' ? finalPrefix.revision : revision),
      view, finalRevision: finalPrefix.revision, finalOrderLength: finalPrefix.length }
  }
  return {
    coordinator: {
      materialize(input) { return applied.coordinator.materialize(input) },
      publishFinal: (length) => serial(async () => {
        if (!Number.isSafeInteger(length) || length < finalPrefix.length || length > order.length) throw new Error('EVENT_EXECUTION_FINAL_PREFIX_INVALID')
        if (length === finalPrefix.length) return
        const next = { length, revision: finalPrefix.revision + 1n }
        await persist(encode(order, revision, next))
        Object.assign(finalPrefix, next)
      }),
    },
    queries: {
      get revision() { return revision }, get orderLength() { return order.length },
      get finalRevision() { return finalPrefix.revision }, get finalOrderLength() { return finalPrefix.length },
      get executionManifestDigest() { return digest.slice() },
      proposalIdAt(index) { return applied.queries.proposalIdAt(index) },
      localSql() { throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
      outcome(id) { return applied.queries.outcome(id) },
      subscribe(subscriber) { return applied.queries.subscribe(subscriber) },
      captureApplication: captureLive,
      captureRead(input) { return eventReadHandle(captureLive(input)) },
    },
    publications: applied.publications,
    close() { return applied.close() },
  }
}

function eventReadHandle<T extends AppliedApplicationSnapshot>(application: T): T & AppliedReadHandle {
  let released = false
  return { ...application,
    query() { if (released) throw new Error('VIEW_RELEASED'); throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
    release() { released = true } }
}

function sameIdentity(left: ReplayProposal, right: ReplayProposal): boolean {
  return equalBytes(left.txId, right.txId) &&
    equalBytes(left.candidateDigest, right.candidateDigest) && equalBytes(left.canonicalCandidate, right.canonicalCandidate)
}

import { bytesToHex, sha256 } from '@chronolog/canonical'
import {
  assertValidChangeProgram, createExecutionManifest,
  encodeTransactionCore, equalBytes, executionManifestArtifacts,
  isEmitStep, transactionDigest, transactionOrderKey, compareTransactionOrder, utf8,
} from '@chronolog/protocol'
import type { ReplayProposal } from './types.js'
import {
  publicationRequestForRevision, type AppliedApplicationSnapshot, type AppliedMaterializationRuntime,
  type AppliedReadHandle, type ChronologMaterializationRuntime, type MaterializationOutcomeChange,
  type MaterializedApplicationSnapshot, type MaterializedRevisionSnapshot, type MaterializedTransactionOutcome,
} from './runtime.js'

import { EventHistoryStore, type EventExecutionStore, type EventHistoryState } from './event-store.js'
export type { EventExecutionStore } from './event-store.js'

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
  const storage = new EventHistoryStore(options.store, key, digest, quota, live ? 'live' : 'applied')
  const historyState = (next: readonly ReplayProposal[], rev: bigint, prefix: FinalPrefix | null): EventHistoryState =>
    prefix === null ? { kind: 'applied', order: next, revision: rev } :
      { kind: 'live', order: next, revision: rev, finalLength: prefix.length, finalRevision: prefix.revision }
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
  const persisted = await storage.load()
  if (persisted !== null) {
    revision = persisted.revision
    if (persisted.kind === 'live' && finalPrefix !== null) {
      finalPrefix.length = persisted.finalLength; finalPrefix.revision = persisted.finalRevision
    }
    order = [...persisted.order]
    outcomes = await evaluate(order)
  }
  let outcomeIndex = new Map(outcomes.map(outcome => [bytesToHex(outcome.txId), outcome]))
  const persist = async (state: EventHistoryState, difference: number): Promise<string> => {
    try { return await storage.commit(state, difference) }
    catch (error) {
      // A body or atomic head may have committed before its reply was lost.
      // Reopen from the durable head before any further mutation.
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
          const changes: MaterializationOutcomeChange[] = nextOutcomes.flatMap((current) => {
            const before = outcomeIndex.get(bytesToHex(current.txId))
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
          // Indexed immutable records are published by one small atomic head.
          const contentHash = await persist(historyState(next, nextRevision, finalPrefix), difference)
          order = next; outcomes = nextOutcomes; revision = nextRevision
          outcomeIndex = new Map(outcomes.map(outcome => [bytesToHex(outcome.txId), outcome]))
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
      outcome(id) { return structuredClone(outcomeIndex.get(bytesToHex(id)) ?? null) },
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
        await persist(historyState(order, revision, next), order.length)
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

import type { BytesStore } from '@chronolog/records'
import { bytesToHex } from '@chronolog/canonical'
import {
  assertValidChangeProgram,
  encodeTransactionCore, equalBytes, executionManifestArtifacts,
  isEmitStep, transactionDigest, transactionOrderKey,
} from '@chronolog/protocol'
import type { ReplayProposal } from './types.js'
import {
  publicationRequestForRevision, type ChronologMaterializationRuntime, type MaterializationOutcomeChange,
  type MaterializedApplicationSnapshot, type MaterializedRevisionSnapshot, type MaterializedTransactionOutcome,
} from './runtime.js'

import { EventHistoryStore, type EventHistoryState } from './event-store.js'
export type { BytesStore } from '@chronolog/records'

export { eventExecutionManifest } from './manifest.js'
import { eventExecutionManifest } from './manifest.js'

export async function createEventMaterializationRuntime(options: {
  readonly store: BytesStore
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
  const storage = new EventHistoryStore(options.store, key, digest, quota)
  const verifiedInputs = new WeakMap<ReplayProposal, ReplayProposal>()
  let knownOperations = new Set<string>(), knownTransactions = new Set<string>(), knownProposals = new Set<string>()
  const rebuildIndices = (entries: readonly ReplayProposal[]) => {
    knownOperations = new Set<string>()
    knownTransactions = new Set<string>()
    knownProposals = new Set<string>()
    for (const entry of entries) {
      knownTransactions.add(bytesToHex(entry.txId))
      knownProposals.add(bytesToHex(entry.candidateDigest))
      knownOperations.add(`${bytesToHex(entry.core.authorId)}/${entry.core.operationId}`)
    }
  }
  const evaluateRange = async (
    next: readonly ReplayProposal[],
    start: number,
    operations: Set<string>,
    transactions: Set<string>,
    proposals: Set<string>,
  ): Promise<MaterializedTransactionOutcome[]> => {
    const result: MaterializedTransactionOutcome[] = []
    for (let index = start; index < next.length; index++) {
      const entry = next[index]!
      const core = entry.core
      if (entry.txId.length === 0) {
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
      const orderKey = transactionOrderKey(core, entry.txId)
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
    revision = persisted.revision; finalLength = persisted.finalLength; finalRevision = persisted.finalRevision
    order = [...persisted.order]
    outcomes = await evaluateRange(order, 0, knownOperations, knownTransactions, knownProposals)
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
  const captureApplication = (input: { readonly view?: 'local' | 'final' } = {}): MaterializedApplicationSnapshot => {
    if (closed) throw new Error('EVENT_EXECUTION_CLOSED')
    const view = input.view ?? 'local'
    const length = view === 'final' ? finalLength : order.length
    const selected = order, selectedOutcomes = outcomes
    return {
      view, revision: view === 'final' ? finalRevision : revision, orderLength: length,
      finalRevision, finalOrderLength: finalLength,
      transactionAt(index) {
        if (!Number.isSafeInteger(index) || index < 0 || index >= length) return null
        const entry = selected[index]!
        return { txId: entry.txId.slice(), canonicalCandidate: entry.canonicalCandidate.slice(), outcome: selectedOutcomes[index]!.outcome }
      },
    }
  }
  return {
    coordinator: {
      materialize: async (input) => {
        // Own unverified suffix inputs synchronously before queuing, while keeping
        // already-verified prefix references O(1) without cloning the whole history.
        const snapshotInput = input.map(entry => verifiedInputs.has(entry) ? entry : structuredClone(entry))
        return serial(async () => {
          let difference = 0
          while (difference < order.length && difference < snapshotInput.length) {
            const incoming = snapshotInput[difference]!, retained = order[difference]!
            if (verifiedInputs.get(incoming) === retained) { difference++; continue }
            if (!sameIdentity(retained, incoming)) break
            if (!equalBytes(encodeTransactionCore(incoming.core), incoming.canonicalCandidate)) {
              throw new Error('EVENT_EXECUTION_INPUT_INVALID')
            }
            difference++
          }
          if (difference < finalLength) throw new Error('EVENT_EXECUTION_FINAL_PREFIX_CHANGED')
          const suffix = snapshotInput.slice(difference)
          const next = difference === order.length && suffix.length === 0 ? order : [...order.slice(0, difference), ...suffix]
          const pureAppend = difference === order.length
          const operations = pureAppend ? new Set(knownOperations) : new Set<string>()
          const transactions = pureAppend ? new Set(knownTransactions) : new Set<string>()
          const proposals = pureAppend ? new Set(knownProposals) : new Set<string>()
          if (!pureAppend) {
            for (let i = 0; i < difference; i++) {
              const entry = order[i]!
              transactions.add(bytesToHex(entry.txId))
              proposals.add(bytesToHex(entry.candidateDigest))
              operations.add(`${bytesToHex(entry.core.authorId)}/${entry.core.operationId}`)
            }
          }
          const suffixOutcomes = await evaluateRange(next, difference, operations, transactions, proposals)
          if (pureAppend && suffix.length === 0) return null
          // A provisional preview may lose authorization before its timestamp
          // closes. Selection may change; original proposal bytes never do.
          if (!pureAppend) {
            const previousById = new Map(order.map(entry => [bytesToHex(entry.txId), entry]))
            for (const entry of suffix) {
              const previous = previousById.get(bytesToHex(entry.txId))
              if (previous !== undefined && !sameIdentity(previous, entry)) throw new Error('EVENT_EXECUTION_IDENTITY_CONFLICT')
            }
          }
          const nextOutcomes = [...outcomes.slice(0, difference), ...suffixOutcomes]
          const previousRevision = revision
          const nextRevision = revision + 1n
          const changes: MaterializationOutcomeChange[] = []
          if (pureAppend) {
            for (const current of suffixOutcomes) {
              changes.push({
                txId: current.txId.slice(), previous: null, current: current.outcome,
                previousRejectionCode: null, currentRejectionCode: current.rejectionCode,
              })
            }
          } else {
            for (const current of suffixOutcomes) {
              const before = outcomeIndex.get(bytesToHex(current.txId))
              if (before?.outcome !== current.outcome || before.rejectionCode !== current.rejectionCode) {
                changes.push({
                  txId: current.txId.slice(), previous: before?.outcome ?? null, current: current.outcome,
                  previousRejectionCode: before?.rejectionCode ?? null, currentRejectionCode: current.rejectionCode,
                })
              }
            }
            const selected = new Set(next.map(entry => bytesToHex(entry.txId)))
            for (let i = difference; i < outcomes.length; i++) {
              const removed = outcomes[i]!
              if (!selected.has(bytesToHex(removed.txId))) changes.push({
                txId: removed.txId.slice(), previous: removed.outcome, current: null,
                previousRejectionCode: removed.rejectionCode, currentRejectionCode: null,
              })
            }
          }
          // Indexed immutable records are published by one small atomic head.
          const contentHash = await persist({ order: next, revision: nextRevision, finalLength, finalRevision }, difference)
          for (let i = 0; i < suffix.length; i++) verifiedInputs.set(snapshotInput[difference + i]!, suffix[i]!)
          order = next; outcomes = nextOutcomes; revision = nextRevision
          knownOperations = operations; knownTransactions = transactions; knownProposals = proposals
          if (pureAppend) {
            for (const outcome of suffixOutcomes) outcomeIndex.set(bytesToHex(outcome.txId), outcome)
          } else {
            outcomeIndex = new Map(outcomes.map(outcome => [bytesToHex(outcome.txId), outcome]))
            rebuildIndices(order)
          }
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
        await persist({ order, revision, finalLength: length, finalRevision: finalRevision + 1n }, order.length)
        finalLength = length; finalRevision++
      }),
    },
    queries: {
      capabilities: Object.freeze({ sql: false }),
      get revision() { return revision }, get orderLength() { return order.length },
      get finalRevision() { return finalRevision }, get finalOrderLength() { return finalLength },
      get executionManifestDigest() { return digest.slice() },
      proposalIdAt(index) { return order[index]?.txId.slice() ?? null },
      localSql() { throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
      outcome(id) { return structuredClone(outcomeIndex.get(bytesToHex(id)) ?? null) },
      subscribe(subscriber) { subscribers.add(subscriber); return () => { subscribers.delete(subscriber) } },
      captureApplication,
      captureRead(input = {}) {
        const application = captureApplication(input)
        let released = false
        return { ...application,
          query() { if (released) throw new Error('VIEW_RELEASED'); throw new Error('SQL_DISABLED_FOR_EVENT_PROFILE') },
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

function sameIdentity(left: ReplayProposal, right: ReplayProposal): boolean {
  return equalBytes(left.txId, right.txId) &&
    equalBytes(left.candidateDigest, right.candidateDigest) && equalBytes(left.canonicalCandidate, right.canonicalCandidate)
}

import { appendControl, controlGenesisRoot, isControlRecord } from './control-chain.js'
import {
  isFinalityClosureRecord, verifyFinalityClosureRecord,
  type FinalityClosureBoundary, type SignedFinalityClosure, type SignedInclusionSnapshot,
} from './finality.js'
import { orderedGenesisRoot, verifyOrderedEntry,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry } from './history-policy.js'

/**
 * Internal immutable verifier state. Construction starts at genesis; callers
 * cannot supply a snapshot and thereby promote unverified bytes to a prefix.
 * Extending creates a staged value, leaving the previous durable state intact.
 */
export class VerifiedFinalityPrefix {
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #snapshot: SignedInclusionSnapshot
  readonly #coveredRecords: number

  private constructor(configuration: CoordinatedHistoryConfiguration, snapshot: SignedInclusionSnapshot, coveredRecords: number) {
    this.#configuration = configuration
    this.#snapshot = snapshot
    this.#coveredRecords = coveredRecords
  }

  static async empty(configuration: CoordinatedHistoryConfiguration): Promise<VerifiedFinalityPrefix> {
    configuration = structuredClone(configuration)
    const root = await orderedGenesisRoot(configuration.historyId)
    return new VerifiedFinalityPrefix(configuration, {
      checkpointId: root, receivedThrough: 0, includedThrough: 0,
      closedReceiptThrough: 0, closedThroughMs: -1n, records: [], closures: [],
      control: { count: 0, root: await controlGenesisRoot(configuration) }, controls: [],
    }, 0)
  }

  get includedThrough(): number { return this.#snapshot.includedThrough }
  get checkpointId(): string { return this.#snapshot.checkpointId }

  snapshot(receivedThrough = this.includedThrough): SignedInclusionSnapshot {
    if (!Number.isSafeInteger(receivedThrough) || receivedThrough < this.includedThrough) {
      throw new Error('FINALITY_CLOSURE_PREFIX_INCOMPLETE')
    }
    return structuredClone({ ...this.#snapshot, receivedThrough })
  }

  async append(entries: readonly OrderedRecordEntry[]): Promise<VerifiedFinalityPrefix> {
    entries = structuredClone(entries)
    if (entries.length === 0) return this
    const configuration = this.#configuration, previous = this.#snapshot
    // These arrays and any newly covered record are replaced, never mutated in
    // the owned prefix. Earlier closure boundaries and admission floors stay exact.
    const records = [...previous.records], closures = [...previous.closures], controls = [...previous.controls]
    let root = previous.checkpointId, position = previous.includedThrough
    let closedThroughMs = previous.closedThroughMs, coveredRecords = this.#coveredRecords
    let control = previous.control
    for (const entry of entries) {
      if (entry.historyId !== configuration.historyId || entry.position !== position + 1 || entry.previousRoot !== root) {
        throw new Error('FINALITY_CLOSURE_PREFIX_INCOMPLETE')
      }
      await verifyOrderedEntry(entry)
      let closure: SignedFinalityClosure | null = null
      if (isFinalityClosureRecord(entry.bytes)) {
        try { closure = await verifyFinalityClosureRecord(entry.bytes, configuration) }
        catch (error) {
          // Generic writer bytes may resemble a marker. Only an authenticated
          // promise can close time or contradict an earlier authority promise.
          if (!(error instanceof Error) || !/^FINALITY_CLOSURE_(INVALID|SIGNATURE_INVALID|CONFIGURATION_MISMATCH)$/u.test(error.message)) throw error
        }
      }
      if (closure !== null) {
        if (closure.includedHead.position !== position || closure.includedHead.root !== root) {
          throw new Error('FINALITY_CLOSURE_HEAD_MISMATCH')
        }
        if (closure.closedThroughMs < closedThroughMs) throw new Error('FINALITY_CLOSURE_REGRESSION')
        const boundary: FinalityClosureBoundary = {
          position: entry.position, root: entry.root, includedThrough: position,
          includedRoot: root, closedThroughMs: closure.closedThroughMs,
        }
        closures.push(boundary)
        for (; coveredRecords < records.length; coveredRecords += 1) {
          const included = records[coveredRecords]!
          if (isControlRecord(included.entry.bytes)) {
            const next = await appendControl(control, included.entry, boundary.closedThroughMs)
            controls.push(next); control = { count: next.index, root: next.root }
          }
          records[coveredRecords] = { ...included, closureBoundary: boundary, closedThroughMs: boundary.closedThroughMs }
        }
        if (closure.control.count !== control.count || closure.control.root !== control.root) {
          throw new Error('FINALITY_CONTROL_PROJECTION_MISMATCH')
        }
        closedThroughMs = closure.closedThroughMs
      } else records.push({ entry, admissionFloorMs: closedThroughMs, closedThroughMs: -1n, closureBoundary: null })
      root = entry.root
      position = entry.position
    }
    return new VerifiedFinalityPrefix(configuration, {
      checkpointId: root, receivedThrough: position, includedThrough: position,
      closedReceiptThrough: closures.at(-1)?.includedThrough ?? 0, closedThroughMs,
      records, closures, control, controls,
    }, coveredRecords)
  }
}

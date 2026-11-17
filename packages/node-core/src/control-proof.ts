import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'

import { Mutex } from './async.js'
import { controlGenesisRoot, verifyControl, type FinalizedControl } from './control-chain.js'
import { decodeFinalityClosureRecord, verifyFinalityClosureRecord, type SignedFinalityClosure } from './finality.js'
import { decodeOrderingEvidence, encodeHistoryConfiguration, encodeOrderingEvidence, orderedGenesisRoot,
  verifyOrderedEntry, verifyPrefixCertificate, type CoordinatedHistoryConfiguration, type OrderedRecordEntry,
  type PrefixCertificate } from './history-policy.js'
import type { DurableOperationStore } from './operations.js'

export interface MembershipLedgerPage {
  readonly entries: readonly FinalizedControl[]
  /** The committed closure authenticates completeness and each original activation cutoff. */
  readonly checkpoint: OrderedRecordEntry | null
  readonly certificate: PrefixCertificate
  readonly hasMore: boolean
}

export interface ControlProgress {
  readonly receivedThrough: number
  readonly verifiedThrough: number
  readonly root: string
  readonly checkpointThrough: number
  readonly receiptThrough: number
  readonly closedThroughMs: bigint
}

const MAX_STORED_BYTES = 16 * 1024 * 1024

export function encodeFinalizedControl(value: FinalizedControl): Uint8Array {
  if (!Number.isSafeInteger(value.index) || value.index < 1 || !/^[0-9a-f]{64}$/u.test(value.previousRoot) ||
      !/^[0-9a-f]{64}$/u.test(value.root) || value.cutoffMs < 0n || value.cutoffMs > (1n << 63n) - 1n) {
    throw new Error('CONTROL_PROJECTION_INVALID')
  }
  return encodeCanonicalCbor([1n, BigInt(value.index), value.previousRoot, value.root,
    encodeOrderingEvidence({ kind: 'ordered-entry', entry: value.entry }), value.cutoffMs])
}

export function decodeFinalizedControl(bytes: Uint8Array): FinalizedControl {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 6 || value[0] !== 1n || typeof value[1] !== 'bigint' ||
      typeof value[2] !== 'string' || typeof value[3] !== 'string' || !(value[4] instanceof Uint8Array) ||
      typeof value[5] !== 'bigint') throw new Error('CONTROL_PROJECTION_INVALID')
  const evidence = decodeOrderingEvidence(value[4])
  if (evidence.kind !== 'ordered-entry') throw new Error('CONTROL_PROJECTION_INVALID')
  const result = { index: Number(value[1]), previousRoot: value[2], root: value[3], entry: evidence.entry, cutoffMs: value[5] }
  encodeFinalizedControl(result)
  return result
}

export function encodeControlPage(page: MembershipLedgerPage): Uint8Array {
  return encodeCanonicalCbor([2n, page.entries.map(encodeFinalizedControl),
    page.checkpoint === null ? null : encodeOrderingEvidence({ kind: 'ordered-entry', entry: page.checkpoint }),
    encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: page.certificate }), page.hasMore])
}

export function decodeControlPage(bytes: Uint8Array, stored = false): MembershipLedgerPage {
  const value = assertCanonicalCbor(bytes, { maxBytes: stored ? MAX_STORED_BYTES : 2 * 1024 * 1024,
    maxByteStringBytes: stored ? MAX_STORED_BYTES : 2 * 1024 * 1024, maxItems: stored ? 65_536 : 256 })
  if (!Array.isArray(value) || value.length !== 5 || value[0] !== 2n || !Array.isArray(value[1]) ||
      (!stored && value[1].length > 128) || !(value[2] === null || value[2] instanceof Uint8Array) ||
      !(value[3] instanceof Uint8Array) || typeof value[4] !== 'boolean') throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  const certificate = decodeOrderingEvidence(value[3])
  const checkpoint = value[2] instanceof Uint8Array ? decodeOrderingEvidence(value[2]) : null
  if (certificate.kind !== 'prefix-certificate' || checkpoint !== null && checkpoint.kind !== 'ordered-entry') {
    throw new Error('MEMBERSHIP_RESPONSE_INVALID')
  }
  return { entries: value[1].map(item => {
    if (!(item instanceof Uint8Array)) throw new Error('MEMBERSHIP_RESPONSE_INVALID')
    return decodeFinalizedControl(item)
  }), checkpoint: checkpoint?.entry ?? null, certificate: certificate.certificate, hasMore: value[4] }
}

/** Verify a compact checkpoint without trusting the HTTP service or membership host. */
export async function verifyControlCheckpoint(input: MembershipLedgerPage,
  expected: CoordinatedHistoryConfiguration): Promise<SignedFinalityClosure | null> {
  const page = { certificate: structuredClone(input.certificate), checkpoint: structuredClone(input.checkpoint) }
  const configuration = structuredClone(expected)
  await verifyPrefixCertificate(page.certificate, configuration)
  const checkpoint = page.checkpoint
  if (checkpoint === null) {
    if (page.certificate.position !== 0 || page.certificate.root !== await orderedGenesisRoot(configuration.historyId)) {
      throw new Error('CONTROL_CHECKPOINT_MISSING')
    }
    return null
  }
  await verifyOrderedEntry(checkpoint)
  const closure = await verifyFinalityClosureRecord(checkpoint.bytes, configuration)
  if (checkpoint.historyId !== configuration.historyId || checkpoint.position !== closure.includedHead.position + 1 ||
      checkpoint.previousRoot !== closure.includedHead.root || page.certificate.position !== checkpoint.position ||
      page.certificate.root !== checkpoint.root) throw new Error('CONTROL_CHECKPOINT_MISMATCH')
  return closure
}

/**
 * Retains governance only. Partial pages are untrusted until their cumulative
 * root reaches a signed closure; they cannot activate grants or become durable
 * checkpoints. A failed/interrupted transfer can restart at verifiedThrough.
 */
export class ControlHistory {
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #store: DurableOperationStore
  readonly #mutex = new Mutex()
  readonly #genesisRoot: string
  readonly #key: string
  readonly #quotaBytes: number
  #controls: readonly FinalizedControl[] = []
  #staged: readonly FinalizedControl[] = []
  #page: MembershipLedgerPage | null = null
  #observed: { readonly certificate: PrefixCertificate; readonly closure: SignedFinalityClosure | null } | null = null

  private constructor(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore, genesisRoot: string, quotaBytes: number) {
    this.#configuration = structuredClone(configuration); this.#store = store; this.#genesisRoot = genesisRoot
    this.#key = `membership/control-proof/${configuration.historyId}`
    this.#quotaBytes = quotaBytes
  }

  static async open(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore,
    options: { readonly quotaBytes?: number } = {}): Promise<ControlHistory> {
    const quotaBytes = options.quotaBytes ?? MAX_STORED_BYTES
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1024 || quotaBytes > MAX_STORED_BYTES) throw new Error('CONTROL_STORAGE_QUOTA_INVALID')
    const history = new ControlHistory(configuration, store, await controlGenesisRoot(configuration), quotaBytes)
    const saved = await store.get(history.#key)
    if (saved !== null) {
      if (saved.length > quotaBytes) throw new Error('CONTROL_STORAGE_QUOTA_EXCEEDED')
      const value = assertCanonicalCbor(saved, { maxBytes: MAX_STORED_BYTES, maxByteStringBytes: MAX_STORED_BYTES })
      if (!Array.isArray(value) || value.length !== 2 || !(value[0] instanceof Uint8Array) || !(value[1] instanceof Uint8Array) ||
          !equalBytes(value[0], encodeHistoryConfiguration(configuration))) throw new Error('CONTROL_STORED_CONFIGURATION_MISMATCH')
      await history.#ingest(decodeControlPage(value[1], true), false)
      if (history.#page === null || history.#staged.length !== history.#controls.length) throw new Error('CONTROL_STORED_PREFIX_INCOMPLETE')
    }
    return history
  }

  get progress(): ControlProgress {
    const closure = this.closure
    return { receivedThrough: this.#staged.length, verifiedThrough: this.#controls.length,
      root: this.#controls.at(-1)?.root ?? this.#genesisRoot,
      checkpointThrough: this.#page?.certificate.position ?? 0,
      receiptThrough: closure?.includedHead.position ?? 0, closedThroughMs: closure?.closedThroughMs ?? -1n }
  }
  get closure(): SignedFinalityClosure | null {
    return this.#page?.checkpoint ? decodeFinalityClosureRecord(this.#page.checkpoint.bytes) : null
  }
  entries(): readonly FinalizedControl[] { return structuredClone(this.#controls) }
  /** Discard an interrupted unverified page sequence; the durable checkpoint is unchanged. */
  restart(): void { this.#staged = this.#controls; this.#observed = null }

  ingest(page: MembershipLedgerPage): Promise<ControlProgress> {
    const captured = structuredClone(page)
    if (captured.entries.length > 128) return Promise.reject(new Error('MEMBERSHIP_RANGE_TOO_LARGE'))
    return this.#mutex.run(async () => {
      try { await this.#ingest(captured, true); return this.progress }
      catch (error) { this.restart(); throw error }
    })
  }

  read(options: { readonly after: number; readonly limit?: number }): MembershipLedgerPage {
    const after = options.after, limit = options.limit ?? 128
    if (!Number.isSafeInteger(after) || after < 0 || after > this.#controls.length ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 128) throw new Error('MEMBERSHIP_RANGE_INVALID')
    if (this.#page === null) throw new Error('MEMBERSHIP_PREFIX_PENDING')
    const entries: FinalizedControl[] = []
    let bytes = 0
    for (const entry of this.#controls.slice(after, after + limit)) {
      const size = encodeFinalizedControl(entry).length
      if (entries.length && bytes + size > 1024 * 1024) break
      entries.push(entry); bytes += size
    }
    return structuredClone({ ...this.#page, entries, hasMore: after + entries.length < this.#controls.length })
  }

  async #ingest(page: MembershipLedgerPage, persist: boolean): Promise<void> {
    const closure = await verifyControlCheckpoint(page, this.#configuration)
    const count = closure?.control.count ?? 0, root = closure?.control.root ?? this.#genesisRoot
    const previous = this.#observed?.closure ?? this.closure
    if (count < Math.max(this.#controls.length, previous?.control.count ?? 0) || (previous !== null && (closure === null ||
        closure.includedHead.position < previous.includedHead.position || closure.closedThroughMs < previous.closedThroughMs))) {
      throw new Error('CONTROL_CHECKPOINT_REGRESSION')
    }
    if (this.#page !== null && page.certificate.position === this.#page.certificate.position &&
        page.certificate.root !== this.#page.certificate.root) throw new Error('CONTROL_CHECKPOINT_EQUIVOCATION')
    if (this.#observed !== null && page.certificate.position === this.#observed.certificate.position &&
        page.certificate.root !== this.#observed.certificate.root) throw new Error('CONTROL_CHECKPOINT_EQUIVOCATION')
    if (previous !== null && count === previous.control.count && root !== previous.control.root) throw new Error('CONTROL_CHECKPOINT_EQUIVOCATION')
    if (count === this.#controls.length && root !== this.progress.root) throw new Error('CONTROL_CHECKPOINT_EQUIVOCATION')
    const staged = [...this.#staged]
    let priorIndex: number | undefined
    for (const control of page.entries) {
      if (priorIndex !== undefined && control.index !== priorIndex + 1) throw new Error('MEMBERSHIP_RANGE_GAP')
      priorIndex = control.index
      await verifyControl(control, this.#configuration)
      if (control.index > count || control.entry.position > (closure?.includedHead.position ?? 0) ||
          control.cutoffMs > (closure?.closedThroughMs ?? -1n)) throw new Error('CONTROL_CHECKPOINT_MISMATCH')
      const known = staged[control.index - 1]
      if (known !== undefined) {
        if (!equalBytes(encodeFinalizedControl(known), encodeFinalizedControl(control))) throw new Error('CONTROL_PREFIX_CONFLICT')
        continue
      }
      const last = staged.at(-1)
      if (control.index !== staged.length + 1 || control.previousRoot !== (last?.root ?? this.#genesisRoot)) throw new Error('MEMBERSHIP_RANGE_GAP')
      if (last !== undefined && (control.entry.position <= last.entry.position || control.cutoffMs < last.cutoffMs)) {
        throw new Error('CONTROL_PROJECTION_ORDER_INVALID')
      }
      staged.push(control)
    }
    if (staged.length > 65_536 || staged.reduce((bytes, control) => bytes + encodeFinalizedControl(control).length, 0) > this.#quotaBytes) {
      throw new Error('CONTROL_STORAGE_QUOTA_EXCEEDED')
    }
    if (staged.length > count || page.hasMore !== ((page.entries.at(-1)?.index ?? staged.length) < count)) throw new Error('CONTROL_PAGE_PROGRESS_INVALID')
    if (staged.length !== count) {
      if (!page.entries.length) throw new Error('MEMBERSHIP_RANGE_GAP')
      this.#staged = staged
      this.#observed = { certificate: page.certificate, closure }
      return
    }
    if ((staged.at(-1)?.root ?? this.#genesisRoot) !== root) throw new Error('CONTROL_PROJECTION_ROOT_MISMATCH')
    const complete = { ...page, entries: staged, hasMore: false }
    const bytes = encodeCanonicalCbor([encodeHistoryConfiguration(this.#configuration), encodeControlPage(complete)])
    if (bytes.length > this.#quotaBytes) throw new Error('CONTROL_STORAGE_QUOTA_EXCEEDED')
    if (persist && (this.#page === null || !equalBytes(encodeControlPage(complete), encodeControlPage(this.#page)))) {
      await this.#store.put(this.#key, bytes)
    }
    this.#controls = staged; this.#staged = staged; this.#page = complete; this.#observed = null
  }
}

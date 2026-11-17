import { bytesToHex, sha256 } from '@chronolog/canonical'
import { assertCanonicalCbor, encodeCanonicalCbor, equalBytes, utf8 } from '@chronolog/protocol'

import { Mutex } from './async.js'
import { decodeSignedFinalityBatch, encodeSignedFinalityBatch, evaluateFinalitySnapshot, finalityBatchId,
  finalityGenesisId, verifyFinalityBatch, type FinalityProvider, type SealedBatchSnapshot, type SignedFinalityBatch } from './finality.js'
import type { DurableOperationStore } from './operations.js'

/** One immutable finality policy: a fixed proposer and every configured validator. */
export interface HistoryConfiguration {
  readonly groupId: Uint8Array
  readonly genesisDigest: Uint8Array
  readonly executionManifestDigest: Uint8Array
  readonly historyId: string
  readonly proposerPublicKey: Uint8Array
  readonly validatorPublicKeys: readonly Uint8Array[]
}

export interface OrderedRecordEntry {
  readonly historyId: string
  /** Descriptor position identifies inclusion, not execution order within a batch. */
  readonly position: number
  readonly recordId: string
  readonly previousRoot: string
  readonly root: string
  readonly bytes: Uint8Array
}
export interface OrderedRecordHead { readonly historyId: string; readonly position: number; readonly root: string }
export type FinalityEvidence =
  | { readonly kind: 'record'; readonly entry: OrderedRecordEntry }
  | { readonly kind: 'batch'; readonly batch: SignedFinalityBatch }
export interface FinalityProgress {
  readonly receivedThrough: number
  readonly verifiedThrough: number
  readonly certifiedThrough: number
  readonly finalizedThrough: number
  readonly batchNumber: number
  readonly root: string
  readonly missing: readonly number[]
}

const LOG_DOMAIN = 'record-log/v1'
export const MAX_RETAINED_HISTORY_ENTRIES = 65_536
const MAX_RETAINED_EVIDENCE = MAX_RETAINED_HISTORY_ENTRIES * 2
const DEFAULT_EVIDENCE_QUOTA_BYTES = 128 * 1024 * 1024
const MAX_LOCAL_HISTORY_BYTES = 512 * 1024 * 1024

export function encodeHistoryConfiguration(configuration: HistoryConfiguration): Uint8Array {
  for (const bytes of [configuration.groupId, configuration.genesisDigest, configuration.executionManifestDigest, configuration.proposerPublicKey]) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('HISTORY_CONFIGURATION_INVALID')
  }
  assertHistoryId(configuration.historyId)
  const validators = configuration.validatorPublicKeys
  if (!Array.isArray(validators) || validators.length < 1 || validators.length > 64) throw new Error('HISTORY_VALIDATORS_INVALID')
  let previous = ''
  for (const key of validators) {
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('HISTORY_VALIDATORS_INVALID')
    const encoded = bytesToHex(key)
    if (encoded <= previous) throw new Error('HISTORY_VALIDATORS_INVALID')
    previous = encoded
  }
  if (!validators.some(key => equalBytes(key, configuration.proposerPublicKey))) throw new Error('HISTORY_PROPOSER_NOT_VALIDATOR')
  return encodeCanonicalCbor([1n, 'chronolog/sealed-history', configuration.groupId, configuration.genesisDigest,
    configuration.executionManifestDigest, configuration.historyId, configuration.proposerPublicKey, validators])
}
export async function historyConfigurationDigest(configuration: HistoryConfiguration): Promise<Uint8Array> {
  return sha256(encodeHistoryConfiguration(configuration))
}
export async function orderedRecordId(bytes: Uint8Array): Promise<string> { return bytesToHex(await sha256(bytes)) }
export async function orderedGenesisRoot(historyId: string): Promise<string> {
  assertHistoryId(historyId)
  return orderedRecordId(utf8(JSON.stringify([LOG_DOMAIN, 'genesis', historyId])))
}
export async function orderedEntryRoot(entry: Omit<OrderedRecordEntry, 'root' | 'bytes'>): Promise<string> {
  assertHistoryId(entry.historyId); assertPosition(entry.position, false); assertHash(entry.previousRoot); assertHash(entry.recordId)
  return orderedRecordId(utf8(JSON.stringify([LOG_DOMAIN, 'entry', entry.historyId, entry.position, entry.previousRoot, entry.recordId])))
}
export async function verifyOrderedEntry(entry: OrderedRecordEntry): Promise<void> {
  if (!(entry.bytes instanceof Uint8Array)) throw new Error('ORDERED_RECORD_BYTES_INVALID')
  if (entry.bytes.byteLength > 1_048_576) throw new Error('ORDERED_RECORD_TOO_LARGE')
  assertHash(entry.root)
  if (await orderedRecordId(entry.bytes) !== entry.recordId) throw new Error('ORDERED_RECORD_DIGEST_MISMATCH')
  if (await orderedEntryRoot(entry) !== entry.root) throw new Error('ORDERED_RECORD_ROOT_MISMATCH')
}

export function encodeFinalityEvidence(evidence: FinalityEvidence): Uint8Array {
  if (evidence.kind === 'record') {
    const e = evidence.entry
    return encodeCanonicalCbor([1n, 'record', e.historyId, BigInt(e.position), e.recordId, e.previousRoot, e.root, e.bytes])
  }
  return encodeCanonicalCbor([1n, 'batch', encodeSignedFinalityBatch(evidence.batch)])
}
export function decodeFinalityEvidence(bytes: Uint8Array): FinalityEvidence {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value[0] !== 1n) throw new Error('FINALITY_EVIDENCE_INVALID')
  if (value[1] === 'record' && value.length === 8 && typeof value[2] === 'string' && typeof value[3] === 'bigint' &&
      typeof value[4] === 'string' && typeof value[5] === 'string' && typeof value[6] === 'string' && value[7] instanceof Uint8Array) {
    const position = Number(value[3]); assertPosition(position, false)
    if (BigInt(position) !== value[3]) throw new Error('FINALITY_EVIDENCE_INVALID')
    return { kind: 'record', entry: { historyId: value[2], position, recordId: value[4], previousRoot: value[5], root: value[6], bytes: value[7] } }
  }
  if (value[1] === 'batch' && value.length === 3 && value[2] instanceof Uint8Array) {
    return { kind: 'batch', batch: decodeSignedFinalityBatch(value[2]) }
  }
  throw new Error('FINALITY_EVIDENCE_INVALID')
}

/** Untrusted descriptor alternatives become canonical only through a complete signed batch chain. */
export class SealedBatchFinalityProvider implements FinalityProvider {
  readonly #configuration: HistoryConfiguration
  readonly #store: DurableOperationStore
  readonly #key: string
  readonly #quotaBytes: number
  readonly #mutex = new Mutex()
  #entries = new Map<number, Map<string, OrderedRecordEntry>>()
  #selectedEntries = new Map<number, OrderedRecordEntry>()
  #batches = new Map<number, SignedFinalityBatch>()
  #progress: FinalityProgress
  #finality: SealedBatchSnapshot
  #uncertain = false

  private constructor(configuration: HistoryConfiguration, store: DurableOperationStore, snapshot: SealedBatchSnapshot, quotaBytes: number) {
    this.#configuration = structuredClone(configuration); this.#store = store
    this.#key = `history/${bytesToHex(configuration.groupId)}/sealed-batches`
    this.#quotaBytes = quotaBytes; this.#finality = snapshot
    this.#progress = { receivedThrough: 0, verifiedThrough: 0, certifiedThrough: 0, finalizedThrough: 0, batchNumber: 0, root: '', missing: [] }
  }
  static async open(configuration: HistoryConfiguration, store: DurableOperationStore,
    options: { readonly quotaBytes?: number } = {}): Promise<SealedBatchFinalityProvider> {
    configuration = structuredClone(configuration); encodeHistoryConfiguration(configuration)
    const quotaBytes = options.quotaBytes ?? DEFAULT_EVIDENCE_QUOTA_BYTES
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1024 || quotaBytes > MAX_LOCAL_HISTORY_BYTES) throw new Error('HISTORY_STORAGE_QUOTA_INVALID')
    const policy = new SealedBatchFinalityProvider(configuration, store, await evaluateFinalitySnapshot(configuration, []), quotaBytes)
    policy.#progress = { ...policy.#progress, root: await orderedGenesisRoot(configuration.historyId) }
    const saved = await store.get(policy.#key)
    if (saved !== null) {
      if (saved.length > quotaBytes) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      const decoded = decodeRetainedHistory(saved, quotaBytes, MAX_RETAINED_EVIDENCE + 8)
      if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== 1n || !(decoded[1] instanceof Uint8Array) ||
          !equalBytes(decoded[1], encodeHistoryConfiguration(configuration)) || !Array.isArray(decoded[2])) throw new Error('HISTORY_STORED_CONFIGURATION_MISMATCH')
      for (const bytes of decoded[2]) {
        if (!(bytes instanceof Uint8Array)) throw new Error('HISTORY_STORED_EVIDENCE_INVALID')
        await policy.#validateAndInsert(decodeFinalityEvidence(bytes), policy.#entries, policy.#batches)
      }
      const state = await policy.#evaluate(policy.#entries, policy.#batches)
      policy.#progress = state.progress; policy.#selectedEntries = state.selected; policy.#finality = state.snapshot
      for (const [position, entry] of state.selected) policy.#entries.set(position, new Map([[entry.root, entry]]))
    }
    return policy
  }
  get configuration(): HistoryConfiguration { return structuredClone(this.#configuration) }
  get progress(): FinalityProgress { return structuredClone(this.#progress) }
  snapshot(): SealedBatchSnapshot { return structuredClone(this.#finality) }
  evidenceBytes(): readonly Uint8Array[] { return this.evidence().map(encodeFinalityEvidence) }
  evidence(): readonly FinalityEvidence[] {
    return [...allEntries(this.#entries).sort((a,b) => a.position-b.position || a.root.localeCompare(b.root))
      .map((entry): FinalityEvidence => ({ kind: 'record', entry: structuredClone(entry) })),
    ...[...this.#batches.values()].sort((a,b) => a.number-b.number).map((batch): FinalityEvidence => ({ kind: 'batch', batch: structuredClone(batch) }))]
  }
  entries(through = this.#progress.verifiedThrough): readonly OrderedRecordEntry[] {
    assertPosition(through, true)
    if (through > this.#progress.verifiedThrough) throw new Error('HISTORY_PREFIX_INCOMPLETE')
    return Array.from({ length: through }, (_, index) => structuredClone(this.#selectedEntries.get(index + 1)!))
  }
  certificates(): readonly SignedFinalityBatch[] { return structuredClone([...this.#batches.values()].sort((a,b) => a.number-b.number)) }
  ingestEvidence(bytes: Uint8Array): Promise<FinalityProgress> { return this.ingest(decodeFinalityEvidence(bytes.slice())) }
  ingest(evidence: FinalityEvidence): Promise<FinalityProgress> { return this.ingestBatch([evidence]) }
  async ingestBatch(evidence: readonly FinalityEvidence[]): Promise<FinalityProgress> {
    if (!Array.isArray(evidence) || evidence.length > 129) throw new Error('HISTORY_EVIDENCE_BATCH_INVALID')
    const captured = structuredClone(evidence)
    return this.#mutex.run(async () => {
      if (this.#uncertain) throw new Error('FINALITY_STORAGE_RECOVERY_REQUIRED')
      const entries = new Map([...this.#entries].map(([position, alternatives]) => [position, new Map(alternatives)]))
      const batches = new Map(this.#batches)
      let changed = false
      for (const item of captured) changed = await this.#validateAndInsert(item, entries, batches) || changed
      if (!changed) return this.progress
      const state = await this.#evaluate(entries, batches)
      if (state.progress.finalizedThrough < this.#progress.finalizedThrough) throw new Error('HISTORY_FINAL_PREFIX_REGRESSION')
      for (const [position, entry] of state.selected) entries.set(position, new Map([[entry.root, entry]]))
      const all: FinalityEvidence[] = [...allEntries(entries).map((entry): FinalityEvidence => ({ kind: 'record', entry })),
        ...[...batches.values()].map((batch): FinalityEvidence => ({ kind: 'batch', batch }))]
      if (all.length > MAX_RETAINED_EVIDENCE) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      const persisted = encodeCanonicalCbor([1n, encodeHistoryConfiguration(this.#configuration), all.map(encodeFinalityEvidence)])
      if (persisted.length > this.#quotaBytes) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      try { await this.#store.put(this.#key, persisted) } catch (error) { this.#uncertain = true; throw error }
      this.#entries = entries; this.#batches = batches; this.#selectedEntries = state.selected; this.#progress = state.progress; this.#finality = state.snapshot
      return this.progress
    })
  }
  async #validateAndInsert(evidence: FinalityEvidence, entries: Map<number, Map<string, OrderedRecordEntry>>,
    batches: Map<number, SignedFinalityBatch>): Promise<boolean> {
    if (evidence.kind === 'record') {
      const entry = evidence.entry
      if (entry.historyId !== this.#configuration.historyId) throw new Error('HISTORY_ID_MISMATCH')
      await verifyOrderedEntry(entry)
      const final = this.#selectedEntries.get(entry.position)
      if (final !== undefined && final.root !== entry.root) throw new Error('HISTORY_POSITION_CONFLICT')
      const alternatives = entries.get(entry.position) ?? new Map<string, OrderedRecordEntry>()
      const previous = alternatives.get(entry.root)
      if (previous !== undefined && !equalBytes(previous.bytes, entry.bytes)) throw new Error('HISTORY_RECORD_HASH_COLLISION')
      alternatives.set(entry.root, entry); entries.set(entry.position, alternatives)
      return previous === undefined
    }
    await verifyFinalityBatch(evidence.batch, this.#configuration)
    const previous = batches.get(evidence.batch.number)
    if (previous !== undefined && await finalityBatchId(previous) !== await finalityBatchId(evidence.batch)) throw new Error('FINALITY_EQUIVOCATION')
    batches.set(evidence.batch.number, evidence.batch)
    return previous === undefined
  }
  async #evaluate(entries: Map<number, Map<string, OrderedRecordEntry>>, batches: Map<number, SignedFinalityBatch>) {
    const selected = new Map<number, OrderedRecordEntry>(), complete: SignedFinalityBatch[] = [], missing = new Set<number>()
    let through = 0, root = await orderedGenesisRoot(this.#configuration.historyId), parentId = await finalityGenesisId(this.#configuration)
    for (let number = 1; ; number++) {
      const batch = batches.get(number)
      if (!batch) break
      if (batch.parentId !== parentId || batch.includedHead.position <= through) throw new Error('FINALITY_BATCH_PARENT_MISMATCH')
      let position = batch.includedHead.position, cursorRoot = batch.includedHead.root
      const path = new Map<number, OrderedRecordEntry>()
      while (position > through) {
        const entry = entries.get(position)?.get(cursorRoot)
        if (!entry) { missing.add(position); break }
        path.set(position, entry); cursorRoot = entry.previousRoot; position--
      }
      if (position !== through) break
      if (cursorRoot !== root) throw new Error('FINALITY_EQUIVOCATION')
      for (const [position, entry] of path) selected.set(position, entry)
      complete.push(batch); through = batch.includedHead.position; root = batch.includedHead.root; parentId = await finalityBatchId(batch)
    }
    const receivedThrough = maximumPosition(entries.keys())
    const certifiedThrough = maximumPosition([...batches.values()].map(batch => batch.includedHead.position))
    const snapshot = await evaluateFinalitySnapshot(this.#configuration,
      [...selected.values()].sort((a,b) => a.position-b.position), complete, receivedThrough)
    return { selected, snapshot, progress: { receivedThrough, verifiedThrough: through, certifiedThrough, finalizedThrough: through,
      batchNumber: complete.length, root, missing: [...missing].sort((a,b) => a-b).slice(0,1024) } }
  }
}
function allEntries(entries: ReadonlyMap<number, ReadonlyMap<string, OrderedRecordEntry>>): OrderedRecordEntry[] {
  return [...entries.values()].flatMap(alternatives => [...alternatives.values()])
}
function maximumPosition(values: Iterable<number>): number { let maximum = 0; for (const value of values) if (value > maximum) maximum = value; return maximum }

const referenceLogLocks = new WeakMap<DurableOperationStore, Map<string, Mutex>>()
function referenceLogLock(store: DurableOperationStore, historyId: string): Mutex {
  let locks = referenceLogLocks.get(store)
  if (locks === undefined) { locks = new Map(); referenceLogLocks.set(store, locks) }
  let mutex = locks.get(historyId)
  if (mutex === undefined) { mutex = new Mutex(); locks.set(historyId, mutex) }
  return mutex
}

/** A reference durable log uses one atomic value in the replica's storage port. */
export class ReferenceRecordLog {
  readonly #mutex: Mutex
  private constructor(readonly historyId: string, readonly store: DurableOperationStore, readonly quotaBytes: number) {
    this.#mutex = referenceLogLock(store, historyId)
  }

  static async open(historyId: string, store: DurableOperationStore, options: {
    readonly quotaBytes?: number
    /** Reopening an established authority must not recreate a missing log. */
    readonly requireExisting?: boolean
  } = {}): Promise<ReferenceRecordLog> {
    assertHistoryId(historyId)
    const quotaBytes = options.quotaBytes ?? 64 * 1024 * 1024
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1 || quotaBytes > MAX_LOCAL_HISTORY_BYTES - MAX_RETAINED_HISTORY_ENTRIES * 512) {
      throw new Error('RECORD_LOG_QUOTA_INVALID')
    }
    const log = new ReferenceRecordLog(historyId, store, quotaBytes)
    return log.#mutex.run(async () => {
      if (await store.get(`record-log/${historyId}`) === null) {
        if (options.requireExisting === true) throw new Error('RECORD_LOG_MISSING')
        // Establish a durable empty history before another component records
        // successful setup. A later missing file is loss, not an empty prefix.
        await store.put(`record-log/${historyId}`, encodeCanonicalCbor([]))
      }
      await log.read()
      return log
    })
  }

  async read(): Promise<readonly OrderedRecordEntry[]> {
    const bytes = await this.store.get(`record-log/${this.historyId}`)
    if (bytes === null) throw new Error('RECORD_LOG_MISSING')
    // The public log quota counts proposal bytes. Reserve a fixed bounded
    // allowance for the hash-chain/index encoding instead of using wire limits
    // that can make an already committed >16 MiB history impossible to reopen.
    const storedLimit = this.quotaBytes + MAX_RETAINED_HISTORY_ENTRIES * 512
    if (bytes.length > storedLimit) throw new Error('RECORD_LOG_QUOTA_EXCEEDED')
    const decoded = decodeRetainedHistory(bytes, storedLimit, MAX_RETAINED_HISTORY_ENTRIES)
    if (!Array.isArray(decoded)) throw new Error('RECORD_LOG_STORAGE_INVALID')
    const entries: OrderedRecordEntry[] = []
    let root = await orderedGenesisRoot(this.historyId)
    for (const encoded of decoded) {
      if (!(encoded instanceof Uint8Array)) throw new Error('RECORD_LOG_STORAGE_INVALID')
      const evidence = decodeFinalityEvidence(encoded)
      if (evidence.kind !== 'record') throw new Error('RECORD_LOG_STORAGE_INVALID')
      const entry = evidence.entry
      await verifyOrderedEntry(entry)
      if (entry.historyId !== this.historyId || entry.position !== entries.length + 1 || entry.previousRoot !== root) {
        throw new Error('RECORD_LOG_STORAGE_CONFLICT')
      }
      entries.push(entry); root = entry.root
    }
    return entries
  }

  async head(): Promise<OrderedRecordHead> {
    const entries = await this.read()
    return { historyId: this.historyId, position: entries.length, root: entries.at(-1)?.root ?? await orderedGenesisRoot(this.historyId) }
  }

  async append(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const exact = bytes.slice()
    return this.#mutex.run(async () => {
      const entries = await this.read()
      const recordId = await orderedRecordId(exact)
      const previous = entries.find((entry) => entry.recordId === recordId)
      if (previous !== undefined) return structuredClone(previous)
      if (entries.length >= MAX_RETAINED_HISTORY_ENTRIES ||
          entries.reduce((size, entry) => size + entry.bytes.byteLength, 0) + exact.byteLength > this.quotaBytes) {
        throw new Error('RECORD_LOG_QUOTA_EXCEEDED')
      }
      const fields = { historyId: this.historyId, position: entries.length + 1, recordId, previousRoot: entries.at(-1)?.root ?? await orderedGenesisRoot(this.historyId) }
      const entry = { ...fields, root: await orderedEntryRoot(fields), bytes: exact }
      await verifyOrderedEntry(entry)
      await this.store.put(`record-log/${this.historyId}`, encodeCanonicalCbor([
        ...entries, entry,
      ].map((item) => encodeFinalityEvidence({ kind: 'record', entry: item }))))
      return structuredClone(entry)
    })
  }
}

function decodeRetainedHistory(bytes: Uint8Array, maxBytes: number, maxItems: number) {
  return assertCanonicalCbor(bytes, { maxBytes, maxItems, maxDepth: 4,
    maxTextBytes: 1024, maxByteStringBytes: 1_048_576 + 2048 })
}

function assertHistoryId(value: string): void {
  if (!/^h_[0-9a-f]{32}$/u.test(value)) throw new Error('HISTORY_ID_INVALID')
}
function assertHash(value: string): void {
  if (!/^[0-9a-f]{64}$/u.test(value)) throw new Error('HISTORY_HASH_INVALID')
}
function assertPosition(value: number, zero: boolean): void {
  if (!Number.isSafeInteger(value) || value < (zero ? 0 : 1)) throw new Error('HISTORY_POSITION_INVALID')
}

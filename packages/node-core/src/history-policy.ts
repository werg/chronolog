import { bytesToHex, sha256 } from '@chronolog/canonical'
import {
  assertCanonicalCbor, encodeCanonicalCbor, equalBytes, utf8,
  type Ed25519KeyPair,
} from '@chronolog/protocol'

import { Mutex } from './async.js'
import { evaluateFinalitySnapshot, type FinalityProvider, type FinalitySnapshot } from './finality.js'
import type { DurableOperationStore } from './operations.js'

/** Immutable group/provider binding. Execution always uses chronological order. */
export type HistoryConfiguration = {
  readonly groupId: Uint8Array
  readonly genesisDigest: Uint8Array
  readonly executionManifestDigest: Uint8Array
  readonly providerId?: string
  /** Opaque bounded parameters authenticated with the selected provider. */
  readonly providerParameters?: Uint8Array
} & ({ readonly kind: 'peer' } | {
  readonly kind: 'coordinated'
  readonly historyId: string
  readonly authorityPublicKey: Uint8Array
})

export type CoordinatedHistoryConfiguration = Extract<HistoryConfiguration, { kind: 'coordinated' }>

export interface OrderedRecordEntry {
  readonly historyId: string
  /** Inclusion receipt position, never an application execution position. */
  readonly position: number
  readonly recordId: string
  readonly previousRoot: string
  readonly root: string
  readonly bytes: Uint8Array
}

export interface OrderedRecordHead {
  readonly historyId: string
  readonly position: number
  readonly root: string
}

export interface PrefixCertificate extends OrderedRecordHead {
  readonly configuration: Uint8Array
  readonly signature: Uint8Array
}

export type OrderingEvidence =
  | { readonly kind: 'ordered-entry'; readonly entry: OrderedRecordEntry }
  | { readonly kind: 'prefix-certificate'; readonly certificate: PrefixCertificate }

export interface CoordinatedProgress {
  readonly receivedThrough: number
  readonly verifiedThrough: number
  readonly certifiedThrough: number
  /** Complete certified receipt prefix; application finality also needs a closure. */
  readonly finalThrough: number
  readonly root: string
  readonly missing: readonly number[]
}

const LOG_DOMAIN = 'record-log/v1'
const CERTIFICATE_DOMAIN = 'chronolog/prefix-certificate/v1\0'
/** Local retained-state bounds are independent from the smaller wire decoder. */
export const MAX_RETAINED_HISTORY_ENTRIES = 65_536
const MAX_RETAINED_EVIDENCE = MAX_RETAINED_HISTORY_ENTRIES * 2
const DEFAULT_EVIDENCE_QUOTA_BYTES = 128 * 1024 * 1024
const MAX_LOCAL_HISTORY_BYTES = 512 * 1024 * 1024

export interface CoordinatedHistoryStorageOptions {
  readonly quotaBytes?: number
}

export function encodeHistoryConfiguration(configuration: HistoryConfiguration): Uint8Array {
  for (const bytes of [configuration.groupId, configuration.genesisDigest, configuration.executionManifestDigest]) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new Error('HISTORY_CONFIGURATION_INVALID')
  }
  const providerId = configuration.providerId ?? (configuration.kind === 'peer' ? 'peer-validators-v1' : 'signed-inclusion-v1')
  if (!/^[a-z][a-z0-9._-]{0,127}$/u.test(providerId)) throw new Error('HISTORY_PROVIDER_ID_INVALID')
  const parameters = configuration.providerParameters ?? new Uint8Array()
  if (!(parameters instanceof Uint8Array) || parameters.length > 16_384) throw new Error('HISTORY_PROVIDER_PARAMETERS_INVALID')
  if (configuration.kind === 'peer') {
    return encodeCanonicalCbor([2n, 'peer', configuration.groupId, configuration.genesisDigest, configuration.executionManifestDigest, providerId, parameters])
  }
  assertHistoryId(configuration.historyId)
  if (configuration.authorityPublicKey.length !== 32) throw new Error('HISTORY_AUTHORITY_KEY_INVALID')
  return encodeCanonicalCbor([
    2n, 'coordinated', configuration.groupId, configuration.genesisDigest,
    configuration.executionManifestDigest, configuration.historyId, configuration.authorityPublicKey, providerId, parameters,
  ])
}

export async function historyConfigurationDigest(configuration: HistoryConfiguration): Promise<Uint8Array> {
  return sha256(encodeHistoryConfiguration(configuration))
}

export async function orderedRecordId(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes))
}

export async function orderedGenesisRoot(historyId: string): Promise<string> {
  assertHistoryId(historyId)
  return orderedRecordId(utf8(JSON.stringify([LOG_DOMAIN, 'genesis', historyId])))
}

export async function orderedEntryRoot(entry: Omit<OrderedRecordEntry, 'root' | 'bytes'>): Promise<string> {
  assertHistoryId(entry.historyId)
  assertPosition(entry.position, false)
  assertHash(entry.previousRoot)
  assertHash(entry.recordId)
  return orderedRecordId(utf8(JSON.stringify([
    LOG_DOMAIN, 'entry', entry.historyId, entry.position, entry.previousRoot, entry.recordId,
  ])))
}

export async function verifyOrderedEntry(entry: OrderedRecordEntry): Promise<void> {
  if (!(entry.bytes instanceof Uint8Array)) throw new Error('ORDERED_RECORD_BYTES_INVALID')
  if (entry.bytes.byteLength > 1_048_576) throw new Error('ORDERED_RECORD_TOO_LARGE')
  assertHash(entry.root)
  if (await orderedRecordId(entry.bytes) !== entry.recordId) throw new Error('ORDERED_RECORD_DIGEST_MISMATCH')
  if (await orderedEntryRoot(entry) !== entry.root) throw new Error('ORDERED_RECORD_ROOT_MISMATCH')
}

function certificatePayload(certificate: Omit<PrefixCertificate, 'signature'>): Uint8Array {
  assertHistoryId(certificate.historyId)
  assertPosition(certificate.position, true)
  assertHash(certificate.root)
  return encodeCanonicalCbor([
    CERTIFICATE_DOMAIN, certificate.configuration, certificate.historyId,
    BigInt(certificate.position), certificate.root,
  ])
}

/** Reads its own committed head. Caller-supplied roots are never signing inputs. */
export function createPrefixAuthority(options: {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly identity: Ed25519KeyPair
  readonly readHead: () => Promise<OrderedRecordHead>
}): { certify(): Promise<PrefixCertificate> } {
  const configuration = encodeHistoryConfiguration(options.configuration)
  if (!equalBytes(options.identity.publicKeyBytes, options.configuration.authorityPublicKey)) {
    throw new Error('HISTORY_AUTHORITY_KEY_MISMATCH')
  }
  const historyId = options.configuration.historyId
  return {
    async certify() {
      const head = await options.readHead()
      if (head.historyId !== historyId) throw new Error('HISTORY_ID_MISMATCH')
      const unsigned = { ...head, configuration: configuration.slice() }
      const signature = new Uint8Array(await crypto.subtle.sign(
        'Ed25519', options.identity.privateKey, certificatePayload(unsigned).slice().buffer,
      ))
      return { ...unsigned, signature }
    },
  }
}

export async function verifyPrefixCertificate(
  certificate: PrefixCertificate,
  configuration: CoordinatedHistoryConfiguration,
): Promise<void> {
  if (certificate.historyId !== configuration.historyId ||
      !equalBytes(certificate.configuration, encodeHistoryConfiguration(configuration))) {
    throw new Error('HISTORY_CERTIFICATE_CONFIGURATION_MISMATCH')
  }
  if (certificate.signature.length !== 64) throw new Error('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
  const key = await crypto.subtle.importKey('raw', configuration.authorityPublicKey.slice().buffer, 'Ed25519', false, ['verify'])
  if (!await crypto.subtle.verify('Ed25519', key, certificate.signature.slice().buffer, certificatePayload(certificate).slice().buffer)) {
    throw new Error('HISTORY_CERTIFICATE_SIGNATURE_INVALID')
  }
}

/** Evidence is immutable data; it is independent of a relay's author/feed. */
export function encodeOrderingEvidence(evidence: OrderingEvidence): Uint8Array {
  if (evidence.kind === 'ordered-entry') {
    const e = evidence.entry
    return encodeCanonicalCbor([1n, 'ordered-entry', e.historyId, BigInt(e.position), e.recordId, e.previousRoot, e.root, e.bytes])
  }
  const c = evidence.certificate
  return encodeCanonicalCbor([1n, 'prefix-certificate', c.configuration, c.historyId, BigInt(c.position), c.root, c.signature])
}

export function decodeOrderingEvidence(bytes: Uint8Array): OrderingEvidence {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value[0] !== 1n) throw new Error('ORDERING_EVIDENCE_INVALID')
  if (value[1] === 'ordered-entry' && value.length === 8 && typeof value[2] === 'string' &&
      typeof value[3] === 'bigint' && typeof value[4] === 'string' && typeof value[5] === 'string' &&
      typeof value[6] === 'string' && value[7] instanceof Uint8Array) {
    const position = Number(value[3]); assertPosition(position, false)
    if (BigInt(position) !== value[3]) throw new Error('ORDERING_EVIDENCE_INVALID')
    return { kind: 'ordered-entry', entry: {
      historyId: value[2], position, recordId: value[4], previousRoot: value[5], root: value[6], bytes: value[7],
    } }
  }
  if (value[1] === 'prefix-certificate' && value.length === 7 && value[2] instanceof Uint8Array &&
      typeof value[3] === 'string' && typeof value[4] === 'bigint' && typeof value[5] === 'string' &&
      value[6] instanceof Uint8Array) {
    const position = Number(value[4]); assertPosition(position, true)
    if (BigInt(position) !== value[4]) throw new Error('ORDERING_EVIDENCE_INVALID')
    return { kind: 'prefix-certificate', certificate: {
      configuration: value[2], historyId: value[3], position, root: value[5], signature: value[6],
    } }
  }
  throw new Error('ORDERING_EVIDENCE_INVALID')
}

/**
 * Shared durable control storage retains the exact entry mapping and portable
 * certificates. Receipt order enumerates inclusion evidence only. Application
 * finality additionally requires the independently signed closure markers.
 */
export class CoordinatedHistoryPolicy implements FinalityProvider {
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #store: DurableOperationStore
  readonly #key: string
  readonly #quotaBytes: number
  readonly #mutex = new Mutex()
  // Entry roots authenticate bytes, not the authority's choice of position.
  // Retain competing untrusted alternatives until a certificate selects one.
  #entries = new Map<number, Map<string, OrderedRecordEntry>>()
  #selectedEntries = new Map<number, OrderedRecordEntry>()
  #certificates = new Map<number, PrefixCertificate>()
  #progress: CoordinatedProgress
  #finality: FinalitySnapshot

  private constructor(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore, root: string, quotaBytes: number) {
    this.#configuration = structuredClone(configuration)
    this.#store = store
    this.#key = `history/${bytesToHex(configuration.groupId)}/coordinated`
    this.#quotaBytes = quotaBytes
    this.#progress = { receivedThrough: 0, verifiedThrough: 0, certifiedThrough: 0, finalThrough: 0, root, missing: [] }
    this.#finality = { checkpointId: root, receivedThrough: 0, includedThrough: 0,
      closedReceiptThrough: 0, closedThroughMs: -1n, records: [], closures: [] }
  }

  static async open(configuration: CoordinatedHistoryConfiguration, store: DurableOperationStore,
    options: CoordinatedHistoryStorageOptions = {}): Promise<CoordinatedHistoryPolicy> {
    encodeHistoryConfiguration(configuration)
    const quotaBytes = options.quotaBytes ?? DEFAULT_EVIDENCE_QUOTA_BYTES
    if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 1024 || quotaBytes > MAX_LOCAL_HISTORY_BYTES) throw new Error('HISTORY_STORAGE_QUOTA_INVALID')
    const policy = new CoordinatedHistoryPolicy(configuration, store, await orderedGenesisRoot(configuration.historyId), quotaBytes)
    const saved = await store.get(policy.#key)
    if (saved !== null) {
      if (saved.length > quotaBytes) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      const decoded = decodeRetainedHistory(saved, quotaBytes, MAX_RETAINED_EVIDENCE)
      if (!Array.isArray(decoded) || decoded.length !== 3 || decoded[0] !== 1n ||
          !(decoded[1] instanceof Uint8Array) || !equalBytes(decoded[1], encodeHistoryConfiguration(configuration)) ||
          !Array.isArray(decoded[2])) throw new Error('HISTORY_STORED_CONFIGURATION_MISMATCH')
      for (const bytes of decoded[2]) {
        if (!(bytes instanceof Uint8Array)) throw new Error('HISTORY_STORED_EVIDENCE_INVALID')
        await policy.#validateAndInsert(decodeOrderingEvidence(bytes), policy.#entries, policy.#certificates)
      }
      const evaluated = await policy.#evaluate(policy.#entries, policy.#certificates)
      policy.#progress = evaluated.progress
      policy.#selectedEntries = evaluated.selectedEntries
      policy.#finality = evaluated.finality
      discardUncommittedAlternatives(policy.#entries, evaluated.selectedEntries)
    }
    return policy
  }

  get progress(): CoordinatedProgress { return structuredClone(this.#progress) }
  get configuration(): CoordinatedHistoryConfiguration { return structuredClone(this.#configuration) }
  get closedThroughMs(): bigint { return this.#finality.closedThroughMs }
  get closedReceiptThrough(): number { return this.#finality.closedReceiptThrough }

  snapshot(): FinalitySnapshot { return structuredClone(this.#finality) }

  async ingestEvidence(bytes: Uint8Array): Promise<CoordinatedProgress> {
    let evidence: OrderingEvidence
    try { evidence = decodeOrderingEvidence(bytes.slice()) }
    catch { throw new Error('ORDERING_EVIDENCE_INVALID') }
    return this.ingest(evidence)
  }

  evidenceBytes(): readonly Uint8Array[] { return this.evidence().map(encodeOrderingEvidence) }

  boundaryForEntry(position: number): bigint | null {
    return this.#finality.records.find(record => record.entry.position === position)?.closureBoundary?.closedThroughMs ?? null
  }

  admissionFloor(position: number): bigint {
    const record = this.#finality.records.find(record => record.entry.position === position)
    if (record === undefined) throw new Error('FINALITY_RECORD_NOT_INCLUDED')
    return record.admissionFloorMs
  }

  isClosure(position: number): boolean { return this.#finality.closures.some(closure => closure.position === position) }

  entries(through = this.#progress.verifiedThrough): readonly OrderedRecordEntry[] {
    assertPosition(through, true)
    if (through > this.#progress.verifiedThrough) throw new Error('HISTORY_PREFIX_INCOMPLETE')
    return Array.from({ length: through }, (_, i) => structuredClone(this.#selectedEntries.get(i + 1)!))
  }

  evidence(): readonly OrderingEvidence[] {
    return [
      ...allEntries(this.#entries).sort((a, b) => a.position - b.position || a.root.localeCompare(b.root)).map((entry): OrderingEvidence => ({ kind: 'ordered-entry', entry: structuredClone(entry) })),
      ...[...this.#certificates.values()].sort((a, b) => a.position - b.position).map((certificate): OrderingEvidence => ({ kind: 'prefix-certificate', certificate: structuredClone(certificate) })),
    ]
  }

  async ingest(evidence: OrderingEvidence): Promise<CoordinatedProgress> {
    return this.ingestBatch([evidence])
  }

  /** Atomically retain one bounded page (up to 128 entries plus its certificate). */
  async ingestBatch(evidence: readonly OrderingEvidence[]): Promise<CoordinatedProgress> {
    if (!Array.isArray(evidence) || evidence.length > 129) throw new Error('HISTORY_EVIDENCE_BATCH_INVALID')
    const captured: readonly OrderingEvidence[] = structuredClone(evidence)
    return this.#mutex.run(async () => {
      const entries = new Map([...this.#entries].map(([position, alternatives]) => [position, new Map(alternatives)]))
      const certificates = new Map(this.#certificates)
      let changed = false
      for (const item of captured) {
        const inserted = await this.#validateAndInsert(item, entries, certificates)
        changed ||= inserted
      }
      // Exact retries still pass hash/signature/configuration validation, but
      // do not rewrite retained history or turn a read into a storage write.
      if (!changed) return this.progress
      const { progress, selectedEntries, finality } = await this.#evaluate(entries, certificates)
      if (progress.finalThrough < this.#progress.finalThrough) throw new Error('HISTORY_FINAL_PREFIX_REGRESSION')
      discardUncommittedAlternatives(entries, selectedEntries)
      const all: OrderingEvidence[] = [
        ...allEntries(entries).map((entry): OrderingEvidence => ({ kind: 'ordered-entry', entry })),
        ...[...certificates.values()].map((certificate): OrderingEvidence => ({ kind: 'prefix-certificate', certificate })),
      ]
      if (all.length > MAX_RETAINED_EVIDENCE) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      const persisted = encodeCanonicalCbor([
        1n, encodeHistoryConfiguration(this.#configuration), all.map(encodeOrderingEvidence),
      ])
      if (persisted.length > this.#quotaBytes) throw new Error('HISTORY_STORAGE_QUOTA_EXCEEDED')
      await this.#store.put(this.#key, persisted)
      this.#entries = entries
      this.#certificates = certificates
      this.#selectedEntries = selectedEntries
      this.#progress = progress
      this.#finality = finality
      return this.progress
    })
  }

  async #validateAndInsert(evidence: OrderingEvidence, entries: Map<number, Map<string, OrderedRecordEntry>>, certificates: Map<number, PrefixCertificate>): Promise<boolean> {
    if (evidence.kind === 'ordered-entry') {
      const entry = evidence.entry
      if (entry.historyId !== this.#configuration.historyId) throw new Error('HISTORY_ID_MISMATCH')
      await verifyOrderedEntry(entry)
      const final = this.#selectedEntries.get(entry.position)
      if (final !== undefined && final.root !== entry.root) {
        // A conflicting unauthenticated entry cannot replace a final entry.
        // Only contradictory signed certificates are authority equivocation.
        throw new Error('HISTORY_POSITION_CONFLICT')
      }
      const alternatives = entries.get(entry.position) ?? new Map<string, OrderedRecordEntry>()
      const previous = alternatives.get(entry.root)
      if (previous !== undefined && !equalBytes(previous.bytes, entry.bytes)) throw new Error('HISTORY_RECORD_HASH_COLLISION')
      alternatives.set(entry.root, entry)
      entries.set(entry.position, alternatives)
      return previous === undefined
    } else {
      const certificate = evidence.certificate
      await verifyPrefixCertificate(certificate, this.#configuration)
      const previous = certificates.get(certificate.position)
      if (previous !== undefined && previous.root !== certificate.root) throw new Error('HISTORY_AUTHORITY_EQUIVOCATION')
      certificates.set(certificate.position, certificate)
      return previous === undefined
    }
  }

  async #evaluate(entries: Map<number, Map<string, OrderedRecordEntry>>, certificates: Map<number, PrefixCertificate>): Promise<{
    readonly progress: CoordinatedProgress
    readonly selectedEntries: Map<number, OrderedRecordEntry>
    readonly finality: FinalitySnapshot
  }> {
    const genesisRoot = await orderedGenesisRoot(this.#configuration.historyId)
    let finalThrough = 0
    let finalRoot = genesisRoot
    const selectedEntries = new Map<number, OrderedRecordEntry>()
    const missing = new Set<number>()
    const genesisCertificate = certificates.get(0)
    if (genesisCertificate !== undefined && genesisCertificate.root !== genesisRoot) throw new Error('HISTORY_CERTIFICATE_ROOT_MISMATCH')
    for (const certificate of [...certificates.values()].sort((a, b) => a.position - b.position)) {
      if (certificate.position === 0) continue
      let root = certificate.root
      let position = certificate.position
      const path = new Map<number, OrderedRecordEntry>()
      let complete = true
      // Work backwards from a signed commitment. A fabricated but internally
      // consistent entry received first can never select the canonical branch.
      while (position > finalThrough) {
        const covered = certificates.get(position)
        if (covered !== undefined && covered.root !== root) throw new Error('HISTORY_AUTHORITY_EQUIVOCATION')
        const entry = entries.get(position)?.get(root)
        if (entry === undefined) { missing.add(position); complete = false; break }
        path.set(position, entry)
        root = entry.previousRoot
        position -= 1
      }
      if (!complete) continue
      if (root !== finalRoot) throw new Error('HISTORY_AUTHORITY_EQUIVOCATION')
      for (const [index, entry] of path) selectedEntries.set(index, entry)
      finalThrough = certificate.position
      finalRoot = certificate.root
    }
    const receivedThrough = maximumPosition(entries.keys())
    const certifiedThrough = maximumPosition(certificates.keys())
    // This is a bounded diagnostic window. Wrong alternatives at a known gap
    // remain a gap, even though some bytes for that position were received.
    const windowEnd = Math.min(certifiedThrough, finalThrough + 1_024)
    for (let position = finalThrough + 1; position <= windowEnd; position += 1) {
      if (!entries.has(position)) missing.add(position)
    }
    const gaps = [...missing].filter((position) => position > finalThrough).sort((a, b) => a - b).slice(0, 1_024)
    const finality = finalThrough === this.#finality.includedThrough && finalRoot === this.#finality.checkpointId
      ? { ...this.#finality, receivedThrough }
      : await evaluateFinalitySnapshot(this.#configuration,
        [...selectedEntries.values()].sort((left, right) => left.position - right.position), receivedThrough)
    return {
      progress: {
        receivedThrough, verifiedThrough: finalThrough, certifiedThrough,
        finalThrough, root: finalRoot, missing: gaps,
      },
      selectedEntries,
      finality,
    }
  }
}

/** Preferred name: this provider certifies inclusion and closes author time. */
export { CoordinatedHistoryPolicy as SignedInclusionFinalityProvider }

function allEntries(entries: ReadonlyMap<number, ReadonlyMap<string, OrderedRecordEntry>>): OrderedRecordEntry[] {
  const result: OrderedRecordEntry[] = []
  for (const alternatives of entries.values()) {
    for (const entry of alternatives.values()) result.push(entry)
  }
  return result
}

function discardUncommittedAlternatives(entries: Map<number, Map<string, OrderedRecordEntry>>, selected: ReadonlyMap<number, OrderedRecordEntry>): void {
  for (const [position, entry] of selected) entries.set(position, new Map([[entry.root, entry]]))
}

function maximumPosition(values: Iterable<number>): number {
  let maximum = 0
  for (const value of values) if (value > maximum) maximum = value
  return maximum
}

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
      const evidence = decodeOrderingEvidence(encoded)
      if (evidence.kind !== 'ordered-entry') throw new Error('RECORD_LOG_STORAGE_INVALID')
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
      ].map((item) => encodeOrderingEvidence({ kind: 'ordered-entry', entry: item }))))
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

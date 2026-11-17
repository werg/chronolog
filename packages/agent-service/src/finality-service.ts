import {
  Mutex, ReferenceRecordLog, createPrefixAuthority, encodeHistoryConfiguration, encodeOrderingEvidence, orderedGenesisRoot,
  createFinalityClosureRecord, evaluateFinalitySnapshot, extendFinalityControlCommitment, createLedgerRecord, decodeLedgerRecord, verifyLedgerPayload,
  decodeOrderingEvidence, verifyPrefixCertificate, encodeFinalizedControl,
  verifyEnrollmentDescriptor, resolveFinalityClockPolicy,
  MAX_RETAINED_HISTORY_ENTRIES, orderedRecordId,
} from '@chronolog/node-core'
import type {
  CoordinatedHistoryConfiguration, DurableOperationStore, EnrollmentDescriptor, OrderedRecordEntry, OrderedRecordHead, PrefixCertificate,
  MembershipLedgerPage,
} from '@chronolog/node-core'
import { assertCanonicalCbor, decodeEnvelope, encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import { validatePayloadHash, verifyPayloadHash, type ChronologTransport } from '@chronolog/records'

export interface EvidenceSink { putEvidence(bytes: Uint8Array): Promise<unknown> }

export interface NativeFinalityServiceOptions {
  /** Signed genesis pins the signer, history, execution profile and clock policy. */
  readonly descriptor: EnrollmentDescriptor
  readonly identity: Ed25519KeyPair
  /** Must have one fenced storage owner, e.g. NativeAgentStore. */
  readonly store: DurableOperationStore
  /** Retained ledger descriptors and closure records. Defaults to 64 MiB. */
  readonly recordQuotaBytes?: number
  /** Detached application bodies, including unfinished durable reservations. Defaults to 64 MiB. */
  readonly payloadQuotaBytes?: number
  /** Provider clock; application execution order never uses receipt time. */
  readonly now?: () => number
  /**
   * An independently trusted continuity checkpoint when recovering a volume.
   * Reading this from the same restored backup cannot detect rollback. An
   * operator without established continuity must create a new history lineage.
   */
  readonly continuity?: OrderedRecordHead
}

interface AuthorityState { readonly mutex: Mutex; idleClosurePending: boolean }
const authorityStates = new WeakMap<DurableOperationStore, Map<string, AuthorityState>>()
function authorityState(store: DurableOperationStore, historyId: string): AuthorityState {
  let histories = authorityStates.get(store)
  if (histories === undefined) { histories = new Map(); authorityStates.set(store, histories) }
  let state = histories.get(historyId)
  if (state === undefined) { state = { mutex: new Mutex(), idleClosurePending: true }; histories.set(historyId, state) }
  return state
}

/** Certifies inclusion and closed author time; replicas always derive execution order. */
export class NativeFinalityService {
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #log: ReferenceRecordLog
  readonly #signer: ReturnType<typeof createPrefixAuthority>
  readonly #store: DurableOperationStore
  readonly #mutex: Mutex
  readonly #serviceState: AuthorityState
  readonly #identity: Ed25519KeyPair
  readonly #now: () => number
  readonly #cutoffLagMs: number
  readonly #futureAdmissionWindowMs: bigint
  readonly #closureIntervalMs: number
  readonly #payloadQuotaBytes: number

  private constructor(options: NativeFinalityServiceOptions, configuration: CoordinatedHistoryConfiguration, log: ReferenceRecordLog) {
    this.#configuration = structuredClone(configuration)
    this.#log = log
    this.#store = options.store
    this.#payloadQuotaBytes = payloadQuota(options.payloadQuotaBytes)
    this.#serviceState = authorityState(options.store, configuration.historyId)
    this.#mutex = this.#serviceState.mutex
    this.#identity = { ...options.identity, publicKeyBytes: new Uint8Array(options.identity.publicKeyBytes) }
    this.#now = options.now ?? Date.now
    const clock = resolveFinalityClockPolicy(options.descriptor.genesis.manifest.clockPolicy)
    this.#cutoffLagMs = clock.cutoffLagMs
    this.#closureIntervalMs = clock.heartbeatIntervalMs
    this.#futureAdmissionWindowMs = BigInt(clock.futureAdmissionWindowMs)
    this.#signer = createPrefixAuthority({ configuration: this.#configuration, identity: this.#identity, readHead: () => log.head() })
  }

  static async open(options: NativeFinalityServiceOptions): Promise<NativeFinalityService> {
    options = { ...options, descriptor: structuredClone(options.descriptor),
      identity: { ...options.identity, publicKeyBytes: new Uint8Array(options.identity.publicKeyBytes) },
      ...(options.continuity === undefined ? {} : { continuity: structuredClone(options.continuity) }) }
    await verifyEnrollmentDescriptor(options.descriptor)
    const history = options.descriptor.history
    if (history.kind !== 'coordinated' || (history.providerId ?? 'signed-inclusion-v2') !== 'signed-inclusion-v2') {
      throw new Error('FINALITY_SERVICE_PROVIDER_MISMATCH')
    }
    resolveFinalityClockPolicy(options.descriptor.genesis.manifest.clockPolicy)
    const payloadQuotaBytes = payloadQuota(options.payloadQuotaBytes)
    return authorityState(options.store, history.historyId).mutex.run(async () => {
      const configuration = encodeHistoryConfiguration(history)
      const prefix = `agent/authority/${history.historyId}/`
      const key = `${prefix}configuration`, saved = await options.store.get(key)
      if (saved !== null && !equalBytes(saved, configuration)) throw new Error('AUTHORITY_CONFIGURATION_MISMATCH')
      // Validate key ownership and any surviving certificate before creating or
      // replacing durable state. A damaged local proof must never be overwritten.
      createPrefixAuthority({ configuration: history, identity: options.identity,
        readHead: async () => { throw new Error('AUTHORITY_NOT_OPEN') } })
      const savedCertificate = await options.store.get(`${prefix}certificate`)
      let retained: PrefixCertificate | undefined
      if (savedCertificate !== null) {
        try {
          const evidence = decodeOrderingEvidence(savedCertificate)
          if (evidence.kind !== 'prefix-certificate') throw new Error('AUTHORITY_CERTIFICATE_KIND_INVALID')
          await verifyPrefixCertificate(evidence.certificate, history)
          retained = evidence.certificate
        } catch (error) { throw new Error('AUTHORITY_RETAINED_CERTIFICATE_INVALID', { cause: error }) }
      }
      let log: ReferenceRecordLog
      try {
        log = await ReferenceRecordLog.open(history.historyId, options.store, {
          ...(options.recordQuotaBytes === undefined ? {} : { quotaBytes: options.recordQuotaBytes }),
          requireExisting: saved !== null || retained !== undefined || (options.continuity?.position ?? 0) > 0,
        })
      } catch (error) {
        if (error instanceof Error && error.message === 'RECORD_LOG_MISSING') {
          throw new Error('AUTHORITY_CONTINUITY_NOT_ESTABLISHED', { cause: error })
        }
        throw error
      }
      const entries = await log.read()
      // Reopen the complete closure history, including a marker committed before
      // the process lost its certificate reply. Never reset a closed frontier.
      await evaluateFinalitySnapshot(history, entries)
      const genesisRoot = await orderedGenesisRoot(log.historyId)
      for (const expected of [retained, options.continuity]) {
        if (expected === undefined) continue
        if (expected.historyId !== log.historyId || !Number.isSafeInteger(expected.position) ||
            expected.position < 0 || expected.position > entries.length ||
            (expected.position === 0 ? genesisRoot : entries[expected.position - 1]?.root) !== expected.root) {
          throw new Error('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
        }
      }
      const payloadIndexKey = `${prefix}payload-reservations`
      const encodedPayloads = await options.store.get(payloadIndexKey)
      if (encodedPayloads === null && (saved !== null || retained !== undefined || entries.length !== 0)) {
        throw new Error('FINALITY_PAYLOAD_STATE_MISSING')
      }
      const payloads = encodedPayloads === null ? new Map<string, number>() : decodePayloadReservations(encodedPayloads)
      if (payloadBytes(payloads) > payloadQuotaBytes) throw new Error('FINALITY_PAYLOAD_QUOTA_EXCEEDED')
      // An acknowledged descriptor must have consumed its body budget before
      // it was committed. Missing accounting cannot silently reopen capacity.
      for (const entry of entries) {
        let record
        try { record = decodeLedgerRecord(entry.bytes) } catch { continue }
        if (record.kind === 'candidate' && payloads.get(record.payloadHash) !== record.payloadLength) {
          throw new Error('FINALITY_PAYLOAD_STATE_MISSING')
        }
      }
      if (encodedPayloads === null) await options.store.put(payloadIndexKey, encodePayloadReservations(payloads))
      // ReferenceRecordLog has already durably initialized even an empty log.
      // Thus a saved configuration always requires that log on a later open.
      if (saved === null) await options.store.put(key, configuration)
      return new NativeFinalityService(options, history, log)
    })
  }

  get configuration(): CoordinatedHistoryConfiguration { return structuredClone(this.#configuration) }
  head(): Promise<OrderedRecordHead> { return this.#log.head() }

  /** Retain the exact payload before committing its small typed ledger record. */
  append(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const exact = new Uint8Array(bytes)
    return this.#mutex.run(() => this.#appendLocked(exact))
  }

  async #appendLocked(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const prepared = await createLedgerRecord(bytes)
    await this.#checkRecordCapacity(prepared.recordBytes)
    if (prepared.detachedPayload !== null) {
      await this.#reservePayload(prepared.record.payloadHash, prepared.detachedPayload.length)
      await this.#store.put(this.#payloadKey(prepared.record.payloadHash), prepared.detachedPayload)
    }
    const entry = await this.#log.append(prepared.recordBytes)
    this.#serviceState.idleClosurePending = true
    return entry
  }

  /** Administrative ingress carries complete inline operations, never application bodies. */
  appendLedgerRecord(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const exact = new Uint8Array(bytes)
    return this.#mutex.run(async () => {
      const record = decodeLedgerRecord(exact)
      const payload = record.inlinePayload ?? await this.getPayload(record.payloadHash)
      if (payload === null) throw new Error('LEDGER_PAYLOAD_UNAVAILABLE')
      await verifyLedgerPayload(record, payload)
      await this.#checkRecordCapacity(exact)
      if (record.kind === 'candidate') await this.#reservePayload(record.payloadHash, record.payloadLength)
      const entry = await this.#log.append(exact)
      this.#serviceState.idleClosurePending = true
      return entry
    })
  }

  async getPayload(hash: string): Promise<Uint8Array | null> {
    validatePayloadHash(hash)
    const bytes = await this.#store.get(this.#payloadKey(hash))
    if (bytes !== null) await verifyPayloadHash(hash, bytes)
    return bytes
  }

  #payloadKey(hash: string): string {
    return `agent/authority/${this.#configuration.historyId}/payload/${hash}`
  }

  /** Logical retained-byte budgets; reservations also count interrupted appends. */
  storageUsage(): Promise<{ readonly recordBytes: number; readonly recordQuotaBytes: number;
    readonly reservedPayloadBytes: number; readonly payloadQuotaBytes: number }> {
    return this.#mutex.run(async () => ({
      recordBytes: (await this.#log.read()).reduce((sum, entry) => sum + entry.bytes.length, 0),
      recordQuotaBytes: this.#log.quotaBytes,
      reservedPayloadBytes: payloadBytes(await this.#payloadReservations()), payloadQuotaBytes: this.#payloadQuotaBytes,
    }))
  }

  async #checkRecordCapacity(bytes: Uint8Array): Promise<void> {
    const entries = await this.#log.read(), id = await orderedRecordId(bytes)
    if (entries.some(entry => entry.recordId === id)) return
    if (entries.length >= MAX_RETAINED_HISTORY_ENTRIES ||
        entries.reduce((sum, entry) => sum + entry.bytes.length, 0) + bytes.length > this.#log.quotaBytes) {
      throw new Error('RECORD_LOG_QUOTA_EXCEEDED')
    }
  }

  async #payloadReservations(): Promise<Map<string, number>> {
    const bytes = await this.#store.get(`agent/authority/${this.#configuration.historyId}/payload-reservations`)
    if (bytes === null) throw new Error('FINALITY_PAYLOAD_STATE_MISSING')
    return decodePayloadReservations(bytes)
  }

  async #reservePayload(hash: string, length: number): Promise<void> {
    const reservations = await this.#payloadReservations(), previous = reservations.get(hash)
    if (previous !== undefined) {
      if (previous !== length) throw new Error('FINALITY_PAYLOAD_STATE_INVALID')
      return
    }
    if (reservations.size >= MAX_RETAINED_HISTORY_ENTRIES || payloadBytes(reservations) + length > this.#payloadQuotaBytes) {
      throw new Error('FINALITY_PAYLOAD_QUOTA_EXCEEDED')
    }
    reservations.set(hash, length)
    // Reserve before storing a body. A crash or a lost body/record reply leaves
    // a bounded reservation that an exact retry reuses; it cannot leak quota.
    await this.#store.put(`agent/authority/${this.#configuration.historyId}/payload-reservations`, encodePayloadReservations(reservations))
  }

  /** Persist the closure marker before certifying this authority's own committed head. */
  certify(): Promise<PrefixCertificate> {
    return this.#mutex.run(() => this.#certifyLocked())
  }

  #observeClock(): number {
    const observed = Math.trunc(this.#now())
    if (!Number.isSafeInteger(observed) || observed < 0) throw new Error('AUTHORITY_CLOCK_INVALID')
    return observed
  }

  async #certifyLocked(observed = this.#observeClock()): Promise<PrefixCertificate> {
    // Snapshot time at the same boundary that excludes new appenders. Awaited
    // storage and proof verification must not close additional author time
    // while already published proposals wait for this service's mutex.
    const entries = await this.#log.read()
    const snapshot = await evaluateFinalitySnapshot(this.#configuration, entries)
    const observedCutoff = BigInt(observed) - BigInt(this.#cutoffLagMs)
    const uncovered = snapshot.records.some((record) => record.closureBoundary === null)
    let coveredDemand = -1n
    for (const record of snapshot.records) {
      if (record.closureBoundary === null) continue
      const horizon = record.closureBoundary.closedThroughMs + this.#futureAdmissionWindowMs
      if (horizon > coveredDemand) coveredDemand = horizon
    }
    const requestedCutoff = uncovered || observedCutoff < coveredDemand ? observedCutoff : coveredDemand
    const closedThroughMs = requestedCutoff > snapshot.closedThroughMs ? requestedCutoff : snapshot.closedThroughMs
    if (closedThroughMs >= 0n && (closedThroughMs > snapshot.closedThroughMs || uncovered)) {
      const includedHead = { historyId: this.#configuration.historyId, position: entries.length,
        root: entries.at(-1)?.root ?? await orderedGenesisRoot(this.#configuration.historyId) }
      const marker = await createFinalityClosureRecord({ configuration: this.#configuration,
        identity: this.#identity, includedHead, closedThroughMs, control: await extendFinalityControlCommitment(snapshot, closedThroughMs) })
      await this.#log.append(marker)
    }
    // Every admissible encrypted proposal has an upper timestamp bound derived
    // from its first closure and the signed genesis window. Once that horizon
    // is closed, idle ticks need neither another marker nor a full log scan.
    this.#serviceState.idleClosurePending = uncovered
      ? closedThroughMs < 0n || this.#futureAdmissionWindowMs > 0n
      : coveredDemand > closedThroughMs
    const certificate = await this.#signer.certify()
    await this.#store.put(`agent/authority/${this.#configuration.historyId}/certificate`,
      encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
    return certificate
  }

  /** The returned range and covering certificate include the same newly closed head. */
  certifiedRead(options: { readonly after?: number; readonly limit?: number } = {}): Promise<{
    readonly entries: readonly OrderedRecordEntry[]
    readonly certificate: PrefixCertificate
    readonly hasMore: boolean
  }> {
    const after = options.after ?? 0, limit = options.limit ?? 64
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
      throw new Error('AUTHORITY_RANGE_INVALID')
    }
    return this.#mutex.run(async () => {
      const observed = this.#observeClock()
      if (after > (await this.#log.head()).position) throw new Error('AUTHORITY_RANGE_AHEAD')
      const certificate = await this.#certifyLocked(observed)
      const entries = (await this.#log.read()).slice(after, after + limit)
      return { entries, certificate, hasMore: after + entries.length < certificate.position }
    })
  }

  /** Membership cursors count controls, independently of application receipts. */
  certifiedControlRead(options: { readonly after?: number; readonly limit?: number } = {}): Promise<MembershipLedgerPage> {
    const after = options.after ?? 0, limit = options.limit ?? 128
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 128) {
      return Promise.reject(new Error('AUTHORITY_RANGE_INVALID'))
    }
    return this.#mutex.run(async () => {
      const certificate = await this.#certifyLocked()
      const retained = await this.#log.read()
      const snapshot = await evaluateFinalitySnapshot(this.#configuration, retained)
      if (certificate.position > 0 && snapshot.closures.at(-1)?.position !== certificate.position) throw new Error('MEMBERSHIP_PREFIX_PENDING')
      if (after > snapshot.controls.length) throw new Error('AUTHORITY_RANGE_AHEAD')
      const entries = []
      let bytes = 0
      for (const control of snapshot.controls.slice(after, after + limit)) {
        const size = encodeFinalizedControl(control).length
        if (size > 1024 * 1024) throw new Error('MEMBERSHIP_ENTRY_TOO_LARGE')
        if (entries.length && bytes + size > 1024 * 1024) break
        entries.push(control); bytes += size
      }
      return { entries, checkpoint: retained.at(-1) ?? null, certificate,
        hasMore: after + entries.length < snapshot.controls.length }
    })
  }

  async read(options: { readonly after?: number; readonly limit?: number } = {}): Promise<{
    readonly entries: readonly OrderedRecordEntry[]
    readonly head: OrderedRecordHead
    readonly hasMore: boolean
  }> {
    const after = options.after ?? 0, limit = options.limit ?? 64
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
      throw new Error('AUTHORITY_RANGE_INVALID')
    }
    return this.#mutex.run(async () => {
      const entries = await this.#log.read()
      const head = await this.#log.head()
      if (after > head.position) throw new Error('AUTHORITY_RANGE_AHEAD')
      return { entries: entries.slice(after, after + limit), head, hasMore: after + limit < entries.length }
    })
  }

  /**
   * Publish one complete captured prefix in bounded pages, then its certificate.
   * `after` is the last position already acknowledged by this sink. New appends
   * belong to a later call; retries resend the same retained evidence bytes.
   * Cancellation stops between acknowledged writes and never rolls one back.
   */
  async share(sink: EvidenceSink, options: { readonly after?: number; readonly signal?: AbortSignal } = {}): Promise<OrderedRecordHead> {
    const signal = options.signal
    signal?.throwIfAborted()
    let after = options.after ?? 0
    const first = await this.certifiedRead({ after, limit: 64 })
    const certificate = first.certificate
    let entries = first.entries
    while (after < certificate.position) {
      signal?.throwIfAborted()
      if (entries.length === 0) throw new Error('AUTHORITY_RANGE_INCOMPLETE')
      for (const entry of entries) {
        signal?.throwIfAborted()
        if (entry.position !== after + 1 || entry.position > certificate.position) throw new Error('AUTHORITY_RANGE_NOT_CONTIGUOUS')
        await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        after = entry.position
      }
      signal?.throwIfAborted()
      if (after < certificate.position) {
        entries = (await this.read({ after, limit: Math.min(64, certificate.position - after) })).entries
      }
    }
    signal?.throwIfAborted()
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
    signal?.throwIfAborted()
    return { historyId: certificate.historyId, position: certificate.position, root: certificate.root }
  }

  /**
   * Resident inclusion loop over a durable replaying transport subscription.
   * The stream must include retained history before continuing live. Records
   * are already feed-authenticated; replicas verify inner authorship, grants,
   * governance and outcomes. Signed closure markers are retained records;
   * prefix certificates are evidence, never log submissions.
   */
  async serve(transport: ChronologTransport, signal?: AbortSignal): Promise<void> {
    if (transport.putEvidence === undefined) throw new Error('AUTHORITY_EVIDENCE_TRANSPORT_REQUIRED')
    const sink: EvidenceSink = { putEvidence: (bytes) => transport.putEvidence!(bytes) }
    const stopped = new AbortController()
    const running = signal === undefined ? stopped.signal : AbortSignal.any([signal, stopped.signal])
    const publication = new Mutex()
    let after = 0
    const include = async (payload: Uint8Array): Promise<boolean> => {
      let type: string
      try { type = decodeEnvelope(payload).messageType } catch { return false }
      if (type !== 'candidate' && type !== 'capability' && type !== 'epoch-manifest') return false
      const exact = new Uint8Array(payload)
      return this.#mutex.run(async () => {
        const before = await this.#log.head()
        const entry = await this.#appendLocked(exact)
        // Replaying retained history must not manufacture extra closures.
        // Only a new receipt triggers publication; idle progress has its timer.
        return entry.position > before.position
      })
    }
    const publish = () => publication.run(async () => {
      if (running.aborted) return
      try {
        after = (await this.share(sink, { after, signal: running })).position
      } catch (error) {
        // An explicit stop is normal; a sink failure must still stop the owner.
        if (!running.aborted || error !== running.reason) throw error
      }
    })
    // Include the already retained local backlog before the first new closure.
    // Replayed exact records still deduplicate to their original receipt.
    for (const record of await transport.history()) {
      if (running.aborted) return
      await include(record.payload)
    }
    if (running.aborted) return
    await publish()
    const consume = async () => {
      for await (const record of transport.subscribe(running)) {
        if (running.aborted) return
        if (await include(record.payload)) await publish()
      }
      stopped.abort()
    }
    const closeIdleTime = async () => {
      while (!running.aborted) {
        await waitForClosure(this.#closureIntervalMs, running)
        if (!running.aborted && this.#serviceState.idleClosurePending) await publish()
      }
    }
    const tasks = [consume(), closeIdleTime()]
    try { await Promise.all(tasks) }
    finally { stopped.abort(); await Promise.allSettled(tasks) }
  }
}

function payloadQuota(value = 64 * 1024 * 1024): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('FINALITY_PAYLOAD_QUOTA_INVALID')
  return value
}

function payloadBytes(reservations: ReadonlyMap<string, number>): number {
  let bytes = 0
  for (const length of reservations.values()) bytes += length
  return bytes
}

function encodePayloadReservations(reservations: ReadonlyMap<string, number>): Uint8Array {
  return encodeCanonicalCbor([1n, [...reservations].map(([hash, length]) => [hash, BigInt(length)])])
}

function decodePayloadReservations(bytes: Uint8Array): Map<string, number> {
  const value = assertCanonicalCbor(bytes, { maxBytes: MAX_RETAINED_HISTORY_ENTRIES * 80 + 1024,
    maxItems: MAX_RETAINED_HISTORY_ENTRIES * 3 + 4, maxDepth: 3, maxTextBytes: 64 })
  if (!Array.isArray(value) || value.length !== 2 || value[0] !== 1n || !Array.isArray(value[1]) ||
      value[1].length > MAX_RETAINED_HISTORY_ENTRIES) throw new Error('FINALITY_PAYLOAD_STATE_INVALID')
  const reservations = new Map<string, number>()
  for (const item of value[1]) {
    if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== 'string' || !/^[0-9a-f]{64}$/u.test(item[0]) ||
        typeof item[1] !== 'bigint' || item[1] < 1n || item[1] > 1_048_576n || reservations.has(item[0])) {
      throw new Error('FINALITY_PAYLOAD_STATE_INVALID')
    }
    reservations.set(item[0], Number(item[1]))
  }
  return reservations
}

function waitForClosure(delay: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve()
  return new Promise((resolve) => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve() }
    const timer = setTimeout(finish, delay)
    signal.addEventListener('abort', finish, { once: true })
  })
}

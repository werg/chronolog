import {
  Mutex, ReferenceRecordLog, createPrefixAuthority, encodeHistoryConfiguration, encodeOrderingEvidence, orderedGenesisRoot,
  createFinalityClosureRecord, evaluateFinalitySnapshot, createLedgerRecord, decodeLedgerRecord, verifyLedgerPayload,
  decodeOrderingEvidence, verifyPrefixCertificate,
} from '@chronolog/node-core'
import type {
  CoordinatedHistoryConfiguration, DurableOperationStore, OrderedRecordEntry, OrderedRecordHead, PrefixCertificate,
} from '@chronolog/node-core'
import { decodeEnvelope, equalBytes } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import { validatePayloadHash, verifyPayloadHash, type ChronologTransport } from '@chronolog/records'

export interface EvidenceSink { putEvidence(bytes: Uint8Array): Promise<unknown> }

export interface NativeAuthorityOptions {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly identity: Ed25519KeyPair
  /** Must have one fenced storage owner, e.g. NativeAgentStore. */
  readonly store: DurableOperationStore
  readonly quotaBytes?: number
  /** Provider clock; application execution order never uses receipt time. */
  readonly now?: () => number
  /** Hold this author-time window open before issuing a closure. */
  readonly cutoffLagMs?: number
  /** Must equal signed genesis maxFutureSkewMs + cutoffLagMs; defaults to 31,000. */
  readonly futureAdmissionWindowMs?: number
  /** Close time while the retained application head is idle. */
  readonly closureIntervalMs?: number
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
export class NativeAuthority {
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

  private constructor(options: NativeAuthorityOptions, log: ReferenceRecordLog) {
    this.#configuration = structuredClone(options.configuration)
    this.#log = log
    this.#store = options.store
    this.#serviceState = authorityState(options.store, options.configuration.historyId)
    this.#mutex = this.#serviceState.mutex
    this.#identity = { ...options.identity, publicKeyBytes: new Uint8Array(options.identity.publicKeyBytes) }
    this.#now = options.now ?? Date.now
    this.#cutoffLagMs = options.cutoffLagMs ?? 1_000
    const futureAdmissionWindowMs = options.futureAdmissionWindowMs ?? 31_000
    this.#closureIntervalMs = options.closureIntervalMs ?? 1_000
    if (!Number.isSafeInteger(this.#cutoffLagMs) || this.#cutoffLagMs < 0 ||
        !Number.isSafeInteger(futureAdmissionWindowMs) || futureAdmissionWindowMs < 0 ||
        !Number.isSafeInteger(this.#closureIntervalMs) || this.#closureIntervalMs < 1 || this.#closureIntervalMs > 60_000) {
      throw new Error('AUTHORITY_CLOCK_CONFIGURATION_INVALID')
    }
    this.#futureAdmissionWindowMs = BigInt(futureAdmissionWindowMs)
    this.#signer = createPrefixAuthority({ configuration: this.#configuration, identity: this.#identity, readHead: () => log.head() })
  }

  static async open(options: NativeAuthorityOptions): Promise<NativeAuthority> {
    options = { ...options, configuration: structuredClone(options.configuration),
      identity: { ...options.identity, publicKeyBytes: new Uint8Array(options.identity.publicKeyBytes) },
      ...(options.continuity === undefined ? {} : { continuity: structuredClone(options.continuity) }) }
    return authorityState(options.store, options.configuration.historyId).mutex.run(async () => {
      const configuration = encodeHistoryConfiguration(options.configuration)
      const prefix = `agent/authority/${options.configuration.historyId}/`
      const key = `${prefix}configuration`, saved = await options.store.get(key)
      if (saved !== null && !equalBytes(saved, configuration)) throw new Error('AUTHORITY_CONFIGURATION_MISMATCH')
      // Validate key ownership and any surviving certificate before creating or
      // replacing durable state. A damaged local proof must never be overwritten.
      createPrefixAuthority({ configuration: options.configuration, identity: options.identity,
        readHead: async () => { throw new Error('AUTHORITY_NOT_OPEN') } })
      const savedCertificate = await options.store.get(`${prefix}certificate`)
      let retained: PrefixCertificate | undefined
      if (savedCertificate !== null) {
        try {
          const evidence = decodeOrderingEvidence(savedCertificate)
          if (evidence.kind !== 'prefix-certificate') throw new Error('AUTHORITY_CERTIFICATE_KIND_INVALID')
          await verifyPrefixCertificate(evidence.certificate, options.configuration)
          retained = evidence.certificate
        } catch (error) { throw new Error('AUTHORITY_RETAINED_CERTIFICATE_INVALID', { cause: error }) }
      }
      let log: ReferenceRecordLog
      try {
        log = await ReferenceRecordLog.open(options.configuration.historyId, options.store, {
          ...(options.quotaBytes === undefined ? {} : { quotaBytes: options.quotaBytes }),
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
      await evaluateFinalitySnapshot(options.configuration, entries)
      const genesisRoot = await orderedGenesisRoot(log.historyId)
      for (const expected of [retained, options.continuity]) {
        if (expected === undefined) continue
        if (expected.historyId !== log.historyId || !Number.isSafeInteger(expected.position) ||
            expected.position < 0 || expected.position > entries.length ||
            (expected.position === 0 ? genesisRoot : entries[expected.position - 1]?.root) !== expected.root) {
          throw new Error('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
        }
      }
      // ReferenceRecordLog has already durably initialized even an empty log.
      // Thus a saved configuration always requires that log on a later open.
      if (saved === null) await options.store.put(key, configuration)
      return new NativeAuthority(options, log)
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
    if (prepared.detachedPayload !== null) {
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

  /** Persist the closure marker before certifying this authority's own committed head. */
  certify(): Promise<PrefixCertificate> {
    return this.#mutex.run(() => this.#certifyLocked())
  }

  async #certifyLocked(): Promise<PrefixCertificate> {
    const entries = await this.#log.read()
    const snapshot = await evaluateFinalitySnapshot(this.#configuration, entries)
    const observed = Math.trunc(this.#now())
    if (!Number.isSafeInteger(observed) || observed < 0) throw new Error('AUTHORITY_CLOCK_INVALID')
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
        identity: this.#identity, includedHead, closedThroughMs })
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
      if (after > (await this.#log.head()).position) throw new Error('AUTHORITY_RANGE_AHEAD')
      const certificate = await this.#certifyLocked()
      const entries = (await this.#log.read()).slice(after, after + limit)
      return { entries, certificate, hasMore: after + entries.length < certificate.position }
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

  /** Re-publishing retained evidence is idempotent and never authors another proposal. */
  async share(sink: EvidenceSink, options: { readonly after?: number; readonly limit?: number } = {}): Promise<OrderedRecordHead> {
    const range = await this.certifiedRead(options)
    for (const entry of range.entries) await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: range.certificate }))
    const last = range.entries.at(-1)
    return last === undefined ? range.certificate : { historyId: last.historyId, position: last.position, root: last.root }
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
      const certificate = await this.certify()
      while (after < certificate.position && !running.aborted) {
        const range = await this.read({ after })
        for (const entry of range.entries) {
          if (entry.position > certificate.position) break
          await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
          after = entry.position
        }
      }
      if (!running.aborted) await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
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

/** Public name for the native inclusion and author-time closure service. */
export { NativeAuthority as NativeFinalityService }
export type NativeFinalityServiceOptions = NativeAuthorityOptions

function waitForClosure(delay: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve()
  return new Promise((resolve) => {
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve() }
    const timer = setTimeout(finish, delay)
    signal.addEventListener('abort', finish, { once: true })
  })
}

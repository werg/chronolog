import { bytesToHex, sha256 } from '@chronolog/canonical'

import {
  ControlStore,
  ControlStoreConflictError,
  type SettlementEvidence,
  type StoredAttestation,
  type StoredCandidate,
  type WatermarkEvidence,
} from '@chronolog/control-store/browser'
import type {
  AdmittedTransaction,
  MaterializedLocalSqlResult,
  MaterializedLocalSqlValue,
  MaterializedTransactionOutcome,
  MaterializedReadHandle,
  MaterializedApplicationSnapshot,
} from '@chronolog/materializer'
import {
  decodeTransactionCore,
  assertCanonicalCbor,
  encodeCanonicalCbor,
  changeProgramToCanonicalCbor,
  decodeEnvelope,
  decodeValidatorAttestation,
  decodeValidatorHeartbeat,
  encodeTransactionCore,
  encodeValidatorAttestation,
  encodeValidatorHeartbeat,
  equalBytes,
  transactionDigest,
  transactionOrderKey,
  utf8,
  type TransactionCore,
  type ChangeProgram,
  assertValidChangeProgram,
  type ValidatorAttestation,
  type ValidatorHeartbeat,
  emit, program, bytesToBase64Url,
  type EventPayload,
  type ViewChange, type ViewChangeOptions,
} from '@chronolog/protocol'
import { ChangeSignal, type TransportRecord } from '@chronolog/records'
import { readEffectiveEvents, type EventBatch, type EventReadOptions, type EventHistorySnapshot, type EventHistoryItem } from './events.js'
import { DurableOperationJournal, MemoryOperationStore } from './operations.js'
import { encodeOrderingEvidence, orderedGenesisRoot, type OrderingEvidence } from './history-policy.js'
import { decodeLedgerRecord, LedgerRecordError, verifyLedgerPayload, type LedgerRecord } from './ledger-record.js'
import { orderFinalizedGovernanceRecords } from './governance.js'
import type { FinalityClosureBoundary, IncludedRecord, LiveFinalityFrontier } from './finality.js'
import { evaluatePeerLiveFinality } from './peer-finality.js'

import { Mutex, RevisionBroadcaster } from './async.js'
import type {
  ChronologNodeOptions,
  NodeRevisionEvent,
  NodeStatus,
  PublishTransactionInput,
  PublishedTransaction,
  ReservedTransactionContext,
} from './types.js'
import { WIRE_ENCRYPTION_EPOCH_UNAVAILABLE, decodeSignedEnvelope, encodeSignedEnvelope, decodeSignedMessage, sealSignedMessage } from './wire.js'
import { FeedForkRegistry } from './feed-forks.js'
import { ValidatorRevisionClosures } from './validator-closures.js'

export type { ViewChange, ViewChangeOptions } from '@chronolog/protocol'

export class ChronologNode {
  readonly #options: ChronologNodeOptions
  readonly #control: ControlStore
  readonly #operations: DurableOperationJournal
  readonly #ingressOperations: DurableOperationJournal
  readonly #validatorClosures: ValidatorRevisionClosures
  #evidenceTask: Promise<void> | null = null
  #coordinatedProcessed = 0
  readonly #finalizedControls = new Set<number>()
  readonly #resolvedInclusionRecords = new Set<number>()
  #coordinatedAppliedThrough = 0
  #processedClosedThroughMs = -1n
  #appliedClosedThroughMs = -1n
  readonly #canonicalPositions = new Map<string, number>()
  readonly #mutex = new Mutex()
  readonly #events = new RevisionBroadcaster<NodeRevisionEvent>()
  readonly #applicationChanges = new ChangeSignal()
  readonly events = {
    publish: (topic: string, payload: EventPayload, options: { readonly operationId: string }) =>
      this.publish({ program: program(emit(topic, payload)), operationId: options.operationId }),
    read: (options: EventReadOptions = {}): Promise<EventBatch> => this.#mutex.run(() =>
      readEffectiveEvents(this.#eventSnapshot(this.#options.materialization.queries.captureApplication({ view: 'final' })), options)),
    subscribe: (options: EventReadOptions & { readonly signal?: AbortSignal } = {}): AsyncIterable<EventBatch> => this.#subscribeEvents(options),
  }
  readonly #seen = new Set<string>()
  readonly #indexedFeeds = new Map<string, { through: bigint; pending: Set<bigint> }>()
  readonly #retryRecords = new Map<string, TransportRecord>()
  readonly #maximumRetryRecords: number
  readonly #feedForks: FeedForkRegistry
  #retryOverflow = false
  readonly #candidateCores = new Map<string, TransactionCore>()
  readonly #replayedOutcomes = new Set<string>()
  readonly #abort = new AbortController()
  #revision = 0n
  #started = false
  #closed = false
  #consumeTask: Promise<void> | null = null
  #subscriptionRestarts = 0
  /** What the transport consumer is doing, for stall diagnosis. */
  #consumerPhase = 'idle'
  #consumerPhaseSince = Date.now()
  #stallWatchdog: NodeJS.Timeout | undefined
  #stallReported = false
  #subscriptionAbort: AbortController | undefined
  #backlogSince: number | undefined
  #backlogAtWindowStart = 0
  #lastResyncAt: number | undefined
  #lastError: Error | undefined
  #materializationError: Error | undefined
  #ingestionError: Error | undefined
  #acceptedAboveMs: bigint
  #heartbeatTimer: ReturnType<typeof setInterval> | undefined
  #materializationDebounceTimer: ReturnType<typeof setTimeout> | undefined
  #materializationRetryTimer: ReturnType<typeof setTimeout> | undefined
  #ingestionRetryTimer: ReturnType<typeof setTimeout> | undefined
  #materializationRetryMs = 100
  #materializationPending = false
  #materializationReady = false
  #lastAuthoredTimestampMs = -1n
  #observedAuthorTimestampMs = -1n
  readonly #authorFutureSkewMs: number | undefined

  constructor(options: ChronologNodeOptions) {
    this.#options = options
    this.#authorFutureSkewMs = options.authorClockPolicy?.maxFutureSkewMs
    if (this.#authorFutureSkewMs !== undefined && (!Number.isSafeInteger(this.#authorFutureSkewMs) || this.#authorFutureSkewMs < 0)) {
      throw new Error('AUTHOR_CLOCK_POLICY_INVALID')
    }
    this.#control = options.controlStore ?? new ControlStore()
    const operationStore = options.operationStore ?? new MemoryOperationStore()
    this.#operations = new DurableOperationJournal(operationStore, `transactions/${bytesToHex(options.groupId)}/${bytesToHex(options.identity.publicKeyBytes)}`)
    this.#ingressOperations = new DurableOperationJournal(operationStore, `ingress/${bytesToHex(options.groupId)}/${bytesToHex(options.identity.publicKeyBytes)}`)
    this.#validatorClosures = new ValidatorRevisionClosures({
      groupId: options.groupId, groupRoute: options.groupRoute ?? options.groupId,
      identity: options.identity, transport: options.transport, store: operationStore,
      ...(options.envelopeCipher === undefined ? {} : { cipher: options.envelopeCipher }),
    })
    if (options.historyPolicy?.kind === 'coordinated') {
      const configured = options.historyPolicy.policy.configuration
      if (configured.kind !== 'coordinated' || !equalBytes(configured.groupId, options.groupId) || !equalBytes(configured.executionManifestDigest, options.materialization.queries.executionManifestDigest)) {
        throw new Error('NODE_HISTORY_CONFIGURATION_MISMATCH')
      }
      if (options.validator !== undefined) throw new Error('COORDINATED_NODE_CANNOT_ATTEST')
      if (options.envelopeCipher !== undefined && options.historyPolicy.encryptionEpochStatusAt === undefined) {
        throw new Error('COORDINATED_ENCRYPTION_POLICY_REQUIRED')
      }
      const futureAdmissionWindowMs = options.historyPolicy.futureAdmissionWindowMs ?? 31_000
      if (!Number.isSafeInteger(futureAdmissionWindowMs) || futureAdmissionWindowMs < 0) {
        throw new Error('FINALITY_FUTURE_ADMISSION_WINDOW_INVALID')
      }
    }
    this.#maximumRetryRecords = options.maximumRetryRecords ?? 4_096
    this.#feedForks = options.feedForkRegistry ?? new FeedForkRegistry()
    if (!Number.isSafeInteger(this.#maximumRetryRecords) || this.#maximumRetryRecords < 1) {
      throw new RangeError('NODE_INVALID_RETRY_CAPACITY')
    }
    this.#revision = this.#control.sequence
    const snapshot = this.#control.snapshot()
    const persistedCutoffs = [
      ...(this.#control.validatorCutoff(options.identity.publicKeyBytes) === null
        ? []
        : [this.#control.validatorCutoff(options.identity.publicKeyBytes)!]),
      ...snapshot.heartbeats
        .filter((item) => equalBytes(item.validatorId, options.identity.publicKeyBytes))
        .map((item) => item.acceptanceCutoffMs),
      ...snapshot.attestations
        .filter((item) => equalBytes(item.validatorId, options.identity.publicKeyBytes))
        .map((item) => item.acceptedAboveMs),
    ]
    this.#acceptedAboveMs = persistedCutoffs.reduce(
      (maximum, value) => value > maximum ? value : maximum,
      options.validator?.initialAcceptedAboveMs ?? 0n,
    )
    this.#lastAuthoredTimestampMs = snapshot.candidates
      .filter((candidate) => equalBytes(candidate.orderKey.authorId, options.identity.publicKeyBytes))
      .reduce(
        (maximum, candidate) => candidate.orderKey.authorTimestampMs > maximum
          ? candidate.orderKey.authorTimestampMs
          : maximum,
        -1n,
      )
  }

  get identity(): Uint8Array { return this.#options.identity.publicKeyBytes.slice() }
  get groupId(): Uint8Array { return this.#options.groupId.slice() }
  get membershipRevision(): Uint8Array { return this.#membershipState().membershipRevision.slice() }
  get validationPolicy(): Uint8Array { return this.#membershipState().validationPolicy.slice() }
  get executionManifestDigest(): Uint8Array {
    return this.#options.materialization.queries.executionManifestDigest
  }
  get controlStore(): ControlStore { return this.#control }
  get revision(): bigint { return this.#revision }
  /** Times the transport subscription ended early and was re-established. */
  get subscriptionRestarts(): number { return this.#subscriptionRestarts }
  get materializedRevision(): bigint { return this.#options.materialization.queries.revision }
  get orderLength(): number { return this.#options.materialization.queries.orderLength }
  get finalOrderLength(): number { return this.#options.materialization.queries.finalOrderLength ?? 0 }
  get finalRevision(): bigint { return this.#options.materialization.queries.finalRevision ?? 0n }
  get historyPolicy(): 'peer' | 'coordinated' { return this.#options.historyPolicy?.kind ?? 'peer' }
  get finalThrough(): number { return this.#coordinatedAppliedThrough }

  #finalityHistoryId(): string {
    const selected = this.#options.historyPolicy
    if (selected?.kind !== 'coordinated' || selected.policy.configuration.kind !== 'coordinated') {
      throw new Error('NODE_HISTORY_CONFIGURATION_MISMATCH')
    }
    return selected.policy.configuration.historyId
  }

  reserveTransactionContext(): ReservedTransactionContext {
    this.#assertReady()
    return this.#allocateTransactionContext()
  }

  async start(): Promise<void> {
    if (this.#closed) throw new Error('NODE_CLOSED')
    if (this.#started) return
    await this.#validatorClosures.recover()
    const history = await this.#options.transport.history()
    await this.#recoverValidatorCutoff(history)
    this.#started = true
    this.#consumeTask = this.#consume()
    this.#stallWatchdog = setInterval(() => { void this.#checkIngestStall().catch(() => {}) }, 5_000)
    this.#stallWatchdog.unref?.()
    await this.#drainHistory(history)
    await this.#operations.recover(async (bytes) => { await this.#applyPreparedTransaction(bytes) })
    await this.#ingressOperations.recover(async (bytes) => { await this.#applyPreparedTransaction(bytes) })
    if (this.#options.historyPolicy?.kind === 'coordinated') {
      for (const evidence of await this.#options.transport.evidenceHistory?.() ?? []) {
        await this.#ingestSharedEvidence(evidence.bytes)
      }
      this.#evidenceTask = this.#consumeEvidence()
    }
    // A restored admission index can refer to records later in the retained
    // history. Do not run SQL until all of those payloads have been restored.
    this.#materializationReady = true
    // The control store is authoritative and is committed before the derived
    // DoltLite revision. A crash between those two writes can therefore leave
    // an admissible order ahead of the materializer. Reconcile even when replay
    // did not cause a new admission transition: restored candidates are already
    // marked admissible, so their normal ingest path intentionally does nothing.
    await this.#mutex.run(async () => {
      this.#materializationPending = true
      try {
        await this.#reconcileMaterializer()
      } catch (error) {
        this.#recordError(error)
        this.#scheduleMaterializationRetry()
      }
    })
    if (this.#options.validator?.heartbeatIntervalMs) {
      const interval = this.#options.validator.heartbeatIntervalMs
      this.#heartbeatTimer = setInterval(() => {
        // Governed membership can grant or revoke the validator role at any
        // time; while this node holds none, there is nothing to publish.
        if (this.#validatorCapability() === undefined) return
        void this.publishHeartbeat().catch((error) => this.#recordError(error))
      }, interval)
      this.#heartbeatTimer.unref?.()
    }
  }

  async publish(input: PublishTransactionInput): Promise<PublishedTransaction> {
    this.#assertReady()
    assertValidChangeProgram(input.program)
    // Freeze the caller's proposal before the first suspension: the durable
    // fingerprint and signed bytes must describe the same program and context.
    input = structuredClone(input)
    const fingerprint = encodeCanonicalCbor([
      changeProgramToCanonicalCbor(input.program), input.authorTimestampMs ?? null,
      input.nonce ?? null, input.membershipRevision ?? null, input.validationPolicy ?? null,
      input.writerCapability ?? null, input.metadata ?? null,
    ])
    const operationId = input.operationId ?? crypto.randomUUID()
    const prepared = await this.#operations.run({
      operationId, fingerprint,
      prepare: () => this.#prepareTransaction({ ...input, operationId }),
      apply: async (bytes) => { await this.#applyPreparedTransaction(bytes) },
    })
    const { canonical } = this.#decodePreparedTransaction(prepared)
    const core = decodeTransactionCore(canonical)
    const candidateDigest = await transactionDigest(canonical)
    const txIdText = `tx_${bytesToHex(candidateDigest)}`
    return { txId: utf8(txIdText), txIdText, candidateDigest, core }
  }


  /**
   * Accept an original signed proposal through an enrolled ingress feed. The
   * ingress encrypts and retains it without acquiring the publisher's identity.
   * Exact retries return the prepared proposal even after its grant is revoked.
   */
  async submitSigned(signed: Uint8Array): Promise<PublishedTransaction> {
    this.#assertReady()
    signed = signed.slice()
    const wire = await decodeSignedMessage(signed)
    if (wire.type !== 'candidate') throw new Error('INGRESS_CANDIDATE_REQUIRED')
    const core = decodeTransactionCore(wire.payload)
    if (!equalBytes(core.authorId, wire.signer) || !equalBytes(core.groupId, this.groupId) ||
        !equalBytes(core.executionManifestDigest, this.executionManifestDigest)) throw new Error('INGRESS_CONTEXT_MISMATCH')
    const operationId = bytesToHex(await sha256(encodeCanonicalCbor([core.authorId, core.operationId])))
    const prepared = await this.#ingressOperations.run({ operationId, fingerprint: signed,
      prepare: async () => {
        if (!await this.#options.membership.canWrite({ groupId: core.groupId, membershipRevision: core.membershipRevision,
          validationPolicy: core.validationPolicy, writerId: core.authorId, program: core.program,
          authorTimestampMs: core.authorTimestampMs,
          ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
        })) throw new Error('WRITER_UNAUTHORIZED')
        if (!await this.#membershipAllowsTransportAuthor(this.#options.transport.identity, 'writer', core.authorId,
          core.membershipRevision, undefined, core.writerCapability)) throw new Error('INGRESS_FORWARDING_UNAUTHORIZED')
        return encodeCanonicalCbor([wire.payload, await sealSignedMessage(this.#groupRoute(), signed, this.#options.envelopeCipher)])
      },
      apply: (bytes) => this.#applyPreparedTransaction(bytes),
    })
    const { canonical } = this.#decodePreparedTransaction(prepared)
    const candidateDigest = await transactionDigest(canonical)
    const txIdText = `tx_${bytesToHex(candidateDigest)}`
    return { txId: utf8(txIdText), txIdText, candidateDigest, core: decodeTransactionCore(canonical) }
  }

  async operation(operationId: string): Promise<{
    readonly operationId: string; readonly proposalId: string; readonly final: boolean;
    readonly outcome: MaterializedTransactionOutcome | null;
  } | null> {
    const prepared = await this.#operations.lookup(operationId)
    if (prepared === null) return null
    const { canonical } = this.#decodePreparedTransaction(prepared)
    const proposalId = `tx_${bytesToHex(await transactionDigest(canonical))}`
    return { operationId, proposalId, final: this.isFinal(utf8(proposalId)), outcome: this.outcome(utf8(proposalId)) }
  }

  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<{
    readonly revision: string; readonly finalRevision: string; readonly view: 'local' | 'final';
    query(sql: string, parameters?: readonly MaterializedLocalSqlValue[]): MaterializedLocalSqlResult;
    readEvents(options?: EventReadOptions): EventBatch; release(): void;
  }> {
    return this.#mutex.run(() => {
      const view = options.view ?? 'final'
      const queries = this.#options.materialization.queries
      if (queries.captureRead === undefined) throw new Error('MATERIALIZER_SNAPSHOT_UNAVAILABLE')
      const sql: MaterializedReadHandle = queries.captureRead({ view })
      try {
      const snapshot = this.#eventSnapshot(sql)
      const finalRevision = this.#viewRevision('final', sql.finalRevision, sql.finalOrderLength)
      let released = false
      return { revision: snapshot.revision, finalRevision, view,
        query: (statement, parameters) => {
          if (released) throw new Error('VIEW_RELEASED')
          return sql.query(statement, parameters)
        },
        readEvents: (readOptions = {}) => {
          if (released) throw new Error('VIEW_RELEASED')
          return readEffectiveEvents(snapshot, readOptions)
        },
        release() { if (!released) { released = true; sql.release() } },
      }
      } catch (error) { sql.release(); throw error }
    })
  }

  /** Current applied view, then coalesced invalidations; no read lease or event replay. */
  changes(options: ViewChangeOptions = {}): AsyncIterable<ViewChange> {
    const view = options.view ?? 'final', external = options.signal, node = this
    if (view !== 'local' && view !== 'final') throw new Error('VIEW_INVALID')
    return { [Symbol.asyncIterator]() {
      const controller = new AbortController()
      const signal = AbortSignal.any([controller.signal, node.#abort.signal, ...(external === undefined ? [] : [external])])
      const iterator = node.#subscribeViewChanges(view, signal)
      const close = (): void => {
        signal.removeEventListener('abort', close)
        // Abort wakes an idle next; return also releases a paused generator.
        void iterator.return().catch(() => undefined)
      }
      signal.addEventListener('abort', close, { once: true })
      if (signal.aborted) close()
      return {
        async next() {
          if (signal.aborted) return { done: true as const, value: undefined }
          const result = await iterator.next()
          if (result.done) controller.abort()
          return signal.aborted ? { done: true as const, value: undefined } : result
        },
        async return() {
          // An async generator's return cannot interrupt its pending next.
          controller.abort(); await iterator.return()
          return { done: true as const, value: undefined }
        },
        async throw(error: unknown) {
          controller.abort(error); await iterator.return(); throw error
        },
      }
    } }
  }

  async *#subscribeViewChanges(view: 'local' | 'final', signal: AbortSignal): AsyncGenerator<ViewChange, void> {
    let previous: ViewChange | undefined
    while (!this.#closed && !signal.aborted) {
      const version = this.#applicationChanges.version
      const current = await this.#mutex.run(() => ({ view,
        revision: this.#viewRevision(view, view === 'final' ? this.finalRevision : this.materializedRevision,
          view === 'final' ? this.finalOrderLength : this.orderLength),
        finalRevision: this.#viewRevision('final', this.finalRevision, this.finalOrderLength) }))
      if (this.#closed || signal.aborted) return
      if (current.revision !== previous?.revision || current.finalRevision !== previous?.finalRevision) {
        previous = current
        yield { ...current }
      }
      await this.#applicationChanges.wait(version, signal)
    }
  }

  async *#subscribeEvents(options: EventReadOptions & { readonly signal?: AbortSignal }): AsyncIterable<EventBatch> {
    let cursor = options.cursor
    while (!this.#closed && options.signal?.aborted !== true) {
      // Capture before reading: no catch-up/live gap and no event queue.
      const version = this.#applicationChanges.version
      const batch = await this.events.read({ ...options, ...(cursor === undefined ? {} : { cursor }) })
      if (batch.scannedThrough !== cursor) { cursor = batch.scannedThrough; yield batch }
      if (!batch.hasMore) await this.#applicationChanges.wait(version, options.signal)
    }
  }

  #applicationHistoryId(): string {
    const policy = this.#options.historyPolicy
    return `${bytesToHex(this.groupId)}/${bytesToHex(this.executionManifestDigest)}/${policy?.kind === 'coordinated' ? this.#finalityHistoryId() : 'peer'}`
  }

  #viewRevision(view: 'local' | 'final', revision: bigint, orderLength: number): string {
    // Pending admissions and transport progress never rename an applied view.
    return bytesToBase64Url(encodeCanonicalCbor(['chronolog/view/v2', this.#applicationHistoryId(), view, revision, BigInt(orderLength)]))
  }

  #eventSnapshot(applied: MaterializedApplicationSnapshot): EventHistorySnapshot {
    const historyId = this.#applicationHistoryId()
    const revision = this.#viewRevision(applied.view, applied.revision, applied.orderLength)
    const itemAt = (index: number): EventHistoryItem | null => {
      const entry = applied.transactionAt(index)
      if (entry === null) return null
      // The published materialization retains the original verified canonical
      // proposal. Reopening or pending control replay cannot change this view.
      const core = decodeTransactionCore(entry.canonicalCandidate)
      return { anchor: this.#idKey(entry.txId), proposalId: new TextDecoder().decode(entry.txId),
        program: core.program, outcome: entry.outcome, origin: {
          kind: 'chronolog', groupId: bytesToBase64Url(core.groupId), authorId: bytesToHex(core.authorId),
          operationId: core.operationId, authorTimestampMs: core.authorTimestampMs.toString(),
          membershipRevision: bytesToBase64Url(core.membershipRevision),
          writerCapability: core.writerCapability === undefined ? null : bytesToBase64Url(core.writerCapability),
        } }
    }
    return { historyId: applied.view === 'local' ? `${historyId}/local/${revision}` : historyId,
      revision, length: applied.orderLength, itemAt }
  }

  /** Permanently stops old-revision admission before publishing its signed promise. */
  async closeGovernanceRevision(previous: Uint8Array, next: Uint8Array): Promise<TransportRecord> {
    if (this.historyPolicy !== 'peer' || this.#options.validator === undefined) throw new Error('NODE_NOT_VALIDATOR')
    return this.#mutex.run(async () => {
      const capability = this.#validatorCapability()
      if (capability === undefined) throw new Error('NODE_VALIDATOR_CAPABILITY_UNAVAILABLE')
      return this.#validatorClosures.close(previous, next, capability, BigInt(Math.trunc(this.#clockNow())))
    })
  }

  /** Re-evaluates records that were waiting for governance or historical keys. */
  async refreshMembership(): Promise<void> {
    if (!this.#started || this.#closed) return
    try {
      for (const record of [...this.#retryRecords.values()]) await this.ingest(record)
      await this.#mutex.run(async () => {
      for (const candidate of this.#control.listCandidates()) {
        const core = this.#candidateCores.get(this.#idKey(candidate.txId))
        if (core === undefined || !isAdmissionPending(candidate.state) || this.historyPolicy !== 'peer') continue
        await this.#evaluateAdmission(candidate.txId, core)
        await this.#maybeAttest(candidate.txId, candidate, core)
      }
      this.#materializationPending = true
      await this.#reconcileMaterializer()
      })
    } catch (error) {
      this.#recordError(error)
      this.#scheduleMaterializationRetry()
    }
  }

  #decodePreparedTransaction(bytes: Uint8Array): { canonical: Uint8Array; envelope: Uint8Array } {
    const value = assertCanonicalCbor(bytes)
    if (!Array.isArray(value) || value.length !== 2 || !(value[0] instanceof Uint8Array) || !(value[1] instanceof Uint8Array)) {
      throw new Error('PREPARED_TRANSACTION_INVALID')
    }
    return { canonical: value[0], envelope: value[1] }
  }

  async #applyPreparedTransaction(bytes: Uint8Array): Promise<void> {
    const { canonical, envelope } = this.#decodePreparedTransaction(bytes)
    const core = decodeTransactionCore(canonical)
    const previous = (await this.#options.transport.history()).find((record) =>
      record.author === this.#options.transport.identity && equalBytes(record.payload, envelope))
    const record = previous ?? await this.#options.transport.publish(envelope, { timestampMs: Number(core.authorTimestampMs) })
    if (previous !== undefined) await this.#options.transport.ensurePublished?.(record)
    await this.ingest(record)
  }

  async #prepareTransaction(input: PublishTransactionInput): Promise<Uint8Array> {
    this.#assertReady()
    assertValidChangeProgram(input.program)
    const membershipRevision = input.membershipRevision ?? this.membershipRevision
    const validationPolicy = input.validationPolicy ?? this.validationPolicy
    const allocated = input.authorTimestampMs === undefined && input.nonce === undefined
      ? this.#allocateTransactionContext()
      : {
          authorTimestampMs: input.authorTimestampMs ?? this.#nextAuthorTimestamp(),
          nonce: input.nonce?.slice() ?? this.#randomBytes(32),
        }
    const authorTimestampMs = allocated.authorTimestampMs
    if (authorTimestampMs < 0n || authorTimestampMs > 0x7fff_ffff_ffff_ffffn) {
      throw new Error('AUTHOR_TIMESTAMP_OUT_OF_RANGE')
    }
    if (allocated.nonce.length < 16) throw new Error('TRANSACTION_NONCE_TOO_SHORT')
    if (authorTimestampMs > this.#lastAuthoredTimestampMs) this.#lastAuthoredTimestampMs = authorTimestampMs
    const writerCapability = input.writerCapability ?? this.#membershipState().writerCapability
    const core: TransactionCore = {
      operationId: input.operationId!,
      ...(writerCapability === undefined ? {} : { writerCapability }),
      groupId: this.#options.groupId,
      membershipRevision,
      validationPolicy,
      authorId: this.identity,
      authorTimestampMs,
      nonce: allocated.nonce,
      executionManifestDigest: this.executionManifestDigest,
      program: input.program,
      ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
    }
    const canWrite = await this.#options.membership.canWrite({
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
    })
    if (!canWrite) throw new Error('WRITER_UNAUTHORIZED')
    if (!await this.#membershipAllowsTransportAuthor(
      this.#options.transport.identity,
      'writer',
      core.authorId,
      core.membershipRevision,
      undefined,
      core.writerCapability,
    )) throw new Error('LOCAL_TRANSPORT_AUTHOR_UNAUTHORIZED')
    const canonical = encodeTransactionCore(core)
    const envelope = await encodeSignedEnvelope(this.#groupRoute(), 'candidate', canonical, this.#options.identity, this.#options.envelopeCipher)
    return encodeCanonicalCbor([canonical, envelope])
  }

  validateProgram(program: ChangeProgram): void {
    assertValidChangeProgram(program)
  }

  async publishHeartbeat(): Promise<void> {
    this.#assertReady()
    const validator = this.#options.validator
    if (!validator) throw new Error('NODE_NOT_VALIDATOR')
    const validatorCapability = this.#validatorCapability()
    if (validatorCapability === undefined) throw new Error('NODE_VALIDATOR_CAPABILITY_UNAVAILABLE')
    if (!await this.#heartbeatAuthorized({
      groupId: this.#options.groupId,
      membershipRevision: this.membershipRevision,
      validatorId: this.identity,
      validatorCapability,
    })) throw new Error('VALIDATOR_UNAUTHORIZED')
    if (!await this.#membershipAllowsTransportAuthor(
      this.#options.transport.identity,
      'validator',
      this.identity,
      this.membershipRevision,
      validatorCapability,
    )) throw new Error('LOCAL_TRANSPORT_AUTHOR_UNAUTHORIZED')
    const now = this.#clockNow()
    this.#advanceValidatorCutoff(now)
    this.#persistValidatorCutoff()
    const heartbeat: ValidatorHeartbeat = {
      groupId: this.#options.groupId,
      membershipRevision: this.membershipRevision,
      validatorCapability,
      validatorId: this.identity,
      acceptanceCutoffMs: this.#acceptedAboveMs,
    }
    const payload = encodeValidatorHeartbeat(heartbeat)
    const envelope = await encodeSignedEnvelope(this.#groupRoute(), 'heartbeat', payload, this.#options.identity, this.#options.envelopeCipher)
    const record = await this.#options.transport.publish(envelope, { timestampMs: now })
    await this.ingest(record)
  }

  async ingest(record: TransportRecord): Promise<void> {
    await this.#mutex.run(async () => {
      if (this.#seen.has(record.id)) return
      this.#setConsumerPhase('ingesting')
      let coordinatedCandidate = false
      try {
        const continuity = this.#feedForks.observe(record)
        if (continuity === 'discarded') {
          // A repaired losing branch has been handled, but it is not a record
          // in the trusted feed prefix consumed by the admission index.
          this.#seen.add(record.id)
          return
        }
        if (continuity === 'quarantined') {
          const error = new Error(`FEED_FORK_QUARANTINED:${record.author}`)
          this.#seen.add(record.id)
          this.#recordError(error)
          return
        }
        let envelope: ReturnType<typeof decodeEnvelope>
        try { envelope = decodeEnvelope(record.payload) } catch { invalid('NODE_ENVELOPE_INVALID') }
        if (envelope.messageType !== 'candidate' && envelope.messageType !== 'attestation' && envelope.messageType !== 'heartbeat') {
          this.#markSeen(record)
          return
        }
        coordinatedCandidate = envelope.messageType === 'candidate' && this.historyPolicy === 'coordinated'
        const wire = await this.#decodeRecord(record)
        if (wire.type === 'candidate') await this.#ingestCandidate(record, wire.payload, wire.signer)
        else if (wire.type === 'attestation') await this.#ingestAttestation(record, wire.payload, wire.signer)
        else await this.#ingestHeartbeat(record, wire.payload, wire.signer)
        this.#markSeen(record)
        this.#retryRecords.delete(record.id)
        if (this.#retryRecords.size === 0 && !this.#retryOverflow) this.#ingestionError = undefined
      } catch (error) {
        if (coordinatedCandidate && error instanceof Error && error.message === WIRE_ENCRYPTION_EPOCH_UNAVAILABLE) {
          // The certified path owns this candidate's retry and decides whether
          // its epoch was issued. An unordered hint needs no second key wait.
          this.#markSeen(record)
          this.#retryRecords.delete(record.id)
          if (this.#retryRecords.size === 0 && !this.#retryOverflow) this.#ingestionError = undefined
        } else if (error instanceof TerminalIngestError || error instanceof ControlStoreConflictError) {
          this.#markSeen(record)
          this.#retryRecords.delete(record.id)
          if (error instanceof ControlStoreConflictError) this.#recordError(error)
          else this.#emit('error', undefined, error)
        } else {
          if (this.#retryRecords.has(record.id) || this.#retryRecords.size < this.#maximumRetryRecords) {
            this.#retryRecords.set(record.id, structuredClone(record))
          } else {
            // Keep memory bounded. Once capacity becomes available, the
            // authoritative transport history supplies records that could not
            // be retained in this process-local retry set.
            this.#retryOverflow = true
          }
          this.#scheduleIngestionRetry()
          this.#recordIngestionError(error)
        }
      }
    })
  }

  localSql(
    sql: string,
    parameters: readonly MaterializedLocalSqlValue[] = [],
    options?: Parameters<ChronologNodeOptions['materialization']['queries']['localSql']>[2],
  ): MaterializedLocalSqlResult {
    return this.#materializerLocalSql(sql, parameters, options)
  }

  outcome(txId: Uint8Array): MaterializedTransactionOutcome | null {
    const outcome = this.#options.materialization.queries.outcome(txId)
    if (outcome !== null) return outcome
    const candidate = this.#control.getCandidate(txId)
    if ((candidate?.state === 'unauthorized' || candidate?.state === 'inadmissible') && this.isFinal(txId)) return {
      txId: candidate.txId, orderKey: candidate.orderKey, orderIndex: -1,
      outcome: 'rejected', rejectionCode: candidate.stateReason ?? 'WRITER_UNAUTHORIZED', failingStatementIndex: null,
    }
    return null
  }

  isFinal(txId: Uint8Array): boolean {
    const candidate = this.#control.getCandidate(txId)
    if (candidate?.state === 'inadmissible' ||
        this.historyPolicy === 'peer' && candidate?.state === 'unauthorized') {
      // These authenticated proposals are permanently excluded from admission.
      // Missing governance is retryable ingestion, never an authorization denial.
      return this.#options.materialization.queries.outcome(txId) === null
    }
    if (this.historyPolicy === 'coordinated') {
      const position = this.#canonicalPositions.get(this.#idKey(txId))
      if (candidate?.state === 'unauthorized') {
        return position !== undefined && position <= this.#coordinatedAppliedThrough &&
          (candidate.stateReason === 'FINALITY_TIMESTAMP_FUTURE' ||
            candidate.orderKey.authorTimestampMs <= this.#appliedClosedThroughMs)
      }
    }
    const outcome = this.#options.materialization.queries.outcome(txId)
    return outcome !== null && outcome.orderIndex >= 0 && outcome.orderIndex < this.finalOrderLength
  }

  async finalTarget(): Promise<Uint8Array> {
    const policy = this.#options.historyPolicy
    if (policy?.kind === 'coordinated') {
      const closure = policy.policy.snapshot().closures.find((item) => item.includedThrough === this.#coordinatedAppliedThrough)
      return encodeCanonicalCbor([4n, this.groupId, 'chronological', this.#finalityHistoryId(),
        BigInt(this.#coordinatedAppliedThrough), closure?.includedRoot ?? await orderedGenesisRoot(this.#finalityHistoryId()),
        this.#appliedClosedThroughMs])
    }
    const length = this.finalOrderLength
    return encodeCanonicalCbor([2n, this.groupId, this.historyPolicy, BigInt(length), await this.#appliedPrefixDigest(length),
      null, null,
    ])
  }

  async isFinalTargetApplied(frontier: Uint8Array): Promise<boolean> {
    const value = assertCanonicalCbor(frontier)
    const policy = this.#options.historyPolicy
    if (policy?.kind === 'coordinated') {
      if (!Array.isArray(value) || value.length !== 7 || value[0] !== 4n || !(value[1] instanceof Uint8Array) ||
          !equalBytes(value[1], this.groupId) || value[2] !== 'chronological' || value[3] !== this.#finalityHistoryId() ||
          typeof value[4] !== 'bigint' || value[4] < 0n || value[4] > BigInt(this.#coordinatedAppliedThrough) ||
          typeof value[5] !== 'string' || typeof value[6] !== 'bigint' || value[6] > this.#appliedClosedThroughMs) return false
      const closure = policy.policy.snapshot().closures.find((item) => item.includedThrough === Number(value[4]) && item.closedThroughMs === value[6])
      const root = closure?.includedRoot ?? (value[4] === 0n && value[6] === -1n ? await orderedGenesisRoot(this.#finalityHistoryId()) : null)
      return root === value[5]
    }
    if (!Array.isArray(value) || value.length !== 7 || value[0] !== 2n || !(value[1] instanceof Uint8Array) ||
        !equalBytes(value[1], this.groupId) || value[2] !== this.historyPolicy || typeof value[3] !== 'bigint' ||
        value[3] < 0n || value[3] > BigInt(this.finalOrderLength) || !(value[4] instanceof Uint8Array)) return false
    if (value[5] !== null || value[6] !== null) return false
    return equalBytes(await this.#appliedPrefixDigest(Number(value[3])), value[4])
  }

  #appliedPrefixDigest(length: number): Promise<Uint8Array> {
    const ids = Array.from({ length }, (_, index) => {
      const id = this.#options.materialization.queries.proposalIdAt(index)
      if (id === null) throw new Error('MATERIALIZATION_APPLIED_ORDER_MISSING')
      return id
    })
    return sha256(encodeCanonicalCbor(ids))
  }

  async ingestOrderingEvidence(evidence: OrderingEvidence): Promise<void> {
    return this.ingestFinalityEvidence(encodeOrderingEvidence(evidence))
  }

  /** The injected verifier interprets proof bytes; it cannot supply a sorter. */
  async ingestFinalityEvidence(bytes: Uint8Array): Promise<void> {
    if (this.#options.historyPolicy?.kind !== 'coordinated') throw new Error('NODE_HISTORY_POLICY_MISMATCH')
    const policy = this.#options.historyPolicy.policy
    const exact = bytes.slice()
    await this.#mutex.run(async () => {
      await policy.ingestEvidence(exact)
      await this.#options.transport.putEvidence?.(exact)
      const snapshot = policy.snapshot()
      // Exact proof replays and open receipt growth cannot change an already
      // applied closed prefix. Pending bodies, keys or publication failures
      // still need reconciliation even when the verified frontier is unchanged.
      if (!this.#materializationPending && snapshot.closedReceiptThrough === this.#coordinatedAppliedThrough &&
          snapshot.closedThroughMs === this.#appliedClosedThroughMs) return
      this.#materializationPending = true
      await this.#reconcileMaterializer()
    })
  }

  async #consumeEvidence(): Promise<void> {
    const subscribe = this.#options.transport.subscribeEvidence?.bind(this.#options.transport)
    if (subscribe === undefined) return
    for await (const item of subscribe(this.#abort.signal)) {
      if (this.#closed) return
      await this.#ingestSharedEvidence(item.bytes)
    }
  }

  async #ingestSharedEvidence(bytes: Uint8Array): Promise<void> {
    try { await this.ingestFinalityEvidence(bytes) }
    catch (error) {
      // Immutable peer storage may contain unrelated or forged evidence. Only
      // validated proofs enter the policy store; invalid bytes cannot poison restart.
      if (error instanceof Error && /^(ORDERING_EVIDENCE_INVALID|HISTORY_(ID_MISMATCH|ID_INVALID|HASH_INVALID|POSITION_INVALID|POSITION_CONFLICT|CERTIFICATE_CONFIGURATION_MISMATCH|CERTIFICATE_SIGNATURE_INVALID)|ORDERED_RECORD_(BYTES_INVALID|TOO_LARGE|DIGEST_MISMATCH|ROOT_MISMATCH))$/u.test(error.message)) return
      this.#recordError(error)
      this.#scheduleMaterializationRetry()
    }
  }

  async #processCoordinatedHistory(): Promise<void> {
    const selected = this.#options.historyPolicy
    if (selected?.kind !== 'coordinated') return
    const snapshot = structuredClone(selected.policy.snapshot())
    if (snapshot.closedThroughMs < this.#appliedClosedThroughMs || snapshot.closedReceiptThrough < this.#coordinatedAppliedThrough) {
      throw new Error('FINALITY_PROVIDER_REGRESSION')
    }
    // Inline controls are causal ledger events. Receipt order is not their
    // activation order, and controls can supply bootstrap keys before bodies.
    const controls = await orderFinalizedGovernanceRecords(snapshot.records
      .filter((item) => item.closureBoundary !== null && !this.#finalizedControls.has(item.entry.position))
      .map((item) => ({ entry: item.entry, cutoffMs: item.closedThroughMs })), this.#groupRoute())
    for (const { entry, cutoffMs } of controls) {
      if (selected.applyGovernanceRecord === undefined) throw new Error('COORDINATED_GOVERNANCE_HANDLER_UNAVAILABLE')
      await selected.applyGovernanceRecord(entry, cutoffMs)
      this.#finalizedControls.add(entry.position)
    }
    type PreparedCandidate = {
      readonly inclusion: IncludedRecord
      readonly record: TransportRecord
      readonly canonical: Uint8Array
      readonly signer: Uint8Array
      readonly decision: FinalityClosureBoundary | null
      readonly rejection: string | undefined
    }
    const proposals = new Map<string, PreparedCandidate[]>()
    for (const inclusion of snapshot.records) {
      const { entry } = inclusion
      if (inclusion.closureBoundary === null || this.#resolvedInclusionRecords.has(entry.position)) continue
      let ledger: LedgerRecord
      try { ledger = decodeLedgerRecord(entry.bytes) }
      catch { this.#resolvedInclusionRecords.add(entry.position); continue }
      if (!equalBytes(ledger.groupRoute, this.#groupRoute())) {
        this.#resolvedInclusionRecords.add(entry.position)
        continue
      }
      if (ledger.kind === 'candidate') {
        // Unknown body/key/execution inputs block progress. They never become
        // rejection evidence, and an inclusion receipt alone is not finality.
        const detached = await this.#options.transport.getPayload(ledger.payloadHash)
        if (detached === null) throw new LedgerRecordError('LEDGER_PAYLOAD_UNAVAILABLE', ledger.payloadHash)
        let payload: Uint8Array
        try { payload = await verifyLedgerPayload(ledger, detached) }
        catch (error) {
          // Metadata is checked only after matching the committed body hash.
          // That contradiction is permanent; a missing or corrupt peer reply
          // remains retryable and cannot make us skip a valid position.
          if (!(error instanceof LedgerRecordError) || error.code !== 'LEDGER_PAYLOAD_METADATA_MISMATCH') throw error
          this.#resolvedInclusionRecords.add(entry.position)
          continue
        }
        if (selected.hasEncryptionEpoch?.(ledger.encryptionEpoch, inclusion.closureBoundary.includedThrough) === false) {
          // A complete finalized control prefix proves this epoch was not
          // issued. No unverified body may manufacture a proposal identity.
          this.#resolvedInclusionRecords.add(entry.position)
          continue
        }
        const record: TransportRecord = {
          id: `included:${entry.historyId}:${entry.position}`, author: '', sequence: 0n,
          receivedAtMs: 0, payload,
        }
        try {
          const wire = await this.#decodeRecord(record)
          const core = this.#decodeCandidate(wire.payload)
          // Invalid alternate signatures must not claim a legitimate proposal's
          // identity while we resolve its independently encrypted envelopes.
          if (!equalBytes(core.groupId, this.groupId)) invalid('CANDIDATE_WRONG_GROUP')
          if (!equalBytes(core.authorId, wire.signer)) invalid('CANDIDATE_SIGNER_MISMATCH')
          try { assertValidChangeProgram(core.program) } catch { invalid('CANDIDATE_SQL_INVALID') }
          const tooFuture = core.authorTimestampMs > inclusion.closureBoundary.closedThroughMs +
            BigInt(selected.futureAdmissionWindowMs ?? 31_000)
          const decision = tooFuture ? inclusion.closureBoundary : snapshot.closures.find(closure =>
            entry.position <= closure.includedThrough && core.authorTimestampMs <= closure.closedThroughMs) ?? null
          if (decision === null && core.authorTimestampMs <= snapshot.closedThroughMs) {
            throw new Error('FINALITY_PROVIDER_CLOSURE_INCOMPLETE')
          }
          const epochStatus = selected.encryptionEpochStatusAt?.(core.authorTimestampMs, ledger.encryptionEpoch)
          const rejection = tooFuture ? 'FINALITY_TIMESTAMP_FUTURE'
            : core.authorTimestampMs <= inclusion.admissionFloorMs ? 'FINALITY_TIMESTAMP_CLOSED'
            : epochStatus === 'closed' || epochStatus === 'unissued' ? 'ENCRYPTION_EPOCH_CLOSED' : undefined
          const proposalId = bytesToHex(await transactionDigest(wire.payload))
          const alternatives = proposals.get(proposalId) ?? []
          alternatives.push({ inclusion, record, canonical: wire.payload, signer: wire.signer, decision, rejection })
          proposals.set(proposalId, alternatives)
          continue
        } catch (error) {
          // A known invalid record occupies its fixed position without stealing
          // a valid proposal identity. Missing keys/engines/storage still block.
          if (!(error instanceof TerminalIngestError)) throw error
        }
      }
      this.#resolvedInclusionRecords.add(entry.position)
    }
    // A signed proposal may have several legitimate encrypted envelopes. Its
    // first decision batch is the first closure covering inclusion AND author
    // time, or its first inclusion closure for an excessive future timestamp.
    // Resolve that whole immutable batch before changing admission: a
    // stale wrapping must not win merely because the provider received it first.
    for (const [, alternatives] of [...proposals].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
      const decided = alternatives.filter(item => item.decision !== null)
      if (decided.length === 0) {
        // Membership may still change before this future timestamp closes.
        const pending = alternatives[0]!
        await this.#ingestCandidate(pending.record, pending.canonical, pending.signer)
        continue
      }
      const firstDecision = decided.reduce((minimum, item) => Math.min(minimum, item.decision!.position), Number.MAX_SAFE_INTEGER)
      const eligible = decided.filter(item => item.decision!.position === firstDecision)
      eligible.sort((left, right) => Number(left.rejection !== undefined) - Number(right.rejection !== undefined) ||
        (left.inclusion.entry.recordId < right.inclusion.entry.recordId ? -1 : left.inclusion.entry.recordId > right.inclusion.entry.recordId ? 1 : 0))
      const representative = eligible[0]!
      await this.#ingestCandidate(representative.record, representative.canonical, representative.signer,
        representative.inclusion.entry.position, representative.rejection)
      for (const alternative of alternatives) this.#resolvedInclusionRecords.add(alternative.inclusion.entry.position)
    }
    this.#coordinatedProcessed = snapshot.closedReceiptThrough
    this.#processedClosedThroughMs = snapshot.closedThroughMs
  }

  outcomeChangedByReplay(txId: Uint8Array): boolean {
    return this.#replayedOutcomes.has(this.#idKey(txId))
  }

  candidate(txId: Uint8Array): StoredCandidate | null {
    return this.#control.getCandidate(txId)
  }

  candidateCore(txId: Uint8Array): TransactionCore | null {
    return structuredClone(this.#candidateCores.get(this.#idKey(txId)) ?? null)
  }

  async settlementEvidence(txId: Uint8Array): Promise<SettlementEvidence | null> {
    return this.#mutex.run(async () => {
      const candidate = this.#control.getCandidate(txId), core = this.candidateCore(txId)
      if (candidate === null || core === null) return null
      const policy = await this.#options.membership.watermarkPolicy?.(core)
      if (!policy) return null
      const frontier = await this.#liveFinalityFrontier()
      return { txId: candidate.txId, candidateState: candidate.state, orderKey: candidate.orderKey,
        proofAttestationIds: candidate.proofAttestationIds,
        watermark: this.#control.watermark(policy, core.membershipRevision), frontier,
        belowWatermark: frontier.closedThroughMs !== null && core.authorTimestampMs <= frontier.closedThroughMs,
        unresolvedAttestationIds: frontier.blockers.filter(item => item.authorTimestampMs <= core.authorTimestampMs)
          .flatMap(item => item.attestationIds),
      }
    })
  }

  /** Live consensus proof progress; application finality additionally requires replay publication. */
  async liveFinality(): Promise<LiveFinalityFrontier> {
    return this.#mutex.run(() => this.#liveFinalityFrontier())
  }

  async #liveFinalityFrontier(): Promise<LiveFinalityFrontier> {
    const selected = this.#options.historyPolicy
    if (selected?.kind === 'coordinated') {
      const snapshot = selected.policy.snapshot()
      return { mode: 'live', checkpointId: snapshot.checkpointId,
        provenThroughMs: snapshot.closedThroughMs < 0n ? null : snapshot.closedThroughMs,
        closedThroughMs: this.#processedClosedThroughMs < 0n ? null : this.#processedClosedThroughMs,
        blockers: [], excludedProposalIds: [],
      }
    }
    if (this.#retryRecords.size > 0 || this.#retryOverflow || this.#feedForks.quarantined()) {
      return { mode: 'live', provenThroughMs: null, closedThroughMs: null, blockers: [], excludedProposalIds: [] }
    }
    const verifiedHeartbeatIds = new Set<string>()
    for (const heartbeat of this.#control.listHeartbeats()) {
      const record = await this.#options.transport.get(new TextDecoder().decode(heartbeat.heartbeatId))
      if (record === undefined || !this.#isPrefixApplied(record.author, record.sequence) || !await this.#isFeedContiguous(record)) continue
      verifiedHeartbeatIds.add(this.#idKey(heartbeat.heartbeatId))
      if (!heartbeat.feedContiguous) this.#control.recordHeartbeat({ ...heartbeat, feedContiguous: true })
    }
    return evaluatePeerLiveFinality({
      groupId: this.#options.groupId, membership: this.#options.membership,
      control: this.#control, candidateCores: this.#candidateCores, verifiedHeartbeatIds,
      closedRevisions: this.#options.peerGovernance?.closedAdmissionRevisions() ?? [],
      isPrefixApplied: (author, sequence) => this.#isPrefixApplied(author, sequence),
      isValidAdmissionProof: (candidate, core, proof) => this.#isValidAdmissionProof(candidate, core, proof),
    })
  }

  async watermark(txId?: Uint8Array): Promise<WatermarkEvidence | null> {
    const candidate = txId === undefined
      ? this.#control.orderedCandidates().at(-1)
      : this.#control.getCandidate(txId)
    if (!candidate) return null
    const core = this.candidateCore(candidate.txId)
    if (!core) return null
    const policy = await this.#options.membership.watermarkPolicy?.(core)
    return policy ? this.#control.watermark(policy, core.membershipRevision) : null
  }

  revisions(afterRevision = 0n, signal?: AbortSignal): AsyncIterable<NodeRevisionEvent> {
    const source = this.#events.subscribe(signal === undefined ? {} : { signal })
    return {
      async *[Symbol.asyncIterator]() {
        for await (const event of source) {
          if (event.revision > afterRevision) yield event
        }
      },
    }
  }

  async status(): Promise<NodeStatus> {
    const error = this.#lastError ?? this.#materializationError ?? this.#ingestionError
    const candidates = this.#control.listCandidates()
    const status: NodeStatus = {
      historyPolicy: this.historyPolicy, finalOrderLength: this.finalOrderLength, finalRevision: this.finalRevision,
      started: this.#started,
      closed: this.#closed,
      eventSetRevision: this.#revision,
      candidates: candidates.length,
      admitted: candidates.filter(candidate => candidate.state === 'admissible').length,
      processedTransportRecords: this.#seen.size,
      materializationPending: this.#materializationPending,
      materializedRevision: this.#options.materialization.queries.revision,
      orderLength: this.#options.materialization.queries.orderLength,
      executionManifestDigest: this.executionManifestDigest,
      validating: this.#options.validator !== undefined,
      transport: await this.#options.transport.status(),
      quarantinedFeeds: this.#feedForks.quarantineEvidence().map((item) => item.feedId),
      ingest: {
        phase: this.#consumerPhase,
        phaseAgeMs: Date.now() - this.#consumerPhaseSince,
        subscriptionRestarts: this.#subscriptionRestarts,
        retryRecords: this.#retryRecords.size,
      },
      ...(error === undefined ? {} : { lastError: error.message }),
    }
    return status
  }

  async isWritable(): Promise<boolean> {
    if (this.#feedForks.quarantined()) return false
    const writerCapability = this.#membershipState().writerCapability
    return this.#options.membership.canWrite({
      ...(writerCapability === undefined ? {} : { writerCapability }),
      groupId: this.#options.groupId,
      membershipRevision: this.membershipRevision,
      validationPolicy: this.validationPolicy,
      writerId: this.identity,
    })
  }

  async waitForIdle(): Promise<void> {
    if (this.historyPolicy === 'coordinated') {
      for (const evidence of await this.#options.transport.evidenceHistory?.() ?? []) {
        await this.#ingestSharedEvidence(evidence.bytes)
      }
    }
    await this.#mutex.run(async () => {
      if (this.#materializationPending) await this.#reconcileMaterializer()
    })
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    this.#abort.abort()
    if (this.#heartbeatTimer) clearInterval(this.#heartbeatTimer)
    if (this.#stallWatchdog) clearInterval(this.#stallWatchdog)
    if (this.#materializationDebounceTimer) clearTimeout(this.#materializationDebounceTimer)
    if (this.#materializationRetryTimer) clearTimeout(this.#materializationRetryTimer)
    if (this.#ingestionRetryTimer) clearTimeout(this.#ingestionRetryTimer)
    await this.#consumeTask?.catch(() => {})
    await this.#evidenceTask?.catch(() => {})
    await this.#mutex.run(async () => {
      if (!this.#materializationPending) return
      try { await this.#reconcileMaterializer() } catch (error) { this.#recordError(error) }
    })
    this.#control.flush()
    this.#events.close()
    this.#applicationChanges.close()
    await this.#options.materialization.close()
    await this.#options.transport.close()
  }

  async #drainHistory(history: readonly TransportRecord[]): Promise<void> {
    for (const record of history) await this.ingest(record)
  }

  /**
   * Follows the transport until the node closes. A transport may end a
   * subscription early, for example when this consumer falls more than the
   * subscriber buffer behind during a replication burst; the node then
   * subscribes again. A new subscription replays history first and already
   * ingested records are skipped, so nothing is lost or applied twice.
   */
  async #consume(): Promise<void> {
    while (!this.#abort.signal.aborted) {
      try {
        this.#setConsumerPhase('waiting-for-record')
        this.#subscriptionAbort = new AbortController()
        const subscriptionSignal = AbortSignal.any([this.#abort.signal, this.#subscriptionAbort.signal])
        for await (const record of this.#options.transport.subscribe(subscriptionSignal)) {
          this.#setConsumerPhase('waiting-for-ingest-lock')
          await this.ingest(record)
          this.#setConsumerPhase('waiting-for-record')
        }
        if (this.#abort.signal.aborted) return
        this.#subscriptionRestarts += 1
      } catch (error) {
        if (this.#abort.signal.aborted) return
        this.#subscriptionRestarts += 1
        if (this.#subscriptionAbort?.signal.aborted) continue
        this.#recordError(error)
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 1_000)
          timer.unref?.()
          this.#abort.signal.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
        })
      }
    }
  }

  async #ingestCandidate(record: TransportRecord, canonical: Uint8Array, signer: Uint8Array, canonicalPosition?: number,
    canonicalRejection?: string): Promise<void> {
    const core = this.#decodeCandidate(canonical)
    if (!equalBytes(core.groupId, this.#options.groupId)) invalid('CANDIDATE_WRONG_GROUP')
    if (!equalBytes(core.authorId, signer)) invalid('CANDIDATE_SIGNER_MISMATCH')
    if (this.historyPolicy === 'peer' && !await this.#canUseTransportAuthor(record, 'writer', signer, core.membershipRevision, undefined, core.writerCapability)) {
      invalid('CANDIDATE_TRANSPORT_AUTHOR_UNAUTHORIZED')
    }
    const foreignProfile = !equalBytes(core.executionManifestDigest, this.executionManifestDigest)
    if (foreignProfile && canonicalPosition === undefined) {
      // A coordinated history already pins this runtime's immutable profile.
      // Defer a raw feed proposal until its certified position can record a
      // final rejection, without leaving an unresolvable feed retry behind.
      if (this.historyPolicy === 'coordinated') return
      throw new Error('CANDIDATE_EXECUTION_MANIFEST_UNAVAILABLE')
    }
    try { assertValidChangeProgram(core.program) } catch { invalid('CANDIDATE_SQL_INVALID') }
    const writerContext = {
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
    }
    const candidateDigest = await transactionDigest(canonical)
    const txId = utf8(`tx_${bytesToHex(candidateDigest)}`)
    if (canonicalPosition !== undefined && !this.#canonicalPositions.has(this.#idKey(txId))) this.#canonicalPositions.set(this.#idKey(txId), canonicalPosition)
    const existing = this.#control.getCandidate(txId)
    this.#candidateCores.set(this.#idKey(txId), core)
    if (existing !== null && (!isAdmissionPending(existing.state) || (this.historyPolicy === 'coordinated' && canonicalPosition === undefined))) return
    const canWrite = canonicalRejection !== undefined || (this.historyPolicy === 'coordinated' && canonicalPosition === undefined)
      ? true : await this.#options.membership.canWrite({ ...writerContext,
        ...(canonicalPosition === undefined ? {} : { finalityClosed: true }) })
    const rejection = canonicalRejection ?? (canWrite ? foreignProfile ? 'EXECUTION_PROFILE_MISMATCH' : undefined : 'WRITER_UNAUTHORIZED')
    const authorized = rejection === undefined
    const state = authorized ? 'pending_validation' as const : 'unauthorized' as const
    const candidate: StoredCandidate = {
      txId,
      groupId: core.groupId,
      candidateDigest,
      validationPolicy: core.validationPolicy,
      orderKey: transactionOrderKey(core, { authorFeedSequence: 0n, txId }),
      canonicalPayload: canonical,
      state,
      ...(rejection === undefined ? {} : { stateReason: rejection }),
      proofAttestationIds: [],
    }
    const inserted = existing === null ? this.#control.putCandidate(candidate) : { added: false }
    if (existing !== null && rejection !== undefined) this.#control.setCandidateState(txId, 'unauthorized', { reason: rejection })
    this.#candidateCores.set(this.#idKey(txId), core)
    if (inserted.added) this.#emit('candidate', txId)
    if (authorized && this.historyPolicy === 'coordinated') {
      if (canonicalPosition !== undefined) {
        this.#control.setCandidateState(txId, 'admissible')
        this.#materializationPending = true
      }
      return
    }
    if (authorized) {
      await this.#evaluateAdmission(txId, core)
      this.#setConsumerPhase('attesting')
      await this.#maybeAttest(txId, candidate, core)
    }
  }

  async #maybeAttest(txId: Uint8Array, candidate: StoredCandidate, core: TransactionCore): Promise<void> {
    const validator = this.#options.validator
    if (!validator) return
    if (this.#validatorClosures.isClosed(core.membershipRevision)) return
    const validatorCapability = this.#validatorCapability()
    if (validatorCapability === undefined) return
    const now = this.#clockNow()
    // The advanced cutoff only becomes a commitment once it is signed, so it
    // is persisted just before signing. Persisting here for every candidate
    // fsynced once per record during history replay (seconds per restart).
    this.#advanceValidatorCutoff(now)
    const futureLimit = BigInt(Math.trunc(now)) + BigInt(validator.maxFutureSkewMs ?? 30_000)
    if (core.authorTimestampMs > futureLimit || core.authorTimestampMs <= this.#acceptedAboveMs) return
    const context = {
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
      validatorId: this.identity,
      validatorCapability,
    }
    if (!await this.#options.membership.canValidate(context)) return
    if (!await this.#membershipAllowsTransportAuthor(
      this.#options.transport.identity,
      'validator',
      this.identity,
      core.membershipRevision,
      validatorCapability,
    )) throw new Error('LOCAL_TRANSPORT_AUTHOR_UNAUTHORIZED')
    if (this.#control.attestationsFor(txId).some((item) => equalBytes(item.validatorId, this.identity))) return
    const policyVersion = await this.#expectedPolicyVersion(core)
    if (policyVersion < 0n) return
    const configuredPolicyVersion = validator.policyVersion ?? policyVersion
    if (configuredPolicyVersion !== policyVersion) throw new Error('VALIDATOR_POLICY_VERSION_MISMATCH')
    this.#persistValidatorCutoff()
    const attestation: ValidatorAttestation = {
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validatorCapability,
      txId,
      validatorId: this.identity,
      authorTimestampMs: core.authorTimestampMs,
      acceptedAboveMs: this.#acceptedAboveMs,
      candidateDigest: candidate.candidateDigest,
      decision: 'admit',
      policyVersion,
    }
    const payload = encodeValidatorAttestation(attestation)
    const envelope = await encodeSignedEnvelope(this.#groupRoute(), 'attestation', payload, this.#options.identity, this.#options.envelopeCipher)
    // Publishing before returning is the validator durability rule. The newly
    // appended record is handled by the normal subscription path.
    this.#setConsumerPhase('publishing-attestation')
    await this.#options.transport.publish(envelope, { timestampMs: now })
  }

  async #ingestAttestation(record: TransportRecord, encoded: Uint8Array, signer: Uint8Array): Promise<void> {
    const value = this.#decodeAttestation(encoded)
    if (!equalBytes(value.groupId, this.#options.groupId)) invalid('ATTESTATION_WRONG_GROUP')
    if (!equalBytes(value.validatorId, signer)) invalid('ATTESTATION_SIGNER_MISMATCH')
    if (!await this.#canUseTransportAuthor(
      record,
      'validator',
      signer,
      value.membershipRevision,
      value.validatorCapability,
    )) invalid('ATTESTATION_TRANSPORT_AUTHOR_UNAUTHORIZED')
    if (
      equalBytes(value.validatorId, this.identity) &&
      record.author === this.#options.transport.identity &&
      value.acceptedAboveMs > this.#acceptedAboveMs
    ) {
      this.#acceptedAboveMs = value.acceptedAboveMs
      this.#persistValidatorCutoff()
    }
    const core = this.#candidateCores.get(this.#idKey(value.txId))
    const stored: StoredAttestation = {
      attestationId: utf8(record.id),
      txId: value.txId,
      validatorId: value.validatorId,
      validatorCapability: value.validatorCapability,
      membershipRevision: value.membershipRevision,
      candidateDigest: value.candidateDigest,
      validatorFeedSequence: record.sequence,
      authorTimestampMs: value.authorTimestampMs,
      acceptedAboveMs: value.acceptedAboveMs,
      policyVersion: value.policyVersion,
      transportAuthor: record.author,
    }
    const inserted = this.#control.putAttestation(stored)
    if (inserted.added) this.#emit('attestation', value.txId)
    if (core) await this.#evaluateAdmission(value.txId, core)
    this.#materializationPending = true
    this.#scheduleMaterialization()
  }

  async #evaluateAdmission(txId: Uint8Array, core: TransactionCore): Promise<void> {
    const candidate = this.#control.getCandidate(txId)
    if (!candidate || !isAdmissionPending(candidate.state)) return
    const context = {
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
    }
    const threshold = await this.#options.membership.threshold(context)
    if (!Number.isSafeInteger(threshold) || threshold < 1) throw new Error('INVALID_VALIDATION_THRESHOLD')
    const eligible: StoredAttestation[] = []
    const validators = new Set<string>()
    for (const attestation of this.#control.attestationsFor(txId)) {
      const key = this.#idKey(attestation.validatorId)
      if (validators.has(key) || !await this.#isValidAdmissionProof(candidate, core, attestation)) continue
      validators.add(key)
      eligible.push(attestation)
    }
    const customSelection = await this.#options.membership.selectAdmission?.(
      context,
      eligible,
    )
    if (customSelection !== undefined) {
      if (customSelection.length === 0) return
      const available = new Set(eligible.map((item) => this.#idKey(item.attestationId)))
      if (customSelection.some((item) => !available.has(this.#idKey(item.attestationId)))) {
        throw new Error('MEMBERSHIP_RESOLVER_RETURNED_UNKNOWN_ATTESTATION')
      }
      this.#control.setCandidateState(txId, 'admissible', {
        proofAttestationIds: customSelection.map((item) => item.attestationId),
      })
      this.#materializationPending = true
      this.#scheduleMaterialization()
      return
    }
    if (eligible.length < threshold) return
    this.#control.setCandidateState(txId, 'admissible', {
      proofAttestationIds: eligible.slice(0, threshold).map((item) => item.attestationId),
    })
    this.#materializationPending = true
    this.#scheduleMaterialization()
  }

  async #ingestHeartbeat(record: TransportRecord, encoded: Uint8Array, signer: Uint8Array): Promise<void> {
    const heartbeat = this.#decodeHeartbeat(encoded)
    if (!equalBytes(heartbeat.groupId, this.#options.groupId)) invalid('HEARTBEAT_WRONG_GROUP')
    if (!equalBytes(heartbeat.validatorId, signer)) invalid('HEARTBEAT_SIGNER_MISMATCH')
    if (!await this.#canUseTransportAuthor(
      record,
      'validator',
      signer,
      heartbeat.membershipRevision,
      heartbeat.validatorCapability,
    )) invalid('HEARTBEAT_TRANSPORT_AUTHOR_UNAUTHORIZED')
    const heartbeatAuthorized = await this.#heartbeatAuthorized({
      groupId: heartbeat.groupId,
      membershipRevision: heartbeat.membershipRevision,
      validatorId: heartbeat.validatorId,
      validatorCapability: heartbeat.validatorCapability,
    })
    if (!heartbeatAuthorized) invalid('HEARTBEAT_VALIDATOR_UNAUTHORIZED')
    if (equalBytes(heartbeat.validatorId, this.identity) && heartbeat.acceptanceCutoffMs > this.#acceptedAboveMs) {
      this.#acceptedAboveMs = heartbeat.acceptanceCutoffMs
      this.#persistValidatorCutoff()
    }
    const recorded = this.#control.recordHeartbeat({
      heartbeatId: utf8(record.id),
      validatorId: heartbeat.validatorId,
      validatorCapability: heartbeat.validatorCapability,
      membershipRevision: heartbeat.membershipRevision,
      validatorFeedSequence: record.sequence,
      acceptanceCutoffMs: heartbeat.acceptanceCutoffMs,
      feedContiguous: this.#isPrefixApplied(record.author, record.sequence - 1n) && await this.#isFeedContiguous(record),
    })
    if (recorded !== null) {
      this.#emit('heartbeat')
      this.#materializationPending = true
      this.#scheduleMaterialization()
    }
  }

  async #reconcileMaterializer(): Promise<void> {
    if (!this.#materializationReady) return
    const beforeLocal = this.materializedRevision, beforeFinal = this.finalRevision
    try {
      await this.#applyMaterializedOrder()
    } catch (error) {
      if (error instanceof ControlStoreConflictError) throw error
      throw new MaterializationProgressError(error)
    } finally {
      // Local publication can succeed before a later finality/storage step
      // fails. The materializer still owns a coherent published local view.
      if (this.materializedRevision !== beforeLocal || this.finalRevision !== beforeFinal) this.#applicationChanges.notify()
    }
  }

  async #applyMaterializedOrder(): Promise<void> {
    if (!this.#materializationPending) return
    const previousFinalLength = this.finalOrderLength
    const previousAppliedThrough = this.#coordinatedAppliedThrough
    await this.#processCoordinatedHistory()
    const frontier = await this.#liveFinalityFrontier()
    let admissionClosed = false
    for (const id of frontier.excludedProposalIds) {
      const candidate = this.#control.getCandidate(id)
      if (candidate !== null && isAdmissionPending(candidate.state)) {
        this.#control.setCandidateState(id, 'inadmissible', { reason: 'ADMISSION_CLOSED' })
        admissionClosed = true
      }
    }
    // Exclusion can remove a selected preview. Replay that removal before
    // exposing a final denial or advancing the immutable application prefix.
    const ordered: AdmittedTransaction[] = this.#control.orderedCandidates().map((candidate) => {
      const core = this.#candidateCores.get(this.#idKey(candidate.txId))
      if (!core || !candidate.canonicalPayload) throw new Error('ADMITTED_CANDIDATE_PAYLOAD_MISSING')
      return {
        txId: candidate.txId,
        authorFeedSequence: candidate.orderKey.authorFeedSequence,
        candidateDigest: candidate.candidateDigest,
        canonicalCandidate: candidate.canonicalPayload,
        core,
      }
    })
    const coordinated = await this.#options.materialization.coordinator.materialize(ordered)
    if (coordinated !== null) {
      const published = await this.#options.materialization.publications.publish(
        coordinated.publication,
      )
      if (
        published.revision !== coordinated.revision.revision ||
        published.orderLength !== coordinated.revision.orderLength ||
        !equalBytes(published.executionManifestDigest, coordinated.revision.manifestDigest)
      ) {
        throw new Error('MATERIALIZATION_PUBLICATION_RESULT_MISMATCH')
      }
      // The snapshot is readable now, even if reconciliation or finality retries.
      this.#observeAuthorTime(ordered.at(-1)?.core.authorTimestampMs ?? -1n)
    }
    const reconciled = await this.#options.materialization.publications.reconcile({
      targetOrderLength: ordered.length,
      ...(coordinated === null ? {} : { targetRevision: coordinated.revision.revision }),
    })
    const queries = this.#options.materialization.queries
    if (
      reconciled.revision !== queries.revision ||
      reconciled.orderLength !== ordered.length ||
      reconciled.orderLength !== queries.orderLength ||
      !equalBytes(reconciled.executionManifestDigest, queries.executionManifestDigest)
    ) {
      throw new Error('MATERIALIZATION_RECONCILIATION_RESULT_MISMATCH')
    }
    // Local reads can expose this published history even if later finality
    // work fails. New intent must already sort after the applied selection.
    // Startup reconciles retained inputs before authoring is allowed.
    this.#observeAuthorTime(ordered.at(-1)?.core.authorTimestampMs ?? -1n)
    let finalLength = this.finalOrderLength
    for (let index = finalLength; index < ordered.length; index += 1) {
      // Closing a timestamp does not admit a selected provisional preview.
      const entry = ordered[index]!
      if (this.#control.getCandidate(entry.txId)?.state !== 'admissible' ||
          frontier.closedThroughMs === null || entry.core.authorTimestampMs > frontier.closedThroughMs) break
      finalLength = index + 1
    }
    // Persist terminal exclusions before publishing the irreversible prefix.
    // A failed flush is retried while the old final length is still in place.
    if (this.historyPolicy === 'peer' && (admissionClosed || finalLength > this.finalOrderLength)) this.#control.flush()
    if (this.#options.materialization.coordinator.publishFinal !== undefined) {
      await this.#options.materialization.coordinator.publishFinal(finalLength)
    } else if (finalLength > 0) throw new Error('MATERIALIZER_FINAL_VIEW_UNAVAILABLE')
    if (this.historyPolicy === 'coordinated') {
      this.#coordinatedAppliedThrough = this.#coordinatedProcessed
      this.#appliedClosedThroughMs = this.#processedClosedThroughMs
    }
    this.#materializationPending = false
    this.#materializationRetryMs = 100
    if (this.#materializationDebounceTimer) {
      clearTimeout(this.#materializationDebounceTimer)
      this.#materializationDebounceTimer = undefined
    }
    if (this.#materializationRetryTimer) {
      clearTimeout(this.#materializationRetryTimer)
      this.#materializationRetryTimer = undefined
    }
    if (coordinated !== null) {
      for (const change of coordinated.revision.outcomeChanges) {
        if (change.previous !== null && change.previous !== change.current) {
          this.#replayedOutcomes.add(this.#idKey(change.txId))
        }
      }
    }
    const recovered = this.#materializationError !== undefined
    this.#materializationError = undefined
    // A completed closure also bounds the timestamp of new authoring, even
    // when no proposal occupies the newly closed interval.
    this.#observeAuthorTime(frontier.closedThroughMs ?? -1n)
    this.#applicationChanges.notify()
    if (coordinated !== null || admissionClosed || this.finalOrderLength !== previousFinalLength ||
        this.#coordinatedAppliedThrough !== previousAppliedThrough || recovered) this.#emit('materialized')
  }

  #scheduleMaterialization(): void {
    if (this.#closed || !this.#materializationReady || !this.#materializationPending) return
    if (this.#materializationDebounceTimer) clearTimeout(this.#materializationDebounceTimer)
    this.#materializationDebounceTimer = setTimeout(() => {
      this.#materializationDebounceTimer = undefined
      void this.#mutex.run(async () => {
        if (this.#closed || !this.#materializationPending) return
        try {
          await this.#reconcileMaterializer()
        } catch (error) {
          this.#recordError(error)
          this.#scheduleMaterializationRetry()
        }
      })
    }, 25)
    this.#materializationDebounceTimer.unref?.()
  }

  #scheduleMaterializationRetry(): void {
    if (this.#closed || !this.#materializationPending || this.#materializationRetryTimer) return
    const delay = this.#materializationRetryMs
    this.#materializationRetryMs = Math.min(this.#materializationRetryMs * 2, 5_000)
    this.#materializationRetryTimer = setTimeout(() => {
      this.#materializationRetryTimer = undefined
      void this.#mutex.run(async () => {
        if (this.#closed || !this.#materializationPending) return
        try {
          await this.#reconcileMaterializer()
        } catch (error) {
          this.#recordError(error)
          this.#scheduleMaterializationRetry()
        }
      })
    }, delay)
    this.#materializationRetryTimer.unref?.()
  }

  #scheduleIngestionRetry(): void {
    if (this.#closed || (this.#retryRecords.size === 0 && !this.#retryOverflow) || this.#ingestionRetryTimer) return
    this.#ingestionRetryTimer = setTimeout(() => {
      this.#ingestionRetryTimer = undefined
      const records = [...this.#retryRecords.values()].map((record) => structuredClone(record))
      void (async () => {
        for (const record of records) {
          if (this.#closed) return
          await this.ingest(record)
        }
        if (this.#retryOverflow && this.#retryRecords.size < this.#maximumRetryRecords) {
          this.#retryOverflow = false
          let history: readonly TransportRecord[]
          try {
            history = await this.#options.transport.history()
          } catch (error) {
            this.#retryOverflow = true
            throw error
          }
          for (const record of history) {
            if (this.#closed) return
            if (this.#seen.has(record.id) || this.#retryRecords.has(record.id)) continue
            if (this.#retryRecords.size >= this.#maximumRetryRecords) {
              this.#retryOverflow = true
              break
            }
            await this.ingest(record)
          }
        }
      })().catch((error) => this.#recordError(error)).finally(() => this.#scheduleIngestionRetry())
    }, 100)
    this.#ingestionRetryTimer.unref?.()
  }

  #emit(reason: NodeRevisionEvent['reason'], txId?: Uint8Array, error?: Error): void {
    if (this.#closed) return
    this.#revision = this.#revision + 1n > this.#control.sequence
      ? this.#revision + 1n
      : this.#control.sequence
    this.#events.emit({
      revision: this.#revision,
      reason,
      ...(txId === undefined ? {} : { txId: txId.slice() }),
      ...(error === undefined ? {} : { error }),
    })
  }

  #recordError(value: unknown): void {
    const error = value instanceof Error ? value : new Error(String(value))
    if (error instanceof MaterializationProgressError) this.#materializationError = error
    else this.#lastError = error
    this.#emit('error', undefined, error)
  }

  #recordIngestionError(value: unknown): void {
    const error = value instanceof Error ? value : new Error(String(value))
    this.#ingestionError = error
    this.#emit('error', undefined, error)
  }

  #clockNow(): number { return this.#options.clock?.now() ?? Date.now() }
  async #decodeRecord(record: TransportRecord): Promise<Awaited<ReturnType<typeof decodeSignedEnvelope>>> {
    try {
      return await decodeSignedEnvelope(record.payload, this.#groupRoute(), this.#options.envelopeCipher)
    } catch (error) {
      // Not terminal: the epoch key may still arrive (for example, a node that
      // just joined), and the retry loop or history replay will decode it then.
      if (error instanceof Error && error.message === WIRE_ENCRYPTION_EPOCH_UNAVAILABLE) throw error
      throw new TerminalIngestError('INVALID_SIGNED_ENVELOPE', { cause: error })
    }
  }
  #decodeCandidate(encoded: Uint8Array): TransactionCore {
    try {
      return decodeTransactionCore(encoded)
    } catch (error) {
      throw new TerminalIngestError('INVALID_CANDIDATE_PAYLOAD', { cause: error })
    }
  }
  #decodeAttestation(encoded: Uint8Array): ValidatorAttestation {
    try {
      return decodeValidatorAttestation(encoded)
    } catch (error) {
      throw new TerminalIngestError('INVALID_ATTESTATION_PAYLOAD', { cause: error })
    }
  }
  #decodeHeartbeat(encoded: Uint8Array): ValidatorHeartbeat {
    try {
      return decodeValidatorHeartbeat(encoded)
    } catch (error) {
      throw new TerminalIngestError('INVALID_HEARTBEAT_PAYLOAD', { cause: error })
    }
  }
  async #recoverValidatorCutoff(history: readonly TransportRecord[]): Promise<void> {
    if (!this.#options.validator) return
    let recovered = this.#acceptedAboveMs
    for (const record of history) {
      if (record.author !== this.#options.transport.identity) continue
      try {
        const wire = await decodeSignedEnvelope(record.payload, this.#groupRoute(), this.#options.envelopeCipher)
        if (!equalBytes(wire.signer, this.identity)) continue
        if (wire.type === 'attestation') {
          const attestation = decodeValidatorAttestation(wire.payload)
          if (
            equalBytes(attestation.groupId, this.#options.groupId) &&
            equalBytes(attestation.validatorId, this.identity) &&
            attestation.acceptedAboveMs > recovered
          ) recovered = attestation.acceptedAboveMs
        } else if (wire.type === 'heartbeat') {
          const heartbeat = decodeValidatorHeartbeat(wire.payload)
          if (
            equalBytes(heartbeat.groupId, this.#options.groupId) &&
            equalBytes(heartbeat.validatorId, this.identity) &&
            heartbeat.acceptanceCutoffMs > recovered
          ) recovered = heartbeat.acceptanceCutoffMs
        }
      } catch {
        // Invalid application records are handled by normal ingestion. Cutoff
        // preflight uses only fully verified records from our own outer feed.
      }
    }
    this.#acceptedAboveMs = recovered
    this.#persistValidatorCutoff()
  }
  #persistValidatorCutoff(): void {
    if (!this.#options.validator) return
    this.#control.persistValidatorCutoff(this.identity, this.#acceptedAboveMs)
  }
  async #expectedPolicyVersion(core: TransactionCore): Promise<bigint> {
    return this.#options.membership.policyVersion?.({
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
    }) ?? 1n
  }
  async #canUseTransportAuthor(
    record: TransportRecord,
    role: 'writer' | 'validator',
    signingId: Uint8Array,
    membershipRevision: Uint8Array,
    validatorCapability?: Uint8Array,
    writerCapability?: Uint8Array,
  ): Promise<boolean> {
    return this.#membershipAllowsTransportAuthor(
      record.author,
      role,
      signingId,
      membershipRevision,
      validatorCapability,
      writerCapability,
    )
  }
  async #membershipAllowsTransportAuthor(
    transportAuthor: string,
    role: 'writer' | 'validator',
    signingId: Uint8Array,
    membershipRevision: Uint8Array,
    validatorCapability?: Uint8Array,
    writerCapability?: Uint8Array,
  ): Promise<boolean> {
    if (this.#options.membership.canUseTransportAuthor === undefined) {
      return transportAuthor === this.#options.transport.identity && equalBytes(signingId, this.identity)
    }
    return this.#options.membership.canUseTransportAuthor({
      groupId: this.#options.groupId,
      membershipRevision,
      role,
      signingId,
      transportAuthor,
      ...(validatorCapability === undefined ? {} : { validatorCapability }),
      ...(writerCapability === undefined ? {} : { writerCapability }),
    })
  }
  #membershipState() {
    return this.#options.membershipState?.() ?? {
      membershipRevision: this.#options.membershipRevision,
      validationPolicy: this.#options.validationPolicy,
      ...(this.#options.validator === undefined ? {} : { validatorCapability: this.#options.validator.capabilityId }),
    }
  }
  #validatorCapability(): Uint8Array | undefined {
    return this.#membershipState().validatorCapability
  }
  async #heartbeatAuthorized(context: {
    readonly groupId: Uint8Array
    readonly membershipRevision: Uint8Array
    readonly validatorId: Uint8Array
    readonly validatorCapability: Uint8Array
  }): Promise<boolean> {
    if (this.#options.membership.canHeartbeat !== undefined) {
      return this.#options.membership.canHeartbeat(context)
    }
    if (!equalBytes(context.membershipRevision, this.membershipRevision)) return false
    return this.#options.membership.canValidate({
      ...context,
      validationPolicy: this.validationPolicy,
      writerId: context.validatorId,
    })
  }
  async #isValidAdmissionProof(
    candidate: StoredCandidate,
    core: TransactionCore,
    attestation: StoredAttestation,
  ): Promise<boolean> {
    if (
      !equalBytes(attestation.txId, candidate.txId) ||
      !equalBytes(attestation.candidateDigest, candidate.candidateDigest) ||
      !equalBytes(attestation.membershipRevision, core.membershipRevision) ||
      attestation.authorTimestampMs !== core.authorTimestampMs ||
      attestation.authorTimestampMs <= attestation.acceptedAboveMs ||
      attestation.policyVersion !== await this.#expectedPolicyVersion(core) ||
      typeof attestation.transportAuthor !== 'string'
    ) return false
    const transportAuthorized = await this.#options.membership.canUseTransportAuthor?.({
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      role: 'validator',
      signingId: attestation.validatorId,
      transportAuthor: attestation.transportAuthor,
      validatorCapability: attestation.validatorCapability,
    }) ?? (
      attestation.transportAuthor === this.#options.transport.identity &&
      equalBytes(attestation.validatorId, this.identity)
    )
    if (!transportAuthorized) return false
    if (this.#options.peerGovernance !== undefined && !await this.#options.peerGovernance.allowsAttestation(
      core.membershipRevision, attestation.validatorId, attestation.validatorFeedSequence,
    )) return false
    return this.#options.membership.canValidate({
      groupId: core.groupId,
      membershipRevision: core.membershipRevision,
      validationPolicy: core.validationPolicy,
      writerId: core.authorId,
      ...(core.writerCapability === undefined ? {} : { writerCapability: core.writerCapability }),
      authorTimestampMs: core.authorTimestampMs,
      program: core.program,
      validatorId: attestation.validatorId,
      validatorCapability: attestation.validatorCapability,
    })
  }
  async #isFeedContiguous(record: TransportRecord): Promise<boolean> {
    const transport = this.#options.transport
    if (transport.feedContiguousThrough !== undefined) {
      return await transport.feedContiguousThrough(record.author) >= record.sequence
    }
    const status = await transport.status()
    const feed = status.feedStates?.find((candidate) => candidate.feedId === record.author)
    if (feed === undefined || !/^(0|[1-9][0-9]*)$/.test(feed.contiguousThrough)) return false
    return BigInt(feed.contiguousThrough) >= record.sequence
  }
  #isPrefixApplied(author: string, sequence: bigint): boolean {
    return (this.#indexedFeeds.get(author)?.through ?? 0n) >= sequence
  }

  #markSeen(record: TransportRecord): void {
    this.#seen.add(record.id)
    const feed = this.#indexedFeeds.get(record.author) ?? { through: 0n, pending: new Set<bigint>() }
    this.#indexedFeeds.set(record.author, feed)
    if (record.sequence > feed.through) feed.pending.add(record.sequence)
    const previous = feed.through
    while (feed.pending.delete(feed.through + 1n)) feed.through++
    if (feed.through > previous && this.historyPolicy === 'peer') {
      // An earlier admission or an unrelated record can complete a signed
      // heartbeat/closure prefix. Transport retention alone is not this proof.
      this.#materializationPending = true
      this.#scheduleMaterialization()
    }
  }
  #observeAuthorTime(timestamp: bigint): void {
    if (timestamp > this.#observedAuthorTimestampMs) this.#observedAuthorTimestampMs = timestamp
  }
  #nextAuthorTimestamp(): bigint {
    const wallClock = BigInt(Math.max(0, Math.trunc(this.#clockNow())))
    const previous = this.#lastAuthoredTimestampMs > this.#observedAuthorTimestampMs
      ? this.#lastAuthoredTimestampMs : this.#observedAuthorTimestampMs
    const next = wallClock > previous ? wallClock : previous + 1n
    const membershipFloor = this.#membershipState().minimumAuthorTimestampMs ?? 0n
    const selected = this.#options.historyPolicy
    const closedFloor = selected?.kind === 'coordinated' ? selected.policy.snapshot().closedThroughMs + 1n : 0n
    const floor = membershipFloor > closedFloor ? membershipFloor : closedFloor
    const timestamp = next < floor ? floor : next
    if (this.#authorFutureSkewMs !== undefined && timestamp > wallClock + BigInt(this.#authorFutureSkewMs)) {
      throw new Error('AUTHOR_CLOCK_AHEAD')
    }
    return timestamp
  }
  #allocateTransactionContext(): ReservedTransactionContext {
    const authorTimestampMs = this.#nextAuthorTimestamp()
    this.#lastAuthoredTimestampMs = authorTimestampMs
    return { authorTimestampMs, nonce: this.#randomBytes(32) }
  }
  #setConsumerPhase(phase: string): void {
    if (phase === this.#consumerPhase) return
    this.#consumerPhase = phase
    this.#consumerPhaseSince = Date.now()
    this.#stallReported = false
  }

  /**
   * Records NODE_INGEST_STALLED:<phase> when the transport holds records this
   * node has not processed and the consumer has not changed phase for 20 s.
   * It only reports; it never changes what the node does.
   */
  async #checkIngestStall(): Promise<void> {
    if (this.#closed) return
    const transport = await this.#options.transport.status()
    const backlog = transport.records - this.#seen.size - this.#retryRecords.size
    if (backlog <= 0) {
      this.#backlogSince = undefined
      return
    }
    const now = Date.now()
    if (!this.#stallReported && now - this.#consumerPhaseSince >= 20_000) {
      this.#stallReported = true
      this.#recordError(new Error(`NODE_INGEST_STALLED:${this.#consumerPhase}`))
    }
    // Fallback: records the transport holds but never delivered to this live
    // subscription (observed under chaos stress: older replicated records
    // missing while new ones flowed; history replay finds them). If records
    // stay unprocessed for 20 s, resubscribe; the new subscription replays
    // history and already-seen records are skipped.
    // A live stream keeps adding records that are ingested promptly, so the
    // backlog fluctuates; what matters is that it never reaches zero. The
    // window restarts only when the backlog is fully drained (above).
    // A node catching up on a large backlog drains it steadily; only a
    // window without real progress (still >= 90% of where it started) counts.
    if (this.#backlogSince === undefined) {
      this.#backlogSince = now
      this.#backlogAtWindowStart = backlog
    } else if (now - this.#backlogSince >= 20_000) {
      const stalled = backlog * 10 >= this.#backlogAtWindowStart * 9
      this.#backlogSince = undefined
      if (stalled) {
        if (this.#lastResyncAt !== undefined && now - this.#lastResyncAt < 300_000) {
          // A recent resync did not drain it: the transport's queries are
          // omitting records it holds (seen under chaos stress after a CPU
          // stall; a process restart recovers them). Report it as degraded.
          this.#recordError(new Error('NODE_TRANSPORT_RECORDS_UNDELIVERED'))
        } else {
          this.#lastResyncAt = now
          await this.#resyncFromHistory()
        }
      }
    }
  }

  /**
   * Ingests every transport record this node has not seen, read through
   * transport.history(). Under chaos stress a live subscription (and a fresh
   * one, whose replay uses a streaming query) missed records that the
   * transport's history query returns; a restart recovers them the same way.
   */
  async #resyncFromHistory(): Promise<void> {
    this.#subscriptionRestarts += 1
    for (const record of await this.#options.transport.history()) {
      if (this.#closed) return
      if (!this.#seen.has(record.id) && !this.#retryRecords.has(record.id)) await this.ingest(record)
    }
  }

  #advanceValidatorCutoff(now: number): void {
    const validator = this.#options.validator
    if (!validator) return
    const proposed = BigInt(Math.max(0, Math.trunc(now - (validator.cutoffLagMs ?? 60_000))))
    if (proposed > this.#acceptedAboveMs) this.#acceptedAboveMs = proposed
  }
  #randomBytes(length: number): Uint8Array { return this.#options.random?.bytes(length) ?? crypto.getRandomValues(new Uint8Array(length)) }
  #materializerLocalSql(
    sql: string,
    parameters: readonly MaterializedLocalSqlValue[],
    options?: Parameters<ChronologNodeOptions['materialization']['queries']['localSql']>[2],
  ): MaterializedLocalSqlResult {
    return this.#options.materialization.queries.localSql(sql, parameters, options)
  }
  #groupRoute(): Uint8Array { return this.#options.groupRoute ?? this.#options.groupId }
  #idKey(value: Uint8Array): string { return bytesToHex(value) }

  #assertReady(): void {
    if (!this.#started) throw new Error('NODE_NOT_STARTED')
    if (this.#closed) throw new Error('NODE_CLOSED')
    if (this.#feedForks.quarantined()) throw new Error('NODE_FEED_FORK_QUARANTINED')
  }
}

class TerminalIngestError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'TerminalIngestError'
  }
}

/** An unavailable derived SQL view remains retryable; integrity faults stay separate. */
class MaterializationProgressError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), { cause })
    this.name = 'MaterializationProgressError'
  }
}

function invalid(code: string): never {
  throw new TerminalIngestError(code)
}

function isAdmissionPending(state: StoredCandidate['state']): boolean {
  return state === 'pending_validation' || state === 'provisional'
}

import { DEFAULT_SIGNAL_TTL_MS, MAX_SIGNAL_TTL_MS, SignalError,
  type Signals, type SignalPayload, type SignalSendOptions, type SignalSubscribeOptions, type EphemeralSignal } from '@chronolog/signals'
import {
  base64UrlToBytes,
  bytesToBase64Url as toBase64Url,
  encodePlatformOp,
  encodeChangeProgram,
  emit,
  isEmitStep,
  program,
  isPlatformOp,
  isSqlValue,
  platformOp,
  toSqlValue,
  type CollectiveGovernance,
  type CollectiveRole,
  type MemberChange,
  type PlatformOp,
  type SqlStatement,
  type SqlValue,
  type ChangeProgram,
  type EmitStep,
  type EventPayload,
  type EventBatch,
  type EventReadOptions,
  type ApplicationChange,
  type ApplicationChangeOptions,
} from '@chronolog/protocol'
import {
  ChronologRpcError,
  isChronologRpcError,
  toChronologRpcError,
  type ApproveEnrollmentResponse,
  type CreateEnrollmentResponse,
  type EnrollmentRole,
  type ProgramRights,
  type EnrollmentStatus,
  type LiveSqlEvent,
  type LocalSqlValue,
  type NodeStatus,
  type ReplicationStatus,
  type RevisionMetadata,
  type RpcCallOptions,
  type RpcProgramStep,
  type RpcSqlStatement,
  type RpcTransport,
  type SettlementEvidence,
  type SqlView,
  type SubmitTransactionResponse,
  type TransactionOutcome,
  type UnaryRequest,
  type UnaryResponse,
  type UnaryRpcMethod,
  type ValidatorWatermark,
  type OperationStatus,
  type OpenReadViewResponse,
  type SubmitChangeResponse,
} from '@chronolog/rpc'

import {
  decodeLocalSqlResult,
  encodeCompiledLocalSqlQuery,
  encodeLocalSqlParameters,
  type CompiledLocalSqlQuery,
  type DecodedLocalSqlResult,
  type LocalSqlInput,
} from './local-sql.js'
import {
  TransactionRejectedError,
  createdObjectId,
  ownershipSteps,
  type OfferAllInput,
  type OfferRowInput,
  type ShareInput,
} from './ownership.js'
import { StreamResource } from './stream-resource.js'
import { SealedDataActions } from './sealed.js'

export interface ChronologClientOptions {
  readonly transport: RpcTransport
  readonly groupId: string
  readonly token?: string
  readonly requestId?: () => string
  readonly unaryRetryAttempts?: number
  readonly streamRetryDelayMs?: (attempt: number) => number
}

export interface QueryOptions {
  readonly signal?: AbortSignal
  readonly maxRows?: number
  readonly atRevision?: string
  /** local is speculative; final selects the applied immutable SQL prefix. */
  readonly view?: SqlView
}

export interface LocalSqlQueryResponse {
  readonly revision: RevisionMetadata
  readonly result: DecodedLocalSqlResult
}

export interface LiveQueryValue {
  readonly type: LiveSqlEvent['type']
  readonly revision: RevisionMetadata
  readonly queryDigest: string
  readonly result?: DecodedLocalSqlResult
  readonly resetReason?: Extract<LiveSqlEvent, { type: 'reset' }>['reason']
}

export interface TransactionOptions {
  readonly signal?: AbortSignal
  /** Durable application identity. A generated identity is returned on the handle when omitted. */
  readonly operationId?: string
}

export interface ChangeOptions { readonly operationId: string; readonly signal?: AbortSignal }
export interface EventReaderOptions extends EventReadOptions { readonly signal?: AbortSignal }
export interface ClientReadView {
  readonly revision: string
  readonly finalRevision: string
  readonly view: SqlView
  readonly expiresAt: number
  query(sql: string, parameters?: readonly LocalSqlInput[], options?: { readonly maxRows?: number; readonly signal?: AbortSignal }): Promise<DecodedLocalSqlResult>
  readEvents(options?: EventReaderOptions): Promise<EventBatch>
  release(): Promise<void>
}

/** A JavaScript value bound to a SQL parameter; see `toSqlValue` for the mapping. */
export type ClientSqlValue = null | undefined | boolean | bigint | number | string | Uint8Array | SqlValue
export type ClientSqlBindings = readonly ClientSqlValue[] | Readonly<Record<string, ClientSqlValue>>

/** One statement of a transaction, in the shape common SQL builders produce. */
export interface CompiledSqlStatement {
  readonly sql: string
  /** Positional values, or named values keyed with or without their `:`/`@`/`$` prefix. */
  readonly params?: readonly unknown[] | Readonly<Record<string, unknown>>
}

export type TransactionStatementInput = string | CompiledSqlStatement | SqlStatement

/** One step of a transaction: SQL, an emitted event, or a platform operation. */
export type TransactionStepInput = TransactionStatementInput | PlatformOp | EmitStep

/** A current accepted/rejected result; it may still change through replay. */
export type ProvisionalTransactionOutcome = TransactionOutcome & {
  readonly outcome: Exclude<TransactionOutcome['outcome'], { readonly type: 'pending' }>
}
/** The immutable accepted/rejected result applied on this replica. */
export type FinalTransactionOutcome = ProvisionalTransactionOutcome & { readonly final: true }
export type AcceptedTransactionOutcome = FinalTransactionOutcome & {
  readonly outcome: Extract<TransactionOutcome['outcome'], { readonly type: 'accepted' }>
}

export class TransactionHandle {
  readonly outcome: StreamResource<TransactionOutcome>
  readonly evidence: StreamResource<SettlementEvidence>

  constructor(
    readonly client: ChronologClient,
    readonly submission: SubmitTransactionResponse,
    readonly operationId?: string,
  ) {
    this.outcome = client.transactionOutcome(submission.transactionId)
    this.evidence = client.settlementEvidence(submission.transactionId)
  }

  get transactionId(): string { return this.submission.transactionId }
  get proposalId(): string { return this.submission.transactionId }

  /** The current speculative result. Replay can change this until final() resolves. */
  provisional(options: { readonly signal?: AbortSignal } = {}): Promise<ProvisionalTransactionOutcome> {
    return this.#waitForOutcome((value): value is ProvisionalTransactionOutcome => value.outcome.type !== 'pending', options.signal)
  }

  /** Resolves only when the accepted or rejected result is applied in the immutable prefix. */
  final(options: { readonly signal?: AbortSignal } = {}): Promise<FinalTransactionOutcome> {
    return this.#waitForOutcome((value): value is FinalTransactionOutcome => value.final && value.outcome.type !== 'pending', options.signal)
  }

  /**
   * Resolves only after immutable acceptance is applied locally. A final
   * rejection throws `TransactionRejectedError` with a parsed `reason`.
   */
  async accepted(options: { readonly signal?: AbortSignal } = {}): Promise<AcceptedTransactionOutcome> {
    const outcome = await this.final(options)
    if (outcome.outcome.type === 'rejected') throw new TransactionRejectedError(this.transactionId, outcome.outcome.rejection)
    return { ...outcome, outcome: outcome.outcome }
  }

  #waitForOutcome<T extends TransactionOutcome>(predicate: (value: TransactionOutcome) => value is T, signal?: AbortSignal): Promise<T> {
    if (signal?.aborted === true) return Promise.reject(signal.reason)
    return new Promise((resolve, reject) => {
      let finished = false
      let unsubscribe = () => undefined as void
      const finish = (value?: T, error?: unknown) => {
        if (finished) return
        finished = true
        signal?.removeEventListener('abort', abort)
        unsubscribe()
        if (value !== undefined) resolve(value)
        else reject(error)
      }
      const abort = () => finish(undefined, signal?.reason)
      const check = () => {
        const snapshot = this.outcome.getSnapshot()
        if (snapshot.value !== undefined && predicate(snapshot.value)) finish(snapshot.value)
        else if (snapshot.status === 'error') finish(undefined, snapshot.error)
        else if (snapshot.status === 'closed') finish(undefined,
          new ChronologRpcError('transport_unavailable', 'Outcome stream closed before the requested result was available'))
      }
      signal?.addEventListener('abort', abort, { once: true })
      unsubscribe = this.outcome.subscribe(check)
      // subscribe can synchronously publish a cached snapshot before returning
      // its cleanup. Detach only this waiter; other stream consumers stay live.
      if (finished) unsubscribe()
      else if (signal?.aborted === true) abort()
      else check()
    })
  }

  /** The id of the grant, team or transfer offer created by step `stepIndex` of this transaction. */
  createdId(stepIndex: number): Promise<Uint8Array> {
    return createdObjectId(this.transactionId, stepIndex)
  }

  dispose(): void { this.outcome.dispose(); this.evidence.dispose() }
  [Symbol.dispose](): void { this.dispose() }
}

export class ChronologClient {
  readonly groupId: string
  readonly #transport: RpcTransport
  readonly #token?: string
  readonly #idFactory: () => string
  readonly #unaryRetryAttempts: number
  readonly #streamRetryDelayMs?: (attempt: number) => number
  readonly #resources = new Set<{ dispose(): void }>()
  readonly #readViews = new Set<ClientReadView>()
  readonly #abort = new AbortController()
  #identity: Promise<Uint8Array> | undefined
  #closed = false
  #observedSignalTime = 0
  /** Sharing, teams and transfers of owned rows; each call submits one transaction. */
  readonly ownership: OwnershipActions = new OwnershipActions(this)
  readonly enrollment: EnrollmentActions = new EnrollmentActions(this)
  /** Live, lossy messages. Calls never use the durable retry/replay machinery. */
  readonly signals: Signals = {
    send: (topic: string, payload: SignalPayload, options: SignalSendOptions = {}): Promise<EphemeralSignal> =>
      this.#sendSignal(topic, payload, options),
    subscribe: (options: SignalSubscribeOptions = {}): AsyncIterable<EphemeralSignal> => this.#liveSignals(options),
  }
  /** At-least-once final batches; never coalesced into snapshot notifications. */
  readonly events = {
    publish: (topic: string, payload: EventPayload, options: ChangeOptions): Promise<TransactionHandle> => this.submit(program(emit(topic, payload)), options),
    read: (options: EventReaderOptions = {}): Promise<EventBatch> => this._unary('events.read', {
      groupId: this.groupId, requestId: this._requestId(), ...eventReadOptions(options),
    }, options.signal === undefined ? {} : { signal: options.signal }),
    subscribe: (options: EventReaderOptions = {}): AsyncIterable<EventBatch> => this.#durableEvents(options),
  }
  readonly operations = {
    get: (operationId: string, options: { readonly signal?: AbortSignal } = {}): Promise<OperationStatus | null> => this._unary('operation.get', {
      groupId: this.groupId, requestId: this._requestId(), operationId,
    }, options),
    subscribe: (options: { readonly operationId: string; readonly signal?: AbortSignal }): AsyncIterable<OperationStatus> => {
      const request = { groupId: this.groupId, requestId: this._requestId(), operationId: options.operationId }
      return this.#reconnecting((signal) => this.#transport.stream('operation.subscribe', request, this.#callOptions(signal)), options.signal)
    },
  }
  /** Explicit reader policies and client-encrypted BLOB columns. */
  readonly sealed: SealedDataActions = new SealedDataActions(this)

  constructor(options: ChronologClientOptions) {
    this.groupId = options.groupId
    this.#transport = options.transport
    if (options.token !== undefined) this.#token = options.token
    this.#idFactory = options.requestId ?? (() => crypto.randomUUID())
    this.#unaryRetryAttempts = options.unaryRetryAttempts ?? 2
    if (options.streamRetryDelayMs !== undefined) this.#streamRetryDelayMs = options.streamRetryDelayMs
  }

  async submit(change: ChangeProgram, options: ChangeOptions): Promise<TransactionHandle> {
    const submission: SubmitChangeResponse = await this._unary('change.submit', {
      groupId: this.groupId, requestId: this._requestId(), operationId: options.operationId, program: encodeChangeProgram(change),
    }, options.signal === undefined ? {} : { signal: options.signal })
    return new TransactionHandle(this, submission, submission.operationId)
  }

  /** Forward an already signed publisher proposal and follow its original transaction. */
  async submitSigned(signedWire: Uint8Array, options: { readonly signal?: AbortSignal } = {}): Promise<TransactionHandle> {
    if (!(signedWire instanceof Uint8Array) || signedWire.byteLength === 0) throw new TypeError('signedWire must contain original signed proposal bytes')
    const submission = await this._unary('ingress.submit', {
      groupId: this.groupId, requestId: this._requestId(), signedWire: signedWire.slice(),
    }, options)
    return new TransactionHandle(this, submission)
  }

  /** Current applied view, then latest-state invalidations. Reconnects without a history cursor. */
  changes(options: ApplicationChangeOptions = {}): AsyncIterable<ApplicationChange> {
    const self = this, view = options.view ?? 'final', external = options.signal
    if (view !== 'local' && view !== 'final') throw new TypeError('view must be local or final')
    return { [Symbol.asyncIterator]() {
      if (self.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
      const controller = new AbortController()
      const signal = AbortSignal.any([controller.signal, self.#abort.signal, ...(external === undefined ? [] : [external])])
      const resource = self.#track(new StreamResource<ApplicationChange>({
        open: (_cursor, lifetime) => self.#transport.stream('view.changes', { groupId: self.groupId, view },
          self.#callOptions(AbortSignal.any([signal, lifetime]))),
        cursor: () => undefined,
        ...(self.#streamRetryDelayMs === undefined ? {} : { retryDelayMs: self.#streamRetryDelayMs }),
      }))
      const iterator = resource[Symbol.asyncIterator]()
      const close = (): void => {
        signal.removeEventListener('abort', close)
        resource.dispose()
        // Disposing wakes an idle next; return also releases a paused yield.
        void iterator.return?.().catch(() => undefined)
      }
      signal.addEventListener('abort', close, { once: true })
      if (signal.aborted) close()
      return {
        async next() {
          if (signal.aborted) return { done: true as const, value: undefined }
          try {
            const result = await iterator.next()
            if (result.done) controller.abort()
            return signal.aborted ? { done: true as const, value: undefined } : result
          } catch (error) { controller.abort(error); throw error }
        },
        async return() {
          controller.abort(); close(); await iterator.return?.()
          return { done: true as const, value: undefined }
        },
        async throw(error: unknown) {
          controller.abort(error); close(); await iterator.return?.(); throw error
        },
      }
    } }
  }

  async readView(options: { readonly view?: SqlView; readonly signal?: AbortSignal } = {}): Promise<ClientReadView> {
    const captured: OpenReadViewResponse = await this._unary('view.open', {
      groupId: this.groupId, requestId: this._requestId(), view: options.view ?? 'final',
    }, options.signal === undefined ? {} : { signal: options.signal })
    let released = false
    const base = { groupId: this.groupId, viewId: captured.viewId }
    const assertHeld = () => { if (released) throw new ChronologRpcError('revision_unavailable', 'Read view was released') }
    const handle: ClientReadView = {
      revision: captured.revision, finalRevision: captured.finalRevision, view: captured.view, expiresAt: captured.expiresAt,
      query: async (sql, parameters = [], queryOptions = {}) => {
        assertHeld()
        return decodeLocalSqlResult(await this._unary('view.query', {
          ...base, requestId: this._requestId(), sql, parameters: encodeLocalSqlParameters(parameters),
          ...(queryOptions.maxRows === undefined ? {} : { maxRows: queryOptions.maxRows }),
        }, queryOptions.signal === undefined ? {} : { signal: queryOptions.signal }))
      },
      readEvents: async (readOptions = {}) => {
        assertHeld()
        return this._unary('view.events', { ...base, requestId: this._requestId(), ...eventReadOptions(readOptions) },
          readOptions.signal === undefined ? {} : { signal: readOptions.signal })
      },
      release: async () => {
        if (released) return
        released = true
        this.#readViews.delete(handle)
        // close() has already disabled authoring; leases must still be released.
        await this.#transport.unary('view.release', { ...base, requestId: this._requestId() }, this.#callOptions())
      },
    }
    if (this.#closed) { await handle.release(); throw new ChronologRpcError('transport_unavailable', 'Client closed while capturing a read view') }
    this.#readViews.add(handle)
    return handle
  }

  async query(sql: string, bindings: readonly LocalSqlInput[] = [], options: QueryOptions = {}): Promise<LocalSqlQueryResponse> {
    const response = await this._unary('query.localSql', {
      groupId: this.groupId,
      requestId: this._requestId(),
      sql,
      parameters: encodeLocalSqlParameters(bindings),
      view: options.view ?? 'local',
      ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
      ...(options.atRevision === undefined ? {} : { atRevision: options.atRevision }),
    }, options.signal === undefined ? {} : { signal: options.signal })
    this._assertCompatibility(response.revision)
    return { revision: response.revision, result: decodeLocalSqlResult(response.result) }
  }

  async queryCompiled(query: CompiledLocalSqlQuery, options: QueryOptions = {}): Promise<LocalSqlQueryResponse> {
    const compiled = encodeCompiledLocalSqlQuery(query)
    return this.query(compiled.sql, compiled.parameters, options)
  }

  liveQuery(sql: string, bindings: readonly LocalSqlInput[] = [], options: Omit<QueryOptions, 'atRevision'> = {}): StreamResource<LiveQueryValue> {
    const requestId = this._requestId()
    const parameters = encodeLocalSqlParameters(bindings)
    let queryDigest: string | undefined
    return this.#track(new StreamResource({
      open: (cursor, signal) => mapAsync(
        this.#transport.stream('query.liveSql', {
          groupId: this.groupId,
          requestId,
          sql,
          parameters,
          view: options.view ?? 'local',
          ...(options.maxRows === undefined ? {} : { maxRows: options.maxRows }),
          ...(cursor === undefined || queryDigest === undefined ? {} : { resume: { groupId: this.groupId, queryDigest, eventSetRevision: cursor } }),
        }, this.#callOptions(options.signal === undefined ? signal : AbortSignal.any([signal, options.signal]))),
        (event): LiveQueryValue => {
          this._assertCompatibility(event.revision)
          queryDigest = event.queryDigest
          return {
            type: event.type,
            revision: event.revision,
            queryDigest: event.queryDigest,
            ...(event.result === undefined ? {} : { result: decodeLocalSqlResult(event.result) }),
            ...(event.type === 'reset' ? { resetReason: event.reason } : {}),
          }
        },
      ),
      cursor: (value) => value.revision.eventSetRevision,
      ...(this.#streamRetryDelayMs === undefined ? {} : { retryDelayMs: this.#streamRetryDelayMs }),
    }))
  }

  /**
   * Submit SQLite statements and platform operations as one replicated
   * transaction, executed in order as this node's key. Any failing step
   * rejects the whole transaction; use `SELECT chronolog_assert(condition,
   * 'code')` to state assumptions. Rows written belong to this node's key
   * unless a grant or collective says otherwise.
   */
  async transaction(steps: readonly TransactionStepInput[], options: TransactionOptions = {}): Promise<TransactionHandle> {
    const requestId = this._requestId()
    const operationId = options.operationId ?? requestId
    const submission = await this._unary('transaction.submit', {
      groupId: this.groupId,
      requestId,
      steps: steps.map(encodeTransactionStep),
      operationId,
    }, options.signal === undefined ? {} : { signal: options.signal })
    return new TransactionHandle(this, submission, operationId)
  }

  async getTransactionOutcome(transactionId: string): Promise<TransactionOutcome> {
    return this._unary('transaction.getOutcome', { groupId: this.groupId, transactionId, requestId: this._requestId() })
  }

  transactionOutcome(transactionId: string): StreamResource<TransactionOutcome> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('transaction.streamOutcome', {
        groupId: this.groupId,
        transactionId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (outcome) => outcome.eventSetRevision,
    )
  }

  async getSettlementEvidence(transactionId: string): Promise<SettlementEvidence> {
    return this._unary('evidence.getSettlement', { groupId: this.groupId, transactionId, requestId: this._requestId() })
  }

  settlementEvidence(transactionId: string): StreamResource<SettlementEvidence> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('evidence.streamSettlement', {
        groupId: this.groupId,
        transactionId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (evidence) => evidence.evidenceRevision,
    )
  }

  async validatorWatermark(): Promise<ValidatorWatermark> {
    return this._unary('evidence.getValidatorWatermark', { groupId: this.groupId, requestId: this._requestId() })
  }

  async getReplicationStatus(): Promise<ReplicationStatus> {
    return this._unary('node.getReplicationStatus', { groupId: this.groupId, requestId: this._requestId() })
  }

  replicationStatus(): StreamResource<ReplicationStatus> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => this.#transport.stream('node.streamReplicationStatus', {
        groupId: this.groupId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)),
      (status) => status.revision,
    )
  }

  async getStatus(): Promise<NodeStatus> {
    const status = await this._unary('node.getStatus', { groupId: this.groupId, requestId: this._requestId() })
    if (status.revision !== undefined) this._assertCompatibility(status.revision)
    return status
  }

  status(): StreamResource<NodeStatus> {
    const requestId = this._requestId()
    return this.#revisionStream(
      (cursor, signal) => mapAsync(this.#transport.stream('node.streamStatus', {
        groupId: this.groupId,
        requestId,
        ...(cursor === undefined ? {} : { resumeAfterEventSetRevision: cursor }),
      }, this.#callOptions(signal)), (status) => { if (status.revision !== undefined) this._assertCompatibility(status.revision); return status }),
      (status) => status.revision?.eventSetRevision,
    )
  }

  /**
   * This node's signing key: the key that signs its transactions and owns the
   * rows they insert. Compare it with `ownerKeySql()` in local reads.
   */
  identity(): Promise<Uint8Array> {
    this.#identity ??= this.getStatus().then(
      (status) => base64UrlToBytes(status.nodeId),
      (error: unknown) => { this.#identity = undefined; throw error },
    )
    return this.#identity
  }

  queryResourceKey(sql: string, bindings: readonly LocalSqlInput[] = [], view: SqlView = 'local'): string {
    return `${view}\0${sql}\0${stableClientValue(bindings)}`
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    this.#abort.abort(new ChronologRpcError('cancelled', 'Client is closed'))
    for (const resource of this.#resources) resource.dispose()
    this.#resources.clear()
    await Promise.allSettled([...this.#readViews].map((view) => view.release()))
    await this.#transport.close?.()
  }

  async #sendSignal(topic: string, payload: SignalPayload, options: SignalSendOptions): Promise<EphemeralSignal> {
    // The caller owns this lifetime, including RPC transit. Wall time carries
    // the deadline across processes; elapsed time bounds this wait despite rollback.
    const startedAt = performance.now(), issuedAtMs = this.#signalNow()
    assertLiveSignalOptions(options, ['ttlMs', 'signal'])
    if (this.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
    const ttlMs = options.ttlMs ?? DEFAULT_SIGNAL_TTL_MS
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_SIGNAL_TTL_MS) {
      throw toChronologRpcError(new SignalError('signal_ttl_invalid'))
    }
    const expiresAtMs = issuedAtMs + ttlMs
    if (!Number.isSafeInteger(expiresAtMs)) throw toChronologRpcError(new SignalError('signal_clock_invalid'))
    const expired = toChronologRpcError(new SignalError('signal_expired'))
    const remaining = Math.min(ttlMs - (performance.now() - startedAt), expiresAtMs - this.#signalNow())
    if (remaining <= 0) throw expired
    const deadline = new AbortController()
    const signal = AbortSignal.any([this.#abort.signal, deadline.signal, ...(options.signal === undefined ? [] : [options.signal])])
    const timer = setTimeout(() => deadline.abort(expired), remaining)
    try {
      const result = await dispatchLiveCall(() => this.#transport.unary('signals.send', {
        groupId: this.groupId, topic, payload, ttlMs, expiresAtMs,
      }, this.#callOptions(signal)), signal)
      if (performance.now() - startedAt >= ttlMs || this.#signalNow() >= expiresAtMs) throw expired
      return result
    } finally { clearTimeout(timer) }
  }

  #signalNow(): number {
    const now = Date.now()
    if (!Number.isSafeInteger(now) || now < 0) throw toChronologRpcError(new SignalError('signal_clock_invalid'))
    this.#observedSignalTime = Math.max(this.#observedSignalTime, now)
    return this.#observedSignalTime
  }

  #liveSignals(options: SignalSubscribeOptions): AsyncIterable<EphemeralSignal> {
    assertLiveSignalOptions(options, ['topics', 'mode', 'signal'])
    const self = this
    const request = { groupId: this.groupId,
      ...(options.topics === undefined ? {} : { topics: Array.isArray(options.topics) ? [...options.topics as readonly string[]] : options.topics }),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
    }
    return { [Symbol.asyncIterator]() {
      if (self.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
      const controller = new AbortController()
      const signal = AbortSignal.any([controller.signal, self.#abort.signal, ...(options.signal === undefined ? [] : [options.signal])])
      const iterator = self.#transport.stream('signals.subscribe', request, self.#callOptions(signal))[Symbol.asyncIterator]()
      let returned = false
      return {
        async next() {
          try {
            const result = await iterator.next()
            if (result.done) controller.abort()
            return result
          } catch (error) {
            if (returned || options.signal?.aborted === true) return { done: true as const, value: undefined }
            controller.abort(error); throw error
          }
        },
        async return() {
          // Cancel a pending pull before awaiting return; do not reconnect it.
          returned = true; controller.abort()
          await iterator.return?.()
          return { done: true as const, value: undefined }
        },
        async throw(error: unknown) {
          returned = true; controller.abort(error)
          if (iterator.throw !== undefined) return iterator.throw(error)
          await iterator.return?.(); throw error
        },
      }
    } }
  }

  #durableEvents(options: EventReaderOptions): AsyncIterable<EventBatch> {
    const request = { groupId: this.groupId, requestId: this._requestId(), ...eventReadOptions(options) }
    const self = this
    return { async *[Symbol.asyncIterator]() {
      let cursor = request.cursor
      const source = self.#reconnecting((signal) => self.#transport.stream('events.subscribe', {
        ...request, ...(cursor === undefined ? {} : { cursor }),
      }, self.#callOptions(signal)), options.signal)
      for await (const batch of source) {
        yield batch
        // Only the next pull advances received progress. Durable processing is
        // the consumer's state/cursor commit, never this in-memory variable.
        cursor = batch.scannedThrough
      }
    } }
  }

  #reconnecting<T>(open: (signal: AbortSignal) => AsyncIterable<T>, externalSignal?: AbortSignal): AsyncIterable<T> {
    const self = this
    return { async *[Symbol.asyncIterator]() {
      const controller = new AbortController()
      const signal = AbortSignal.any([controller.signal, self.#abort.signal, ...(externalSignal === undefined ? [] : [externalSignal])])
      let attempt = 0
      try {
        while (!signal.aborted) {
          if (self.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
          try {
            for await (const value of open(signal)) { attempt = 0; yield value }
            if (signal.aborted) return
            throw new ChronologRpcError('transport_unavailable', 'Subscription disconnected')
          } catch (error) {
            if (signal.aborted) return
            if (!isChronologRpcError(error) || !error.retryable) throw error
            attempt++
            await delay(self.#streamRetryDelayMs?.(attempt) ?? Math.min(100 * 2 ** Math.min(attempt, 5), 3000), signal)
          }
        }
      } finally { controller.abort() }
    } }
  }

  _requestId(): string { return this.#idFactory() }
  /** Retained for callers that validate revisions; every manifest is accepted. */
  _assertCompatibility(_revision: RevisionMetadata): void { /* no generated bindings to check */ }

  async _unary<M extends UnaryRpcMethod>(method: M, request: UnaryRequest<M>, options: RpcCallOptions = {}): Promise<UnaryResponse<M>> {
    if (this.#closed) throw new ChronologRpcError('transport_unavailable', 'Client is closed')
    let attempt = 0
    while (true) {
      try { return await this.#transport.unary(method, request, { ...this.#callOptions(options.signal), ...options }) } catch (error) {
        attempt += 1
        if (attempt > this.#unaryRetryAttempts || !isChronologRpcError(error) || !error.retryable || options.signal?.aborted === true) throw error
        await delay(Math.min(50 * 2 ** attempt, 500), options.signal)
      }
    }
  }

  #revisionStream<T>(open: (cursor: string | undefined, signal: AbortSignal) => AsyncIterable<T>, cursor: (value: T) => string | undefined): StreamResource<T> {
    return this.#track(new StreamResource({ open, cursor, ...(this.#streamRetryDelayMs === undefined ? {} : { retryDelayMs: this.#streamRetryDelayMs }) }))
  }

  #track<T>(resource: StreamResource<T>): StreamResource<T> {
    this.#resources.add(resource)
    resource.onDispose(() => this.#resources.delete(resource))
    return resource
  }

  #callOptions(signal?: AbortSignal): RpcCallOptions {
    return { ...(signal === undefined ? {} : { signal }), ...(this.#token === undefined ? {} : { token: this.#token }) }
  }
}

/** Signed, resumable reader/writer enrollment for the current replica. */
export class EnrollmentActions {
  constructor(readonly client: ChronologClient) {}

  /** The caller keeps requestId so a reopened device resumes the same request and keys. */
  async createRequest(input: {
    readonly requestId: string
    readonly roles: readonly EnrollmentRole[]
    readonly writerProgram?: ProgramRights
  }, options: RpcCallOptions = {}): Promise<CreateEnrollmentResponse> {
    return this.client._unary('enrollment.createRequest', { groupId: this.client.groupId, ...input }, options)
  }

  /** An issuer's stable operationId makes an interrupted multi-step approval resumable. */
  async approveRequest(input: {
    readonly operationId: string
    readonly signedRequest: string
    readonly roles: readonly EnrollmentRole[]
    readonly writerProgram?: ProgramRights
    readonly grantFullHistory: boolean
  }, options: RpcCallOptions = {}): Promise<ApproveEnrollmentResponse> {
    return this.client._unary('enrollment.approveRequest', {
      groupId: this.client.groupId, requestId: input.operationId, signedRequest: input.signedRequest,
      roles: input.roles, grantFullHistory: input.grantFullHistory,
      ...(input.writerProgram === undefined ? {} : { writerProgram: input.writerProgram }),
    }, options)
  }

  /** Applying a receipt does not report ready until grants, keys, engine and final history are usable. */
  async getStatus(requestId: string, options: RpcCallOptions & { readonly signedApproval?: string } = {}): Promise<EnrollmentStatus> {
    const { signedApproval, ...call } = options
    return this.client._unary('enrollment.getStatus', {
      groupId: this.client.groupId, requestId, ...(signedApproval === undefined ? {} : { signedApproval }),
    }, call)
  }
}

/** A submitted ownership change, with the id of the object it created (when it creates one). */
export interface OwnershipChange<Id extends Uint8Array | undefined = undefined> {
  readonly handle: TransactionHandle
  readonly id: Id
}

/**
 * Sharing, teams and transfers. Each method submits one transaction whose
 * only step is the platform operation; await `change.handle.final()` and
 * inspect its outcome before depending on the change. To combine with SQL, use
 * `ownershipSteps` or `platformOp` and `TransactionHandle.createdId()`.
 */
export class OwnershipActions {
  constructor(readonly client: ChronologClient) {}

  /** Let `input.with` change your rows of a table (one row, or all of them). */
  async share(input: ShareInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.share(input), options)
  }

  /** End a grant. The grantor (or an admin of a grantor team) revokes; the grantee may renounce. */
  async revoke(grantId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.revokeGrant(grantId), options)
  }

  /** Create a team administered by you. Invitees join by accepting. */
  async createTeam(
    input: { readonly governance?: CollectiveGovernance; readonly invite?: readonly Uint8Array[] } = {},
    options?: TransactionOptions,
  ): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.createTeam(input), options)
  }

  async acceptInvitation(teamId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.acceptMembership(teamId), options)
  }

  async leaveTeam(teamId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.leave(teamId), options)
  }

  /** Invite keys to a team (team admins only); an existing member's role changes instead. */
  async invite(teamId: Uint8Array, members: readonly Uint8Array[], role: CollectiveRole = 'member', options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(ownershipSteps.invite(teamId, members, role), options)
  }

  async removeMembers(teamId: Uint8Array, members: readonly Uint8Array[], options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(ownershipSteps.remove(teamId, members), options)
  }

  /** Any mix of invitations, role changes and removals, applied together. */
  async setMembers(teamId: Uint8Array, changes: readonly MemberChange[], options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.setMembers(teamId, changes), options)
  }

  /** Offer one row to a new owner; it moves when the recipient accepts. */
  async offerRow(input: OfferRowInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.offerRow(input), options)
  }

  /**
   * Offer every row you (or a team you administer) own, across all tables:
   * the key-change path. The offered row set and contents must remain unchanged.
   */
  async offerAll(input: OfferAllInput, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    return this.#create(ownershipSteps.offerAll(input), options)
  }

  /** Cancel your offer, or decline an offer addressed to you (team admins may act for teams). */
  async cancelOffer(offerId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.cancelTransfer(offerId), options)
  }

  async acceptOffer(offerId: Uint8Array, options?: TransactionOptions): Promise<OwnershipChange> {
    return this.#submit(platformOp.acceptTransfer(offerId), options)
  }

  async #submit(step: PlatformOp, options?: TransactionOptions): Promise<OwnershipChange> {
    return { handle: await this.client.transaction([step], options), id: undefined }
  }

  async #create(step: PlatformOp, options?: TransactionOptions): Promise<OwnershipChange<Uint8Array>> {
    const handle = await this.client.transaction([step], options)
    return { handle, id: await handle.createdId(0) }
  }
}

function encodeTransactionStep(input: TransactionStepInput): RpcProgramStep {
  if (isEmitStep(input)) {
    const validated = emit(input.topic, input.payload)
    return { emit: { topic: validated.topic, payload: validated.payload } }
  }
  return typeof input !== 'string' && isPlatformOp(input) ? { platform: encodePlatformOp(input) } : encodeTransactionStatement(input)
}

function eventReadOptions(options: EventReadOptions): EventReadOptions {
  return { ...(options.cursor === undefined ? {} : { cursor: options.cursor }),
    ...(options.topics === undefined ? {} : { topics: [...options.topics] }),
    ...(options.limit === undefined ? {} : { limit: options.limit }) }
}

function encodeTransactionStatement(input: TransactionStatementInput): RpcSqlStatement {
  if (typeof input === 'string') return { sql: input, bindings: [] }
  if ('bindings' in input) {
    return {
      sql: input.sql,
      bindings: input.bindings.map((binding) => ({ parameter: binding.parameter, value: toRpcValue(binding.value) })),
    }
  }
  const params = input.params ?? []
  if (isClientSqlValueArray(params)) {
    return {
      sql: input.sql,
      bindings: params.map((value, index) => ({ parameter: { kind: 'index' as const, index: index + 1 }, value: toRpcValue(toSqlValue(value)) })),
    }
  }
  const used = new Set<string>()
  const bindings = scanNamedParameters(input.sql).map((token) => {
    const bare = token.slice(1)
    const key = Object.hasOwn(params, token) ? token : Object.hasOwn(params, bare) ? bare : undefined
    if (key === undefined) throw new TypeError(`Missing SQL binding ${token}`)
    used.add(key)
    return { parameter: { kind: 'name' as const, name: token }, value: toRpcValue(toSqlValue(params[key])) }
  })
  const unused = Object.keys(params).filter((key) => !used.has(key))
  if (unused.length > 0) throw new TypeError(`Unused SQL bindings: ${unused.join(', ')}`)
  return { sql: input.sql, bindings }
}

function toRpcValue(value: SqlValue): LocalSqlValue {
  if (!isSqlValue(value)) throw new TypeError('Invalid SQL value')
  switch (value.kind) {
    case 'null': return { kind: 'null' }
    case 'integer': return { kind: 'integer', value: value.value.toString(10) }
    case 'real': return { kind: 'real', value: value.value }
    case 'text': return { kind: 'text', value: value.value }
    case 'blob': return { kind: 'blob', value: Uint8Array.from(value.value) }
  }
}

/** Finds SQLite named parameters while ignoring quoted text, identifiers, and comments. */
function scanNamedParameters(sql: string): readonly string[] {
  const found: string[] = []
  const seen = new Set<string>()
  for (let index = 0; index < sql.length;) {
    const char = sql[index]!
    const next = sql[index + 1]
    if (char === "'" || char === '"' || char === '`' || char === '[') {
      const close = char === '[' ? ']' : char
      index += 1
      while (index < sql.length) {
        if (sql[index] === close) {
          if (close !== ']' && sql[index + 1] === close) { index += 2; continue }
          index += 1
          break
        }
        index += 1
      }
      continue
    }
    if (char === '-' && next === '-') { index = sql.indexOf('\n', index + 2); if (index < 0) break; continue }
    if (char === '/' && next === '*') { const end = sql.indexOf('*/', index + 2); index = end < 0 ? sql.length : end + 2; continue }
    if ((char === ':' || char === '@' || char === '$') && /[A-Za-z_]/u.test(next ?? '')) {
      let end = index + 2
      while (/[A-Za-z0-9_]/u.test(sql[end] ?? '')) end += 1
      const token = sql.slice(index, end)
      if (!seen.has(token)) { seen.add(token); found.push(token) }
      index = end
      continue
    }
    index += 1
  }
  return found
}

async function* mapAsync<A, B>(source: AsyncIterable<A>, map: (value: A) => B): AsyncIterable<B> {
  for await (const value of source) yield map(value)
}

/** Bound the caller even when an injected transport ignores cancellation. */
function dispatchLiveCall<T>(dispatch: () => Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const cancelled = () => {
      signal.removeEventListener('abort', cancelled)
      reject(isChronologRpcError(signal.reason) ? signal.reason :
        new ChronologRpcError('cancelled', 'Live signal send was cancelled', { cause: signal.reason, retryable: false }))
    }
    if (signal.aborted) { cancelled(); return }
    signal.addEventListener('abort', cancelled, { once: true })
    try {
      void dispatch().then(value => {
        signal.removeEventListener('abort', cancelled); resolve(value)
      }, (error: unknown) => {
        signal.removeEventListener('abort', cancelled)
        if (signal.aborted) cancelled()
        else reject(error)
      })
    } catch (error) {
      signal.removeEventListener('abort', cancelled); reject(error)
    }
  })
}

function assertLiveSignalOptions(value: unknown, names: readonly string[]): void {
  const prototype: unknown = typeof value === 'object' && value !== null ? Object.getPrototypeOf(value) : undefined
  if (typeof value !== 'object' || value === null ||
      (prototype !== Object.prototype && prototype !== null) ||
      Object.keys(value).some(name => !names.includes(name))) {
    throw new ChronologRpcError('invalid_argument', 'Live signal options have no durable retry or replay fields', {
      retryable: false, details: { signalCode: 'signal_options_invalid' },
    })
  }
}

function stableClientValue(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'bigint') return `${value}n`
  if (value instanceof Uint8Array) return toBase64Url(value)
  if (Array.isArray(value)) return `[${value.map(stableClientValue).join(',')}]`
  if (typeof value === 'object') {
    const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableClientValue(item)}`).join(',')}}`
  }
  return typeof value
}

function isClientSqlValueArray(value: readonly unknown[] | Readonly<Record<string, unknown>>): value is readonly unknown[] {
  return Array.isArray(value)
}

function delay(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) return Promise.reject(signal.reason)
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timeout); reject(signal?.reason) }
    const timeout = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, milliseconds)
    signal?.addEventListener('abort', abort, { once: true })
  })
}

import { sha256, utf8 } from '@chronolog/canonical'
import type { EphemeralSignal, Signals } from '@chronolog/signals'
import {
  assertValidChangeProgram,
  bytesToBase64Url as toBase64Url,
  decodePlatformOp,
  decodeChangeProgram,
  emit,
  type ProgramStep,
  type SqlStatement,
  type ChangeProgram,
  type SqlValue,
  type EventReadOptions,
} from '@chronolog/protocol'

import type { ChronologRpcService, RpcCallContext } from './contract.js'
import { ChronologRpcError, type RpcErrorCode } from './errors.js'
import type {
  ApproveEnrollmentRequest,
  ApproveEnrollmentResponse,
  CreateEnrollmentRequest,
  CreateEnrollmentResponse,
  EnrollmentStatus,
  GetEnrollmentStatusRequest,
  GetOutcomeRequest,
  GetGovernanceStatusRequest,
  GetReplicationStatusRequest,
  GetSettlementEvidenceRequest,
  GetStatusRequest,
  GetValidatorWatermarkRequest,
  GovernanceStatus,
  GrantCapabilityRequest,
  GrantCapabilityResponse,
  GrantHistoricalAccessRequest,
  GrantHistoricalAccessResponse,
  LiveSqlEvent,
  LiveSqlRequest,
  LocalSqlRequest,
  LocalSqlResponse,
  LocalSqlValue,
  NodeStatus,
  RevokeCapabilitiesRequest,
  RevokeCapabilitiesResponse,
  ReplicationStatus,
  RevisionMetadata,
  RpcProgramStep,
  RpcSqlStatement,
  SettlementEvidence,
  SqlView,
  StreamOutcomeRequest,
  StreamReplicationStatusRequest,
  StreamSettlementEvidenceRequest,
  StreamStatusRequest,
  RotateEpochRequest,
  RotateEpochResponse,
  SubmitTransactionRequest,
  SubmitTransactionResponse,
  TransactionOutcome,
  ValidatorWatermark,
  SubmitChangeRequest, SubmitChangeResponse, SubmitSignedRequest, EventReadRequest, EventReadResponse,
  SendSignalRequest, SubscribeSignalsRequest,
  GetOperationRequest, OperationStatus, StreamOperationsRequest,
  OpenReadViewRequest, OpenReadViewResponse, ReadViewRequest, QueryReadViewRequest, EventsReadViewRequest, LocalSqlResult,
  ViewChangesRequest, ViewChangesResponse,
} from './types.js'
import { RPC_API_VERSION } from './types.js'
import type {
  ChronologRpcNodeService,
  EnrollmentRpcService,
  GovernanceRpcAdmin,
  RpcReadHandle,
  RpcPublishedTransaction,
} from './service-contract.js'

export type {
  ChronologRpcNodeService,
  LocalSqlExecution,
  RpcMaterializedOutcome,
  RpcNodeCandidate,
  RpcNodeCandidateCore,
  RpcNodeSettlementEvidence,
  RpcNodeStatusSnapshot,
  RpcNodeWatermark,
} from './service-contract.js'

export interface NodeRpcServiceOptions {
  readonly node: ChronologRpcNodeService
  readonly governanceAdmin?: GovernanceRpcAdmin
  readonly enrollment?: EnrollmentRpcService
  /** Owned by the peer service; RPC supplies only a cancellable local facade. */
  readonly signals?: Signals
  readonly maxLocalSqlRows?: number
  readonly now?: () => number
  readonly maxReadViews?: number
  readonly readViewLeaseMs?: number
}

interface ReadLease {
  readonly owner: string
  readonly requestKey: string
  readonly handle: RpcReadHandle
  readonly response: OpenReadViewResponse
  readonly timer: ReturnType<typeof setTimeout>
}

/** RPC facade over a node: local reads, transaction submission, outcomes and evidence. */
export class NodeRpcService implements ChronologRpcService {
  readonly #node: ChronologRpcNodeService
  readonly #governanceAdmin: GovernanceRpcAdmin | undefined
  readonly #enrollmentService: EnrollmentRpcService | undefined
  readonly #signals: Signals | undefined
  readonly #signalLifetime = new AbortController()
  readonly #maxLocalSqlRows: number
  readonly #now: () => number
  readonly #maxReadViews: number
  readonly #readViewLeaseMs: number
  readonly #views = new Map<string, ReadLease>()
  readonly #opening = new Map<string, { readonly view: SqlView; readonly promise: Promise<OpenReadViewResponse> }>()
  #closed = false

  constructor(options: NodeRpcServiceOptions) {
    this.#node = options.node
    this.#governanceAdmin = options.governanceAdmin
    this.#enrollmentService = options.enrollment
    this.#signals = options.signals
    this.#maxLocalSqlRows = nonnegative(options.maxLocalSqlRows ?? 10_000, 'maxLocalSqlRows')
    this.#now = options.now ?? Date.now
    this.#maxReadViews = nonnegative(options.maxReadViews ?? 32, 'maxReadViews')
    this.#readViewLeaseMs = nonnegative(options.readViewLeaseMs ?? 30_000, 'readViewLeaseMs')
    if (this.#readViewLeaseMs < 1 || this.#readViewLeaseMs > 300_000) throw new TypeError('readViewLeaseMs must be from 1 to 300000')
  }

  async submitChange(request: SubmitChangeRequest, context: RpcCallContext): Promise<SubmitChangeResponse> {
    this.#assertGroup(request.groupId)
    let program: ChangeProgram
    try {
      if (!(request.program instanceof Uint8Array)) throw invalid('program must be canonical bytes')
      program = decodeChangeProgram(request.program)
    } catch (error) { throw new ChronologRpcError('invalid_argument', 'Invalid canonical change program', { cause: error }) }
    const submission = await this.#publish(program, request.operationId, request.groupId, context)
    return { ...submission, operationId: request.operationId, proposalId: submission.transactionId }
  }

  async submitSigned(request: SubmitSignedRequest, context: RpcCallContext): Promise<SubmitTransactionResponse> {
    this.#assertGroup(request.groupId)
    context.signal?.throwIfAborted()
    if (!(request.signedWire instanceof Uint8Array) || request.signedWire.byteLength === 0) throw invalid('signedWire must contain original signed proposal bytes')
    if (this.#node.submitSigned === undefined) throw failed('Signed publisher ingress is not enabled for this node')
    // The publisher owns signing and retry identity. The replica validates and
    // appends these exact bytes without access to its local authoring path.
    return submissionResponse(await this.#node.submitSigned(request.signedWire))
  }

  async readEvents(request: EventReadRequest, context: RpcCallContext): Promise<EventReadResponse> {
    this.#assertGroup(request.groupId)
    context.signal?.throwIfAborted()
    if (this.#node.events === undefined) throw failed('Durable events are not enabled for this node')
    return this.#node.events.read(eventOptions(request))
  }

  async *subscribeEvents(request: EventReadRequest, context: RpcCallContext): AsyncIterable<EventReadResponse> {
    this.#assertGroup(request.groupId)
    if (this.#node.events === undefined) throw failed('Durable events are not enabled for this node')
    yield* this.#node.events.subscribe({ ...eventOptions(request), ...(context.signal === undefined ? {} : { signal: context.signal }) })
  }

  async sendSignal(request: SendSignalRequest, context: RpcCallContext): Promise<EphemeralSignal> {
    this.#assertGroup(request.groupId)
    const signal = this.#liveSignal(context)
    signal.throwIfAborted()
    if (this.#signals === undefined) throw failed('Live signals are not enabled for this node')
    try {
      return await this.#signals.send(request.topic, request.payload, {
        signal, ...(request.ttlMs === undefined ? {} : { ttlMs: request.ttlMs }),
      })
    } catch (error) { throw signalRpcError(error, signal) }
  }

  async *subscribeSignals(request: SubscribeSignalsRequest, context: RpcCallContext): AsyncIterable<EphemeralSignal> {
    this.#assertGroup(request.groupId)
    const signal = this.#liveSignal(context)
    signal.throwIfAborted()
    if (this.#signals === undefined) throw failed('Live signals are not enabled for this node')
    try {
      yield* this.#signals.subscribe({
        signal, ...(request.topics === undefined ? {} : { topics: request.topics }),
        ...(request.mode === undefined ? {} : { mode: request.mode }),
      })
    } catch (error) { throw signalRpcError(error, signal) }
  }

  #liveSignal(context: RpcCallContext): AbortSignal {
    return context.signal === undefined ? this.#signalLifetime.signal
      : AbortSignal.any([this.#signalLifetime.signal, context.signal])
  }

  async getOperation(request: GetOperationRequest, context: RpcCallContext): Promise<OperationStatus | null> {
    this.#assertGroup(request.groupId)
    if (this.#node.operation === undefined) throw failed('Durable operation lookup is not enabled for this node')
    const identity = await operationIdentity(request.operationId, request.groupId, context)
    const found = await this.#node.operation(identity)
    if (found === null) return null
    return { operationId: request.operationId, proposalId: found.proposalId, final: found.final,
      outcome: found.outcome === null ? null : { outcome: found.outcome.outcome,
        rejectionCode: found.outcome.rejectionCode, failingStatementIndex: found.outcome.failingStatementIndex } }
  }

  async *subscribeOperations(request: StreamOperationsRequest, context: RpcCallContext): AsyncIterable<OperationStatus> {
    this.#assertGroup(request.groupId)
    let previous: string | undefined
    for await (const operation of this.#snapshots(undefined, context.signal, () => this.getOperation(request, context))) {
      if (operation === null) continue
      const fingerprint = stableFingerprint(operation)
      if (fingerprint !== previous) { previous = fingerprint; yield operation }
    }
  }

  async *streamViewChanges(request: ViewChangesRequest, context: RpcCallContext): AsyncIterable<ViewChangesResponse> {
    this.#assertGroup(request.groupId)
    if (Object.keys(request).some(key => !['groupId', 'requestId', 'view'].includes(key))) throw invalid('View changes have no replay cursor')
    const signal = context.signal === undefined ? this.#signalLifetime.signal : AbortSignal.any([this.#signalLifetime.signal, context.signal])
    signal.throwIfAborted()
    if (this.#node.changes === undefined) throw failed('View change notifications are not enabled for this node')
    yield* this.#node.changes({ view: request.view === undefined ? 'final' : sqlView(request.view), signal })
  }

  async openReadView(request: OpenReadViewRequest, context: RpcCallContext): Promise<OpenReadViewResponse> {
    this.#assertGroup(request.groupId)
    context.signal?.throwIfAborted()
    if (this.#node.readView === undefined) throw failed('Revision-scoped reads are not enabled for this node')
    if (typeof request.requestId !== 'string' || request.requestId.length === 0 || request.requestId.length > 512) throw invalid('Read requestId must contain 1 to 512 characters')
    const view = request.view === undefined ? 'final' : sqlView(request.view)
    const owner = principal(context)
    const requestKey = JSON.stringify([owner, request.groupId, request.requestId])
    const existing = this.#opening.get(requestKey)
    if (existing !== undefined) {
      if (existing.view !== view) throw new ChronologRpcError('already_exists', 'Read request identity is bound to another view')
      return existing.promise
    }
    for (const [viewId, lease] of this.#views) if (lease.response.expiresAt <= this.#now()) await this.#releaseView(viewId)
    if (this.#opening.size >= this.#maxReadViews) throw new ChronologRpcError('resource_exhausted', 'Too many pinned read views')
    const promise = (async () => {
      const handle = await this.#node.readView!({ view })
      if (this.#closed || context.signal?.aborted === true) {
        await handle.release()
        throw new ChronologRpcError('cancelled', 'Read view creation was cancelled')
      }
      const viewId = crypto.randomUUID()
      const response = { viewId, revision: handle.revision, finalRevision: handle.finalRevision, view: handle.view, expiresAt: this.#now() + this.#readViewLeaseMs }
      const timer = setTimeout(() => { void this.#releaseView(viewId).catch(() => undefined) }, this.#readViewLeaseMs)
      timer.unref?.()
      this.#views.set(viewId, { owner, requestKey, handle, response, timer })
      return response
    })()
    this.#opening.set(requestKey, { view, promise })
    try { return await promise }
    catch (error) { this.#opening.delete(requestKey); throw error }
  }

  async queryReadView(request: QueryReadViewRequest, context: RpcCallContext): Promise<LocalSqlResult> {
    const lease = await this.#lease(request, context)
    const execution = await lease.handle.query(request.sql, request.parameters.map(copyLocalSqlValue))
    const limit = boundedRows(request.maxRows, this.#maxLocalSqlRows)
    const rows = execution.rows.slice(0, limit).map((row) => row.map(copyLocalSqlValue))
    return { columns: execution.columns.map((column) => ({ ...column })), rows, truncated: rows.length !== execution.rows.length, consensusSafe: false }
  }

  async eventsReadView(request: EventsReadViewRequest, context: RpcCallContext): Promise<EventReadResponse> {
    const lease = await this.#lease(request, context)
    return lease.handle.readEvents(eventOptions(request))
  }

  async releaseReadView(request: ReadViewRequest, context: RpcCallContext): Promise<{ readonly released: true }> {
    this.#assertGroup(request.groupId)
    const lease = this.#views.get(request.viewId)
    if (lease !== undefined) {
      if (lease.owner !== principal(context)) throw new ChronologRpcError('not_found', 'Unknown read view')
      await this.#releaseView(request.viewId)
    }
    return { released: true }
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    this.#signalLifetime.abort(new ChronologRpcError('cancelled', 'RPC service is closed'))
    await Promise.allSettled([...this.#views.keys()].map((viewId) => this.#releaseView(viewId)))
    await Promise.allSettled([...this.#opening.values()].map((entry) => entry.promise))
    this.#opening.clear()
  }

  async #lease(request: ReadViewRequest, context: RpcCallContext): Promise<ReadLease> {
    this.#assertGroup(request.groupId)
    context.signal?.throwIfAborted()
    if (typeof request.viewId !== 'string' || request.viewId.length > 128) throw invalid('Invalid read view identity')
    const lease = this.#views.get(request.viewId)
    if (lease === undefined || lease.owner !== principal(context)) throw revisionUnavailable('Pinned read view is unavailable')
    if (lease.response.expiresAt <= this.#now()) {
      await this.#releaseView(request.viewId)
      throw revisionUnavailable('Pinned read view expired; capture a new coherent view')
    }
    return lease
  }

  async #releaseView(viewId: string): Promise<void> {
    const lease = this.#views.get(viewId)
    if (lease === undefined) return
    this.#views.delete(viewId)
    this.#opening.delete(lease.requestKey)
    clearTimeout(lease.timer)
    await lease.handle.release()
  }

  async getStatus(request: GetStatusRequest, _context: RpcCallContext): Promise<NodeStatus> {
    this.#assertGroupOptional(request.groupId)
    const status = await this.#node.status()
    return {
      apiVersion: RPC_API_VERSION,
      state: !status.started
        ? 'starting'
        : status.lastError === undefined && status.quarantinedFeeds.length === 0
          ? 'ready'
          : 'degraded',
      nodeId: toBase64Url(this.#node.identity),
      revision: this.#revision(status.materializedRevision, status.orderLength),
      writable: await this.#node.isWritable(),
      validating: status.validating,
      ...(status.lastError === undefined ? {} : { lastErrorCode: status.lastError }),
    }
  }

  async getGovernanceStatus(request: GetGovernanceStatusRequest, _context: RpcCallContext): Promise<GovernanceStatus> {
    this.#assertGroup(request.groupId)
    return this.#admin().getStatus(request)
  }

  async grantCapability(request: GrantCapabilityRequest, _context: RpcCallContext): Promise<GrantCapabilityResponse> {
    this.#assertGroup(request.groupId)
    return this.#admin().grantCapability(request)
  }

  async revokeCapabilities(request: RevokeCapabilitiesRequest, _context: RpcCallContext): Promise<RevokeCapabilitiesResponse> {
    this.#assertGroup(request.groupId)
    return this.#admin().revokeCapabilities(request)
  }

  async rotateEpoch(request: RotateEpochRequest, _context: RpcCallContext): Promise<RotateEpochResponse> {
    this.#assertGroup(request.groupId)
    return this.#admin().rotateEpoch(request)
  }

  async grantHistoricalAccess(request: GrantHistoricalAccessRequest, _context: RpcCallContext): Promise<GrantHistoricalAccessResponse> {
    this.#assertGroup(request.groupId)
    return this.#admin().grantHistoricalAccess(request)
  }

  async createEnrollmentRequest(request: CreateEnrollmentRequest, _context: RpcCallContext): Promise<CreateEnrollmentResponse> {
    this.#assertGroup(request.groupId)
    return this.#enrollment().createRequest(request)
  }

  async approveEnrollmentRequest(request: ApproveEnrollmentRequest, _context: RpcCallContext): Promise<ApproveEnrollmentResponse> {
    this.#assertGroup(request.groupId)
    return this.#enrollment().approveRequest(request)
  }

  async getEnrollmentStatus(request: GetEnrollmentStatusRequest, _context: RpcCallContext): Promise<EnrollmentStatus> {
    this.#assertGroup(request.groupId)
    return this.#enrollment().getStatus(request)
  }

  async *streamStatus(request: StreamStatusRequest, context: RpcCallContext): AsyncIterable<NodeStatus> {
    this.#assertGroupOptional(request.groupId)
    yield* this.#snapshots(request.resumeAfterEventSetRevision, context.signal, () => this.getStatus(request, context))
  }

  async localSql(request: LocalSqlRequest, _context: RpcCallContext): Promise<LocalSqlResponse> {
    this.#assertGroup(request.groupId)
    const view = sqlView(request.view)
    const atRevision = request.atRevision === undefined ? this.#viewRevision(view) : parseRevision(request.atRevision)
    const execution = this.#node.localSql(
      request.sql,
      request.parameters.map(copyLocalSqlValue),
      { atRevision, view },
    )
    if (execution.revision !== atRevision) throw revisionUnavailable('Requested SQL reader is unavailable')
    const limit = boundedRows(request.maxRows, this.#maxLocalSqlRows)
    const rows = execution.rows.slice(0, limit).map((row) => row.map(copyLocalSqlValue))
    return {
      revision: this.#revision(execution.revision, execution.orderLength, view),
      result: {
        columns: execution.columns.map((column) => ({ ...column })),
        rows,
        truncated: rows.length !== execution.rows.length,
        consensusSafe: false,
      },
    }
  }

  async *liveSql(request: LiveSqlRequest, context: RpcCallContext): AsyncIterable<LiveSqlEvent> {
    this.#assertGroup(request.groupId)
    const view = sqlView(request.view)
    const queryDigest = toBase64Url(await sha256(utf8(stableFingerprint({
      sql: request.sql, parameters: request.parameters, view, maxRows: boundedRows(request.maxRows, this.#maxLocalSqlRows),
    }))))
    if (request.resume !== undefined &&
        (request.resume.groupId !== request.groupId || request.resume.queryDigest !== queryDigest)) {
      throw invalid('Live-query cursor does not belong to this SQL query')
    }
    const barrier = this.#node.revision
    const events = this.#node.revisions(barrier, context.signal)
    let prior: LocalSqlResponse
    try {
      prior = await this.localSql({ ...request, view }, context)
    } catch (error) {
      if (isSqlInvalid(error)) {
        yield { type: 'reset', revision: this.#revision(this.#viewRevision(view), this.#viewOrderLength(view), view), queryDigest, reason: 'query_invalid' }
        return
      }
      throw error
    }
    const initialMatches = request.resume === undefined || request.resume.eventSetRevision === prior.revision.eventSetRevision
    yield initialMatches
      ? { type: 'snapshot', revision: prior.revision, queryDigest, result: prior.result }
      : { type: 'reset', revision: prior.revision, queryDigest, result: prior.result, reason: 'history_unavailable' }
    let priorMaterialized = prior.revision.materializedRevision
    let priorManifest = prior.revision.executionManifestDigest
    for await (const _event of events) {
      if (this.#viewRevision(view).toString(10) === priorMaterialized) continue
      let next: LocalSqlResponse
      try {
        next = await this.localSql({ ...request, view }, context)
      } catch (error) {
        if (isSqlInvalid(error)) {
          yield { type: 'reset', revision: this.#revision(this.#viewRevision(view), this.#viewOrderLength(view), view), queryDigest, reason: 'query_invalid' }
          return
        }
        throw error
      }
      const previousMaterializedRevision = priorMaterialized
      priorMaterialized = next.revision.materializedRevision
      if (next.revision.executionManifestDigest !== priorManifest) {
        priorManifest = next.revision.executionManifestDigest
        yield { type: 'reset', revision: next.revision, queryDigest, result: next.result, reason: 'manifest_changed' }
      } else {
        yield { type: 'change', revision: next.revision, queryDigest, result: next.result, previousMaterializedRevision }
      }
    }
  }

  async submitTransaction(request: SubmitTransactionRequest, context: RpcCallContext): Promise<SubmitTransactionResponse> {
    this.#assertGroup(request.groupId)
    const program: ChangeProgram = { version: 3, steps: decodeSteps(request.steps) }
    try { assertValidChangeProgram(program) } catch (error) {
      throw new ChronologRpcError('invalid_argument', `Invalid SQL transaction: ${errorCode(error, 'SQL_PROGRAM_INVALID')}`, { cause: error })
    }
    return this.#publish(program, request.idempotencyKey ?? request.requestId, request.groupId, context)
  }

  async #publish(program: ChangeProgram, callerOperationId: string, groupId: string, context: RpcCallContext): Promise<SubmitTransactionResponse> {
    const operationId = await operationIdentity(callerOperationId, groupId, context)
    try {
      // The node's durable journal owns authoring, authorization and exact-byte
      // retries. Recreating this facade or revoking a writer cannot erase a
      // previous publication or allocate a new timestamp for the same request.
      const published = await this.#node.publish({ program, operationId })
      return submissionResponse(published)
    } catch (error) {
      const code = errorCode(error, 'TRANSACTION_PUBLICATION_FAILED')
      if (code === 'OPERATION_ID_CONFLICT') throw new ChronologRpcError('already_exists', 'Transaction retry identity is already bound to different steps', { cause: error })
      if (code === 'WRITER_UNAUTHORIZED') throw failed('This node cannot write to the group')
      throw error
    }
  }

  async getOutcome(request: GetOutcomeRequest, _context: RpcCallContext): Promise<TransactionOutcome> {
    this.#assertGroup(request.groupId)
    const txId = utf8(request.transactionId)
    const candidate = this.#node.candidate(txId)
    if (candidate === null) throw new ChronologRpcError('not_found', 'Unknown transaction')
    // Read the outcome and its finality in one synchronous replica snapshot.
    // Awaiting transport status between them could label an earlier speculative
    // result final after a replay changed the transaction while we waited.
    const outcome = this.#node.outcome(txId)
    return {
      transactionId: request.transactionId,
      outcome: outcome === null
        ? { type: 'pending' }
        : outcome.outcome === 'accepted'
          ? { type: 'accepted' }
          : {
              type: 'rejected',
              rejection: { code: outcome.rejectionCode ?? 'rejected', statementIndex: outcome.failingStatementIndex },
            },
      eventSetRevision: this.#node.revision.toString(10),
      materializedRevision: this.#node.materializedRevision.toString(10),
      orderKey: orderKeyText(candidate.orderKey),
      changedByReplay: this.#node.outcomeChangedByReplay(txId),
      admissible: candidate.state === 'admissible',
      final: outcome !== null && this.#node.isFinal(txId),
      observedAt: new Date(this.#now()).toISOString(),
    }
  }

  async *streamOutcome(request: StreamOutcomeRequest, context: RpcCallContext): AsyncIterable<TransactionOutcome> {
    this.#assertGroup(request.groupId)
    yield* this.#snapshots(request.resumeAfterEventSetRevision, context.signal, () => this.getOutcome(request, context))
  }

  async getSettlementEvidence(request: GetSettlementEvidenceRequest, context: RpcCallContext): Promise<SettlementEvidence> {
    const outcome = await this.getOutcome(request, context)
    const txId = utf8(request.transactionId)
    const candidate = this.#node.candidate(txId)
    const core = this.#node.candidateCore(txId)
    if (candidate === null || core === null) throw new ChronologRpcError('not_found', 'Unknown transaction')
    const evidence = await this.#node.settlementEvidence(txId)
    return {
      transactionId: request.transactionId,
      outcome,
      evidenceRevision: this.#node.revision.toString(10),
      orderKey: orderKeyText(candidate.orderKey),
      authorTimestamp: core.authorTimestampMs.toString(10),
      validationPolicyId: toBase64Url(core.validationPolicy),
      membershipRevision: toBase64Url(core.membershipRevision),
      ...(evidence?.watermark.cutoffMs == null ? {} : { policyWatermarkTimestamp: evidence.watermark.cutoffMs.toString(10) }),
      blockingHeartbeats: (evidence?.watermark.heartbeatIds ?? []).map(toBase64Url),
      unresolvedReferences: (evidence?.unresolvedAttestationIds ?? []).map((reference) => ({ kind: 'attestation' as const, reference: toBase64Url(reference) })),
      confidence: evidence?.belowWatermark === true ? 'policy_watermark_reached' : evidence === null ? 'insufficient' : 'provisional',
      calculatedAt: new Date(this.#now()).toISOString(),
    }
  }

  async *streamSettlementEvidence(request: StreamSettlementEvidenceRequest, context: RpcCallContext): AsyncIterable<SettlementEvidence> {
    this.#assertGroup(request.groupId)
    yield* this.#snapshots(request.resumeAfterEventSetRevision, context.signal, () => this.getSettlementEvidence(request, context))
  }

  async getValidatorWatermark(request: GetValidatorWatermarkRequest, _context: RpcCallContext): Promise<ValidatorWatermark> {
    this.#assertGroup(request.groupId)
    const watermark = await this.#node.watermark()
    return {
      groupId: this.#groupId(),
      revision: this.#node.revision.toString(10),
      policyId: watermark?.policyId ?? toBase64Url(this.#node.validationPolicy),
      membershipRevision: toBase64Url(this.#node.membershipRevision),
      ...(watermark?.cutoffMs == null ? {} : { timestamp: watermark.cutoffMs.toString(10) }),
      supportingValidators: (watermark?.blockingValidatorIds ?? []).map(toBase64Url),
      blockedBy: watermark?.explanation === 'established' ? [] : (watermark?.blockingValidatorIds ?? []).map(toBase64Url),
    }
  }

  async getReplicationStatus(request: GetReplicationStatusRequest, _context: RpcCallContext): Promise<ReplicationStatus> {
    this.#assertGroup(request.groupId)
    const status = await this.#node.status()
    const knownPeers = status.transport.configuredPeers?.length ?? status.transport.peers.length
    const ingestionBacklog = Math.max(0, status.transport.records - status.processedTransportRecords)
    const feedsWithGaps = status.transport.feedsWithGaps ?? status.transport.feedStates?.filter((feed) => feed.hasGaps).length ?? 0
    const pendingPayloads = this.#node.controlStore.missingProposalCount
    return {
      groupId: this.#groupId(),
      revision: this.#node.revision.toString(10),
      connectedPeers: status.transport.peers.length,
      knownPeers,
      feedsWithGaps,
      quarantinedFeeds: [...status.quarantinedFeeds],
      pendingPayloads,
      ingestionBacklog,
      ...(status.ingest === undefined && status.transport.lastCatchUpError === undefined ? {} : {
        ingestDiagnostics: [
          ...(status.ingest === undefined ? [] : [`phase=${status.ingest.phase}`, `age=${status.ingest.phaseAgeMs}ms`, `restarts=${status.ingest.subscriptionRestarts}`, `retry=${status.ingest.retryRecords}`]),
          ...(status.transport.lastCatchUpError === undefined ? [] : [`catchUp=${status.transport.lastCatchUpError}`]),
        ].join(' '),
      }),
      materializationPending: status.materializationPending,
      state: status.lastError !== undefined || status.transport.lastCatchUpError !== undefined || status.quarantinedFeeds.length > 0
        ? 'degraded'
        : ingestionBacklog > 0 || feedsWithGaps > 0 || pendingPayloads > 0 || status.materializationPending
          ? 'syncing'
          : (status.transport.connected ?? (knownPeers === 0 || status.transport.peers.length > 0)) ? 'current' : 'offline',
    }
  }

  async *streamReplicationStatus(request: StreamReplicationStatusRequest, context: RpcCallContext): AsyncIterable<ReplicationStatus> {
    this.#assertGroup(request.groupId)
    yield* this.#snapshots(request.resumeAfterEventSetRevision, context.signal, () => this.getReplicationStatus(request, context))
  }

  async *#snapshots<T>(resume: string | undefined, signal: AbortSignal | undefined, read: () => Promise<T>): AsyncIterable<T> {
    if (resume !== undefined) parseRevision(resume)
    const controller = new AbortController()
    const subscriptionSignal = signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal])
    // These streams send the complete current state first. A cursor from a
    // previous process is only a resume hint: the node's local event counter
    // can restart below it. Subscribe at the current barrier before reading so
    // neither a restart nor an update during the initial read hides finality.
    const events = this.#node.revisions(this.#node.revision, subscriptionSignal)
    try {
      yield await read()
      for await (const _event of events) yield await read()
    } finally {
      controller.abort()
    }
  }

  #revision(materializedRevision: bigint, orderLength: number, view: SqlView = 'local'): RevisionMetadata {
    return {
      groupId: this.#groupId(),
      view,
      eventSetRevision: this.#node.revision.toString(10),
      materializedRevision: materializedRevision.toString(10),
      publishedOrderLength: orderLength.toString(10),
      finalRevision: this.#node.finalRevision.toString(10),
      finalOrderLength: this.#node.finalOrderLength.toString(10),
      executionManifestDigest: toBase64Url(this.#node.executionManifestDigest),
      replaying: false,
    }
  }

  #viewRevision(view: SqlView): bigint { return view === 'final' ? this.#node.finalRevision : this.#node.materializedRevision }
  #viewOrderLength(view: SqlView): number { return view === 'final' ? this.#node.finalOrderLength : this.#node.orderLength }

  #enrollment(): EnrollmentRpcService {
    if (this.#enrollmentService === undefined) throw failed('Enrollment is not enabled for this node')
    return this.#enrollmentService
  }

  #admin(): GovernanceRpcAdmin {
    if (this.#governanceAdmin === undefined) {
      throw failed('Replicated governance is not enabled for this node')
    }
    return this.#governanceAdmin
  }

  #assertGroup(groupId: string): void {
    if (this.#closed) throw new ChronologRpcError('transport_unavailable', 'RPC service is closed')
    if (groupId !== this.#groupId()) throw new ChronologRpcError('not_found', 'Unknown group')
  }

  #assertGroupOptional(groupId?: string): void { if (groupId !== undefined) this.#assertGroup(groupId) }
  #groupId(): string { return toBase64Url(this.#node.groupId) }

}

function submissionResponse(published: RpcPublishedTransaction): SubmitTransactionResponse {
  return {
    transactionId: published.txIdText,
    candidateDigest: toBase64Url(published.candidateDigest),
    authorTimestampMs: published.core.authorTimestampMs.toString(10),
    transactionNonce: toBase64Url(published.core.nonce),
    executionManifestDigest: toBase64Url(published.core.executionManifestDigest),
    durableLocalAppend: true,
    publishedAt: new Date(Number(published.core.authorTimestampMs)).toISOString(),
  }
}

function decodeSteps(values: readonly RpcProgramStep[]): ProgramStep[] {
  if (!(values instanceof Array)) throw invalid('steps must be an array')
  return values.map((value): ProgramStep => {
    if (typeof value === 'object' && value !== null && 'emit' in value) {
      if (Object.keys(value).length !== 1 || typeof value.emit !== 'object' || value.emit === null) throw invalid('Emit step is malformed')
      try { return emit(value.emit.topic, value.emit.payload) }
      catch (error) { throw new ChronologRpcError('invalid_argument', 'Invalid emit step', { cause: error }) }
    }
    if (typeof value === 'object' && value !== null && 'platform' in value) {
      if (!(value.platform instanceof Uint8Array)) throw invalid('Platform step must be canonical CBOR bytes')
      try { return decodePlatformOp(value.platform) } catch (error) {
        throw new ChronologRpcError('invalid_argument', `Invalid platform step: ${errorCode(error, 'PLATFORM_OP_INVALID')}`, { cause: error })
      }
    }
    return decodeStatement(value)
  })
}

function decodeStatement(value: RpcSqlStatement): SqlStatement {
  {
    const bindings: RpcSqlStatement['bindings'] = value?.bindings
    if (typeof value?.sql !== 'string' || !(bindings instanceof Array)) throw invalid('SQL statement is malformed')
    return {
      sql: value.sql,
      bindings: bindings.map((binding) => ({
        parameter: binding.parameter?.kind === 'index'
          ? { kind: 'index' as const, index: binding.parameter.index }
          : binding.parameter?.kind === 'name'
            ? { kind: 'name' as const, name: binding.parameter.name }
            : (() => { throw invalid('SQL binding parameter is malformed') })(),
        value: rpcValueToSqlValue(binding.value),
      })),
    }
  }
}

/** The JSON-safe RPC value (integer as decimal text) as a protocol SqlValue. */
export function rpcValueToSqlValue(value: LocalSqlValue): SqlValue {
  switch (value?.kind) {
    case 'null': return { kind: 'null' }
    case 'integer':
      if (typeof value.value !== 'string' || !/^-?(0|[1-9][0-9]*)$/u.test(value.value)) throw invalid('SQL integer must be decimal text')
      return { kind: 'integer', value: BigInt(value.value) }
    case 'real':
      if (typeof value.value !== 'number' || !Number.isFinite(value.value)) throw invalid('SQL real must be a finite number')
      return { kind: 'real', value: value.value }
    case 'text':
      if (typeof value.value !== 'string') throw invalid('SQL text must be a string')
      return { kind: 'text', value: value.value }
    case 'blob':
      if (!(value.value instanceof Uint8Array)) throw invalid('SQL blob must be bytes')
      return { kind: 'blob', value: Uint8Array.from(value.value) }
    default: throw invalid('SQL value kind is unknown')
  }
}

/** A protocol SqlValue in the JSON-safe RPC form. */
export function sqlValueToRpcValue(value: SqlValue): LocalSqlValue {
  switch (value.kind) {
    case 'null': return { kind: 'null' }
    case 'integer': return { kind: 'integer', value: value.value.toString(10) }
    case 'real': return { kind: 'real', value: value.value }
    case 'text': return { kind: 'text', value: value.value }
    case 'blob': return { kind: 'blob', value: Uint8Array.from(value.value) }
  }
}

function copyLocalSqlValue(value: LocalSqlValue): LocalSqlValue {
  return value.kind === 'blob' ? { ...value, value: Uint8Array.from(value.value) } : { ...value }
}

function boundedRows(requested: number | undefined, maximum: number): number {
  if (requested === undefined) return maximum
  if (!Number.isSafeInteger(requested) || requested < 0) throw invalid('maxRows must be a nonnegative safe integer')
  return Math.min(requested, maximum)
}

function nonnegative(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be a nonnegative safe integer`)
  return value
}

function principal(context: RpcCallContext): string { return context.metadata?.principal ?? context.token ?? 'anonymous-local' }
async function operationIdentity(operationId: string, groupId: string, context: RpcCallContext): Promise<string> {
  if (typeof operationId !== 'string' || operationId.length === 0 || operationId.length > 512) throw invalid('Operation identity must contain 1 to 512 characters')
  return `rpc-operation:${toBase64Url(await sha256(utf8(JSON.stringify([principal(context), groupId, operationId]))))}`
}
function eventOptions(request: EventReadRequest | EventsReadViewRequest): EventReadOptions {
  return { ...(request.cursor === undefined ? {} : { cursor: request.cursor }),
    ...(request.topics === undefined ? {} : { topics: request.topics }),
    ...(request.limit === undefined ? {} : { limit: request.limit }) }
}
function invalid(message: string): ChronologRpcError { return new ChronologRpcError('invalid_argument', message) }
function failed(message: string): ChronologRpcError { return new ChronologRpcError('failed_precondition', message) }
function revisionUnavailable(message: string): ChronologRpcError { return new ChronologRpcError('revision_unavailable', message) }
function isSqlInvalid(error: unknown): boolean { return error instanceof Error && /SQL|sqlite|prepare|syntax/iu.test(error.message) }
function errorCode(error: unknown, fallback: string): string {
  if (typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string') return error.code
  return error instanceof Error && error.message !== '' ? error.message : fallback
}

function sqlView(value: SqlView | undefined): SqlView {
  if (value !== undefined && value !== 'local' && value !== 'final') throw invalid('SQL view must be local or final')
  return value ?? 'local'
}

function parseRevision(value: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) throw invalid('SQL revision must be a nonnegative decimal integer')
  return BigInt(value)
}
function orderKeyText(key: { readonly authorTimestampMs: bigint; readonly authorId: Uint8Array; readonly authorFeedSequence: bigint; readonly txId: Uint8Array }): string {
  return `${key.authorTimestampMs}:${toBase64Url(key.authorId)}:${key.authorFeedSequence}:${toBase64Url(key.txId)}`
}

function stableFingerprint(value: unknown): string {
  if (value === undefined) return 'u'
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'bigint') return `b:${value}`
  if (value instanceof Uint8Array) return `x:${toBase64Url(value)}`
  if (Array.isArray(value)) return `[${value.map(stableFingerprint).join(',')}]`
  if (typeof value === 'object') return `{${Object.entries(value as Record<string, unknown>).filter(([, item]) => item !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableFingerprint(item)}`).join(',')}}`
  throw new TypeError('Unsupported RPC value')
}

/** Live messages must never acquire the ordinary durable RPC retry policy. */
function signalRpcError(error: unknown, signal?: AbortSignal): ChronologRpcError {
  const message = error instanceof Error ? error.message : 'Signal operation failed'
  let code: RpcErrorCode = 'internal'
  if (signal?.aborted === true || (error instanceof DOMException && error.name === 'AbortError')) code = 'cancelled'
  else if (error instanceof DOMException && error.name === 'TimeoutError') code = 'deadline_exceeded'
  else if (message === 'SIGNAL_UNAUTHORIZED') code = 'permission_denied'
  else if (message === 'SIGNAL_ROUTE_UNAVAILABLE' || message === 'SIGNAL_ROUTE_CLOSED' || message === 'SIGNAL_CHANNEL_CLOSED' || message === 'SIGNAL_SEND_FAILED') code = 'transport_unavailable'
  else if (message === 'SIGNAL_BACKPRESSURE' || message === 'SIGNAL_SUBSCRIPTION_OVERFLOW' || message.endsWith('_QUOTA_EXCEEDED')) code = 'resource_exhausted'
  else if (message === 'SIGNAL_EXPIRED' || message === 'SIGNAL_SEND_TIMEOUT' || message === 'SIGNAL_RECEIVE_TIMEOUT') code = 'deadline_exceeded'
  else if (message.startsWith('SIGNAL_') && (message.endsWith('_INVALID') || message.endsWith('_TOO_LARGE') || message.endsWith('_TOO_COMPLEX'))) code = 'invalid_argument'
  else if (error instanceof ChronologRpcError) code = error.code
  return new ChronologRpcError(code, message, { cause: error, retryable: false })
}

import { sha256, utf8 } from '@chronolog/canonical'
import {
  assertValidSqlTransactionProgram,
  bytesToBase64Url as toBase64Url,
  decodePlatformOp,
  type ProgramStep,
  type SqlStatement,
  type SqlTransactionProgram,
  type SqlValue,
} from '@chronolog/protocol'

import type { ChronologRpcService, RpcCallContext } from './contract.js'
import { ChronologRpcError } from './errors.js'
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
} from './types.js'
import { RPC_API_VERSION } from './types.js'
import type {
  ChronologRpcNodeService,
  EnrollmentRpcService,
  GovernanceRpcAdmin,
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
  readonly maxLocalSqlRows?: number
  readonly now?: () => number
}

/** RPC facade over a node: local reads, transaction submission, outcomes and evidence. */
export class NodeRpcService implements ChronologRpcService {
  readonly #node: ChronologRpcNodeService
  readonly #governanceAdmin: GovernanceRpcAdmin | undefined
  readonly #enrollmentService: EnrollmentRpcService | undefined
  readonly #maxLocalSqlRows: number
  readonly #now: () => number

  constructor(options: NodeRpcServiceOptions) {
    this.#node = options.node
    this.#governanceAdmin = options.governanceAdmin
    this.#enrollmentService = options.enrollment
    this.#maxLocalSqlRows = nonnegative(options.maxLocalSqlRows ?? 10_000, 'maxLocalSqlRows')
    this.#now = options.now ?? Date.now
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
    yield await this.getStatus(request, context)
    const after = BigInt(request.resumeAfterEventSetRevision ?? this.#node.revision)
    for await (const _event of this.#node.events(after, context.signal)) {
      yield await this.getStatus(request, context)
    }
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
    const events = this.#node.events(barrier, context.signal)
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
    const program: SqlTransactionProgram = { version: 2, steps: decodeSteps(request.steps) }
    try { assertValidSqlTransactionProgram(program) } catch (error) {
      throw new ChronologRpcError('invalid_argument', `Invalid SQL transaction: ${errorCode(error, 'SQL_PROGRAM_INVALID')}`, { cause: error })
    }
    const retryIdentity = request.idempotencyKey ?? request.requestId
    if (typeof retryIdentity !== 'string' || retryIdentity.length === 0 || retryIdentity.length > 512) {
      throw invalid('Transaction requestId or idempotencyKey must contain 1 to 512 characters')
    }
    const operationId = `rpc-transaction:${toBase64Url(await sha256(utf8(JSON.stringify([
      principal(context), request.groupId, retryIdentity,
    ]))))}`
    try {
      // The node's durable journal owns authoring, authorization and exact-byte
      // retries. Recreating this facade or revoking a writer cannot erase a
      // previous publication or allocate a new timestamp for the same request.
      const published = await this.#node.publish({ program, operationId })
      return {
        transactionId: published.txIdText,
        candidateDigest: toBase64Url(published.candidateDigest),
        authorTimestampMs: published.core.authorTimestampMs.toString(10),
        transactionNonce: toBase64Url(published.core.nonce),
        executionManifestDigest: toBase64Url(published.core.executionManifestDigest),
        durableLocalAppend: true as const,
        publishedAt: new Date(Number(published.core.authorTimestampMs)).toISOString(),
      }
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
    const outcome = this.#node.outcome(txId)
    const status = await this.#node.status()
    const phase = outcome === null
      ? candidate.state === 'admissible' ? 'admissible' : 'collecting_attestations'
      : outcome.outcome === 'accepted' ? 'accepted' : 'rejected'
    return {
      transactionId: request.transactionId,
      phase,
      outcome: outcome === null
        ? { type: 'pending' }
        : outcome.outcome === 'accepted'
          ? { type: 'accepted' }
          : {
              type: 'rejected',
              rejection: { code: outcome.rejectionCode ?? 'rejected', statementIndex: outcome.failingStatementIndex },
            },
      eventSetRevision: this.#node.revision.toString(10),
      materializedRevision: status.materializedRevision.toString(10),
      orderKey: orderKeyText(candidate.orderKey),
      changedByReplay: this.#node.outcomeChangedByReplay(txId),
      admissible: candidate.state === 'admissible',
      final: outcome !== null && this.#node.isFinal(txId),
      observedAt: new Date(this.#now()).toISOString(),
    }
  }

  async *streamOutcome(request: StreamOutcomeRequest, context: RpcCallContext): AsyncIterable<TransactionOutcome> {
    const after = BigInt(request.resumeAfterEventSetRevision ?? this.#node.revision)
    const events = this.#node.events(after, context.signal)
    yield await this.getOutcome(request, context)
    for await (const _event of events) yield await this.getOutcome(request, context)
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
    yield await this.getSettlementEvidence(request, context)
    const after = BigInt(request.resumeAfterEventSetRevision ?? this.#node.revision)
    for await (const _event of this.#node.events(after, context.signal)) yield await this.getSettlementEvidence(request, context)
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
    const pendingPayloads = this.#node.controlStore.listCandidates().filter((candidate) => candidate.state === 'waiting_for_payload').length
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
          : knownPeers === 0 || status.transport.peers.length > 0 ? 'current' : 'offline',
    }
  }

  async *streamReplicationStatus(request: StreamReplicationStatusRequest, context: RpcCallContext): AsyncIterable<ReplicationStatus> {
    yield await this.getReplicationStatus(request, context)
    const after = BigInt(request.resumeAfterEventSetRevision ?? this.#node.revision)
    for await (const _event of this.#node.events(after, context.signal)) yield await this.getReplicationStatus(request, context)
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
    if (groupId !== this.#groupId()) throw new ChronologRpcError('not_found', 'Unknown group')
  }

  #assertGroupOptional(groupId?: string): void { if (groupId !== undefined) this.#assertGroup(groupId) }
  #groupId(): string { return toBase64Url(this.#node.groupId) }

}

function decodeSteps(values: readonly RpcProgramStep[]): ProgramStep[] {
  if (!(values instanceof Array)) throw invalid('steps must be an array')
  return values.map((value): ProgramStep => {
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

import type { EphemeralSignal } from '@chronolog/signals'
import type {
  ApproveEnrollmentRequest,
  ApproveEnrollmentResponse,
  CreateEnrollmentRequest,
  CreateEnrollmentResponse,
  EnrollmentStatus,
  GetEnrollmentStatusRequest,
  GetOutcomeRequest,
  GetReplicationStatusRequest,
  GetSettlementEvidenceRequest,
  GetStatusRequest,
  GetGovernanceStatusRequest,
  GetValidatorWatermarkRequest,
  LiveSqlEvent,
  LiveSqlRequest,
  LocalSqlRequest,
  LocalSqlResponse,
  NodeStatus,
  SubmitTransactionRequest,
  SubmitTransactionResponse,
  ReplicationStatus,
  SettlementEvidence,
  StreamOutcomeRequest,
  StreamReplicationStatusRequest,
  StreamSettlementEvidenceRequest,
  StreamStatusRequest,
  TransactionOutcome,
  ValidatorWatermark,
  GovernanceStatus,
  GrantCapabilityRequest,
  GrantCapabilityResponse,
  RevokeCapabilitiesRequest,
  RevokeCapabilitiesResponse,
  RotateEpochRequest,
  RotateEpochResponse,
  GrantHistoricalAccessRequest,
  GrantHistoricalAccessResponse,
  SubmitChangeRequest, SubmitChangeResponse, SubmitSignedRequest,
  EventReadRequest, EventReadResponse,
  SendSignalRequest, SubscribeSignalsRequest,
  GetOperationRequest, OperationStatus, StreamOperationsRequest,
  OpenReadViewRequest, OpenReadViewResponse, ReadViewRequest, QueryReadViewRequest, EventsReadViewRequest, LocalSqlResult,
  ViewChangesRequest, ViewChangesResponse,
} from './types.js'

export interface RpcCallOptions { readonly signal?: AbortSignal; readonly token?: string; readonly timeoutMs?: number; readonly metadata?: Readonly<Record<string, string>> }
export interface RpcCallContext extends RpcCallOptions { readonly method: RpcMethod; readonly peer?: string }

export interface UnaryRpcMethods {
  'signals.send': { request: SendSignalRequest; response: EphemeralSignal }
  'change.submit': { request: SubmitChangeRequest; response: SubmitChangeResponse }
  'ingress.submit': { request: SubmitSignedRequest; response: SubmitTransactionResponse }
  'events.read': { request: EventReadRequest; response: EventReadResponse }
  'operation.get': { request: GetOperationRequest; response: OperationStatus | null }
  'view.open': { request: OpenReadViewRequest; response: OpenReadViewResponse }
  'view.query': { request: QueryReadViewRequest; response: LocalSqlResult }
  'view.events': { request: EventsReadViewRequest; response: EventReadResponse }
  'view.release': { request: ReadViewRequest; response: { readonly released: true } }
  'node.getStatus': { request: GetStatusRequest; response: NodeStatus }
  'query.localSql': { request: LocalSqlRequest; response: LocalSqlResponse }
  'transaction.submit': { request: SubmitTransactionRequest; response: SubmitTransactionResponse }
  'transaction.getOutcome': { request: GetOutcomeRequest; response: TransactionOutcome }
  'evidence.getSettlement': { request: GetSettlementEvidenceRequest; response: SettlementEvidence }
  'evidence.getValidatorWatermark': { request: GetValidatorWatermarkRequest; response: ValidatorWatermark }
  'node.getReplicationStatus': { request: GetReplicationStatusRequest; response: ReplicationStatus }
  'governance.getStatus': { request: GetGovernanceStatusRequest; response: GovernanceStatus }
  'governance.grantCapability': { request: GrantCapabilityRequest; response: GrantCapabilityResponse }
  'governance.revokeCapabilities': { request: RevokeCapabilitiesRequest; response: RevokeCapabilitiesResponse }
  'governance.rotateEpoch': { request: RotateEpochRequest; response: RotateEpochResponse }
  'governance.grantHistoricalAccess': { request: GrantHistoricalAccessRequest; response: GrantHistoricalAccessResponse }
  'enrollment.createRequest': { request: CreateEnrollmentRequest; response: CreateEnrollmentResponse }
  'enrollment.approveRequest': { request: ApproveEnrollmentRequest; response: ApproveEnrollmentResponse }
  'enrollment.getStatus': { request: GetEnrollmentStatusRequest; response: EnrollmentStatus }
}
export interface StreamRpcMethods {
  'view.changes': { request: ViewChangesRequest; response: ViewChangesResponse }
  'signals.subscribe': { request: SubscribeSignalsRequest; response: EphemeralSignal }
  'events.subscribe': { request: EventReadRequest; response: EventReadResponse }
  'operation.subscribe': { request: StreamOperationsRequest; response: OperationStatus }
  'node.streamStatus': { request: StreamStatusRequest; response: NodeStatus }
  'query.liveSql': { request: LiveSqlRequest; response: LiveSqlEvent }
  'transaction.streamOutcome': { request: StreamOutcomeRequest; response: TransactionOutcome }
  'evidence.streamSettlement': { request: StreamSettlementEvidenceRequest; response: SettlementEvidence }
  'node.streamReplicationStatus': { request: StreamReplicationStatusRequest; response: ReplicationStatus }
}
export type UnaryRpcMethod = keyof UnaryRpcMethods
export type StreamRpcMethod = keyof StreamRpcMethods
export type RpcMethod = UnaryRpcMethod | StreamRpcMethod
export type UnaryRequest<M extends UnaryRpcMethod> = UnaryRpcMethods[M]['request']
export type UnaryResponse<M extends UnaryRpcMethod> = UnaryRpcMethods[M]['response']
export type StreamRequest<M extends StreamRpcMethod> = StreamRpcMethods[M]['request']
export type StreamResponse<M extends StreamRpcMethod> = StreamRpcMethods[M]['response']
export interface RpcTransport {
  unary<M extends UnaryRpcMethod>(method: M, request: UnaryRequest<M>, options?: RpcCallOptions): Promise<UnaryResponse<M>>
  stream<M extends StreamRpcMethod>(method: M, request: StreamRequest<M>, options?: RpcCallOptions): AsyncIterable<StreamResponse<M>>
  close?(): Promise<void>
}
export interface ChronologRpcService {
  sendSignal(request: SendSignalRequest, context: RpcCallContext): Promise<EphemeralSignal>
  subscribeSignals(request: SubscribeSignalsRequest, context: RpcCallContext): AsyncIterable<EphemeralSignal>
  submitChange(request: SubmitChangeRequest, context: RpcCallContext): Promise<SubmitChangeResponse>
  submitSigned(request: SubmitSignedRequest, context: RpcCallContext): Promise<SubmitTransactionResponse>
  readEvents(request: EventReadRequest, context: RpcCallContext): Promise<EventReadResponse>
  subscribeEvents(request: EventReadRequest, context: RpcCallContext): AsyncIterable<EventReadResponse>
  getOperation(request: GetOperationRequest, context: RpcCallContext): Promise<OperationStatus | null>
  subscribeOperations(request: StreamOperationsRequest, context: RpcCallContext): AsyncIterable<OperationStatus>
  openReadView(request: OpenReadViewRequest, context: RpcCallContext): Promise<OpenReadViewResponse>
  streamViewChanges(request: ViewChangesRequest, context: RpcCallContext): AsyncIterable<ViewChangesResponse>
  queryReadView(request: QueryReadViewRequest, context: RpcCallContext): Promise<LocalSqlResult>
  eventsReadView(request: EventsReadViewRequest, context: RpcCallContext): Promise<EventReadResponse>
  releaseReadView(request: ReadViewRequest, context: RpcCallContext): Promise<{ readonly released: true }>
  /** Release retained read leases when the owning RPC server/Worker stops. */
  close?(): void | Promise<void>
  getStatus(request: GetStatusRequest, context: RpcCallContext): Promise<NodeStatus>
  streamStatus(request: StreamStatusRequest, context: RpcCallContext): AsyncIterable<NodeStatus>
  localSql(request: LocalSqlRequest, context: RpcCallContext): Promise<LocalSqlResponse>
  liveSql(request: LiveSqlRequest, context: RpcCallContext): AsyncIterable<LiveSqlEvent>
  submitTransaction(request: SubmitTransactionRequest, context: RpcCallContext): Promise<SubmitTransactionResponse>
  getOutcome(request: GetOutcomeRequest, context: RpcCallContext): Promise<TransactionOutcome>
  streamOutcome(request: StreamOutcomeRequest, context: RpcCallContext): AsyncIterable<TransactionOutcome>
  getSettlementEvidence(request: GetSettlementEvidenceRequest, context: RpcCallContext): Promise<SettlementEvidence>
  streamSettlementEvidence(request: StreamSettlementEvidenceRequest, context: RpcCallContext): AsyncIterable<SettlementEvidence>
  getValidatorWatermark(request: GetValidatorWatermarkRequest, context: RpcCallContext): Promise<ValidatorWatermark>
  getReplicationStatus(request: GetReplicationStatusRequest, context: RpcCallContext): Promise<ReplicationStatus>
  streamReplicationStatus(request: StreamReplicationStatusRequest, context: RpcCallContext): AsyncIterable<ReplicationStatus>
  getGovernanceStatus(request: GetGovernanceStatusRequest, context: RpcCallContext): Promise<GovernanceStatus>
  grantCapability(request: GrantCapabilityRequest, context: RpcCallContext): Promise<GrantCapabilityResponse>
  revokeCapabilities(request: RevokeCapabilitiesRequest, context: RpcCallContext): Promise<RevokeCapabilitiesResponse>
  rotateEpoch(request: RotateEpochRequest, context: RpcCallContext): Promise<RotateEpochResponse>
  grantHistoricalAccess(request: GrantHistoricalAccessRequest, context: RpcCallContext): Promise<GrantHistoricalAccessResponse>
  createEnrollmentRequest(request: CreateEnrollmentRequest, context: RpcCallContext): Promise<CreateEnrollmentResponse>
  approveEnrollmentRequest(request: ApproveEnrollmentRequest, context: RpcCallContext): Promise<ApproveEnrollmentResponse>
  getEnrollmentStatus(request: GetEnrollmentStatusRequest, context: RpcCallContext): Promise<EnrollmentStatus>
}
export type ChronologService = ChronologRpcService

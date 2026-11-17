import type { ChangeProgram, EventBatch, EventReadOptions, ViewChange, ViewChangeOptions } from '@chronolog/protocol'

import type {
  ApproveEnrollmentRequest,
  ApproveEnrollmentResponse,
  CreateEnrollmentRequest,
  CreateEnrollmentResponse,
  EnrollmentStatus,
  GetEnrollmentStatusRequest,
  GetGovernanceStatusRequest,
  GovernanceStatus,
  GrantCapabilityRequest,
  GrantCapabilityResponse,
  GrantHistoricalAccessRequest,
  GrantHistoricalAccessResponse,
  LocalSqlValue,
  RevokeCapabilitiesRequest,
  RevokeCapabilitiesResponse,
  RotateEpochRequest,
  RotateEpochResponse,
  SqlView,
  OperationStatus,
} from './types.js'

export interface GovernanceRpcAdmin {
  getStatus(request: GetGovernanceStatusRequest): Promise<GovernanceStatus>
  grantCapability(request: GrantCapabilityRequest): Promise<GrantCapabilityResponse>
  revokeCapabilities(request: RevokeCapabilitiesRequest): Promise<RevokeCapabilitiesResponse>
  rotateEpoch(request: RotateEpochRequest): Promise<RotateEpochResponse>
  grantHistoricalAccess(request: GrantHistoricalAccessRequest): Promise<GrantHistoricalAccessResponse>
}

/** Local replica enrollment. Approval is exposed only when this device is an issuer. */
export interface EnrollmentRpcService {
  createRequest(request: CreateEnrollmentRequest): Promise<CreateEnrollmentResponse>
  approveRequest(request: ApproveEnrollmentRequest): Promise<ApproveEnrollmentResponse>
  getStatus(request: GetEnrollmentStatusRequest): Promise<EnrollmentStatus>
}

export interface LocalSqlExecution {
  readonly revision: bigint
  readonly orderLength: number
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly LocalSqlValue[])[]
}

export interface RpcNodeCandidate {
  readonly state: string
  readonly orderKey: {
    readonly authorTimestampMs: bigint
    readonly authorId: Uint8Array
    readonly txId: Uint8Array
  }
}

export interface RpcNodeCandidateCore {
  readonly authorTimestampMs: bigint
  readonly validationPolicy: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly program: ChangeProgram
}

export interface RpcNodeSettlementEvidence {
  readonly unresolvedAttestationIds: readonly Uint8Array[]
  readonly belowWatermark: boolean
  readonly watermark: { readonly cutoffMs: bigint | null; readonly heartbeatIds: readonly Uint8Array[] }
}

export interface RpcNodeWatermark {
  readonly policyId: string
  readonly cutoffMs: bigint | null
  readonly blockingValidatorIds: readonly Uint8Array[]
  readonly explanation: string
}

export interface RpcNodeStatusSnapshot {
  readonly started: boolean
  readonly materializedRevision: bigint
  readonly orderLength: number
  readonly validating: boolean
  readonly processedTransportRecords: number
  readonly materializationPending: boolean
  readonly quarantinedFeeds: readonly string[]
  readonly lastError?: string
  readonly ingest?: { readonly phase: string; readonly phaseAgeMs: number; readonly subscriptionRestarts: number; readonly retryRecords: number }
  readonly transport: {
    readonly records: number
    readonly peers: readonly string[]
    readonly connected?: boolean
    readonly configuredPeers?: readonly unknown[]
    readonly feedsWithGaps?: number
    readonly feedStates?: readonly { readonly hasGaps: boolean }[]
    readonly lastCatchUpError?: string
  }
}

export interface RpcMaterializedOutcome {
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
  readonly failingStatementIndex: number | null
}

/** Captured read port, supplied by the materializer without any RPC dependency. */
export interface RpcReadHandle {
  readonly revision: string
  readonly finalRevision: string
  readonly view: SqlView
  query(sql: string, parameters?: readonly LocalSqlValue[]): LocalSqlExecution | Promise<LocalSqlExecution>
  readEvents(options?: EventReadOptions): EventBatch | Promise<EventBatch>
  release(): void | Promise<void>
}

export interface RpcPublishedTransaction {
  readonly txId: Uint8Array
  readonly txIdText: string
  readonly candidateDigest: Uint8Array
  readonly core: { readonly authorTimestampMs: bigint; readonly nonce: Uint8Array; readonly executionManifestDigest: Uint8Array }
}

export interface ChronologRpcNodeService {
  readonly events?: {
    readonly historyProfile: 'chronological'
    read(options?: EventReadOptions): Promise<EventBatch>
    subscribe(options?: EventReadOptions & { readonly signal?: AbortSignal }): AsyncIterable<EventBatch>
  }
  readView?(options?: { readonly view?: SqlView }): Promise<RpcReadHandle>
  changes?(options?: ViewChangeOptions): AsyncIterable<ViewChange>
  operation?(operationId: string): Promise<OperationStatus | null>
  submitSigned?(signedWire: Uint8Array): Promise<RpcPublishedTransaction>
  readonly identity: Uint8Array
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly revision: bigint
  readonly materializedRevision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
  readonly finalRevision: bigint
  readonly finalOrderLength: number
  readonly controlStore: {
    readonly missingProposalCount: number
  }
  publish(input: { readonly program: ChangeProgram; readonly operationId: string }): Promise<RpcPublishedTransaction>
  status(): Promise<RpcNodeStatusSnapshot>
  isWritable(): Promise<boolean>
  candidate(txId: Uint8Array): RpcNodeCandidate | null
  candidateCore(txId: Uint8Array): RpcNodeCandidateCore | null
  outcome(txId: Uint8Array): RpcMaterializedOutcome | null
  outcomeChangedByReplay(txId: Uint8Array): boolean
  isFinal(txId: Uint8Array): boolean
  settlementEvidence(txId: Uint8Array): Promise<RpcNodeSettlementEvidence | null>
  watermark(): Promise<RpcNodeWatermark | null>
  revisions(afterRevision?: bigint, signal?: AbortSignal): AsyncIterable<unknown>
  localSql(sql: string, parameters?: readonly LocalSqlValue[], options?: { readonly atRevision?: bigint; readonly view?: SqlView }): LocalSqlExecution
  validateProgram(program: ChangeProgram): void
}

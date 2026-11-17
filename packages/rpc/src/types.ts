import type { EventBatch, EventReadOptions } from '@chronolog/protocol'
import type { SignalPayload } from '@chronolog/signals'
import type { CapabilityRole, ProgramRights } from '@chronolog/capabilities'
export type { CapabilityRole, ProgramRights } from '@chronolog/capabilities'

/** Chronolog's local RPC API. Consensus codecs are versioned separately. */
export const RPC_API_VERSION = 'chronolog.rpc' as const

export type RpcApiVersion = typeof RPC_API_VERSION
export type Revision = string
export type GroupId = string
export type TransactionId = string
export type RequestId = string
export type CanonicalBytes = string
export type SqlView = 'local' | 'final'

export type LocalSqlValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: string }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: Uint8Array }

export interface LocalSqlResult {
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly LocalSqlValue[])[]
  readonly truncated: boolean
  readonly consensusSafe: false
}

export interface SubmitChangeRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  readonly operationId: string
  /** Canonical, versioned ChangeProgram. */
  readonly program: Uint8Array
}
export interface SubmitChangeResponse extends SubmitTransactionResponse {
  readonly operationId: string
  readonly proposalId: string
}
/** Original signed publisher proposal; the ingress must never re-author it. */
export interface SubmitSignedRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  readonly signedWire: Uint8Array
}
export interface EventReadRequest extends EventReadOptions { readonly groupId: GroupId; readonly requestId: RequestId }
export type EventReadResponse = EventBatch
/** A live publication has no durable operation identity or replay cursor. */
export interface SendSignalRequest {
  readonly groupId: GroupId
  readonly topic: string
  readonly payload: SignalPayload
  readonly ttlMs?: number
}
export interface SubscribeSignalsRequest {
  readonly groupId: GroupId
  readonly topics?: readonly string[]
  readonly mode?: 'all' | 'latest'
}
export interface OperationStatus {
  readonly operationId: string
  readonly proposalId: string
  readonly final: boolean
  readonly outcome: {
    readonly outcome: 'accepted' | 'rejected'
    readonly rejectionCode: string | null
    readonly failingStatementIndex: number | null
  } | null
}
export interface GetOperationRequest { readonly groupId: GroupId; readonly requestId: RequestId; readonly operationId: string }
export interface StreamOperationsRequest { readonly groupId: GroupId; readonly requestId: RequestId; readonly operationId: string }

export interface OpenReadViewRequest { readonly groupId: GroupId; readonly requestId: RequestId; readonly view?: SqlView }
export interface ViewChangesRequest { readonly groupId: GroupId; readonly view?: SqlView }
export type { ViewChange } from '@chronolog/protocol'
export interface OpenReadViewResponse {
  readonly viewId: string
  readonly revision: string
  readonly finalRevision: string
  readonly view: SqlView
  readonly expiresAt: number
}
export interface ReadViewRequest { readonly groupId: GroupId; readonly requestId: RequestId; readonly viewId: string }
export interface QueryReadViewRequest extends ReadViewRequest { readonly sql: string; readonly parameters: readonly LocalSqlValue[]; readonly maxRows?: number }
export interface EventsReadViewRequest extends ReadViewRequest, EventReadOptions {}

export interface RevisionMetadata {
  readonly groupId: GroupId
  /** The SQL reader represented by materializedRevision and publishedOrderLength. */
  readonly view: SqlView
  readonly eventSetRevision: Revision
  readonly materializedRevision: Revision
  readonly publishedOrderLength: string
  /** Applied immutable prefix, independent of speculative local SQL progress. */
  readonly finalRevision: Revision
  readonly finalOrderLength: string
  readonly executionManifestDigest: string
  readonly replaying: boolean
}

export interface LocalSqlRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  readonly sql: string
  readonly parameters: readonly LocalSqlValue[]
  /** Defaults to the final applied reader. Select local explicitly for speculative SQL. */
  readonly view?: SqlView
  readonly maxRows?: number
  readonly atRevision?: Revision
}

export interface LocalSqlResponse {
  readonly revision: RevisionMetadata
  readonly result: LocalSqlResult
}

export interface LiveSqlCursor {
  readonly groupId: GroupId
  readonly queryDigest: string
  readonly eventSetRevision: Revision
}

export interface LiveSqlRequest extends Omit<LocalSqlRequest, 'atRevision'> {
  readonly resume?: LiveSqlCursor
}

export type LiveSqlEvent =
  | { readonly type: 'snapshot' | 'change'; readonly revision: RevisionMetadata; readonly queryDigest: string; readonly result: LocalSqlResult; readonly previousMaterializedRevision?: Revision }
  | { readonly type: 'reset'; readonly revision: RevisionMetadata; readonly queryDigest: string; readonly result?: LocalSqlResult; readonly reason: 'history_unavailable' | 'server_restart' | 'subscription_rebuilt' | 'schema_changed' | 'manifest_changed' | 'query_invalid' }

export type NodeLifecycleState = 'starting' | 'ready' | 'replaying' | 'degraded' | 'stopping'
export interface NodeStatus {
  readonly apiVersion: RpcApiVersion
  readonly state: NodeLifecycleState
  readonly nodeId: string
  readonly revision?: RevisionMetadata
  readonly writable: boolean
  readonly validating: boolean
  readonly lastErrorCode?: string
}
export interface GetStatusRequest { readonly groupId?: GroupId; readonly requestId: RequestId }
export interface StreamStatusRequest extends GetStatusRequest { readonly resumeAfterEventSetRevision?: Revision }

export interface SubmitTransactionResponse {
  readonly transactionId: TransactionId
  readonly candidateDigest: string
  readonly authorTimestampMs: string
  readonly transactionNonce: CanonicalBytes
  readonly executionManifestDigest: string
  readonly durableLocalAppend: true
  readonly publishedAt: string
}

export interface TransactionRejection {
  /** `assert:<code>`, `policy:<table>:<command>`, `platform:<reason>`, `constraint`, `denied`, … */
  readonly code: string
  /** Index of the failing step; null for whole-transaction rejections. */
  readonly statementIndex: number | null
}
export type TransactionResult =
  | { readonly type: 'pending' }
  | { readonly type: 'accepted' }
  | { readonly type: 'rejected'; readonly rejection: TransactionRejection }
export interface TransactionOutcome {
  readonly transactionId: TransactionId
  readonly outcome: TransactionResult
  readonly eventSetRevision: Revision
  readonly materializedRevision: Revision
  readonly orderKey?: string
  readonly changedByReplay: boolean
  readonly admissible: boolean
  /** True only after the policy's immutable prefix has been applied locally. */
  readonly final: boolean
  readonly observedAt: string
}
export interface GetOutcomeRequest { readonly groupId: GroupId; readonly transactionId: TransactionId; readonly requestId: RequestId }
export interface StreamOutcomeRequest extends GetOutcomeRequest { readonly resumeAfterEventSetRevision?: Revision }

export type SettlementConfidence = 'insufficient' | 'provisional' | 'policy_watermark_reached'
export interface EvidenceReference { readonly kind: 'candidate' | 'attestation' | 'heartbeat' | 'membership' | 'epoch'; readonly reference: string }
export interface SettlementEvidence {
  readonly transactionId: TransactionId
  readonly outcome: TransactionOutcome
  readonly evidenceRevision: Revision
  readonly orderKey: string
  readonly authorTimestamp: string
  readonly validationPolicyId: string
  readonly membershipRevision: string
  readonly policyWatermarkTimestamp?: string
  readonly blockingHeartbeats: readonly string[]
  readonly unresolvedReferences: readonly EvidenceReference[]
  readonly confidence: SettlementConfidence
  readonly calculatedAt: string
}
export type GetSettlementEvidenceRequest = GetOutcomeRequest
export interface StreamSettlementEvidenceRequest extends GetSettlementEvidenceRequest { readonly resumeAfterEventSetRevision?: Revision }
export interface ValidatorWatermark { readonly groupId: GroupId; readonly revision: Revision; readonly policyId: string; readonly membershipRevision: string; readonly timestamp?: string; readonly supportingValidators: readonly string[]; readonly blockedBy: readonly string[] }
export interface GetValidatorWatermarkRequest { readonly groupId: GroupId; readonly requestId: RequestId }
export type ReplicationState = 'offline' | 'connecting' | 'syncing' | 'current' | 'degraded'
export interface ReplicationStatus { readonly groupId: GroupId; readonly revision: Revision; readonly connectedPeers: number; readonly knownPeers: number; readonly feedsWithGaps: number; readonly quarantinedFeeds: readonly string[]; readonly pendingPayloads: number; readonly ingestionBacklog: number; readonly materializationPending: boolean; readonly state: ReplicationState; readonly ingestDiagnostics?: string }
export interface GetReplicationStatusRequest { readonly groupId: GroupId; readonly requestId: RequestId }
export interface StreamReplicationStatusRequest extends GetReplicationStatusRequest { readonly resumeAfterEventSetRevision?: Revision }

interface GovernanceCapabilityDetails {
  readonly capabilityId: string
  readonly subjectId: string
  readonly signingPublicKey: string
  readonly transportAuthor?: string
  readonly validFromRevision: string
  readonly revokedAtRevision?: string
  readonly active: boolean
  readonly hpkePublicKey?: string
  readonly minimumAuthorTimestampMs?: string
}
export type GovernanceCapabilityStatus = GovernanceCapabilityDetails & (
  | { readonly role: 'writer'; readonly program: ProgramRights }
  | { readonly role: Exclude<CapabilityRole, 'writer'>; readonly program?: never }
)

export interface GetGovernanceStatusRequest { readonly groupId: GroupId; readonly requestId: RequestId }
export interface GovernanceStatus {
  readonly groupId: GroupId
  readonly revision: string
  readonly revisionDigest: string
  readonly rootAdminPublicKey: string
  readonly capabilityLogFeed: string
  readonly currentEpoch: string | null
  readonly capabilities: readonly GovernanceCapabilityStatus[]
}

interface GrantCapabilityIdentity {
  readonly subjectId: string
  readonly signingPublicKey: string
  readonly transportAuthor?: string
  readonly minimumAuthorTimestampMs?: string
  readonly hpkePublicKey?: string
}
export type GrantCapabilityInput = GrantCapabilityIdentity & (
  | { readonly role: 'writer'; readonly program: ProgramRights }
  | { readonly role: Exclude<CapabilityRole, 'writer'>; readonly program?: never }
)
export type GrantCapabilityRequest = GetGovernanceStatusRequest & GrantCapabilityInput
export interface GrantCapabilityResponse { readonly revision: string; readonly capabilityId: string }
export interface RevokeCapabilitiesRequest extends GetGovernanceStatusRequest { readonly capabilityIds: readonly string[] }
export interface RevokeCapabilitiesResponse { readonly revision: string; readonly revokedCapabilityIds: readonly string[] }
export type RotateEpochRequest = GetGovernanceStatusRequest
export interface RotateEpochResponse { readonly epoch: string }
export interface GrantHistoricalAccessRequest extends GetGovernanceStatusRequest { readonly subjectId: string }
export interface GrantHistoricalAccessResponse { readonly epochManifestsPublished: number }

export type EnrollmentRole = 'reader' | 'writer'
export type EnrollmentState = 'requested' | 'approved' | 'authorized-disconnected' | 'awaiting-keys' | 'awaiting-history' | 'unsupported-engine' | 'revoked' | 'ready'
export interface CreateEnrollmentRequest {
  readonly groupId: GroupId
  /** Stable device-local request identity; persist it before retrying enrollment. */
  readonly requestId: RequestId
  readonly roles: readonly EnrollmentRole[]
  readonly writerProgram?: ProgramRights
}
export interface CreateEnrollmentResponse { readonly signedRequest: CanonicalBytes }
export interface ApproveEnrollmentRequest {
  readonly groupId: GroupId
  /** Stable approval operation identity on the issuer. */
  readonly requestId: RequestId
  readonly signedRequest: CanonicalBytes
  readonly roles: readonly EnrollmentRole[]
  readonly writerProgram?: ProgramRights
  readonly grantFullHistory: boolean
}
export interface ApproveEnrollmentResponse { readonly signedApproval: CanonicalBytes }
export interface GetEnrollmentStatusRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  readonly signedApproval?: CanonicalBytes
}
export interface EnrollmentStatus {
  readonly requestId: RequestId
  readonly state: EnrollmentState
  readonly missingEpochs: readonly string[]
  readonly roles: readonly EnrollmentRole[]
}

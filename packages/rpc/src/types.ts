/** Chronolog's local RPC API. Consensus codecs are versioned separately. */
export const RPC_API_VERSION = 'chronolog.rpc' as const

export type RpcApiVersion = typeof RPC_API_VERSION
export type Revision = string
export type GroupId = string
export type TransactionId = string
export type RequestId = string
export type CanonicalBytes = string

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

export interface RpcSqlBinding {
  readonly parameter:
    | { readonly kind: 'index'; readonly index: number }
    | { readonly kind: 'name'; readonly name: string }
  readonly value: LocalSqlValue
}

export interface RpcSqlStatement {
  readonly sql: string
  readonly bindings: readonly RpcSqlBinding[]
}

/** A platform operation (grant, transfer, register a table, …) as its canonical CBOR encoding. */
export interface RpcPlatformStep {
  readonly platform: Uint8Array
}

export type RpcProgramStep = RpcSqlStatement | RpcPlatformStep

export interface RevisionMetadata {
  readonly groupId: GroupId
  readonly eventSetRevision: Revision
  readonly materializedRevision: Revision
  readonly publishedOrderLength: string
  readonly executionManifestDigest: string
  readonly replaying: boolean
}

export interface LocalSqlRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  readonly sql: string
  readonly parameters: readonly LocalSqlValue[]
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

export interface SubmitTransactionRequest {
  readonly groupId: GroupId
  readonly requestId: RequestId
  /** SQL statements and platform operations, executed in order as this node's key. */
  readonly steps: readonly RpcProgramStep[]
  /** Repeating a key with the same steps returns the original submission. */
  readonly idempotencyKey?: string
}
export interface SubmitTransactionResponse {
  readonly transactionId: TransactionId
  readonly candidateDigest: string
  readonly authorTimestampMs: string
  readonly transactionNonce: CanonicalBytes
  readonly executionManifestDigest: string
  readonly durableLocalAppend: true
  readonly publishedAt: string
}

export type TransactionPhase = 'candidate_published' | 'collecting_attestations' | 'validation_threshold_met' | 'admissible' | 'replicated' | 'accepted' | 'rejected'
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
  readonly phase: TransactionPhase
  readonly outcome: TransactionResult
  readonly eventSetRevision: Revision
  readonly materializedRevision: Revision
  readonly orderKey?: string
  readonly changedByReplay: boolean
  readonly admissible: boolean
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

export type GovernanceCapabilityRole =
  | 'reader'
  | 'writer'
  | 'validator'
  | 'administrator'

export interface GovernanceCapabilityStatus {
  readonly capabilityId: string
  readonly subjectId: string
  readonly signingPublicKey: string
  readonly transportAuthor?: string
  readonly role: GovernanceCapabilityRole
  readonly validFromRevision: string
  readonly revokedAtRevision?: string
  readonly active: boolean
  readonly hpkePublicKey?: string
}

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

export interface GrantCapabilityRequest extends GetGovernanceStatusRequest {
  readonly subjectId: string
  readonly signingPublicKey: string
  readonly transportAuthor?: string
  readonly role: GovernanceCapabilityRole
  readonly minimumAuthorTimestampMs?: string
  readonly hpkePublicKey?: string
}
export interface GrantCapabilityResponse { readonly revision: string; readonly capabilityId: string }
export interface RevokeCapabilitiesRequest extends GetGovernanceStatusRequest { readonly capabilityIds: readonly string[] }
export interface RevokeCapabilitiesResponse { readonly revision: string; readonly revokedCapabilityIds: readonly string[] }
export type RotateEpochRequest = GetGovernanceStatusRequest
export interface RotateEpochResponse { readonly epoch: string }
export interface GrantHistoricalAccessRequest extends GetGovernanceStatusRequest { readonly subjectId: string }
export interface GrantHistoricalAccessResponse { readonly epochManifestsPublished: number }

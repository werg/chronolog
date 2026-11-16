import type { ControlStore, StoredAttestation, WatermarkPolicy } from '@chronolog/control-store'
import type {
  ChronologMaterializationRuntime,
  MaterializedLocalSqlResult,
  MaterializedLocalSqlValue,
} from '@chronolog/materializer'
import type {
  Ed25519KeyPair,
  SqlStatement,
  ChangeProgram,
  TransactionCore,
} from '@chronolog/protocol'
import type { ChronologTransport, TransportStatus } from '@chronolog/records'
import type { FeedForkRegistry } from './feed-forks.js'
import type { CoordinatedHistoryPolicy, OrderedRecordEntry } from './history-policy.js'
import type { DurableOperationStore } from './operations.js'

export interface Clock {
  now(): number
}

export interface RandomSource {
  bytes(length: number): Uint8Array
}

export interface EnvelopeCipher {
  readonly epochId: Uint8Array
  seal(plaintext: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>
  open(ciphertext: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>
}

/** Resolves the current writer key and retained reader keys across rotations. */
export interface EnvelopeCipherResolver {
  current(): EnvelopeCipher
  resolve(epochId: Uint8Array): EnvelopeCipher | undefined
}

export interface CandidateAdmissionContext {
  readonly program?: ChangeProgram
  readonly writerCapability?: Uint8Array
  readonly authorTimestampMs?: bigint
  readonly canonicalPosition?: bigint
  readonly txId?: Uint8Array
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly writerId: Uint8Array
  readonly validatorId: Uint8Array
  readonly validatorCapability: Uint8Array
}

export interface ValidatorAuthorityContext {
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validatorId: Uint8Array
  readonly validatorCapability: Uint8Array
}

export interface TransportAuthorContext {
  readonly writerCapability?: Uint8Array
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly role: 'writer' | 'validator'
  readonly signingId: Uint8Array
  readonly transportAuthor: string
  readonly validatorCapability?: Uint8Array
}

/**
 * Resolves authority at the transaction's pinned membership revision. It can be
 * backed by the in-log capability system, a central service, a chain, or a
 * operator-controlled out-of-band source. No fixed validator set is assumed.
 */
export interface MembershipResolver {
  canWrite(context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>): boolean | Promise<boolean>
  canValidate(context: CandidateAdmissionContext): boolean | Promise<boolean>
  threshold(context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>): number | Promise<number>
  /** Authorizes revision-scoped validator heartbeat evidence. */
  canHeartbeat?(context: ValidatorAuthorityContext): boolean | Promise<boolean>
  /**
   * Binds an inner Chronolog signing key to an authenticated outer feed. When
   * omitted, node-core permits only records authored by the local transport
   * identity and signed by the local node identity.
   */
  canUseTransportAuthor?(context: TransportAuthorContext): boolean | Promise<boolean>
  /** Resolves the version committed by attestations for a pinned policy. */
  policyVersion?(
    context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>,
  ): bigint | Promise<bigint>
  selectAdmission?(
    context: Omit<CandidateAdmissionContext, 'validatorId' | 'validatorCapability'>,
    attestations: readonly StoredAttestation[],
  ): readonly StoredAttestation[] | Promise<readonly StoredAttestation[]>
  watermarkPolicy?(core: TransactionCore): WatermarkPolicy | null | Promise<WatermarkPolicy | null>
}

export interface ValidatorOptions {
  readonly capabilityId: Uint8Array
  readonly policyVersion?: bigint
  readonly cutoffLagMs?: number
  readonly maxFutureSkewMs?: number
  readonly heartbeatIntervalMs?: number
  readonly initialAcceptedAboveMs?: bigint
}

export interface OperationalMembershipState {
  readonly minimumAuthorTimestampMs?: bigint
  readonly writerCapability?: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly validatorCapability?: Uint8Array
}

export interface ChronologNodeOptions {
  readonly peerGovernance?: {
    isRevisionClosed(revision: Uint8Array): boolean
    closureAdmissions(revision: Uint8Array): readonly Uint8Array[]
    allowsAttestation(revision: Uint8Array, validatorId: Uint8Array, sequence: bigint): Promise<boolean>
  }
  readonly operationStore?: DurableOperationStore
  readonly historyPolicy?: { readonly kind: 'peer' } | {
    readonly kind: 'coordinated'
    readonly policy: CoordinatedHistoryPolicy
    /** Receives verified snapshots/keys without activating application authority. */
    readonly receiveControlRecord?: (entry: OrderedRecordEntry) => Promise<void>
    /** Applies verified governance records at their certified position. */
    readonly applyControlRecord?: (entry: OrderedRecordEntry) => Promise<void>
  }
  readonly groupId: Uint8Array
  readonly groupRoute?: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly validationPolicy: Uint8Array
  readonly identity: Ed25519KeyPair
  readonly transport: ChronologTransport
  readonly materialization: ChronologMaterializationRuntime
  readonly membership: MembershipResolver
  /** Live governance head used for newly authored records and validator work. */
  readonly membershipState?: () => OperationalMembershipState
  readonly controlStore?: ControlStore
  readonly validator?: ValidatorOptions
  readonly clock?: Clock
  readonly random?: RandomSource
  readonly envelopeCipher?: EnvelopeCipher | EnvelopeCipherResolver
  /** Maximum transiently failed records retained before history-backed recovery takes over. */
  readonly maximumRetryRecords?: number
  readonly feedForkRegistry?: FeedForkRegistry
}

export interface PublishTransactionInput {
  readonly operationId?: string
  readonly writerCapability?: Uint8Array
  readonly program: ChangeProgram
  readonly authorTimestampMs?: bigint
  readonly nonce?: Uint8Array
  readonly metadata?: ReadonlyMap<string, Uint8Array>
  readonly membershipRevision?: Uint8Array
  readonly validationPolicy?: Uint8Array
}

export interface PublishedTransaction {
  readonly txId: Uint8Array
  readonly txIdText: string
  readonly candidateDigest: Uint8Array
  readonly core: TransactionCore
}

export interface ReservedTransactionContext {
  readonly authorTimestampMs: bigint
  readonly nonce: Uint8Array
}

export interface NodeRevisionEvent {
  readonly revision: bigint
  readonly reason: 'candidate' | 'attestation' | 'heartbeat' | 'materialized' | 'error'
  readonly txId?: Uint8Array
  readonly error?: Error
}

export interface NodeStatus {
  readonly historyPolicy?: 'peer' | 'coordinated'
  readonly finalOrderLength?: number
  readonly finalRevision?: bigint
  readonly started: boolean
  readonly closed: boolean
  readonly eventSetRevision: bigint
  readonly candidates: number
  readonly admitted: number
  readonly processedTransportRecords: number
  readonly materializationPending: boolean
  readonly materializedRevision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
  readonly validating: boolean
  readonly lastError?: string
  readonly transport: TransportStatus
  readonly quarantinedFeeds: readonly string[]
  /** Transport consumer state, for diagnosing ingestion that stops progressing. */
  readonly ingest?: {
    readonly phase: string
    readonly phaseAgeMs: number
    readonly subscriptionRestarts: number
    readonly retryRecords: number
  }
}

export type NodeLocalSqlQueryResult = MaterializedLocalSqlResult
export type NodeSqlStatement = SqlStatement
export type NodeLocalSqlParameter = MaterializedLocalSqlValue

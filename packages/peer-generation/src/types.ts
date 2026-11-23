import type { BytesStore } from '@chronolog/records'
import type { ChangeProgram } from '@chronolog/protocol'
import type { ChronologMaterializationRuntime, MaterializedQueryCapabilities, MaterializedReadHandle } from '@chronolog/materializer'
import type { ApplicationDescriptor, AuthorityBundle, HistoryPoint, OrderReceipt, PeerGrant, PeerIdentity, PrefixProof, Signed, SignedGeneration } from './control-types.js'
import type { PEER_GENERATION_PROFILE } from './control-types.js'
export * from './control-types.js'

export interface AttemptHeader {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly generation: string
  readonly controlRevision: number
  readonly epoch: number
  readonly author: string
  readonly operationId: string
  readonly definitionDigest: string
  readonly command: string
  readonly commandVersion: string
  readonly basedOn: PeerRevision | null
  readonly reapplyOf: string | null
  readonly coreDigest: string
}
/** The signature authenticates the original encrypted body and all admission metadata. */
export interface AttemptEnvelope {
  readonly header: AttemptHeader
  readonly nonce: string
  readonly ciphertext: string
}
export interface SignedAttempt extends Signed<AttemptEnvelope> { readonly id: string }
export interface OrderedCommand { readonly receipt: OrderReceipt; readonly attempt: SignedAttempt }
export interface PeerRevision {
  readonly applicationId: string
  readonly historyId: string
  readonly generation: string
  readonly point: HistoryPoint
  readonly controlRevision: number
  readonly materializationRevision: string
}
export interface AppliedResult {
  readonly status: 'applied'
  readonly attemptId: string
  readonly operationId: string
  readonly author: string
  readonly generation: string
  readonly sequence: number
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
}
export type OperationState =
  | { readonly status: 'saved'; readonly attemptId: string; readonly operationId: string; readonly generation: string }
  | AppliedResult
  | { readonly status: 'abandoned' | 'needsReapply'; readonly attemptId: string; readonly operationId: string; readonly generation: string; readonly selectedGeneration: string; readonly previous: AppliedResult | null }

export interface RecoveryNotice {
  readonly previousGeneration: string
  readonly generation: string
  readonly adopted: HistoryPoint | null
  readonly revision: PeerRevision
  readonly abandoned: readonly OperationState[]
  readonly unknownLoss: boolean
}
export interface HistoryReceiveResult {
  readonly ready: boolean
  readonly recovery: RecoveryNotice | null
}
export interface RetainedCoverage {
  readonly applicationId: string
  readonly generation: string
  readonly point: HistoryPoint
  readonly peer: string
  readonly storageId: string
  readonly retainedAt: number
}
export type SignedRetainedCoverage = Signed<RetainedCoverage>

export interface PeerReplicaOptions {
  readonly authority: AuthorityBundle
  readonly device: PeerIdentity
  readonly store: BytesStore
  readonly storageId: string
  readonly materializer: ChronologMaterializationRuntime
  readonly epochKeys: ReadonlyMap<number, Uint8Array>
  readonly now?: () => number
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}
export interface PrepareCommand {
  readonly operationId: string
  readonly program: ChangeProgram
  readonly command?: string
  readonly commandVersion?: string
  readonly basedOn?: PeerRevision
  readonly reapplyOf?: string
  readonly authorTimestampMs?: bigint
}
export interface CapturedPeerView {
  readonly authority: AuthorityBundle
  readonly revision: PeerRevision
  readonly read: MaterializedReadHandle
  release(): void
}

/** One durable coordinator pause; only explicit reconciliation may resume ordering. */
export interface PeerOrderingPause {
  readonly operationId: string
  readonly generation: string
  readonly base: PrefixProof
}

/** All replication is peer-to-peer. Authority refresh is an explicit lifecycle action. */
export interface PeerReplica {
  readonly queryCapabilities: MaterializedQueryCapabilities
  readonly descriptor: ApplicationDescriptor
  readonly device: PeerIdentity
  readonly storageId: string
  readonly requiredEpochs: readonly number[]
  readonly authority: AuthorityBundle
  readonly generation: SignedGeneration
  /** Fatal storage or execution failures fence this owner until it is reopened. */
  readonly closed: boolean
  /** A complete selected prefix has been published as an application view. */
  readonly ready: boolean
  /** Last contiguous retained command in the selected history, before application publication if necessary. */
  readonly retainedPoint: HistoryPoint | null
  readonly revision: PeerRevision
  readonly isCoordinator: boolean
  /** Current verified control, including a selection whose application bodies are still recovering. */
  grant(publicKey: string): PeerGrant | null
  prepare(input: PrepareCommand): Promise<SignedAttempt>
  order(attempt: SignedAttempt): Promise<OrderedCommand>
  ingest(commands: readonly OrderedCommand[]): Promise<void>
  adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null>
  /** Fetches bounded pages outside the replica lock, then publishes one complete target. */
  synchronize(authority: AuthorityBundle, commands: readonly OrderedCommand[] | AsyncIterable<readonly OrderedCommand[]>, options?: { readonly at?: PeerRevision }): Promise<RecoveryNotice | null>
  receiveHistory(authority: AuthorityBundle, commands: readonly OrderedCommand[]): Promise<HistoryReceiveResult>
  operation(operationId: string, author?: string): Promise<OperationState | null>
  attempt(operationId: string, author?: string): Promise<SignedAttempt | null>
  capture(): Promise<CapturedPeerView>
  /** Validate the current complete prefix, or a complete selected ancestor while newer inherited bodies are unavailable. Does not publish a recovering view. */
  recoveryPoint(): Promise<PrefixProof>
  /** Drain prior ordering and retain its exact prefix before a reviewed control change. */
  pauseOrdering(operationId: string): Promise<PeerOrderingPause>
  orderingPause(): Promise<PeerOrderingPause | null>
  /** Caller must first reconcile any submitted control mutation; cancellation alone is insufficient. */
  resumeOrdering(operationId: string): Promise<void>
  prefixProof(point: HistoryPoint): Promise<PrefixProof>
  /** The contiguous retained selected prefix, including evidence available while recovery is pending. */
  exportCommands(options?: { readonly after?: HistoryPoint; readonly offset?: number; readonly limit?: number; readonly maxBytes?: number; readonly at?: PeerRevision }): Promise<readonly OrderedCommand[]>
  /** Receipt root for a retained command on the selected history, without copying its body. */
  receiptRoot(attemptId: string): string | null
  pendingAttempts(): Promise<readonly SignedAttempt[]>
  retainedCoverage(point?: HistoryPoint): Promise<SignedRetainedCoverage>
  observeCoverage(coverage: SignedRetainedCoverage): Promise<void>
  shared(point?: HistoryPoint): readonly SignedRetainedCoverage[]
  subscribe(listener: () => void): () => void
  onRecovery(listener: (notice: RecoveryNotice) => void): () => void
  inspectRecovery(): readonly RecoveryNotice[]
  close(): Promise<void>
}

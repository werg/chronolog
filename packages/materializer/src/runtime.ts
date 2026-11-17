import type { TransactionOrderKey } from '@chronolog/protocol'

import type { ReplayProposal } from './types.js'

export type MaterializedTransactionOutcomeKind = 'accepted' | 'rejected'

export interface MaterializedTransactionOutcome {
  readonly txId: Uint8Array
  readonly orderKey: TransactionOrderKey
  readonly orderIndex: number
  readonly outcome: MaterializedTransactionOutcomeKind
  readonly rejectionCode: string | null
  readonly failingStatementIndex: number | null
}

export interface MaterializationOutcomeChange {
  readonly txId: Uint8Array
  readonly previous: MaterializedTransactionOutcomeKind | null
  /** Null when a previously selected provisional proposal leaves the replay. */
  readonly current: MaterializedTransactionOutcomeKind | null
  readonly previousRejectionCode: string | null
  readonly currentRejectionCode: string | null
}

export interface MaterializedRevision {
  readonly revision: bigint
  readonly previousRevision: bigint
  readonly orderLength: number
  readonly replayFromIndex: number
  readonly replayedTransactions: number
  readonly checkpointPrefix: number
  readonly contentHash: string
  readonly manifestDigest: Uint8Array
  readonly earliestChangedOrderIndex: number
  readonly outcomeChanges: readonly MaterializationOutcomeChange[]
}

export interface MaterializationPublicationRequest {
  readonly publicationKey: string
  readonly expectedRevision: bigint
  readonly targetRevision: bigint
  readonly targetOrderLength: number
  readonly candidateIdentity: string
}

export interface CoordinatedMaterialization {
  readonly revision: MaterializedRevision
  readonly publication: MaterializationPublicationRequest
}

/** Calculates or follows one immutable materialization candidate. */
export interface MaterializationCoordinator {
  materialize(
    orderedTransactions: readonly ReplayProposal[],
  ): Promise<CoordinatedMaterialization | null>
}

/** Applied SQL can also project a verified external membership history into its data authority. */
export interface AppliedMaterializationCoordinator extends MaterializationCoordinator {
  materialize(
    orderedTransactions: readonly ReplayProposal[],
    controls?: PeerExecutionControls,
  ): Promise<CoordinatedMaterialization | null>
}

/** Live consensus alone can freeze a proven application prefix. */
export interface LiveMaterializationCoordinator extends MaterializationCoordinator {
  /** Materialize and pin an actual immutable final prefix, independently of local state. */
  publishFinal(prefixLength: number): Promise<void>
}

/**
 * A control projection authenticated by the caller before replay. Its digest is
 * the exact signed control identity bound by each proposal's membershipRevision.
 * The materializer validates structure and retained continuity, not signatures.
 */
export interface PeerExecutionControl {
  readonly revision: number
  readonly digest: Uint8Array
  readonly members: readonly { readonly publicKey: Uint8Array; readonly role: 'member' | 'admin' }[]
}
export interface PeerExecutionControls {
  readonly applicationId: Uint8Array
  readonly currentRevision: number
  readonly revisions: readonly PeerExecutionControl[]
}

export type MaterializedLocalSqlValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'integer'; readonly value: string }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'blob'; readonly value: Uint8Array }

export interface AppliedSqlResult {
  readonly revision: bigint
  readonly orderLength: number
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly MaterializedLocalSqlValue[])[]
}

/** SQL metadata for the live runtime's local and final views. */
export interface MaterializedLocalSqlResult extends AppliedSqlResult {
  readonly view?: 'local' | 'final'
  readonly finalOrderLength?: number
}

export interface MaterializedRevisionSnapshot {
  readonly revision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
}

export interface MaterializedApplicationTransaction {
  readonly txId: Uint8Array
  readonly canonicalCandidate: Uint8Array
  readonly outcome: MaterializedTransactionOutcomeKind
}

/** Immutable capture of a replaceable applied revision, with no finality semantics. */
export interface AppliedApplicationSnapshot {
  readonly revision: bigint
  readonly orderLength: number
  /** A detached entry at this captured revision, or null outside its prefix. */
  transactionAt(index: number): MaterializedApplicationTransaction | null
}

/** A bounded SQL lease over the same applied revision as its application entries. */
export interface AppliedReadHandle extends AppliedApplicationSnapshot {
  query(sql: string, parameters?: readonly MaterializedLocalSqlValue[]): AppliedSqlResult
  release(): void
}

/** Live view capture; only requested application entries are copied. */
export interface MaterializedApplicationSnapshot extends AppliedApplicationSnapshot {
  readonly finalRevision: bigint
  readonly finalOrderLength: number
  readonly view: 'local' | 'final'
}

/** A bounded SQL lease captured atomically with its published application snapshot. */
export interface MaterializedReadHandle extends MaterializedApplicationSnapshot {
  query(sql: string, parameters?: readonly MaterializedLocalSqlValue[]): MaterializedLocalSqlResult
  release(): void
}

/** Reads the currently published applied state; a later replay can replace it. */
export interface AppliedQueryService {
  readonly revision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
  proposalIdAt(index: number): Uint8Array | null
  localSql(
    sql: string,
    parameters?: readonly MaterializedLocalSqlValue[],
    options?: { readonly atRevision?: bigint },
  ): AppliedSqlResult
  outcome(txId: Uint8Array): MaterializedTransactionOutcome | null
  captureApplication(): AppliedApplicationSnapshot
  captureRead(): AppliedReadHandle
  subscribe(subscriber: (revision: MaterializedRevisionSnapshot) => void): () => void
}

/** Reads one published immutable materialization and reports revision changes. */
export interface MaterializedQueryService {
  readonly revision: bigint
  readonly orderLength: number
  readonly finalRevision?: bigint
  readonly finalOrderLength?: number
  readonly executionManifestDigest: Uint8Array
  /** Original proposal identity at this position in the currently applied local order. */
  proposalIdAt(index: number): Uint8Array | null
  localSql(
    sql: string,
    parameters?: readonly MaterializedLocalSqlValue[],
    options?: { readonly atRevision?: bigint; readonly view?: 'local' | 'final' },
  ): MaterializedLocalSqlResult
  outcome(txId: Uint8Array): MaterializedTransactionOutcome | null
  captureApplication(options?: { readonly view?: 'local' | 'final' }): MaterializedApplicationSnapshot
  captureRead?(options?: { readonly view?: 'local' | 'final' }): MaterializedReadHandle
  subscribe(subscriber: (revision: MaterializedRevisionSnapshot) => void): () => void
}

export interface MaterializationPublicationResult extends MaterializedRevisionSnapshot {
  readonly status: 'published' | 'already_current' | 'reconciled'
  readonly publicationKey: string | null
}

/** Owns mutable publication; reducers and query services do not. */
export interface MaterializationPublicationStore {
  publish(request: MaterializationPublicationRequest): Promise<MaterializationPublicationResult>
  reconcile(expectation: {
    readonly targetOrderLength: number
    readonly targetRevision?: bigint
  }): Promise<MaterializationPublicationResult>
}

/** Deterministic replay and atomic publication, independent of any finality protocol. */
export interface AppliedMaterializationRuntime {
  readonly kind: 'applied'
  readonly coordinator: AppliedMaterializationCoordinator
  readonly queries: AppliedQueryService
  readonly publications: MaterializationPublicationStore
  close(): void | Promise<void>
}

/** Live collaboration adds a proven immutable prefix to the shared replay engine. */
export interface ChronologMaterializationRuntime {
  readonly coordinator: LiveMaterializationCoordinator
  readonly queries: MaterializedQueryService
  readonly publications: MaterializationPublicationStore
  close(): void | Promise<void>
}

export function publicationRequestForRevision(
  revision: MaterializedRevision,
): MaterializationPublicationRequest {
  return {
    // A later replay can restore identical content. It is a new publication,
    // while retrying this exact revision keeps the same immutable request.
    publicationKey: `revision:${revision.previousRevision}:${revision.revision}:${revision.orderLength}:${revision.contentHash}`,
    expectedRevision: revision.previousRevision,
    targetRevision: revision.revision,
    targetOrderLength: revision.orderLength,
    candidateIdentity: revision.contentHash,
  }
}

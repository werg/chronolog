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
    controls?: PeerExecutionControls,
  ): Promise<CoordinatedMaterialization | null>
  /** Materialize and pin an actual immutable final prefix, independently of local state. */
  publishFinal?(prefixLength: number): Promise<void>
}

/** A verified control projection supplied by the history owner, never an application callback. */
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

export interface MaterializedLocalSqlResult {
  readonly revision: bigint
  readonly orderLength: number
  readonly view?: 'local' | 'final'
  readonly finalOrderLength?: number
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly MaterializedLocalSqlValue[])[]
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

/** Immutable published revision; only requested application entries are copied. */
export interface MaterializedApplicationSnapshot {
  readonly revision: bigint
  readonly orderLength: number
  readonly finalRevision: bigint
  readonly finalOrderLength: number
  readonly view: 'local' | 'final'
  /** A detached entry at this captured revision, or null outside its prefix. */
  transactionAt(index: number): MaterializedApplicationTransaction | null
}

/** A bounded SQL lease captured atomically with its published application snapshot. */
export interface MaterializedReadHandle extends MaterializedApplicationSnapshot {
  query(sql: string, parameters?: readonly MaterializedLocalSqlValue[]): MaterializedLocalSqlResult
  release(): void
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

export interface ChronologMaterializationRuntime {
  readonly historyProfile?: 'chronological' | 'peer-generation-v1'
  readonly coordinator: MaterializationCoordinator
  readonly queries: MaterializedQueryService
  readonly publications: MaterializationPublicationStore
  close(): void | Promise<void>
}

export function publicationRequestForRevision(
  revision: MaterializedRevision,
): MaterializationPublicationRequest {
  return {
    publicationKey: `revision:${revision.revision}:${revision.contentHash}`,
    expectedRevision: revision.previousRevision,
    targetRevision: revision.revision,
    targetOrderLength: revision.orderLength,
    candidateIdentity: revision.contentHash,
  }
}

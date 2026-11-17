import {
  publicationRequestForRevision,
  type ReplayProposal,
  type AppliedApplicationSnapshot,
  type AppliedMaterializationCoordinator,
  type AppliedMaterializationRuntime,
  type AppliedReadHandle,
  type AppliedSqlResult,
  type PeerExecutionControls,
  type ChronologMaterializationRuntime,
  type MaterializedApplicationSnapshot,
  type MaterializationPublicationRequest,
  type MaterializationPublicationResult,
  type MaterializationPublicationStore,
  type MaterializedRevisionSnapshot,
  type MaterializedReadHandle,
} from '@chronolog/materializer'

import type {
  LocalSqlOptions,
  LocalSqlQueryResult,
  LocalSqlValue,
  MaterializedRevision,
  TransactionOutcome,
} from './types.js'

interface ReplayBackend {
  readonly revision: bigint
  readonly orderLength: number
  readonly executionManifestDigest: Uint8Array
  proposalIdAt(index: number): Uint8Array | null
  materialize(orderedTransactions: readonly ReplayProposal[], controls?: PeerExecutionControls): Promise<MaterializedRevision | null>
  outcome(txId: Uint8Array): TransactionOutcome | null
  subscribe(subscriber: (revision: MaterializedRevision) => void): () => void
  close(): void
}

/** The applied SQL engine exposes no final prefix, final view, or finality operation. */
export interface DoltLiteAppliedMaterializerRuntimeBackend extends ReplayBackend {
  readonly kind: 'applied'
  localSql(sql: string, parameters?: readonly LocalSqlValue[], options?: { readonly atRevision?: bigint }): AppliedSqlResult
  captureApplication(): AppliedApplicationSnapshot
  captureRead(): AppliedReadHandle
}

/** Live finality extends the same replay engine with an immutable published prefix. */
export interface DoltLiteMaterializerRuntimeBackend extends ReplayBackend {
  readonly finalRevision: bigint
  readonly finalOrderLength: number
  publishFinal(prefixLength: number): Promise<void>
  localSql(sql: string, parameters?: readonly LocalSqlValue[], options?: LocalSqlOptions): LocalSqlQueryResult
  captureApplication(options?: { readonly view?: 'local' | 'final' }): MaterializedApplicationSnapshot
  captureRead(options?: { readonly view?: 'local' | 'final' }): MaterializedReadHandle
}

export function createDoltLiteAppliedMaterializationRuntime(
  materializer: DoltLiteAppliedMaterializerRuntimeBackend,
): AppliedMaterializationRuntime {
  return {
    kind: 'applied',
    ...publicationRuntime(materializer),
    queries: {
      get revision() { return materializer.revision },
      get orderLength() { return materializer.orderLength },
      get executionManifestDigest() { return materializer.executionManifestDigest },
      proposalIdAt(index) { return materializer.proposalIdAt(index) },
      localSql(sql, parameters, options) { return materializer.localSql(sql, parameters, options) },
      outcome(txId) { return materializer.outcome(txId) },
      captureApplication() { return materializer.captureApplication() },
      captureRead() { return materializer.captureRead() },
      subscribe(subscriber) { return subscribe(materializer, subscriber) },
    },
  }
}

export function createDoltLiteMaterializationRuntime(
  materializer: DoltLiteMaterializerRuntimeBackend,
): ChronologMaterializationRuntime {
  const runtime = publicationRuntime(materializer)
  return {
    ...runtime,
    coordinator: {
      materialize(input) { return runtime.coordinator.materialize(input) },
      async publishFinal(prefixLength) { await materializer.publishFinal(prefixLength) },
    },
    queries: {
      get revision() { return materializer.revision },
      get orderLength() { return materializer.orderLength },
      get finalRevision() { return materializer.finalRevision },
      get finalOrderLength() { return materializer.finalOrderLength },
      get executionManifestDigest() { return materializer.executionManifestDigest },
      proposalIdAt(index) { return materializer.proposalIdAt(index) },
      localSql(sql, parameters, options) { return materializer.localSql(sql, parameters, options) },
      outcome(txId) { return materializer.outcome(txId) },
      captureApplication(options) { return materializer.captureApplication(options) },
      captureRead(options) { return materializer.captureRead(options) },
      subscribe(subscriber) { return subscribe(materializer, subscriber) },
    },
  }
}

/** DoltLite moves its applied head during replay; publication validates that exact movement. */
function publicationRuntime(materializer: ReplayBackend): {
  readonly coordinator: AppliedMaterializationCoordinator
  readonly publications: MaterializationPublicationStore
  close(): void
} {
  const prepared = new Map<string, MaterializationPublicationRequest>()
  const publications = new Map<string, {
    readonly request: MaterializationPublicationRequest
    readonly result: MaterializationPublicationResult
  }>()
  const snapshot = (): MaterializedRevisionSnapshot => ({
    revision: materializer.revision,
    orderLength: materializer.orderLength,
    executionManifestDigest: materializer.executionManifestDigest.slice(),
  })
  const result = (
    status: MaterializationPublicationResult['status'],
    publicationKey: string | null,
  ): MaterializationPublicationResult => ({ status, publicationKey, ...snapshot() })
  return {
    coordinator: {
      async materialize(orderedTransactions, controls) {
        const revision = await materializer.materialize(orderedTransactions, controls)
        if (revision === null) return null
        const publication = publicationRequestForRevision(revision)
        prepared.set(publication.publicationKey, publication)
        return { revision, publication }
      },
    },
    publications: {
      async publish(request): Promise<MaterializationPublicationResult> {
        const previous = publications.get(request.publicationKey)
        if (previous !== undefined) {
          if (!sameRequest(previous.request, request)) throw new Error('MATERIALIZATION_PUBLICATION_KEY_REUSED')
          return copyResult(previous.result)
        }
        const candidate = prepared.get(request.publicationKey)
        if (candidate === undefined || !sameRequest(candidate, request)) throw new Error('MATERIALIZATION_PUBLICATION_NOT_PREPARED')
        if (materializer.revision !== request.targetRevision || materializer.orderLength !== request.targetOrderLength) {
          throw new Error('MATERIALIZATION_PUBLICATION_NOT_CURRENT')
        }
        const completed = result('already_current', request.publicationKey)
        publications.set(request.publicationKey, { request: { ...request }, result: completed })
        prepared.delete(request.publicationKey)
        return copyResult(completed)
      },
      async reconcile(expectation): Promise<MaterializationPublicationResult> {
        if (materializer.orderLength !== expectation.targetOrderLength ||
            (expectation.targetRevision !== undefined && materializer.revision !== expectation.targetRevision)) {
          throw new Error('MATERIALIZATION_RECONCILIATION_MISMATCH')
        }
        return result('reconciled', null)
      },
    },
    close() { materializer.close() },
  }
}

function subscribe(materializer: ReplayBackend, subscriber: (revision: MaterializedRevisionSnapshot) => void): () => void {
  return materializer.subscribe((revision) => subscriber({
    revision: revision.revision,
    orderLength: revision.orderLength,
    executionManifestDigest: revision.manifestDigest.slice(),
  }))
}

function copyResult(value: MaterializationPublicationResult): MaterializationPublicationResult {
  return {
    status: value.status,
    publicationKey: value.publicationKey,
    revision: value.revision,
    orderLength: value.orderLength,
    executionManifestDigest: value.executionManifestDigest.slice(),
  }
}

function sameRequest(left: MaterializationPublicationRequest, right: MaterializationPublicationRequest): boolean {
  return left.publicationKey === right.publicationKey &&
    left.expectedRevision === right.expectedRevision &&
    left.targetRevision === right.targetRevision &&
    left.targetOrderLength === right.targetOrderLength &&
    left.candidateIdentity === right.candidateIdentity
}

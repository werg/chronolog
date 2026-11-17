import {
  publicationRequestForRevision,
  type AdmittedTransaction,
  type ChronologMaterializationRuntime,
  type MaterializationPublicationRequest,
  type MaterializationPublicationResult,
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

export interface DoltLiteMaterializerRuntimeBackend {
  readonly revision: bigint
  readonly orderLength: number
  readonly finalRevision?: bigint
  readonly finalOrderLength?: number
  readonly executionManifestDigest: Uint8Array
  proposalIdAt(index: number): Uint8Array | null
  materialize(orderedTransactions: readonly AdmittedTransaction[]): Promise<MaterializedRevision | null>
  publishFinal?(prefixLength: number): Promise<void>
  localSql(
    sql: string,
    parameters?: readonly LocalSqlValue[],
    options?: LocalSqlOptions,
  ): LocalSqlQueryResult
  outcome(txId: Uint8Array): TransactionOutcome | null
  captureRead?(options?: { readonly view?: 'local' | 'final' }): MaterializedReadHandle
  subscribe(subscriber: (revision: MaterializedRevision) => void): () => void
  close(): void
}

/**
 * Adapts the branch-backed DoltLite materializer to the portable runtime seams.
 * DoltLite has already moved its local head when materialize() returns, so
 * publish() validates and memoizes that exact movement as already-current.
 */
export function createDoltLiteMaterializationRuntime(
  materializer: DoltLiteMaterializerRuntimeBackend,
): ChronologMaterializationRuntime {
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
      async publishFinal(prefixLength) {
        if (materializer.publishFinal === undefined) throw new Error('MATERIALIZER_FINAL_VIEW_UNAVAILABLE')
        await materializer.publishFinal(prefixLength)
      },
      async materialize(orderedTransactions) {
        const revision = await materializer.materialize(orderedTransactions)
        if (revision === null) return null
        const publication = publicationRequestForRevision(revision)
        prepared.set(publication.publicationKey, publication)
        return { revision, publication }
      },
    },
    queries: {
      get revision() { return materializer.revision },
      get orderLength() { return materializer.orderLength },
      get finalRevision() { return materializer.finalRevision ?? 0n },
      get finalOrderLength() { return materializer.finalOrderLength ?? 0 },
      get executionManifestDigest() { return materializer.executionManifestDigest },
      proposalIdAt(index) { return materializer.proposalIdAt(index) },
      localSql(sql, parameters, options) { return materializer.localSql(sql, parameters, options) },
      outcome(txId) { return materializer.outcome(txId) },
      captureRead(options) {
        if (materializer.captureRead === undefined) throw new Error('MATERIALIZER_SNAPSHOT_UNAVAILABLE')
        return materializer.captureRead(options)
      },
      subscribe(subscriber) {
        return materializer.subscribe((revision) => subscriber({
          revision: revision.revision,
          orderLength: revision.orderLength,
          executionManifestDigest: revision.manifestDigest.slice(),
        }))
      },
    },
    publications: {
      async publish(request): Promise<MaterializationPublicationResult> {
        const previous = publications.get(request.publicationKey)
        if (previous !== undefined) {
          if (!sameRequest(previous.request, request)) {
            throw new Error('MATERIALIZATION_PUBLICATION_KEY_REUSED')
          }
          return copyResult(previous.result)
        }
        const candidate = prepared.get(request.publicationKey)
        if (candidate === undefined || !sameRequest(candidate, request)) {
          throw new Error('MATERIALIZATION_PUBLICATION_NOT_PREPARED')
        }
        if (
          materializer.revision !== request.targetRevision ||
          materializer.orderLength !== request.targetOrderLength
        ) {
          throw new Error('MATERIALIZATION_PUBLICATION_NOT_CURRENT')
        }
        const completed = result('already_current', request.publicationKey)
        publications.set(request.publicationKey, { request: { ...request }, result: completed })
        prepared.delete(request.publicationKey)
        return copyResult(completed)
      },
      async reconcile(expectation): Promise<MaterializationPublicationResult> {
        if (
          materializer.orderLength !== expectation.targetOrderLength ||
          (expectation.targetRevision !== undefined &&
            materializer.revision !== expectation.targetRevision)
        ) {
          throw new Error('MATERIALIZATION_RECONCILIATION_MISMATCH')
        }
        return result('reconciled', null)
      },
    },
    close() { materializer.close() },
  }
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

function sameRequest(
  left: MaterializationPublicationRequest,
  right: MaterializationPublicationRequest,
): boolean {
  return left.publicationKey === right.publicationKey &&
    left.expectedRevision === right.expectedRevision &&
    left.targetRevision === right.targetRevision &&
    left.targetOrderLength === right.targetOrderLength &&
    left.candidateIdentity === right.candidateIdentity
}

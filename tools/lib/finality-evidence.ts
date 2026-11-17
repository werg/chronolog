import type { EvidenceSink, NativeFinalityService } from '@chronolog/agent-service'
import {
  Mutex, encodeOrderingEvidence, orderedGenesisRoot, verifyOrderedEntry, verifyPrefixCertificate,
  type OrderedRecordHead,
} from '@chronolog/node-core'

/** Publish a complete fixed certified prefix without repeating earlier pages. */
export function createFinalityEvidencePublisher(
  source: Pick<NativeFinalityService, 'configuration' | 'certifiedRead' | 'read'>,
  sink: EvidenceSink,
): () => Promise<OrderedRecordHead> {
  const configuration = source.configuration, mutex = new Mutex()
  let cursor: OrderedRecordHead | undefined
  return () => mutex.run(async () => {
    const first = structuredClone(await source.certifiedRead({ after: cursor?.position ?? 0, limit: 64 }))
    const certificate = first.certificate
    await verifyPrefixCertificate(certificate, configuration)
    cursor ??= { historyId: configuration.historyId, position: 0, root: await orderedGenesisRoot(configuration.historyId) }
    if (certificate.position < cursor.position) throw new Error('FINALITY_PUBLICATION_REGRESSION')
    let entries = first.entries
    while (cursor.position < certificate.position) {
      if (entries.length === 0) throw new Error('FINALITY_PUBLICATION_NO_PROGRESS')
      if (entries.length > Math.min(64, certificate.position - cursor.position)) throw new Error('FINALITY_PUBLICATION_RANGE_INVALID')
      for (const entry of entries) {
        if (entry.historyId !== cursor.historyId || entry.position !== cursor.position + 1 || entry.previousRoot !== cursor.root) {
          throw new Error('FINALITY_PUBLICATION_DISCONTINUOUS')
        }
        await verifyOrderedEntry(entry)
        await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        // A lost reply retries this same entry. Already acknowledged evidence
        // stays owned by the sink even if a later page or certificate fails.
        cursor = { historyId: entry.historyId, position: entry.position, root: entry.root }
      }
      if (cursor.position < certificate.position) {
        const page = await source.read({ after: cursor.position, limit: Math.min(64, certificate.position - cursor.position) })
        if (page.head.historyId !== certificate.historyId || page.head.position < certificate.position) {
          throw new Error('FINALITY_PUBLICATION_RANGE_INVALID')
        }
        entries = structuredClone(page.entries)
      }
    }
    if (cursor.root !== certificate.root) throw new Error('FINALITY_PUBLICATION_ROOT_MISMATCH')
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
    return { ...cursor }
  })
}

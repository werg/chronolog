import type { EvidenceSink, NativeFinalityService } from '@chronolog/agent-service'
import { Mutex, type OrderedRecordHead } from '@chronolog/node-core'

/** Remember the last complete publication acknowledged by this sink. */
export function createFinalityEvidencePublisher(
  source: Pick<NativeFinalityService, 'share'>,
  sink: EvidenceSink,
): () => Promise<OrderedRecordHead> {
  const mutex = new Mutex()
  let after = 0
  return () => mutex.run(async () => {
    const head = await source.share(sink, { after })
    // share owns finite paging and certificate delivery. A failed or lost
    // acknowledgement leaves this cursor unchanged; retained evidence retries
    // are idempotent even if the sink already accepted part of that attempt.
    after = head.position
    return head
  })
}

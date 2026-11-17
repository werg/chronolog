import type { FeedStorePort } from './store.js'
import { MAX_EVIDENCE_BATCH_BYTES, MAX_EVIDENCE_BATCH_SIZE, type EvidenceBatch, type ImmutableEvidence } from './types.js'

/** A nonempty short page can be a byte-limited prefix, never an end-of-log claim. */
export async function readEvidencePage(
  store: Pick<FeedStorePort, 'evidenceAfter'>, after: bigint, limit: number, signal?: AbortSignal,
): Promise<readonly { readonly index: bigint; readonly evidence: ImmutableEvidence }[]> {
  if (after < 0n || after > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(limit) || limit < 1 || limit > 4096) throw new Error('FEED_RANGE_INVALID')
  const page: Array<{ readonly index: bigint; readonly evidence: ImmutableEvidence }> = []
  let bytes = 0
  while (page.length < Math.min(limit, MAX_EVIDENCE_BATCH_SIZE) && bytes < MAX_EVIDENCE_BATCH_BYTES && !signal?.aborted) {
    // Bound allocation before reading the next object, rather than materializing
    // count × maximum-size objects and checking their sum afterward.
    const entries = await store.evidenceAfter(after, 1)
    if (signal?.aborted) return []
    if (entries.length === 0) break
    const entry = entries[0]
    if (entries.length !== 1 || entry === undefined || entry.index !== after + 1n) throw new Error('FEED_EVIDENCE_PREFIX_MISSING')
    if (entry.evidence.bytes.length > MAX_EVIDENCE_BATCH_BYTES) throw new Error('FEED_EVIDENCE_BATCH_TOO_LARGE')
    if (bytes + entry.evidence.bytes.length > MAX_EVIDENCE_BATCH_BYTES) break
    page.push(entry)
    bytes += entry.evidence.bytes.length
    after = entry.index
  }
  return page
}

/** Share one bounded, finite committed-prefix reader between replay and live delivery. */
export async function* readEvidenceBatches(
  store: Pick<FeedStorePort, 'evidenceHead' | 'evidenceAfter'>,
  options: { readonly after?: bigint; readonly signal?: AbortSignal } = {},
): AsyncIterable<EvidenceBatch> {
  if (options.signal?.aborted) return
  const through = await store.evidenceHead()
  let after = options.after ?? 0n
  if (after < 0n || through < after) throw new Error('FEED_EVIDENCE_HEAD_REGRESSED')
  while (after < through && !options.signal?.aborted) {
    const limit = Number(through - after < BigInt(MAX_EVIDENCE_BATCH_SIZE) ? through - after : BigInt(MAX_EVIDENCE_BATCH_SIZE))
    const page = await readEvidencePage(store, after, limit, options.signal)
    if (options.signal?.aborted) return
    if (page.length === 0) throw new Error('FEED_EVIDENCE_PREFIX_MISSING')
    after = page.at(-1)!.index
    yield page.map(entry => entry.evidence)
  }
}

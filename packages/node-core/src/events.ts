import {
  assertCanonicalCbor, assertEventTopic, base64UrlToBytes, bytesToBase64Url,
  encodeCanonicalCbor, equalBytes, isEmitStep, type ChangeProgram, type CborValue,
} from '@chronolog/protocol'

export type { EffectiveEvent, EventTransaction, EventReadOptions, EventBatch } from '@chronolog/protocol'
import type { EffectiveEvent, EventTransaction, EventReadOptions, EventBatch } from '@chronolog/protocol'
export interface EventHistoryItem {
  readonly anchor: string
  readonly proposalId?: string
  readonly program?: ChangeProgram
  readonly outcome: 'accepted' | 'rejected' | 'skipped' | 'unresolved'
}
export interface EventHistorySnapshot {
  readonly historyId: string
  readonly revision: string
  readonly items: readonly EventHistoryItem[]
}
export const MAX_EVENT_BATCH_BYTES = 1_048_576
export const MAX_EVENT_SCAN = 1024
export const MAX_EVENT_BATCH_TRANSACTIONS = 128

function filterTopics(topics?: readonly string[]): readonly string[] | null {
  if (topics === undefined) return null
  const input: unknown = topics
  if (!Array.isArray(input) || topics.length > 128) throw new Error('EVENT_FILTER_INVALID')
  topics.forEach(assertEventTopic)
  return [...new Set(topics)].sort()
}
function cursor(snapshot: EventHistorySnapshot, topics: readonly string[] | null, scan: number): string {
  // Whole-transaction batches always stop at event ordinal zero of the next
  // proposal. The field is explicit so partial delivery cannot masquerade as
  // a completed proposal. The canonical anchor prevents cross-branch reuse.
  return bytesToBase64Url(encodeCanonicalCbor([
    'chronolog/events/v1', snapshot.historyId, topics, BigInt(scan), 0n,
    scan === 0 ? null : snapshot.items[scan - 1]!.anchor,
  ]))
}
function resume(snapshot: EventHistorySnapshot, topics: readonly string[] | null, token?: string): number {
  if (token === undefined) return 0
  if (typeof token !== 'string' || token.length > 32768) throw new Error('EVENT_CURSOR_INVALID')
  let value
  try { value = assertCanonicalCbor(base64UrlToBytes(token)) } catch { throw new Error('EVENT_CURSOR_INVALID') }
  if (!Array.isArray(value) || value.length !== 6) throw new Error('EVENT_CURSOR_MISMATCH')
  const fields = value as readonly CborValue[]
  if (fields[0] !== 'chronolog/events/v1' ||
      fields[1] !== snapshot.historyId || !equalBytes(encodeCanonicalCbor(fields[2] ?? null), encodeCanonicalCbor(topics)) ||
      typeof fields[3] !== 'bigint' || fields[3] < 0n || fields[3] > BigInt(snapshot.items.length) || fields[4] !== 0n) {
    throw new Error('EVENT_CURSOR_MISMATCH')
  }
  const scan = Number(fields[3])
  if (fields[5] !== (scan === 0 ? null : snapshot.items[scan - 1]!.anchor)) throw new Error('EVENT_CURSOR_PREFIX_MISMATCH')
  return scan
}

/** Rebuildable index over applied outcomes. Certificates alone never supply outcomes. */
export function readEffectiveEvents(snapshot: EventHistorySnapshot, options: EventReadOptions = {}): EventBatch {
  const topics = filterTopics(options.topics)
  const limit = options.limit ?? 32
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_EVENT_BATCH_TRANSACTIONS) throw new Error('EVENT_LIMIT_INVALID')
  let scan = resume(snapshot, topics, options.cursor)
  const end = Math.min(snapshot.items.length, scan + MAX_EVENT_SCAN)
  const transactions: EventTransaction[] = []
  let bytes = 0
  while (scan < end && transactions.length < limit) {
    const item = snapshot.items[scan]!
    if (item.outcome === 'unresolved') break
    if (item.outcome === 'accepted') {
      if (item.program === undefined || item.proposalId === undefined) throw new Error('EVENT_APPLIED_INPUT_MISSING')
      let ordinal = 0
      const events: EffectiveEvent[] = []
      for (const step of item.program.steps) {
        if (!isEmitStep(step)) continue
        const eventOrdinal = ordinal++
        if (topics === null || topics.includes(step.topic)) events.push({
          id: `${item.proposalId}:${eventOrdinal}`, proposalId: item.proposalId,
          eventOrdinal, topic: step.topic, payload: structuredClone(step.payload),
        })
      }
      if (events.length > 0) {
        const transaction = { proposalId: item.proposalId, events }
        const size = new TextEncoder().encode(JSON.stringify(transaction)).length
        if (size > MAX_EVENT_BATCH_BYTES) throw new Error('EVENT_TRANSACTION_TOO_LARGE')
        if (bytes + size > MAX_EVENT_BATCH_BYTES) break
        bytes += size
        transactions.push(transaction)
      }
    }
    scan++
  }
  return { transactions, scannedThrough: cursor(snapshot, topics, scan), hasMore: scan < snapshot.items.length && snapshot.items[scan]?.outcome !== 'unresolved', revision: snapshot.revision }
}

export interface DurableEventSource {
  read(options?: EventReadOptions): Promise<EventBatch>
  subscribe(options?: EventReadOptions & { readonly signal?: AbortSignal }): AsyncIterable<EventBatch>
}

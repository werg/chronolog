import { bytesToHex, hexToBytes, utf8 } from '@chronolog/canonical'
import type { JsonValue, OperationVisibility } from '@chronolog/protocol'

/** One committed operation outcome as kept by the kernel (and its materialized cache). */
export interface EmittedKernelEvent {
  readonly opId: string
  readonly eventOrdinal: number
  readonly topic: string
  readonly payload: JsonValue
  readonly author: string
  readonly operationId: string
  readonly authorTimestampMs: bigint
}

export interface KernelOperationOutcome {
  readonly opId: string
  readonly author: string
  readonly operationId: string
  readonly authorTimestampMs: bigint
  readonly visibility: OperationVisibility
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
  readonly rejectionDetail?: string
  readonly conflictRecorded?: boolean
  readonly events: readonly EmittedKernelEvent[]
}

/**
 * Exported kernel state: enough to resume materialization without replaying history.
 *
 * `frontierOpIds` are ops already folded into `topics` whose inputs are NOT needed (snapshot
 * bootstrap); `orderOpIds`/`outcomes` are the replayable suffix whose inputs must be present
 * locally for an exact restore. A wire snapshot carries an empty suffix (frontier only).
 */
export interface KernelMaterializedCache {
  readonly v: 2
  readonly logId: string
  readonly blindHostMode: boolean
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly seenOpsRoot: string
  readonly historyDigest: string
  readonly stateRoot: string
  readonly frontierOpIds: readonly string[]
  readonly frontierMaxTimestampMs: bigint
  readonly orderOpIds: readonly string[]
  readonly outcomes: readonly KernelOperationOutcome[]
  /** Last accepted op per topic (lets restore skip re-reading every op's updates). */
  readonly topicLastOpIds: Readonly<Record<string, string>>
  /** Last accepted op per author (and public-only per author on private logs) for causal-chain checks. */
  readonly authorLastOpIds?: Readonly<Record<string, string>>
  readonly publicAuthorLastOpIds?: Readonly<Record<string, string>>
}

const MAGIC = 0x434c4d43 // 'CLMC'
const FORMAT = 2

const F_ENCRYPTED = 1
const F_REJECTED = 2
const F_CONFLICT = 4

/**
 * Compact binary encoding of a KernelMaterializedCache:
 *   u32 magic | u8 format | u32 headerLen | header JSON | u32 frontierCount | 32B ids |
 *   u32 orderCount | 32B ids | u32 outcomesLen | outcomes JSON
 * Op ids are raw 32-byte values; outcomes are positional tuples with an author table, so the
 * encoding is O(N) bytes with no per-op hex or keys, and decoding is one native JSON.parse.
 */
export function encodeMaterializedCache(cache: KernelMaterializedCache): Uint8Array {
  const authors: string[] = []
  const authorIndex = new Map<string, number>()
  const authorOf = (hex: string): number => {
    let index = authorIndex.get(hex)
    if (index === undefined) { index = authors.length; authors.push(hex); authorIndex.set(hex, index) }
    return index
  }
  const outcomes = cache.outcomes.map(o => {
    const flags = (o.visibility === 'encrypted' ? F_ENCRYPTED : 0) | (o.outcome === 'rejected' ? F_REJECTED : 0) | (o.conflictRecorded === true ? F_CONFLICT : 0)
    return [
      authorOf(o.author), o.operationId, o.authorTimestampMs.toString(), flags, o.rejectionCode, o.rejectionDetail ?? null,
      o.events.map(e => [e.eventOrdinal, e.topic, e.payload]),
    ]
  })
  const header = utf8(JSON.stringify({
    logId: cache.logId,
    blindHostMode: cache.blindHostMode,
    topics: cache.topics,
    seenOpsRoot: cache.seenOpsRoot,
    historyDigest: cache.historyDigest,
    stateRoot: cache.stateRoot,
    frontierMaxTimestampMs: cache.frontierMaxTimestampMs.toString(),
    topicLastOpIds: cache.topicLastOpIds,
    ...(cache.authorLastOpIds === undefined ? {} : { authorLastOpIds: cache.authorLastOpIds }),
    ...(cache.publicAuthorLastOpIds === undefined ? {} : { publicAuthorLastOpIds: cache.publicAuthorLastOpIds }),
    authors,
  }))
  const body = utf8(JSON.stringify(outcomes))
  const total = 4 + 1 + 4 + header.length + 4 + 32 * cache.frontierOpIds.length + 4 + 32 * cache.orderOpIds.length + 4 + body.length
  const out = new Uint8Array(total)
  const view = new DataView(out.buffer)
  let at = 0
  view.setUint32(at, MAGIC); at += 4
  out[at++] = FORMAT
  view.setUint32(at, header.length); at += 4
  out.set(header, at); at += header.length
  for (const ids of [cache.frontierOpIds, cache.orderOpIds]) {
    view.setUint32(at, ids.length); at += 4
    for (const id of ids) { out.set(hexToBytes(id), at); at += 32 }
  }
  view.setUint32(at, body.length); at += 4
  out.set(body, at)
  return out
}

/** Decode encodeMaterializedCache output; returns null for any other or malformed input. */
export function decodeMaterializedCache(bytes: Uint8Array): KernelMaterializedCache | null {
  try {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    let at = 0
    if (view.getUint32(at) !== MAGIC) return null
    at += 4
    if (bytes[at++] !== FORMAT) return null
    const text = new TextDecoder('utf-8', { fatal: true })
    const headerLen = view.getUint32(at); at += 4
    const header = JSON.parse(text.decode(bytes.subarray(at, at + headerLen))) as {
      logId: string; blindHostMode: boolean; topics: Record<string, JsonValue>; seenOpsRoot: string
      historyDigest: string; stateRoot: string; frontierMaxTimestampMs: string
      topicLastOpIds: Record<string, string>; authorLastOpIds?: Record<string, string>; publicAuthorLastOpIds?: Record<string, string>; authors: string[]
    }
    at += headerLen
    const readIds = (): string[] => {
      const count = view.getUint32(at); at += 4
      if (at + count * 32 > bytes.length) throw new Error('CACHE_TRUNCATED')
      const ids = new Array<string>(count)
      for (let i = 0; i < count; i++) { ids[i] = bytesToHex(bytes.subarray(at, at + 32)); at += 32 }
      return ids
    }
    const frontierOpIds = readIds()
    const orderOpIds = readIds()
    const bodyLen = view.getUint32(at); at += 4
    if (at + bodyLen !== bytes.length) return null
    const rows = JSON.parse(text.decode(bytes.subarray(at, at + bodyLen))) as [number, string, string, number, string | null, string | null, [number, string, JsonValue][]][]
    if (!Array.isArray(rows) || rows.length !== orderOpIds.length) return null
    const outcomes: KernelOperationOutcome[] = rows.map((row, i) => {
      const [authorIdx, operationId, ts, flags, rejectionCode, rejectionDetail, events] = row
      const opId = orderOpIds[i]!
      const author = header.authors[authorIdx]!
      const authorTimestampMs = BigInt(ts)
      return {
        opId,
        author,
        operationId,
        authorTimestampMs,
        visibility: (flags & F_ENCRYPTED) !== 0 ? 'encrypted' : 'public',
        outcome: (flags & F_REJECTED) !== 0 ? 'rejected' : 'accepted',
        rejectionCode,
        ...(rejectionDetail === null ? {} : { rejectionDetail }),
        ...((flags & F_CONFLICT) !== 0 ? { conflictRecorded: true } : {}),
        events: events.map(([eventOrdinal, topic, payload]) => ({ opId, eventOrdinal, topic, payload, author, operationId, authorTimestampMs })),
      }
    })
    return {
      v: 2,
      logId: header.logId,
      blindHostMode: header.blindHostMode,
      topics: header.topics,
      seenOpsRoot: header.seenOpsRoot,
      historyDigest: header.historyDigest,
      stateRoot: header.stateRoot,
      frontierOpIds,
      frontierMaxTimestampMs: BigInt(header.frontierMaxTimestampMs),
      orderOpIds,
      outcomes,
      topicLastOpIds: header.topicLastOpIds,
      ...(header.authorLastOpIds === undefined ? {} : { authorLastOpIds: header.authorLastOpIds }),
      ...(header.publicAuthorLastOpIds === undefined ? {} : { publicAuthorLastOpIds: header.publicAuthorLastOpIds }),
    }
  } catch {
    return null
  }
}

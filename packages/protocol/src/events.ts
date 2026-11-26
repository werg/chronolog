import type { EventPayload } from './v2.js'
import { base64UrlToBytes, bytesToBase64Url } from './bytes.js'

/** Authenticated proposal facts, supplied by the replica rather than an emit payload. */
export interface ChronologEventOrigin {
  readonly kind: 'chronolog'
  /** Canonical unpadded base64url group digest. */
  readonly groupId: string
  /** Lowercase hex public key, identical to Signals.authorId for the same signer. */
  readonly authorId: string
  readonly operationId: string
  /** Signed ordering timestamp as an exact decimal integer, not delivery time. */
  readonly authorTimestampMs: string
  /** Canonical unpadded base64url membership revision digest. */
  readonly membershipRevision: string
  /** Canonical unpadded base64url signed grant digest; null only for explicit static membership. */
  readonly writerCapability: string | null
}

/** Validate and copy a serialized origin. Authentication remains the source's responsibility. */
export function cloneEventOrigin(value: ChronologEventOrigin): ChronologEventOrigin {
  if (value === null || typeof value !== 'object' || value.kind !== 'chronolog' ||
      typeof value.authorId !== 'string' || !/^[0-9a-f]{64}$/u.test(value.authorId) ||
      typeof value.operationId !== 'string' || value.operationId.length === 0 || value.operationId.length > 512 ||
      [...value.operationId].some(character => { const code = character.codePointAt(0)!; return code < 32 || code >= 0xd800 && code <= 0xdfff }) ||
      typeof value.authorTimestampMs !== 'string' || !/^(?:0|[1-9][0-9]{0,18})$/u.test(value.authorTimestampMs) ||
      BigInt(value.authorTimestampMs) > (1n << 63n) - 1n) throw new Error('EVENT_ORIGIN_INVALID')
  for (const id of [value.groupId, value.membershipRevision, ...(value.writerCapability === null ? [] : [value.writerCapability])]) {
    if (typeof id !== 'string' || id.length !== 43) throw new Error('EVENT_ORIGIN_INVALID')
    try { const bytes = base64UrlToBytes(id); if (bytes.length !== 32 || bytesToBase64Url(bytes) !== id) throw new Error() } catch { throw new Error('EVENT_ORIGIN_INVALID') }
  }
  return { kind: 'chronolog', groupId: value.groupId, authorId: value.authorId, operationId: value.operationId,
    authorTimestampMs: value.authorTimestampMs, membershipRevision: value.membershipRevision, writerCapability: value.writerCapability }
}

export interface EffectiveEvent {
  readonly id: string
  readonly proposalId: string
  readonly eventOrdinal: number
  readonly topic: string
  readonly payload: EventPayload
  readonly origin: ChronologEventOrigin
}
export interface EventTransaction { readonly proposalId: string; readonly events: readonly EffectiveEvent[] }
export interface EventReadOptions {
  readonly cursor?: string
  readonly topics?: readonly string[]
  /** Maximum matching whole proposals, not an event count. */
  readonly limit?: number
}
export interface EventBatch {
  readonly transactions: readonly EventTransaction[]
  readonly scannedThrough: string
  readonly hasMore: boolean
  readonly revision: string
}

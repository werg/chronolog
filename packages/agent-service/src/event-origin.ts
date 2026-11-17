import { cloneEventOrigin, type CborValue, type ChronologEventOrigin } from '@chronolog/protocol'

/** One private checkpoint codec shared by effect and timer consumers. */
export function encodeEventOrigin(origin: ChronologEventOrigin): CborValue {
  return [origin.kind, origin.groupId, origin.authorId, origin.operationId, origin.authorTimestampMs,
    origin.membershipRevision, origin.writerCapability]
}

export function decodeEventOrigin(value: unknown): ChronologEventOrigin {
  if (!Array.isArray(value) || value.length !== 7) throw new Error('EVENT_ORIGIN_INVALID')
  const [kind, groupId, authorId, operationId, authorTimestampMs, membershipRevision, writerCapability] = value as readonly unknown[]
  if (kind !== 'chronolog' || typeof groupId !== 'string' || typeof authorId !== 'string' || typeof operationId !== 'string' ||
      typeof authorTimestampMs !== 'string' || typeof membershipRevision !== 'string' ||
      (writerCapability !== null && typeof writerCapability !== 'string')) throw new Error('EVENT_ORIGIN_INVALID')
  return cloneEventOrigin({ kind, groupId, authorId, operationId, authorTimestampMs, membershipRevision, writerCapability })
}

import type { CborValue } from '@chronolog/protocol'

import { validateConsumerId } from './event-source.js'
import type { FinalEventPublicationRejection } from './event-source.js'

export const MAX_PUBLICATION_ATTEMPTS = 64

export function publicationOperationId(kind: 'effect-result' | 'timer-occurrence', identity: string, attempt: number): string {
  if (!Number.isSafeInteger(attempt) || attempt < 0 || attempt >= MAX_PUBLICATION_ATTEMPTS) throw new Error('PUBLICATION_ATTEMPT_INVALID')
  return `${kind}:${identity}:${attempt}`
}

export function encodePublicationRejections(rejections: readonly FinalEventPublicationRejection[]): CborValue {
  return rejections.map(item => [BigInt(item.attempt), item.proposalId, item.rejectionCode])
}

export function decodePublicationRejections(value: unknown, operationId: (attempt: number) => string): readonly FinalEventPublicationRejection[] {
  if (!Array.isArray(value) || value.length > MAX_PUBLICATION_ATTEMPTS) throw new Error('PUBLICATION_AUDIT_INVALID')
  return value.map((item, index) => {
    if (!Array.isArray(item) || item.length !== 3 || item[0] !== BigInt(index) || typeof item[1] !== 'string' ||
        (item[2] !== null && typeof item[2] !== 'string')) throw new Error('PUBLICATION_AUDIT_INVALID')
    validateConsumerId(item[1])
    return { attempt: index, operationId: operationId(index), proposalId: item[1], rejectionCode: item[2] as string | null }
  })
}

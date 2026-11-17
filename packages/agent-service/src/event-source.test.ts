import { describe, expect, it } from 'vitest'
import type { ChronologEventOrigin } from '@chronolog/protocol'

import { cloneFinalEvent, type FinalEvent } from './event-source.js'

const origin: ChronologEventOrigin = { kind: 'chronolog', groupId: 'A'.repeat(43), authorId: '11'.repeat(32),
  operationId: 'verified-operation', authorTimestampMs: '123', membershipRevision: 'A'.repeat(43), writerCapability: null }
const event: FinalEvent = { id: 'proposal:0', proposalId: 'proposal', eventOrdinal: 0, topic: 'intent',
  payload: { authorId: 'forged-author', origin: { ...origin } }, origin }

describe('structural final-event provenance', () => {
  it('detaches source metadata and payload while copying only the public fields', () => {
    const source = structuredClone(event), cloned = cloneFinalEvent({ ...source, extra: 'not part of the port' } as FinalEvent)
    Object.assign(source.origin, { authorId: 'changed' })
    Object.assign(source.payload!, { authorId: 'changed' })
    expect(cloned).toEqual(event)
    expect(cloned.origin).not.toBe(origin)
    expect(cloned).not.toHaveProperty('extra')
  })

  it.each([undefined, null, 1, [], { ...origin, kind: '' }, { ...origin, kind: 'k'.repeat(65) },
    { ...origin, authorId: 'a'.repeat(257) }, { ...origin, operationId: 'o'.repeat(513) },
    { ...origin, operationId: 'hidden\u0000operation' }, { ...origin, operationId: 'invalid\ud800operation' }])('rejects missing, malformed or unbounded source metadata: %j', invalid => {
    expect(() => cloneFinalEvent({ ...event, origin: invalid } as FinalEvent)).toThrow('EVENT_ORIGIN_INVALID')
  })
})

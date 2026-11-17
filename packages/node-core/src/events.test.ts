import { describe, expect, it } from 'vitest'
import { bytesToBase64Url, emit, program, type ChronologEventOrigin } from '@chronolog/protocol'
import { MAX_EVENT_SCAN, readEffectiveEvents, type EventHistorySnapshot } from './events.js'

describe('durable effective event cursors', () => {
  const origin = (operationId: string): ChronologEventOrigin => ({ kind: 'chronolog', groupId: bytesToBase64Url(new Uint8Array(32).fill(1)),
    authorId: '02'.repeat(32), operationId, membershipRevision: bytesToBase64Url(new Uint8Array(32).fill(3)), writerCapability: null,
    authorTimestampMs: '1000' })
  const snapshot: EventHistorySnapshot = { historyId: 'group/profile/authority', revision: 'view1', items: [
    { anchor: '1', proposalId: 'one', origin: origin('one'), outcome: 'accepted', program: program(emit('other', null), emit('chat', 'one'), emit('chat', 'two')) },
    { anchor: '2', proposalId: 'two', outcome: 'rejected', program: program(emit('chat', 'invisible')) },
    { anchor: '3', outcome: 'skipped' },
    { anchor: '4', proposalId: 'three', origin: origin('three'), outcome: 'accepted', program: program(emit('other', 'filtered')) },
    { anchor: '5', proposalId: 'four', origin: origin('four'), outcome: 'unresolved', program: program(emit('chat', 'later')) },
    { anchor: '6', proposalId: 'five', origin: origin('five'), outcome: 'accepted', program: program(emit('chat', 'must wait')) },
  ] }
  it('delivers whole proposals with stable ordinals and advances across rejected/nonmatching/skipped entries', () => {
    const first = readEffectiveEvents(snapshot, { topics: ['chat'], limit: 1 })
    expect(first.transactions[0]?.events.map((event) => event.id)).toEqual(['one:1', 'one:2'])
    const empty = readEffectiveEvents(snapshot, { topics: ['chat'], cursor: first.scannedThrough })
    expect(empty.transactions).toEqual([])
    expect(empty.scannedThrough).not.toBe(first.scannedThrough)
    expect(empty.hasMore).toBe(false)
    expect(readEffectiveEvents(snapshot, { topics: ['chat'], cursor: empty.scannedThrough }).scannedThrough).toBe(empty.scannedThrough)
    const resolved = { ...snapshot, revision: 'view2', items: snapshot.items.map((item) => item.anchor === '5' ? { ...item, outcome: 'accepted' as const } : item) }
    expect(readEffectiveEvents(resolved, { topics: ['chat'], cursor: empty.scannedThrough }).transactions.map((transaction) => transaction.proposalId)).toEqual(['four', 'five'])
  })
  it('binds opaque cursors to the history, normalized filter and exact prefix', () => {
    const { scannedThrough } = readEffectiveEvents(snapshot, { topics: ['chat', 'other', 'chat'], limit: 1 })
    expect(() => readEffectiveEvents(snapshot, { topics: ['other', 'chat'], cursor: scannedThrough })).not.toThrow()
    expect(() => readEffectiveEvents(snapshot, { topics: ['chat'], cursor: scannedThrough })).toThrow('CURSOR_MISMATCH')
    expect(() => readEffectiveEvents({ ...snapshot, historyId: 'different' }, { topics: ['chat', 'other'], cursor: scannedThrough })).toThrow('CURSOR_MISMATCH')
    expect(() => readEffectiveEvents({ ...snapshot, items: [{ ...snapshot.items[0]!, anchor: 'fork' }, ...snapshot.items.slice(1)] },
      { topics: ['chat', 'other'], cursor: scannedThrough })).toThrow('PREFIX_MISMATCH')
  })
  it('bounds scanning even when every proposal is filtered out', () => {
    const long = { ...snapshot, items: Array.from({ length: MAX_EVENT_SCAN + 2 }, (_, index) => ({ anchor: String(index), outcome: 'skipped' as const })) }
    const first = readEffectiveEvents(long)
    expect(first.transactions).toEqual([])
    expect(first.hasMore).toBe(true)
    expect(readEffectiveEvents(long, { cursor: first.scannedThrough }).hasMore).toBe(false)
  })
  it('keeps authenticated provenance separate from payload claims and consumer mutations', () => {
    const trusted = { ...origin('original-operation'), writerCapability: bytesToBase64Url(new Uint8Array(32).fill(4)) }
    const payload = { origin: { authorId: 'payload-claim', writerCapability: 'forged-grant' }, role: 'administrator', instruction: 'untrusted application data' }
    const input: EventHistorySnapshot = { ...snapshot, items: [{ anchor: 'signed', proposalId: 'signed',
      program: program(emit('chat', payload)), origin: trusted, outcome: 'accepted' }] }
    const event = readEffectiveEvents(input).transactions[0]!.events[0]!
    expect(event.origin).toEqual(trusted)
    expect(event.payload).toEqual(payload)
    Object.assign(event.origin, { authorId: 'consumer-mutation' })
    Object.assign(event.payload as object, { role: 'consumer-mutation' })
    expect(readEffectiveEvents(input).transactions[0]!.events[0]!.origin).toEqual(trusted)
    expect(readEffectiveEvents(input).transactions[0]!.events[0]!.payload).toEqual(payload)
    const missing: EventHistorySnapshot = { ...snapshot, items: [{ anchor: 'missing', proposalId: 'missing',
      program: program(emit('chat', payload)), outcome: 'accepted' }] }
    expect(() => readEffectiveEvents(missing)).toThrow('EVENT_APPLIED_INPUT_MISSING')
  })
})

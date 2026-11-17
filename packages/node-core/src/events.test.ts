import { describe, expect, it } from 'vitest'
import { emit, program, type ChronologEventOrigin } from '@chronolog/protocol'
import { MAX_EVENT_SCAN, readEffectiveEvents, type EventHistoryItem, type EventHistorySnapshot } from './events.js'

function itemsView(items: readonly EventHistoryItem[]) {
  return { length: items.length, itemAt: (index: number) => items[index] ?? null }
}

describe('durable effective event cursors', () => {
  const origin: ChronologEventOrigin = { kind: 'chronolog', groupId: 'A'.repeat(43), authorId: '11'.repeat(32),
    operationId: 'signed-operation', authorTimestampMs: '123', membershipRevision: 'A'.repeat(43), writerCapability: null }
  const items: readonly EventHistoryItem[] = [
    { anchor: '1', proposalId: 'one', outcome: 'accepted', origin, program: program(emit('other', null), emit('chat', 'one'), emit('chat', 'two')) },
    { anchor: '2', proposalId: 'two', outcome: 'rejected', program: program(emit('chat', 'invisible')) },
    { anchor: '3', outcome: 'skipped' },
    { anchor: '4', proposalId: 'three', outcome: 'accepted', origin, program: program(emit('other', 'filtered')) },
    { anchor: '5', proposalId: 'four', outcome: 'unresolved', origin, program: program(emit('chat', 'later')) },
    { anchor: '6', proposalId: 'five', outcome: 'accepted', origin, program: program(emit('chat', 'must wait')) },
  ]
  const snapshot: EventHistorySnapshot = { historyId: 'group/profile/authority', revision: 'view1', ...itemsView(items) }
  it('delivers whole proposals with stable ordinals and advances across rejected/nonmatching/skipped entries', () => {
    const first = readEffectiveEvents(snapshot, { topics: ['chat'], limit: 1 })
    expect(first.transactions[0]?.events.map((event) => event.id)).toEqual(['one:1', 'one:2'])
    const empty = readEffectiveEvents(snapshot, { topics: ['chat'], cursor: first.scannedThrough })
    expect(empty.transactions).toEqual([])
    expect(empty.scannedThrough).not.toBe(first.scannedThrough)
    expect(empty.hasMore).toBe(false)
    expect(readEffectiveEvents(snapshot, { topics: ['chat'], cursor: empty.scannedThrough }).scannedThrough).toBe(empty.scannedThrough)
    const resolved = { ...snapshot, revision: 'view2', ...itemsView(items.map((item) => item.anchor === '5' ? { ...item, outcome: 'accepted' as const } : item)) }
    expect(readEffectiveEvents(resolved, { topics: ['chat'], cursor: empty.scannedThrough }).transactions.map((transaction) => transaction.proposalId)).toEqual(['four', 'five'])
  })
  it('binds opaque cursors to the history, normalized filter and exact prefix', () => {
    const { scannedThrough } = readEffectiveEvents(snapshot, { topics: ['chat', 'other', 'chat'], limit: 1 })
    expect(() => readEffectiveEvents(snapshot, { topics: ['other', 'chat'], cursor: scannedThrough })).not.toThrow()
    expect(() => readEffectiveEvents(snapshot, { topics: ['chat'], cursor: scannedThrough })).toThrow('CURSOR_MISMATCH')
    expect(() => readEffectiveEvents({ ...snapshot, historyId: 'different' }, { topics: ['chat', 'other'], cursor: scannedThrough })).toThrow('CURSOR_MISMATCH')
    expect(() => readEffectiveEvents({ ...snapshot, ...itemsView([{ ...items[0]!, anchor: 'fork' }, ...items.slice(1)]) },
      { topics: ['chat', 'other'], cursor: scannedThrough })).toThrow('PREFIX_MISMATCH')
  })
  it('bounds scanning even when every proposal is filtered out', () => {
    const long = { ...snapshot, ...itemsView(Array.from({ length: MAX_EVENT_SCAN + 2 }, (_, index) => ({ anchor: String(index), outcome: 'skipped' as const }))) }
    const first = readEffectiveEvents(long)
    expect(first.transactions).toEqual([])
    expect(first.hasMore).toBe(true)
    expect(readEffectiveEvents(long, { cursor: first.scannedThrough }).hasMore).toBe(false)
  })
  it('reads only a bounded window from a million-item lazy history', () => {
    let reads = 0
    const large: EventHistorySnapshot = { ...snapshot, length: 1_000_000,
      itemAt(index) { reads++; return { anchor: String(index), outcome: 'skipped' } } }
    const batch = readEffectiveEvents(large)
    expect(batch.hasMore).toBe(true)
    expect(reads).toBeLessThanOrEqual(MAX_EVENT_SCAN + 2)
    const beforeResume = reads
    expect(readEffectiveEvents(large, { cursor: batch.scannedThrough }).hasMore).toBe(true)
    expect(reads - beforeResume).toBeLessThanOrEqual(MAX_EVENT_SCAN + 3)
  })
  it('projects verified proposal facts independently of payload claims and caller mutation', () => {
    const payload = { origin: { authorId: 'forged-owner', writerCapability: 'forged-grant' }, role: 'administrator' }
    const signed = { ...snapshot, ...itemsView([{ anchor: 'signed', proposalId: 'signed', outcome: 'accepted' as const, origin, program: program(emit('chat', payload)) }]) }
    const event = readEffectiveEvents(signed).transactions[0]!.events[0]!
    expect(event.origin).toEqual(origin)
    expect(event.origin).not.toBe(origin)
    expect(event.payload).toEqual(payload)
    Object.assign(event.origin, { authorId: '22'.repeat(32) })
    Object.assign(event.payload as object, { role: 'consumer-mutation' })
    expect(readEffectiveEvents(signed).transactions[0]!.events[0]!.origin).toEqual(origin)
    expect(readEffectiveEvents(signed).transactions[0]!.events[0]!.payload).toEqual(payload)
    const { origin: _origin, ...missing } = signed.itemAt(0)!
    expect(() => readEffectiveEvents({ ...signed, ...itemsView([missing]) })).toThrow('EVENT_APPLIED_INPUT_MISSING')
  })
})

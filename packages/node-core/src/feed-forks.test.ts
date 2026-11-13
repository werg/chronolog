import { DatabaseSync } from 'node:sqlite'

import { describe, expect, it } from 'vitest'

import { FeedForkRegistry, SqliteFeedForkPersistence } from './feed-forks.js'

describe('feed fork quarantine and repair', () => {
  it('persists quarantine when one author sequence has divergent identities', () => {
    const database = new DatabaseSync(':memory:')
    const registry = new FeedForkRegistry(new SqliteFeedForkPersistence(database))
    expect(registry.observe(record(1n, 'first'))).toBe('accepted')
    expect(registry.observe(record(2n, 'left', 'first'))).toBe('accepted')
    expect(registry.observe(record(2n, 'right', 'first'))).toBe('quarantined')
    expect(registry.quarantined('@writer.ed25519')).toBe(true)
    expect(registry.quarantineEvidence()).toMatchObject([{
      feedId: '@writer.ed25519', sequence: '2', acceptedId: 'left', conflictingId: 'right',
    }])
    expect(new FeedForkRegistry(new SqliteFeedForkPersistence(database)).quarantined()).toBe(true)
  })

  it('requires a complete trusted prefix before clearing quarantine', () => {
    const registry = new FeedForkRegistry()
    registry.observe(record(1n, 'first'))
    registry.observe(record(2n, 'left', 'first'))
    registry.observe(record(2n, 'right', 'first'))
    expect(() => registry.createRepairPlan('@writer.ed25519', [record(2n, 'right', 'first')], 'right'))
      .toThrow('FEED_REPAIR_PREFIX_INCOMPLETE')
    const trusted = [record(1n, 'first'), record(2n, 'right', 'first')]
    registry.applyRepair(registry.createRepairPlan('@writer.ed25519', trusted, 'right'))
    expect(registry.quarantined()).toBe(false)
    expect(registry.observe(record(2n, 'left', 'first'))).toBe('discarded')
    expect(registry.observe(record(3n, 'third', 'right'))).toBe('accepted')
  })
})

function record(sequence: bigint, id: string, previous?: string) {
  return {
    author: '@writer.ed25519',
    sequence,
    id,
    ...(previous === undefined ? {} : { previous }),
    receivedAtMs: 100,
    payload: new Uint8Array(),
  }
}

describe('SqliteFeedForkPersistence', () => {
  it('restores continuity, quarantines and discarded ids across reopen', () => {
    const database = new DatabaseSync(':memory:')
    const record = (sequence: bigint, id: string, previous?: string) => ({
      id, author: '@feed', sequence, receivedAtMs: 1, payload: Uint8Array.of(1), ...(previous === undefined ? {} : { previous }),
    })
    const registry = new FeedForkRegistry(new SqliteFeedForkPersistence(database))
    expect(registry.observe(record(1n, '%a'))).toBe('accepted')
    expect(registry.observe(record(2n, '%b', '%a'))).toBe('accepted')
    expect(registry.observe(record(2n, '%c', '%a'))).toBe('quarantined')
    const reopened = new FeedForkRegistry(new SqliteFeedForkPersistence(database))
    expect(reopened.snapshot()).toEqual(registry.snapshot())
    expect(reopened.quarantined('@feed')).toBe(true)
  })
})

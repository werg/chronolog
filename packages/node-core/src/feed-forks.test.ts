import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { FeedForkRegistry, JsonFeedForkPersistence } from './feed-forks.js'

const directories: string[] = []
afterEach(() => directories.splice(0).forEach((directory) => rmSync(directory, { recursive: true, force: true })))

describe('feed fork quarantine and repair', () => {
  it('persists quarantine when one author sequence has divergent identities', () => {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-feed-fork-'))
    directories.push(directory)
    const path = join(directory, 'continuity.json')
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    expect(registry.observe(record(1n, 'first'))).toBe('accepted')
    expect(registry.observe(record(2n, 'left', 'first'))).toBe('accepted')
    expect(registry.observe(record(2n, 'right', 'first'))).toBe('quarantined')
    expect(registry.quarantined('@writer.ed25519')).toBe(true)
    expect(registry.quarantineEvidence()).toMatchObject([{
      feedId: '@writer.ed25519', sequence: '2', acceptedId: 'left', conflictingId: 'right',
    }])
    expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ format: 'chronolog-feed-continuity-v1' })
    expect(new FeedForkRegistry(new JsonFeedForkPersistence(path)).quarantined()).toBe(true)
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

describe('feed continuity journal', () => {
  function temporaryPath(): string {
    const directory = mkdtempSync(join(tmpdir(), 'chronolog-feed-journal-'))
    directories.push(directory)
    return join(directory, 'continuity.json')
  }

  it('appends accepted records instead of rewriting the snapshot', () => {
    const path = temporaryPath()
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    registry.observe(record(1n, 'first'))
    const snapshotSize = existsSync(path) ? statSync(path).size : 0
    for (let sequence = 2n; sequence <= 20n; sequence += 1n) {
      registry.observe(record(sequence, `id-${sequence}`, sequence === 2n ? 'first' : `id-${sequence - 1n}`))
    }
    expect(existsSync(path) ? statSync(path).size : 0).toBe(snapshotSize)
    expect(readFileSync(`${path}.journal`, 'utf8').trim().split('\n')).toHaveLength(20)
    const reopened = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    expect(reopened.snapshot()).toEqual(registry.snapshot())
    // Reopening compacts the journal into the snapshot.
    expect(existsSync(`${path}.journal`)).toBe(false)
    expect(reopened.observe(record(2n, 'fork', 'first'))).toBe('quarantined')
  })

  it('compacts after the configured number of entries', () => {
    const path = temporaryPath()
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path, 3))
    registry.observe(record(1n, 'a'))
    registry.observe(record(2n, 'b', 'a'))
    expect(existsSync(`${path}.journal`)).toBe(true)
    registry.observe(record(3n, 'c', 'b'))
    expect(existsSync(`${path}.journal`)).toBe(false)
    expect(new FeedForkRegistry(new JsonFeedForkPersistence(path)).snapshot()).toEqual(registry.snapshot())
  })

  it('ignores a torn final append and tolerates entries already compacted', () => {
    const path = temporaryPath()
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    registry.observe(record(1n, 'a'))
    registry.observe(record(2n, 'b', 'a'))
    const journal = readFileSync(`${path}.journal`, 'utf8')
    // Crash after compaction renamed the snapshot but before the journal was removed.
    new JsonFeedForkPersistence(path).save(registry.snapshot())
    writeFileSync(`${path}.journal`, journal)
    appendFileSync(`${path}.journal`, '{"feedId":"@writer.ed25519","seq')
    expect(new FeedForkRegistry(new JsonFeedForkPersistence(path)).snapshot()).toEqual(registry.snapshot())
  })

  it('drops a torn first append so later appends stay readable', () => {
    const path = temporaryPath()
    // Crash during the very first append: no snapshot, only a fragment.
    writeFileSync(`${path}.journal`, '{"feedId":"@writer.ed25519","seq')
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    expect(registry.observe(record(1n, 'a'))).toBe('accepted')
    expect(new FeedForkRegistry(new JsonFeedForkPersistence(path)).snapshot()).toEqual(registry.snapshot())
  })

  it('fails closed on a corrupt or conflicting journal entry', () => {
    const path = temporaryPath()
    const registry = new FeedForkRegistry(new JsonFeedForkPersistence(path))
    registry.observe(record(1n, 'a'))
    new JsonFeedForkPersistence(path).save(registry.snapshot())
    writeFileSync(`${path}.journal`, 'not json\n')
    expect(() => new FeedForkRegistry(new JsonFeedForkPersistence(path))).toThrow('FEED_FORK_JOURNAL_INVALID')
    writeFileSync(`${path}.journal`, `${JSON.stringify({ feedId: '@writer.ed25519', sequence: '1', id: 'other', previous: null })}\n`)
    expect(() => new FeedForkRegistry(new JsonFeedForkPersistence(path))).toThrow('FEED_FORK_JOURNAL_CONFLICT')
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

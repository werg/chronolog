import { afterEach, describe, expect, it, vi } from 'vitest'

import { feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from './feed-codec.js'
import { pullFeedLink, type FeedLink } from './replication.js'
import { DurableFeedStore } from './store.js'
import { PortableFeedTransport } from './transport.js'
import type { ImmutableEvidence } from './types.js'

async function retainedEvidence(transport: PortableFeedTransport): Promise<ImmutableEvidence[]> {
  const result: ImmutableEvidence[] = []
  for await (const batch of transport.evidenceHistory()) result.push(...batch)
  return result
}

const peers: PortableFeedTransport[] = []
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(peers.splice(0).map(peer => peer.close())) })
async function peer() {
  const values = new Map<string, Uint8Array>()
  const bytes = { get: async (key: string) => values.get(key)?.slice() ?? null,
    put: async (key: string, value: Uint8Array) => { values.set(key, value.slice()) } }
  const store = await DurableFeedStore.open(bytes, webFeedCrypto)
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
  const identity = feedIdFromPublicKey(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)))
  const transport = new PortableFeedTransport({ store, signer: webFeedSigner(identity, keys.privateKey), crypto: webFeedCrypto })
  peers.push(transport)
  return { store, transport, bytes }
}

describe('finite retained-prefix synchronization', () => {
  it('keeps a failed network page invisible and retries its original cursor after reopen', async () => {
    const author = await peer(), reader = await peer()
    await author.transport.putEvidenceBatch(Array.from({ length: 64 }, (_, index) => Uint8Array.of(index)))
    await author.transport.putEvidenceBatch(Array.from({ length: 6 }, (_, index) => Uint8Array.of(index + 64)))
    const put = reader.bytes.put.bind(reader.bytes)
    const failure = vi.spyOn(reader.bytes, 'put').mockImplementation(async (key, value) => {
      if (key.startsWith('feed/object/') && value[0] === 32) throw new Error('interrupted page object')
      await put(key, value)
    })
    const cursor = { evidenceAfter: 0n }, notified = vi.fn()
    await expect(pullFeedLink(author.transport.asLink(), [], cursor,
      { store: reader.store, crypto: webFeedCrypto, onEvidenceStored: notified })).rejects.toThrow('interrupted page object')
    expect(cursor.evidenceAfter).toBe(0n)
    expect(reader.store.evidenceHead()).toBe(0n)
    expect(await retainedEvidence(reader.transport)).toEqual([])
    expect(notified).not.toHaveBeenCalled()
    await reader.transport.close(); failure.mockRestore()
    const repaired = await DurableFeedStore.open(reader.bytes, webFeedCrypto), heads: bigint[] = []
    try {
      await pullFeedLink(author.transport.asLink(), [], cursor,
        { store: repaired, crypto: webFeedCrypto, onEvidenceStored: () => { heads.push(repaired.evidenceHead()) } })
      expect(cursor.evidenceAfter).toBe(70n)
      expect(heads).toEqual([64n, 70n])
      expect(repaired.evidenceAfter(0n, 128).map(item => item.evidence.bytes[0])).toEqual(Array.from({ length: 70 }, (_, i) => i))
    } finally { await repaired.close() }
  })

  it('continues nonempty byte-limited evidence pages toward the captured head', async () => {
    const author = await peer(), reader = await peer()
    await author.transport.putEvidenceBatch([Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3)])
    const source = author.transport.asLink(), cursor = { evidenceAfter: 0n }, ranges: bigint[] = []
    await pullFeedLink({ ...source, readEvidence: (after) => { ranges.push(after); return source.readEvidence(after, 1) } }, [], cursor,
      { store: reader.store, crypto: webFeedCrypto })
    expect(ranges).toEqual([0n, 1n, 2n])
    expect(cursor.evidenceAfter).toBe(3n)
  })

  it('finishes captured feed and evidence prefixes while both sources keep appending', async () => {
    const author = await peer(), reader = await peer()
    let sequence = 0
    const append = async () => {
      sequence += 1
      const bytes = new TextEncoder().encode(String(sequence))
      await author.transport.publish(bytes)
      await author.transport.putEvidence(bytes)
    }
    for (let index = 0; index < 70; index += 1) await append()
    const source = author.transport.asLink(), feedLimits: number[] = [], evidenceLimits: number[] = []
    let growing = true
    const link: FeedLink = { ...source, async read(feed, after, limit) {
      feedLimits.push(limit)
      const records = await source.read(feed, after, limit)
      if (growing) await append()
      return records
    }, async readEvidence(after, limit) {
      evidenceLimits.push(limit)
      const evidence = await source.readEvidence(after, limit)
      if (growing) await append()
      return evidence
    } }
    const cursor = { evidenceAfter: 0n }, options = { store: reader.store, crypto: webFeedCrypto }
    await pullFeedLink(link, [source.identity], cursor, options)
    expect(await reader.transport.feedContiguousThrough(source.identity)).toBe(70n)
    expect(cursor.evidenceAfter).toBe(70n)
    expect(await retainedEvidence(reader.transport)).toHaveLength(70)
    expect(feedLimits).toEqual([64, 6])
    expect(evidenceLimits).toEqual([64, 6])
    expect(sequence).toBe(74)
    growing = false
    await pullFeedLink(link, [source.identity], cursor, options)
    expect(await reader.transport.feedContiguousThrough(source.identity)).toBe(74n)
    expect(cursor.evidenceAfter).toBe(74n)
    expect(await retainedEvidence(reader.transport)).toHaveLength(74)
  })

  it('rejects a short advertised feed prefix while keeping its acknowledged records for repair', async () => {
    const author = await peer(), reader = await peer()
    await author.transport.publish(Uint8Array.of(1)); await author.transport.publish(Uint8Array.of(2))
    const source = author.transport.asLink(), cursor = { evidenceAfter: 0n }
    await expect(pullFeedLink({ ...source, read: (feed, after) => source.read(feed, after, 1) }, [source.identity], cursor,
      { store: reader.store, crypto: webFeedCrypto })).rejects.toThrow('FEED_RANGE_TARGET_UNAVAILABLE')
    expect(await reader.transport.feedContiguousThrough(source.identity)).toBe(1n)
    await pullFeedLink(source, [source.identity], cursor, { store: reader.store, crypto: webFeedCrypto })
    expect(await reader.transport.feedContiguousThrough(source.identity)).toBe(2n)
  })

  it('rejects an unavailable evidence target and resumes from the durable evidence cursor', async () => {
    const author = await peer(), reader = await peer()
    await author.transport.putEvidence(Uint8Array.of(1)); await author.transport.putEvidence(Uint8Array.of(2))
    const source = author.transport.asLink(), cursor = { evidenceAfter: 0n }
    const options = { store: reader.store, crypto: webFeedCrypto }
    await expect(pullFeedLink({ ...source, readEvidence: after => after === 0n ? source.readEvidence(after, 1) : Promise.resolve([]) }, [], cursor, options))
      .rejects.toThrow('FEED_RANGE_TARGET_UNAVAILABLE')
    expect(cursor.evidenceAfter).toBe(1n)
    await expect(pullFeedLink({ ...source, readEvidence: async () => [] }, [], cursor, options))
      .rejects.toThrow('FEED_RANGE_TARGET_UNAVAILABLE')
    expect(cursor.evidenceAfter).toBe(1n)
    await pullFeedLink(source, [], cursor, options)
    expect(cursor.evidenceAfter).toBe(2n)
    expect(await retainedEvidence(reader.transport)).toHaveLength(2)
    await expect(pullFeedLink({ ...source, evidenceHead: async () => 1n }, [], cursor, options))
      .rejects.toThrow('FEED_EVIDENCE_HEAD_REGRESSED')
  })

  it.each([-1n, BigInt(Number.MAX_SAFE_INTEGER) + 1n, 1 as unknown as bigint])('rejects invalid availability head %s', async invalid => {
    const author = await peer(), reader = await peer(), source = author.transport.asLink()
    const read = vi.fn(source.readEvidence.bind(source))
    await expect(pullFeedLink({ ...source, evidenceHead: async () => invalid, readEvidence: read }, [], { evidenceAfter: 0n },
      { store: reader.store, crypto: webFeedCrypto })).rejects.toThrow('FEED_POSITION_INVALID')
    expect(read).not.toHaveBeenCalled()
    await expect(pullFeedLink({ ...source, head: async () => invalid }, [source.identity], { evidenceAfter: 0n },
      { store: reader.store, crypto: webFeedCrypto })).rejects.toThrow('FEED_POSITION_INVALID')
  })

  it('cancels a remote availability wait without waiting for an unresponsive peer', async () => {
    const author = await peer(), reader = await peer(), controller = new AbortController()
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    const catchingUp = pullFeedLink({ ...author.transport.asLink(), evidenceHead: async () => {
      entered(); return new Promise<bigint>(() => {})
    } }, [], { evidenceAfter: 0n }, { store: reader.store, crypto: webFeedCrypto }, controller.signal)
    const rejected = expect(catchingUp).rejects.toThrow('stop catch-up')
    await started; controller.abort(new Error('stop catch-up')); await rejected
  })

  it('awaits an in-flight durable evidence append before completing cancellation', async () => {
    const author = await peer(), reader = await peer(), controller = new AbortController()
    await author.transport.putEvidence(Uint8Array.of(7))
    let entered!: () => void, release!: () => void, finished = false
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const putEvidenceBatch = reader.store.putEvidenceBatch.bind(reader.store)
    vi.spyOn(reader.store, 'putEvidenceBatch').mockImplementation(async bytes => { entered(); await gate; return putEvidenceBatch(bytes) })
    const cursor = { evidenceAfter: 0n }
    const catchingUp = pullFeedLink(author.transport.asLink(), [], cursor, { store: reader.store, crypto: webFeedCrypto }, controller.signal)
      .finally(() => { finished = true })
    const rejected = expect(catchingUp).rejects.toThrow('stop after commit')
    await started; controller.abort(new Error('stop after commit'))
    await Promise.resolve()
    expect(finished).toBe(false)
    expect(cursor.evidenceAfter).toBe(0n)
    release(); await rejected
    expect(cursor.evidenceAfter).toBe(1n)
    expect(await retainedEvidence(reader.transport)).toHaveLength(1)
  })
})

import { mkdtemp, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { createFeedRecord, decodeFeedRecord, FeedStore, type FeedKeys } from './feed-store.js'
import { FeedTransport } from './feed-transport.js'
import type { TransportRecord } from './types.js'

const require = createRequire(import.meta.url)
const ssbKeys = require('ssb-keys') as { generate(): FeedKeys }

const directories: string[] = []
const transports: FeedTransport[] = []
afterEach(async () => {
  await Promise.all(transports.splice(0).map((transport) => transport.close()))
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })))
})

async function directory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), 'chronolog-feed-'))
  directories.push(path)
  return path
}

async function open(path: string, options: Partial<Parameters<typeof FeedTransport.open>[0]> = {}): Promise<FeedTransport> {
  const transport = await FeedTransport.open({ path: join(path, 'ssb'), ...options })
  transports.push(transport)
  return transport
}

async function take(iterable: AsyncIterable<TransportRecord>, count: number): Promise<TransportRecord[]> {
  const records: TransportRecord[] = []
  for await (const record of iterable) {
    records.push(record)
    if (records.length === count) break
  }
  return records
}

async function eventually(check: () => Promise<boolean>, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!await check()) {
    if (Date.now() > deadline) throw new Error('condition not reached')
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

describe('signed feed records', () => {
  it('round-trips, chains and rejects tampering', () => {
    const keys = ssbKeys.generate()
    const first = createFeedRecord(keys, 1n, null, 5n, Uint8Array.of(1, 2, 3))
    const second = createFeedRecord(keys, 2n, first.id, 6n, Uint8Array.of(4))
    expect(decodeFeedRecord(first.raw)).toEqual(first)
    expect(decodeFeedRecord(second.raw).previous).toBe(first.id)
    const tampered = Uint8Array.from(second.raw)
    tampered[tampered.length - 70] = tampered[tampered.length - 70]! ^ 1
    expect(() => decodeFeedRecord(tampered)).toThrow()
    expect(() => decodeFeedRecord(second.raw, 10)).toThrow('FEED_RECORD_TOO_LARGE')
  })

  it('appends only the next record and keeps a conflicting record as fork evidence', async () => {
    const path = join(await directory(), 'feeds.sqlite')
    const store = new FeedStore(path)
    try {
      const keys = ssbKeys.generate()
      const first = createFeedRecord(keys, 1n, null, 1n, Uint8Array.of(1))
      const skip = createFeedRecord(keys, 3n, first.id, 3n, Uint8Array.of(3))
      const conflict = createFeedRecord(keys, 1n, null, 1n, Uint8Array.of(9))
      expect(store.append(first).kind).toBe('appended')
      expect(store.append(first).kind).toBe('duplicate')
      expect(store.append(skip)).toEqual({ kind: 'out_of_order', head: 1n })
      expect(store.append(conflict).kind).toBe('fork')
      expect(store.forkedAuthors()).toEqual([keys.id])
      expect(store.heads()).toEqual(new Map([[keys.id, 1n]]))
    } finally {
      store.close()
    }
  })
})

describe('FeedTransport', () => {
  it('durably appends and reads exact payloads across reopen, without a size cap at SSB scale', async () => {
    const path = await directory()
    let transport = await open(path)
    const large = Uint8Array.from({ length: 1_000_000 }, (_value, index) => index & 0xff)
    const first = await transport.publish(Uint8Array.of(1, 2, 3), { timestampMs: 7 })
    const second = await transport.publish(large)
    expect(second.previous).toBe(first.id)
    await transport.close()
    transports.splice(transports.indexOf(transport), 1)

    transport = await open(path)
    expect((await transport.get(second.id))?.payload).toEqual(large)
    expect((await transport.history()).map((record) => record.sequence)).toEqual([1n, 2n])
    expect(await transport.feedContiguousThrough(transport.identity)).toBe(2n)
    expect((await transport.status()).records).toBe(2)
  })

  it('refuses a second concurrent owner of the same storage', async () => {
    const path = await directory()
    await open(path)
    await expect(FeedTransport.open({ path: join(path, 'ssb') })).rejects.toThrow('FEED_STORE_IN_USE')
  })

  it('streams existing and live records once, and stops on abort', async () => {
    const transport = await open(await directory())
    await transport.publish(Uint8Array.of(1))
    const controller = new AbortController()
    const seen = take(transport.subscribe(controller.signal), 3)
    await transport.publish(Uint8Array.of(2))
    await transport.publish(Uint8Array.of(3))
    expect((await seen).map((record) => record.payload[0])).toEqual([1, 2, 3])
    const aborted = take(transport.subscribe(controller.signal), 10)
    controller.abort()
    expect((await aborted).length).toBeLessThanOrEqual(3)
  })

  it('replicates wanted feeds over an authenticated connection, including through a relay', async () => {
    const [aPath, bPath, cPath] = [await directory(), await directory(), await directory()]
    const b = await open(bPath, { network: { listen: { port: 0 }, reconnect: false } })
    const bAddress = b.address()!
    const a = await open(aPath, { network: { listen: { port: 0 }, peers: [{ address: bAddress, feedId: b.identity }], reconnect: false } })
    const c = await open(cPath, { network: { peers: [{ address: bAddress, feedId: b.identity }], reconnect: false } })
    // c never connects to a, so a's feed reaches c only through b.
    b.requestFeed(a.identity)
    c.requestFeed(a.identity)
    const record = await a.publish(Uint8Array.from({ length: 200_000 }, (_value, index) => index % 251))
    await b.publish(Uint8Array.of(42))
    await eventually(async () => (await c.get(record.id)) !== undefined)
    expect((await c.get(record.id))?.payload).toEqual((await a.get(record.id))?.payload)
    await eventually(async () => await a.feedContiguousThrough(b.identity) === 1n)
    const status = await c.status()
    expect(status.peers).toEqual([b.identity])
    expect(status.feedsWithGaps).toBe(0)
  })

  it('is healthy again once a restarted peer reconnects and replicates', async () => {
    const [aPath, bPath] = [await directory(), await directory()]
    let b = await open(bPath, { network: { listen: { port: 0 }, reconnect: false } })
    const bAddress = b.address()!
    const port = Number(/:(\d+)~/u.exec(bAddress)![1])
    const a = await open(aPath, {
      network: { peers: [{ address: bAddress, feedId: b.identity }], reconnect: { initialDelayMs: 50, maximumDelayMs: 100, connectTimeoutMs: 2_000 } },
    })
    const first = await b.publish(Uint8Array.of(1))
    await eventually(async () => (await a.get(first.id)) !== undefined)

    // The peer goes away mid-stream (a restart), then comes back on the same address.
    await b.close()
    transports.splice(transports.indexOf(b), 1)
    await eventually(async () => (await a.status()).peers.length === 0, 30_000)
    b = await open(bPath, { network: { listen: { port }, reconnect: false } })
    const second = await b.publish(Uint8Array.of(2))
    await eventually(async () => (await a.get(second.id)) !== undefined, 30_000)
    expect((await a.status()).lastCatchUpError).toBeUndefined()
  }, 60_000)
})

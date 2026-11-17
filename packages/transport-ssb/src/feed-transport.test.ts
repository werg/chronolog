import { mkdtemp, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { afterEach, describe, expect, it, vi } from 'vitest'

import { createFeedRecord, decodeFeedRecord, FeedStore, type FeedKeys } from './feed-store.js'
import { FeedTransport } from './feed-transport.js'
import type { TransportRecord } from './types.js'

const require = createRequire(import.meta.url)
const ssbKeys = require('ssb-keys') as { generate(): FeedKeys }

const directories: string[] = []
const transports: FeedTransport[] = []
afterEach(async () => {
  vi.restoreAllMocks()
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

function rejectEvidenceByte(path: string): void {
  const database = new DatabaseSync(path)
  try {
    database.exec("CREATE TRIGGER reject_evidence BEFORE INSERT ON evidence WHEN NEW.raw = X'ff' BEGIN SELECT RAISE(ABORT, 'EVIDENCE_WRITE_FAILED'); END")
  } finally { database.close() }
}

function allowEvidenceByte(path: string): void {
  const database = new DatabaseSync(path)
  try { database.exec('DROP TRIGGER reject_evidence') } finally { database.close() }
}

describe('signed feed records', () => {
  it('retains exact immutable evidence across reopen without requiring an author feed', async () => {
    const path = join(await directory(), 'evidence.sqlite')
    let store = new FeedStore(path)
    const first = store.putEvidence(Uint8Array.of(4, 5, 6))
    store.close()
    store = new FeedStore(path)
    try {
      expect(store.putEvidence(first.evidence.bytes)).toMatchObject({ kind: 'duplicate', index: 1n, evidence: first.evidence })
      expect(store.evidenceHead()).toBe(1n)
      expect(store.putEvidence(Uint8Array.of(7, 8, 9)).index).toBe(2n)
      expect(store.evidenceHead()).toBe(2n)
      expect(store.evidenceAfter(0n, 1)).toEqual([{ index: 1n, evidence: first.evidence }])
      expect(store.count()).toBe(0)
    } finally { store.close() }
  })

  it('deduplicates within a native evidence page and rolls back every insert when a later one fails', async () => {
    const path = join(await directory(), 'evidence.sqlite')
    let store = new FeedStore(path)
    const first = Uint8Array.of(1), second = Uint8Array.of(2)
    const initial = store.putEvidenceBatch([first, first, second])
    expect(initial.map(item => [item.kind, item.index])).toEqual([['appended', 1n], ['duplicate', 1n], ['appended', 2n]])
    expect(initial[0]!.evidence).toEqual(initial[1]!.evidence)
    expect(store.evidenceHead()).toBe(2n)
    store.close()
    rejectEvidenceByte(path)
    store = new FeedStore(path)
    const failedPage = [Uint8Array.of(3), Uint8Array.of(255)]
    try {
      expect(() => store.putEvidenceBatch(failedPage)).toThrow('EVIDENCE_WRITE_FAILED')
      expect(store.evidenceHead()).toBe(2n)
      expect(store.evidenceAfter(0n, 64).map(item => item.evidence.bytes)).toEqual([first, second])
    } finally { store.close() }
    allowEvidenceByte(path)
    store = new FeedStore(path)
    try {
      expect(store.putEvidenceBatch(failedPage).map(item => [item.kind, item.index]))
        .toEqual([['appended', 3n], ['appended', 4n]])
      expect(store.putEvidenceBatch(failedPage).map(item => item.kind)).toEqual(['duplicate', 'duplicate'])
      expect(store.evidenceAfter(0n, 64).map(item => item.evidence.bytes)).toEqual([first, second, ...failedPage])
      expect(store.count()).toBe(0)
    } finally { store.close() }
  })

  it('fences native reads and writes after an uncertain evidence rollback until reopen', async () => {
    const path = join(await directory(), 'evidence.sqlite')
    let store = new FeedStore(path)
    const original = Uint8Array.of(1)
    store.putEvidence(original)
    store.close()
    rejectEvidenceByte(path)
    store = new FeedStore(path)
    // Preserve the original method and call it with the intercepted database.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const exec = DatabaseSync.prototype.exec
    const rollback = vi.spyOn(DatabaseSync.prototype, 'exec').mockImplementation(function (this: DatabaseSync, sql) {
      if (sql === 'ROLLBACK') throw new Error('ROLLBACK_REPLY_LOST')
      return exec.call(this, sql)
    })
    const failedPage = [Uint8Array.of(2), Uint8Array.of(255)]
    try {
      expect(() => store.putEvidenceBatch(failedPage)).toThrow('EVIDENCE_WRITE_FAILED')
      expect(rollback).toHaveBeenCalledWith('ROLLBACK')
      const keys = ssbKeys.generate(), record = createFeedRecord(keys, 1n, null, 1n, Uint8Array.of(4))
      const access: Record<string, () => unknown> = {
        head: () => store.head(keys.id), append: () => store.append(record), get: () => store.get(record.id),
        getPayload: () => store.getPayload('0'.repeat(64)), putPayload: () => store.putPayload(Uint8Array.of(4)),
        after: () => store.after(0n, 1), forksAfter: () => store.forksAfter(0n, 1),
        feedAfter: () => store.feedAfter(keys.id, 0n, 1), heads: () => store.heads(), count: () => store.count(),
        maxLocalIndex: () => store.maxLocalIndex(), forkedAuthors: () => store.forkedAuthors(),
        evidenceHead: () => store.evidenceHead(), evidenceAfter: () => store.evidenceAfter(0n, 1),
        putEvidence: () => store.putEvidence(Uint8Array.of(4)), putEvidenceBatch: () => store.putEvidenceBatch([Uint8Array.of(4)]),
      }
      for (const [name, operation] of Object.entries(access)) expect(operation, name).toThrow('FEED_STORE_REOPEN_REQUIRED')
    } finally { rollback.mockRestore(); store.close() }
    allowEvidenceByte(path)
    store = new FeedStore(path)
    try {
      expect(store.evidenceAfter(0n, 64).map(item => item.evidence.bytes)).toEqual([original])
      expect(store.putEvidenceBatch(failedPage).map(item => item.index)).toEqual([2n, 3n])
      expect(store.evidenceAfter(0n, 64).map(item => item.evidence.bytes)).toEqual([original, ...failedPage])
    } finally { store.close() }
  })

  it('fences a lost commit acknowledgment and recovers the complete native evidence page on reopen', async () => {
    const path = join(await directory(), 'evidence.sqlite')
    let store = new FeedStore(path)
    const original = Uint8Array.of(1), page = [Uint8Array.of(2), Uint8Array.of(3)]
    store.putEvidence(original)
    // Preserve the original method and call it with the intercepted database.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const exec = DatabaseSync.prototype.exec
    const committed = vi.spyOn(DatabaseSync.prototype, 'exec').mockImplementation(function (this: DatabaseSync, sql) {
      exec.call(this, sql)
      if (sql === 'COMMIT') throw new Error('COMMIT_REPLY_LOST')
    })
    try {
      expect(() => store.putEvidenceBatch(page)).toThrow('COMMIT_REPLY_LOST')
      expect(() => store.evidenceHead()).toThrow('FEED_STORE_REOPEN_REQUIRED')
      expect(() => store.evidenceAfter(0n, 64)).toThrow('FEED_STORE_REOPEN_REQUIRED')
      expect(() => store.putEvidenceBatch(page)).toThrow('FEED_STORE_REOPEN_REQUIRED')
    } finally { committed.mockRestore(); store.close() }
    store = new FeedStore(path)
    try {
      expect(store.evidenceAfter(0n, 64).map(item => item.evidence.bytes)).toEqual([original, ...page])
      expect(store.putEvidenceBatch(page).map(item => [item.kind, item.index]))
        .toEqual([['duplicate', 2n], ['duplicate', 3n]])
      expect(store.evidenceHead()).toBe(3n)
    } finally { store.close() }
  })

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
  it('replicates exact evidence as bounded muxrpc array pages without authoring feed records', async () => {
    const sender = await open(await directory(), { network: { listen: { port: 0 }, reconnect: false } })
    const proofs = Array.from({ length: 70 }, (_, index) => Uint8Array.of(index, 255 - index))
    await sender.putEvidenceBatch(proofs.slice(0, 64))
    await sender.putEvidenceBatch(proofs.slice(64))
    const received: Uint8Array[][] = []
    // Each incoming call must execute on its actual transport instance.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const retain = FeedTransport.prototype.putEvidenceBatch
    const delivery = vi.spyOn(FeedTransport.prototype, 'putEvidenceBatch').mockImplementation(async function (this: FeedTransport, batch) {
      const result = await retain.call(this, batch)
      if (this !== sender) received.push(batch.map(bytes => bytes.slice()))
      return result
    })
    try {
      const receiver = await open(await directory(), {
        network: { peers: [{ address: sender.address()!, feedId: sender.identity }], reconnect: false },
      })
      await eventually(async () => received.flat().length === proofs.length)
      expect(received.map(batch => batch.length)).toEqual([64, 6])
      expect(received.flat()).toEqual(proofs)
      const retained: Uint8Array[] = []
      for await (const batch of receiver.evidenceHistory()) retained.push(...batch.map(item => item.bytes))
      expect(retained).toEqual(proofs)
      expect((await receiver.status()).records).toBe(0)
      expect((await receiver.status()).lastCatchUpError).toBeUndefined()
    } finally { delivery.mockRestore() }
  }, 20_000)

  it('ends paused finite and live evidence iterators when the transport closes', async () => {
    const transport = await open(await directory(), { network: { reconnect: false } })
    const proofs = Array.from({ length: 70 }, (_, index) => Uint8Array.of(index))
    await transport.putEvidenceBatch(proofs.slice(0, 64))
    await transport.putEvidenceBatch(proofs.slice(64))
    const finite = transport.evidenceHistory()[Symbol.asyncIterator]()
    const paused = transport.subscribeEvidenceBatches()[Symbol.asyncIterator]()
    const waiting = transport.subscribeEvidenceBatches()[Symbol.asyncIterator]()
    expect((await finite.next()).value).toHaveLength(64)
    expect((await paused.next()).value).toHaveLength(64)
    expect((await waiting.next()).value).toHaveLength(64)
    expect((await waiting.next()).value).toHaveLength(6)
    const pending = waiting.next()
    await transport.close()
    await expect(finite.next()).resolves.toEqual({ done: true, value: undefined })
    await expect(paused.next()).resolves.toEqual({ done: true, value: undefined })
    await expect(pending).resolves.toEqual({ done: true, value: undefined })
  })

  it('replays durable conflicts through history and new subscriptions after restart', async () => {
    const path = await directory(), keys = ssbKeys.generate()
    let transport = await open(path, { keys: { ...keys }, network: { reconnect: false } })
    const first = await transport.publish(Uint8Array.of(1), { timestampMs: 1 })
    await transport.close()
    transports.splice(transports.indexOf(transport), 1)
    const store = new FeedStore(join(path, 'ssb', 'feeds.sqlite'))
    const fork = createFeedRecord(keys, 1n, null, 1n, Uint8Array.of(2))
    store.append(fork, 10)
    store.append(fork, 20)
    store.close()
    transport = await open(path, { keys: { ...keys }, network: { reconnect: false } })
    expect((await transport.history()).map((record) => record.id)).toEqual([first.id, fork.id])
    expect((await take(transport.subscribe(AbortSignal.timeout(1_000)), 2)).map((record) => record.id)).toEqual([first.id, fork.id])
    expect(await transport.feedContiguousThrough(keys.id)).toBe(1n)
    expect((await transport.status()).records).toBe(1)
  })

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

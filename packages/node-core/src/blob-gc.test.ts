import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createPayloadManifest, encodeEnvelope, generateEd25519KeyPair } from '@chronolog/protocol'
import type { TransportRecord } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import {
  BlobGcRefusal,
  listQuarantinedBlobs,
  markReachableBlobs,
  planBlobCollection,
  purgeQuarantinedBlobs,
  quarantineBlobs,
  readBlobGcJournal,
  recoverBlobGcJournal,
  restoreQuarantinedBlobs,
  scanBlobStore,
  verifyReferencedBlobs,
  type BlobGcPaths,
  type BlobMark,
} from './blob-gc.js'
import { FileBlobStore } from './blobs.js'
import type { FeedForkSnapshot } from './feed-forks.js'
import { encodeSignedEnvelope } from './wire.js'

const directories: string[] = []
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }) })

const ROUTE = new Uint8Array(32).fill(7)
const DAY = 24 * 60 * 60 * 1000
const NOW = Date.UTC(2026, 10, 12)

interface Fixture {
  readonly paths: BlobGcPaths
  readonly store: FileBlobStore
}

function fixture(): Fixture {
  const dataDirectory = mkdtempSync(join(tmpdir(), 'chronolog-blob-gc-'))
  directories.push(dataDirectory)
  const blobRoot = join(dataDirectory, 'blobs')
  return { paths: { dataDirectory, blobRoot }, store: new FileBlobStore(blobRoot) }
}

async function manifestEnvelope(store: FileBlobStore, bytes: number, type: 'candidate' | 'heartbeat' = 'candidate'): Promise<Uint8Array> {
  const signer = await generateEd25519KeyPair()
  return encodeSignedEnvelope(ROUTE, type, new Uint8Array(bytes).map((_value, index) => (index * 31 + bytes) & 0xff), signer, undefined, {
    store,
    maxInlineBytes: 8,
    chunkBytes: 32,
  })
}

async function inlineEnvelope(): Promise<Uint8Array> {
  const signer = await generateEd25519KeyPair()
  return encodeSignedEnvelope(ROUTE, 'heartbeat', Uint8Array.of(1, 2, 3), signer)
}

function chain(author: string, payloads: readonly Uint8Array[]): TransportRecord[] {
  const records: TransportRecord[] = []
  payloads.forEach((payload, index) => {
    records.push({
      id: `%${author}-${index + 1}`,
      author,
      sequence: BigInt(index + 1),
      ...(index === 0 ? {} : { previous: `%${author}-${index}` }),
      receivedAtMs: NOW,
      payload,
    })
  })
  return records
}

function clockOf(records: readonly TransportRecord[]): Map<string, bigint> {
  const clock = new Map<string, bigint>()
  for (const record of records) if (record.sequence > (clock.get(record.author) ?? 0n)) clock.set(record.author, record.sequence)
  return clock
}

function age(paths: BlobGcPaths, relativePath: string, ageMs: number): void {
  const when = new Date(NOW - ageMs)
  utimesSync(join(paths.blobRoot, relativePath), when, when)
}

async function orphanChunk(store: FileBlobStore, seed: number): Promise<string> {
  const bytes = Uint8Array.of(seed, seed, seed)
  const manifest = await createPayloadManifest([bytes])
  await store.put(manifest.chunks[0]!.digest, bytes)
  return Buffer.from(manifest.chunks[0]!.digest).toString('hex')
}

function chunkPath(digest: string): string { return `${digest.slice(0, 2)}/${digest.slice(2)}` }

function ageAll(paths: BlobGcPaths, ageMs: number): void {
  for (const file of scanBlobStore(paths.blobRoot).files) age(paths, file.path, ageMs)
}

describe('blob mark', () => {
  it('references every chunk named by any record type, including manifest-backed heartbeats', async () => {
    const { paths, store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 100), await inlineEnvelope(), await manifestEnvelope(store, 70, 'heartbeat')])
    const mark = markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })
    expect(mark.manifestRecords).toBe(2)
    expect(mark.reachable.size).toBeGreaterThan(2)
    expect([...mark.reachable.keys()].sort()).toEqual(scanBlobStore(paths.blobRoot).files.map((file) => file.digest).sort())
    expect(mark.feedHeads).toEqual([{ feedId: '@a', sequence: '3', id: '%@a-3' }])
    expect(mark.evidenceDigest).toMatch(/^[0-9a-f]{64}$/u)
    expect(markReachableBlobs({ records: [...records].reverse(), contiguousThrough: clockOf(records), continuity: null }).evidenceDigest)
      .toBe(mark.evidenceDigest)
  })

  it('fails closed on any doubt about the local history', async () => {
    const { store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 40), await inlineEnvelope(), await inlineEnvelope()])
    const clock = clockOf(records)
    const refused = (input: Parameters<typeof markReachableBlobs>[0]) => {
      try { markReachableBlobs(input); return 'accepted' } catch (error) { return error instanceof BlobGcRefusal ? error.code : String(error) }
    }
    expect(refused({ records: [records[0]!, records[2]!], contiguousThrough: clock, continuity: null })).toBe('BLOB_GC_FEED_NOT_CONTIGUOUS')
    expect(refused({ records: [records[0]!, { ...records[1]!, previous: '%other' }, records[2]!], contiguousThrough: clock, continuity: null })).toBe('BLOB_GC_FEED_CHAIN_BROKEN')
    expect(refused({ records, contiguousThrough: new Map([['@a', 2n]]), continuity: null })).toBe('BLOB_GC_CLOCK_MISMATCH')
    expect(refused({ records, contiguousThrough: new Map([...clock, ['@b', 1n]]), continuity: null })).toBe('BLOB_GC_CLOCK_MISMATCH')
    expect(refused({ records: [{ ...records[0]!, payload: Uint8Array.of(1, 2) }, records[1]!, records[2]!], contiguousThrough: clock, continuity: null })).toBe('BLOB_GC_ENVELOPE_UNDECODABLE')
    const quarantined: FeedForkSnapshot = { format: 'chronolog-feed-continuity-v1', feeds: [], quarantines: [{ feedId: '@a', sequence: '2', acceptedId: 'x', conflictingId: 'y', detectedAt: '' }], discardedRecordIds: [] }
    expect(refused({ records, contiguousThrough: clock, continuity: quarantined })).toBe('BLOB_GC_FEED_QUARANTINED')
    // The node once saw sequence 4, but the log ends at 3: the log was rolled back.
    const ahead: FeedForkSnapshot = {
      format: 'chronolog-feed-continuity-v1',
      feeds: [{ feedId: '@a', records: [...records.map((record) => ({ sequence: record.sequence.toString(), id: record.id, previous: record.previous ?? null })), { sequence: '4', id: '%@a-4', previous: '%@a-3' }] }],
      quarantines: [],
      discardedRecordIds: [],
    }
    expect(refused({ records, contiguousThrough: clock, continuity: ahead })).toBe('BLOB_GC_LOG_BEHIND_CONTINUITY')
  })

  it('refuses a digest declared with two sizes', async () => {
    const { store } = fixture()
    const bytes = new Uint8Array(40).fill(9)
    const manifest = await createPayloadManifest([bytes])
    const conflicting = { ...manifest, totalSize: 41n, chunks: [{ ...manifest.chunks[0]!, size: 41n }] }
    const envelope = (value: typeof manifest) => encodeEnvelope({
      groupRoute: ROUTE, messageType: 'candidate', encryptionEpoch: null, payloadDigest: new Uint8Array(32), payload: { type: 'manifest', manifest: value },
    })
    await store.put(manifest.chunks[0]!.digest, bytes)
    const records = chain('@a', [envelope(manifest), envelope(conflicting)])
    expect(() => markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })).toThrow('BLOB_GC_CHUNK_SIZE_CONFLICT')
  })
})

describe('blob collection plan', () => {
  it('only offers old unreferenced canonical files and reports missing, mismatched and unknown entries', async () => {
    const { paths, store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 100)])
    const mark = markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })
    const oldOrphan = await orphanChunk(store, 1)
    const youngOrphan = await orphanChunk(store, 2)
    mkdirSync(join(paths.blobRoot, 'zz'), { recursive: true })
    writeFileSync(join(paths.blobRoot, 'notes.txt'), 'operator file')
    writeFileSync(join(paths.blobRoot, chunkPath(oldOrphan) + '.123.tmp'), 'partial')
    symlinkSync(join(paths.blobRoot, chunkPath(oldOrphan)), join(paths.blobRoot, oldOrphan.slice(0, 2), 'f'.repeat(62)))
    ageAll(paths, 30 * DAY)
    age(paths, chunkPath(youngOrphan), 60 * 1000)
    const plan = planBlobCollection(mark, scanBlobStore(paths.blobRoot), { nowMs: NOW, graceMs: 7 * DAY })
    expect(plan.candidates.map((file) => file.path).sort()).toEqual([chunkPath(oldOrphan), `${chunkPath(oldOrphan)}.123.tmp`].sort())
    expect(plan.retainedUnreferenced.map((file) => file.path)).toEqual([chunkPath(youngOrphan)])
    expect(plan.referencedPresent).toBe(mark.reachable.size)
    expect(plan.referencedMissing).toEqual([])
    expect(plan.unknown).toEqual(expect.arrayContaining(['notes.txt', 'zz', `${oldOrphan.slice(0, 2)}/${'f'.repeat(62)}`]))
    // A referenced chunk is never a candidate however old it is.
    for (const digest of mark.reachable.keys()) expect(plan.candidates.some((file) => file.digest === digest && file.kind === 'chunk')).toBe(false)
  })

  it('reports a partially fetched blob without failing and lets operator holds lower the floor', async () => {
    const { paths, store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 100)])
    const mark = markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })
    const [missing] = [...mark.reachable.keys()]
    rmSync(join(paths.blobRoot, chunkPath(missing!)))
    const orphan = await orphanChunk(store, 3)
    ageAll(paths, 30 * DAY)
    const scan = scanBlobStore(paths.blobRoot)
    expect(planBlobCollection(mark, scan, { nowMs: NOW, graceMs: DAY }).referencedMissing).toEqual([missing])
    const held = planBlobCollection(mark, scan, { nowMs: NOW, graceMs: DAY, keepModifiedSinceMs: NOW - 60 * DAY })
    expect(held.candidates).toEqual([])
    expect(held.retainedUnreferenced.map((file) => file.digest)).toEqual([orphan])
    // A hold can never raise the floor above now - grace.
    expect(planBlobCollection(mark, scan, { nowMs: NOW, graceMs: 60 * DAY, keepModifiedSinceMs: NOW }).candidates).toEqual([])
  })

  it('detects corrupt and size-mismatched referenced chunks without offering them', async () => {
    const { paths, store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 64)])
    const mark = markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })
    const [first, second] = [...mark.reachable.keys()]
    writeFileSync(join(paths.blobRoot, chunkPath(first!)), new Uint8Array(32))
    writeFileSync(join(paths.blobRoot, chunkPath(second!)), new Uint8Array(5))
    const scan = scanBlobStore(paths.blobRoot)
    expect(await verifyReferencedBlobs(paths.blobRoot, mark, scan)).toEqual([chunkPath(first!), chunkPath(second!)].sort())
    const plan = planBlobCollection(mark, scan, { nowMs: NOW + DAY * 365, graceMs: 0 })
    expect(plan.referencedSizeMismatch).toEqual([chunkPath(second!)])
    expect(plan.candidates).toEqual([])
  })
})

describe('blob quarantine, restore and purge', () => {
  async function prepared(): Promise<{ paths: BlobGcPaths; store: FileBlobStore; mark: BlobMark; orphans: string[]; records: TransportRecord[] }> {
    const { paths, store } = fixture()
    const records = chain('@a', [await manifestEnvelope(store, 50)])
    const mark = markReachableBlobs({ records, contiguousThrough: clockOf(records), continuity: null })
    const orphans = [await orphanChunk(store, 4), await orphanChunk(store, 5)]
    ageAll(paths, 30 * DAY)
    return { paths, store, mark, orphans, records }
  }

  it('quarantines, restores with digest verification, and journals every step', async () => {
    const { paths, store, mark, orphans } = await prepared()
    const plan = planBlobCollection(mark, scanBlobStore(paths.blobRoot), { nowMs: NOW, graceMs: DAY })
    const result = quarantineBlobs(paths, plan, NOW)
    expect(result.quarantined).toBe(2)
    for (const digest of orphans) expect(await store.get(Buffer.from(digest, 'hex'))).toBeNull()
    for (const digest of mark.reachable.keys()) expect(await store.get(Buffer.from(digest, 'hex'))).not.toBeNull()
    expect(listQuarantinedBlobs(paths)).toHaveLength(2)

    const [corrupted, intact] = listQuarantinedBlobs(paths)
    writeFileSync(join(paths.dataDirectory, corrupted!.quarantinePath), 'tampered')
    const restored = await restoreQuarantinedBlobs(paths, NOW + 1)
    expect(restored.restored).toBe(1)
    expect(restored.skipped).toEqual([{ path: corrupted!.blobPath, reason: 'digest-mismatch' }])
    expect(await store.get(Buffer.from(intact!.digest, 'hex'))).not.toBeNull()
    expect(listQuarantinedBlobs(paths).map((item) => item.digest)).toEqual([corrupted!.digest])

    const phases = readBlobGcJournal(paths).map((entry) => `${entry.type}:${'op' in entry ? entry.op : 'stage' in entry ? entry.stage : ''}:${entry.phase}`)
    expect(phases).toEqual([
      'run:quarantine:start',
      'move:quarantine:intent', 'move:quarantine:done',
      'move:quarantine:intent', 'move:quarantine:done',
      'run:quarantine:end',
      'run:restore:start',
      'move:restore:intent', 'move:restore:done',
      'run:restore:end',
    ])
  })

  it('skips files that changed between plan and move', async () => {
    const { paths, mark, orphans } = await prepared()
    const plan = planBlobCollection(mark, scanBlobStore(paths.blobRoot), { nowMs: NOW, graceMs: DAY })
    age(paths, chunkPath(orphans[0]!), DAY * 10)
    rmSync(join(paths.blobRoot, chunkPath(orphans[1]!)))
    const result = quarantineBlobs(paths, plan, NOW)
    expect(result.quarantined).toBe(0)
    expect(result.skipped.map((item) => item.reason).sort()).toEqual(['changed-since-scan', 'missing'])
  })

  it('purges only aged, still-unreferenced files and restores anything that became referenced', async () => {
    const { paths, store, mark, orphans, records } = await prepared()
    quarantineBlobs(paths, planBlobCollection(mark, scanBlobStore(paths.blobRoot), { nowMs: NOW, graceMs: DAY }), NOW)

    const early = await purgeQuarantinedBlobs(paths, mark, { nowMs: NOW + DAY, minimumQuarantineMs: 7 * DAY })
    expect(early).toMatchObject({ purged: 0, retained: 2, restoredReferenced: 0 })

    // A late record now references the first orphan.
    const lateManifest = await createPayloadManifest([Uint8Array.of(4, 4, 4)])
    const late = encodeEnvelope({ groupRoute: ROUTE, messageType: 'candidate', encryptionEpoch: null, payloadDigest: new Uint8Array(32), payload: { type: 'manifest', manifest: lateManifest } })
    const extended = [...records, { id: '%@a-2', author: '@a', sequence: 2n, previous: '%@a-1', receivedAtMs: NOW, payload: late }]
    const fresh = markReachableBlobs({ records: extended, contiguousThrough: clockOf(extended), continuity: null })
    expect(fresh.reachable.has(orphans[0]!)).toBe(true)

    const result = await purgeQuarantinedBlobs(paths, fresh, { nowMs: NOW + 8 * DAY, minimumQuarantineMs: 7 * DAY })
    expect(result).toMatchObject({ purged: 1, restoredReferenced: 1, retained: 0 })
    expect(await store.get(Buffer.from(orphans[0]!, 'hex'))).not.toBeNull()
    expect(listQuarantinedBlobs(paths)).toEqual([])
    expect(existsSync(join(paths.blobRoot, chunkPath(orphans[1]!)))).toBe(false)
  })

  it('recovers a crash mid-sweep from the journal and refuses ambiguous state', async () => {
    const { paths, mark, orphans } = await prepared()
    const plan = planBlobCollection(mark, scanBlobStore(paths.blobRoot), { nowMs: NOW, graceMs: DAY })
    const journal = join(paths.dataDirectory, 'blob-gc', 'journal.ndjson')
    mkdirSync(join(paths.dataDirectory, 'blob-gc', 'quarantine', 'crash', orphans[0]!.slice(0, 2)), { recursive: true })
    const intent = (digest: string) => ({ type: 'move', runId: 'crash', op: 'quarantine', phase: 'intent', kind: 'chunk', digest, blobPath: chunkPath(digest), quarantinePath: `blob-gc/quarantine/crash/${chunkPath(digest)}`, atMs: NOW })
    // First file was moved before the crash, the second was not; then a torn line.
    writeFileSync(journal, `${JSON.stringify(intent(orphans[0]!))}\n${JSON.stringify(intent(orphans[1]!))}\n{"type":"mo`)
    renameSync(join(paths.blobRoot, chunkPath(orphans[0]!)), join(paths.dataDirectory, intent(orphans[0]!).quarantinePath))

    expect(() => quarantineBlobs(paths, plan, NOW)).toThrow('BLOB_GC_JOURNAL_RECOVERY_REQUIRED')
    expect(recoverBlobGcJournal(paths, NOW)).toEqual({ completed: 1, skipped: 1 })
    expect(listQuarantinedBlobs(paths).map((item) => item.digest)).toEqual([orphans[0]])
    expect(recoverBlobGcJournal(paths, NOW)).toEqual({ completed: 0, skipped: 0 })

    // Both copies present for an open intent is ambiguous.
    const restoreIntent = { ...intent(orphans[0]!), op: 'restore' }
    appendFileSync(journal, `${JSON.stringify(restoreIntent)}\n`)
    writeFileSync(join(paths.blobRoot, chunkPath(orphans[0]!)), readFileSync(join(paths.dataDirectory, restoreIntent.quarantinePath)))
    expect(() => recoverBlobGcJournal(paths, NOW)).toThrow('BLOB_GC_JOURNAL_AMBIGUOUS')
  })
})

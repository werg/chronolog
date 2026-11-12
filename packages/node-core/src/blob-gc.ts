import { createHash, randomBytes } from 'node:crypto'
import {
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  truncateSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'

import { decodeEnvelope, payloadChunkDigest } from '@chronolog/protocol'
import type { TransportRecord } from '@chronolog/transport-ssb'

import type { FeedForkSnapshot } from './feed-forks.js'

// Operator-invoked, local-only blob garbage collection. See
// docs/blob-replication.md ("Garbage-collection design"). The caller must hold
// the exclusive data-directory lock for every function that touches files, and
// must compute the mark from the complete local transport history under that
// same lock. Nothing here performs distributed reasoning: a local proof only
// shows that no record in this node's log names a chunk.

export class BlobGcRefusal extends Error {
  constructor(readonly code: string, detail?: string) {
    super(detail === undefined ? code : `${code}:${detail}`)
  }
}

export interface BlobMarkInput {
  /** Every Chronolog record in the local transport, in any order. */
  readonly records: readonly TransportRecord[]
  /** Transport vector clock: highest contiguous sequence per feed. */
  readonly contiguousThrough: ReadonlyMap<string, bigint>
  /** Feed-continuity state recorded by the node, if any. */
  readonly continuity: FeedForkSnapshot | null
}

export interface BlobFeedHead { readonly feedId: string; readonly sequence: string; readonly id: string }

export interface BlobMark {
  /** Referenced chunk digest (hex) to its declared size. */
  readonly reachable: ReadonlyMap<string, bigint>
  readonly feedHeads: readonly BlobFeedHead[]
  readonly manifestRecords: number
  /** SHA-256 over feed heads and sorted reachable digests and sizes. */
  readonly evidenceDigest: string
}

/** Computes the set of chunks named by any local record, failing closed on any doubt about the history. */
export function markReachableBlobs(input: BlobMarkInput): BlobMark {
  const continuity = input.continuity
  if (continuity !== null && continuity.quarantines.length > 0) {
    throw new BlobGcRefusal('BLOB_GC_FEED_QUARANTINED', continuity.quarantines.map((item) => item.feedId).join(','))
  }
  const feeds = new Map<string, TransportRecord[]>()
  for (const record of input.records) {
    const list = feeds.get(record.author) ?? []
    list.push(record)
    feeds.set(record.author, list)
  }
  const feedHeads: BlobFeedHead[] = []
  const bySequence = new Map<string, Map<bigint, TransportRecord>>()
  for (const [feedId, records] of feeds) {
    records.sort((left, right) => left.sequence < right.sequence ? -1 : left.sequence > right.sequence ? 1 : 0)
    const index = new Map<bigint, TransportRecord>()
    records.forEach((record, position) => {
      if (record.sequence !== BigInt(position + 1)) throw new BlobGcRefusal('BLOB_GC_FEED_NOT_CONTIGUOUS', `${feedId}:${record.sequence}`)
      const expectedPrevious = position === 0 ? undefined : records[position - 1]!.id
      if (record.previous !== expectedPrevious) throw new BlobGcRefusal('BLOB_GC_FEED_CHAIN_BROKEN', `${feedId}:${record.sequence}`)
      index.set(record.sequence, record)
    })
    const head = records.at(-1)!
    const clock = input.contiguousThrough.get(feedId)
    if (clock !== head.sequence) throw new BlobGcRefusal('BLOB_GC_CLOCK_MISMATCH', `${feedId}:${clock ?? 'none'}:${head.sequence}`)
    bySequence.set(feedId, index)
    feedHeads.push({ feedId, sequence: head.sequence.toString(10), id: head.id })
  }
  for (const [feedId, clock] of input.contiguousThrough) {
    if (clock > 0n && !feeds.has(feedId)) throw new BlobGcRefusal('BLOB_GC_CLOCK_MISMATCH', `${feedId}:${clock}:0`)
  }
  for (const feed of continuity?.feeds ?? []) {
    const index = bySequence.get(feed.feedId)
    for (const entry of feed.records) {
      const record = index?.get(BigInt(entry.sequence))
      if (record === undefined || record.id !== entry.id) {
        // The node once observed a record that the log no longer holds: the log
        // was rolled back or replaced. Chunks we authored for such records may
        // be the only copy a lagging peer can fetch.
        throw new BlobGcRefusal('BLOB_GC_LOG_BEHIND_CONTINUITY', `${feed.feedId}:${entry.sequence}`)
      }
    }
  }
  const reachable = new Map<string, bigint>()
  let manifestRecords = 0
  for (const record of input.records) {
    let envelope: ReturnType<typeof decodeEnvelope>
    try { envelope = decodeEnvelope(record.payload) } catch (error) {
      throw new BlobGcRefusal('BLOB_GC_ENVELOPE_UNDECODABLE', `${record.id}:${error instanceof Error ? error.message : String(error)}`)
    }
    if (envelope.payload.type !== 'manifest') continue
    manifestRecords += 1
    for (const chunk of envelope.payload.manifest.chunks) {
      if (chunk.digest.length !== 32) throw new BlobGcRefusal('BLOB_GC_MANIFEST_INVALID', record.id)
      const key = Buffer.from(chunk.digest).toString('hex')
      const known = reachable.get(key)
      if (known !== undefined && known !== chunk.size) throw new BlobGcRefusal('BLOB_GC_CHUNK_SIZE_CONFLICT', key)
      reachable.set(key, chunk.size)
    }
  }
  feedHeads.sort((left, right) => left.feedId.localeCompare(right.feedId))
  const hash = createHash('sha256')
  hash.update('chronolog/blob-gc-mark/v1\n')
  for (const head of feedHeads) hash.update(`head ${head.feedId} ${head.sequence} ${head.id}\n`)
  for (const key of [...reachable.keys()].sort()) hash.update(`chunk ${key} ${reachable.get(key)!.toString(10)}\n`)
  return { reachable, feedHeads, manifestRecords, evidenceDigest: hash.digest('hex') }
}

export interface BlobFileEntry {
  readonly kind: 'chunk' | 'temporary'
  /** Path relative to the blob root, using '/' separators. */
  readonly path: string
  /** Hex digest for chunks and for the chunk a temporary file was writing. */
  readonly digest: string
  readonly size: number
  readonly mtimeMs: number
  readonly ino: number
}

export interface BlobStoreScan {
  readonly files: readonly BlobFileEntry[]
  /** Entries that are not canonical chunk or temporary files; never touched. */
  readonly unknown: readonly string[]
}

const PREFIX = /^[0-9a-f]{2}$/u
const CHUNK = /^[0-9a-f]{62}$/u
const TEMPORARY = /^([0-9a-f]{62})\.[0-9]+\.tmp$/u

/** Lists canonical chunk files and stale temporary files. Symlinks and unknown names are reported, not followed. */
export function scanBlobStore(root: string): BlobStoreScan {
  const files: BlobFileEntry[] = []
  const unknown: string[] = []
  if (!existsSync(root)) return { files, unknown }
  for (const prefix of readdirSync(root).sort()) {
    const prefixPath = join(root, prefix)
    const stat = lstatSync(prefixPath)
    if (!PREFIX.test(prefix) || !stat.isDirectory()) { unknown.push(prefix); continue }
    for (const name of readdirSync(prefixPath).sort()) {
      const path = join(prefixPath, name)
      const file = lstatSync(path)
      const chunk = CHUNK.exec(name)
      const temporary = TEMPORARY.exec(name)
      if (!file.isFile() || (chunk === null && temporary === null)) { unknown.push(`${prefix}/${name}`); continue }
      files.push({
        kind: chunk === null ? 'temporary' : 'chunk',
        path: `${prefix}/${name}`,
        digest: prefix + (chunk === null ? temporary![1]! : name),
        size: file.size,
        mtimeMs: file.mtimeMs,
        ino: file.ino,
      })
    }
  }
  return { files, unknown }
}

export interface BlobCollectionPlan {
  readonly evidenceDigest: string
  readonly retentionFloorMs: number
  readonly candidates: readonly BlobFileEntry[]
  readonly retainedUnreferenced: readonly BlobFileEntry[]
  readonly referencedPresent: number
  readonly referencedMissing: readonly string[]
  readonly referencedSizeMismatch: readonly string[]
  readonly unknown: readonly string[]
  readonly candidateBytes: number
}

export interface BlobPlanOptions {
  readonly nowMs: number
  /** Unreferenced files younger than this are never candidates. */
  readonly graceMs: number
  /** Operator hold: keep files modified at or after this instant. May only lower the floor. */
  readonly keepModifiedSinceMs?: number
}

/** A snapshot archive the operator wants to keep restorable. */
export interface BlobSnapshotHold {
  readonly feedHeads: readonly { readonly feedId: string; readonly sequence: bigint }[]
  readonly createdAtMs: bigint
}

/**
 * Holds may only make collection more conservative. A local log that is behind
 * a held snapshot's feed heads (for example after restoring an older `ssb/`)
 * blocks collection; otherwise the returned floor keeps every file modified
 * since the oldest held snapshot was created.
 */
export function snapshotHoldFloor(mark: BlobMark, holds: readonly BlobSnapshotHold[]): number | undefined {
  const heads = new Map(mark.feedHeads.map((head) => [head.feedId, BigInt(head.sequence)]))
  let floor: number | undefined
  for (const hold of holds) {
    for (const head of hold.feedHeads) {
      const local = heads.get(head.feedId) ?? 0n
      if (local < head.sequence) throw new BlobGcRefusal('BLOB_GC_LOG_BEHIND_SNAPSHOT', `${head.feedId}:${local}:${head.sequence}`)
    }
    const created = Number(hold.createdAtMs)
    floor = floor === undefined ? created : Math.min(floor, created)
  }
  return floor
}

export function planBlobCollection(mark: BlobMark, scan: BlobStoreScan, options: BlobPlanOptions): BlobCollectionPlan {
  if (!Number.isSafeInteger(options.graceMs) || options.graceMs < 0) throw new BlobGcRefusal('BLOB_GC_GRACE_INVALID')
  let retentionFloorMs = options.nowMs - options.graceMs
  if (options.keepModifiedSinceMs !== undefined) retentionFloorMs = Math.min(retentionFloorMs, options.keepModifiedSinceMs)
  const candidates: BlobFileEntry[] = []
  const retainedUnreferenced: BlobFileEntry[] = []
  const referencedSizeMismatch: string[] = []
  const present = new Set<string>()
  for (const file of scan.files) {
    const declared = mark.reachable.get(file.digest)
    if (file.kind === 'chunk' && declared !== undefined) {
      present.add(file.digest)
      if (BigInt(file.size) !== declared) referencedSizeMismatch.push(file.path)
      continue
    }
    // A temporary file is never read by the store, even when its target chunk
    // is referenced; it only becomes the chunk through rename.
    if (file.mtimeMs < retentionFloorMs) candidates.push(file)
    else retainedUnreferenced.push(file)
  }
  const referencedMissing = [...mark.reachable.keys()].filter((digest) => !present.has(digest)).sort()
  return {
    evidenceDigest: mark.evidenceDigest,
    retentionFloorMs,
    candidates,
    retainedUnreferenced,
    referencedPresent: present.size,
    referencedMissing,
    referencedSizeMismatch,
    unknown: scan.unknown,
    candidateBytes: candidates.reduce((total, file) => total + file.size, 0),
  }
}

/** Reads every referenced chunk present on disk and returns the paths whose content does not match its digest. */
export async function verifyReferencedBlobs(root: string, mark: BlobMark, scan: BlobStoreScan): Promise<readonly string[]> {
  const corrupt: string[] = []
  for (const file of scan.files) {
    if (file.kind !== 'chunk' || !mark.reachable.has(file.digest)) continue
    const digest = Buffer.from(await payloadChunkDigest(readFileSync(join(root, file.path)))).toString('hex')
    if (digest !== file.digest) corrupt.push(file.path)
  }
  return corrupt
}

// ── Journal ────────────────────────────────────────────────────────────────

export type BlobGcJournalEntry =
  | { readonly type: 'run'; readonly runId: string; readonly stage: 'quarantine' | 'restore' | 'purge'; readonly phase: 'start' | 'end'; readonly atMs: number; readonly evidenceDigest?: string; readonly summary?: Record<string, number> }
  | { readonly type: 'move'; readonly runId: string; readonly op: 'quarantine' | 'restore'; readonly phase: 'intent' | 'done' | 'skipped'; readonly kind: 'chunk' | 'temporary'; readonly digest: string; readonly blobPath: string; readonly quarantinePath: string; readonly atMs: number; readonly reason?: string }
  | { readonly type: 'purge'; readonly runId: string; readonly phase: 'intent' | 'done'; readonly digest: string; readonly quarantinePath: string; readonly atMs: number }

export interface BlobGcPaths {
  /** Data directory; journal and quarantine paths are relative to it. */
  readonly dataDirectory: string
  readonly blobRoot: string
}

function gcDirectory(paths: BlobGcPaths): string { return join(paths.dataDirectory, 'blob-gc') }
function journalPath(paths: BlobGcPaths): string { return join(gcDirectory(paths), 'journal.ndjson') }

export function readBlobGcJournal(paths: BlobGcPaths): BlobGcJournalEntry[] {
  const path = journalPath(paths)
  if (!existsSync(path)) return []
  const lines = readFileSync(path, 'utf8').split('\n')
  // The element after the final newline is '' or a torn append.
  return lines.slice(0, -1).map((line) => {
    try { return JSON.parse(line) as BlobGcJournalEntry } catch { throw new BlobGcRefusal('BLOB_GC_JOURNAL_INVALID') }
  })
}

function appendJournal(paths: BlobGcPaths, entry: BlobGcJournalEntry): void {
  mkdirSync(gcDirectory(paths), { recursive: true })
  const path = journalPath(paths)
  const created = !existsSync(path)
  if (!created) {
    // Drop a torn final line left by a crash so the next entry starts cleanly.
    const contents = readFileSync(path)
    const end = contents.lastIndexOf(0x0a) + 1
    if (end !== contents.length) truncateSync(path, end)
  }
  const file = openSync(path, 'a', 0o600)
  try {
    writeSync(file, `${JSON.stringify(entry)}\n`)
    fsyncSync(file)
  } finally { closeSync(file) }
  if (created) syncDirectory(gcDirectory(paths))
}

export interface QuarantinedBlob {
  readonly runId: string
  readonly kind: 'chunk' | 'temporary'
  readonly digest: string
  readonly blobPath: string
  readonly quarantinePath: string
  readonly quarantinedAtMs: number
}

/** Files currently held in quarantine, derived from the journal. */
export function listQuarantinedBlobs(paths: BlobGcPaths): QuarantinedBlob[] {
  const held = new Map<string, QuarantinedBlob>()
  for (const entry of readBlobGcJournal(paths)) {
    if (entry.type === 'move' && entry.phase === 'done' && entry.op === 'quarantine') {
      held.set(entry.quarantinePath, { runId: entry.runId, kind: entry.kind, digest: entry.digest, blobPath: entry.blobPath, quarantinePath: entry.quarantinePath, quarantinedAtMs: entry.atMs })
    } else if ((entry.type === 'move' && entry.phase === 'done' && entry.op === 'restore') || (entry.type === 'purge' && entry.phase === 'done')) {
      held.delete(entry.quarantinePath)
    }
  }
  return [...held.values()].sort((left, right) => left.quarantinePath.localeCompare(right.quarantinePath))
}

/**
 * Resolves intents left by a crash. A move intent without an outcome is
 * completed or marked skipped from what is on disk; a state where both or
 * neither file exists is ambiguous and refused.
 */
export function recoverBlobGcJournal(paths: BlobGcPaths, nowMs: number): { readonly completed: number; readonly skipped: number } {
  const entries = readBlobGcJournal(paths)
  const open = new Map<string, BlobGcJournalEntry>()
  for (const entry of entries) {
    if (entry.type === 'run') continue
    const key = `${entry.type}:${entry.runId}:${entry.quarantinePath}:${entry.type === 'move' ? entry.op : ''}`
    if (entry.phase === 'intent') open.set(key, entry)
    else open.delete(key)
  }
  let completed = 0
  let skipped = 0
  for (const entry of open.values()) {
    if (entry.type === 'purge') {
      const target = join(paths.dataDirectory, entry.quarantinePath)
      if (existsSync(target)) unlinkSync(target)
      syncDirectory(dirname(target))
      appendJournal(paths, { ...entry, phase: 'done', atMs: nowMs })
      completed += 1
      continue
    }
    if (entry.type !== 'move') continue
    const source = entry.op === 'quarantine' ? join(paths.blobRoot, entry.blobPath) : join(paths.dataDirectory, entry.quarantinePath)
    const target = entry.op === 'quarantine' ? join(paths.dataDirectory, entry.quarantinePath) : join(paths.blobRoot, entry.blobPath)
    const sourceExists = existsSync(source)
    const targetExists = existsSync(target)
    if (sourceExists === targetExists) throw new BlobGcRefusal('BLOB_GC_JOURNAL_AMBIGUOUS', entry.quarantinePath)
    if (targetExists) {
      appendJournal(paths, { ...entry, phase: 'done', atMs: nowMs, reason: 'recovered' })
      completed += 1
    } else {
      appendJournal(paths, { ...entry, phase: 'skipped', atMs: nowMs, reason: 'not-moved-before-crash' })
      skipped += 1
    }
  }
  return { completed, skipped }
}

function assertNoOpenIntents(paths: BlobGcPaths): void {
  const entries = readBlobGcJournal(paths)
  const open = new Set<string>()
  for (const entry of entries) {
    if (entry.type === 'run') continue
    const key = `${entry.type}:${entry.runId}:${entry.quarantinePath}:${entry.type === 'move' ? entry.op : ''}`
    if (entry.phase === 'intent') open.add(key)
    else open.delete(key)
  }
  if (open.size > 0) throw new BlobGcRefusal('BLOB_GC_JOURNAL_RECOVERY_REQUIRED')
}

function newRunId(nowMs: number): string {
  return `${new Date(nowMs).toISOString().replace(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`
}

export interface BlobQuarantineResult {
  readonly runId: string
  readonly quarantined: number
  readonly quarantinedBytes: number
  readonly skipped: readonly { readonly path: string; readonly reason: string }[]
}

/** Moves plan candidates into quarantine. Each file is re-checked unchanged since the scan. */
export function quarantineBlobs(paths: BlobGcPaths, plan: BlobCollectionPlan, nowMs: number): BlobQuarantineResult {
  assertNoOpenIntents(paths)
  const runId = newRunId(nowMs)
  appendJournal(paths, { type: 'run', runId, stage: 'quarantine', phase: 'start', atMs: nowMs, evidenceDigest: plan.evidenceDigest, summary: { candidates: plan.candidates.length } })
  let quarantined = 0
  let quarantinedBytes = 0
  const skipped: { path: string; reason: string }[] = []
  for (const file of plan.candidates) {
    const source = join(paths.blobRoot, file.path)
    const quarantinePath = relative(paths.dataDirectory, join(gcDirectory(paths), 'quarantine', runId, file.path)).split(sep).join('/')
    let current: ReturnType<typeof lstatSync>
    try { current = lstatSync(source) } catch { skipped.push({ path: file.path, reason: 'missing' }); continue }
    if (!current.isFile() || current.size !== file.size || current.mtimeMs !== file.mtimeMs || current.ino !== file.ino) {
      skipped.push({ path: file.path, reason: 'changed-since-scan' })
      continue
    }
    const target = join(paths.dataDirectory, quarantinePath)
    const base = { type: 'move' as const, runId, op: 'quarantine' as const, kind: file.kind, digest: file.digest, blobPath: file.path, quarantinePath }
    appendJournal(paths, { ...base, phase: 'intent', atMs: nowMs })
    mkdirSync(dirname(target), { recursive: true })
    renameSync(source, target)
    syncDirectory(dirname(target))
    syncDirectory(dirname(source))
    appendJournal(paths, { ...base, phase: 'done', atMs: nowMs })
    quarantined += 1
    quarantinedBytes += file.size
  }
  appendJournal(paths, { type: 'run', runId, stage: 'quarantine', phase: 'end', atMs: nowMs, evidenceDigest: plan.evidenceDigest, summary: { quarantined, skipped: skipped.length } })
  return { runId, quarantined, quarantinedBytes, skipped }
}

export interface BlobRestoreResult {
  readonly restored: number
  readonly skipped: readonly { readonly path: string; readonly reason: string }[]
}

async function restoreOne(paths: BlobGcPaths, item: QuarantinedBlob, nowMs: number): Promise<string | null> {
  const source = join(paths.dataDirectory, item.quarantinePath)
  const target = join(paths.blobRoot, item.blobPath)
  const base = { type: 'move' as const, runId: item.runId, op: 'restore' as const, kind: item.kind, digest: item.digest, blobPath: item.blobPath, quarantinePath: item.quarantinePath }
  if (item.kind === 'chunk') {
    const actual = Buffer.from(await payloadChunkDigest(readFileSync(source))).toString('hex')
    if (actual !== item.digest) return 'digest-mismatch'
  }
  if (existsSync(target)) return 'already-present'
  appendJournal(paths, { ...base, phase: 'intent', atMs: nowMs })
  mkdirSync(dirname(target), { recursive: true })
  renameSync(source, target)
  syncDirectory(dirname(target))
  syncDirectory(dirname(source))
  appendJournal(paths, { ...base, phase: 'done', atMs: nowMs })
  return null
}

/** Moves quarantined files back, verifying chunk digests first. */
export async function restoreQuarantinedBlobs(paths: BlobGcPaths, nowMs: number, options: { readonly runId?: string } = {}): Promise<BlobRestoreResult> {
  assertNoOpenIntents(paths)
  const runId = newRunId(nowMs)
  appendJournal(paths, { type: 'run', runId, stage: 'restore', phase: 'start', atMs: nowMs })
  let restored = 0
  const skipped: { path: string; reason: string }[] = []
  for (const item of listQuarantinedBlobs(paths)) {
    if (options.runId !== undefined && item.runId !== options.runId) continue
    const reason = await restoreOne(paths, item, nowMs)
    if (reason === null) restored += 1
    else skipped.push({ path: item.blobPath, reason })
  }
  appendJournal(paths, { type: 'run', runId, stage: 'restore', phase: 'end', atMs: nowMs, summary: { restored, skipped: skipped.length } })
  return { restored, skipped }
}

export interface BlobPurgeResult {
  readonly purged: number
  readonly purgedBytes: number
  readonly restoredReferenced: number
  readonly retained: number
  readonly skipped: readonly { readonly path: string; readonly reason: string }[]
}

/**
 * Permanently deletes quarantined files older than `minimumQuarantineMs`.
 * `mark` must be freshly computed under the lock: anything it now references
 * is restored instead of deleted.
 */
export async function purgeQuarantinedBlobs(
  paths: BlobGcPaths,
  mark: BlobMark,
  options: { readonly nowMs: number; readonly minimumQuarantineMs: number },
): Promise<BlobPurgeResult> {
  if (!Number.isSafeInteger(options.minimumQuarantineMs) || options.minimumQuarantineMs < 0) throw new BlobGcRefusal('BLOB_GC_QUARANTINE_AGE_INVALID')
  assertNoOpenIntents(paths)
  const runId = newRunId(options.nowMs)
  appendJournal(paths, { type: 'run', runId, stage: 'purge', phase: 'start', atMs: options.nowMs, evidenceDigest: mark.evidenceDigest })
  let purged = 0
  let purgedBytes = 0
  let restoredReferenced = 0
  let retained = 0
  const skipped: { path: string; reason: string }[] = []
  for (const item of listQuarantinedBlobs(paths)) {
    if (item.kind === 'chunk' && mark.reachable.has(item.digest)) {
      const reason = await restoreOne(paths, item, options.nowMs)
      if (reason === null) restoredReferenced += 1
      else skipped.push({ path: item.blobPath, reason: `referenced:${reason}` })
      continue
    }
    if (options.nowMs - item.quarantinedAtMs < options.minimumQuarantineMs) { retained += 1; continue }
    const target = join(paths.dataDirectory, item.quarantinePath)
    const size = existsSync(target) ? lstatSync(target).size : 0
    appendJournal(paths, { type: 'purge', runId, phase: 'intent', digest: item.digest, quarantinePath: item.quarantinePath, atMs: options.nowMs })
    if (existsSync(target)) unlinkSync(target)
    syncDirectory(dirname(target))
    appendJournal(paths, { type: 'purge', runId, phase: 'done', digest: item.digest, quarantinePath: item.quarantinePath, atMs: options.nowMs })
    purged += 1
    purgedBytes += size
  }
  appendJournal(paths, { type: 'run', runId, stage: 'purge', phase: 'end', atMs: options.nowMs, evidenceDigest: mark.evidenceDigest, summary: { purged, restoredReferenced, retained } })
  return { purged, purgedBytes, restoredReferenced, retained, skipped }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

// Operator-invoked local blob garbage collection. Run with the daemon stopped:
//
//   pnpm blob stats [--verify]
//   pnpm blob gc [--grace-days 7] [--keep-modified-since ISO_TIME] [--apply]
//   pnpm blob restore [--run RUN_ID]
//   pnpm blob purge [--min-quarantine-days 7]
//
// gc without --apply only prints the plan. Applying moves candidates into
// <data>/blob-gc/quarantine; purge deletes quarantined files after a fresh mark
// and restores any that became referenced. Every step is journaled in
// <data>/blob-gc/journal.ndjson. See docs/blob-replication.md.
import { join, resolve } from 'node:path'

import {
  BlobGcRefusal,
  JsonFeedForkPersistence,
  listQuarantinedBlobs,
  markReachableBlobs,
  planBlobCollection,
  purgeQuarantinedBlobs,
  quarantineBlobs,
  recoverBlobGcJournal,
  restoreQuarantinedBlobs,
  scanBlobStore,
  verifyReferencedBlobs,
  type BlobGcPaths,
  type BlobMark,
} from '@chronolog/node-core'
import { SsbDb2Transport } from '@chronolog/transport-ssb'

import { acquireDataDirectoryLock } from './data-lock.js'

const DAY_MS = 24 * 60 * 60 * 1000
const args = process.argv.slice(2)
const command = args.shift()
if (command === undefined || !['stats', 'gc', 'restore', 'purge'].includes(command)) {
  process.stderr.write('Usage: pnpm blob <stats [--verify] | gc [--grace-days N] [--keep-modified-since ISO] [--apply] | restore [--run RUN_ID] | purge [--min-quarantine-days N]>\n')
  process.exit(2)
}
const dataDirectory = resolve(process.env.CHRONOLOG_DATA_DIR ?? '.chronolog')
const paths: BlobGcPaths = { dataDirectory, blobRoot: join(dataDirectory, 'blobs') }

const lock = await acquireDataDirectoryLock(dataDirectory, `blob-${command}`)
try {
  const now = Date.now()
  const recovered = recoverBlobGcJournal(paths, now)
  if (command === 'restore') {
    const runId = option('--run')
    output({ recovered, ...await restoreQuarantinedBlobs(paths, now, runId === undefined ? {} : { runId }) })
  } else {
    const mark = await markFromLocalHistory()
    const scan = scanBlobStore(paths.blobRoot)
    if (command === 'stats') {
      const plan = planBlobCollection(mark, scan, { nowMs: now, graceMs: 0 })
      output({
        recovered,
        evidenceDigest: mark.evidenceDigest,
        feeds: mark.feedHeads.length,
        manifestRecords: mark.manifestRecords,
        referenced: mark.reachable.size,
        referencedPresent: plan.referencedPresent,
        referencedMissing: plan.referencedMissing,
        referencedSizeMismatch: plan.referencedSizeMismatch,
        ...(args.includes('--verify') ? { referencedCorrupt: await verifyReferencedBlobs(paths.blobRoot, mark, scan) } : {}),
        unreferencedFiles: plan.candidates.length,
        unreferencedBytes: plan.candidateBytes,
        unknownEntries: plan.unknown,
        quarantined: listQuarantinedBlobs(paths).length,
      })
    } else if (command === 'gc') {
      const keepSince = option('--keep-modified-since')
      const keepModifiedSinceMs = keepSince === undefined ? undefined : Date.parse(keepSince)
      if (keepModifiedSinceMs !== undefined && !Number.isFinite(keepModifiedSinceMs)) throw new Error('--keep-modified-since must be an ISO time')
      const plan = planBlobCollection(mark, scan, {
        nowMs: now,
        graceMs: days('--grace-days', 7),
        ...(keepModifiedSinceMs === undefined ? {} : { keepModifiedSinceMs }),
      })
      if (plan.referencedMissing.length > 0 || plan.referencedSizeMismatch.length > 0) {
        process.stderr.write(`warning: ${plan.referencedMissing.length} referenced chunks missing, ${plan.referencedSizeMismatch.length} size-mismatched; they are reported, never collected\n`)
      }
      const summary = {
        evidenceDigest: plan.evidenceDigest,
        retentionFloor: new Date(plan.retentionFloorMs).toISOString(),
        candidates: plan.candidates.map((file) => ({ path: file.path, kind: file.kind, size: file.size })),
        candidateBytes: plan.candidateBytes,
        retainedUnreferenced: plan.retainedUnreferenced.length,
        referencedMissing: plan.referencedMissing,
        unknownEntries: plan.unknown,
      }
      if (!args.includes('--apply')) output({ recovered, dryRun: true, ...summary })
      else output({ recovered, ...summary, ...quarantineBlobs(paths, plan, now) })
    } else {
      output({ recovered, evidenceDigest: mark.evidenceDigest, ...await purgeQuarantinedBlobs(paths, mark, { nowMs: now, minimumQuarantineMs: days('--min-quarantine-days', 7) }) })
    }
  }
} catch (error) {
  if (error instanceof BlobGcRefusal) {
    process.stderr.write(`refused: ${error.message}\n`)
    process.exitCode = 3
  } else throw error
} finally {
  await lock.release()
}

async function markFromLocalHistory(): Promise<BlobMark> {
  // Offline: no listener and no peers, so nothing is replicated while marking.
  const transport = await SsbDb2Transport.open({ path: join(dataDirectory, 'ssb') })
  try {
    const records = await transport.history()
    const status = await transport.status()
    const contiguousThrough = new Map((status.feedStates ?? []).map((feed) => [feed.feedId, BigInt(feed.contiguousThrough)]))
    const continuity = new JsonFeedForkPersistence(join(dataDirectory, 'feed-continuity.json')).load()
    return markReachableBlobs({ records, contiguousThrough, continuity })
  } finally {
    await transport.close()
  }
}

function option(name: string): string | undefined {
  const index = args.indexOf(name)
  return index === -1 ? undefined : args[index + 1]
}

function days(name: string, fallback: number): number {
  const value = option(name)
  if (value === undefined) return fallback * DAY_MS
  if (!/^[0-9]+(\.[0-9]+)?$/u.test(value)) throw new Error(`${name} must be a non-negative number of days`)
  return Math.round(Number(value) * DAY_MS)
}

function output(value: unknown): void { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`) }

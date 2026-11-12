import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'

import type { TransportRecord } from '@chronolog/transport-ssb'

export interface FeedForkEvidence {
  readonly feedId: string
  readonly sequence: string
  readonly acceptedId: string
  readonly conflictingId: string
  readonly detectedAt: string
}

export interface FeedForkSnapshot {
  readonly format: 'chronolog-feed-continuity-v1'
  readonly feeds: readonly {
    readonly feedId: string
    readonly records: readonly {
      readonly sequence: string
      readonly id: string
      readonly previous: string | null
    }[]
  }[]
  readonly quarantines: readonly FeedForkEvidence[]
  readonly discardedRecordIds: readonly string[]
}

export interface FeedContinuityEntry {
  readonly feedId: string
  readonly sequence: string
  readonly id: string
  readonly previous: string | null
}

export interface FeedForkPersistence {
  load(): FeedForkSnapshot | null
  save(snapshot: FeedForkSnapshot): void
  /**
   * Durably records one newly accepted record without rewriting the whole
   * snapshot. Optional; registries fall back to save() when absent.
   * Returns true when the caller should compact by calling save().
   */
  append?(entry: FeedContinuityEntry): boolean
}

export interface FeedRepairPlan {
  readonly feedId: string
  readonly trustedHeadId: string
  readonly records: readonly TransportRecord[]
}

export class FeedForkRegistry {
  readonly #feeds = new Map<string, Map<bigint, { readonly id: string; readonly previous: string | null }>>()
  readonly #quarantines = new Map<string, FeedForkEvidence>()
  readonly #discardedRecordIds = new Set<string>()

  constructor(private readonly persistence?: FeedForkPersistence) {
    const snapshot = persistence?.load()
    if (snapshot !== null && snapshot !== undefined) this.#restore(snapshot)
    if (persistence?.append !== undefined && snapshot !== null && snapshot !== undefined) this.#save()
  }

  observe(record: TransportRecord): 'accepted' | 'duplicate' | 'discarded' | 'quarantined' {
    validateRecord(record)
    if (this.#discardedRecordIds.has(record.id)) return 'discarded'
    if (this.#quarantines.has(record.author)) return 'quarantined'
    const feed = this.#feeds.get(record.author) ??
      new Map<bigint, { readonly id: string; readonly previous: string | null }>()
    this.#feeds.set(record.author, feed)
    const previous = record.previous ?? null
    const existing = feed.get(record.sequence)
    if (existing !== undefined) {
      if (existing.id === record.id && existing.previous === previous) return 'duplicate'
      this.#quarantine(record, existing.id)
      return 'quarantined'
    }
    const predecessor = feed.get(record.sequence - 1n)
    if (predecessor !== undefined && previous !== predecessor.id) {
      this.#quarantine(record, predecessor.id)
      return 'quarantined'
    }
    const successor = feed.get(record.sequence + 1n)
    if (successor !== undefined && successor.previous !== record.id) {
      this.#quarantine(record, successor.id)
      return 'quarantined'
    }
    feed.set(record.sequence, { id: record.id, previous })
    if (this.persistence?.append === undefined) this.#save()
    else if (this.persistence.append({ feedId: record.author, sequence: record.sequence.toString(), id: record.id, previous })) this.#save()
    return 'accepted'
  }

  quarantined(feedId?: string): boolean {
    return feedId === undefined ? this.#quarantines.size > 0 : this.#quarantines.has(feedId)
  }

  quarantineEvidence(): readonly FeedForkEvidence[] {
    return [...this.#quarantines.values()].sort((left, right) => left.feedId.localeCompare(right.feedId))
  }

  createRepairPlan(
    feedId: string,
    records: readonly TransportRecord[],
    trustedHeadId: string,
  ): FeedRepairPlan {
    const selected = records.filter((record) => record.author === feedId)
      .sort((left, right) => left.sequence < right.sequence ? -1 : left.sequence > right.sequence ? 1 : 0)
    if (selected.length === 0 || selected.at(-1)?.id !== trustedHeadId) {
      throw new Error('FEED_REPAIR_TRUSTED_HEAD_MISSING')
    }
    for (let index = 0; index < selected.length; index += 1) {
      const record = selected[index]!
      if (record.sequence !== BigInt(index + 1)) throw new Error('FEED_REPAIR_PREFIX_INCOMPLETE')
      const expectedPrevious = index === 0 ? undefined : selected[index - 1]!.id
      if (record.previous !== expectedPrevious) throw new Error('FEED_REPAIR_CHAIN_INVALID')
    }
    return { feedId, trustedHeadId, records: selected.map((record) => structuredClone(record)) }
  }

  /** Apply only while the node is stopped; derived stores must then rebuild from this trusted prefix. */
  applyRepair(plan: FeedRepairPlan): void {
    const verified = this.createRepairPlan(plan.feedId, plan.records, plan.trustedHeadId)
    const quarantine = this.#quarantines.get(verified.feedId)
    if (quarantine === undefined) throw new Error('FEED_REPAIR_NOT_QUARANTINED')
    const trustedAtConflict = verified.records.find((record) => record.sequence.toString() === quarantine.sequence)?.id
    if (trustedAtConflict === undefined ||
        (trustedAtConflict !== quarantine.acceptedId && trustedAtConflict !== quarantine.conflictingId)) {
      throw new Error('FEED_REPAIR_CONFLICT_NOT_RESOLVED')
    }
    const discarded = trustedAtConflict === quarantine.acceptedId ? quarantine.conflictingId : quarantine.acceptedId
    this.#discardedRecordIds.add(discarded)
    this.#feeds.set(verified.feedId, new Map(verified.records.map((record) => [
      record.sequence,
      { id: record.id, previous: record.previous ?? null },
    ])))
    this.#quarantines.delete(verified.feedId)
    this.#save()
  }

  snapshot(): FeedForkSnapshot {
    return {
      format: 'chronolog-feed-continuity-v1',
      feeds: [...this.#feeds.entries()].sort(([left], [right]) => left.localeCompare(right)).map(
        ([feedId, records]) => ({
          feedId,
          records: [...records.entries()].sort(([left], [right]) => left < right ? -1 : 1).map(
            ([sequence, record]) => ({ sequence: sequence.toString(), ...record }),
          ),
        }),
      ),
      quarantines: this.quarantineEvidence(),
      discardedRecordIds: [...this.#discardedRecordIds].sort(),
    }
  }

  #quarantine(record: TransportRecord, acceptedId: string): void {
    this.#quarantines.set(record.author, {
      feedId: record.author,
      sequence: record.sequence.toString(),
      acceptedId,
      conflictingId: record.id,
      detectedAt: new Date(record.receivedAtMs).toISOString(),
    })
    this.#save()
  }

  #save(): void { this.persistence?.save(this.snapshot()) }

  #restore(snapshot: FeedForkSnapshot): void {
    if (snapshot.format !== 'chronolog-feed-continuity-v1') throw new Error('FEED_FORK_SNAPSHOT_INVALID')
    for (const feed of snapshot.feeds) {
      const records = new Map<bigint, { readonly id: string; readonly previous: string | null }>()
      for (const record of feed.records) {
        if (!/^[1-9][0-9]*$/u.test(record.sequence) || records.has(BigInt(record.sequence))) {
          throw new Error('FEED_FORK_SNAPSHOT_INVALID')
        }
        records.set(BigInt(record.sequence), { id: record.id, previous: record.previous })
      }
      this.#feeds.set(feed.feedId, records)
    }
    for (const quarantine of snapshot.quarantines) this.#quarantines.set(quarantine.feedId, quarantine)
    for (const id of snapshot.discardedRecordIds ?? []) {
      if (typeof id !== 'string' || id.length === 0) throw new Error('FEED_FORK_SNAPSHOT_INVALID')
      this.#discardedRecordIds.add(id)
    }
  }
}

/**
 * Snapshot plus append-only journal. Accepted records are appended as one
 * JSON line each and fsynced, so per-record cost no longer grows with history.
 * save() writes a full snapshot atomically and truncates the journal; load()
 * replays the journal over the snapshot. A torn final line (crash during an
 * append) is ignored, since its record is re-observed from the transport; any
 * other malformed line fails closed.
 */
export class JsonFeedForkPersistence implements FeedForkPersistence {
  readonly #journalPath: string
  #journalEntries = 0

  constructor(private readonly path: string, private readonly compactAfterEntries = 1_024) {
    this.#journalPath = `${path}.journal`
  }

  load(): FeedForkSnapshot | null {
    const base = existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) as FeedForkSnapshot : null
    const entries = this.#readJournal()
    this.#journalEntries = entries.length
    if (entries.length === 0) return base
    const snapshot: FeedForkSnapshot = base ?? { format: 'chronolog-feed-continuity-v1', feeds: [], quarantines: [], discardedRecordIds: [] }
    const feeds = new Map(snapshot.feeds.map((feed) => [
      feed.feedId,
      new Map(feed.records.map((record) => [record.sequence, record])),
    ]))
    for (const entry of entries) {
      const records = feeds.get(entry.feedId) ?? new Map<string, FeedForkSnapshot['feeds'][number]['records'][number]>()
      const existing = records.get(entry.sequence)
      // A crash after the snapshot rename but before the journal is removed
      // leaves entries that the snapshot already contains.
      if (existing !== undefined) {
        if (existing.id !== entry.id || existing.previous !== entry.previous) throw new Error('FEED_FORK_JOURNAL_CONFLICT')
        continue
      }
      records.set(entry.sequence, { sequence: entry.sequence, id: entry.id, previous: entry.previous })
      feeds.set(entry.feedId, records)
    }
    return { ...snapshot, feeds: [...feeds.entries()].map(([feedId, records]) => ({ feedId, records: [...records.values()] })) }
  }

  save(snapshot: FeedForkSnapshot): void {
    mkdirSync(dirname(this.path), { recursive: true })
    const temporary = `${this.path}.tmp`
    writeFileSync(temporary, `${JSON.stringify(snapshot)}\n`, { encoding: 'utf8', mode: 0o600 })
    const file = openSync(temporary, 'r')
    try { fsyncSync(file) } finally { closeSync(file) }
    renameSync(temporary, this.path)
    syncDirectory(dirname(this.path))
    // The snapshot now contains every journaled entry.
    rmSync(this.#journalPath, { force: true })
    this.#journalEntries = 0
  }

  append(entry: FeedContinuityEntry): boolean {
    mkdirSync(dirname(this.path), { recursive: true })
    const created = !existsSync(this.#journalPath)
    const file = openSync(this.#journalPath, 'a', 0o600)
    try {
      writeSync(file, `${JSON.stringify(entry)}\n`)
      fsyncSync(file)
    } finally { closeSync(file) }
    if (created) syncDirectory(dirname(this.path))
    this.#journalEntries += 1
    return this.#journalEntries >= this.compactAfterEntries
  }

  #readJournal(): FeedContinuityEntry[] {
    if (!existsSync(this.#journalPath)) return []
    const lines = readFileSync(this.#journalPath, 'utf8').split('\n')
    // The element after the last newline is either '' or a torn append.
    return lines.slice(0, -1).map((line) => {
      let value: unknown
      try { value = JSON.parse(line) } catch { throw new Error('FEED_FORK_JOURNAL_INVALID') }
      if (!isJournalEntry(value)) throw new Error('FEED_FORK_JOURNAL_INVALID')
      return value
    })
  }
}

function isJournalEntry(value: unknown): value is FeedContinuityEntry {
  if (typeof value !== 'object' || value === null) return false
  const entry = value as Record<string, unknown>
  return typeof entry.feedId === 'string' && entry.feedId.length > 0 &&
    typeof entry.sequence === 'string' && /^[1-9][0-9]*$/u.test(entry.sequence) &&
    typeof entry.id === 'string' && entry.id.length > 0 &&
    (entry.previous === null || typeof entry.previous === 'string')
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, 'r')
  try { fsyncSync(descriptor) } finally { closeSync(descriptor) }
}

function validateRecord(record: TransportRecord): void {
  if (record.author.length === 0 || record.id.length === 0 || record.sequence < 1n ||
      !Number.isFinite(record.receivedAtMs)) throw new Error('FEED_RECORD_INVALID')
  if (record.sequence === 1n && record.previous !== undefined) throw new Error('FEED_RECORD_GENESIS_PREVIOUS_INVALID')
  if (record.sequence > 1n && record.previous === undefined) throw new Error('FEED_RECORD_PREVIOUS_MISSING')
}

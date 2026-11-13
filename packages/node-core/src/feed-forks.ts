import type { DatabaseSync } from 'node:sqlite'

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
  /** False when appends never need folding into a snapshot on open. */
  readonly compactOnOpen?: boolean
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
    if (persistence?.append !== undefined && persistence.compactOnOpen !== false && snapshot !== null && snapshot !== undefined) this.#save()
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

function validateRecord(record: TransportRecord): void {
  if (record.author.length === 0 || record.id.length === 0 || record.sequence < 1n ||
      !Number.isFinite(record.receivedAtMs)) throw new Error('FEED_RECORD_INVALID')
  if (record.sequence === 1n && record.previous !== undefined) throw new Error('FEED_RECORD_GENESIS_PREVIOUS_INVALID')
  if (record.sequence > 1n && record.previous === undefined) throw new Error('FEED_RECORD_PREVIOUS_MISSING')
}

/**
 * Feed-continuity state in the node's SQLite state file: one row per
 * accepted record, plus quarantines and operator-discarded record ids.
 */
export class SqliteFeedForkPersistence implements FeedForkPersistence {
  readonly compactOnOpen = false

  constructor(private readonly database: DatabaseSync) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS feed_continuity (
        feed_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        id TEXT NOT NULL,
        previous TEXT,
        PRIMARY KEY (feed_id, sequence)
      );
      CREATE TABLE IF NOT EXISTS feed_quarantines (feed_id TEXT PRIMARY KEY, evidence TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS feed_discarded_records (id TEXT PRIMARY KEY);
    `)
  }

  load(): FeedForkSnapshot | null {
    const rows = this.database.prepare('SELECT feed_id, sequence, id, previous FROM feed_continuity ORDER BY feed_id, sequence')
    rows.setReadBigInts(true)
    const records = rows.all() as { feed_id: string; sequence: bigint; id: string; previous: string | null }[]
    const quarantines = (this.database.prepare('SELECT evidence FROM feed_quarantines ORDER BY feed_id').all() as { evidence: string }[])
      .map((row) => JSON.parse(row.evidence) as FeedForkEvidence)
    const discarded = (this.database.prepare('SELECT id FROM feed_discarded_records ORDER BY id').all() as { id: string }[]).map((row) => row.id)
    if (records.length === 0 && quarantines.length === 0 && discarded.length === 0) return null
    const feeds = new Map<string, { sequence: string; id: string; previous: string | null }[]>()
    for (const row of records) {
      const feed = feeds.get(row.feed_id) ?? []
      feed.push({ sequence: row.sequence.toString(10), id: row.id, previous: row.previous })
      feeds.set(row.feed_id, feed)
    }
    return {
      format: 'chronolog-feed-continuity-v1',
      feeds: [...feeds.entries()].map(([feedId, feedRecords]) => ({ feedId, records: feedRecords })),
      quarantines,
      discardedRecordIds: discarded,
    }
  }

  save(snapshot: FeedForkSnapshot): void {
    this.database.exec('BEGIN IMMEDIATE')
    try {
      this.database.exec('DELETE FROM feed_continuity; DELETE FROM feed_quarantines; DELETE FROM feed_discarded_records;')
      const record = this.database.prepare('INSERT INTO feed_continuity (feed_id, sequence, id, previous) VALUES (?, ?, ?, ?)')
      for (const feed of snapshot.feeds) {
        for (const entry of feed.records) record.run(feed.feedId, BigInt(entry.sequence), entry.id, entry.previous)
      }
      const quarantine = this.database.prepare('INSERT INTO feed_quarantines (feed_id, evidence) VALUES (?, ?)')
      for (const evidence of snapshot.quarantines) quarantine.run(evidence.feedId, JSON.stringify(evidence))
      const discarded = this.database.prepare('INSERT INTO feed_discarded_records (id) VALUES (?)')
      for (const id of snapshot.discardedRecordIds) discarded.run(id)
      this.database.exec('COMMIT')
    } catch (error) {
      this.database.exec('ROLLBACK')
      throw error
    }
  }

  /** One durable row per accepted record; never needs compaction. */
  append(entry: FeedContinuityEntry): boolean {
    this.database.prepare('INSERT OR REPLACE INTO feed_continuity (feed_id, sequence, id, previous) VALUES (?, ?, ?, ?)')
      .run(entry.feedId, BigInt(entry.sequence), entry.id, entry.previous)
    return false
  }
}

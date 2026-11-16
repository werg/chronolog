import {
  decodeRecord, recordGenesisRoot, recordId,
  type RecordLogClient, type RecordLogEntry, type RecordLogHead,
} from '@tendriller/core/records'
import {
  encodeHistoryConfiguration, encodeOrderingEvidence, verifyPrefixCertificate,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry, type PrefixCertificate,
} from '@chronolog/node-core/history'
import { decodeEnvelope, equalBytes } from '@chronolog/protocol'
import type {
  ChronologTransport, ImmutableEvidence, PublishOptions, TransportRecord, TransportStatus,
} from '@chronolog/records'

type EvidenceTransport = ChronologTransport & Required<Pick<ChronologTransport,
  'putEvidence' | 'evidenceHistory' | 'subscribeEvidence'>>

export interface TendrillerTransportOptions {
  readonly local: ChronologTransport
  readonly records: RecordLogClient
  readonly configuration: CoordinatedHistoryConfiguration
  readonly groupRoute: Uint8Array
  /** Authenticated on-demand endpoint. Returned certificates never enter the log. */
  readonly certificate?: (signal?: AbortSignal) => Promise<PrefixCertificate>
  /** Defaults to true; false lets an application schedule explicit catch-up. */
  readonly watch?: boolean
}

export function adaptRecordEntry(entry: RecordLogEntry): OrderedRecordEntry {
  return {
    historyId: entry.historyId, position: entry.position, recordId: entry.recordId,
    previousRoot: entry.previousRoot, root: entry.root, bytes: decodeRecord(entry.record),
  }
}

/**
 * One local signed-record/evidence store, with Tendriller as an optional route.
 * The local author feed is the durable retry source, not an adapter-owned outbox.
 */
export class TendrillerTransport implements ChronologTransport {
  readonly #local: EvidenceTransport
  readonly #records: RecordLogClient
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #groupRoute: Uint8Array
  readonly #certificate: ((signal?: AbortSignal) => Promise<PrefixCertificate>) | undefined
  readonly #watch: boolean
  readonly #controller = new AbortController()
  readonly #acknowledged = new Set<string>()
  #previous: RecordLogHead | undefined
  #certifiedThrough: number | undefined
  #pending: Promise<void> = Promise.resolve()
  #stopWatch: (() => void) | undefined
  #retry: ReturnType<typeof setTimeout> | undefined
  #lastError: string | undefined
  #closed = false

  constructor(options: TendrillerTransportOptions) {
    const local = options.local
    if (local.putEvidence === undefined || local.evidenceHistory === undefined || local.subscribeEvidence === undefined) {
      throw new Error('TENDRILLER_REQUIRES_DURABLE_EVIDENCE_TRANSPORT')
    }
    if (options.groupRoute.length !== 32) throw new Error('TENDRILLER_GROUP_ROUTE_INVALID')
    encodeHistoryConfiguration(options.configuration)
    this.#local = local as EvidenceTransport
    this.#records = options.records
    this.#configuration = structuredClone(options.configuration)
    this.#groupRoute = options.groupRoute.slice()
    this.#certificate = options.certificate
    this.#watch = options.watch !== false
    if (this.#watch) {
      this.#stopWatch = this.#records.watch({
        historyId: this.#configuration.historyId, after: 0,
        onError: (error) => { this.#lastError = error.message },
      }, () => { void this.catchUp().catch(() => undefined) })
      void this.catchUp().catch(() => undefined)
    }
  }

  get identity(): string { return this.#local.identity }

  publish(payload: Uint8Array, options?: PublishOptions): Promise<TransportRecord> {
    const exact = payload.slice()
    return this.#serial(async () => {
      // A lost relay reply must not create a second signed local feed record.
      const existing = (await this.#local.history()).find((record) =>
        record.author === this.identity && equalBytes(record.payload, exact))
      const record = existing ?? await this.#local.publish(exact, options)
      await this.#flushLocal()
      return record
    })
  }

  ensurePublished(record: TransportRecord): Promise<void> {
    const exact = { ...record, payload: record.payload.slice() }
    return this.#serial(async () => {
      const saved = await this.#local.get(exact.id)
      if (saved === undefined || saved.author !== this.identity || saved.author !== exact.author || saved.sequence !== exact.sequence ||
          !equalBytes(saved.payload, exact.payload)) throw new Error('TENDRILLER_RECORD_NOT_DURABLE_LOCALLY')
      // Flush in original local sequence: dependent governance cannot overtake
      // a predecessor whose remote append response was lost.
      await this.#flushLocal()
    })
  }

  /** Re-read retained history after missed hints or restart, then request progress evidence. */
  catchUp(): Promise<void> {
    return this.#serial(async () => {
      await this.#flushLocal()
      await this.#pull()
      if (this.#certificate !== undefined && this.#previous !== undefined &&
          (this.#certifiedThrough === undefined || this.#previous.position > this.#certifiedThrough)) {
        const certificate = await this.#certificate(this.#controller.signal)
        await verifyPrefixCertificate(certificate, this.#configuration)
        await this.#local.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
        this.#certifiedThrough = Math.max(this.#certifiedThrough ?? 0, certificate.position)
        // The authority may observe a newer head while the prior range is read.
        await this.#pull(certificate.position)
      }
    })
  }

  get(id: string): Promise<TransportRecord | undefined> { return this.#local.get(id) }
  history(): Promise<readonly TransportRecord[]> { return this.#local.history() }
  subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord> { return this.#local.subscribe(signal) }
  putEvidence(bytes: Uint8Array): Promise<ImmutableEvidence> { return this.#local.putEvidence(bytes) }
  evidenceHistory(): Promise<readonly ImmutableEvidence[]> { return this.#local.evidenceHistory() }
  subscribeEvidence(signal?: AbortSignal): AsyncIterable<ImmutableEvidence> { return this.#local.subscribeEvidence(signal) }
  feedContiguousThrough(feedId: string): Promise<bigint> {
    if (this.#local.feedContiguousThrough === undefined) return Promise.resolve(0n)
    return this.#local.feedContiguousThrough(feedId)
  }
  requestFeed(feedId: string): void { this.#local.requestFeed?.(feedId) }

  async status(): Promise<TransportStatus> {
    const status = await this.#local.status()
    return { ...status, ...(this.#lastError === undefined ? {} : { lastCatchUpError: this.#lastError }) }
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    this.#stopWatch?.()
    clearTimeout(this.#retry)
    this.#controller.abort()
    await this.#pending
    await this.#local.close()
  }

  #serial<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.#pending.then(async () => {
      if (this.#closed) throw new Error('TENDRILLER_TRANSPORT_CLOSED')
      try {
        const result = await operation()
        this.#lastError = undefined
        return result
      } catch (error) {
        this.#lastError = error instanceof Error ? error.message : String(error)
        this.#scheduleRetry()
        throw error
      }
    })
    this.#pending = pending.then(() => undefined, () => undefined)
    return pending
  }

  #scheduleRetry(): void {
    if (!this.#watch || this.#closed || this.#retry !== undefined) return
    // A lost certificate response does not advance the head. Retrying only on
    // new-head hints would leave otherwise complete durable work stuck forever.
    this.#retry = setTimeout(() => {
      this.#retry = undefined
      void this.catchUp().catch(() => undefined)
    }, 1_000)
  }

  #isSubmission(bytes: Uint8Array): boolean {
    try {
      const envelope = decodeEnvelope(bytes)
      return equalBytes(envelope.groupRoute, this.#groupRoute) &&
        (envelope.messageType === 'candidate' || envelope.messageType === 'capability' || envelope.messageType === 'epoch-manifest')
    } catch { return false }
  }

  async #flushLocal(): Promise<void> {
    const local = [...await this.#local.history()].filter((record) => record.author === this.identity)
      .sort((a, b) => a.sequence < b.sequence ? -1 : a.sequence > b.sequence ? 1 : 0)
    for (const record of local) {
      if (!this.#isSubmission(record.payload)) continue
      const id = await recordId(record.payload)
      if (this.#acknowledged.has(id)) continue
      const accepted = await this.#records.append(record.payload, { historyId: this.#configuration.historyId, signal: this.#controller.signal })
      await this.#local.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry: adaptRecordEntry(accepted) }))
      this.#acknowledged.add(id)
    }
  }

  async #pull(requiredThrough = 0): Promise<void> {
    const historyId = this.#configuration.historyId
    const { head } = await this.#records.info({ historyId, signal: this.#controller.signal })
    if (head.position < requiredThrough) throw new Error('TENDRILLER_HEAD_BEHIND_CERTIFICATE')
    this.#previous ??= { historyId, position: 0, root: await recordGenesisRoot(historyId), bytes: 0 }
    if (head.position < this.#previous.position || head.position === this.#previous.position && head.root !== this.#previous.root) {
      throw new Error('TENDRILLER_HISTORY_CONFLICT')
    }
    const target = Math.max(requiredThrough, head.position)
    while (this.#previous.position < target) {
      const page = await this.#records.read({ historyId, after: this.#previous.position, previous: this.#previous, signal: this.#controller.signal })
      if (page.head.position < target || page.entries.length === 0) throw new Error('TENDRILLER_HISTORY_CONFLICT')
      for (const record of page.entries) {
        const entry = adaptRecordEntry(record)
        if (entry.position === head.position && entry.root !== head.root) throw new Error('TENDRILLER_HISTORY_CONFLICT')
        await this.#local.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        // This is only a delivery optimization. The durable evidence store owns
        // recovery; reopening revalidates retained bytes from genesis.
        this.#previous = { historyId, position: entry.position, root: entry.root, bytes: this.#previous.bytes + entry.bytes.length }
      }
    }
  }
}

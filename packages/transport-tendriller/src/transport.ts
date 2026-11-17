import {
  decodeRecord, recordGenesisRoot, recordId,
  type RecordLogClient, type RecordLogEntry, type RecordLogHead,
} from '@tendriller/core/records'
import {
  encodeHistoryConfiguration, encodeOrderingEvidence, verifyPrefixCertificate,
  type CoordinatedHistoryConfiguration, type OrderedRecordEntry, type PrefixCertificate,
} from '@chronolog/node-core/history'
import { decodeEnvelope, equalBytes } from '@chronolog/protocol'
import { createLedgerRecord } from '@chronolog/node-core/ledger'
import {
  MAX_EVIDENCE_BATCH_SIZE, type ChronologTransport, type EvidenceBatch, type ImmutableEvidence, type PublishOptions, type TransportRecord, type TransportStatus,
} from '@chronolog/records'

type EvidenceTransport = ChronologTransport & Required<Pick<ChronologTransport,
  'putEvidence' | 'putEvidenceBatch' | 'evidenceHistory' | 'subscribeEvidenceBatches'>>

export interface TendrillerTransportOptions {
  readonly local: ChronologTransport
  readonly records: RecordLogClient
  readonly configuration: CoordinatedHistoryConfiguration
  readonly groupRoute: Uint8Array
  /** Authenticated on-demand endpoint. Returned certificates never enter the log. */
  readonly certificate?: (signal?: AbortSignal) => Promise<PrefixCertificate>
  /** Defaults to true; false lets an application schedule explicit catch-up. */
  readonly watch?: boolean
  /** Poll finality even when application receipt hints remain quiet. */
  readonly finalityPollIntervalMs?: number
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
  readonly #finalityPollIntervalMs: number
  readonly #controller = new AbortController()
  readonly #acknowledged = new Set<string>()
  #previous: RecordLogHead | undefined
  #pending: Promise<void> = Promise.resolve()
  #stopWatch: (() => void) | undefined
  #retry: ReturnType<typeof setTimeout> | undefined
  #lastError: string | undefined
  #relayConnected = false
  #closed = false

  constructor(options: TendrillerTransportOptions) {
    const local = options.local
    if (local.putEvidence === undefined || local.putEvidenceBatch === undefined || local.evidenceHistory === undefined || local.subscribeEvidenceBatches === undefined) {
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
    this.#finalityPollIntervalMs = options.finalityPollIntervalMs ?? 1_000
    if (!Number.isSafeInteger(this.#finalityPollIntervalMs) || this.#finalityPollIntervalMs < 1 ||
        this.#finalityPollIntervalMs > 60_000) throw new Error('TENDRILLER_FINALITY_POLL_INVALID')
    if (this.#watch) {
      this.#stopWatch = this.#records.watch({
        historyId: this.#configuration.historyId, after: 0,
        onError: (error) => { this.#relayConnected = false; this.#lastError = error.message },
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
      if (this.#certificate !== undefined && this.#previous !== undefined) {
        const certificate = await this.#certificate(this.#controller.signal)
        await verifyPrefixCertificate(certificate, this.#configuration)
        await this.#local.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
        // Certification may append an idle-time closure marker. Its retained
        // bytes must arrive before the policy can use the covering certificate.
        await this.#pull(certificate.position)
      }
    }).finally(() => this.#scheduleRetry())
  }

  get(id: string): Promise<TransportRecord | undefined> { return this.#local.get(id) }
  getPayload(hash: string): Promise<Uint8Array | null> { return this.#local.getPayload(hash) }
  history(): Promise<readonly TransportRecord[]> { return this.#local.history() }
  subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord> { return this.#local.subscribe(signal) }
  putEvidence(bytes: Uint8Array): Promise<ImmutableEvidence> { return this.#local.putEvidence(bytes) }
  putEvidenceBatch(bytes: readonly Uint8Array[]): Promise<EvidenceBatch> { return this.#local.putEvidenceBatch(bytes) }
  evidenceHistory(signal?: AbortSignal): AsyncIterable<EvidenceBatch> { return this.#local.evidenceHistory(signal) }
  subscribeEvidenceBatches(signal?: AbortSignal): AsyncIterable<EvidenceBatch> { return this.#local.subscribeEvidenceBatches(signal) }
  feedContiguousThrough(feedId: string): Promise<bigint> {
    if (this.#local.feedContiguousThrough === undefined) return Promise.resolve(0n)
    return this.#local.feedContiguousThrough(feedId)
  }
  requestFeed(feedId: string): void { this.#local.requestFeed?.(feedId) }

  async status(): Promise<TransportStatus> {
    const status = await this.#local.status()
    return {
      ...status,
      connected: !this.#closed && (this.#relayConnected || (status.connected ?? status.peers.length > 0)),
      ...(this.#lastError === undefined ? {} : { lastCatchUpError: this.#lastError }),
    }
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
        this.#relayConnected = false
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
    // A quiet receipt head still needs author-time closure. The same bounded
    // poll also retries a lost certificate response without a new head hint.
    this.#retry = setTimeout(() => {
      this.#retry = undefined
      void this.catchUp().catch(() => undefined)
    }, this.#finalityPollIntervalMs)
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
      const prepared = await createLedgerRecord(record.payload)
      const id = await recordId(prepared.recordBytes)
      if (this.#acknowledged.has(id)) continue
      const accepted = await this.#records.append(prepared.recordBytes, { historyId: this.#configuration.historyId, signal: this.#controller.signal })
      await this.#local.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry: adaptRecordEntry(accepted) }))
      this.#acknowledged.add(id)
      this.#relayConnected = true
    }
  }

  async #pull(requiredThrough = 0): Promise<void> {
    const historyId = this.#configuration.historyId
    const { head } = await this.#records.info({ historyId, signal: this.#controller.signal })
    if (head.position < requiredThrough) throw new Error('TENDRILLER_HEAD_BEHIND_CERTIFICATE')
    let previous: RecordLogHead = this.#previous ?? { historyId, position: 0, root: await recordGenesisRoot(historyId), bytes: 0 }
    this.#previous = previous
    if (head.position < previous.position || head.position === previous.position && head.root !== previous.root) {
      throw new Error('TENDRILLER_HISTORY_CONFLICT')
    }
    const target = Math.max(requiredThrough, head.position)
    while (previous.position < target) {
      const limit = Math.min(MAX_EVIDENCE_BATCH_SIZE, target - previous.position)
      const page = await this.#records.read({ historyId, after: previous.position, limit, previous, signal: this.#controller.signal })
      if (page.head.position < target || page.entries.length === 0 || page.entries.length > limit) throw new Error('TENDRILLER_HISTORY_CONFLICT')
      const batch: Uint8Array[] = []
      let next: RecordLogHead = previous
      for (const record of page.entries) {
        const entry = adaptRecordEntry(record)
        if (entry.position === head.position && entry.root !== head.root) throw new Error('TENDRILLER_HISTORY_CONFLICT')
        batch.push(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        next = { historyId, position: entry.position, root: entry.root, bytes: next.bytes + entry.bytes.length }
      }
      await this.#local.putEvidenceBatch(batch)
      // Advance delivery only after the complete retained page commits. A lost
      // acknowledgement replays the same immutable page without partial exposure.
      this.#previous = next
      previous = next
    }
    this.#relayConnected = true
  }
}

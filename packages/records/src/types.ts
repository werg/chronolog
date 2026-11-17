export interface TransportRecord {
  readonly id: string
  readonly author: string
  readonly sequence: bigint
  readonly previous?: string
  readonly receivedAtMs: number
  readonly payload: Uint8Array
}

/** Content-addressed immutable proof bytes; interpretation belongs to the selected policy. */
export interface ImmutableEvidence {
  readonly id: string
  readonly bytes: Uint8Array
}

/** A bounded local publication unit; it makes no claim about proof validity. */
export type EvidenceBatch = readonly ImmutableEvidence[]
export const MAX_EVIDENCE_BATCH_SIZE = 64
export const MAX_EVIDENCE_BATCH_BYTES = 64 * 1024 * 1024

/** Validate the whole bound before copying caller-owned bytes. */
export function captureEvidenceBatch(input: readonly Uint8Array[]): readonly Uint8Array[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_EVIDENCE_BATCH_SIZE) {
    throw new Error('FEED_EVIDENCE_BATCH_INVALID')
  }
  const values: readonly Uint8Array[] = input
  let bytes = 0
  for (const item of values) {
    if (!(item instanceof Uint8Array)) throw new Error('FEED_EVIDENCE_BATCH_INVALID')
    bytes += item.length
    if (bytes > MAX_EVIDENCE_BATCH_BYTES) throw new Error('FEED_EVIDENCE_BATCH_TOO_LARGE')
  }
  return values.map(item => item.slice())
}

export interface PublishOptions {
  readonly timestampMs?: number
}

export interface TransportStatus {
  readonly identity: string
  readonly records: number
  readonly closed: boolean
  readonly peers: readonly string[]
  /** Reachable history route, including a retained log with no live feed peers. */
  readonly connected?: boolean
  readonly configuredPeers?: readonly {
    readonly feedId: string
    readonly address: string
    readonly connected: boolean
    readonly attempts: number
    readonly lastError?: string
    readonly lastProgressAt?: number
    readonly maximumSequence?: string
  }[]
  readonly lastCatchUpError?: string
  /** Per-feed local replication state derived from the transport's vector clock. */
  readonly feedStates?: readonly {
    readonly feedId: string
    /** Highest sequence for which the complete signed feed prefix is present locally. */
    readonly contiguousThrough: string
    /** Highest locally observed sequence, including any out-of-order record. */
    readonly maximumSequence: string
    readonly hasGaps: boolean
  }[]
  readonly feedsWithGaps?: number
  /** True when derived SSB indexes were rebuilt after an unclean prior exit. */
  readonly recoveredAfterUncleanClose?: boolean
}

export interface ChronologTransport {
  readonly identity: string
  publish(payload: Uint8Array, options?: PublishOptions): Promise<TransportRecord>
  /** Recover publication of an already durable local record without authoring it again. */
  ensurePublished?(record: TransportRecord): Promise<void>
  get(id: string): Promise<TransportRecord | undefined>
  /** Fetch exact content-addressed bytes from local storage or a connected peer. */
  getPayload(hash: string): Promise<Uint8Array | null>
  history(): Promise<readonly TransportRecord[]>
  subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord>
  status(): Promise<TransportStatus>
  /**
   * Highest sequence of `feedId` whose complete signed prefix is present
   * locally (0 when none). Equivalent to the matching `status().feedStates`
   * entry, but must be cheap enough to call once per ingested record.
   */
  feedContiguousThrough?(feedId: string): Promise<bigint>
  /** Replicate `feedId` from connected peers (membership tells the node which feeds matter). */
  requestFeed?(feedId: string): void
  /** Retain an entire bounded page before notifying any evidence consumer. */
  putEvidenceBatch?(bytes: readonly Uint8Array[]): Promise<EvidenceBatch>
  /** Immediate singleton publication through the same durable batch boundary. */
  putEvidence?(bytes: Uint8Array): Promise<ImmutableEvidence>
  /** A finite retained head, captured when iteration begins, in bounded batches. */
  evidenceHistory?(signal?: AbortSignal): AsyncIterable<EvidenceBatch>
  /** Only committed batches are visible; cancellation ends iteration normally. */
  subscribeEvidenceBatches?(signal?: AbortSignal): AsyncIterable<EvidenceBatch>
  close(): Promise<void>
}

export function cloneRecord(record: TransportRecord): TransportRecord {
  return {
    ...record,
    payload: record.payload.slice(),
  }
}

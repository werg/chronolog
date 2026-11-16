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
  putEvidence?(bytes: Uint8Array): Promise<ImmutableEvidence>
  evidenceHistory?(): Promise<readonly ImmutableEvidence[]>
  subscribeEvidence?(signal?: AbortSignal): AsyncIterable<ImmutableEvidence>
  close(): Promise<void>
}

export function cloneRecord(record: TransportRecord): TransportRecord {
  return {
    ...record,
    payload: record.payload.slice(),
  }
}

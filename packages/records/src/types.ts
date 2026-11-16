export interface TransportRecord {
  readonly id: string
  readonly author: string
  readonly sequence: bigint
  readonly previous?: string
  readonly receivedAtMs: number
  readonly payload: Uint8Array
}

export interface PublishOptions {
  readonly timestampMs?: number
}

export interface TransportStatus {
  readonly identity: string
  readonly records: number
  readonly closed: boolean
  readonly peers: readonly string[]
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
  get(id: string): Promise<TransportRecord | undefined>
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
  close(): Promise<void>
}

export function cloneRecord(record: TransportRecord): TransportRecord {
  return {
    ...record,
    payload: record.payload.slice(),
  }
}

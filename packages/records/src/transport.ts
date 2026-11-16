import { createFeedRecord, DEFAULT_MAX_RECORD_BYTES, type FeedCrypto, type FeedSigner } from './feed-codec.js'
import { ChangeSignal, type FeedLink, pullFeed } from './replication.js'
import type { FeedStorePort } from './store.js'
import { cloneRecord, type ChronologTransport, type ImmutableEvidence, type PublishOptions, type TransportRecord, type TransportStatus } from './types.js'

interface Connection {
  readonly link: FeedLink
  readonly controller: AbortController
  pending: Promise<void>
  evidenceAfter: bigint
  error?: string
}

/** Full local peer transport with injected storage, signer, and connections. */
export class PortableFeedTransport implements ChronologTransport {
  readonly #store: FeedStorePort
  readonly #signer: FeedSigner
  readonly #crypto: FeedCrypto
  readonly #maxRecordBytes: number
  readonly #changes = new ChangeSignal()
  readonly #wanted = new Set<string>()
  readonly #connections = new Map<string, Connection>()
  readonly #forks: TransportRecord[] = []
  #publish: Promise<unknown> = Promise.resolve()
  #closed = false

  constructor(options: { store: FeedStorePort; signer: FeedSigner; crypto: FeedCrypto; maxRecordBytes?: number }) {
    this.#store = options.store
    this.#signer = options.signer
    this.#crypto = options.crypto
    this.#maxRecordBytes = options.maxRecordBytes ?? DEFAULT_MAX_RECORD_BYTES
    this.#wanted.add(this.identity)
  }

  get identity(): string { return this.#signer.identity }

  publish(payload: Uint8Array, options: PublishOptions = {}): Promise<TransportRecord> {
    const exactPayload = payload.slice()
    const timestamp = BigInt(Math.trunc(options.timestampMs ?? Date.now()))
    const pending = this.#publish.then(async () => {
      if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
      const head = await this.#store.head(this.identity)
      const record = await createFeedRecord(this.#signer, this.#crypto, head.sequence + 1n, head.id, timestamp, exactPayload)
      if (record.raw.length > this.#maxRecordBytes) throw new Error('FEED_RECORD_TOO_LARGE')
      const result = await this.#store.append(record)
      if (result.kind !== 'appended') throw new Error(`FEED_LOCAL_APPEND_${result.kind.toUpperCase()}`)
      this.#changes.notify()
      return result.record
    })
    this.#publish = pending.catch(() => undefined)
    return pending
  }

  async get(id: string): Promise<TransportRecord | undefined> { return this.#store.get(id) }

  async history(): Promise<readonly TransportRecord[]> {
    const records: TransportRecord[] = []
    let after = 0n
    for (;;) {
      const batch = await this.#store.after(after, 4096)
      if (batch.length === 0) return records
      records.push(...batch.map(({ record }) => record))
      after = batch.at(-1)!.index
    }
  }

  async *subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord> {
    let after = 0n
    let forkCursor = this.#forks.length
    while (!this.#closed && signal?.aborted !== true) {
      const version = this.#changes.version
      const batch = await this.#store.after(after, 256)
      for (const entry of batch) { after = entry.index; yield cloneRecord(entry.record) }
      while (forkCursor < this.#forks.length) yield cloneRecord(this.#forks[forkCursor++]!)
      if (batch.length < 256) await this.#changes.wait(version, signal)
    }
  }

  async feedContiguousThrough(feed: string): Promise<bigint> { return (await this.#store.head(feed)).sequence }

  requestFeed(feed: string): void {
    if (this.#wanted.has(feed)) return
    this.#wanted.add(feed)
    for (const connection of this.#connections.values()) this.#queueSync(connection)
  }

  /** Attaches a link and starts retained catch-up. Errors remain observable and retryable. */
  connect(link: FeedLink): void {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    this.disconnect(link.identity)
    this.#wanted.add(link.identity)
    const connection: Connection = { link, controller: new AbortController(), pending: Promise.resolve(), evidenceAfter: 0n }
    this.#connections.set(link.identity, connection)
    this.#queueSync(connection)
    void (async () => {
      try {
        for await (const _hint of link.watch(connection.controller.signal)) {
          if (connection.controller.signal.aborted) return
          this.#queueSync(connection)
          await connection.pending
        }
      } catch (error) { connection.error = error instanceof Error ? error.message : String(error) }
    })()
  }

  disconnect(identity: string): void {
    this.#connections.get(identity)?.controller.abort()
    this.#connections.delete(identity)
  }

  /** Explicit repair after a missed hint; no cursor is advanced without durable storage. */
  async catchUp(): Promise<void> {
    for (const connection of this.#connections.values()) this.#queueSync(connection)
    await Promise.all([...this.#connections.values()].map((connection) => connection.pending))
    const error = [...this.#connections.values()].find((connection) => connection.error !== undefined)?.error
    if (error !== undefined) throw new Error(error)
  }

  asLink(): FeedLink {
    return {
      identity: this.identity,
      read: async (feed, after, limit) => {
        if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
        return (await this.#store.feedAfter(feed, after, limit)).map(({ raw }) => raw.slice())
      },
      readEvidence: async (after, limit) => (await this.#store.evidenceAfter(after, limit)).map(({ evidence }) => evidence.bytes.slice()),
      watch: (signal) => this.#changes.watch(signal),
    }
  }

  async putEvidence(bytes: Uint8Array): Promise<ImmutableEvidence> {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    const result = await this.#store.putEvidence(bytes)
    if (result.kind === 'appended') this.#changes.notify()
    return result.evidence
  }

  async evidenceHistory(): Promise<readonly ImmutableEvidence[]> {
    const result: ImmutableEvidence[] = []
    let after = 0n
    for (;;) {
      const batch = await this.#store.evidenceAfter(after, 256)
      if (batch.length === 0) return result
      result.push(...batch.map((item) => item.evidence))
      after = batch.at(-1)!.index
    }
  }

  async *subscribeEvidence(signal?: AbortSignal): AsyncIterable<ImmutableEvidence> {
    let after = 0n
    while (!this.#closed && !signal?.aborted) {
      const version = this.#changes.version
      const batch = await this.#store.evidenceAfter(after, 256)
      for (const item of batch) { after = item.index; yield item.evidence }
      if (batch.length < 256) await this.#changes.wait(version, signal)
    }
  }

  async status(): Promise<TransportStatus> {
    const heads = await this.#store.heads()
    const error = [...this.#connections.values()].find((connection) => connection.error !== undefined)?.error
    return {
      identity: this.identity, records: await this.#store.count(), closed: this.#closed,
      peers: [...this.#connections.keys()].sort(), feedsWithGaps: 0,
      feedStates: [...heads].map(([feedId, sequence]) => ({ feedId, contiguousThrough: String(sequence), maximumSequence: String(sequence), hasGaps: false })),
      ...(error === undefined ? {} : { lastCatchUpError: error }),
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    for (const connection of this.#connections.values()) connection.controller.abort()
    await this.#publish
    await Promise.all([...this.#connections.values()].map((connection) => connection.pending))
    this.#connections.clear()
    this.#changes.close()
    await this.#store.close()
  }

  #queueSync(connection: Connection): void {
    connection.pending = connection.pending.then(async () => {
      if (connection.controller.signal.aborted || this.#closed) return
      try {
        for (const feed of this.#wanted) {
          await pullFeed(connection.link, feed, {
            store: this.#store, crypto: this.#crypto, maxRecordBytes: this.#maxRecordBytes,
            onStored: (_record, result) => {
              if (result.kind === 'fork') this.#forks.push(result.record)
              this.#changes.notify()
            },
          }, connection.controller.signal)
        }
        while (!connection.controller.signal.aborted) {
          const batch = await connection.link.readEvidence(connection.evidenceAfter, 64)
          if (batch.length > 64) throw new Error('FEED_RANGE_TOO_LARGE')
          for (const bytes of batch) {
            await this.putEvidence(bytes)
            connection.evidenceAfter += 1n
          }
          if (batch.length < 64) break
        }
        delete connection.error
      } catch (error) { connection.error = error instanceof Error ? error.message : String(error) }
    })
  }
}

/** A tiny test/application link with exactly the same range protocol as network adapters. */
export function connectInProcess(left: PortableFeedTransport, right: PortableFeedTransport): () => void {
  left.connect(right.asLink())
  right.connect(left.asLink())
  return () => { left.disconnect(right.identity); right.disconnect(left.identity) }
}

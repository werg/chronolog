import { createFeedRecord, DEFAULT_MAX_RECORD_BYTES, type FeedCrypto, type FeedSigner } from './feed-codec.js'
import { ChangeSignal, type FeedLink, pullFeedLink } from './replication.js'
import type { FeedStorePort } from './store.js'
import { validatePayloadHash, verifyPayloadHash } from './payload.js'
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
  readonly #syncTasks = new Set<Promise<void>>()
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

  async getPayload(hash: string): Promise<Uint8Array | null> {
    validatePayloadHash(hash)
    const local = await this.#store.getPayload(hash)
    if (local !== null) return local
    let failure: Error | undefined
    for (const connection of this.#connections.values()) {
      try {
        const bytes = await connection.link.readPayload(hash)
        if (bytes === null) continue
        if (bytes.length > this.#maxRecordBytes) throw new Error('FEED_RECORD_TOO_LARGE')
        await verifyPayloadHash(hash, bytes)
        await this.#store.putPayload(bytes)
        return bytes.slice()
      } catch (error) { failure = error instanceof Error ? error : new Error(String(error)) }
    }
    if (failure !== undefined) throw failure
    return null
  }

  async history(): Promise<readonly TransportRecord[]> {
    const records: TransportRecord[] = []
    for (const read of [this.#store.after.bind(this.#store), this.#store.forksAfter.bind(this.#store)]) {
      let after = 0n
      for (;;) {
        const batch = await read(after, 4096)
        if (batch.length === 0) break
        records.push(...batch.map(({ record }) => record))
        after = batch.at(-1)!.index
      }
    }
    return records
  }

  async *subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord> {
    let after = 0n
    let forkCursor = 0n
    while (!this.#closed && signal?.aborted !== true) {
      const version = this.#changes.version
      const batch = await this.#store.after(after, 256)
      for (const entry of batch) { after = entry.index; yield cloneRecord(entry.record) }
      const forks = await this.#store.forksAfter(forkCursor, 256)
      for (const entry of forks) { forkCursor = entry.index; yield cloneRecord(entry.record) }
      if (batch.length < 256 && forks.length < 256) await this.#changes.wait(version, signal)
    }
  }

  async feedContiguousThrough(feed: string): Promise<bigint> { return (await this.#store.head(feed)).sequence }

  requestFeed(feed: string): void {
    if (this.#wanted.has(feed)) return
    this.#wanted.add(feed)
    for (const connection of this.#connections.values()) void this.#queueSync(connection)
  }

  /** Attaches a link; the returned detach belongs only to this connection. */
  connect(link: FeedLink): () => void {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    this.disconnect(link.identity)
    this.#wanted.add(link.identity)
    const connection: Connection = { link, controller: new AbortController(), pending: Promise.resolve(), evidenceAfter: 0n }
    this.#connections.set(link.identity, connection)
    void this.#queueSync(connection)
    void (async () => {
      try {
        for await (const _hint of link.watch(connection.controller.signal)) {
          if (connection.controller.signal.aborted) return
          void this.#queueSync(connection)
          await connection.pending
        }
      } catch (error) { connection.error = error instanceof Error ? error.message : String(error) }
    })()
    return () => {
      connection.controller.abort()
      if (this.#connections.get(link.identity) === connection) this.#connections.delete(link.identity)
    }
  }

  disconnect(identity: string): void {
    this.#connections.get(identity)?.controller.abort()
    this.#connections.delete(identity)
  }

  /** Copy finite advertised prefixes for the connections and feeds present at this call. */
  async catchUp(): Promise<void> {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    const connections = [...this.#connections.values()], feeds = [...this.#wanted]
    await Promise.all(connections.map(connection => this.#queueSync(connection, feeds)))
  }

  asLink(): FeedLink {
    return {
      identity: this.identity,
      head: async feed => {
        if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
        return (await this.#store.head(feed)).sequence
      },
      evidenceHead: async () => {
        if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
        return this.#store.evidenceHead()
      },
      read: async (feed, after, limit) => {
        if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
        return (await this.#store.feedAfter(feed, after, limit)).map(({ raw }) => raw.slice())
      },
      readEvidence: async (after, limit) => (await this.#store.evidenceAfter(after, limit)).map(({ evidence }) => evidence.bytes.slice()),
      readPayload: async (hash) => this.#store.getPayload(hash),
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
    await Promise.all(this.#syncTasks)
    this.#connections.clear()
    this.#changes.close()
    await this.#store.close()
  }

  #queueSync(connection: Connection, feeds = [...this.#wanted]): Promise<void> {
    const work = connection.pending.then(async () => {
      connection.controller.signal.throwIfAborted()
      if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
      await pullFeedLink(connection.link, feeds, connection, {
        store: this.#store, crypto: this.#crypto, maxRecordBytes: this.#maxRecordBytes,
        onStored: () => { this.#changes.notify() }, onEvidenceStored: () => { this.#changes.notify() },
      }, connection.controller.signal)
    })
    // A failed attempt must not poison later repair. Its caller still observes
    // that exact attempt's failure, even if the connection has been replaced.
    connection.pending = work.then(() => { delete connection.error }, (error: unknown) => {
      if (!connection.controller.signal.aborted) connection.error = error instanceof Error ? error.message : String(error)
    })
    const settled = connection.pending
    this.#syncTasks.add(settled)
    void settled.then(() => { this.#syncTasks.delete(settled) })
    return work
  }
}

/** A tiny test/application link with exactly the same range protocol as network adapters. */
export function connectInProcess(left: PortableFeedTransport, right: PortableFeedTransport): () => void {
  const detachLeft = left.connect(right.asLink()), detachRight = right.connect(left.asLink())
  return () => { detachLeft(); detachRight() }
}

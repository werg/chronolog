// Chronolog's replication transport.
//
// Connections use Secure Scuttlebutt's authenticated secret handshake and
// muxrpc (secret-stack), so feed ids and peer addresses are SSB's. Storage and
// replication are Chronolog's own: signed hash-chained feeds in one SQLite
// file (feed-store.ts) and a pull protocol in which a node asks every
// connected peer for each feed it wants, after its local head. Records have no
// size cap beyond `maxRecordBytes`, and feeds never have gaps.
import { mkdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'

import {
  createFeedRecord,
  nativeFeedCrypto,
  DEFAULT_MAX_RECORD_BYTES,
  FeedRecordError,
  FeedStore,
  type FeedKeys,
} from './feed-store.js'
import { consumeFeed, decodeBase64, pullFeed, validatePayloadHash, verifyPayloadHash, type FeedLink } from '@chronolog/records'
import type { ChronologTransport, ImmutableEvidence, PublishOptions, TransportRecord, TransportStatus } from './types.js'

const require = createRequire(import.meta.url)

export interface SsbPeer {
  readonly address: string
  readonly feedId: string
}

export interface FeedTransportOptions {
  /** Directory holding feeds.sqlite. */
  readonly path: string
  readonly secretPath?: string
  readonly keys?: FeedKeys & Readonly<Record<string, unknown>>
  readonly maxRecordBytes?: number
  readonly network?: {
    readonly listen?: {
      readonly host?: string
      readonly port: number
      readonly scope?: 'device' | 'local' | 'public'
    }
    readonly peers?: readonly SsbPeer[]
    readonly reconnect?: false | {
      readonly initialDelayMs?: number
      readonly maximumDelayMs?: number
      readonly connectTimeoutMs?: number
      /** Recycle a connected peer whose own feed stops advancing. */
      readonly staleAfterMs?: number
    }
  }
}

type PullEnd = true | Error | null
type PullSource<T> = (end: PullEnd, callback: (end: PullEnd, value?: T) => void) => void

interface Rpc {
  readonly id?: string
  readonly chronologFeeds?: { history(options: HistoryRequest): PullSource<string>; objects?(options: { after: string }): PullSource<string> }
  on?(event: string, callback: () => void): void
  close?(error?: Error | boolean, callback?: () => void): void
}

interface Server {
  readonly id: string
  connect?(address: string, callback: (error: Error | null, rpc?: Rpc) => void): void
  getAddress?(scope?: string): string | undefined
  on?(event: string, callback: (...arguments_: unknown[]) => void): void
  /** `true` also closes every peer connection; without it, close waits for peers to hang up. */
  close(force: true, callback: (error?: Error) => void): void
}

interface HistoryRequest {
  readonly feed: string
  /** Send records with a sequence greater than this (decimal string). */
  readonly after: string
}

interface ConfiguredPeer {
  address: string
  readonly feedId: string
  attempts: number
  nextAttemptAt: number
  lastError?: string
}

interface ReconnectOptions {
  readonly initialDelayMs: number
  readonly maximumDelayMs: number
  readonly connectTimeoutMs: number
  readonly staleAfterMs?: number
}

interface FramedLinkConnection {
  readonly link: FeedLink
  readonly controller: AbortController
  pending: Promise<void>
  evidenceAfter: bigint
  error?: string
}

const HISTORY_BATCH = 64
const SUBSCRIPTION_BATCH = 256
const RESTREAM_DELAY_MS = 250

export class FeedTransport implements ChronologTransport {
  readonly #server: Server
  readonly #store: FeedStore
  readonly #keys: FeedKeys
  readonly #maxRecordBytes: number
  readonly #wanted = new Set<string>()
  readonly #connections = new Map<string, Set<Rpc>>()
  readonly #links = new Map<string, FramedLinkConnection>()
  readonly #streams = new Map<Rpc, Map<string, () => void>>()
  readonly #configured = new Map<string, ConfiguredPeer>()
  readonly #progress = new Map<string, number>()
  readonly #connecting = new Set<string>()
  readonly #waiters = new Set<() => void>()
  #reconnect?: ReconnectOptions
  #reconnectTimer?: ReturnType<typeof setInterval>
  /**
   * The current error of each live stream, by connection and feed. An entry
   * clears when that stream makes progress or its connection closes, so a
   * peer restart does not leave the node degraded after it reconnects.
   */
  readonly #streamErrors = new Map<Rpc, Map<string, string>>()
  /** Incremented on every stored change; lets readers wait without losing a wakeup. */
  #version = 0
  #closed = false

  private constructor(server: Server, store: FeedStore, keys: FeedKeys, maxRecordBytes: number) {
    this.#server = server
    this.#store = store
    this.#keys = keys
    this.#maxRecordBytes = maxRecordBytes
    this.#wanted.add(keys.id)
    server.on?.('rpc:connect', (...arguments_: unknown[]) => {
      const rpc = arguments_[0] as Rpc | undefined
      if (rpc?.id !== undefined) this.#register(rpc.id, rpc)
    })
  }

  static async open(options: FeedTransportOptions): Promise<FeedTransport> {
    const reconnect = parseReconnectOptions(options.network?.reconnect)
    await mkdir(options.path, { recursive: true })
    const store = new FeedStore(join(options.path, 'feeds.sqlite'))
    let server: Server | undefined
    try {
      const ssbKeys = require('ssb-keys') as { loadOrCreateSync(path: string): FeedKeys }
      const keys = options.keys ?? ssbKeys.loadOrCreateSync(options.secretPath ?? join(dirname(options.path), 'secret'))
      const maxRecordBytes = options.maxRecordBytes ?? DEFAULT_MAX_RECORD_BYTES
      const ready: { transport?: FeedTransport } = {}
      const plugin = {
        name: 'chronologFeeds',
        version: '1.0.0',
        manifest: { history: 'source', objects: 'source' },
        permissions: { anonymous: { allow: ['history', 'objects'] } },
        init: () => ({
          history: (request: HistoryRequest): PullSource<string> => {
            if (ready.transport === undefined) return (_end, callback) => callback(new Error('FEED_TRANSPORT_STARTING'))
            return ready.transport.#historySource(request)
          },
          objects: (request: { after: string }): PullSource<string> => {
            if (ready.transport === undefined) return (_end, callback) => callback(new Error('FEED_TRANSPORT_STARTING'))
            return ready.transport.#evidenceSource(request)
          },
        }),
      }
      const SecretStack = require('secret-stack') as (options: unknown) => { use(plugin: unknown): { call(context: null, config: unknown): Server } }
      const caps = require('ssb-caps') as unknown
      server = SecretStack({ caps }).use(plugin).call(null, {
        keys,
        path: options.path,
        ...(options.network === undefined ? {} : {
          connections: {
            incoming: options.network.listen === undefined ? {} : {
              net: [{
                host: options.network.listen.host ?? '127.0.0.1',
                port: options.network.listen.port,
                scope: options.network.listen.scope ?? 'device',
                transform: 'shs',
              }],
            },
            outgoing: { net: [{ transform: 'shs' }] },
          },
        }),
      })
      const created = new FeedTransport(server, store, keys, maxRecordBytes)
      ready.transport = created
      if (reconnect !== undefined) {
        created.#reconnect = reconnect
        created.configurePeers(options.network?.peers ?? [])
        created.#reconnectTimer = setInterval(() => { void created.#reconnectTick() }, reconnect.initialDelayMs)
        created.#reconnectTimer.unref?.()
      } else {
        for (const peer of options.network?.peers ?? []) {
          created.#wanted.add(peer.feedId)
          await created.connect(peer)
        }
      }
      return created
    } catch (error) {
      if (server !== undefined) await closeServer(server).catch(() => undefined)
      store.close()
      throw error
    }
  }

  get identity(): string { return this.#keys.id }

  address(scope: 'device' | 'local' | 'public' = 'device'): string | undefined {
    try { return this.#server.getAddress?.(scope) } catch { return undefined }
  }

  /** Replicate `feedId` from every connected peer. */
  requestFeed(feedId: string): void {
    if (this.#wanted.has(feedId)) return
    this.#wanted.add(feedId)
    for (const rpc of this.#streams.keys()) this.#startStream(rpc, feedId)
    for (const connection of this.#links.values()) this.#queueLinkSync(connection)
  }

  /** Attach a grant-authenticated link; detach only this connection on cleanup. */
  connectLink(link: FeedLink): () => void {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    this.disconnectLink(link.identity)
    this.#wanted.add(link.identity)
    const connection: FramedLinkConnection = { link, controller: new AbortController(), pending: Promise.resolve(), evidenceAfter: 0n }
    this.#links.set(link.identity, connection)
    this.#queueLinkSync(connection)
    void (async () => {
      try {
        for await (const _hint of link.watch(connection.controller.signal)) {
          if (connection.controller.signal.aborted) return
          this.#queueLinkSync(connection)
          await connection.pending
        }
      } catch (error) {
        if (!connection.controller.signal.aborted) connection.error = errorMessage(error)
      }
    })()
    return () => {
      connection.controller.abort()
      if (this.#links.get(link.identity) === connection) this.#links.delete(link.identity)
    }
  }

  disconnectLink(identity: string): void {
    this.#links.get(identity)?.controller.abort()
    this.#links.delete(identity)
  }

  async catchUpLinks(): Promise<void> {
    const connections = [...this.#links.values()]
    for (const connection of connections) this.#queueLinkSync(connection)
    await Promise.all(connections.map((connection) => connection.pending))
    const failed = connections.find((connection) => connection.error !== undefined)
    if (failed?.error !== undefined) throw new Error(failed.error)
  }

  /** Replace the configured peers; their feeds become wanted. */
  configurePeers(peers: readonly SsbPeer[]): void {
    const next = new Set(peers.map((peer) => peer.feedId))
    for (const feedId of this.#configured.keys()) if (!next.has(feedId)) this.#configured.delete(feedId)
    for (const peer of peers) {
      if (!peer.feedId.startsWith('@') || peer.address.length === 0) throw new Error('SSB_PEER_INVALID')
      this.requestFeed(peer.feedId)
      const current = this.#configured.get(peer.feedId)
      if (current !== undefined) {
        current.address = peer.address
        current.nextAttemptAt = Math.min(current.nextAttemptAt, Date.now())
      } else {
        this.#configured.set(peer.feedId, { ...peer, attempts: 0, nextAttemptAt: Date.now() })
        this.#progress.set(peer.feedId, Date.now())
      }
    }
    void this.#reconnectTick()
  }

  async connect(peer: SsbPeer): Promise<void> {
    if (this.#closed) throw new Error('transport is closed')
    if (this.#server.connect === undefined) throw new Error('SSB_NETWORK_UNAVAILABLE')
    this.requestFeed(peer.feedId)
    await new Promise<void>((resolve, reject) => {
      this.#server.connect!(peer.address, (error, rpc) => {
        if (error) reject(error)
        else {
          if (rpc !== undefined) this.#register(rpc.id ?? peer.feedId, rpc)
          resolve()
        }
      })
    })
  }

  async publish(payload: Uint8Array, options: PublishOptions = {}): Promise<TransportRecord> {
    if (this.#closed) throw new Error('transport is closed')
    const head = this.#store.head(this.#keys.id)
    const record = createFeedRecord(this.#keys, head.sequence + 1n, head.id, BigInt(Math.trunc(options.timestampMs ?? Date.now())), payload)
    if (record.raw.length > this.#maxRecordBytes) throw new FeedRecordError('FEED_RECORD_TOO_LARGE')
    const result = this.#store.append(record)
    if (result.kind !== 'appended') throw new Error(`FEED_LOCAL_APPEND_${result.kind.toUpperCase()}`)
    this.#notify()
    return result.record
  }

  async get(id: string): Promise<TransportRecord | undefined> {
    return this.#store.get(id)
  }

  async getPayload(hash: string): Promise<Uint8Array | null> {
    validatePayloadHash(hash)
    const local = this.#store.getPayload(hash)
    if (local !== null) return local
    let failure: Error | undefined
    for (const connection of this.#links.values()) {
      try {
        const bytes = await connection.link.readPayload(hash)
        if (bytes === null) continue
        if (bytes.length > this.#maxRecordBytes) throw new Error('FEED_RECORD_TOO_LARGE')
        await verifyPayloadHash(hash, bytes)
        this.#store.putPayload(bytes)
        return bytes.slice()
      } catch (error) { failure = error instanceof Error ? error : new Error(String(error)) }
    }
    if (failure !== undefined) throw failure
    return null
  }

  async history(): Promise<readonly TransportRecord[]> {
    const records: TransportRecord[] = []
    for (const read of [this.#store.after.bind(this.#store), this.#store.forksAfter.bind(this.#store)]) {
      let cursor = 0n
      for (;;) {
        const batch = read(cursor, 4_096)
        if (batch.length === 0) break
        for (const entry of batch) records.push(entry.record)
        cursor = batch[batch.length - 1]!.index
      }
    }
    return records
  }

  /** Public retained-range port for authenticated direct or relayed frame adapters. */
  asLink(): FeedLink {
    const transport = this
    const range = (after: bigint, limit: number): void => {
      if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
      if (after < 0n || after > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(limit) || limit < 1 || limit > 4096) {
        throw new Error('FEED_RANGE_INVALID')
      }
    }
    return {
      identity: this.identity,
      read: async (feed, after, limit) => {
        range(after, limit)
        return this.#store.feedAfter(feed, after, limit).map(({ raw }) => raw.slice())
      },
      readEvidence: async (after, limit) => {
        range(after, limit)
        return this.#store.evidenceAfter(after, limit).map(({ evidence }) => evidence.bytes.slice())
      },
      readPayload: async (hash) => this.#store.getPayload(hash),
      async *watch(signal) {
        while (!transport.#closed && signal?.aborted !== true) {
          const version = transport.#version
          yield undefined
          await transport.#waitForChange(version, signal)
        }
      },
    }
  }

  /**
   * Every stored record once, in local arrival order, then each new one as it
   * is stored; a conflicting record for an existing sequence (fork evidence)
   * is replayed from durable storage and delivered as it is seen.
   */
  subscribe(signal?: AbortSignal): AsyncIterable<TransportRecord> {
    const transport = this
    return {
      async *[Symbol.asyncIterator]() {
        let cursor = 0n
        let forkCursor = 0n
        while (!transport.#closed && signal?.aborted !== true) {
          const version = transport.#version
          const batch = transport.#store.after(cursor, SUBSCRIPTION_BATCH)
          for (const entry of batch) {
            cursor = entry.index
            yield entry.record
          }
          const forks = transport.#store.forksAfter(forkCursor, SUBSCRIPTION_BATCH)
          for (const entry of forks) { forkCursor = entry.index; yield entry.record }
          if (batch.length < SUBSCRIPTION_BATCH && forks.length < SUBSCRIPTION_BATCH) await transport.#waitForChange(version, signal)
        }
      },
    }
  }

  async putEvidence(bytes: Uint8Array): Promise<ImmutableEvidence> {
    if (this.#closed) throw new Error('FEED_TRANSPORT_CLOSED')
    const result = this.#store.putEvidence(bytes)
    if (result.kind === 'appended') this.#notify()
    return result.evidence
  }

  async evidenceHistory(): Promise<readonly ImmutableEvidence[]> {
    const result: ImmutableEvidence[] = []
    let after = 0n
    for (;;) {
      const batch = this.#store.evidenceAfter(after, 256)
      if (batch.length === 0) return result
      result.push(...batch.map((entry) => entry.evidence))
      after = batch.at(-1)!.index
    }
  }

  async *subscribeEvidence(signal?: AbortSignal): AsyncIterable<ImmutableEvidence> {
    let after = 0n
    while (!this.#closed && !signal?.aborted) {
      const version = this.#version
      const batch = this.#store.evidenceAfter(after, 256)
      for (const entry of batch) { after = entry.index; yield entry.evidence }
      if (batch.length < 256) await this.#waitForChange(version, signal)
    }
  }

  async feedContiguousThrough(feedId: string): Promise<bigint> {
    return this.#store.head(feedId).sequence
  }

  async status(): Promise<TransportStatus> {
    const heads = this.#store.heads()
    const feedIds = new Set([...heads.keys(), ...this.#configured.keys()])
    const feedStates = [...feedIds].sort().map((feedId) => {
      const sequence = (heads.get(feedId) ?? 0n).toString(10)
      return { feedId, contiguousThrough: sequence, maximumSequence: sequence, hasGaps: false }
    })
    return {
      identity: this.identity,
      records: this.#store.count(),
      closed: this.#closed,
      peers: [...new Set([...this.#connections.keys(), ...this.#links.keys()])].sort(),
      configuredPeers: [...this.#configured.values()]
        .sort((left, right) => left.feedId.localeCompare(right.feedId))
        .map((peer) => ({
          feedId: peer.feedId,
          address: peer.address,
          connected: this.#connections.has(peer.feedId),
          attempts: peer.attempts,
          ...(peer.lastError === undefined ? {} : { lastError: peer.lastError }),
          ...(this.#progress.has(peer.feedId) ? { lastProgressAt: this.#progress.get(peer.feedId)! } : {}),
          maximumSequence: (heads.get(peer.feedId) ?? 0n).toString(10),
        })),
      feedStates,
      feedsWithGaps: 0,
      ...(this.#lastStreamError() === undefined ? {} : { lastCatchUpError: this.#lastStreamError()! }),
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true
    if (this.#reconnectTimer !== undefined) clearInterval(this.#reconnectTimer)
    for (const streams of this.#streams.values()) for (const stop of streams.values()) stop()
    this.#streams.clear()
    const links = [...this.#links.values()]
    for (const connection of links) connection.controller.abort()
    this.#links.clear()
    this.#notify()
    await closeServer(this.#server)
    await Promise.all(links.map((connection) => connection.pending))
    this.#store.close()
  }

  // ── replication ────────────────────────────────────────────────────────

  #queueLinkSync(connection: FramedLinkConnection): void {
    connection.pending = connection.pending.then(async () => {
      if (connection.controller.signal.aborted || this.#closed) return
      try {
        for (const feed of this.#wanted) {
          await pullFeed(connection.link, feed, { store: this.#store, crypto: nativeFeedCrypto,
            maxRecordBytes: this.#maxRecordBytes,
            onStored: (record, result) => {
              if (result.kind === 'appended') this.#progress.set(record.author, Date.now())
              this.#notify()
            },
          }, connection.controller.signal)
        }
        while (!connection.controller.signal.aborted) {
          const batch = await connection.link.readEvidence(connection.evidenceAfter, 64)
          if (batch.length > 64) throw new Error('FEED_RANGE_TOO_LARGE')
          for (const bytes of batch) {
            if (connection.controller.signal.aborted) return
            await this.putEvidence(bytes)
            connection.evidenceAfter += 1n
          }
          if (batch.length < 64) break
        }
        delete connection.error
      } catch (error) {
        if (!connection.controller.signal.aborted) connection.error = errorMessage(error)
      }
    })
  }

  #register(feedId: string, rpc: Rpc): void {
    if (this.#closed || this.#streams.has(rpc)) return
    const connections = this.#connections.get(feedId) ?? new Set<Rpc>()
    connections.add(rpc)
    this.#connections.set(feedId, connections)
    this.#streams.set(rpc, new Map())
    for (const feed of this.#wanted) this.#startStream(rpc, feed)
    this.#startEvidence(rpc)
    let closed = false
    rpc.on?.('closed', () => {
      if (closed) return
      closed = true
      for (const stop of this.#streams.get(rpc)?.values() ?? []) stop()
      this.#streams.delete(rpc)
      this.#streamErrors.delete(rpc)
      connections.delete(rpc)
      if (connections.size === 0) this.#connections.delete(feedId)
      const configured = this.#configured.get(feedId)
      if (configured !== undefined) configured.nextAttemptAt = Date.now()
    })
  }

  /** Pull `feed` from `rpc` after the local head, live, until either side stops. */
  #startStream(rpc: Rpc, feed: string): void {
    const streams = this.#streams.get(rpc)
    if (this.#closed || streams === undefined || streams.has(feed) || rpc.chronologFeeds === undefined) return
    let source: PullSource<string>
    try {
      source = rpc.chronologFeeds.history({ feed, after: this.#store.head(feed).sequence.toString(10) })
    } catch (error) {
      this.#setStreamError(rpc, feed, error)
      return
    }
    const controller = new AbortController()
    let stopped = false
    const stop = (): void => {
      if (stopped) return
      stopped = true
      streams.delete(feed)
      controller.abort()
    }
    streams.set(feed, stop)
    void consumeFeed(pullRecords(source, controller.signal), {
      store: this.#store, crypto: nativeFeedCrypto, feed, maxRecordBytes: this.#maxRecordBytes,
      onStored: (record, result) => {
        this.#clearStreamError(rpc, feed)
        if (result.kind === 'appended' && this.#configured.has(record.author)) this.#progress.set(record.author, Date.now())
        this.#notify()
      },
    }, controller.signal).catch((error: unknown) => {
      if (!stopped) this.#setStreamError(rpc, feed, error)
    }).finally(() => {
      if (stopped) return
      stopped = true
      streams.delete(feed)
      this.#restreamLater(rpc, feed)
    })
  }

  #startEvidence(rpc: Rpc, after = 0n): void {
    const streams = this.#streams.get(rpc)
    const key = '__immutable_evidence__'
    if (this.#closed || streams === undefined || streams.has(key) || rpc.chronologFeeds?.objects === undefined) return
    const controller = new AbortController()
    let stopped = false
    let source: PullSource<string>
    try { source = rpc.chronologFeeds.objects({ after: after.toString(10) }) } catch (error) {
      this.#setStreamError(rpc, key, error)
      return
    }
    streams.set(key, () => { stopped = true; controller.abort(); streams.delete(key) })
    void (async () => {
      for await (const raw of pullRecords(source, controller.signal)) {
        await this.putEvidence(raw)
        after += 1n
        this.#clearStreamError(rpc, key)
      }
    })().catch((error: unknown) => { if (!stopped) this.#setStreamError(rpc, key, error) }).finally(() => {
      if (stopped) return
      streams.delete(key)
      const timer = setTimeout(() => { if (this.#streams.has(rpc)) this.#startEvidence(rpc, after) }, RESTREAM_DELAY_MS)
      timer.unref?.()
    })
  }

  #restreamLater(rpc: Rpc, feed: string): void {
    const timer = setTimeout(() => { if (this.#streams.has(rpc)) this.#startStream(rpc, feed) }, RESTREAM_DELAY_MS)
    timer.unref?.()
  }

  #setStreamError(rpc: Rpc, feed: string, error: unknown): void {
    // A stream of a connection that already closed is gone; its error is moot.
    if (!this.#streams.has(rpc)) return
    const errors = this.#streamErrors.get(rpc) ?? new Map<string, string>()
    errors.set(feed, errorMessage(error))
    this.#streamErrors.set(rpc, errors)
  }

  #clearStreamError(rpc: Rpc, feed: string): void {
    const errors = this.#streamErrors.get(rpc)
    if (errors === undefined) return
    errors.delete(feed)
    if (errors.size === 0) this.#streamErrors.delete(rpc)
  }

  #lastStreamError(): string | undefined {
    for (const errors of this.#streamErrors.values()) for (const error of errors.values()) return error
    for (const connection of this.#links.values()) if (connection.error !== undefined) return connection.error
    return undefined
  }

  /** Serve one feed's signed records after `after`, then live appends. */
  #historySource(request: HistoryRequest): PullSource<string> {
    let cursor: bigint
    try {
      cursor = BigInt(request.after)
      if (typeof request.feed !== 'string' || cursor < 0n) throw new Error('invalid')
    } catch {
      return (_end, callback) => callback(new Error('FEED_HISTORY_REQUEST_INVALID'))
    }
    return this.#rangeSource(cursor, (after) => this.#store.feedAfter(request.feed, after, HISTORY_BATCH))
  }

  #evidenceSource(request: { after: string }): PullSource<string> {
    let cursor: bigint
    try { cursor = BigInt(request.after); if (cursor < 0n) throw new Error('invalid') } catch {
      return (_end, callback) => callback(new Error('FEED_HISTORY_REQUEST_INVALID'))
    }
    return this.#rangeSource(cursor, (after) => this.#store.evidenceAfter(after, HISTORY_BATCH)
      .map((entry) => ({ sequence: entry.index, raw: entry.evidence.bytes })))
  }

  #rangeSource(cursor: bigint, read: (after: bigint) => readonly { readonly sequence: bigint; readonly raw: Uint8Array }[]): PullSource<string> {
    const buffer: string[] = []
    let ended = false
    let cancelWait: (() => void) | undefined
    return (end, callback) => {
      if (end) {
        ended = true
        cancelWait?.()
        callback(end)
        return
      }
      const deliver = (): void => {
        if (ended || this.#closed) {
          callback(true)
          return
        }
        if (buffer.length === 0) {
          for (const row of read(cursor)) {
            buffer.push(Buffer.from(row.raw).toString('base64'))
            cursor = row.sequence
          }
        }
        if (buffer.length > 0) {
          callback(null, buffer.shift())
          return
        }
        const waiter = (): void => {
          this.#waiters.delete(waiter)
          cancelWait = undefined
          deliver()
        }
        cancelWait = () => {
          this.#waiters.delete(waiter)
          cancelWait = undefined
        }
        this.#waiters.add(waiter)
      }
      deliver()
    }
  }

  #notify(): void {
    this.#version += 1
    for (const waiter of [...this.#waiters]) waiter()
  }

  /** Resolves once anything changed after `version` was read (or immediately if it already has). */
  #waitForChange(version: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
      const done = (): void => {
        this.#waiters.delete(done)
        signal?.removeEventListener('abort', done)
        resolve()
      }
      this.#waiters.add(done)
      signal?.addEventListener('abort', done, { once: true })
      if (this.#closed || signal?.aborted === true || this.#version !== version) done()
    })
  }

  async #reconnectTick(): Promise<void> {
    if (this.#closed || this.#reconnect === undefined) return
    const now = Date.now()
    await Promise.all([...this.#configured.values()].map(async (peer) => {
      const stale = this.#reconnect!.staleAfterMs !== undefined &&
        now - (this.#progress.get(peer.feedId) ?? now) >= this.#reconnect!.staleAfterMs
      if (this.#connections.has(peer.feedId) && !stale) return
      if (stale) this.#recycle(peer.feedId, now)
      if (this.#connecting.has(peer.feedId) || peer.nextAttemptAt > now) return
      this.#connecting.add(peer.feedId)
      try {
        await withTimeout(this.connect(peer), this.#reconnect!.connectTimeoutMs)
        peer.attempts = 0
        peer.nextAttemptAt = Number.MAX_SAFE_INTEGER
        delete peer.lastError
      } catch (error) {
        peer.attempts += 1
        peer.lastError = errorMessage(error)
        const delay = Math.min(
          this.#reconnect!.maximumDelayMs,
          this.#reconnect!.initialDelayMs * 2 ** Math.min(peer.attempts - 1, 20),
        )
        peer.nextAttemptAt = Date.now() + delay
      } finally {
        this.#connecting.delete(peer.feedId)
      }
    }))
  }

  #recycle(feedId: string, now: number): void {
    this.#progress.set(feedId, now)
    for (const rpc of this.#connections.get(feedId) ?? []) rpc.close?.(new Error('FEED_PROGRESS_STALE'), () => {})
    const configured = this.#configured.get(feedId)
    if (configured !== undefined) configured.nextAttemptAt = now
  }
}

function positiveInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`SSB_RECONNECT_INVALID_${field.toUpperCase()}`)
  return value
}

function parseReconnectOptions(
  value: NonNullable<FeedTransportOptions['network']>['reconnect'] | undefined,
): ReconnectOptions | undefined {
  if (value === false) return undefined
  const reconnect = value ?? {}
  const options: ReconnectOptions = {
    initialDelayMs: positiveInteger(reconnect.initialDelayMs ?? 250, 'initialDelayMs'),
    maximumDelayMs: positiveInteger(reconnect.maximumDelayMs ?? 10_000, 'maximumDelayMs'),
    connectTimeoutMs: positiveInteger(reconnect.connectTimeoutMs ?? 5_000, 'connectTimeoutMs'),
    ...(reconnect.staleAfterMs === undefined ? {} : { staleAfterMs: positiveInteger(reconnect.staleAfterMs, 'staleAfterMs') }),
  }
  if (options.maximumDelayMs < options.initialDelayMs) throw new Error('SSB_RECONNECT_MAXIMUM_BEFORE_INITIAL')
  return options
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close(true, (error) => {
    if (error && !(typeof error === 'object' && 'code' in error && error.code === 'ERR_SERVER_NOT_RUNNING')) reject(error)
    else resolve()
  }))
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('SSB_CONNECT_TIMEOUT')), timeoutMs)
    timer.unref?.()
    promise.then(
      (value) => { clearTimeout(timer); resolve(value) },
      (error: unknown) => { clearTimeout(timer); reject(error) },
    )
  })
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Adapt SSB pull callbacks to the portable authenticated record consumer. */
async function* pullRecords(source: PullSource<string>, signal: AbortSignal): AsyncIterable<Uint8Array> {
  try {
    while (!signal.aborted) {
      const next = await new Promise<{ readonly ended: true } | { readonly ended: false; readonly value: string }>((resolve, reject) => {
        let settled = false
        const abort = (): void => {
          if (settled) return
          settled = true
          source(true, () => {})
          resolve({ ended: true })
        }
        signal.addEventListener('abort', abort, { once: true })
        source(null, (end, value) => {
          if (settled) return
          settled = true
          signal.removeEventListener('abort', abort)
          if (end instanceof Error) reject(end)
          else if (end === true) resolve({ ended: true })
          else if (typeof value !== 'string') reject(new FeedRecordError('FEED_RECORD_MALFORMED'))
          else resolve({ ended: false, value })
        })
        if (signal.aborted) abort()
      })
      if (next.ended) return
      yield decodeBase64(next.value)
    }
  } finally { source(true, () => {}) }
}

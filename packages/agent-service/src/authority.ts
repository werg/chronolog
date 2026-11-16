import {
  Mutex, ReferenceRecordLog, createPrefixAuthority, encodeHistoryConfiguration, encodeOrderingEvidence, orderedGenesisRoot,
} from '@chronolog/node-core'
import type {
  CoordinatedHistoryConfiguration, DurableOperationStore, OrderedRecordEntry, OrderedRecordHead, PrefixCertificate,
} from '@chronolog/node-core'
import { decodeEnvelope, equalBytes } from '@chronolog/protocol'
import type { Ed25519KeyPair } from '@chronolog/protocol'
import type { ChronologTransport } from '@chronolog/records'

export interface EvidenceSink { putEvidence(bytes: Uint8Array): Promise<unknown> }

export interface NativeAuthorityOptions {
  readonly configuration: CoordinatedHistoryConfiguration
  readonly identity: Ed25519KeyPair
  /** Must have one fenced storage owner, e.g. NativeAgentStore. */
  readonly store: DurableOperationStore
  readonly quotaBytes?: number
  /**
   * An independently trusted continuity checkpoint when recovering a volume.
   * Reading this from the same restored backup cannot detect rollback. An
   * operator without established continuity must create a new history lineage.
   */
  readonly continuity?: OrderedRecordHead
}

const authorityLocks = new WeakMap<DurableOperationStore, Map<string, Mutex>>()
function authorityLock(store: DurableOperationStore, historyId: string): Mutex {
  let histories = authorityLocks.get(store)
  if (histories === undefined) { histories = new Map(); authorityLocks.set(store, histories) }
  let lock = histories.get(historyId)
  if (lock === undefined) { lock = new Mutex(); histories.set(historyId, lock) }
  return lock
}

/** The fixed agent authority owns order only; SQL and event success stay in replicas. */
export class NativeAuthority {
  readonly #configuration: CoordinatedHistoryConfiguration
  readonly #log: ReferenceRecordLog
  readonly #signer: ReturnType<typeof createPrefixAuthority>
  readonly #store: DurableOperationStore
  readonly #mutex: Mutex

  private constructor(options: NativeAuthorityOptions, log: ReferenceRecordLog) {
    this.#configuration = structuredClone(options.configuration)
    this.#log = log
    this.#store = options.store
    this.#mutex = authorityLock(options.store, options.configuration.historyId)
    this.#signer = createPrefixAuthority({ configuration: this.#configuration, identity: options.identity, readHead: () => log.head() })
  }

  static async open(options: NativeAuthorityOptions): Promise<NativeAuthority> {
    return authorityLock(options.store, options.configuration.historyId).run(async () => {
    const configuration = encodeHistoryConfiguration(options.configuration)
    const key = `agent/authority/${options.configuration.historyId}/configuration`
    const saved = await options.store.get(key)
    if (saved !== null && !equalBytes(saved, configuration)) throw new Error('AUTHORITY_CONFIGURATION_MISMATCH')
    // Validate key ownership before creating any durable authority state.
    createPrefixAuthority({ configuration: options.configuration, identity: options.identity,
      readHead: async () => { throw new Error('AUTHORITY_NOT_OPEN') } })
    const log = await ReferenceRecordLog.open(options.configuration.historyId, options.store, options.quotaBytes)
    if (options.continuity !== undefined) {
      const expected = options.continuity
      const entries = await log.read()
      const current = await log.head()
      if (expected.historyId !== current.historyId || !Number.isSafeInteger(expected.position) ||
          expected.position < 0 || expected.position > current.position ||
          (expected.position === 0 ? await orderedGenesisRoot(current.historyId) :
            entries[expected.position - 1]?.root) !== expected.root) {
        throw new Error('AUTHORITY_CONTINUITY_NOT_ESTABLISHED')
      }
    }
    if (saved === null) await options.store.put(key, configuration)
    return new NativeAuthority(options, log)
    })
  }

  get configuration(): CoordinatedHistoryConfiguration { return structuredClone(this.#configuration) }
  head(): Promise<OrderedRecordHead> { return this.#log.head() }

  /** Exact bytes, deduplication, position and prefix root commit before return. */
  append(bytes: Uint8Array): Promise<OrderedRecordEntry> {
    const exact = bytes.slice()
    return this.#mutex.run(() => this.#log.append(exact))
  }

  /** The only signing input is this authority's own committed native head. */
  certify(): Promise<PrefixCertificate> {
    return this.#mutex.run(async () => {
      const certificate = await this.#signer.certify()
      await this.#store.put(`agent/authority/${this.#configuration.historyId}/certificate`,
        encodeOrderingEvidence({ kind: 'prefix-certificate', certificate }))
      return certificate
    })
  }

  async read(options: { readonly after?: number; readonly limit?: number } = {}): Promise<{
    readonly entries: readonly OrderedRecordEntry[]
    readonly head: OrderedRecordHead
    readonly hasMore: boolean
  }> {
    const after = options.after ?? 0, limit = options.limit ?? 64
    if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
      throw new Error('AUTHORITY_RANGE_INVALID')
    }
    return this.#mutex.run(async () => {
      const entries = await this.#log.read()
      const head = await this.#log.head()
      if (after > head.position) throw new Error('AUTHORITY_RANGE_AHEAD')
      return { entries: entries.slice(after, after + limit), head, hasMore: after + limit < entries.length }
    })
  }

  /** Re-publishing retained evidence is idempotent and never authors another proposal. */
  async share(sink: EvidenceSink, options: { readonly after?: number; readonly limit?: number } = {}): Promise<OrderedRecordHead> {
    const range = await this.read(options)
    for (const entry of range.entries) await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await this.certify() }))
    const last = range.entries.at(-1)
    return last === undefined ? range.head : { historyId: last.historyId, position: last.position, root: last.root }
  }

  /**
   * Resident ordering loop over a durable replaying transport subscription.
   * The stream must include retained history before continuing live. Records
   * are already feed-authenticated; replicas verify inner authorship, grants,
   * governance and outcomes. Certificates are evidence, never log submissions.
   */
  async serve(transport: ChronologTransport, signal?: AbortSignal): Promise<void> {
    if (transport.putEvidence === undefined) throw new Error('AUTHORITY_EVIDENCE_TRANSPORT_REQUIRED')
    const sink: EvidenceSink = { putEvidence: (bytes) => transport.putEvidence!(bytes) }
    // Republish durable commitments even if the prior process stopped between
    // ordering and evidence delivery. Ordinary range sync can relay these later.
    let after = 0
    for (;;) {
      if (signal?.aborted) return
      const range = await this.read({ after })
      for (const entry of range.entries) {
        await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
        after = entry.position
      }
      if (!range.hasMore) break
    }
    await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await this.certify() }))
    for await (const record of transport.subscribe(signal)) {
      if (signal?.aborted) return
      let type: string
      try { type = decodeEnvelope(record.payload).messageType } catch { continue }
      if (type !== 'candidate' && type !== 'capability' && type !== 'epoch-manifest') continue
      const entry = await this.append(record.payload)
      await sink.putEvidence(encodeOrderingEvidence({ kind: 'ordered-entry', entry }))
      await sink.putEvidence(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await this.certify() }))
    }
  }
}

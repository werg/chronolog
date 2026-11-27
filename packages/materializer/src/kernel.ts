import {
  bytesToHex,
  encodeCanonicalCbor,
  hashDomainSync,
  type CborValue,
} from '@chronolog/canonical'
import {
  assertValidReducersConfig,
  canonicalJson,
  compareOperationOrder,
  decodeLogGenesis,
  encodeCanonicalJsonCbor,
  encodeLogGenesis,
  genesisLogId,
  isControlTopic,
  jsonToCbor,
  normalizeJsonValue,
  operationIdDigest,
  type LogGenesis,
  type JsonValue,
  type OperationAssumption,
  type OperationCore,
  type OperationVisibility,
  type ReducersConfig,
} from '@chronolog/protocol'
import type { CasPartition, ContentAddressedStore } from '@chronolog/records'
import {
  MissingDependencyError,
  QuickJsSandbox,
  type QuickJsSandboxOptions,
} from './quickjs-sandbox.js'

export interface KernelOperationInput {
  readonly opId: Uint8Array
  readonly core: OperationCore
  /** Caller already verified opId === operationIdDigest(core); skips O(N) CBOR+SHA-256 re-verification on every materialize(). */
  readonly verified?: boolean
}

export interface EmittedKernelEvent {
  readonly opId: string
  readonly eventOrdinal: number
  readonly topic: string
  readonly payload: JsonValue
  readonly author: string
  readonly operationId: string
  readonly authorTimestampMs: bigint
}

export interface KernelOperationOutcome {
  readonly opId: string
  readonly author: string
  readonly operationId: string
  readonly authorTimestampMs: bigint
  readonly visibility: OperationVisibility
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
  readonly rejectionDetail?: string
  readonly conflictRecorded?: boolean
  readonly events: readonly EmittedKernelEvent[]
}

export interface KernelRevision {
  readonly stateRoot: string
  readonly historyDigest: string
  readonly digest: string
  readonly view: 'local' | 'final'
  readonly orderLength: number
}

interface RecordedOpOutcome {
  readonly outcome: 'accepted' | 'rejected'
  readonly visibility: OperationVisibility
}

export interface KernelSnapshot {
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly seenOps: ReadonlySet<string>
  readonly opOutcomes: ReadonlyMap<string, RecordedOpOutcome>
  readonly topicLastOpIds: ReadonlyMap<string, string>
  readonly seenOpsRoot: string
  readonly historyDigest: string
  readonly stateRoot: string
  readonly orderLength: number
}

export interface KernelMaterializedCache {
  readonly v: 1
  readonly logId: string
  readonly blindHostMode: boolean
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly seenOpsRoot: string
  readonly historyDigest: string
  readonly stateRoot: string
  readonly orderOpIds: readonly string[]
  readonly outcomes: readonly KernelOperationOutcome[]
}

interface KernelMutableState {
  topics: Record<string, JsonValue>
  seenOps: Set<string>
  opOutcomes: Map<string, RecordedOpOutcome>
  topicLastOpIds: Map<string, string>
  seenOpsRoot: string
  historyDigest: string
  stateRoot: string
}

export interface KernelMaterializeResult {
  readonly revision: KernelRevision
  readonly outcomes: readonly KernelOperationOutcome[]
  readonly pendingDependencies: readonly string[]
  readonly skippedOpIds: readonly string[]
}

export interface TopicKernelOptions extends QuickJsSandboxOptions {
  readonly genesis: LogGenesis | Uint8Array
  readonly cas: ContentAddressedStore
  /** When true (e.g. blind Cloudflare Worker), only public-control operations are replayed. */
  readonly blindHostMode?: boolean
  readonly snapshotInterval?: number
  readonly policyContextDigest?: string
}

const ZERO_HASH = '0'.repeat(64)

function seenOpKey(visibility: OperationVisibility, authorHex: string, operationId: string): string {
  return `${visibility}:${authorHex}:${operationId}`
}

function hashSeenOpsSet(seen: ReadonlySet<string>, cas: ContentAddressedStore, partition: CasPartition): string {
  const sorted = [...seen].sort()
  const bytes = encodeCanonicalCbor(sorted)
  return cas.putSync(bytes, [], partition)
}

function computeStateRoot(topics: Readonly<Record<string, JsonValue>>, seenOpsRoot: string): string {
  const payload = encodeCanonicalCbor(new Map<string, CborValue>([
    ['seenOpsRoot', seenOpsRoot],
    ['topics', jsonToCbor(normalizeJsonValue(topics))],
  ]))
  return bytesToHex(hashDomainSync('state', payload))
}

function advanceHistoryDigest(
  prev: string,
  opId: string,
  outcome: 'accepted' | 'rejected',
  rejectionCode: string | null,
  events: readonly EmittedKernelEvent[],
): string {
  const eventsBytes = encodeCanonicalJsonCbor(
    events.map(e => ({ o: e.eventOrdinal, t: e.topic, p: e.payload })),
  )
  const payload = encodeCanonicalCbor([prev, opId, outcome, rejectionCode ?? '', eventsBytes])
  return bytesToHex(hashDomainSync('history', payload))
}

function computeRevisionDigest(
  historyDigest: string,
  stateRoot: string,
  view: 'local' | 'final',
  policyContextDigest: string,
): string {
  const payload = encodeCanonicalCbor([historyDigest, stateRoot, view, policyContextDigest])
  return bytesToHex(hashDomainSync('revision', payload))
}

function filterPublicTopics(topics: Readonly<Record<string, JsonValue>>): Record<string, JsonValue> {
  const out: Record<string, JsonValue> = {}
  for (const [k, v] of Object.entries(topics)) {
    if (isControlTopic(k)) out[k] = v
  }
  return out
}

function extractCasHashes(value: JsonValue, out: Set<string>): void {
  if (typeof value === 'string') {
    if (/^[0-9a-f]{64}$/u.test(value)) out.add(value)
    else if (value.startsWith('cas:sha256-') && value.length === 75) out.add(value.slice(11))
    return
  }
  if (Array.isArray(value)) {
    for (const item of value as readonly JsonValue[]) extractCasHashes(item, out)
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value)) extractCasHashes(v, out)
  }
}

function extractRequiredCasHashes(value: JsonValue, out: Set<string>, key?: string): void {
  if (typeof value === 'string') {
    if (value.startsWith('cas:sha256-') && value.length === 75) out.add(value.slice(11))
    else if (key === 'dbRoot' && /^[0-9a-f]{64}$/u.test(value)) out.add(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value as readonly JsonValue[]) extractRequiredCasHashes(item, out)
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) extractRequiredCasHashes(v, out, k)
  }
}

/**
 * Chronolog v2 Topic Kernel & Suffix-Replay Engine.
 * - Flat timestamp-ordered operation set: (authorTimestampMs, author, opId)
 * - Strict two-way public/encrypted control partition (blind-host equivalent)
 * - Scoped idempotency (visibility, author, operationId) in authenticated seenOpsRoot
 * - Rolling historyDigest + stateRoot + revision.digest
 * - Fresh QuickJSContext per call + uncatchable MissingDependency suspension
 */
export class TopicKernel {
  readonly genesis: LogGenesis
  readonly genesisBytes: Uint8Array
  readonly logId: Uint8Array
  readonly logIdHex: string
  readonly cas: ContentAddressedStore
  readonly sandbox: QuickJsSandbox
  readonly blindHostMode: boolean
  readonly #snapshotInterval: number
  readonly #policyContextDigest: string

  #order: KernelOperationInput[] = []
  #outcomes: KernelOperationOutcome[] = []
  #topics: Record<string, JsonValue>
  #seenOps = new Set<string>()
  #opOutcomes = new Map<string, RecordedOpOutcome>()
  #topicLastOpIds = new Map<string, string>()
  #seenOpsRoot: string
  #historyDigest: string = ZERO_HASH
  #stateRoot: string
  #pendingDependencies = new Set<string>()
  #skippedOpIds = new Set<string>()
  #snapshots = new Map<number, KernelSnapshot>()
  #frontierOpIds = new Set<string>()
  #frontierOrderLength = 0
  #frontierMaxTimestampMs = 0n
  readonly #genesisSnapshot: KernelSnapshot
  #cacheRestores = 0
  #cachedDescribe: { stateRoot: string; value: Readonly<Record<string, JsonValue>> } | null = null
  #queryCacheStateRoot = ''
  #queryCache = new Map<string, JsonValue>()

  constructor(options: TopicKernelOptions) {
    this.genesisBytes = options.genesis instanceof Uint8Array
      ? options.genesis.slice()
      : encodeLogGenesis(options.genesis)
    this.genesis = decodeLogGenesis(this.genesisBytes)
    this.logId = genesisLogId(this.genesisBytes)
    this.logIdHex = bytesToHex(this.logId)
    this.cas = options.cas
    this.blindHostMode = options.blindHostMode ?? false
    this.#snapshotInterval = options.snapshotInterval ?? 16
    this.#policyContextDigest = options.policyContextDigest ?? ZERO_HASH
    this.sandbox = new QuickJsSandbox(options)

    this.#topics = this.blindHostMode
      ? filterPublicTopics(structuredClone(this.genesis.initialTopics))
      : structuredClone(this.genesis.initialTopics)
    this.#seenOpsRoot = hashSeenOpsSet(this.#seenOps, this.cas, 'public')
    this.#stateRoot = computeStateRoot(this.#topics, this.#seenOpsRoot)
    this.#genesisSnapshot = this.#captureSnapshot(0)
    this.#snapshots.set(0, this.#genesisSnapshot)
  }

  #captureSnapshotFrom(state: KernelMutableState, orderLength: number): KernelSnapshot {
    return {
      topics: structuredClone(state.topics),
      seenOps: new Set(state.seenOps),
      opOutcomes: new Map(state.opOutcomes),
      topicLastOpIds: new Map(state.topicLastOpIds),
      seenOpsRoot: state.seenOpsRoot,
      historyDigest: state.historyDigest,
      stateRoot: state.stateRoot,
      orderLength,
    }
  }

  #captureSnapshot(orderLength: number): KernelSnapshot {
    return {
      topics: structuredClone(this.#topics),
      seenOps: new Set(this.#seenOps),
      opOutcomes: new Map(this.#opOutcomes),
      topicLastOpIds: new Map(this.#topicLastOpIds),
      seenOpsRoot: this.#seenOpsRoot,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
      orderLength,
    }
  }

  get topics(): Readonly<Record<string, JsonValue>> {
    return structuredClone(this.#topics)
  }

  get seenOpsRoot(): string {
    return this.#seenOpsRoot
  }

  snapshot(): {
    readonly topics: Readonly<Record<string, JsonValue>>
    readonly seenOpsRoot: string
    readonly historyDigest: string
    readonly stateRoot: string
  } {
    return {
      topics: structuredClone(this.#topics),
      seenOpsRoot: this.#seenOpsRoot,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
    }
  }

  topic(name: string): JsonValue | null {
    return Object.hasOwn(this.#topics, name) ? structuredClone(this.#topics[name]!) : null
  }

  opOutcome(opId: string): 'accepted' | 'rejected' | null {
    return this.#opOutcomes.get(opId)?.outcome ?? null
  }

  topicLastOpId(topic: string): string | null {
    return this.#topicLastOpIds.get(topic) ?? null
  }

  get outcomes(): readonly KernelOperationOutcome[] {
    return this.#outcomes.slice()
  }

  get pendingDependencies(): readonly string[] {
    return [...this.#pendingDependencies].sort()
  }

  revision(view: 'local' | 'final' = 'local', policyContextDigest = this.#policyContextDigest): KernelRevision {
    return {
      stateRoot: this.#stateRoot,
      historyDigest: this.#historyDigest,
      digest: computeRevisionDigest(this.#historyDigest, this.#stateRoot, view, policyContextDigest),
      view,
      orderLength: this.#frontierOrderLength + this.#order.length,
    }
  }

  get frontierOrderLength(): number {
    return this.#frontierOrderLength
  }

  get frontierMaxTimestampMs(): bigint {
    return this.#frontierMaxTimestampMs
  }

  hasFrontierOp(opId: string): boolean {
    return this.#frontierOpIds.has(opId)
  }

  /** Collect all CAS root hashes reachable from current state + retained suffix snapshots (for local GC). */
  gcRoots(): Set<string> {
    const roots = new Set<string>()
    roots.add(this.#seenOpsRoot)
    extractCasHashes(this.#topics, roots)
    for (const snap of this.#snapshots.values()) {
      roots.add(snap.seenOpsRoot)
      extractCasHashes(snap.topics, roots)
    }
    return roots
  }

  get cacheRestores(): number {
    return this.#cacheRestores
  }

  /** Export a self-verifying materialized cache snapshot for instant cold-open or suffix catch-up. */
  exportMaterializedCache(): KernelMaterializedCache {
    return {
      v: 1,
      logId: this.logIdHex,
      blindHostMode: this.blindHostMode,
      topics: structuredClone(this.#topics),
      seenOpsRoot: this.#seenOpsRoot,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
      orderOpIds: this.#order.map(item => bytesToHex(item.opId)),
      outcomes: this.#outcomes.map(o => ({
        opId: o.opId,
        author: o.author,
        operationId: o.operationId,
        authorTimestampMs: o.authorTimestampMs,
        visibility: o.visibility,
        outcome: o.outcome,
        rejectionCode: o.rejectionCode,
        ...(o.rejectionDetail === undefined ? {} : { rejectionDetail: o.rejectionDetail }),
        events: o.events.map((e: EmittedKernelEvent) => ({
          opId: e.opId,
          eventOrdinal: e.eventOrdinal,
          topic: e.topic,
          payload: structuredClone(e.payload),
          author: e.author,
          operationId: e.operationId,
          authorTimestampMs: e.authorTimestampMs,
        })),
      })),
    }
  }

  /**
   * Restore materialized state directly from a previously exported cache if:
   * - logId, blindHostMode, and recomputed stateRoot match exactly,
   * - seenOpsRoot and every CAS node hash referenced by topics exist locally, and
   * - cache.orderOpIds is an exact prefix of canonically sorted `inputs`.
   * Returns true on cache hit (exact or suffix-catchup prefix), false on miss.
   */
  async restoreMaterializedCache(
    cache: KernelMaterializedCache,
    inputs: readonly KernelOperationInput[],
  ): Promise<boolean> {
    if (
      cache.v !== 1 ||
      cache.logId !== this.logIdHex ||
      cache.blindHostMode !== this.blindHostMode ||
      !Array.isArray(cache.orderOpIds) ||
      !Array.isArray(cache.outcomes) ||
      cache.orderOpIds.length === 0 ||
      cache.orderOpIds.length !== cache.outcomes.length
    ) {
      return false
    }
    if (computeStateRoot(cache.topics, cache.seenOpsRoot) !== cache.stateRoot) {
      return false
    }
    const seenNode = await this.cas.get(cache.seenOpsRoot, 'any')
    if (seenNode === null) return false
    const neededCas = new Set<string>()
    extractRequiredCasHashes(cache.topics, neededCas)
    for (const hash of neededCas) {
      if (!this.cas.hasSync(hash, 'any') && await this.cas.get(hash, 'any') === null) {
        return false
      }
    }
    let decodedSeen: string[]
    try {
      const { assertCanonicalCbor, DEFAULT_DECODE_LIMITS } = await import('@chronolog/canonical')
      const raw = normalizeJsonValue(JSON.parse(JSON.stringify(assertCanonicalCbor(seenNode.bytes, DEFAULT_DECODE_LIMITS))))
      if (!Array.isArray(raw)) return false
      decodedSeen = raw.filter((v): v is string => typeof v === 'string')
    } catch {
      return false
    }

    const eligible: KernelOperationInput[] = []
    const seenIds = new Set<string>()
    for (const item of inputs) {
      if (bytesToHex(item.core.logId) !== this.logIdHex) continue
      if (this.blindHostMode && this.genesis.privateLog && item.core.visibility !== 'public') continue
      const opIdHex = bytesToHex(item.opId)
      if (seenIds.has(opIdHex)) continue
      seenIds.add(opIdHex)
      eligible.push(item)
    }
    eligible.sort((a, b) => compareOperationOrder(
      { authorTimestampMs: a.core.authorTimestampMs, author: a.core.author, opId: a.opId },
      { authorTimestampMs: b.core.authorTimestampMs, author: b.core.author, opId: b.opId },
    ))

    const prefixLen = cache.orderOpIds.length
    if (prefixLen > eligible.length) return false
    for (let i = 0; i < prefixLen; i++) {
      if (bytesToHex(eligible[i]!.opId) !== cache.orderOpIds[i]) return false
    }

    this.#order = eligible.slice(0, prefixLen)
    const cachedOutcomes: readonly KernelOperationOutcome[] = cache.outcomes
    this.#outcomes = cachedOutcomes.map((o: KernelOperationOutcome) => ({
      opId: o.opId,
      author: o.author,
      operationId: o.operationId,
      authorTimestampMs: BigInt(o.authorTimestampMs),
      visibility: o.visibility,
      outcome: o.outcome,
      rejectionCode: o.rejectionCode,
      ...(o.rejectionDetail === undefined ? {} : { rejectionDetail: o.rejectionDetail }),
      events: o.events.map((e: EmittedKernelEvent) => ({
        opId: e.opId,
        eventOrdinal: e.eventOrdinal,
        topic: e.topic,
        payload: structuredClone(e.payload),
        author: e.author,
        operationId: e.operationId,
        authorTimestampMs: BigInt(e.authorTimestampMs),
      })),
    }))
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(cache.topics)) : structuredClone(cache.topics)
    this.#seenOps = new Set(decodedSeen)
    this.#opOutcomes = new Map()
    this.#topicLastOpIds = new Map()
    for (let i = 0; i < this.#outcomes.length; i++) {
      const o = this.#outcomes[i]!
      const entry = this.#order[i]!
      this.#opOutcomes.set(o.opId, { outcome: o.outcome, visibility: o.visibility })
      if (o.outcome === 'accepted') {
        for (const u of entry.core.updates) {
          this.#topicLastOpIds.set(u.topic, o.opId)
        }
      }
    }
    this.#seenOpsRoot = cache.seenOpsRoot
    this.#historyDigest = cache.historyDigest
    this.#stateRoot = cache.stateRoot
    this.#pendingDependencies.clear()
    this.#skippedOpIds.clear()
    this.#snapshots.clear()
    this.#snapshots.set(0, this.#genesisSnapshot)
    this.#snapshots.set(prefixLen, this.#captureSnapshot(prefixLen))
    this.#cacheRestores++
    return true
  }

  /**
   * Bootstrap kernel state directly from a verified FinalityCheckpoint snapshot.
   * Restores both topicsMap, seenOpsRoot (consumed handles), and rolling historyDigest
   * so subsequent suffix replay produces identical stateRoot AND revision.digest.
   */
  async bootstrapFromCheckpoint(checkpoint: {
    readonly topics: Readonly<Record<string, JsonValue>>
    readonly seenOpsRoot: string
    readonly historyDigest: string
    readonly stateRoot: string
  }): Promise<void> {
    const seenNode = await this.cas.get(checkpoint.seenOpsRoot, 'any')
    if (seenNode === null) throw new MissingDependencyError(checkpoint.seenOpsRoot, 'cas')
    const decodedSeen = normalizeJsonValue(
      JSON.parse(JSON.stringify(
        // Decode CBOR array of strings stored in seenOpsRoot
        await import('@chronolog/canonical').then(m => m.assertCanonicalCbor(seenNode.bytes, m.DEFAULT_DECODE_LIMITS)),
      )),
    ) as string[]
    const computedStateRoot = computeStateRoot(checkpoint.topics, checkpoint.seenOpsRoot)
    if (computedStateRoot !== checkpoint.stateRoot) {
      throw new Error(`CHECKPOINT_STATE_ROOT_MISMATCH: expected ${checkpoint.stateRoot}, got ${computedStateRoot}`)
    }
    this.#order = []
    this.#outcomes = []
    this.#opOutcomes.clear()
    this.#topicLastOpIds.clear()
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(checkpoint.topics)) : structuredClone(checkpoint.topics)
    this.#seenOps = new Set(decodedSeen)
    this.#seenOpsRoot = checkpoint.seenOpsRoot
    this.#historyDigest = checkpoint.historyDigest
    this.#stateRoot = checkpoint.stateRoot
    this.#snapshots.clear()
    this.#snapshots.set(0, this.#captureSnapshot(0))
  }

  /**
   * Bootstrap kernel state directly from a host-cached encrypted Snapshot Bundle WITHOUT requiring
   * all historical operations to be downloaded first. Subsequent materialize(suffixInputs) skips
   * any op already covered by `frontierOpIds` and applies only new tail operations.
   */
  async restoreSnapshotFrontier(snapshot: {
    readonly topics: Readonly<Record<string, JsonValue>>
    readonly seenOpsRoot: string
    readonly historyDigest: string
    readonly stateRoot: string
    readonly orderOpIds: readonly string[]
    readonly maxAuthorTimestampMs?: bigint | string | number
  }): Promise<boolean> {
    if (computeStateRoot(snapshot.topics, snapshot.seenOpsRoot) !== snapshot.stateRoot) {
      return false
    }
    const seenNode = await this.cas.get(snapshot.seenOpsRoot, 'any')
    if (seenNode === null) return false
    const neededCas = new Set<string>()
    extractRequiredCasHashes(snapshot.topics, neededCas)
    for (const hash of neededCas) {
      if (!this.cas.hasSync(hash, 'any') && await this.cas.get(hash, 'any') === null) {
        return false
      }
    }
    let decodedSeen: string[]
    try {
      const { assertCanonicalCbor, DEFAULT_DECODE_LIMITS } = await import('@chronolog/canonical')
      const raw = normalizeJsonValue(JSON.parse(JSON.stringify(assertCanonicalCbor(seenNode.bytes, DEFAULT_DECODE_LIMITS))))
      if (!Array.isArray(raw)) return false
      decodedSeen = raw.filter((v): v is string => typeof v === 'string')
    } catch {
      return false
    }
    this.#order = []
    this.#outcomes = []
    this.#opOutcomes.clear()
    this.#topicLastOpIds.clear()
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(snapshot.topics)) : structuredClone(snapshot.topics)
    this.#seenOps = new Set(decodedSeen)
    this.#seenOpsRoot = snapshot.seenOpsRoot
    this.#historyDigest = snapshot.historyDigest
    this.#stateRoot = snapshot.stateRoot
    this.#frontierOpIds = new Set(snapshot.orderOpIds)
    this.#frontierOrderLength = snapshot.orderOpIds.length
    this.#frontierMaxTimestampMs = snapshot.maxAuthorTimestampMs !== undefined ? BigInt(snapshot.maxAuthorTimestampMs) : 0n
    this.#pendingDependencies.clear()
    this.#skippedOpIds.clear()
    this.#snapshots.clear()
    this.#snapshots.set(0, this.#captureSnapshot(0))
    this.#cacheRestores++
    return true
  }

  /**
   * Deterministically materialize an eligible operation set (arbitrary input order; sorted internally).
   * Rewinds only to the earliest snapshot before the first changed position (suffix replay).
   */
  async materialize(inputs: readonly KernelOperationInput[]): Promise<KernelMaterializeResult> {
    // Filter for blindHostMode and logId, sort strictly by canonical comparator
    const eligible: KernelOperationInput[] = []
    const seenIds = new Set<string>()
    for (const item of inputs) {
      if (bytesToHex(item.core.logId) !== this.logIdHex) continue
      if (this.blindHostMode && this.genesis.privateLog && item.core.visibility !== 'public') continue
      const opIdHex = bytesToHex(item.opId)
      if (this.#frontierOpIds.has(opIdHex)) continue
      if (item.verified !== true && bytesToHex(operationIdDigest(item.core)) !== opIdHex) {
        throw new Error('KERNEL_OP_ID_MISMATCH')
      }
      if (seenIds.has(opIdHex)) continue
      seenIds.add(opIdHex)
      eligible.push(item)
    }
    eligible.sort((a, b) => compareOperationOrder(
      { authorTimestampMs: a.core.authorTimestampMs, author: a.core.author, opId: a.opId },
      { authorTimestampMs: b.core.authorTimestampMs, author: b.core.author, opId: b.opId },
    ))

    // Find first divergence point from current materialized prefix
    let diff = 0
    while (diff < this.#order.length && diff < eligible.length) {
      if (bytesToHex(this.#order[diff]!.opId) !== bytesToHex(eligible[diff]!.opId)) break
      diff++
    }
    // Fast path: identical eligible set and no pending dependencies — nothing to re-evaluate
    if (diff === eligible.length && this.#order.length === eligible.length && this.#pendingDependencies.size === 0) {
      return {
        revision: this.revision('local'),
        outcomes: this.#outcomes.slice(),
        pendingDependencies: this.pendingDependencies,
        skippedOpIds: [...this.#skippedOpIds],
      }
    }
    // If previous run had missing dependencies, re-evaluate from earliest missing point (0 if uncertain)
    if (this.#pendingDependencies.size > 0) diff = 0

    // Find nearest cached snapshot <= diff (includes the rolling tip snapshot at this.#order.length!)
    let snapIndex = 0
    for (const idx of this.#snapshots.keys()) {
      if (idx <= diff && idx > snapIndex) snapIndex = idx
    }
    const snap = this.#snapshots.get(snapIndex)!
    const work: KernelMutableState = {
      topics: structuredClone(snap.topics),
      seenOps: new Set(snap.seenOps),
      opOutcomes: new Map(snap.opOutcomes),
      topicLastOpIds: new Map(snap.topicLastOpIds),
      seenOpsRoot: snap.seenOpsRoot,
      historyDigest: snap.historyDigest,
      stateRoot: snap.stateRoot,
    }
    const nextSnapshots = new Map<number, KernelSnapshot>()
    for (const [idx, s] of this.#snapshots) {
      if (idx <= snapIndex && (idx === 0 || idx % this.#snapshotInterval === 0 || idx === snapIndex)) {
        nextSnapshots.set(idx, s)
      }
    }

    const nextOutcomes = this.#outcomes.slice(0, snapIndex)
    const nextOrder = this.#order.slice(0, snapIndex)
    const nextPendingDeps = new Set<string>()
    const nextSkippedOps = new Set<string>()

    this.cas.beginBatch()
    try {
      for (let i = snapIndex; i < eligible.length; i++) {
        const entry = eligible[i]!
        const opIdHex = bytesToHex(entry.opId)
        const authorHex = bytesToHex(entry.core.author)

        const step = await this.#applyOne(work, entry, opIdHex, authorHex)
        if (step.kind === 'missing') {
          nextPendingDeps.add(step.dependency)
          nextSkippedOps.add(opIdHex)
          // Stop advancing past an unresolved dependency so later ops never execute against incomplete causal state
          break
        }
        nextOrder.push(entry)
        nextOutcomes.push(step.outcome)
        if (nextOrder.length % this.#snapshotInterval === 0) {
          nextSnapshots.set(nextOrder.length, this.#captureSnapshotFrom(work, nextOrder.length))
        }
      }
      // Always capture a rolling tip snapshot so the next monotonic append replays strictly 1 op (never 2..16).
      if (nextOrder.length > 0 && !nextSnapshots.has(nextOrder.length)) {
        // Evict the previous non-interval tip snapshot so memory stays bounded.
        for (const idx of [...nextSnapshots.keys()]) {
          if (idx > 0 && idx % this.#snapshotInterval !== 0) nextSnapshots.delete(idx)
        }
        nextSnapshots.set(nextOrder.length, this.#captureSnapshotFrom(work, nextOrder.length))
      }
      await this.cas.flushBatch()
      // Atomically commit all derived state once replay and CAS flush succeed so concurrent
      // readers never observe a rewound or partially materialized kernel.
      this.#topics = work.topics
      this.#seenOps = work.seenOps
      this.#opOutcomes = work.opOutcomes
      this.#topicLastOpIds = work.topicLastOpIds
      this.#seenOpsRoot = work.seenOpsRoot
      this.#historyDigest = work.historyDigest
      this.#stateRoot = work.stateRoot
      this.#order = nextOrder
      this.#outcomes = nextOutcomes
      this.#pendingDependencies = nextPendingDeps
      this.#skippedOpIds = nextSkippedOps
      this.#snapshots = nextSnapshots
    } catch (err) {
      this.cas.rollbackBatch()
      throw err
    }

    return {
      revision: this.revision('local'),
      outcomes: this.#outcomes.slice(),
      pendingDependencies: this.pendingDependencies,
      skippedOpIds: [...this.#skippedOpIds],
    }
  }

  async #applyOne(
    work: KernelMutableState,
    entry: KernelOperationInput,
    opIdHex: string,
    authorHex: string,
  ): Promise<{ readonly kind: 'done'; readonly outcome: KernelOperationOutcome } | { readonly kind: 'missing'; readonly dependency: string }> {
    const core = entry.core
    const makeRejected = (
      code: string,
      detail?: string,
      extra?: { readonly conflictRecorded?: boolean; readonly events?: readonly EmittedKernelEvent[] },
    ): { readonly kind: 'done'; readonly outcome: KernelOperationOutcome } => {
      const evs = extra?.events ?? []
      const outcome: KernelOperationOutcome = {
        opId: opIdHex,
        author: authorHex,
        operationId: core.operationId,
        authorTimestampMs: core.authorTimestampMs,
        visibility: core.visibility,
        outcome: 'rejected',
        rejectionCode: code,
        ...(detail === undefined ? {} : { rejectionDetail: detail }),
        ...(extra?.conflictRecorded === true ? { conflictRecorded: true } : {}),
        events: evs,
      }
      work.opOutcomes.set(opIdHex, { outcome: 'rejected', visibility: core.visibility })
      work.historyDigest = advanceHistoryDigest(work.historyDigest, opIdHex, 'rejected', code, evs)
      return { kind: 'done', outcome }
    }

    // Strict two-way partition check on privateLog
    if (this.genesis.privateLog) {
      if (core.visibility === 'public') {
        if (core.updates.some(u => !isControlTopic(u.topic))) {
          return makeRejected('partition:public_op_private_topic')
        }
      } else {
        if (core.updates.some(u => isControlTopic(u.topic))) {
          return makeRejected('partition:encrypted_op_control_topic')
        }
      }
    }

    if (core.updates.length > this.genesis.limits.maxUpdatesPerOp) {
      return makeRejected('limit:max_updates_per_op')
    }

    // Scoped idempotency check: (visibility, author, operationId)
    const dedupKey = seenOpKey(core.visibility, authorHex, core.operationId)
    if (work.seenOps.has(dedupKey)) {
      return makeRejected('operation_conflict')
    }

    // Consume idempotency handle (even if reducer rejects, matching Chronolog's contract)
    const casPartition: CasPartition = (this.genesis.privateLog && core.visibility === 'public') ? 'public' : 'private'
    const isPublicOnPrivate = this.genesis.privateLog && core.visibility === 'public'

    const buildVisibleOutcomes = (): Record<string, 'accepted' | 'rejected'> => {
      const out: Record<string, 'accepted' | 'rejected'> = {}
      for (const [k, rec] of work.opOutcomes) {
        if (isPublicOnPrivate && rec.visibility !== 'public') continue
        out[k] = rec.outcome
      }
      return out
    }
    const buildVisibleTopicLastOpIds = (): Record<string, string> => {
      const out: Record<string, string> = {}
      for (const [topicName, lastId] of work.topicLastOpIds) {
        if (isPublicOnPrivate && !isControlTopic(topicName)) continue
        out[topicName] = lastId
      }
      return out
    }

    // Evaluate signed operation-level assumptions before applying topic updates
    if (core.assumptions !== undefined && core.assumptions.checks.length > 0) {
      const visibleTopicsForAssumptions = isPublicOnPrivate ? filterPublicTopics(work.topics) : work.topics
      const visibleOutcomes = buildVisibleOutcomes()
      const visibleTopicLastOps = buildVisibleTopicLastOpIds()
      let failure: { readonly code: string; readonly detail?: string; readonly checkIndex: number } | null = null

      for (let i = 0; i < core.assumptions.checks.length; i++) {
        const chk: OperationAssumption = core.assumptions.checks[i]!
        if (chk.kind === 'op_accepted') {
          const st = Object.hasOwn(visibleOutcomes, chk.opId) ? visibleOutcomes[chk.opId] : undefined
          if (st === undefined) {
            failure = { code: 'assumption:missing_op', detail: `Required op ${chk.opId} not present`, checkIndex: i }
            break
          }
          if (st !== 'accepted') {
            failure = { code: 'assumption:dependency_rejected', detail: `Required op ${chk.opId} was rejected`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'op_rejected') {
          const st = Object.hasOwn(visibleOutcomes, chk.opId) ? visibleOutcomes[chk.opId] : undefined
          if (st === undefined) {
            failure = { code: 'assumption:missing_op', detail: `Referenced op ${chk.opId} not present`, checkIndex: i }
            break
          }
          if (st !== 'rejected') {
            failure = { code: 'assumption:expected_rejected', detail: `Expected op ${chk.opId} to be rejected`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'topic_revision') {
          if (isPublicOnPrivate && !isControlTopic(chk.topic)) {
            failure = { code: 'partition:public_op_private_assumption', detail: `Public op cannot assume private topic ${chk.topic}`, checkIndex: i }
            break
          }
          const actual = Object.hasOwn(visibleTopicLastOps, chk.topic) ? visibleTopicLastOps[chk.topic]! : null
          if (actual !== chk.lastOpId) {
            failure = { code: 'assumption:topic_modified', detail: `Topic ${chk.topic} lastOpId expected ${String(chk.lastOpId)}, got ${String(actual)}`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'query_match') {
          if (isPublicOnPrivate && !isControlTopic(chk.topic)) {
            failure = { code: 'partition:public_op_private_assumption', detail: `Public op cannot query private topic ${chk.topic}`, checkIndex: i }
            break
          }
          let reducersConfig: ReducersConfig
          try {
            reducersConfig = assertValidReducersConfig(work.topics.$reducers)
          } catch (err) {
            failure = { code: 'reducers_config_invalid', detail: err instanceof Error ? err.message : String(err), checkIndex: i }
            break
          }
          const binding = reducersConfig.topics[chk.topic]
          const topicState: JsonValue = Object.hasOwn(visibleTopicsForAssumptions, chk.topic) ? visibleTopicsForAssumptions[chk.topic]! : null
          let actualValue: JsonValue = topicState
          if (binding !== undefined) {
            let qRes
            try {
              qRes = await this.sandbox.invoke({
                imports: reducersConfig.imports,
                builtins: reducersConfig.runtime.builtins,
                topicBindings: reducersConfig.topics,
                moduleSpecifier: binding.module,
                exportName: binding.export ?? 'default',
                method: 'query',
                state: topicState,
                payload: chk.query,
                opOutcomes: visibleOutcomes,
                topicLastOpIds: visibleTopicLastOps,
                topics: visibleTopicsForAssumptions,
                ...(binding.config === undefined ? {} : { config: binding.config }),
                cas: this.cas,
                casPartition: (isPublicOnPrivate || isControlTopic(chk.topic)) ? 'public' : 'private',
                readOnly: true,
                maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
              })
            } catch (err) {
              if (err instanceof MissingDependencyError) {
                return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
              }
              throw err
            }
            if (!qRes.ok) {
              if (qRes.code !== 'vm:missing_method:query') {
                failure = { code: 'assumption:query_failed', detail: qRes.detail ?? qRes.code, checkIndex: i }
                break
              }
            } else {
              actualValue = qRes.value
            }
          }
          if (canonicalJson(actualValue) !== canonicalJson(chk.expect)) {
            failure = { code: 'assumption:query_mismatch', detail: `Query assumption ${i} on ${chk.topic} did not match`, checkIndex: i }
            break
          }
        }
      }

      if (failure !== null) {
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        if (core.assumptions.onFailed === 'record_conflict' && failure.code !== 'partition:public_op_private_assumption') {
          const primaryUpdate = core.updates[0]!
          let reducersConfig: ReducersConfig | null = null
          try { reducersConfig = assertValidReducersConfig(work.topics.$reducers) } catch { /* leave null */ }
          const binding = reducersConfig?.topics[primaryUpdate.topic]
          if (reducersConfig !== null && binding !== undefined) {
            const curTopicState: JsonValue = Object.hasOwn(work.topics, primaryUpdate.topic) ? work.topics[primaryUpdate.topic]! : null
            let conflictRes
            try {
              conflictRes = await this.sandbox.invoke({
                imports: reducersConfig.imports,
                builtins: reducersConfig.runtime.builtins,
                topicBindings: reducersConfig.topics,
                moduleSpecifier: binding.module,
                exportName: binding.export ?? 'default',
                method: 'onConflict',
                state: curTopicState,
                payload: primaryUpdate.input,
                tx: {
                  opId: opIdHex,
                  author: authorHex,
                  authorTimestampMs: Number(core.authorTimestampMs),
                  operationId: core.operationId,
                },
                conflict: failure,
                opOutcomes: visibleOutcomes,
                topicLastOpIds: visibleTopicLastOps,
                topics: visibleTopicsForAssumptions,
                ...(binding.config === undefined ? {} : { config: binding.config }),
                cas: this.cas,
                casPartition,
                readOnly: false,
                maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
              })
            } catch (err) {
              if (err instanceof MissingDependencyError) {
                return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
              }
              throw err
            }
            if (conflictRes.ok && conflictRes.value !== null && typeof conflictRes.value === 'object' && !Array.isArray(conflictRes.value)) {
              const outRec = conflictRes.value as Readonly<Record<string, JsonValue>>
              if (outRec.ok === true) {
                const nextTopicState: JsonValue = outRec.state === undefined ? null : outRec.state
                const encodedTopic = encodeCanonicalJsonCbor(nextTopicState)
                if (encodedTopic.length <= this.genesis.limits.maxTopicStateBytes) {
                  const conflictEvents: EmittedKernelEvent[] = []
                  let ord = 0
                  if (Array.isArray(outRec.events)) {
                    for (const rawEv of outRec.events as readonly JsonValue[]) {
                      if (rawEv !== null && typeof rawEv === 'object' && !Array.isArray(rawEv)) {
                        const ev = rawEv as Readonly<Record<string, JsonValue>>
                        if (typeof ev.topic === 'string') {
                          conflictEvents.push({
                            opId: opIdHex,
                            eventOrdinal: ord++,
                            topic: ev.topic,
                            payload: ev.payload ?? null,
                            author: authorHex,
                            operationId: core.operationId,
                            authorTimestampMs: core.authorTimestampMs,
                          })
                        }
                      }
                    }
                  }
                  work.topics = { ...work.topics, [primaryUpdate.topic]: nextTopicState }
                  work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
                  return makeRejected(failure.code, failure.detail, { conflictRecorded: true, events: conflictEvents })
                }
              }
            }
          }
        }
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected(failure.code, failure.detail)
      }
    }

    // Copy-on-write working topics map
    const workingTopics: Record<string, JsonValue> = structuredClone(work.topics)
    const emitted: EmittedKernelEvent[] = []
    let ordinal = 0
    const visibleOutcomesForReduce = buildVisibleOutcomes()
    const visibleTopicLastOpsForReduce = buildVisibleTopicLastOpIds()

    for (const update of core.updates) {
      let reducersConfig: ReducersConfig
      try {
        reducersConfig = assertValidReducersConfig(workingTopics.$reducers)
      } catch (err) {
        return makeRejected('reducers_config_invalid', err instanceof Error ? err.message : String(err))
      }

      const binding = reducersConfig.topics[update.topic]
      if (binding === undefined) {
        // Missing reducer for $reducers means rules are permanently frozen; missing reducer for any topic rejects cleanly.
        return makeRejected(update.topic === '$reducers' ? 'reducers_frozen' : `no_reducer:${update.topic}`)
      }

      // Public-control ops on privateLog only see $* control topics and public CAS
      const visibleTopics = (this.genesis.privateLog && core.visibility === 'public')
        ? filterPublicTopics(workingTopics)
        : workingTopics

      const curTopicState: JsonValue = Object.hasOwn(workingTopics, update.topic) ? workingTopics[update.topic]! : null

      let res
      try {
        res = await this.sandbox.invoke({
          imports: reducersConfig.imports,
          builtins: reducersConfig.runtime.builtins,
          topicBindings: reducersConfig.topics,
          moduleSpecifier: binding.module,
          exportName: binding.export ?? 'default',
          method: 'reduce',
          state: curTopicState,
          payload: update.input,
          tx: {
            opId: opIdHex,
            author: authorHex,
            authorTimestampMs: Number(core.authorTimestampMs),
            operationId: core.operationId,
          },
          opOutcomes: visibleOutcomesForReduce,
          topicLastOpIds: visibleTopicLastOpsForReduce,
          topics: visibleTopics,
          ...(binding.config === undefined ? {} : { config: binding.config }),
          cas: this.cas,
          casPartition,
          readOnly: false,
          maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
        })
      } catch (err) {
        if (err instanceof MissingDependencyError) {
          return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
        }
        throw err
      }

      if (!res.ok) {
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected(res.code, res.detail)
      }

      const outObj = res.value
      if (outObj === null || typeof outObj !== 'object' || Array.isArray(outObj)) {
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected('vm:invalid_reducer_return')
      }
      const outRec = outObj as Readonly<Record<string, JsonValue>>
      if (typeof outRec.ok !== 'boolean') {
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected('vm:invalid_reducer_return')
      }

      if (!outRec.ok) {
        const rejCode = typeof outRec.code === 'string' && outRec.code.length > 0 ? outRec.code : 'reducer:rejected'
        const rejDetail = typeof outRec.detail === 'string' ? outRec.detail : undefined
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected(rejCode, rejDetail)
      }

      const nextTopicState: JsonValue = outRec.state === undefined ? null : outRec.state
      const encodedTopic = encodeCanonicalJsonCbor(nextTopicState)
      if (encodedTopic.length > this.genesis.limits.maxTopicStateBytes) {
        work.seenOps.add(dedupKey)
        work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
        work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
        return makeRejected('limit:max_topic_state_bytes')
      }

      // If updating $reducers, validate new config shape immediately!
      if (update.topic === '$reducers') {
        try { assertValidReducersConfig(nextTopicState) }
        catch (err) {
          work.seenOps.add(dedupKey)
          work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
          work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
          return makeRejected('reducers_config_invalid', err instanceof Error ? err.message : String(err))
        }
      }

      workingTopics[update.topic] = nextTopicState

      if (Array.isArray(outRec.events)) {
        for (const rawEv of outRec.events as readonly JsonValue[]) {
          if (rawEv !== null && typeof rawEv === 'object' && !Array.isArray(rawEv)) {
            const ev = rawEv as Readonly<Record<string, JsonValue>>
            if (typeof ev.topic === 'string') {
              emitted.push({
                opId: opIdHex,
                eventOrdinal: ordinal++,
                topic: ev.topic,
                payload: ev.payload ?? null,
                author: authorHex,
                operationId: core.operationId,
                authorTimestampMs: core.authorTimestampMs,
              })
            }
          }
        }
      }
    }

    // Atomic commit of all topic updates in this op
    work.seenOps.add(dedupKey)
    work.seenOpsRoot = hashSeenOpsSet(work.seenOps, this.cas, casPartition)
    work.topics = workingTopics
    work.opOutcomes.set(opIdHex, { outcome: 'accepted', visibility: core.visibility })
    for (const u of core.updates) {
      work.topicLastOpIds.set(u.topic, opIdHex)
    }
    work.stateRoot = computeStateRoot(work.topics, work.seenOpsRoot)
    work.historyDigest = advanceHistoryDigest(work.historyDigest, opIdHex, 'accepted', null, emitted)

    return {
      kind: 'done',
      outcome: {
        opId: opIdHex,
        author: authorHex,
        operationId: core.operationId,
        authorTimestampMs: core.authorTimestampMs,
        visibility: core.visibility,
        outcome: 'accepted',
        rejectionCode: null,
        events: emitted,
      },
    }
  }

  /** Execute a pure read-only query against a topic's query() export (or return raw topic state if no query export). */
  async query(topic: string, input: JsonValue = null, topicsOverride?: Readonly<Record<string, JsonValue>>): Promise<JsonValue> {
    const sourceTopics = topicsOverride ?? this.#topics
    const normalizedInput = normalizeJsonValue(input)
    let cacheKey: string | null = null
    if (topicsOverride === undefined) {
      if (this.#queryCacheStateRoot !== this.#stateRoot) {
        this.#queryCache.clear()
        this.#queryCacheStateRoot = this.#stateRoot
      }
      cacheKey = `${topic}\0${bytesToHex(encodeCanonicalJsonCbor(normalizedInput))}`
      const hit = this.#queryCache.get(cacheKey)
      if (hit !== undefined) {
        // Refresh LRU order and return a defensive clone so callers cannot mutate cached snapshots.
        this.#queryCache.delete(cacheKey)
        this.#queryCache.set(cacheKey, hit)
        return structuredClone(hit)
      }
    }
    const reducersConfig = assertValidReducersConfig(sourceTopics.$reducers)
    const binding = reducersConfig.topics[topic]
    const state = Object.hasOwn(sourceTopics, topic) ? sourceTopics[topic]! : null
    if (binding === undefined) return structuredClone(state)
    const casPartition: CasPartition = (this.genesis.privateLog && isControlTopic(topic)) ? 'public' : 'private'
    const visibleTopics = (this.genesis.privateLog && isControlTopic(topic))
      ? filterPublicTopics(sourceTopics)
      : sourceTopics
    const res = await this.sandbox.invoke({
      imports: reducersConfig.imports,
      builtins: reducersConfig.runtime.builtins,
      topicBindings: reducersConfig.topics,
      moduleSpecifier: binding.module,
      exportName: binding.export ?? 'default',
      method: 'query',
      state,
      payload: normalizedInput,
      topics: visibleTopics,
      ...(binding.config === undefined ? {} : { config: binding.config }),
      cas: this.cas,
      casPartition,
      readOnly: true,
      maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
    })
    if (!res.ok) {
      if (res.code === 'vm:missing_method:query') return structuredClone(state)
      throw new Error(`KERNEL_QUERY_FAILED:${res.code}:${res.detail ?? ''}`)
    }
    if (cacheKey !== null && this.#queryCacheStateRoot === this.#stateRoot) {
      this.#queryCache.set(cacheKey, structuredClone(res.value))
      if (this.#queryCache.size > 128) {
        const oldest = this.#queryCache.keys().next().value
        if (oldest !== undefined) this.#queryCache.delete(oldest)
      }
    }
    return res.value
  }

  /**
   * Time-travel materialization: reconstructs the exact coherent state at a specific opId
   * or at/before a timestamp without mutating live kernel state.
   */
  async materializeAt(
    target: { readonly opId: string } | { readonly atTimestampMs: bigint },
  ): Promise<{
    readonly revision: KernelRevision
    readonly topics: Readonly<Record<string, JsonValue>>
    readonly orderLength: number
    readonly targetOpId: string | null
  }> {
    let targetLen = 0
    if ('opId' in target) {
      const idx = this.#order.findIndex(item => bytesToHex(item.opId) === target.opId)
      if (idx < 0) throw new Error(`TIME_TRAVEL_OP_NOT_FOUND:${target.opId}`)
      targetLen = idx + 1
    } else {
      for (let i = 0; i < this.#order.length; i++) {
        if (this.#order[i]!.core.authorTimestampMs <= target.atTimestampMs) {
          targetLen = i + 1
        } else {
          break
        }
      }
    }

    let snapIndex = 0
    for (const idx of this.#snapshots.keys()) {
      if (idx <= targetLen && idx > snapIndex) snapIndex = idx
    }
    const snap = this.#snapshots.get(snapIndex)!
    const work: KernelMutableState = {
      topics: structuredClone(snap.topics),
      seenOps: new Set(snap.seenOps),
      opOutcomes: new Map(snap.opOutcomes),
      topicLastOpIds: new Map(snap.topicLastOpIds),
      seenOpsRoot: snap.seenOpsRoot,
      historyDigest: snap.historyDigest,
      stateRoot: snap.stateRoot,
    }

    this.cas.beginBatch()
    try {
      for (let i = snapIndex; i < targetLen; i++) {
        const entry = this.#order[i]!
        const opIdHex = bytesToHex(entry.opId)
        const authorHex = bytesToHex(entry.core.author)
        const step = await this.#applyOne(work, entry, opIdHex, authorHex)
        if (step.kind === 'missing') {
          throw new MissingDependencyError(step.dependency.split('/')[1] ?? step.dependency, 'cas')
        }
      }
      // Keep ephemeral replay writes out of persisted CAS (rollbackBatch discards uncommitted staging)
      this.cas.rollbackBatch()
    } catch (err) {
      this.cas.rollbackBatch()
      throw err
    }

    const revision: KernelRevision = {
      stateRoot: work.stateRoot,
      historyDigest: work.historyDigest,
      digest: computeRevisionDigest(work.historyDigest, work.stateRoot, 'local', this.#policyContextDigest),
      view: 'local',
      orderLength: targetLen,
    }
    return {
      revision,
      topics: structuredClone(work.topics),
      orderLength: targetLen,
      targetOpId: targetLen > 0 ? bytesToHex(this.#order[targetLen - 1]!.opId) : null,
    }
  }

  /** Execute a read-only query against a historical revision (by opId or timestamp). */
  async queryAt(
    topic: string,
    input: JsonValue,
    target: { readonly opId: string } | { readonly atTimestampMs: bigint },
  ): Promise<{
    readonly revision: KernelRevision
    readonly targetOpId: string | null
    readonly value: JsonValue
  }> {
    const snap = await this.materializeAt(target)
    const value = await this.query(topic, input, snap.topics)
    return { revision: snap.revision, targetOpId: snap.targetOpId, value }
  }

  /** Collect exported command/query descriptions across all bound topics (for MCP & scoped tools). */
  async describe(): Promise<Readonly<Record<string, JsonValue>>> {
    if (this.#cachedDescribe !== null && this.#cachedDescribe.stateRoot === this.#stateRoot) {
      return structuredClone(this.#cachedDescribe.value)
    }
    const reducersConfig = assertValidReducersConfig(this.#topics.$reducers)
    const out: Record<string, JsonValue> = {}
    for (const [topic, binding] of Object.entries(reducersConfig.topics)) {
      if (this.blindHostMode && this.genesis.privateLog && !isControlTopic(topic)) continue
      const state = Object.hasOwn(this.#topics, topic) ? this.#topics[topic]! : null
      const casPartition: CasPartition = (this.genesis.privateLog && isControlTopic(topic)) ? 'public' : 'private'
      const res = await this.sandbox.invoke({
        imports: reducersConfig.imports,
        builtins: reducersConfig.runtime.builtins,
        topicBindings: reducersConfig.topics,
        moduleSpecifier: binding.module,
        exportName: binding.export ?? 'default',
        method: 'describe',
        state,
        payload: null,
        topics: this.blindHostMode ? filterPublicTopics(this.#topics) : this.#topics,
        ...(binding.config === undefined ? {} : { config: binding.config }),
        cas: this.cas,
        casPartition,
        readOnly: true,
        maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
      })
      if (res.ok) out[topic] = res.value
    }
    this.#cachedDescribe = { stateRoot: this.#stateRoot, value: structuredClone(out) }
    return out
  }

  /** Evaluate signal authorization policy for the current stateRoot (cached by caller per stateRoot). */
  async signalPolicy(): Promise<{ readonly rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] }> {
    const reducersConfig = assertValidReducersConfig(this.#topics.$reducers)
    if (reducersConfig.topics.$signal_policy !== undefined) {
      const val = await this.query('$signal_policy', null)
      if (val !== null && typeof val === 'object' && !Array.isArray(val) && Array.isArray((val as Readonly<Record<string, JsonValue>>).rules)) {
        return val as { readonly rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] }
      }
    }
    const queriedReaders = await this.query('$permissions', { list: 'readers' }).catch(() => null)
    if (Array.isArray(queriedReaders) && queriedReaders.every(x => typeof x === 'string')) {
      return {
        rules: [{ topicPattern: '*', allowedAuthors: queriedReaders, maxTtlMs: 30_000, allowRelay: true }],
      }
    }
    const perms = this.#topics.$permissions as { readonly members?: readonly { readonly publicKey: string; readonly reader?: boolean }[] } | undefined
    const readers = (perms?.members ?? []).filter(m => m.reader).map(m => m.publicKey)
    return {
      rules: [{ topicPattern: '*', allowedAuthors: readers, maxTtlMs: 30_000, allowRelay: true }],
    }
  }
}

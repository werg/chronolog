import {
  bytesToHex,
  encodeCanonicalCbor,
  hashDomainSync,
  type CborValue,
} from '@chronolog/canonical'
import {
  assertValidReducersConfig,
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
  readonly events: readonly EmittedKernelEvent[]
}

export interface KernelRevision {
  readonly stateRoot: string
  readonly historyDigest: string
  readonly digest: string
  readonly view: 'local' | 'final'
  readonly orderLength: number
}

export interface KernelSnapshot {
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly seenOps: ReadonlySet<string>
  readonly seenOpsRoot: string
  readonly historyDigest: string
  readonly stateRoot: string
  readonly orderLength: number
}

interface KernelMutableState {
  topics: Record<string, JsonValue>
  seenOps: Set<string>
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
  #seenOpsRoot: string
  #historyDigest: string = ZERO_HASH
  #stateRoot: string
  #pendingDependencies = new Set<string>()
  #skippedOpIds = new Set<string>()
  #snapshots = new Map<number, KernelSnapshot>()
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
    this.#snapshots.set(0, this.#captureSnapshot(0))
  }

  #captureSnapshotFrom(state: KernelMutableState, orderLength: number): KernelSnapshot {
    return {
      topics: structuredClone(state.topics),
      seenOps: new Set(state.seenOps),
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
      orderLength: this.#order.length,
    }
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
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(checkpoint.topics)) : structuredClone(checkpoint.topics)
    this.#seenOps = new Set(decodedSeen)
    this.#seenOpsRoot = checkpoint.seenOpsRoot
    this.#historyDigest = checkpoint.historyDigest
    this.#stateRoot = checkpoint.stateRoot
    this.#snapshots.clear()
    this.#snapshots.set(0, this.#captureSnapshot(0))
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
      if (bytesToHex(operationIdDigest(item.core)) !== opIdHex) throw new Error('KERNEL_OP_ID_MISMATCH')
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

    // Find nearest cached snapshot <= diff
    let snapIndex = 0
    for (const idx of this.#snapshots.keys()) {
      if (idx <= diff && idx > snapIndex) snapIndex = idx
    }
    const snap = this.#snapshots.get(snapIndex)!
    const work: KernelMutableState = {
      topics: structuredClone(snap.topics),
      seenOps: new Set(snap.seenOps),
      seenOpsRoot: snap.seenOpsRoot,
      historyDigest: snap.historyDigest,
      stateRoot: snap.stateRoot,
    }
    const nextSnapshots = new Map<number, KernelSnapshot>()
    for (const [idx, s] of this.#snapshots) {
      if (idx <= snapIndex) nextSnapshots.set(idx, s)
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
      await this.cas.flushBatch()
      // Atomically commit all derived state once replay and CAS flush succeed so concurrent
      // readers never observe a rewound or partially materialized kernel.
      this.#topics = work.topics
      this.#seenOps = work.seenOps
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
    const makeRejected = (code: string, detail?: string): { readonly kind: 'done'; readonly outcome: KernelOperationOutcome } => {
      const outcome: KernelOperationOutcome = {
        opId: opIdHex,
        author: authorHex,
        operationId: core.operationId,
        authorTimestampMs: core.authorTimestampMs,
        visibility: core.visibility,
        outcome: 'rejected',
        rejectionCode: code,
        ...(detail === undefined ? {} : { rejectionDetail: detail }),
        events: [],
      }
      work.historyDigest = advanceHistoryDigest(work.historyDigest, opIdHex, 'rejected', code, [])
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

    // Copy-on-write working topics map
    const workingTopics: Record<string, JsonValue> = structuredClone(work.topics)
    const emitted: EmittedKernelEvent[] = []
    let ordinal = 0

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

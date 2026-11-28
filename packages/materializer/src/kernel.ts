import { perfTimeAsync } from '@chronolog/canonical'
import {
  bytesToHex,
  decodeCanonicalCbor,
  DEFAULT_DECODE_LIMITS,
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
import type { EmittedKernelEvent, KernelMaterializedCache, KernelOperationOutcome } from './materialized-cache.js'
export type { EmittedKernelEvent, KernelMaterializedCache, KernelOperationOutcome } from './materialized-cache.js'
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

/**
 * Cheap positional snapshot. Topic values are immutable (never mutated in place), so a snapshot
 * is a shallow copy of the topic record plus the lengths of the append-only seen/outcome logs.
 */
export interface KernelSnapshot {
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly topicHashes: ReadonlyMap<string, string>
  readonly topicLastOpIds: ReadonlyMap<string, string>
  readonly authorLastOpIds: ReadonlyMap<string, string>
  readonly publicAuthorLastOpIds: ReadonlyMap<string, string>
  readonly seenLength: number
  readonly historyDigest: string
  readonly stateRoot: string
  readonly orderLength: number
}

/** Append-only keyed log that can be truncated back to an earlier length (O(removed)). */
class AppendLog<V> {
  readonly keys: string[] = []
  readonly #map = new Map<string, { readonly value: V; readonly pos: number }>()
  get length(): number { return this.keys.length }
  has(key: string): boolean { return this.#map.has(key) }
  get(key: string): V | undefined { return this.#map.get(key)?.value }
  /** Value only if it was appended at a position below `limit`. */
  getBefore(key: string, limit: number): V | undefined {
    const entry = this.#map.get(key)
    return entry !== undefined && entry.pos < limit && this.keys[entry.pos] === key ? entry.value : undefined
  }
  /** Position of `key` if present below `limit`. */
  positionBefore(key: string, limit: number): number | undefined {
    const entry = this.#map.get(key)
    return entry !== undefined && entry.pos < limit && this.keys[entry.pos] === key ? entry.pos : undefined
  }
  add(key: string, value: V): void {
    if (this.#map.has(key)) return
    this.#map.set(key, { value, pos: this.keys.length }); this.keys.push(key)
  }
  truncate(length: number): void {
    while (this.keys.length > length) {
      const key = this.keys.pop()!
      const entry = this.#map.get(key)
      if (entry !== undefined && entry.pos >= length) this.#map.delete(key)
    }
  }
  clear(): void { this.keys.length = 0; this.#map.clear() }
  clone(length = this.keys.length): AppendLog<V> {
    const out = new AppendLog<V>()
    for (let i = 0; i < length; i++) out.add(this.keys[i]!, this.#map.get(this.keys[i]!)!.value)
    return out
  }
}

interface KernelMutableState {
  topics: Record<string, JsonValue>
  topicHashes: Map<string, string>
  seen: AppendLog<true>
  outcomes: AppendLog<RecordedOpOutcome>
  topicLastOpIds: Map<string, string>
  authorLastOpIds: Map<string, string>
  publicAuthorLastOpIds: Map<string, string>
  historyDigest: string
  stateRoot: string
}

export interface KernelMaterializeResult {
  readonly revision: KernelRevision
  readonly outcomes: readonly KernelOperationOutcome[]
  /** Outcomes before this index are unchanged (same objects) since the previous materialize. */
  readonly replayedFrom?: number
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

/** Per-input memo: hex op id and whether this input object already passed id/log validation. */
const inputMeta = new WeakMap<KernelOperationInput, { readonly opIdHex: string; readonly logIdHex: string }>()
function metaOf(item: KernelOperationInput): { readonly opIdHex: string; readonly logIdHex: string } {
  let meta = inputMeta.get(item)
  if (meta === undefined) {
    const opIdHex = bytesToHex(item.opId)
    if (item.verified !== true && bytesToHex(operationIdDigest(item.core)) !== opIdHex) throw new Error('KERNEL_OP_ID_MISMATCH')
    meta = { opIdHex, logIdHex: bytesToHex(item.core.logId) }
    inputMeta.set(item, meta)
  }
  return meta
}

function seenOpKey(visibility: OperationVisibility, authorHex: string, operationId: string): string {
  return `${visibility}:${authorHex}:${operationId}`
}

/** Commit an idempotency key set as one CAS node (only at snapshot/checkpoint export, never per op). */
function hashSeenOpsSet(seen: Iterable<string>, cas: ContentAddressedStore, partition: CasPartition): string {
  const sorted = [...seen].sort()
  const bytes = encodeCanonicalCbor(sorted)
  return cas.putSync(bytes, [], partition)
}

/** Content hash of one topic state (domain 'state' over its canonical CBOR). */
function hashTopicBytes(encoded: Uint8Array): string {
  return bytesToHex(hashDomainSync('topic', encoded))
}

function topicHashOf(value: JsonValue): string {
  return hashTopicBytes(encodeCanonicalJsonCbor(value))
}

/**
 * v3 state root: a commitment to the per-topic content hashes. Idempotency (seen-op) state is
 * a deterministic function of the ordered history (already committed by historyDigest), so it is
 * no longer folded into every per-op state root; snapshots/checkpoints carry `seenOpsRoot` explicitly.
 */
function stateRootFromHashes(topicHashes: ReadonlyMap<string, string>): string {
  const names = [...topicHashes.keys()].sort()
  const payload = encodeCanonicalCbor(new Map<string, CborValue>(names.map(name => [name, topicHashes.get(name)!])))
  return bytesToHex(hashDomainSync('state', payload))
}

function computeTopicHashes(topics: Readonly<Record<string, JsonValue>>): Map<string, string> {
  const out = new Map<string, string>()
  for (const [name, value] of Object.entries(topics)) out.set(name, topicHashOf(value))
  return out
}

function computeStateRoot(topics: Readonly<Record<string, JsonValue>>): string {
  return stateRootFromHashes(computeTopicHashes(topics))
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

interface NormalizedSeals {
  readonly reducers: Readonly<Record<string, true>>
  readonly paths: Readonly<Record<string, Readonly<Record<string, 'frozen' | 'append-only'>>>>
}

function normalizeSealsState(raw: JsonValue | undefined): NormalizedSeals {
  const reducers: Record<string, true> = {}
  const paths: Record<string, Record<string, 'frozen' | 'append-only'>> = {}
  if (raw !== null && raw !== undefined && typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Readonly<Record<string, JsonValue>>
    if (obj.reducers && typeof obj.reducers === 'object' && !Array.isArray(obj.reducers)) {
      for (const [k, v] of Object.entries(obj.reducers)) {
        if (v === true && k.length > 0) reducers[k] = true
      }
    }
    if (obj.paths && typeof obj.paths === 'object' && !Array.isArray(obj.paths)) {
      for (const [topic, rules] of Object.entries(obj.paths)) {
        if (!rules || typeof rules !== 'object' || Array.isArray(rules)) continue
        const clean: Record<string, 'frozen' | 'append-only'> = {}
        for (const [p, mode] of Object.entries(rules)) {
          if (p.length > 0 && (mode === 'frozen' || mode === 'append-only')) clean[p] = mode
        }
        if (Object.keys(clean).length > 0) paths[topic] = clean
      }
    }
  }
  return { reducers, paths }
}

function checkSealsMonotonicity(beforeRaw: JsonValue | undefined, afterRaw: JsonValue | undefined): { readonly ok: true } | { readonly ok: false; readonly code: string; readonly detail: string } {
  const before = normalizeSealsState(beforeRaw)
  const after = normalizeSealsState(afterRaw)
  for (const topic of Object.keys(before.reducers)) {
    if (after.reducers[topic] !== true) {
      return { ok: false, code: 'seal:cannot_weaken', detail: `reducer:${topic}` }
    }
  }
  for (const [topic, rules] of Object.entries(before.paths)) {
    const afterRules = after.paths[topic]
    for (const [path, mode] of Object.entries(rules)) {
      const nextMode = afterRules?.[path]
      if (nextMode === undefined || (mode === 'frozen' && nextMode !== 'frozen')) {
        return { ok: false, code: 'seal:cannot_weaken', detail: `${topic}.${path}` }
      }
    }
  }
  return { ok: true }
}

function canonicalValueTag(val: JsonValue | undefined): string {
  if (val === undefined) return 'U'
  return `V:${bytesToHex(encodeCanonicalJsonCbor(val))}`
}

function readTopicPath(root: JsonValue | undefined, path: string): JsonValue | undefined {
  if (path === '*' || path === '') return root
  let cur: JsonValue | undefined = root
  for (const seg of path.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object' || Array.isArray(cur)) return undefined
    const rec = cur as Readonly<Record<string, JsonValue>>
    if (!Object.hasOwn(rec, seg)) return undefined
    cur = rec[seg]
  }
  return cur
}

function resolveEffectiveBindingTag(reducersRaw: JsonValue | undefined, topic: string): string {
  if (reducersRaw === undefined) return 'NONE'
  let cfg: ReducersConfig
  try { cfg = assertValidReducersConfig(reducersRaw) } catch { return 'INVALID' }
  const b = cfg.topics[topic]
  if (b === undefined) return 'UNBOUND'
  const resolvedModule = b.module.startsWith('cas:sha256-') ? b.module : (cfg.imports[b.module] ?? b.module)
  return canonicalValueTag({
    module: resolvedModule,
    export: b.export ?? 'default',
    config: b.config ?? null,
  })
}

function checkSealsEnforced(
  beforeSealsRaw: JsonValue | undefined,
  beforeTopics: Readonly<Record<string, JsonValue>>,
  afterTopics: Readonly<Record<string, JsonValue>>,
): { readonly ok: true } | { readonly ok: false; readonly code: string; readonly detail: string } {
  const seals = normalizeSealsState(beforeSealsRaw)
  const lockedReducers = Object.keys(seals.reducers)
  if (lockedReducers.length > 0 && beforeTopics.$reducers !== afterTopics.$reducers) {
    for (const topic of lockedReducers) {
      if (resolveEffectiveBindingTag(beforeTopics.$reducers, topic) !== resolveEffectiveBindingTag(afterTopics.$reducers, topic)) {
        return { ok: false, code: 'seal:reducer_locked', detail: topic }
      }
    }
  }
  for (const [topic, rules] of Object.entries(seals.paths)) {
    if (beforeTopics[topic] === afterTopics[topic]) continue
    for (const [path, mode] of Object.entries(rules)) {
      const bVal = readTopicPath(beforeTopics[topic], path)
      const aVal = readTopicPath(afterTopics[topic], path)
      if (mode === 'frozen') {
        if (canonicalValueTag(bVal) !== canonicalValueTag(aVal)) {
          return { ok: false, code: 'seal:path_frozen', detail: `${topic}.${path}` }
        }
      } else {
        // append-only
        if (bVal === undefined || bVal === null) continue
        if (Array.isArray(bVal)) {
          if (!Array.isArray(aVal) || aVal.length < bVal.length) {
            return { ok: false, code: 'seal:path_append_only', detail: `${topic}.${path}` }
          }
          const bArr = bVal as readonly JsonValue[]
          const aArr = aVal as readonly JsonValue[]
          for (let i = 0; i < bArr.length; i++) {
            if (canonicalValueTag(bArr[i]) !== canonicalValueTag(aArr[i])) {
              return { ok: false, code: 'seal:path_append_only', detail: `${topic}.${path}[${i}]` }
            }
          }
        } else if (typeof bVal === 'object') {
          if (aVal === null || aVal === undefined || typeof aVal !== 'object' || Array.isArray(aVal)) {
            return { ok: false, code: 'seal:path_append_only', detail: `${topic}.${path}` }
          }
          const aObj = aVal as Readonly<Record<string, JsonValue>>
          for (const [k, v] of Object.entries(bVal)) {
            if (!Object.hasOwn(aObj, k) || canonicalValueTag(v) !== canonicalValueTag(aObj[k])) {
              return { ok: false, code: 'seal:path_append_only', detail: `${topic}.${path}.${k}` }
            }
          }
        } else if (canonicalValueTag(bVal) !== canonicalValueTag(aVal)) {
          return { ok: false, code: 'seal:path_append_only', detail: `${topic}.${path}` }
        }
      }
    }
  }
  return { ok: true }
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
  #topicHashes: Map<string, string>
  /** Live idempotency log; `#committedSeenLength` is its committed prefix. */
  #seen = new AppendLog<true>()
  #committedSeenLength = 0
  /** Live outcome log, positionally aligned with `#order` (+ any restored base). */
  #outcomeLog = new AppendLog<RecordedOpOutcome>()
  #seenRootCache: { readonly length: number; readonly root: string } | null = null
  /** Set when a materialize threw mid-replay: the live logs no longer match committed state. */
  #logsDirty = false
  #topicLastOpIds = new Map<string, string>()
  #authorLastOpIds = new Map<string, string>()
  #publicAuthorLastOpIds = new Map<string, string>()
  #historyDigest: string = ZERO_HASH
  #stateRoot: string
  #pendingDependencies = new Set<string>()
  #skippedOpIds = new Set<string>()
  #snapshots = new Map<number, KernelSnapshot>()
  /** All $reducers module/package CAS hashes ever activated in the current replay window (prevents GC from dropping intermediate upgrades). */
  #historicalReducerRoots = new Set<string>()
  #frontierOpIds = new Set<string>()
  #frontierOrderLength = 0
  #frontierMaxTimestampMs = 0n
  readonly #genesisSnapshot: KernelSnapshot
  #cacheRestores = 0
  /** describe() results per topic, keyed by binding + reducers config + topic content hash. */
  #describeCache = new Map<string, JsonValue | undefined>()
  /** query() results keyed by the exact state they can observe (see #queryScope). */
  #queryCache = new Map<string, JsonValue>()
  /** Memoize whether a resolved $admission binding exports `verify` so logs without verify pay zero overhead. */
  #admissionHasVerify = new Map<string, boolean>()

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
    this.#topicHashes = computeTopicHashes(this.#topics)
    this.#stateRoot = stateRootFromHashes(this.#topicHashes)
    if (this.#topics.$reducers !== undefined) extractCasHashes(this.#topics.$reducers, this.#historicalReducerRoots)
    this.#genesisSnapshot = this.#captureSnapshot(0)
    this.#snapshots.set(0, this.#genesisSnapshot)
  }

  #captureSnapshotFrom(state: KernelMutableState, orderLength: number): KernelSnapshot {
    return {
      topics: { ...state.topics },
      topicHashes: new Map(state.topicHashes),
      topicLastOpIds: new Map(state.topicLastOpIds),
      authorLastOpIds: new Map(state.authorLastOpIds),
      publicAuthorLastOpIds: new Map(state.publicAuthorLastOpIds),
      seenLength: state.seen.length,
      historyDigest: state.historyDigest,
      stateRoot: state.stateRoot,
      orderLength,
    }
  }

  #captureSnapshot(orderLength: number): KernelSnapshot {
    return {
      topics: { ...this.#topics },
      topicHashes: new Map(this.#topicHashes),
      topicLastOpIds: new Map(this.#topicLastOpIds),
      authorLastOpIds: new Map(this.#authorLastOpIds),
      publicAuthorLastOpIds: new Map(this.#publicAuthorLastOpIds),
      seenLength: this.#committedSeenLength,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
      orderLength,
    }
  }

  /** Reset live logs to a restored base: `seenKeys` consumed, no op outcomes yet. */
  #resetLogs(seenKeys: Iterable<string>): void {
    this.#seen.clear()
    for (const key of seenKeys) this.#seen.add(key, true)
    this.#committedSeenLength = this.#seen.length
    this.#outcomeLog.clear()
    this.#seenRootCache = null
    this.#logsDirty = false
  }

  get topics(): Readonly<Record<string, JsonValue>> {
    return structuredClone(this.#topics)
  }

  /** CAS root of the committed idempotency set; computed lazily (O(N log N)) and cached per commit. */
  get seenOpsRoot(): string {
    if (this.#seenRootCache === null || this.#seenRootCache.length !== this.#committedSeenLength) {
      const partition: CasPartition = this.genesis.privateLog && this.blindHostMode ? 'public' : 'private'
      const root = hashSeenOpsSet(this.#seen.keys.slice(0, this.#committedSeenLength), this.cas, partition)
      this.#seenRootCache = { length: this.#committedSeenLength, root }
    }
    return this.#seenRootCache.root
  }

  #disposed = false

  get disposed(): boolean { return this.#disposed }

  /**
   * Release this kernel's VM runtimes, snapshots, logs and caches. Idempotent. Committed revision
   * fields stay readable; materialize/query/describe throw SANDBOX_DISPOSED afterwards.
   */
  dispose(): void {
    if (this.#disposed) return
    this.#disposed = true
    this.sandbox.dispose()
    this.#snapshots.clear()
    this.#queryCache.clear()
    this.#describeCache.clear()
    this.#seen.clear()
    this.#outcomeLog.clear()
    this.#logsDirty = true
  }

  /** Durably persist the committed idempotency set node and return its root (call before exporting state). */
  async commitSeenOpsRoot(): Promise<string> {
    const partition: CasPartition = this.genesis.privateLog && this.blindHostMode ? 'public' : 'private'
    const length = this.#committedSeenLength
    const root = await this.cas.put(encodeCanonicalCbor([...this.#seen.keys.slice(0, length)].sort()), [], partition)
    if (this.#committedSeenLength === length) this.#seenRootCache = { length, root }
    return root
  }

  /** Content hash of a committed topic state (or undefined when absent). */
  topicHash(name: string): string | undefined {
    return this.#topicHashes.get(name)
  }

  snapshot(): {
    readonly topics: Readonly<Record<string, JsonValue>>
    readonly seenOpsRoot: string
    readonly historyDigest: string
    readonly stateRoot: string
  } {
    return {
      topics: structuredClone(this.#topics),
      seenOpsRoot: this.seenOpsRoot,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
    }
  }

  topic(name: string): JsonValue | null {
    return Object.hasOwn(this.#topics, name) ? structuredClone(this.#topics[name]!) : null
  }

  opOutcome(opId: string): 'accepted' | 'rejected' | null {
    const committed = this.#outcomes.length
    if (!this.#logsDirty) {
      const hit = this.#outcomeLog.getBefore(opId, committed)
      if (hit !== undefined) return hit.outcome
    }
    // Slow path (mid-replay or dirty logs): consult the committed outcome list.
    for (let i = committed - 1; i >= 0; i--) if (this.#outcomes[i]!.opId === opId) return this.#outcomes[i]!.outcome
    return null
  }

  topicLastOpId(topic: string): string | null {
    return this.#topicLastOpIds.get(topic) ?? null
  }

  authorLastOpId(author: string, options: { readonly publicOnly?: boolean } = {}): string | null {
    return (options.publicOnly === true ? this.#publicAuthorLastOpIds : this.#authorLastOpIds).get(author) ?? null
  }

  get outcomes(): readonly KernelOperationOutcome[] {
    return this.#outcomes.slice()
  }

  /** Committed outcome for one op in O(1) (falls back to a scan mid-replay). */
  outcomeOf(opId: string): KernelOperationOutcome | undefined {
    if (!this.#logsDirty) {
      const pos = this.#outcomeLog.positionBefore(opId, this.#outcomes.length)
      if (pos !== undefined && this.#outcomes[pos]?.opId === opId) return this.#outcomes[pos]
    }
    return this.#outcomes.find(o => o.opId === opId)
  }

  /** Committed outcome list without copying (replaced, never mutated, on each commit). */
  get materializedOutcomes(): readonly KernelOperationOutcome[] {
    return this.#outcomes
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

  /** Collect all CAS root hashes reachable from current state + retained suffix snapshots + historical $reducers (for local GC). */
  gcRoots(): Set<string> {
    const roots = new Set<string>(this.#historicalReducerRoots)
    if (this.#seenRootCache !== null) roots.add(this.#seenRootCache.root)
    extractCasHashes(this.#topics, roots)
    for (const snap of this.#snapshots.values()) extractCasHashes(snap.topics, roots)
    return roots
  }

  get cacheRestores(): number {
    return this.#cacheRestores
  }

  /**
   * Export the committed state for instant cold open (local cache) or snapshot bootstrap.
   * `suffix: false` omits the replayable suffix (order ids, outcomes and events) and folds it
   * into the frontier, giving a bundle whose size is O(state + op count x 32 bytes).
   * Outcome/event objects are immutable and shared, not cloned.
   */
  exportMaterializedCache(options: { readonly suffix?: boolean } = {}): KernelMaterializedCache {
    const orderOpIds = this.#order.map(item => metaOf(item).opIdHex)
    const includeSuffix = options.suffix !== false
    let maxTs = this.#frontierMaxTimestampMs
    if (!includeSuffix) for (const o of this.#outcomes) if (o.authorTimestampMs > maxTs) maxTs = o.authorTimestampMs
    return {
      v: 2,
      logId: this.logIdHex,
      blindHostMode: this.blindHostMode,
      topics: this.#topics,
      seenOpsRoot: this.seenOpsRoot,
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
      frontierOpIds: includeSuffix ? [...this.#frontierOpIds] : [...this.#frontierOpIds, ...orderOpIds],
      frontierMaxTimestampMs: maxTs,
      orderOpIds: includeSuffix ? orderOpIds : [],
      outcomes: includeSuffix ? this.#outcomes : [],
      topicLastOpIds: Object.fromEntries(this.#topicLastOpIds),
      authorLastOpIds: Object.fromEntries(this.#authorLastOpIds),
      publicAuthorLastOpIds: Object.fromEntries(this.#publicAuthorLastOpIds),
    }
  }

  /** Validate cache state against local CAS and decode its idempotency set (null on any miss). */
  async #loadCacheBase(cache: KernelMaterializedCache): Promise<string[] | null> {
    if (
      cache.v !== 2 ||
      cache.logId !== this.logIdHex ||
      cache.blindHostMode !== this.blindHostMode ||
      !Array.isArray(cache.orderOpIds) ||
      !Array.isArray(cache.frontierOpIds) ||
      !Array.isArray(cache.outcomes) ||
      cache.orderOpIds.length !== cache.outcomes.length
    ) {
      return null
    }
    if (computeStateRoot(cache.topics) !== cache.stateRoot) return null
    const seenNode = await this.cas.get(cache.seenOpsRoot, 'any')
    if (seenNode === null) return null
    const neededCas = new Set<string>()
    extractRequiredCasHashes(cache.topics, neededCas)
    for (const hash of neededCas) {
      if (!this.cas.hasSync(hash, 'any') && await this.cas.get(hash, 'any') === null) return null
    }
    try {
      // The seen node is content-addressed (its hash was checked when it entered CAS), so a plain
      // decode suffices; no canonical re-encode round trip.
      const raw = decodeCanonicalCbor(seenNode.bytes, DEFAULT_DECODE_LIMITS)
      if (!Array.isArray(raw)) return null
      return raw.filter((v): v is string => typeof v === 'string')
    } catch {
      return null
    }
  }

  /**
   * Restore materialized state directly from a previously exported cache if:
   * - logId, blindHostMode, and recomputed stateRoot match exactly,
   * - seenOpsRoot and every CAS node hash referenced by topics exist locally, and
   * - every suffix op id in cache.orderOpIds is present in `inputs` (in canonical order).
   * O(N) id lookups; no re-sort. Inputs not in the cache are applied by the next materialize().
   * Returns true on cache hit, false on miss.
   */
  async restoreMaterializedCache(
    cache: KernelMaterializedCache,
    inputs: readonly KernelOperationInput[],
  ): Promise<boolean> {
    if (cache.orderOpIds === undefined || (cache.orderOpIds.length === 0 && (cache.frontierOpIds?.length ?? 0) === 0)) return false
    const decodedSeen = await this.#loadCacheBase(cache)
    if (decodedSeen === null) return false

    const byId = new Map<string, KernelOperationInput>()
    for (const item of inputs) {
      const meta = metaOf(item)
      if (meta.logIdHex !== this.logIdHex) continue
      if (this.blindHostMode && this.genesis.privateLog && item.core.visibility !== 'public') continue
      byId.set(meta.opIdHex, item)
    }
    const prefixLen = cache.orderOpIds.length
    const order: KernelOperationInput[] = new Array<KernelOperationInput>(prefixLen)
    for (let i = 0; i < prefixLen; i++) {
      const item = byId.get(cache.orderOpIds[i]!)
      if (item === undefined) return false
      if (i > 0) {
        const prev = order[i - 1]!
        if (compareOperationOrder(
          { authorTimestampMs: prev.core.authorTimestampMs, author: prev.core.author, opId: prev.opId },
          { authorTimestampMs: item.core.authorTimestampMs, author: item.core.author, opId: item.opId },
        ) >= 0) return false
      }
      order[i] = item
    }

    this.#order = order
    this.#outcomes = cache.outcomes.slice()
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(cache.topics)) : structuredClone(cache.topics)
    this.#topicHashes = computeTopicHashes(this.#topics)
    this.#resetLogs(decodedSeen)
    this.#seenRootCache = { length: this.#committedSeenLength, root: cache.seenOpsRoot }
    this.#topicLastOpIds = new Map(Object.entries(cache.topicLastOpIds ?? {}))
    this.#authorLastOpIds = new Map(Object.entries(cache.authorLastOpIds ?? {}))
    this.#publicAuthorLastOpIds = new Map(Object.entries(cache.publicAuthorLastOpIds ?? {}))
    for (const o of this.#outcomes) {
      this.#outcomeLog.add(o.opId, { outcome: o.outcome, visibility: o.visibility })
    }
    this.#frontierOpIds = new Set(cache.frontierOpIds)
    this.#frontierOrderLength = cache.frontierOpIds.length
    this.#frontierMaxTimestampMs = BigInt(cache.frontierMaxTimestampMs ?? 0n)
    this.#historyDigest = cache.historyDigest
    this.#stateRoot = cache.stateRoot
    this.#pendingDependencies.clear()
    this.#skippedOpIds.clear()
    this.#snapshots.clear()
    // With a frontier the genesis snapshot is not a valid rewind base: the base is the frontier.
    if (this.#frontierOrderLength === 0) this.#snapshots.set(0, this.#genesisSnapshot)
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
    const computedStateRoot = computeStateRoot(checkpoint.topics)
    if (computedStateRoot !== checkpoint.stateRoot) {
      throw new Error(`CHECKPOINT_STATE_ROOT_MISMATCH: expected ${checkpoint.stateRoot}, got ${computedStateRoot}`)
    }
    this.#order = []
    this.#outcomes = []
    this.#topicLastOpIds.clear()
    this.#authorLastOpIds.clear()
    this.#publicAuthorLastOpIds.clear()
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(checkpoint.topics)) : structuredClone(checkpoint.topics)
    this.#topicHashes = computeTopicHashes(this.#topics)
    this.#resetLogs(decodedSeen)
    this.#seenRootCache = { length: this.#committedSeenLength, root: checkpoint.seenOpsRoot }
    this.#historyDigest = checkpoint.historyDigest
    this.#stateRoot = checkpoint.stateRoot
    this.#snapshots.clear()
    this.#snapshots.set(0, this.#captureSnapshot(0))
    this.#historicalReducerRoots.clear()
    if (this.#topics.$reducers !== undefined) extractCasHashes(this.#topics.$reducers, this.#historicalReducerRoots)
  }

  /**
   * Bootstrap kernel state from a verified snapshot WITHOUT the historical operations: every op in
   * the cache (frontier and suffix) becomes frontier, so materialize(inputs) skips those ops and
   * applies only operations that are new. Trust: the caller has verified the snapshot's signer.
   */
  async restoreSnapshotFrontier(cache: KernelMaterializedCache): Promise<boolean> {
    const decodedSeen = await this.#loadCacheBase(cache)
    if (decodedSeen === null) return false
    let maxTs = BigInt(cache.frontierMaxTimestampMs ?? 0n)
    for (const o of cache.outcomes) if (o.authorTimestampMs > maxTs) maxTs = o.authorTimestampMs
    this.#order = []
    this.#outcomes = []
    this.#topicLastOpIds = new Map(Object.entries(cache.topicLastOpIds ?? {}))
    this.#authorLastOpIds = new Map(Object.entries(cache.authorLastOpIds ?? {}))
    this.#publicAuthorLastOpIds = new Map(Object.entries(cache.publicAuthorLastOpIds ?? {}))
    this.#topics = this.blindHostMode ? filterPublicTopics(structuredClone(cache.topics)) : structuredClone(cache.topics)
    this.#topicHashes = computeTopicHashes(this.#topics)
    this.#resetLogs(decodedSeen)
    this.#seenRootCache = { length: this.#committedSeenLength, root: cache.seenOpsRoot }
    this.#historyDigest = cache.historyDigest
    this.#stateRoot = cache.stateRoot
    this.#frontierOpIds = new Set([...cache.frontierOpIds, ...cache.orderOpIds])
    this.#frontierOrderLength = this.#frontierOpIds.size
    this.#frontierMaxTimestampMs = maxTs
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
    return perfTimeAsync('kernel.materialize', () => this.materialize__impl(inputs))
  }

  async materialize__impl(inputs: readonly KernelOperationInput[]): Promise<KernelMaterializeResult> {
    if (this.#disposed) throw new Error('SANDBOX_DISPOSED')
    // Filter for blindHostMode and logId, sort strictly by canonical comparator
    const eligible: KernelOperationInput[] = []
    const seenIds = new Set<string>()
    for (const item of inputs) {
      const meta = metaOf(item)
      if (meta.logIdHex !== this.logIdHex) continue
      if (this.blindHostMode && this.genesis.privateLog && item.core.visibility !== 'public') continue
      const opIdHex = meta.opIdHex
      if (this.#frontierOpIds.has(opIdHex)) continue
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
      const prev = this.#order[diff]!, next = eligible[diff]!
      if (prev !== next && metaOf(prev).opIdHex !== metaOf(next).opIdHex) break
      diff++
    }
    // Fast path: identical eligible set and no pending dependencies — nothing to re-evaluate
    if (diff === eligible.length && this.#order.length === eligible.length && this.#pendingDependencies.size === 0) {
      return {
        revision: this.revision('local'),
        outcomes: this.#outcomes,
        replayedFrom: this.#outcomes.length,
        pendingDependencies: this.pendingDependencies,
        skippedOpIds: [...this.#skippedOpIds],
      }
    }
    // A previous run that stopped at a missing dependency simply left #order shorter; the divergence
    // scan above already resumes from that point. Only a replay that threw mid-way (dirty logs)
    // forces a rebuild from the base snapshot.
    if (this.#logsDirty) {
      diff = 0
      for (const idx of [...this.#snapshots.keys()]) if (idx !== 0) this.#snapshots.delete(idx)
    }

    // Find nearest cached snapshot <= diff (includes the rolling tip snapshot at this.#order.length!)
    let snapIndex = 0
    for (const idx of this.#snapshots.keys()) {
      if (idx <= diff && idx > snapIndex) snapIndex = idx
    }
    const snapshotAt = this.#snapshots.get(snapIndex)
    // A frontier (snapshot bootstrap) cannot be rewound: an op that would sort before ops folded
    // into it, or a rewind below the restored suffix base, needs a full replay by the caller.
    if (snapshotAt === undefined) throw new Error('KERNEL_FRONTIER_REWIND')
    if (this.#frontierOrderLength > 0) {
      for (let i = diff; i < eligible.length; i++) {
        if (eligible[i]!.core.authorTimestampMs <= this.#frontierMaxTimestampMs) throw new Error('KERNEL_FRONTIER_REWIND')
      }
    }
    const snap = snapshotAt
    // Rewind the live logs to the snapshot (O(rewound ops)); topic values are immutable so the
    // working topic record is a shallow copy.
    this.#seen.truncate(snap.seenLength)
    this.#outcomeLog.truncate(snapIndex)
    this.#logsDirty = true
    const work: KernelMutableState = {
      topics: { ...snap.topics },
      topicHashes: new Map(snap.topicHashes),
      seen: this.#seen,
      outcomes: this.#outcomeLog,
      topicLastOpIds: new Map(snap.topicLastOpIds),
      authorLastOpIds: new Map(snap.authorLastOpIds),
      publicAuthorLastOpIds: new Map(snap.publicAuthorLastOpIds),
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
      this.#topicHashes = work.topicHashes
      this.#topicLastOpIds = work.topicLastOpIds
      this.#authorLastOpIds = work.authorLastOpIds
      this.#publicAuthorLastOpIds = work.publicAuthorLastOpIds
      this.#historyDigest = work.historyDigest
      this.#stateRoot = work.stateRoot
      this.#order = nextOrder
      this.#outcomes = nextOutcomes
      this.#committedSeenLength = this.#seen.length
      this.#seenRootCache = null
      this.#logsDirty = false
      this.#pendingDependencies = nextPendingDeps
      this.#skippedOpIds = nextSkippedOps
      this.#snapshots = nextSnapshots
    } catch (err) {
      this.cas.rollbackBatch()
      throw err
    }

    return {
      revision: this.revision('local'),
      // Committed outcome arrays are never mutated in place, so callers may hold this reference.
      outcomes: this.#outcomes,
      replayedFrom: Math.min(snapIndex, this.#outcomes.length),
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
      work.outcomes.add(opIdHex, { outcome: 'rejected', visibility: core.visibility })
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
    if (work.seen.has(dedupKey)) {
      return makeRejected('operation_conflict')
    }

    // Consume idempotency handle (even if reducer rejects, matching Chronolog's contract)
    const casPartition: CasPartition = (this.genesis.privateLog && core.visibility === 'public') ? 'public' : 'private'
    const isPublicOnPrivate = this.genesis.privateLog && core.visibility === 'public'

    const visibleOutcome = (opId: string): 'accepted' | 'rejected' | null => {
      const rec = work.outcomes.get(opId)
      if (rec === undefined || (isPublicOnPrivate && rec.visibility !== 'public')) return null
      return rec.outcome
    }
    const buildVisibleTopicLastOpIds = (): Record<string, string> => {
      const out: Record<string, string> = {}
      for (const [topicName, lastId] of work.topicLastOpIds) {
        if (isPublicOnPrivate && !isControlTopic(topicName)) continue
        out[topicName] = lastId
      }
      return out
    }

    const buildVisibleAuthorLastOpIds = (): Record<string, string> => {
      const source = isPublicOnPrivate ? work.publicAuthorLastOpIds : work.authorLastOpIds
      return Object.fromEntries(source)
    }

    // Evaluate signed operation-level assumptions before applying topic updates
    if (core.assumptions !== undefined && core.assumptions.checks.length > 0) {
      const visibleTopicsForAssumptions = isPublicOnPrivate ? filterPublicTopics(work.topics) : work.topics
      const visibleTopicLastOps = buildVisibleTopicLastOpIds()
      const visibleAuthorLastOps = buildVisibleAuthorLastOpIds()
      let failure: { readonly code: string; readonly detail?: string; readonly checkIndex: number } | null = null

      for (let i = 0; i < core.assumptions.checks.length; i++) {
        const chk: OperationAssumption = core.assumptions.checks[i]!
        if (chk.kind === 'op_accepted') {
          const st = visibleOutcome(chk.opId)
          if (st === null) {
            failure = { code: 'assumption:missing_op', detail: `Required op ${chk.opId} not present`, checkIndex: i }
            break
          }
          if (st !== 'accepted') {
            failure = { code: 'assumption:dependency_rejected', detail: `Required op ${chk.opId} was rejected`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'op_rejected') {
          const st = visibleOutcome(chk.opId)
          if (st === null) {
            failure = { code: 'assumption:missing_op', detail: `Referenced op ${chk.opId} not present`, checkIndex: i }
            break
          }
          if (st !== 'rejected') {
            failure = { code: 'assumption:expected_rejected', detail: `Expected op ${chk.opId} to be rejected`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'op_present') {
          const st = visibleOutcome(chk.opId)
          if (st === null) {
            failure = { code: 'assumption:missing_op', detail: `Required op ${chk.opId} not present`, checkIndex: i }
            break
          }
        } else if (chk.kind === 'author_last_op') {
          const targetAuthor = chk.author ?? authorHex
          const actual = Object.hasOwn(visibleAuthorLastOps, targetAuthor) ? visibleAuthorLastOps[targetAuthor]! : null
          if (actual !== chk.lastOpId) {
            failure = { code: 'assumption:author_history_mismatch', detail: `Author ${targetAuthor} lastOpId expected ${String(chk.lastOpId)}, got ${String(actual)}`, checkIndex: i }
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
                opOutcome: visibleOutcome,
                topicLastOpIds: visibleTopicLastOps,
                topics: visibleTopicsForAssumptions,
                ...(binding.config === undefined ? {} : { config: binding.config }),
                cas: this.cas,
                casPartition: (isPublicOnPrivate || isControlTopic(chk.topic)) ? 'public' : 'private',
                readOnly: true,
                maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
                ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
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
        work.seen.add(dedupKey, true)
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
                opOutcome: visibleOutcome,
                topicLastOpIds: visibleTopicLastOps,
                topics: visibleTopicsForAssumptions,
                ...(binding.config === undefined ? {} : { config: binding.config }),
                cas: this.cas,
                casPartition,
                readOnly: false,
                maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
                ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
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
                  work.topicHashes.set(primaryUpdate.topic, hashTopicBytes(encodedTopic))
                  work.stateRoot = stateRootFromHashes(work.topicHashes)
                  return makeRejected(failure.code, failure.detail, { conflictRecorded: true, events: conflictEvents })
                }
              }
            }
          }
        }
        return makeRejected(failure.code, failure.detail)
      }
    }

    // Copy-on-write working topics map (topic values are immutable; only the record is copied)
    const workingTopics: Record<string, JsonValue> = { ...work.topics }
    const workingHashes = new Map<string, string>()
    const topicHash = (name: string): string | undefined => workingHashes.get(name) ?? work.topicHashes.get(name)
    const emitted: EmittedKernelEvent[] = []
    let ordinal = 0
    const visibleTopicLastOpsForReduce = buildVisibleTopicLastOpIds()
    const visibleAuthorLastOpsForReduce = buildVisibleAuthorLastOpIds()

    // Global fail-closed $admission.authorize(state, tx, ctx) gate (monotonic attenuation:
    // topic reducers can only tighten, never weaken global admission decisions).
    if (core.updates.some(u => u.topic !== '$admission')) {
      let authReducersConfig: ReducersConfig
      try {
        authReducersConfig = assertValidReducersConfig(workingTopics.$reducers)
      } catch (err) {
        return makeRejected('reducers_config_invalid', err instanceof Error ? err.message : String(err))
      }
      const admissionBinding = authReducersConfig.topics.$admission
      if (admissionBinding !== undefined) {
        let authRes
        try {
          authRes = await this.sandbox.invoke({
            imports: authReducersConfig.imports,
            builtins: authReducersConfig.runtime.builtins,
            topicBindings: authReducersConfig.topics,
            moduleSpecifier: admissionBinding.module,
            exportName: admissionBinding.export ?? 'default',
            method: 'authorize',
            state: Object.hasOwn(workingTopics, '$admission') ? workingTopics.$admission! : null,
            payload: null,
            tx: {
              opId: opIdHex,
              author: authorHex,
              authorTimestampMs: Number(core.authorTimestampMs),
              operationId: core.operationId,
              visibility: core.visibility,
              updates: core.updates,
            },
            opOutcome: visibleOutcome,
            topicLastOpIds: visibleTopicLastOpsForReduce,
            authorLastOpIds: visibleAuthorLastOpsForReduce,
            txVisibility: core.visibility,
            topics: filterPublicTopics(workingTopics),
            topicHash,
            ...(admissionBinding.config === undefined ? {} : { config: admissionBinding.config }),
            cas: this.cas,
            casPartition: 'public',
            readOnly: true,
            maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
            ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
          })
        } catch (err) {
          if (err instanceof MissingDependencyError) {
            return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
          }
          throw err
        }
        if (authRes.ok) {
          if (authRes.value === false) {
            work.seen.add(dedupKey, true)
            return makeRejected('admission_denied')
          }
          if (authRes.value !== null && typeof authRes.value === 'object' && !Array.isArray(authRes.value)) {
            const authObj = authRes.value as Readonly<Record<string, JsonValue>>
            if (authObj.ok === false) {
              work.seen.add(dedupKey, true)
              return makeRejected(
                typeof authObj.code === 'string' && authObj.code.length > 0 ? authObj.code : 'admission_denied',
                typeof authObj.detail === 'string' ? authObj.detail : undefined,
              )
            }
          }
        } else if (authRes.code !== 'vm:missing_method:authorize') {
          work.seen.add(dedupKey, true)
          return makeRejected(authRes.code, authRes.detail)
        }
      }
    }

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
          opOutcome: visibleOutcome,
          topicLastOpIds: visibleTopicLastOpsForReduce,
          authorLastOpIds: visibleAuthorLastOpsForReduce,
          txVisibility: core.visibility,
          topics: visibleTopics,
          topicHash,
          ...(binding.config === undefined ? {} : { config: binding.config }),
          cas: this.cas,
          casPartition,
          readOnly: false,
          maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
          ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
        })
      } catch (err) {
        if (err instanceof MissingDependencyError) {
          return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
        }
        throw err
      }

      if (!res.ok) {
        work.seen.add(dedupKey, true)
        return makeRejected(res.code, res.detail)
      }

      const outObj = res.value
      if (outObj === null || typeof outObj !== 'object' || Array.isArray(outObj)) {
        work.seen.add(dedupKey, true)
        return makeRejected('vm:invalid_reducer_return')
      }
      const outRec = outObj as Readonly<Record<string, JsonValue>>
      if (typeof outRec.ok !== 'boolean') {
        work.seen.add(dedupKey, true)
        return makeRejected('vm:invalid_reducer_return')
      }

      if (!outRec.ok) {
        const rejCode = typeof outRec.code === 'string' && outRec.code.length > 0 ? outRec.code : 'reducer:rejected'
        const rejDetail = typeof outRec.detail === 'string' ? outRec.detail : undefined
        work.seen.add(dedupKey, true)
        return makeRejected(rejCode, rejDetail)
      }

      const nextTopicState: JsonValue = outRec.state === undefined ? null : outRec.state
      const encodedTopic = encodeCanonicalJsonCbor(nextTopicState)
      if (encodedTopic.length > this.genesis.limits.maxTopicStateBytes) {
        work.seen.add(dedupKey, true)
        return makeRejected('limit:max_topic_state_bytes')
      }

      // If updating $reducers, validate new config shape immediately and pin its module hashes!
      if (update.topic === '$reducers') {
        try { assertValidReducersConfig(nextTopicState) }
        catch (err) {
          work.seen.add(dedupKey, true)
          return makeRejected('reducers_config_invalid', err instanceof Error ? err.message : String(err))
        }
        extractCasHashes(nextTopicState, this.#historicalReducerRoots)
      }

      workingTopics[update.topic] = nextTopicState
      workingHashes.set(update.topic, hashTopicBytes(encodedTopic))

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

    // Kernel-enforced monotonic immutability controller ($seals):
    // 1. Existing seals can NEVER be removed or weakened (even if $seals reducer were modified).
    const sealMono = checkSealsMonotonicity(work.topics.$seals, workingTopics.$seals)
    if (!sealMono.ok) {
      work.seen.add(dedupKey, true)
      return makeRejected(sealMono.code, sealMono.detail)
    }
    // 2. Enforce all active reducer hash locks and frozen/append-only JSON path locks.
    const sealCheck = checkSealsEnforced(work.topics.$seals, work.topics, workingTopics)
    if (!sealCheck.ok) {
      work.seen.add(dedupKey, true)
      return makeRejected(sealCheck.code, sealCheck.detail)
    }

    // 3. Optional flat semantic post-condition hook: $admission.verify(before, after, tx, ctx).
    //    Skipped in O(1) when the resolved $admission module does not export `verify`.
    {
      let postReducersConfig: ReducersConfig | null = null
      try { postReducersConfig = assertValidReducersConfig(workingTopics.$reducers) } catch { /* ignore */ }
      const admBinding = postReducersConfig?.topics.$admission
      if (postReducersConfig !== null && admBinding !== undefined) {
        const verifyCacheKey = resolveEffectiveBindingTag(workingTopics.$reducers, '$admission')
        if (this.#admissionHasVerify.get(verifyCacheKey) !== false) {
          const isPublicOnly = this.genesis.privateLog && core.visibility === 'public'
          const visibleBefore = isPublicOnly ? filterPublicTopics(work.topics) : work.topics
          const visibleAfter = isPublicOnly ? filterPublicTopics(workingTopics) : workingTopics
          let verifyRes
          try {
            verifyRes = await this.sandbox.invoke({
              imports: postReducersConfig.imports,
              builtins: postReducersConfig.runtime.builtins,
              topicBindings: postReducersConfig.topics,
              moduleSpecifier: admBinding.module,
              exportName: admBinding.export ?? 'default',
              method: 'verify',
              state: Object.hasOwn(visibleAfter, '$admission') ? visibleAfter.$admission! : null,
              payload: { before: visibleBefore, after: visibleAfter },
              tx: {
                opId: opIdHex,
                author: authorHex,
                authorTimestampMs: Number(core.authorTimestampMs),
                operationId: core.operationId,
                visibility: core.visibility,
                updates: core.updates,
              },
              opOutcome: visibleOutcome,
              topicLastOpIds: visibleTopicLastOpsForReduce,
              authorLastOpIds: visibleAuthorLastOpsForReduce,
              txVisibility: core.visibility,
              topics: visibleAfter,
              topicHash,
              ...(admBinding.config === undefined ? {} : { config: admBinding.config }),
              cas: this.cas,
              casPartition: isPublicOnly ? 'public' : casPartition,
              readOnly: true,
              maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
              ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
            })
          } catch (err) {
            if (err instanceof MissingDependencyError) {
              return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
            }
            throw err
          }
          if (!verifyRes.ok && verifyRes.code === 'vm:missing_method:verify') {
            this.#admissionHasVerify.set(verifyCacheKey, false)
          } else {
            this.#admissionHasVerify.set(verifyCacheKey, true)
            if (!verifyRes.ok) {
              work.seen.add(dedupKey, true)
              return makeRejected(verifyRes.code, verifyRes.detail)
            }
            if (verifyRes.value === false) {
              work.seen.add(dedupKey, true)
              return makeRejected('verify:rejected')
            }
            if (verifyRes.value !== null && typeof verifyRes.value === 'object' && !Array.isArray(verifyRes.value)) {
              const vObj = verifyRes.value as Readonly<Record<string, JsonValue>>
              if (vObj.ok === false) {
                work.seen.add(dedupKey, true)
                return makeRejected(
                  typeof vObj.code === 'string' && vObj.code.length > 0 ? vObj.code : 'verify:rejected',
                  typeof vObj.detail === 'string' ? vObj.detail : undefined,
                )
              }
            }
          }
        }
      }
    }

    // Atomic commit of all topic updates in this op
    work.seen.add(dedupKey, true)
    work.topics = workingTopics
    for (const [name, hash] of workingHashes) work.topicHashes.set(name, hash)
    work.outcomes.add(opIdHex, { outcome: 'accepted', visibility: core.visibility })
    for (const u of core.updates) {
      work.topicLastOpIds.set(u.topic, opIdHex)
    }
    work.authorLastOpIds.set(authorHex, opIdHex)
    if (core.visibility === 'public') {
      work.publicAuthorLastOpIds.set(authorHex, opIdHex)
    }
    work.stateRoot = stateRootFromHashes(work.topicHashes)
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
      cacheKey = `${topic}\0${this.#queryScope(topic)}\0${bytesToHex(encodeCanonicalJsonCbor(normalizedInput))}`
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
    const isPublicOnly = this.genesis.privateLog && isControlTopic(topic)
    const casPartition: CasPartition = isPublicOnly ? 'public' : 'private'
    const visibleTopics = isPublicOnly
      ? filterPublicTopics(sourceTopics)
      : sourceTopics
    const visibleTopicLastOps: Record<string, string> = {}
    for (const [tName, lastId] of this.#topicLastOpIds) {
      if (isPublicOnly && !isControlTopic(tName)) continue
      visibleTopicLastOps[tName] = lastId
    }
    const visibleAuthorLastOps = Object.fromEntries(isPublicOnly ? this.#publicAuthorLastOpIds : this.#authorLastOpIds)
    const visibleOpOutcome = (opId: string): 'accepted' | 'rejected' | null => {
      const committed = this.#outcomes.length
      if (!this.#logsDirty) {
        const hit = this.#outcomeLog.getBefore(opId, committed)
        if (hit !== undefined) return (isPublicOnly && hit.visibility !== 'public') ? null : hit.outcome
      }
      for (let i = committed - 1; i >= 0; i--) {
        const o = this.#outcomes[i]!
        if (o.opId === opId) return (isPublicOnly && o.visibility !== 'public') ? null : o.outcome
      }
      return null
    }
    const historyRows = this.#outcomes
      .filter(o => !isPublicOnly || o.visibility === 'public')
      .map((o, idx) => ({
        seq: this.#frontierOrderLength + idx,
        opId: o.opId,
        author: o.author,
        operationId: o.operationId,
        authorTimestampMs: Number(o.authorTimestampMs),
        visibility: o.visibility,
        outcome: o.outcome,
        rejectionCode: o.rejectionCode,
      }))
    const res = await this.sandbox.invoke({
      imports: reducersConfig.imports,
      builtins: reducersConfig.runtime.builtins,
      topicBindings: reducersConfig.topics,
      moduleSpecifier: binding.module,
      exportName: binding.export ?? 'default',
      method: 'query',
      state,
      payload: normalizedInput,
      opOutcome: visibleOpOutcome,
      topicLastOpIds: visibleTopicLastOps,
      authorLastOpIds: visibleAuthorLastOps,
      historyRows,
      topics: visibleTopics,
      ...(topicsOverride === undefined ? { topicHash: (name: string) => this.#topicHashes.get(name) } : {}),
      ...(binding.config === undefined ? {} : { config: binding.config }),
      cas: this.cas,
      casPartition,
      readOnly: true,
      maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
      ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
    })
    if (!res.ok) {
      if (res.code === 'vm:missing_method:query') return structuredClone(state)
      throw new Error(`KERNEL_QUERY_FAILED:${res.code}:${res.detail ?? ''}`)
    }
    if (cacheKey !== null && this.#topics === sourceTopics) {
      this.#queryCache.set(cacheKey, structuredClone(res.value))
      if (this.#queryCache.size > 256) {
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
    const snap = this.#snapshots.get(snapIndex)
    if (snap === undefined) throw new Error('TIME_TRAVEL_BEFORE_FRONTIER')
    if (this.#logsDirty) throw new Error('KERNEL_REPLAY_IN_PROGRESS')
    const work: KernelMutableState = {
      topics: { ...snap.topics },
      topicHashes: new Map(snap.topicHashes),
      seen: this.#seen.clone(snap.seenLength),
      outcomes: this.#outcomeLog.clone(snapIndex),
      topicLastOpIds: new Map(snap.topicLastOpIds),
      authorLastOpIds: new Map(snap.authorLastOpIds),
      publicAuthorLastOpIds: new Map(snap.publicAuthorLastOpIds),
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
    const reducersConfig = assertValidReducersConfig(this.#topics.$reducers)
    const out: Record<string, JsonValue> = {}
    const liveKeys = new Set<string>()
    for (const [topic, binding] of Object.entries(reducersConfig.topics)) {
      if (this.blindHostMode && this.genesis.privateLog && !isControlTopic(topic)) continue
      const key = `${topic}\0${this.#queryScope(topic)}`
      liveKeys.add(key)
      if (this.#describeCache.has(key)) {
        const hit = this.#describeCache.get(key)
        if (hit !== undefined) out[topic] = structuredClone(hit)
        continue
      }
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
        ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
      })
      if (res.ok) out[topic] = res.value
      this.#describeCache.set(key, res.ok ? structuredClone(res.value) : undefined)
    }
    for (const key of [...this.#describeCache.keys()]) if (!liveKeys.has(key)) this.#describeCache.delete(key)
    return out
  }

  /**
   * Cache scope for read-only calls on `topic`: everything such a call can observe. Control topics on
   * private logs can only observe control topics (partition rule), so app writes never invalidate them.
   */
  #queryScope(topic: string): string {
    if (this.genesis.privateLog && isControlTopic(topic)) {
      let scope = ''
      for (const [name, hash] of this.#topicHashes) if (isControlTopic(name)) scope += `${name}=${hash};`
      return scope
    }
    return this.#stateRoot
  }

  /**
   * Simulate an operation against the current materialized state without mutating
   * persisted CAS, kernel state, or outcomes (ephemeral dry-run).
   */
  async simulate(entry: KernelOperationInput): Promise<{
    readonly ok: boolean
    readonly outcome: 'accepted' | 'rejected'
    readonly rejectionCode: string | null
    readonly rejectionDetail?: string
    readonly events: readonly EmittedKernelEvent[]
    readonly changedTopics: readonly string[]
    readonly stateRoot: string
  }> {
    if (this.#logsDirty) throw new Error('KERNEL_REPLAY_IN_PROGRESS')
    const work: KernelMutableState = {
      topics: { ...this.#topics },
      topicHashes: new Map(this.#topicHashes),
      seen: this.#seen.clone(this.#committedSeenLength),
      outcomes: this.#outcomeLog.clone(this.#outcomes.length),
      topicLastOpIds: new Map(this.#topicLastOpIds),
      authorLastOpIds: new Map(this.#authorLastOpIds),
      publicAuthorLastOpIds: new Map(this.#publicAuthorLastOpIds),
      historyDigest: this.#historyDigest,
      stateRoot: this.#stateRoot,
    }
    const opIdHex = bytesToHex(entry.opId)
    const authorHex = bytesToHex(entry.core.author)
    this.cas.beginBatch()
    try {
      const step = await this.#applyOne(work, entry, opIdHex, authorHex)
      if (step.kind === 'missing') {
        throw new MissingDependencyError(step.dependency.split('/')[1] ?? step.dependency, 'cas')
      }
      const changedTopics: string[] = []
      for (const [name, hash] of work.topicHashes) {
        if (this.#topicHashes.get(name) !== hash) changedTopics.push(name)
      }
      changedTopics.sort()
      return {
        ok: step.outcome.outcome === 'accepted',
        outcome: step.outcome.outcome,
        rejectionCode: step.outcome.rejectionCode,
        ...(step.outcome.rejectionDetail === undefined ? {} : { rejectionDetail: step.outcome.rejectionDetail }),
        events: step.outcome.events,
        changedTopics,
        stateRoot: work.stateRoot,
      }
    } finally {
      this.cas.rollbackBatch()
    }
  }

  /**
   * Create a deterministic `AdmissionEvaluator` that invokes the log's state-defined
   * `$admission.admit(state, { logId, ops, evidence, pinnedFrontier }, ctx)` function
   * against public control state and available external evidence. Runs identically on
   * browsers, Node agents, and blind Cloudflare Worker hosts.
   */
  createAdmissionEvaluator(): (input: {
    readonly logId: string
    readonly ops: readonly { readonly opId: string; readonly author: string; readonly authorTimestampMs: bigint; readonly visibility: 'public' | 'encrypted' }[]
    readonly evidence: readonly unknown[]
    readonly pinnedFrontier?: { readonly closedThroughMs: bigint; readonly stateRoot: string; readonly historyDigest: string; readonly includedOpIds: readonly string[] } | null
  }) => Promise<{
    readonly closedThroughMs?: number | string | bigint | null
    readonly includedOpIds?: readonly string[]
    readonly excludedOpIds?: readonly string[]
    readonly verifiedEvidenceIndices?: readonly number[]
    readonly latestCheckpointIndex?: number | null
    readonly equivocations?: readonly { readonly signer: string; readonly scopeId?: string; readonly reason: string; readonly detail?: string }[]
  } | null> {
    const toJsonSafe = (value: unknown, depth = 0): JsonValue => {
      if (depth > 16 || value === null || value === undefined) return null
      if (typeof value === 'boolean' || typeof value === 'string') return value
      if (typeof value === 'number') return Number.isFinite(value) ? value : String(value)
      if (typeof value === 'bigint') return value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value.toString()
      if (value instanceof Uint8Array) return bytesToHex(value)
      if (Array.isArray(value)) return value.map(item => toJsonSafe(item, depth + 1))
      if (typeof value === 'object') {
        const out: Record<string, JsonValue> = {}
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          if (v !== undefined) out[k] = toJsonSafe(v, depth + 1)
        }
        return out
      }
      return null
    }
    return async (input) => {
      let reducersConfig: ReducersConfig
      try { reducersConfig = assertValidReducersConfig(this.#topics.$reducers) } catch { return null }
      const binding = reducersConfig.topics.$admission
      if (binding === undefined) return null
      const visibleControlTopics = filterPublicTopics(this.#topics)
      const payload = toJsonSafe(input)
      try {
        const res = await this.sandbox.invoke({
          imports: reducersConfig.imports,
          builtins: reducersConfig.runtime.builtins,
          topicBindings: reducersConfig.topics,
          moduleSpecifier: binding.module,
          exportName: binding.export ?? 'default',
          method: 'admit',
          state: visibleControlTopics.$admission ?? null,
          payload,
          topics: visibleControlTopics,
          ...(binding.config === undefined ? {} : { config: binding.config }),
          cas: this.cas,
          casPartition: 'public',
          readOnly: true,
          maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
          ...(this.genesis.limits.maxFuel === undefined ? {} : { maxFuel: this.genesis.limits.maxFuel }),
        })
        if (!res.ok || res.value === null || typeof res.value !== 'object' || Array.isArray(res.value)) return null
        return res.value as {
          readonly closedThroughMs?: number | string | bigint | null
          readonly includedOpIds?: readonly string[]
          readonly excludedOpIds?: readonly string[]
          readonly verifiedEvidenceIndices?: readonly number[]
          readonly latestCheckpointIndex?: number | null
          readonly equivocations?: readonly { readonly signer: string; readonly scopeId?: string; readonly reason: string; readonly detail?: string }[]
        }
      } catch {
        return null
      }
    }
  }

  /** Evaluate signal authorization policy from `$admission` for the current stateRoot. */
  async signalPolicy(): Promise<{ readonly rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] }> {
    const val = await this.query('$admission', { kind: 'signals' }).catch(() => null)
    if (val !== null && typeof val === 'object' && !Array.isArray(val) && Array.isArray((val as Readonly<Record<string, JsonValue>>).rules)) {
      return val as { readonly rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] }
    }
    return { rules: [] }
  }
}

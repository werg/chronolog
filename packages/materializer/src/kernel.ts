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
  type ReducerInvocationResult,
} from './quickjs-sandbox.js'

export interface KernelOperationInput {
  readonly opId: Uint8Array
  readonly core: OperationCore
  /** Caller already verified opId === operationIdDigest(core); skips O(N) CBOR+SHA-256 re-verification on every materialize(). */
  readonly verified?: boolean
  /** Compartment key ring that decrypted this encrypted operation ('default' when omitted). */
  readonly ring?: string
  /**
   * Public envelope epoch of an encrypted operation on a private log. Required to enforce
   * `$keys.policy.maxOpsPerEpoch`: when that budget is set, an encrypted op without it is rejected.
   */
  readonly epoch?: number
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
  /** Key ring of an encrypted op on a private log (null otherwise); scopes outcome visibility. */
  readonly ring: string | null
}

type ApplyStep =
  | { readonly kind: 'done'; readonly outcome: KernelOperationOutcome }
  | { readonly kind: 'missing'; readonly dependency: string }

type TopicBindingConfig = ReducersConfig['topics'][string]

interface AssumptionFailure {
  readonly code: string
  readonly detail: string
  readonly checkIndex: number
}

/** Everything one operation's evaluation may observe (see TopicKernel#opView). */
interface OpView {
  readonly visible: (topic: string) => boolean
  readonly filter: (topics: Readonly<Record<string, JsonValue>>) => Readonly<Record<string, JsonValue>>
  readonly topicLastOpIds: Readonly<Record<string, string>>
  readonly authorLastOpIds: Readonly<Record<string, string>>
  readonly opOutcome: (opId: string) => 'accepted' | 'rejected' | null
  /** Public op on a private log (`$*` only). */
  readonly publicOnly: boolean
}

interface OpContext {
  readonly core: OperationCore
  readonly opIdHex: string
  readonly authorHex: string
  readonly view: OpView
  /** CAS partition reducers of this op write to. */
  readonly casPartition: CasPartition
}

interface CommitCandidate {
  readonly kind: 'commit'
  readonly topics: Record<string, JsonValue>
  readonly hashes: ReadonlyMap<string, string>
  readonly events: readonly EmittedKernelEvent[]
}

type EvaluateResult = CommitCandidate | { readonly kind: 'rejected'; readonly code: string; readonly detail?: string }

/**
 * Interpret an authorize/verify result: null when allowed (including a module that does not export
 * the method), otherwise the rejection. `false` or `{ ok: false, code?, detail? }` deny.
 */
function decisionDenial(
  res: ReducerInvocationResult,
  method: 'authorize' | 'verify',
  defaultCode: string,
): { readonly kind: 'rejected'; readonly code: string; readonly detail?: string } | null {
  if (!res.ok) {
    if (res.code === `vm:missing_method:${method}`) return null
    return { kind: 'rejected', code: res.code, ...(res.detail === undefined ? {} : { detail: res.detail }) }
  }
  if (res.value === false) return { kind: 'rejected', code: defaultCode }
  if (res.value !== null && typeof res.value === 'object' && !Array.isArray(res.value)) {
    const obj = res.value as Readonly<Record<string, JsonValue>>
    if (obj.ok === false) {
      return {
        kind: 'rejected',
        code: typeof obj.code === 'string' && obj.code.length > 0 ? obj.code : defaultCode,
        ...(typeof obj.detail === 'string' ? { detail: obj.detail } : {}),
      }
    }
  }
  return null
}

/** `$keys.topicRings` (topic -> ring) or null when the log defines no ring bindings. */
function topicRingsOf(topics: Readonly<Record<string, JsonValue>>): Readonly<Record<string, JsonValue>> | null {
  const keys = topics.$keys
  if (keys === null || keys === undefined || typeof keys !== 'object' || Array.isArray(keys)) return null
  const raw = (keys as Readonly<Record<string, JsonValue>>).topicRings
  return raw !== undefined && raw !== null && typeof raw === 'object' && !Array.isArray(raw)
    ? (raw as Readonly<Record<string, JsonValue>>)
    : null
}

/** `$keys.policy.maxOpsPerEpoch` as a positive safe integer, or null when no budget is set. */
function maxOpsPerEpochOf(topics: Readonly<Record<string, JsonValue>>): number | null {
  const keys = topics.$keys
  if (keys === null || typeof keys !== 'object' || Array.isArray(keys)) return null
  const policy = (keys as Readonly<Record<string, JsonValue>>).policy
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) return null
  const max = (policy as Readonly<Record<string, JsonValue>>).maxOpsPerEpoch
  return typeof max === 'number' && Number.isSafeInteger(max) && max >= 1 ? max : null
}

function ringOfTopic(topicRings: Readonly<Record<string, JsonValue>> | null, topic: string): string {
  const bound = topicRings?.[topic]
  return typeof bound === 'string' && bound.length > 0 ? bound : 'default'
}

/** Private-log `authorLastOpIds` key: last op of `author` among ops of `ring` (newer than its last public op). */
function ringAuthorKey(ring: string, author: string): string {
  return `${ring}:${author}`
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
  readonly epochOpCounts: ReadonlyMap<string, number>
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
  /** Private logs: `${ring}:${epoch}` -> accepted encrypted ops (for `$keys.policy.maxOpsPerEpoch`). */
  epochOpCounts: Map<string, number>
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

/** Commitment over every topic's content hash (CRDT contract §4 `stateRoot`). */
export function computeStateRoot(topics: Readonly<Record<string, JsonValue>>): string {
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

/**
 * Deterministic identity of a topic's reducer binding, used by `$seals.reducers` pinning and the
 * `$admission.verify` presence memo. It is a pure function of `$reducers` (never of local CAS
 * contents): the binding's module reference, export and config plus the log-wide runtime
 * (engine + builtins) and the FULL import map, which is everything module resolution can consult
 * (`chronolog/*` overrides, package fallbacks to top-level imports, transitive bare specifiers).
 * Consequently a sealed reducer also freezes the import map; new topics can still be added with
 * direct `cas:sha256-...` module references in `$reducers.topics`.
 */
function reducerBindingTag(reducersRaw: JsonValue | undefined, topic: string): string {
  if (reducersRaw === undefined) return 'NONE'
  let cfg: ReducersConfig
  try { cfg = assertValidReducersConfig(reducersRaw) } catch { return 'INVALID' }
  const b = cfg.topics[topic]
  if (b === undefined) return 'UNBOUND'
  return canonicalValueTag({
    module: b.module,
    export: b.export ?? 'default',
    config: b.config ?? null,
    runtime: { js: cfg.runtime.js, builtins: cfg.runtime.builtins },
    imports: cfg.imports,
  })
}

/** The binding's own resolved module reference, export and config (diagnostics only). */
function directBindingTag(reducersRaw: JsonValue | undefined, topic: string): string {
  if (reducersRaw === undefined) return 'NONE'
  let cfg: ReducersConfig
  try { cfg = assertValidReducersConfig(reducersRaw) } catch { return 'INVALID' }
  const b = cfg.topics[topic]
  if (b === undefined) return 'UNBOUND'
  return canonicalValueTag({ module: cfg.imports[b.module] ?? b.module, export: b.export ?? 'default', config: b.config ?? null })
}

function checkSealsEnforced(
  beforeSealsRaw: JsonValue | undefined,
  beforeTopics: Readonly<Record<string, JsonValue>>,
  afterTopics: Readonly<Record<string, JsonValue>>,
): { readonly ok: true } | { readonly ok: false; readonly code: string; readonly detail: string } {
  const seals = normalizeSealsState(beforeSealsRaw)
  const lockedReducers = Object.keys(seals.reducers)
  if (lockedReducers.length > 0 && beforeTopics.$reducers !== afterTopics.$reducers) {
    const violated = lockedReducers
      .filter(topic => reducerBindingTag(beforeTopics.$reducers, topic) !== reducerBindingTag(afterTopics.$reducers, topic))
      .sort()
    if (violated.length > 0) {
      // Report the sealed topics whose own module/export/config changed; fall back to every sealed
      // topic invalidated only by a shared import-map or runtime change.
      const direct = violated.filter(topic => directBindingTag(beforeTopics.$reducers, topic) !== directBindingTag(afterTopics.$reducers, topic))
      return { ok: false, code: 'seal:reducer_locked', detail: (direct.length > 0 ? direct : violated).join(',') }
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
 * Chronolog Topic Kernel & Suffix-Replay Engine.
 * - Flat timestamp-ordered operation set: (authorTimestampMs, author, opId)
 * - Strict two-way public/encrypted control partition (blind-host equivalent)
 * - Scoped idempotency (visibility, author, operationId) in authenticated seenOpsRoot
 * - Rolling historyDigest + stateRoot + revision.digest
 * - Fresh QuickJSContext per call + uncatchable MissingDependency suspension
 * - `$keys.topicRings` compartments: an encrypted op only observes `$*` and its own ring
 * - Consensus calls are bounded by genesis `limits.maxFuel` only (no wall clock)
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
  /**
   * Non-private logs: author -> last accepted op. Private logs: `${ring}:${author}` -> last accepted
   * encrypted op of that ring, present only while newer than the author's last public op.
   */
  #authorLastOpIds = new Map<string, string>()
  #publicAuthorLastOpIds = new Map<string, string>()
  /** `${ring}:${epoch}` -> accepted encrypted ops of that epoch (enforces `$keys.policy.maxOpsPerEpoch`). */
  #epochOpCounts = new Map<string, number>()
  #historyDigest: string = ZERO_HASH
  #stateRoot: string
  #pendingDependencies = new Set<string>()
  #skippedOpIds = new Set<string>()
  #snapshots = new Map<number, KernelSnapshot>()
  /** All $reducers module/package CAS hashes ever activated in the current replay window (prevents GC from dropping intermediate upgrades). */
  #historicalReducerRoots = new Set<string>()
  /** Every key ring ever seen (monotonic superset; only used to retire ring-scoped author entries). */
  #ringNames = new Set<string>(['default'])
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
      epochOpCounts: new Map(state.epochOpCounts),
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
      epochOpCounts: new Map(this.#epochOpCounts),
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

  /** Record ring names that appear in restored ring-scoped author entries. */
  #seedRingNames(): void {
    if (!this.genesis.privateLog) return
    for (const key of this.#authorLastOpIds.keys()) {
      const at = key.lastIndexOf(':')
      if (at > 0) this.#ringNames.add(key.slice(0, at))
    }
  }

  /**
   * Last accepted op of `author` as an operation authored now would observe it (`author_last_op`
   * assumptions): `publicOnly` for a public op; otherwise, on private logs, the view of an encrypted
   * op in `ring` (default 'default'): its ring's ops and all public ops.
   */
  authorLastOpId(author: string, options: { readonly publicOnly?: boolean; readonly ring?: string } = {}): string | null {
    if (options.publicOnly === true) return this.#publicAuthorLastOpIds.get(author) ?? null
    if (!this.genesis.privateLog) return this.#authorLastOpIds.get(author) ?? null
    return this.#authorLastOpIds.get(ringAuthorKey(options.ring ?? 'default', author)) ?? this.#publicAuthorLastOpIds.get(author) ?? null
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
      epochOpCounts: Object.fromEntries(this.#epochOpCounts),
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
    this.#epochOpCounts = new Map(Object.entries(cache.epochOpCounts ?? {}))
    for (let i = 0; i < this.#outcomes.length; i++) {
      const o = this.#outcomes[i]!
      const ring = this.genesis.privateLog && o.visibility === 'encrypted' ? (order[i]!.ring ?? 'default') : null
      this.#outcomeLog.add(o.opId, { outcome: o.outcome, visibility: o.visibility, ring })
    }
    this.#seedRingNames()
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
    this.#epochOpCounts.clear()
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
    this.#epochOpCounts = new Map(Object.entries(cache.epochOpCounts ?? {}))
    this.#seedRingNames()
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
      epochOpCounts: new Map(snap.epochOpCounts),
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
      this.#epochOpCounts = work.epochOpCounts
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

  /**
   * Apply one operation to `work`. A MissingDependencyError anywhere in evaluation suspends the op
   * (`kind: 'missing'`) and leaves `work` exactly as it was (including the idempotency log).
   */
  async #applyOne(
    work: KernelMutableState,
    entry: KernelOperationInput,
    opIdHex: string,
    authorHex: string,
  ): Promise<ApplyStep> {
    const seenMark = work.seen.length
    try {
      return await this.#applyOneInner(work, entry, opIdHex, authorHex)
    } catch (err) {
      if (err instanceof MissingDependencyError) {
        work.seen.truncate(seenMark)
        return { kind: 'missing', dependency: `${err.kind}/${err.hash}` }
      }
      throw err
    }
  }

  async #applyOneInner(
    work: KernelMutableState,
    entry: KernelOperationInput,
    opIdHex: string,
    authorHex: string,
  ): Promise<ApplyStep> {
    const core = entry.core
    const privateLog = this.genesis.privateLog
    const ring = privateLog && core.visibility === 'encrypted' ? (entry.ring ?? 'default') : null
    if (ring !== null) this.#ringNames.add(ring)
    const reject = (
      code: string,
      detail?: string,
      extra?: { readonly conflictRecorded?: boolean; readonly events?: readonly EmittedKernelEvent[] },
    ): ApplyStep => {
      const evs = extra?.events ?? []
      work.outcomes.add(opIdHex, { outcome: 'rejected', visibility: core.visibility, ring })
      work.historyDigest = advanceHistoryDigest(work.historyDigest, opIdHex, 'rejected', code, evs)
      return {
        kind: 'done',
        outcome: {
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
        },
      }
    }

    // Scoped idempotency (visibility, author, operationId). Every outcome other than this duplicate
    // rejection consumes the key, so the consumed set is a pure function of the ordered history.
    const dedupKey = seenOpKey(core.visibility, authorHex, core.operationId)
    if (work.seen.has(dedupKey)) return reject('operation_conflict')
    work.seen.add(dedupKey, true)

    const topicRings = topicRingsOf(work.topics)
    if (privateLog) {
      if (core.visibility === 'public') {
        if (core.updates.some(u => !isControlTopic(u.topic))) return reject('partition:public_op_private_topic')
      } else {
        if (core.updates.some(u => isControlTopic(u.topic))) return reject('partition:encrypted_op_control_topic')
        // Kernel-enforced compartment ring isolation: any topic bound in `$keys.topicRings` MUST be
        // encrypted under that exact ring and cannot be mixed with another ring.
        if (topicRings !== null) {
          let requiredRing: string | null = null
          for (const u of core.updates) {
            const topicRing = ringOfTopic(topicRings, u.topic)
            if (requiredRing === null) requiredRing = topicRing
            else if (requiredRing !== topicRing) {
              return reject('ring:mixed_updates', `Cannot mix topics from rings "${requiredRing}" and "${topicRing}"`)
            }
          }
          if (requiredRing !== null && ring !== requiredRing) {
            return reject('ring:mismatch', `Expected ring "${requiredRing}", got "${String(ring)}"`)
          }
        }
      }
    }
    if (core.updates.length > this.genesis.limits.maxUpdatesPerOp) return reject('limit:max_updates_per_op')

    // `$keys.policy.maxOpsPerEpoch`: accepted encrypted ops per (ring, envelope epoch), counted in
    // canonical order. Every replica holding the ring key sees the same ops, so the cut is identical.
    let epochKey: string | null = null
    if (ring !== null) {
      const budget = maxOpsPerEpochOf(work.topics)
      if (entry.epoch !== undefined) epochKey = `${ring}:${entry.epoch}`
      if (budget !== null) {
        if (epochKey === null) return reject('epoch_op_budget_exhausted', 'Encrypted operation input carries no envelope epoch')
        if ((work.epochOpCounts.get(epochKey) ?? 0) >= budget) {
          return reject('epoch_op_budget_exhausted', `Epoch ${String(entry.epoch)} of ring "${ring}" reached $keys.policy.maxOpsPerEpoch (${String(budget)})`)
        }
      }
    }

    const view = this.#opView(work, core.visibility, ring, topicRings)
    const op: OpContext = {
      core,
      opIdHex,
      authorHex,
      view,
      casPartition: privateLog && core.visibility === 'public' ? 'public' : 'private',
    }

    if (core.assumptions !== undefined && core.assumptions.checks.length > 0) {
      const failure = await this.#checkAssumptions(work, op)
      if (failure !== null) {
        const foreign = failure.code === 'partition:public_op_private_assumption' || failure.code === 'ring:foreign_assumption'
        if (core.assumptions.onFailed === 'record_conflict' && !foreign) {
          const evaluated = await this.#evaluate(work, op, failure)
          if (evaluated.kind === 'commit') {
            this.#commitTopics(work, evaluated)
            return reject(failure.code, failure.detail, { conflictRecorded: true, events: evaluated.events })
          }
        }
        return reject(failure.code, failure.detail)
      }
    }

    const evaluated = await this.#evaluate(work, op, null)
    if (evaluated.kind === 'rejected') return reject(evaluated.code, evaluated.detail)
    this.#commitTopics(work, evaluated)
    work.outcomes.add(opIdHex, { outcome: 'accepted', visibility: core.visibility, ring })
    if (epochKey !== null) work.epochOpCounts.set(epochKey, (work.epochOpCounts.get(epochKey) ?? 0) + 1)
    for (const u of core.updates) work.topicLastOpIds.set(u.topic, opIdHex)
    if (!privateLog) {
      work.authorLastOpIds.set(authorHex, opIdHex)
    } else if (ring !== null) {
      work.authorLastOpIds.set(ringAuthorKey(ring, authorHex), opIdHex)
    } else {
      // A later public op supersedes every ring-scoped entry of this author (see #opView).
      for (const name of this.#ringNames) work.authorLastOpIds.delete(ringAuthorKey(name, authorHex))
    }
    if (core.visibility === 'public') work.publicAuthorLastOpIds.set(authorHex, opIdHex)
    work.historyDigest = advanceHistoryDigest(work.historyDigest, opIdHex, 'accepted', null, evaluated.events)
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
        events: evaluated.events,
      },
    }
  }

  /** Install an evaluated candidate's topic states (and pin any new `$reducers` module hashes). */
  #commitTopics(work: KernelMutableState, candidate: CommitCandidate): void {
    if (candidate.topics.$reducers !== work.topics.$reducers && candidate.topics.$reducers !== undefined) {
      extractCasHashes(candidate.topics.$reducers, this.#historicalReducerRoots)
    }
    work.topics = candidate.topics
    for (const [name, hash] of candidate.hashes) work.topicHashes.set(name, hash)
    work.stateRoot = stateRootFromHashes(work.topicHashes)
  }

  /**
   * What an operation's evaluation may observe. Public ops on private logs see `$*` only; encrypted
   * ops see `$*` plus the topics, outcomes and last-op ids of their own `$keys` ring, so a replica's
   * result never depends on which other rings it can decrypt. Non-private logs see everything.
   */
  #opView(
    work: KernelMutableState,
    visibility: OperationVisibility,
    ring: string | null,
    topicRings: Readonly<Record<string, JsonValue>> | null,
  ): OpView {
    if (!this.genesis.privateLog) {
      return {
        visible: () => true,
        filter: topics => topics,
        topicLastOpIds: Object.fromEntries(work.topicLastOpIds),
        authorLastOpIds: Object.fromEntries(work.authorLastOpIds),
        opOutcome: opId => work.outcomes.get(opId)?.outcome ?? null,
        publicOnly: false,
      }
    }
    if (visibility === 'public' || ring === null) {
      return {
        visible: isControlTopic,
        filter: filterPublicTopics,
        topicLastOpIds: Object.fromEntries([...work.topicLastOpIds].filter(([t]) => isControlTopic(t))),
        authorLastOpIds: Object.fromEntries(work.publicAuthorLastOpIds),
        opOutcome: opId => {
          const rec = work.outcomes.get(opId)
          return rec === undefined || rec.visibility !== 'public' ? null : rec.outcome
        },
        publicOnly: true,
      }
    }
    const visible = (topic: string): boolean => isControlTopic(topic) || ringOfTopic(topicRings, topic) === ring
    const allVisible = topicRings === null && ring === 'default'
    const authorLastOpIds: Record<string, string> = Object.fromEntries(work.publicAuthorLastOpIds)
    const prefix = `${ring}:`
    for (const [key, opId] of work.authorLastOpIds) {
      if (key.startsWith(prefix) && key.lastIndexOf(':') === prefix.length - 1) authorLastOpIds[key.slice(prefix.length)] = opId
    }
    return {
      visible,
      filter: allVisible ? topics => topics : topics => {
        const out: Record<string, JsonValue> = {}
        for (const [k, v] of Object.entries(topics)) if (visible(k)) out[k] = v
        return out
      },
      topicLastOpIds: Object.fromEntries([...work.topicLastOpIds].filter(([t]) => visible(t))),
      authorLastOpIds,
      opOutcome: opId => {
        const rec = work.outcomes.get(opId)
        return rec === undefined || (rec.visibility !== 'public' && rec.ring !== ring) ? null : rec.outcome
      },
      publicOnly: false,
    }
  }

  /** Shared `sandbox.invoke` plumbing for every consensus call made while applying `op`. */
  #invokeFor(
    op: OpContext,
    config: ReducersConfig,
    binding: TopicBindingConfig,
    call: {
      readonly method: 'reduce' | 'query' | 'onConflict' | 'authorize' | 'verify'
      readonly state: JsonValue
      readonly payload: JsonValue
      readonly topics: Readonly<Record<string, JsonValue>>
      readonly casPartition: CasPartition
      readonly readOnly: boolean
      readonly controlTx?: boolean
      readonly conflict?: AssumptionFailure
    },
  ): Promise<ReducerInvocationResult> {
    const core = op.core
    return this.sandbox.invoke({
      logId: this.logIdHex,
      imports: config.imports,
      builtins: config.runtime.builtins,
      topicBindings: config.topics,
      moduleSpecifier: binding.module,
      exportName: binding.export ?? 'default',
      method: call.method,
      state: call.state,
      payload: call.payload,
      tx: call.controlTx === true
        ? {
            opId: op.opIdHex,
            author: op.authorHex,
            authorTimestampMs: Number(core.authorTimestampMs),
            operationId: core.operationId,
            visibility: core.visibility,
            updates: core.updates,
          }
        : { opId: op.opIdHex, author: op.authorHex, authorTimestampMs: Number(core.authorTimestampMs), operationId: core.operationId },
      ...(call.conflict === undefined ? {} : { conflict: call.conflict }),
      opOutcome: op.view.opOutcome,
      topicLastOpIds: op.view.topicLastOpIds,
      authorLastOpIds: op.view.authorLastOpIds,
      txVisibility: core.visibility,
      topics: call.topics,
      ...(binding.config === undefined ? {} : { config: binding.config }),
      cas: this.cas,
      casPartition: call.casPartition,
      readOnly: call.readOnly,
      maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
      maxFuel: this.genesis.limits.maxFuel,
    })
  }

  /** Evaluate signed operation-level assumptions against the op's view; null when all hold. */
  async #checkAssumptions(work: KernelMutableState, op: OpContext): Promise<AssumptionFailure | null> {
    const checks = op.core.assumptions?.checks ?? []
    const foreign = (topic: string, what: string, checkIndex: number): AssumptionFailure => op.view.publicOnly
      ? { code: 'partition:public_op_private_assumption', detail: `Public op cannot ${what} private topic ${topic}`, checkIndex }
      : { code: 'ring:foreign_assumption', detail: `Op cannot ${what} topic ${topic} of another key ring`, checkIndex }
    for (let i = 0; i < checks.length; i++) {
      const chk: OperationAssumption = checks[i]!
      if (chk.kind === 'op_accepted' || chk.kind === 'op_rejected' || chk.kind === 'op_present') {
        const st = op.view.opOutcome(chk.opId)
        if (st === null) return { code: 'assumption:missing_op', detail: `Required op ${chk.opId} not present`, checkIndex: i }
        if (chk.kind === 'op_accepted' && st !== 'accepted') {
          return { code: 'assumption:dependency_rejected', detail: `Required op ${chk.opId} was rejected`, checkIndex: i }
        }
        if (chk.kind === 'op_rejected' && st !== 'rejected') {
          return { code: 'assumption:expected_rejected', detail: `Expected op ${chk.opId} to be rejected`, checkIndex: i }
        }
      } else if (chk.kind === 'author_last_op') {
        const targetAuthor = chk.author ?? op.authorHex
        const ids = op.view.authorLastOpIds
        const actual = Object.hasOwn(ids, targetAuthor) ? ids[targetAuthor]! : null
        if (actual !== chk.lastOpId) {
          return { code: 'assumption:author_history_mismatch', detail: `Author ${targetAuthor} lastOpId expected ${String(chk.lastOpId)}, got ${String(actual)}`, checkIndex: i }
        }
      } else if (chk.kind === 'topic_revision') {
        if (!op.view.visible(chk.topic)) return foreign(chk.topic, 'assume', i)
        const ids = op.view.topicLastOpIds
        const actual = Object.hasOwn(ids, chk.topic) ? ids[chk.topic]! : null
        if (actual !== chk.lastOpId) {
          return { code: 'assumption:topic_modified', detail: `Topic ${chk.topic} lastOpId expected ${String(chk.lastOpId)}, got ${String(actual)}`, checkIndex: i }
        }
      } else if (chk.kind === 'query_match') {
        if (!op.view.visible(chk.topic)) return foreign(chk.topic, 'query', i)
        let config: ReducersConfig
        try {
          config = assertValidReducersConfig(work.topics.$reducers)
        } catch (err) {
          return { code: 'reducers_config_invalid', detail: err instanceof Error ? err.message : String(err), checkIndex: i }
        }
        const binding = config.topics[chk.topic]
        const topicState: JsonValue = Object.hasOwn(work.topics, chk.topic) ? work.topics[chk.topic]! : null
        let actualValue: JsonValue = topicState
        if (binding !== undefined) {
          const qRes = await this.#invokeFor(op, config, binding, {
            method: 'query',
            state: topicState,
            payload: chk.query,
            topics: op.view.filter(work.topics),
            casPartition: op.view.publicOnly || isControlTopic(chk.topic) ? 'public' : 'private',
            readOnly: true,
          })
          if (qRes.ok) actualValue = qRes.value
          else if (qRes.code !== 'vm:missing_method:query') {
            return { code: 'assumption:query_failed', detail: qRes.detail ?? qRes.code, checkIndex: i }
          }
        }
        if (canonicalJson(actualValue) !== canonicalJson(chk.expect)) {
          return { code: 'assumption:query_mismatch', detail: `Query assumption ${i} on ${chk.topic} did not match`, checkIndex: i }
        }
      }
    }
    return null
  }

  /**
   * The single candidate pipeline shared by normal application and `onConflict` recording:
   * `$admission.authorize` -> reduce (every update) or onConflict (primary update) -> `$reducers`
   * validation -> kernel `$seals` monotonicity + enforcement -> `$admission.verify`.
   * Returns the candidate topic states to commit, or the rejection.
   */
  async #evaluate(work: KernelMutableState, op: OpContext, conflict: AssumptionFailure | null): Promise<EvaluateResult> {
    const core = op.core
    let config: ReducersConfig
    try {
      config = assertValidReducersConfig(work.topics.$reducers)
    } catch (err) {
      return { kind: 'rejected', code: 'reducers_config_invalid', detail: err instanceof Error ? err.message : String(err) }
    }
    const workingTopics: Record<string, JsonValue> = { ...work.topics }
    const workingHashes = new Map<string, string>()

    // 1. Global fail-closed $admission.authorize(state, tx, ctx) gate (monotonic attenuation: topic
    //    reducers can only tighten, never weaken global admission decisions).
    const admission = config.topics.$admission
    if (admission !== undefined && core.updates.some(u => u.topic !== '$admission')) {
      const authRes = await this.#invokeFor(op, config, admission, {
        method: 'authorize',
        state: Object.hasOwn(workingTopics, '$admission') ? workingTopics.$admission! : null,
        payload: null,
        topics: filterPublicTopics(workingTopics),
        casPartition: 'public',
        readOnly: true,
        controlTx: true,
      })
      const denied = decisionDenial(authRes, 'authorize', 'admission_denied')
      if (denied !== null) return denied
    }

    // 2. Produce the candidate: every update through its reducer, or the primary update's onConflict.
    const events: EmittedKernelEvent[] = []
    const updates = conflict === null ? core.updates : core.updates.slice(0, 1)
    for (const update of updates) {
      let stepConfig: ReducersConfig
      try {
        stepConfig = assertValidReducersConfig(workingTopics.$reducers)
      } catch (err) {
        return { kind: 'rejected', code: 'reducers_config_invalid', detail: err instanceof Error ? err.message : String(err) }
      }
      const binding = stepConfig.topics[update.topic]
      if (binding === undefined) {
        // No reducer for $reducers means rules are permanently frozen; any other unbound topic rejects cleanly.
        return { kind: 'rejected', code: update.topic === '$reducers' ? 'reducers_frozen' : `no_reducer:${update.topic}` }
      }
      const res = await this.#invokeFor(op, stepConfig, binding, {
        method: conflict === null ? 'reduce' : 'onConflict',
        state: Object.hasOwn(workingTopics, update.topic) ? workingTopics[update.topic]! : null,
        payload: update.input,
        topics: op.view.filter(workingTopics),
        casPartition: op.casPartition,
        readOnly: false,
        ...(conflict === null ? {} : { conflict }),
      })
      if (!res.ok) return { kind: 'rejected', code: res.code, ...(res.detail === undefined ? {} : { detail: res.detail }) }
      const out = res.value
      if (out === null || typeof out !== 'object' || Array.isArray(out)) return { kind: 'rejected', code: 'vm:invalid_reducer_return' }
      const outRec = out as Readonly<Record<string, JsonValue>>
      if (typeof outRec.ok !== 'boolean') return { kind: 'rejected', code: 'vm:invalid_reducer_return' }
      if (!outRec.ok) {
        return {
          kind: 'rejected',
          code: typeof outRec.code === 'string' && outRec.code.length > 0 ? outRec.code : 'reducer:rejected',
          ...(typeof outRec.detail === 'string' ? { detail: outRec.detail } : {}),
        }
      }
      const nextTopicState: JsonValue = outRec.state === undefined ? null : outRec.state
      const encodedTopic = encodeCanonicalJsonCbor(nextTopicState)
      if (encodedTopic.length > this.genesis.limits.maxTopicStateBytes) return { kind: 'rejected', code: 'limit:max_topic_state_bytes' }
      if (update.topic === '$reducers') {
        try { assertValidReducersConfig(nextTopicState) } catch (err) {
          return { kind: 'rejected', code: 'reducers_config_invalid', detail: err instanceof Error ? err.message : String(err) }
        }
      }
      workingTopics[update.topic] = nextTopicState
      workingHashes.set(update.topic, hashTopicBytes(encodedTopic))
      if (Array.isArray(outRec.events)) {
        for (const rawEv of outRec.events as readonly JsonValue[]) {
          if (rawEv === null || typeof rawEv !== 'object' || Array.isArray(rawEv)) continue
          const ev = rawEv as Readonly<Record<string, JsonValue>>
          if (typeof ev.topic !== 'string') continue
          events.push({
            opId: op.opIdHex,
            eventOrdinal: events.length,
            topic: ev.topic,
            payload: ev.payload ?? null,
            author: op.authorHex,
            operationId: core.operationId,
            authorTimestampMs: core.authorTimestampMs,
          })
        }
      }
    }

    // 3. Kernel-enforced monotonic immutability ($seals): existing seals can never be removed or
    //    weakened, and every reducer pin and frozen/append-only path lock holds.
    const sealMono = checkSealsMonotonicity(work.topics.$seals, workingTopics.$seals)
    if (!sealMono.ok) return { kind: 'rejected', code: sealMono.code, detail: sealMono.detail }
    const sealCheck = checkSealsEnforced(work.topics.$seals, work.topics, workingTopics)
    if (!sealCheck.ok) return { kind: 'rejected', code: sealCheck.code, detail: sealCheck.detail }

    // 4. Optional flat semantic post-condition $admission.verify(before, after, tx, ctx), resolved
    //    from the post-state config; skipped in O(1) once a binding is known not to export verify.
    let postConfig: ReducersConfig | null = null
    try { postConfig = assertValidReducersConfig(workingTopics.$reducers) } catch { /* validated above */ }
    const postAdmission = postConfig?.topics.$admission
    if (postConfig !== null && postAdmission !== undefined) {
      const verifyKey = reducerBindingTag(workingTopics.$reducers, '$admission')
      if (this.#admissionHasVerify.get(verifyKey) !== false) {
        const visibleAfter = op.view.filter(workingTopics)
        const vRes = await this.#invokeFor(op, postConfig, postAdmission, {
          method: 'verify',
          state: Object.hasOwn(visibleAfter, '$admission') ? visibleAfter.$admission! : null,
          payload: { before: op.view.filter(work.topics), after: visibleAfter },
          topics: visibleAfter,
          casPartition: op.casPartition,
          readOnly: true,
          controlTx: true,
        })
        const missing = !vRes.ok && vRes.code === 'vm:missing_method:verify'
        this.#admissionHasVerify.set(verifyKey, !missing)
        const denied = decisionDenial(vRes, 'verify', 'verify:rejected')
        if (denied !== null) return denied
      }
    }
    return { kind: 'commit', topics: workingTopics, hashes: workingHashes, events }
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
      logId: this.logIdHex,
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
      ...(binding.config === undefined ? {} : { config: binding.config }),
      cas: this.cas,
      casPartition,
      readOnly: true,
      maxMemoryBytes: this.genesis.limits.maxMemoryBytes,
      maxFuel: this.genesis.limits.maxFuel,
      local: true,
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
      epochOpCounts: new Map(snap.epochOpCounts),
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
        logId: this.logIdHex,
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
        maxFuel: this.genesis.limits.maxFuel,
        local: true,
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
      epochOpCounts: new Map(this.#epochOpCounts),
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
          logId: this.logIdHex,
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
          maxFuel: this.genesis.limits.maxFuel,
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

import { bytesToHex, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { decryptEpochPayload, encryptEpochPayload } from '@chronolog/crypto'
import {
  computeCasHash,
  ContentAddressedStore,
  decodeCasNode,
  hashCasNode,
  type BytesStore,
  type CasPartition,
} from '@chronolog/records'
import {
  assertValidReducersConfig,
  compareOperationOrder,
  decodeEncryptedEnvelope,
  decodeGenesisBlock,
  decodeSignedOperation,
  encodeEncryptedEnvelope,
  encodeGenesisBlock,
  encodeSignedOperation,
  encryptedEnvelopeDigest,
  envelopeAad,
  genesisChainId,
  isControlTopic,
  normalizeJsonValue,
  operationIdDigest,
  signOperationCore,
  verifySignedOperation,
  type EncryptedOperationEnvelope,
  type GenesisBlock,
  type JsonValue,
  type OperationCore,
  type OperationVisibility,
  type SignedOperation,
  type TopicUpdate,
} from '@chronolog/protocol'
import {
  check,
  checkedApplicationInputSchema,
  computeIncludedSetDigest,
  decodeRecord,
  encodeRecord,
  parseFinalitySchedule,
  policyScopeId,
  recordDigest,
  signFinalityCheckpoint,
  signRecord,
  validateApplicationDescription,
  verifyFinalityV2,
  verifyRecord,
  type ApplicationDescription,
  type BlockchainAnchorVerifier,
  type FinalityCheckpoint,
  type FinalityCheckpointPayload,
  type FinalityPolicyV2,
  type ScheduledFinalityEntry,
  type VerifiedFinalityV2,
} from '@chronolog/authority'
import {
  STANDARD_MODULE_SOURCES,
  TopicKernel,
  type EmittedKernelEvent,
  type KernelOperationInput,
  type QuickJsSandboxOptions,
  type SqliteBuiltinDriver,
} from '@chronolog/materializer'
import { SignalChannel, type SignalAuthorization } from '@chronolog/signals'
import { ApplicationContent } from './content.js'
import type { ApplicationDevice } from './device.js'
import { describeApplication, type ApplicationDefinition } from './definition.js'
import {
  epochKeyCommitmentV2,
  hpkeOpenEpochKey,
  hpkeSealEpochKey,
  type EpochKeyBox,
} from './genesis.js'
import {
  applicationPeerDiagnostics,
  applicationPeerLinks,
  connectApplicationPeer,
  onApplicationPeerLink,
  type ApplicationPeerConnectOptions,
  type ApplicationPeerDiagnostics,
  type ApplicationPeerLink,
} from './network.js'
import {
  ApplicationOperation,
  type ApplicationSubmission,
  type MaterializedOperation,
  type OperationInspection,
  type RetentionEvidence,
} from './operation.js'
import {
  APPLICATION_EVENT_CURSOR_LIMIT,
  type ApplicationChange,
  type ApplicationEvent,
  type ApplicationEventBatch,
  type ApplicationEventOptions,
  type ApplicationReadView,
  type CommandOptions,
  type MaterializedRevision,
  type SessionStatus,
  type WaitOptions,
} from './session-types.js'

export interface SessionCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
  readonly partition: CasPartition
}

export interface SessionFacts {
  readonly genesisBytes?: Uint8Array
  readonly publicOps: readonly Uint8Array[]
  readonly encryptedEnvelopes: readonly Uint8Array[]
  readonly casNodes: readonly SessionCasNode[]
  readonly retentions: readonly RetentionEvidence[]
  readonly checkpoints: readonly FinalityCheckpoint[]
}

export interface MemberRecord {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly reader: boolean
  readonly writer: boolean
  readonly administrator: boolean
  readonly publisher: boolean
  readonly finalizer: boolean
}

export interface PermissionsTopicState {
  readonly members: readonly MemberRecord[]
  readonly admission: { readonly hostKey?: string } | null
}

export interface KeysTopicState {
  readonly currentEpoch: number
  readonly epochs: Readonly<Record<string, {
    readonly epoch: number
    readonly keyCommitment: string
    readonly boxes: Readonly<Record<string, EpochKeyBox>>
  }>>
}

export interface CheckpointBootstrapSnapshot {
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly seenOpsRoot: string
  readonly historyDigest: string
  readonly stateRoot: string
}

export interface OpenApplicationSessionOptions<D extends ApplicationDefinition = ApplicationDefinition> extends QuickJsSandboxOptions {
  readonly device: ApplicationDevice
  readonly store: BytesStore
  readonly genesis?: GenesisBlock | Uint8Array
  readonly chainId?: string
  readonly casNodes?: readonly SessionCasNode[]
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  readonly definition?: D
  readonly blindHostMode?: boolean
  readonly blockchainVerifier?: BlockchainAnchorVerifier
  readonly sqliteWasmModule?: WebAssembly.Module
  readonly maxOperations?: number
  readonly release: () => void | Promise<void>
}

interface StoredPublicOp {
  readonly raw: Uint8Array
  readonly signed: SignedOperation
  readonly core: OperationCore
}

interface StoredEncryptedEnvelope {
  readonly digest: string
  readonly raw: Uint8Array
  readonly envelope: EncryptedOperationEnvelope
  decrypted?: { readonly opId: string; readonly signed: SignedOperation; readonly core: OperationCore }
}

interface LocalPendingOp {
  readonly raw: Uint8Array
  readonly signed: SignedOperation
  readonly core: OperationCore
  currentEnvelopeDigest: string
  currentEpoch: number
}

interface EvaluatedPermissionsSummary {
  readonly members: readonly MemberRecord[]
  readonly readers: ReadonlySet<string>
  readonly writers: ReadonlySet<string>
  readonly administrators: ReadonlySet<string>
  readonly publishers: ReadonlySet<string>
  readonly openReaders: boolean
  readonly openWriters: boolean
  readonly admission: { readonly hostKey?: string } | null
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function globMatches(pattern: string, topic: string): boolean {
  if (pattern === '*' || pattern === topic) return true
  if (pattern.endsWith('*')) return topic.startsWith(pattern.slice(0, -1))
  return false
}

function toMaterializedRevision(rev: ReturnType<TopicKernel['revision']>): MaterializedRevision {
  return Object.freeze({
    digest: rev.digest,
    stateRoot: rev.stateRoot,
    historyDigest: rev.historyDigest,
    view: rev.view,
    orderLength: rev.orderLength,
  })
}

function toApplicationEvent(ev: EmittedKernelEvent): ApplicationEvent {
  return Object.freeze({
    id: `${ev.opId}:${ev.eventOrdinal}`,
    proposalId: ev.opId,
    operationId: ev.operationId,
    author: ev.author,
    authorTimestampMs: ev.authorTimestampMs.toString(),
    topic: ev.topic,
    payload: structuredClone(ev.payload),
  })
}

/**
 * Chronolog v2 ApplicationSession.
 *
 * Built directly on:
 * - Flat timestamp-ordered operation set: (authorTimestampMs, author, opId)
 * - Pure Merkle-DAG CAS (public/private partitions, explicit links, exact GC)
 * - TopicKernel + QuickJS-NG Import-Map ES Module reducers + lazy chronolog:sqlite
 * - Automatic HPKE $keys unsealing + reconnect rewrapping of offline encrypted ops
 * - Time-scoped $finality verification & checkpoint bootstrap
 * - State-root-cached $signal_policy enforcement
 */
export class ApplicationSession<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly applicationId: string
  readonly chainId: string
  readonly genesis: GenesisBlock
  readonly genesisBytes: Uint8Array
  readonly device: ApplicationDevice
  readonly identity: { readonly publicKey: string }
  readonly definition?: D
  readonly cas: ContentAddressedStore
  readonly content: ApplicationContent
  readonly signals: SignalChannel

  readonly #store: BytesStore
  readonly #prefix: string
  readonly #lifetime = new AbortController()
  readonly #release: () => void | Promise<void>
  readonly #blindHostMode: boolean
  readonly #blockchainVerifier?: BlockchainAnchorVerifier
  readonly #sandboxOptions: QuickJsSandboxOptions
  readonly #sqliteWasmModule?: WebAssembly.Module
  readonly #maxOperations: number

  #sqliteDriver?: SqliteBuiltinDriver
  #sqliteLoadPromise?: Promise<SqliteBuiltinDriver>
  #kernel: TopicKernel
  #finalKernel: TopicKernel | null = null

  readonly #publicOps = new Map<string, StoredPublicOp>()
  readonly #encryptedEnvelopes = new Map<string, StoredEncryptedEnvelope>()
  readonly #localPending = new Map<string, LocalPendingOp>()
  readonly #retentions = new Map<string, Map<string, RetentionEvidence>>()
  readonly #checkpoints = new Map<string, FinalityCheckpoint>()
  readonly #epochKeys = new Map<number, Uint8Array>()

  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #changeListeners = new Set<(change: ApplicationChange) => void>()
  readonly #factListeners = new Set<() => void>()

  #connectedPeers = 0
  #connectionRevision = 0
  #materializationError: string | null = null
  #lastLocalRevision: MaterializedRevision
  #lastFinalRevision: MaterializedRevision | null = null
  #verifiedFinality: VerifiedFinalityV2 = {
    closedThroughMs: null,
    includedOpIds: new Set(),
    excludedOpIds: new Set(),
    latestCheckpoint: null,
    verifiedCheckpoints: [],
  }
  #cachedSignalPolicy: { stateRoot: string; rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] } | null = null
  #evaluatedPermissions: EvaluatedPermissionsSummary | null = null
  #closed = false
  #closing?: Promise<void>
  #tail: Promise<unknown> = Promise.resolve()

  private constructor(
    options: OpenApplicationSessionOptions<D>,
    genesisBytes: Uint8Array,
    cas: ContentAddressedStore,
  ) {
    this.genesisBytes = genesisBytes.slice()
    this.genesis = decodeGenesisBlock(this.genesisBytes)
    this.chainId = bytesToHex(genesisChainId(this.genesisBytes))
    this.applicationId = this.chainId
    this.device = options.device
    this.identity = Object.freeze({ publicKey: options.device.identity.publicKey })
    if (options.definition !== undefined) this.definition = options.definition
    this.cas = cas
    this.#store = options.store
    this.#prefix = `v2/${this.chainId}`
    this.#release = options.release
    this.#blindHostMode = options.blindHostMode ?? false
    if (options.blockchainVerifier !== undefined) this.#blockchainVerifier = options.blockchainVerifier
    if (options.sqliteWasmModule !== undefined) this.#sqliteWasmModule = options.sqliteWasmModule
    this.#maxOperations = options.maxOperations ?? 50_000
    this.#sandboxOptions = {
      ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
      ...(options.sqliteDriver === undefined ? {} : { sqliteDriver: options.sqliteDriver }),
    }
    if (options.sqliteDriver !== undefined) this.#sqliteDriver = options.sqliteDriver

    this.#kernel = new TopicKernel({
      genesis: this.genesisBytes,
      cas: this.cas,
      blindHostMode: this.#blindHostMode,
      ...this.#sandboxOptions,
    })
    this.#lastLocalRevision = toMaterializedRevision(this.#kernel.revision('local'))

    this.content = new ApplicationContent({
      store: this.#store,
      identity: this.device.identity,
      storageId: this.device.storageId,
      authority: {
        applicationId: this.applicationId,
        isReader: pk => this.isReader(pk),
        currentEpoch: () => Math.max(0, this.currentEpoch()),
        epochKey: epoch => this.#epochKeys.get(epoch) ?? null,
      },
    })

    this.signals = new SignalChannel({
      scope: this.applicationId,
      identity: {
        publicKeyBytes: hexToBytes(this.device.identity.publicKey),
        privateKey: this.device.identity.privateKey,
      },
      localEcho: true,
      authorize: async (auth: SignalAuthorization) => {
        if (auth.scope !== this.applicationId) return false
        const authorHex = bytesToHex(auth.authorId)
        const policy = await this.#resolveSignalPolicy()
        for (const rule of policy.rules) {
          if (!globMatches(rule.topicPattern, auth.topic)) continue
          if (!rule.allowedAuthors.includes('*') && !rule.allowedAuthors.includes(authorHex)) continue
          return true
        }
        return false
      },
    })
  }

  static async open<D extends ApplicationDefinition = ApplicationDefinition>(
    options: OpenApplicationSessionOptions<D>,
  ): Promise<ApplicationSession<D>> {
    const cas = new ContentAddressedStore({ store: options.store })
    await cas.preload()

    if (options.casNodes !== undefined) {
      for (const node of options.casNodes) {
        const expected = computeCasHash(node.bytes, [])
        if (expected === node.hash) {
          await cas.put(node.bytes, [], node.partition)
        } else if (hashCasNode(node.bytes) === node.hash) {
          await cas.putRaw(node.hash, node.bytes, node.partition)
        } else {
          throw new Error(`CAS_NODE_HASH_MISMATCH:${node.hash}`)
        }
      }
    }

    let genesisBytes: Uint8Array | null = null
    if (options.genesis !== undefined) {
      genesisBytes = options.genesis instanceof Uint8Array
        ? options.genesis.slice()
        : encodeGenesisBlock(options.genesis)
      const chainId = bytesToHex(genesisChainId(genesisBytes))
      if (options.chainId !== undefined && options.chainId !== chainId) {
        throw new Error('SESSION_CHAIN_ID_MISMATCH')
      }
      const existing = await options.store.get(`v2/${chainId}/genesis`)
      if (existing !== null && !sameBytes(existing, genesisBytes)) {
        throw new Error('SESSION_GENESIS_MISMATCH')
      }
      if (existing === null) await options.store.put(`v2/${chainId}/genesis`, genesisBytes)
    } else if (options.chainId !== undefined) {
      genesisBytes = await options.store.get(`v2/${options.chainId}/genesis`)
    } else {
      const all = options.store.entries ? await options.store.entries() : []
      for (const entry of all) {
        if (entry.key.startsWith('v2/') && entry.key.endsWith('/genesis')) {
          genesisBytes = entry.value
          break
        }
      }
    }
    if (genesisBytes === null) throw new Error('SESSION_GENESIS_NOT_FOUND')

    const session = new ApplicationSession<D>(options, genesisBytes, cas)
    if (options.epochKeys !== undefined) {
      for (const [epoch, key] of options.epochKeys) {
        await session.installEpochKey(epoch, key)
      }
    }
    await session.#hydrateFromStore()
    await session.#rematerialize()
    return session
  }

  get signal(): AbortSignal { return this.#lifetime.signal }

  get status(): SessionStatus {
    const pendingOps = this.#countPendingOps()
    const canAuthor = !this.#closed && !this.#blindHostMode && this.#canLocallyAuthor()
    const awaitingKeys = this.genesis.privateChain && !this.#blindHostMode && this.isReader(this.identity.publicKey) && this.currentEpoch() >= 0 && !this.#epochKeys.has(this.currentEpoch())
    return Object.freeze({
      ...(this.#kernel.pendingDependencies.length > 0 ? { pendingDependencies: this.#kernel.pendingDependencies } : {}),
      canAuthor,
      phase: this.#closed ? 'closed' : awaitingKeys ? 'awaiting-keys' : 'ready',
      database: this.#closed ? 'closed' : this.#materializationError !== null ? 'failed' : 'ready',
      connectedPeers: this.#connectedPeers,
      connectionRevision: this.#connectionRevision,
      pendingOperations: pendingOps,
      materializationError: this.#materializationError,
    })
  }

  permissions(): PermissionsTopicState {
    if (this.#evaluatedPermissions !== null) {
      return {
        members: this.#evaluatedPermissions.members,
        admission: this.#evaluatedPermissions.admission,
      }
    }
    const raw = this.#kernel.topic('$permissions') as PermissionsTopicState | null
    if (raw === null || typeof raw !== 'object' || !Array.isArray(raw.members)) {
      return { members: [], admission: null }
    }
    return raw
  }

  member(publicKey: string): MemberRecord | null {
    return this.permissions().members.find(m => m.publicKey === publicKey) ?? null
  }

  isMember(publicKey: string): boolean {
    if (this.#evaluatedPermissions !== null) {
      if (this.#evaluatedPermissions.openWriters || this.#evaluatedPermissions.openReaders) return /^[0-9a-f]{64}$/u.test(publicKey)
      return this.#evaluatedPermissions.members.some(m => m.publicKey === publicKey) ||
        this.#evaluatedPermissions.readers.has(publicKey) ||
        this.#evaluatedPermissions.writers.has(publicKey) ||
        this.#evaluatedPermissions.administrators.has(publicKey)
    }
    return this.member(publicKey) !== null
  }

  isReader(publicKey: string): boolean {
    if (!this.genesis.privateChain) return true
    if (this.#evaluatedPermissions !== null) {
      if (this.#evaluatedPermissions.openReaders) return /^[0-9a-f]{64}$/u.test(publicKey)
      return this.#evaluatedPermissions.readers.has(publicKey)
    }
    return this.member(publicKey)?.reader === true
  }

  isWriter(publicKey: string): boolean {
    if (this.#evaluatedPermissions !== null) {
      if (this.#evaluatedPermissions.openWriters) return /^[0-9a-f]{64}$/u.test(publicKey)
      return this.#evaluatedPermissions.writers.has(publicKey) || this.#evaluatedPermissions.administrators.has(publicKey)
    }
    return this.member(publicKey)?.writer === true || this.member(publicKey)?.administrator === true
  }

  isAdministrator(publicKey: string): boolean {
    if (this.#evaluatedPermissions !== null) {
      return this.#evaluatedPermissions.administrators.has(publicKey)
    }
    return this.member(publicKey)?.administrator === true
  }

  /** Query an arbitrary capability (standard or custom) against the chain's `$permissions` reducer. */
  async checkPermission(capability: string, actor = this.identity.publicKey): Promise<boolean> {
    const res = await this.#kernel.query('$permissions', { check: capability, actor }).catch(() => null)
    if (typeof res === 'boolean') return res
    if (capability === 'reader') return this.isReader(actor)
    if (capability === 'writer') return this.isWriter(actor)
    if (capability === 'administrator') return this.isAdministrator(actor)
    if (capability === 'publisher') {
      return this.#evaluatedPermissions !== null
        ? this.#evaluatedPermissions.publishers.has(actor) || this.#evaluatedPermissions.administrators.has(actor)
        : this.member(actor)?.publisher === true || this.member(actor)?.administrator === true
    }
    if (capability === 'member') return this.isMember(actor)
    return false
  }

  keysState(): KeysTopicState {
    const raw = this.#kernel.topic('$keys') as KeysTopicState | null
    if (raw === null || typeof raw !== 'object') return { currentEpoch: -1, epochs: {} }
    return raw
  }

  currentEpoch(): number {
    const state = this.keysState()
    if (state.currentEpoch >= 0) return state.currentEpoch
    if (this.#epochKeys.size > 0) return Math.max(...this.#epochKeys.keys())
    return -1
  }

  epochKey(epoch: number): Uint8Array | null {
    return this.#epochKeys.get(epoch)?.slice() ?? null
  }

  hasEpochKey(epoch: number): boolean {
    return this.#epochKeys.has(epoch)
  }

  exportEpochKeys(): ReadonlyMap<number, Uint8Array> {
    const out = new Map<number, Uint8Array>()
    for (const [ep, key] of this.#epochKeys) out.set(ep, key.slice())
    return out
  }

  async installEpochKey(epoch: number, key: Uint8Array): Promise<void> {
    check(Number.isSafeInteger(epoch) && epoch >= 0 && key instanceof Uint8Array && key.length === 32, 'EPOCH_KEY_INVALID')
    this.#epochKeys.set(epoch, key.slice())
    await this.#store.put(`${this.#prefix}/epoch-key/${epoch}`, key.slice())
  }

  async unlockEpochsFromKeysTopic(wrapPrivateKey: CryptoKey, wrapPublicKeyHex: string): Promise<number> {
    return this.#serial(async () => {
      if (!this.genesis.privateChain || this.#blindHostMode) return 0
      const keys = this.keysState()
      let unlocked = 0
      for (const entry of Object.values(keys.epochs ?? {})) {
        if (this.#epochKeys.has(entry.epoch)) continue
        const box = entry.boxes?.[this.identity.publicKey]
        if (box === undefined) continue
        try {
          const plainKey = await hpkeOpenEpochKey(
            wrapPrivateKey,
            wrapPublicKeyHex,
            box,
            this.chainId,
            entry.epoch,
          )
          if (epochKeyCommitmentV2(plainKey) !== entry.keyCommitment) continue
          await this.installEpochKey(entry.epoch, plainKey)
          unlocked++
        } catch {
          // Wrong wrap key or corrupted lockbox — ignore
        }
      }
      if (unlocked > 0) await this.#rematerialize()
      return unlocked
    })
  }

  topic(name: string): JsonValue | null {
    return this.#kernel.topic(name)
  }

  revision(view: 'local' | 'final' = 'local'): MaterializedRevision {
    if (view === 'final') {
      return this.#lastFinalRevision ?? toMaterializedRevision(this.#kernel.revision('final'))
    }
    return this.#lastLocalRevision
  }

  async retryMaterialization(): Promise<void> {
    await this.#serial(() => this.#rematerialize())
  }

  #canLocallyAuthor(): boolean {
    const pk = this.identity.publicKey
    const isAdmin = this.isAdministrator(pk)
    const isPub = this.#evaluatedPermissions !== null
      ? this.#evaluatedPermissions.publishers.has(pk)
      : this.member(pk)?.publisher === true
    if (!this.isWriter(pk) && !isAdmin && !isPub) return false
    if (this.genesis.privateChain && this.currentEpoch() >= 0 && !this.#epochKeys.has(this.currentEpoch())) {
      return isAdmin
    }
    return true
  }

  #countPendingOps(): number {
    let count = this.#kernel.pendingDependencies.length
    if (!this.#blindHostMode) {
      for (const entry of this.#encryptedEnvelopes.values()) {
        if (entry.decrypted === undefined) count++
      }
    }
    return count
  }

  #serial<T>(work: () => Promise<T>): Promise<T> {
    const task = this.#tail.then(() => {
      if (this.#closed) throw new Error('SESSION_CLOSED')
      return work()
    })
    this.#tail = task.catch(() => undefined)
    return task
  }

  #emitStatus(): void {
    const snap = this.status
    for (const listener of this.#statusListeners) {
      try { listener(snap) } catch { /* isolate observer */ }
    }
  }

  #emitChange(change: ApplicationChange): void {
    for (const listener of this.#changeListeners) {
      try { listener(change) } catch { /* isolate observer */ }
    }
  }

  #emitFacts(): void {
    for (const listener of this.#factListeners) {
      try { listener() } catch { /* isolate observer */ }
    }
  }

  onStatus(listener: (status: SessionStatus) => void): () => void {
    this.#statusListeners.add(listener)
    try { listener(this.status) } catch { /* isolate observer */ }
    return () => { this.#statusListeners.delete(listener) }
  }

  onChange(listener: (change: ApplicationChange) => void): () => void {
    this.#changeListeners.add(listener)
    return () => { this.#changeListeners.delete(listener) }
  }

  onFacts(listener: () => void): () => void {
    this.#factListeners.add(listener)
    return () => { this.#factListeners.delete(listener) }
  }

  async *changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    const queue: ApplicationChange[] = []
    let wake: (() => void) | undefined
    const stop = this.onChange(value => { queue.splice(0, queue.length, value); wake?.() })
    const abort = (): void => { wake?.() }
    signal.addEventListener('abort', abort)
    try {
      while (!signal.aborted) {
        if (queue.length === 0) await new Promise<void>(resolve => { wake = resolve })
        while (queue.length > 0 && !signal.aborted) yield queue.shift()!
      }
    } finally {
      stop()
      signal.removeEventListener('abort', abort)
    }
  }

  setConnectedPeers(count: number): void {
    this.#connectedPeers = count
    this.#connectionRevision++
    this.#emitStatus()
  }

  async #ensureSqliteIfNeeded(): Promise<void> {
    if (this.#sqliteDriver !== undefined) return
    const reducersRaw = this.#kernel.topic('$reducers')
    if (reducersRaw === null) return
    let needsSqlite = false
    try {
      const cfg = assertValidReducersConfig(reducersRaw)
      const queue: string[] = []
      const visited = new Set<string>()
      for (const [topicName, binding] of Object.entries(cfg.topics)) {
        if (this.#blindHostMode && this.genesis.privateChain && !isControlTopic(topicName)) continue
        queue.push(binding.module)
      }
      const importSpecRe = /\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/gu
      while (queue.length > 0) {
        const modSpec = queue.shift()!
        if (visited.has(modSpec)) continue
        visited.add(modSpec)
        if (modSpec === 'chronolog:sqlite' || modSpec === 'chronolog/sql') {
          needsSqlite = true
          break
        }
        const ref = cfg.imports[modSpec]
        if (ref === undefined || !ref.startsWith('cas:sha256-')) continue
        const hash = ref.slice(11)
        const node = await this.cas.get(hash, 'any')
        if (node === null) continue
        const text = new TextDecoder().decode(node.bytes)
        if (text.includes('chronolog:sqlite') || text.includes('chronolog/sql')) {
          needsSqlite = true
          break
        }
        importSpecRe.lastIndex = 0
        let match: RegExpExecArray | null
        while ((match = importSpecRe.exec(text)) !== null) {
          const dep = match[1] ?? match[2]
          if (dep !== undefined && !visited.has(dep) && Object.hasOwn(cfg.imports, dep)) {
            queue.push(dep)
          }
        }
      }
    } catch { return }
    if (!needsSqlite) return

    this.#sqliteLoadPromise ??= (async () => {
      const mod = await import('@chronolog/sqlite-cas')
      const driver = await mod.createSqliteCasDriver({
        ...(this.#sqliteWasmModule === undefined ? {} : { wasmModule: this.#sqliteWasmModule }),
      })
      this.#sqliteDriver = driver
      this.#kernel = new TopicKernel({
        genesis: this.genesisBytes,
        cas: this.cas,
        blindHostMode: this.#blindHostMode,
        ...this.#sandboxOptions,
        sqliteDriver: driver,
      })
      this.#finalKernel = null
      return driver
    })()
    await this.#sqliteLoadPromise
  }

  async #refreshPermissionsCache(): Promise<void> {
    const parseStringList = (val: unknown): { readonly keys: Set<string>; readonly open: boolean } => {
      const keys = new Set<string>()
      let open = false
      if (Array.isArray(val)) {
        for (const item of val) {
          if (item === '*') open = true
          else if (typeof item === 'string') keys.add(item)
        }
      }
      return { keys, open }
    }
    const parseMembers = (val: unknown): MemberRecord[] => {
      if (!Array.isArray(val)) return []
      return val.filter((m): m is MemberRecord => m !== null && typeof m === 'object' && typeof (m as MemberRecord).publicKey === 'string')
    }

    try {
      const summary = await this.#kernel.query('$permissions', { summary: true })
      if (
        summary !== null &&
        typeof summary === 'object' &&
        !Array.isArray(summary) &&
        Array.isArray((summary as Record<string, unknown>).administrators) &&
        Array.isArray((summary as Record<string, unknown>).readers)
      ) {
        const s = summary as Record<string, unknown>
        const readers = parseStringList(s.readers)
        const writers = parseStringList(s.writers)
        const admins = parseStringList(s.administrators)
        const pubs = parseStringList(s.publishers)
        const admission = (s.admission !== null && typeof s.admission === 'object' && !Array.isArray(s.admission))
          ? s.admission as { readonly hostKey?: string }
          : null
        this.#evaluatedPermissions = {
          members: parseMembers(s.members),
          readers: readers.keys,
          writers: writers.keys,
          administrators: admins.keys,
          publishers: pubs.keys,
          openReaders: s.openReaders === true || readers.open,
          openWriters: s.openWriters === true || writers.open,
          admission,
        }
        return
      }

      const [rRaw, wRaw, aRaw, pRaw, mRaw, admRaw] = await Promise.all([
        this.#kernel.query('$permissions', { list: 'readers' }).catch(() => null),
        this.#kernel.query('$permissions', { list: 'writers' }).catch(() => null),
        this.#kernel.query('$permissions', { list: 'administrators' }).catch(() => null),
        this.#kernel.query('$permissions', { list: 'publishers' }).catch(() => null),
        this.#kernel.query('$permissions', { list: 'members' }).catch(() => null),
        this.#kernel.query('$permissions', { admission: true }).catch(() => null),
      ])
      if (Array.isArray(rRaw) || Array.isArray(wRaw) || Array.isArray(aRaw)) {
        const readers = parseStringList(rRaw)
        const writers = parseStringList(wRaw)
        const admins = parseStringList(aRaw)
        const pubs = parseStringList(pRaw)
        const admission = (admRaw !== null && typeof admRaw === 'object' && !Array.isArray(admRaw))
          ? admRaw as { readonly hostKey?: string }
          : null
        this.#evaluatedPermissions = {
          members: parseMembers(mRaw),
          readers: readers.keys,
          writers: writers.keys,
          administrators: admins.keys,
          publishers: pubs.keys,
          openReaders: readers.open,
          openWriters: writers.open,
          admission,
        }
        return
      }
    } catch {
      // Fall through to legacy raw topic inspection
    }

    const raw = this.#kernel.topic('$permissions') as PermissionsTopicState | null
    if (raw !== null && typeof raw === 'object' && Array.isArray(raw.members)) {
      const members = parseMembers(raw.members)
      this.#evaluatedPermissions = {
        members,
        readers: new Set(members.filter(m => m.reader).map(m => m.publicKey)),
        writers: new Set(members.filter(m => m.writer || m.administrator).map(m => m.publicKey)),
        administrators: new Set(members.filter(m => m.administrator).map(m => m.publicKey)),
        publishers: new Set(members.filter(m => m.publisher || m.administrator).map(m => m.publicKey)),
        openReaders: false,
        openWriters: false,
        admission: raw.admission ?? null,
      }
    } else {
      this.#evaluatedPermissions = null
    }
  }

  async #hydrateFromStore(): Promise<void> {
    const entries = this.#store.entries ? await this.#store.entries() : []
    const prefix = `${this.#prefix}/`
    for (const entry of entries) {
      if (!entry.key.startsWith(prefix)) continue
      const rest = entry.key.slice(prefix.length)
      if (rest.startsWith('epoch-key/')) {
        const ep = Number(rest.slice('epoch-key/'.length))
        if (Number.isSafeInteger(ep) && ep >= 0 && entry.value.length === 32 && !this.#epochKeys.has(ep)) {
          this.#epochKeys.set(ep, entry.value.slice())
        }
      } else if (rest.startsWith('public-op/')) {
        try {
          const signed = decodeSignedOperation(entry.value)
          const verified = await verifySignedOperation(signed)
          if (bytesToHex(verified.core.chainId) === this.chainId && verified.core.visibility === 'public') {
            this.#publicOps.set(bytesToHex(verified.opId), { raw: entry.value.slice(), signed, core: verified.core })
          }
        } catch { /* ignore corrupt entry */ }
      } else if (rest.startsWith('enc-env/')) {
        try {
          const envelope = decodeEncryptedEnvelope(entry.value)
          if (bytesToHex(envelope.chainId) === this.chainId) {
            const digest = bytesToHex(encryptedEnvelopeDigest(entry.value))
            this.#encryptedEnvelopes.set(digest, { digest, raw: entry.value.slice(), envelope })
          }
        } catch { /* ignore corrupt entry */ }
      } else if (rest.startsWith('local-pending/')) {
        try {
          const rec = decodeRecord<{ readonly raw: Uint8Array; readonly envelopeDigest: string; readonly epoch: number }>(entry.value)
          const signed = decodeSignedOperation(rec.raw)
          const verified = await verifySignedOperation(signed)
          this.#localPending.set(bytesToHex(verified.opId), {
            raw: rec.raw.slice(),
            signed,
            core: verified.core,
            currentEnvelopeDigest: rec.envelopeDigest,
            currentEpoch: rec.epoch,
          })
        } catch { /* ignore */ }
      } else if (rest.startsWith('retention/')) {
        try {
          const ev = decodeRecord<RetentionEvidence>(entry.value)
          await verifyRecord('operation-retention', ev, ev.signer)
          let byPeer = this.#retentions.get(ev.payload.proposalId)
          if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(ev.payload.proposalId, byPeer) }
          byPeer.set(ev.signer, ev)
        } catch { /* ignore */ }
      } else if (rest.startsWith('checkpoint/')) {
        try {
          const cp = decodeRecord<FinalityCheckpoint>(entry.value)
          const key = await recordDigest(cp.payload)
          this.#checkpoints.set(key, cp)
        } catch { /* ignore */ }
      }
    }
  }

  async #unsealAvailableEpochKeys(): Promise<boolean> {
    if (!this.genesis.privateChain || this.#blindHostMode) return false
    const keys = this.keysState()
    let unlockedAny = false
    for (const entry of Object.values(keys.epochs ?? {})) {
      if (this.#epochKeys.has(entry.epoch)) continue
      const box = entry.boxes?.[this.identity.publicKey]
      if (box === undefined) continue
      try {
        const plainKey = await hpkeOpenEpochKey(
          this.device.wrapKey.privateKey,
          this.device.wrapKey.publicKey,
          box,
          this.chainId,
          entry.epoch,
        )
        if (epochKeyCommitmentV2(plainKey) !== entry.keyCommitment) continue
        await this.installEpochKey(entry.epoch, plainKey)
        unlockedAny = true
      } catch {
        // Wrong wrap key or corrupted lockbox — ignore
      }
    }
    return unlockedAny
  }

  async #decryptPendingEnvelopes(): Promise<void> {
    if (!this.genesis.privateChain || this.#blindHostMode) return
    for (const entry of this.#encryptedEnvelopes.values()) {
      if (entry.decrypted !== undefined) continue
      const epochKey = this.#epochKeys.get(entry.envelope.epoch)
      if (epochKey === undefined) continue
      try {
        const aad = envelopeAad(entry.envelope.chainId, entry.envelope.opId, entry.envelope.author)
        const plaintext = await decryptEpochPayload(epochKey, {
          epoch: BigInt(entry.envelope.epoch),
          nonce: entry.envelope.nonce,
          ciphertext: entry.envelope.ciphertext,
        }, aad)
        const signed = decodeSignedOperation(plaintext)
        const verified = await verifySignedOperation(signed)
        if (bytesToHex(verified.core.chainId) !== this.chainId) continue
        if (verified.core.visibility !== 'encrypted') continue
        if (!sameBytes(verified.opId, entry.envelope.opId) || !sameBytes(verified.core.author, entry.envelope.author)) continue
        entry.decrypted = { opId: bytesToHex(verified.opId), signed, core: verified.core }
      } catch {
        // Cannot decrypt / forged ciphertext — stays undecryptable
      }
    }
  }

  /**
   * Reconnect rewrapping: if this device authored offline encrypted ops under an older epoch
   * and $keys has since rotated to a newer epoch that we hold (and we are still a writer),
   * re-encrypt the EXACT original SignedOperation bytes under the newest epoch so peers can
   * decrypt them without changing opId, authorTimestampMs, or signature!
   */
  async #rewrapPendingLocalOps(): Promise<boolean> {
    if (!this.genesis.privateChain || this.#blindHostMode) return false
    const newestEpoch = this.currentEpoch()
    if (newestEpoch < 0) return false
    const newestKey = this.#epochKeys.get(newestEpoch)
    if (newestKey === undefined || !this.isWriter(this.identity.publicKey)) return false

    let rewrapped = false
    for (const [opId, pending] of this.#localPending) {
      if (pending.currentEpoch >= newestEpoch) continue
      const chainIdBytes = hexToBytes(this.chainId)
      const opIdBytes = hexToBytes(opId)
      const aad = envelopeAad(chainIdBytes, opIdBytes, pending.core.author)
      const enc = await encryptEpochPayload(newestKey, BigInt(newestEpoch), pending.raw, aad)
      const env: EncryptedOperationEnvelope = {
        version: 1,
        chainId: chainIdBytes,
        opId: opIdBytes,
        author: pending.core.author,
        epoch: newestEpoch,
        nonce: enc.nonce,
        ciphertext: enc.ciphertext,
      }
      const envBytes = encodeEncryptedEnvelope(env)
      const envDigest = bytesToHex(encryptedEnvelopeDigest(envBytes))

      const oldRetentions = this.#retentions.get(opId)
      const oldRetainedRemotely = oldRetentions !== undefined && [...oldRetentions.values()].some(r => r.signer !== this.identity.publicKey)
      if (!oldRetainedRemotely && this.#encryptedEnvelopes.has(pending.currentEnvelopeDigest)) {
        this.#encryptedEnvelopes.delete(pending.currentEnvelopeDigest)
        await this.#store.delete?.(`${this.#prefix}/enc-env/${pending.currentEnvelopeDigest}`)
      }

      await this.#store.put(`${this.#prefix}/enc-env/${envDigest}`, envBytes)
      this.#encryptedEnvelopes.set(envDigest, {
        digest: envDigest,
        raw: envBytes,
        envelope: env,
        decrypted: { opId, signed: pending.signed, core: pending.core },
      })
      pending.currentEpoch = newestEpoch
      pending.currentEnvelopeDigest = envDigest
      await this.#store.put(`${this.#prefix}/local-pending/${opId}`, encodeRecord({
        raw: pending.raw,
        envelopeDigest: envDigest,
        epoch: newestEpoch,
      }))
      rewrapped = true
    }
    return rewrapped
  }

  #collectDecryptedKernelInputs(): Map<string, KernelOperationInput> {
    const byOpId = new Map<string, KernelOperationInput>()
    for (const [opId, entry] of this.#publicOps) {
      byOpId.set(opId, { opId: hexToBytes(opId), core: entry.core })
    }
    if (!this.#blindHostMode) {
      for (const entry of this.#encryptedEnvelopes.values()) {
        if (entry.decrypted === undefined) continue
        if (!byOpId.has(entry.decrypted.opId)) {
          byOpId.set(entry.decrypted.opId, {
            opId: hexToBytes(entry.decrypted.opId),
            core: entry.decrypted.core,
          })
        }
      }
    }
    return byOpId
  }

  async #rematerialize(): Promise<void> {
    const prevDigest = this.#lastLocalRevision.digest
    const prevFinalDigest = this.#lastFinalRevision?.digest ?? null
    const prevOutcomes = new Map(this.#kernel.outcomes.map(o => [o.opId, `${o.outcome}:${o.rejectionCode ?? ''}`]))

    try {
      await this.#ensureSqliteIfNeeded()

      const publicInputs: KernelOperationInput[] = []
      for (const [opId, entry] of this.#publicOps) {
        publicInputs.push({ opId: hexToBytes(opId), core: entry.core })
      }
      await this.#kernel.materialize(publicInputs)
      await this.#refreshPermissionsCache()

      await this.#unsealAvailableEpochKeys()
      await this.#decryptPendingEnvelopes()
      const rewrapped = await this.#rewrapPendingLocalOps()

      const allByOpId = this.#collectDecryptedKernelInputs()
      const schedule = parseFinalitySchedule(this.#kernel.topic('$finality'))
      this.#verifiedFinality = await verifyFinalityV2({
        chainId: this.chainId,
        schedule,
        checkpoints: [...this.#checkpoints.values()],
        knownOps: [...allByOpId.entries()].map(([opId, input]) => ({
          opId,
          authorTimestampMs: input.core.authorTimestampMs,
        })),
        ...(this.#blockchainVerifier === undefined ? {} : { blockchainVerifier: this.#blockchainVerifier }),
      })

      const eligibleLocal: KernelOperationInput[] = []
      for (const [opId, input] of allByOpId) {
        if (this.#verifiedFinality.excludedOpIds.has(opId)) continue
        eligibleLocal.push(input)
      }
      await this.#ensureSqliteIfNeeded()
      const localResult = await this.#kernel.materialize(eligibleLocal)
      await this.#refreshPermissionsCache()
      this.#lastLocalRevision = toMaterializedRevision(localResult.revision)

      if (this.#verifiedFinality.closedThroughMs !== null) {
        this.#finalKernel ??= new TopicKernel({
          genesis: this.genesisBytes,
          cas: this.cas,
          blindHostMode: this.#blindHostMode,
          ...this.#sandboxOptions,
          ...(this.#sqliteDriver === undefined ? {} : { sqliteDriver: this.#sqliteDriver }),
        })
        const finalInputs: KernelOperationInput[] = []
        for (const [opId, input] of allByOpId) {
          if (this.#verifiedFinality.includedOpIds.has(opId)) finalInputs.push(input)
        }
        await this.#finalKernel.materialize(finalInputs)
        this.#lastFinalRevision = toMaterializedRevision(this.#finalKernel.revision('final'))
      } else {
        this.#lastFinalRevision = null
      }

      if (this.#cachedSignalPolicy !== null && this.#cachedSignalPolicy.stateRoot !== this.#lastLocalRevision.stateRoot) {
        this.#cachedSignalPolicy = null
      }

      this.#materializationError = null

      const revised: string[] = []
      for (const o of localResult.outcomes) {
        const key = `${o.outcome}:${o.rejectionCode ?? ''}`
        if (prevOutcomes.get(o.opId) !== key) revised.push(o.opId)
      }
      if (this.#lastLocalRevision.digest !== prevDigest) {
        this.#emitChange({
          kind: localResult.pendingDependencies.length > 0 ? 'dependency' : 'materialized',
          revision: this.#lastLocalRevision,
          revisedProposalIds: revised,
        })
      }
      if (this.#lastFinalRevision !== null && this.#lastFinalRevision.digest !== prevFinalDigest) {
        this.#emitChange({
          kind: 'finalized',
          revision: this.#lastFinalRevision,
          revisedProposalIds: [],
        })
      }
      this.#emitStatus()
      if (rewrapped) this.#emitFacts()
    } catch (error) {
      this.#materializationError = error instanceof Error ? error.message : String(error)
      this.#emitStatus()
      throw error
    }
  }

  async #resolveSignalPolicy() {
    const stateRoot = this.#lastLocalRevision.stateRoot
    if (this.#cachedSignalPolicy !== null && this.#cachedSignalPolicy.stateRoot === stateRoot) {
      return this.#cachedSignalPolicy
    }
    const policy = await this.#kernel.signalPolicy()
    this.#cachedSignalPolicy = { stateRoot, rules: policy.rules }
    return this.#cachedSignalPolicy
  }

  /** Author locally and durably before network delivery. */
  submit(input: ApplicationSubmission): Promise<ApplicationOperation> {
    return this.#serial(async () => {
      check(!this.#blindHostMode, 'SESSION_BLIND_HOST_CANNOT_AUTHOR')
      check(Array.isArray(input.updates) && input.updates.length > 0, 'OPERATION_UPDATES_REQUIRED')
      const updatesList: readonly TopicUpdate[] = input.updates
      const allControl = updatesList.every(u => isControlTopic(u.topic))
      const anyControl = updatesList.some(u => isControlTopic(u.topic))
      check(!anyControl || allControl, 'OPERATION_CROSS_PARTITION_FORBIDDEN')

      const visibility: OperationVisibility = input.visibility ?? (
        this.genesis.privateChain
          ? (allControl ? 'public' : 'encrypted')
          : 'public'
      )
      if (this.genesis.privateChain) {
        if (allControl) check(visibility === 'public', 'CONTROL_OP_MUST_BE_PUBLIC')
        else check(visibility === 'encrypted', 'PRIVATE_OP_MUST_BE_ENCRYPTED')
      }

      const operationId = input.operationId ?? crypto.randomUUID()
      for (const [opId, entry] of this.#publicOps) {
        if (
          entry.core.visibility === visibility &&
          bytesToHex(entry.core.author) === this.identity.publicKey &&
          entry.core.operationId === operationId
        ) {
          return new ApplicationOperation(opId, operationId, this)
        }
      }
      for (const [opId, pending] of this.#localPending) {
        if (pending.core.visibility === visibility && pending.core.operationId === operationId) {
          return new ApplicationOperation(opId, operationId, this)
        }
      }

      const authorTimestampMs = input.authorTimestampMs ?? BigInt(Date.now())
      const chainIdBytes = hexToBytes(this.chainId)
      const authorBytes = hexToBytes(this.identity.publicKey)
      const core: OperationCore = {
        version: 1,
        chainId: chainIdBytes,
        author: authorBytes,
        operationId,
        authorTimestampMs,
        nonce: crypto.getRandomValues(new Uint8Array(16)),
        visibility,
        updates: updatesList.map(u => ({ topic: u.topic, input: normalizeJsonValue(u.input) })),
      }

      const signed = await signOperationCore(core, this.device.identity.privateKey)
      const opBytes = encodeSignedOperation(signed)
      const opIdBytes = operationIdDigest(signed.coreBytes)
      const opIdHex = bytesToHex(opIdBytes)

      if (visibility === 'public') {
        await this.#store.put(`${this.#prefix}/public-op/${opIdHex}`, opBytes)
        this.#publicOps.set(opIdHex, { raw: opBytes, signed, core })
      } else {
        const epoch = this.currentEpoch()
        check(epoch >= 0, 'EPOCH_KEY_REQUIRED')
        const epochKey = this.#epochKeys.get(epoch)
        check(epochKey !== undefined, 'EPOCH_KEY_MISSING')
        const aad = envelopeAad(chainIdBytes, opIdBytes, authorBytes)
        const enc = await encryptEpochPayload(epochKey, BigInt(epoch), opBytes, aad)
        const env: EncryptedOperationEnvelope = {
          version: 1,
          chainId: chainIdBytes,
          opId: opIdBytes,
          author: authorBytes,
          epoch,
          nonce: enc.nonce,
          ciphertext: enc.ciphertext,
        }
        const envBytes = encodeEncryptedEnvelope(env)
        const envDigest = bytesToHex(encryptedEnvelopeDigest(envBytes))
        await this.#store.put(`${this.#prefix}/enc-env/${envDigest}`, envBytes)
        await this.#store.put(`${this.#prefix}/local-pending/${opIdHex}`, encodeRecord({
          raw: opBytes,
          envelopeDigest: envDigest,
          epoch,
        }))
        this.#encryptedEnvelopes.set(envDigest, {
          digest: envDigest,
          raw: envBytes,
          envelope: env,
          decrypted: { opId: opIdHex, signed, core },
        })
        this.#localPending.set(opIdHex, {
          raw: opBytes,
          signed,
          core,
          currentEnvelopeDigest: envDigest,
          currentEpoch: epoch,
        })
      }

      await this.#rematerialize()
      this.#emitFacts()
      return new ApplicationOperation(opIdHex, operationId, this)
    })
  }

  /** Execute a named command (via local ApplicationDefinition if present, else direct topic dispatch). */
  async command(name: string, input: unknown = {}, options: CommandOptions = {}): Promise<ApplicationOperation> {
    if (this.definition !== undefined && Object.hasOwn(this.definition.commands, name)) {
      const cmd = this.definition.commands[name]!
      const updates = cmd.prepare(input as never)
      return this.submit({ ...options, updates })
    }
    const reducers = this.#kernel.topic('$reducers') as { readonly topics?: Record<string, unknown> } | null
    const topics = reducers?.topics ?? {}
    if (Object.hasOwn(topics, name)) {
      return this.submit({ ...options, updates: [{ topic: name, input: normalizeJsonValue(input) }] })
    }
    const sep = name.includes('.') ? name.indexOf('.') : name.indexOf(':')
    if (sep > 0) {
      const topic = name.slice(0, sep)
      const action = name.slice(sep + 1)
      if (Object.hasOwn(topics, topic)) {
        const body = (input !== null && typeof input === 'object' && !Array.isArray(input))
          ? { action, ...(input as Record<string, JsonValue>) }
          : { action, input: normalizeJsonValue(input) }
        return this.submit({ ...options, updates: [{ topic, input: body }] })
      }
    }
    const appTopics = Object.keys(topics).filter(t => !isControlTopic(t))
    if (appTopics.length === 1) {
      const topic = appTopics[0]!
      const described = await this.describe().catch(() => null)
      if (described && described.commands.length > 0 && !described.commands.some(c => c.name === name)) {
        throw new Error(`APPLICATION_COMMAND_UNKNOWN:${name}`)
      }
      const body = (input !== null && typeof input === 'object' && !Array.isArray(input))
        ? { action: name, ...(input as Record<string, JsonValue>) }
        : { action: name, input: normalizeJsonValue(input) }
      return this.submit({ ...options, updates: [{ topic, input: body }] })
    }
    throw new Error(`APPLICATION_COMMAND_UNKNOWN:${name}`)
  }

  /** Execute a named query (via local ApplicationDefinition if present, else reducer query()). */
  async query(name: string, input: unknown = null, _options?: { readonly signal?: AbortSignal }): Promise<{
    readonly applicationId: string
    readonly revision: MaterializedRevision
    readonly value: unknown
  }> {
    if (this.definition !== undefined && Object.hasOwn(this.definition.queries, name)) {
      const view = await this.readView()
      try {
        const value = await this.definition.queries[name]!.read(view as never, input as never)
        return { applicationId: this.applicationId, revision: view.revision, value }
      } finally {
        view.release()
      }
    }
    const reducers = this.#kernel.topic('$reducers') as { readonly topics?: Record<string, unknown> } | null
    const topics = reducers?.topics ?? {}
    if (Object.hasOwn(topics, name)) {
      const value = await this.#kernel.query(name, normalizeJsonValue(input))
      return { applicationId: this.applicationId, revision: this.#lastLocalRevision, value }
    }
    const sep = name.includes('.') ? name.indexOf('.') : name.indexOf(':')
    if (sep > 0) {
      const topic = name.slice(0, sep)
      const queryName = name.slice(sep + 1)
      if (Object.hasOwn(topics, topic)) {
        const body = (input !== null && typeof input === 'object' && !Array.isArray(input))
          ? { query: queryName, ...(input as Record<string, JsonValue>) }
          : { query: queryName, input: normalizeJsonValue(input) }
        const value = await this.#kernel.query(topic, body)
        return { applicationId: this.applicationId, revision: this.#lastLocalRevision, value }
      }
    }
    const appTopics = Object.keys(topics).filter(t => !isControlTopic(t))
    if (appTopics.length === 1) {
      const topic = appTopics[0]!
      const described = await this.describe().catch(() => null)
      if (described && described.queries.length > 0 && !described.queries.some(q => q.name === name)) {
        throw new Error(`APPLICATION_QUERY_UNKNOWN:${name}`)
      }
      const body = (input !== null && typeof input === 'object' && !Array.isArray(input))
        ? { query: name, ...(input as Record<string, JsonValue>) }
        : { query: name, input: normalizeJsonValue(input) }
      const value = await this.#kernel.query(topic, body)
      return { applicationId: this.applicationId, revision: this.#lastLocalRevision, value }
    }
    throw new Error(`APPLICATION_QUERY_UNKNOWN:${name}`)
  }

  /** Describe available commands and queries (from local definition or in-chain reducer describe() exports). */
  async describe(): Promise<ApplicationDescription> {
    if (this.definition !== undefined) return describeApplication(this.definition)
    const raw = await this.#kernel.describe()
    const commands: { readonly name: string; readonly description: string; readonly input: ApplicationDescription['commands'][number]['input'] }[] = []
    const queries: { readonly name: string; readonly description: string; readonly input: ApplicationDescription['queries'][number]['input'] }[] = []
    const multiTopic = Object.keys(raw).filter(t => !isControlTopic(t)).length > 1

    for (const [topic, entry] of Object.entries(raw)) {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue
      const obj = entry as Record<string, unknown>
      const prefix = multiTopic ? `${topic}.` : ''
      if (Array.isArray(obj.commands)) {
        for (const c of obj.commands) {
          if (c && typeof c === 'object' && typeof (c as { name?: unknown }).name === 'string') {
            const cmd = c as { name: string; description?: string; input?: ApplicationDescription['commands'][number]['input'] }
            commands.push({
              name: `${prefix}${cmd.name}`,
              description: cmd.description ?? '',
              input: checkedApplicationInputSchema(cmd.input ?? { type: 'object', properties: {} }),
            })
          }
        }
      }
      if (Array.isArray(obj.queries)) {
        for (const q of obj.queries) {
          if (q && typeof q === 'object' && typeof (q as { name?: unknown }).name === 'string') {
            const qry = q as { name: string; description?: string; input?: ApplicationDescription['queries'][number]['input'] }
            queries.push({
              name: `${prefix}${qry.name}`,
              description: qry.description ?? '',
              input: checkedApplicationInputSchema(qry.input ?? { type: 'object', properties: {} }),
            })
          }
        }
      }
    }
    commands.sort((a, b) => a.name.localeCompare(b.name))
    queries.sort((a, b) => a.name.localeCompare(b.name))
    return validateApplicationDescription({
      id: `chain-${this.chainId.slice(0, 16)}`,
      version: '2.0.0',
      commands,
      queries,
    })
  }

  #hasActiveFinalityPolicy(): boolean {
    const schedule = parseFinalitySchedule(this.#kernel.topic('$finality'))
    return schedule.some(entry => entry.policy.kind !== 'none')
  }

  /** Capture a coherent read snapshot for reactive views, queries, and event pagination. */
  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<ApplicationReadView> {
    const viewKind = options.view ?? 'local'
    if (viewKind === 'final' && !this.#hasActiveFinalityPolicy()) {
      throw Object.assign(new Error('FINALITY_UNSUPPORTED'), { code: 'FINALITY_UNSUPPORTED' })
    }
    const kernel = viewKind === 'final' ? this.#finalKernel : this.#kernel
    const revision = this.revision(viewKind)
    const topicsSnap = kernel === null ? {} : kernel.topics
    const outcomesSnap = kernel === null ? [] : kernel.outcomes
    const events: ApplicationEvent[] = []
    for (const outcome of outcomesSnap) {
      if (outcome.outcome !== 'accepted') continue
      for (const ev of outcome.events) events.push(toApplicationEvent(ev))
    }

    let released = false
    const checkLive = (): void => { if (released) throw new Error('READ_VIEW_RELEASED') }
    return {
      applicationId: this.applicationId,
      revision,
      topic(name: string): JsonValue | null {
        checkLive()
        return Object.hasOwn(topicsSnap, name) ? structuredClone(topicsSnap[name]!) : null
      },
      async query(topic: string, input?: JsonValue): Promise<JsonValue> {
        checkLive()
        if (kernel === null) return Object.hasOwn(topicsSnap, topic) ? structuredClone(topicsSnap[topic]!) : null
        return kernel.query(topic, input ?? null, topicsSnap)
      },
      readEvents(eventOptions: ApplicationEventOptions = {}): ApplicationEventBatch {
        checkLive()
        return sliceEvents(events, revision, eventOptions)
      },
      release(): void { released = true },
    }
  }

  readEvents(options: ApplicationEventOptions & { readonly view?: 'local' | 'final' } = {}): ApplicationEventBatch {
    const viewKind = options.view ?? 'local'
    if (viewKind === 'final' && !this.#hasActiveFinalityPolicy()) {
      throw Object.assign(new Error('FINALITY_UNSUPPORTED'), { code: 'FINALITY_UNSUPPORTED' })
    }
    const kernel = viewKind === 'final' ? this.#finalKernel : this.#kernel
    const revision = this.revision(viewKind)
    const events: ApplicationEvent[] = []
    if (kernel !== null) {
      for (const outcome of kernel.outcomes) {
        if (outcome.outcome !== 'accepted') continue
        for (const ev of outcome.events) events.push(toApplicationEvent(ev))
      }
    }
    return sliceEvents(events, revision, options)
  }

  // ---- High-level v2 control helpers ----

  async admitMember(options: {
    readonly publicKey: string
    readonly wrapKey?: string
    readonly reader?: boolean
    readonly writer?: boolean
    readonly administrator?: boolean
    readonly publisher?: boolean
    readonly finalizer?: boolean
    readonly attestation?: { readonly payload: JsonValue; readonly signature: string }
    readonly minEpoch?: number
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    const memberPayload: Record<string, JsonValue> = {
      publicKey: options.publicKey,
      ...(options.wrapKey ? { wrapKey: options.wrapKey } : {}),
      reader: options.reader ?? true,
      writer: options.writer ?? true,
      administrator: options.administrator ?? false,
      publisher: options.publisher ?? false,
      finalizer: options.finalizer ?? false,
    }
    const updates: TopicUpdate[] = [
      {
        topic: '$permissions',
        input: {
          action: 'setMember',
          member: memberPayload,
          ...(options.attestation ? { attestation: options.attestation as unknown as JsonValue } : {}),
        },
      },
    ]

    if (this.genesis.privateChain && (options.reader ?? true) && options.wrapKey) {
      const keysState = this.keysState()
      if (keysState.currentEpoch < 0) {
        const epoch0 = this.#epochKeys.get(0) ?? crypto.getRandomValues(new Uint8Array(32))
        await this.installEpochKey(0, epoch0)
        const boxes: Record<string, EpochKeyBox> = {}
        const allReaders = new Map<string, string>()
        for (const m of this.permissions().members) {
          if (m.reader && m.wrapKey) allReaders.set(m.publicKey, m.wrapKey)
        }
        allReaders.set(options.publicKey, options.wrapKey)
        for (const [pk, wk] of allReaders) {
          boxes[pk] = await hpkeSealEpochKey(wk, epoch0, this.chainId, 0)
        }
        updates.push({
          topic: '$keys',
          input: {
            action: 'rotateEpoch',
            epoch: 0,
            keyCommitment: epochKeyCommitmentV2(epoch0),
            boxes: boxes as unknown as JsonValue,
          },
        })
      } else {
        const minEp = options.minEpoch ?? 0
        const epochBoxes: Record<string, EpochKeyBox> = {}
        for (let ep = minEp; ep <= keysState.currentEpoch; ep++) {
          const epKey = this.#epochKeys.get(ep)
          if (epKey === undefined) continue
          epochBoxes[String(ep)] = await hpkeSealEpochKey(options.wrapKey, epKey, this.chainId, ep)
        }
        if (Object.keys(epochBoxes).length > 0) {
          updates.push({
            topic: '$keys',
            input: {
              action: 'grantBoxes',
              member: options.publicKey,
              epochBoxes: epochBoxes as unknown as JsonValue,
            },
          })
        }
      }
    }

    return this.submit({
      visibility: 'public',
      updates,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
    })
  }

  async rotateEpoch(options: {
    readonly excludeMembers?: readonly string[]
    readonly newEpochKey?: Uint8Array
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<{ readonly epoch: number; readonly operation: ApplicationOperation }> {
    check(this.genesis.privateChain, 'EPOCH_ROTATION_PRIVATE_CHAIN_ONLY')
    const keysState = this.keysState()
    const nextEpoch = keysState.currentEpoch + 1
    const key = options.newEpochKey ?? crypto.getRandomValues(new Uint8Array(32))
    await this.installEpochKey(nextEpoch, key)

    const exclude = new Set(options.excludeMembers ?? [])
    const boxes: Record<string, EpochKeyBox> = {}
    for (const m of this.permissions().members) {
      if (!m.reader || !m.wrapKey || exclude.has(m.publicKey)) continue
      boxes[m.publicKey] = await hpkeSealEpochKey(m.wrapKey, key, this.chainId, nextEpoch)
    }

    const operation = await this.submit({
      visibility: 'public',
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$keys',
        input: {
          action: 'rotateEpoch',
          epoch: nextEpoch,
          keyCommitment: epochKeyCommitmentV2(key),
          boxes: boxes as unknown as JsonValue,
        },
      }],
    })
    return { epoch: nextEpoch, operation }
  }

  async removeMember(publicKey: string, options: {
    readonly rotateEpoch?: boolean
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<ApplicationOperation> {
    const updates: TopicUpdate[] = [
      { topic: '$permissions', input: { action: 'removeMember', publicKey } },
    ]
    if (this.genesis.privateChain && options.rotateEpoch !== false) {
      const nextEpoch = this.keysState().currentEpoch + 1
      const key = crypto.getRandomValues(new Uint8Array(32))
      await this.installEpochKey(nextEpoch, key)
      const boxes: Record<string, EpochKeyBox> = {}
      for (const m of this.permissions().members) {
        if (!m.reader || !m.wrapKey || m.publicKey === publicKey) continue
        boxes[m.publicKey] = await hpkeSealEpochKey(m.wrapKey, key, this.chainId, nextEpoch)
      }
      updates.push({
        topic: '$keys',
        input: {
          action: 'rotateEpoch',
          epoch: nextEpoch,
          keyCommitment: epochKeyCommitmentV2(key),
          boxes: boxes as unknown as JsonValue,
        },
      })
    }
    return this.submit({
      visibility: 'public',
      updates,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
    })
  }

  async publishRelease(options: {
    readonly entry: string
    readonly files: readonly { readonly path: string; readonly bytes?: Uint8Array; readonly hash?: string; readonly size?: number; readonly type: string }[]
    readonly expectedRevision?: number
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    const descriptors: { readonly path: string; readonly hash: string; readonly size: number; readonly type: string }[] = []
    for (const f of options.files) {
      let hash = f.hash
      let size = f.size
      if (f.bytes !== undefined) {
        hash = await this.cas.put(f.bytes, [], 'public')
        size = f.bytes.length
      }
      check(hash !== undefined && size !== undefined, 'PUBLICATION_FILE_INVALID')
      descriptors.push({ path: f.path, hash, size, type: f.type })
    }
    return this.submit({
      visibility: 'public',
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$publications',
        input: {
          action: 'publish',
          entry: options.entry,
          files: descriptors as unknown as JsonValue,
          ...(options.expectedRevision === undefined ? {} : { expectedRevision: options.expectedRevision }),
        },
      }],
    })
  }

  async scheduleFinality(options: {
    readonly effectiveAfterMs: bigint | number
    readonly policy: FinalityPolicyV2
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    return this.submit({
      visibility: 'public',
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$finality',
        input: {
          action: 'schedulePolicy',
          effectiveAfterMs: Number(options.effectiveAfterMs),
          policy: options.policy as unknown as JsonValue,
        },
      }],
    })
  }

  async updateReducers(options: {
    readonly imports?: Readonly<Record<string, string | null>>
    readonly topics?: Readonly<Record<string, JsonValue>>
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    const pinnedImports: Record<string, JsonValue> = {}
    if (options.imports !== undefined) {
      for (const [spec, val] of Object.entries(options.imports)) {
        if (val === null || val.startsWith('cas:sha256-')) {
          pinnedImports[spec] = val
        } else {
          const hash = await this.cas.put(utf8(val), [], 'public')
          pinnedImports[spec] = `cas:sha256-${hash}`
        }
      }
    }
    return this.submit({
      visibility: 'public',
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$reducers',
        input: {
          ...(Object.keys(pinnedImports).length > 0 ? { imports: pinnedImports } : {}),
          ...(options.topics !== undefined ? { topics: options.topics as JsonValue } : {}),
        },
      }],
    })
  }

  // ---- Finality operations ----

  readonly finality = {
    status: (): VerifiedFinalityV2 & { readonly schedule: readonly ScheduledFinalityEntry[] } => ({
      ...this.#verifiedFinality,
      schedule: parseFinalitySchedule(this.#kernel.topic('$finality')),
    }),

    createCheckpoint: async (options: { readonly throughMs: bigint }): Promise<{
      readonly checkpoint: FinalityCheckpoint
      readonly snapshot: CheckpointBootstrapSnapshot
    }> => {
      return this.#serial(async () => {
        const schedule = parseFinalitySchedule(this.#kernel.topic('$finality'))
        let active: ScheduledFinalityEntry = schedule[0]!
        for (const entry of schedule) {
          if (entry.effectiveAfterMs <= options.throughMs) active = entry
        }
        check(active.policy.kind !== 'none', 'FINALITY_NOT_ACTIVE')
        const scopeId = await policyScopeId(this.chainId, active)

        const all = this.#collectDecryptedKernelInputs()
        const included: KernelOperationInput[] = []
        for (const [opId, input] of all) {
          if (this.#verifiedFinality.excludedOpIds.has(opId)) continue
          if (input.core.authorTimestampMs <= options.throughMs) included.push(input)
        }
        included.sort((a, b) => compareOperationOrder(
          { authorTimestampMs: a.core.authorTimestampMs, author: a.core.author, opId: a.opId },
          { authorTimestampMs: b.core.authorTimestampMs, author: b.core.author, opId: b.opId },
        ))

        const tempKernel = new TopicKernel({
          genesis: this.genesisBytes,
          cas: this.cas,
          blindHostMode: this.#blindHostMode,
          ...this.#sandboxOptions,
          ...(this.#sqliteDriver === undefined ? {} : { sqliteDriver: this.#sqliteDriver }),
        })
        await tempKernel.materialize(included)
        const snap = tempKernel.snapshot()

        const inclusions = included.map(i => ({
          opId: bytesToHex(i.opId),
          authorTimestampMs: i.core.authorTimestampMs,
          author: bytesToHex(i.core.author),
        }))
        const payload: FinalityCheckpointPayload = {
          chainId: this.chainId,
          policyScopeId: scopeId,
          closedThroughMs: options.throughMs,
          includedSetDigest: computeIncludedSetDigest(inclusions.map(i => i.opId)),
          historyDigest: snap.historyDigest,
          stateRoot: snap.stateRoot,
          inclusions,
        }
        const sig = await signFinalityCheckpoint(payload, this.device.identity)
        const checkpoint: FinalityCheckpoint = {
          payload,
          attestation: { kind: 'signatures', signatures: [sig] },
        }

        const key = await recordDigest(payload)
        this.#checkpoints.set(key, checkpoint)
        await this.#store.put(`${this.#prefix}/checkpoint/${key}`, encodeRecord(checkpoint))
        await this.#rematerialize()
        this.#emitFacts()
        return { checkpoint, snapshot: snap }
      })
    },

    submitCheckpoints: async (checkpoints: readonly FinalityCheckpoint[]): Promise<void> => {
      await this.mergeFacts({
        publicOps: [],
        encryptedEnvelopes: [],
        casNodes: [],
        retentions: [],
        checkpoints,
      })
    },

    bootstrapFromCheckpoint: async (
      checkpoint: FinalityCheckpoint,
      snapshot: CheckpointBootstrapSnapshot,
    ): Promise<void> => {
      await this.#serial(async () => {
        check(checkpoint.payload.chainId === this.chainId, 'CHECKPOINT_CHAIN_MISMATCH')
        check(checkpoint.payload.stateRoot === snapshot.stateRoot && checkpoint.payload.historyDigest === snapshot.historyDigest, 'CHECKPOINT_SNAPSHOT_MISMATCH')
        const key = await recordDigest(checkpoint.payload)
        this.#checkpoints.set(key, checkpoint)
        await this.#store.put(`${this.#prefix}/checkpoint/${key}`, encodeRecord(checkpoint))
        await this.#kernel.bootstrapFromCheckpoint(snapshot)
        this.#lastLocalRevision = toMaterializedRevision(this.#kernel.revision('local'))
        this.#emitChange({ kind: 'finalized', revision: this.#lastLocalRevision, revisedProposalIds: [] })
        this.#emitStatus()
      })
    },
  }

  // ---- Operation inspection & waiting ----

  inspectOperation(idOrOperationId: string): OperationInspection {
    let opIdHex = idOrOperationId
    let core: OperationCore | null = null
    let pending: 'dependency' | 'key' | null = null

    const pub = this.#publicOps.get(idOrOperationId)
    if (pub !== undefined) {
      core = pub.core
    } else {
      for (const [k, v] of this.#publicOps) {
        if (v.core.operationId === idOrOperationId && bytesToHex(v.core.author) === this.identity.publicKey) {
          opIdHex = k; core = v.core; break
        }
      }
    }
    if (core === null) {
      const byDigest = this.#encryptedEnvelopes.get(idOrOperationId)
      if (byDigest?.decrypted !== undefined) {
        opIdHex = byDigest.decrypted.opId; core = byDigest.decrypted.core
      }
    }
    if (core === null) {
      for (const entry of this.#encryptedEnvelopes.values()) {
        if (entry.decrypted?.opId === idOrOperationId) {
          opIdHex = entry.decrypted.opId; core = entry.decrypted.core; break
        }
        if (entry.decrypted?.core.operationId === idOrOperationId && bytesToHex(entry.decrypted.core.author) === this.identity.publicKey) {
          opIdHex = entry.decrypted.opId; core = entry.decrypted.core; break
        }
      }
    }
    if (core === null) {
      const pend = this.#localPending.get(idOrOperationId)
      if (pend !== undefined) core = pend.core
      else {
        for (const [k, v] of this.#localPending) {
          if (v.core.operationId === idOrOperationId) { opIdHex = k; core = v.core; break }
        }
      }
    }

    const outcome = this.#kernel.outcomes.find(o => o.opId === opIdHex)
    const materialized: MaterializedOperation | null = outcome === undefined ? null : {
      proposalId: opIdHex,
      revision: this.#lastLocalRevision,
      outcome: outcome.outcome,
      rejectionCode: outcome.rejectionCode,
      ...(outcome.rejectionDetail === undefined ? {} : { rejectionDetail: outcome.rejectionDetail }),
    }

    if (materialized === null) {
      if (this.#kernel.pendingDependencies.length > 0) pending = 'dependency'
      else if (core === null) pending = 'key'
    }

    const retained = [...(this.#retentions.get(opIdHex)?.values() ?? [])]
      .filter(r => r.signer !== this.identity.publicKey && r.payload.storageId !== this.device.storageId)

    return {
      applicationId: this.applicationId,
      author: core === null ? '' : bytesToHex(core.author),
      authorTimestampMs: core === null ? null : core.authorTimestampMs.toString(),
      proposalId: opIdHex,
      operationId: core === null ? idOrOperationId : core.operationId,
      visibility: core === null ? 'encrypted' : core.visibility,
      stored: core !== null,
      pending,
      materialized,
      retained,
      finalized: this.#verifiedFinality.includedOpIds.has(opIdHex),
      excluded: this.#verifiedFinality.excludedOpIds.has(opIdHex),
    }
  }

  async waitOperation(
    id: string,
    fact: 'materialized' | 'retained' | 'finalized',
    options: WaitOptions = {},
  ): Promise<OperationInspection> {
    if (fact === 'finalized' && !this.#hasActiveFinalityPolicy()) {
      throw Object.assign(new Error('FINALITY_UNSUPPORTED'), { code: 'FINALITY_UNSUPPORTED' })
    }
    const checkDone = (): OperationInspection | null => {
      const info = this.inspectOperation(id)
      if (fact === 'materialized' && info.materialized !== null) return info
      if (fact === 'retained' && info.retained.length > 0) return info
      if (fact === 'finalized' && info.finalized && info.materialized !== null) return info
      return null
    }
    const immediate = checkDone()
    if (immediate !== null) return immediate

    const timeoutMs = options.timeoutMs ?? 30_000
    const signal = options.signal === undefined ? this.#lifetime.signal : AbortSignal.any([this.#lifetime.signal, options.signal])
    signal.throwIfAborted()

    return new Promise<OperationInspection>((resolve, reject) => {
      let settled = false
      const done = (fn: () => void): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        stopChange(); stopStatus(); stopFacts()
        signal.removeEventListener('abort', onAbort)
        fn()
      }
      const evaluate = (): void => {
        const ready = checkDone()
        if (ready !== null) done(() => resolve(ready))
      }
      const onAbort = (): void => done(() => reject(signal.reason))
      const timer = setTimeout(() => done(() => reject(new Error(`OPERATION_WAIT_TIMEOUT:${fact}`))), timeoutMs)
      const stopChange = this.onChange(evaluate)
      const stopStatus = this.onStatus(evaluate)
      const stopFacts = this.onFacts(evaluate)
      signal.addEventListener('abort', onAbort, { once: true })
      evaluate()
    })
  }

  readonly operations = {
    get: (idOrOperationId: string): ApplicationOperation | null => {
      const info = this.inspectOperation(idOrOperationId)
      return info.stored ? new ApplicationOperation(info.proposalId, info.operationId, this) : null
    },
    retry: async (idOrOperationId: string): Promise<ApplicationOperation> => {
      const existing = this.operations.get(idOrOperationId)
      check(existing !== null, 'OPERATION_UNKNOWN')
      this.#emitFacts()
      return existing
    },
  }

  // ---- Retention ----

  async retain(proposalId: string, subject: { readonly author: string; readonly envelopeDigest: string }): Promise<RetentionEvidence> {
    const evidence = await signRecord('operation-retention', {
      applicationId: this.applicationId,
      proposalId,
      author: subject.author,
      envelopeDigest: subject.envelopeDigest,
      peer: this.identity.publicKey,
      storageId: this.device.storageId,
    }, this.device.identity)
    let byPeer = this.#retentions.get(proposalId)
    if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(proposalId, byPeer) }
    byPeer.set(this.identity.publicKey, evidence)
    await this.#store.put(`${this.#prefix}/retention/${proposalId}/${this.identity.publicKey}`, encodeRecord(evidence))
    this.#emitFacts()
    return evidence
  }

  // ---- Facts export & merge (P2P + blind host sync) ----

  async exportFacts(options: { readonly includePrivateCas?: boolean; readonly includeGenesis?: boolean } = {}): Promise<SessionFacts> {
    const includePrivate = options.includePrivateCas ?? (!this.#blindHostMode && this.isReader(this.identity.publicKey))
    const casNodes: SessionCasNode[] = []
    const partitions: readonly CasPartition[] = includePrivate ? ['public', 'private'] : ['public']
    for (const partition of partitions) {
      for (const hash of this.cas.listKnownHashes(partition)) {
        const raw = await this.cas.getRaw(hash, partition)
        if (raw !== null) casNodes.push({ hash, bytes: raw, partition })
      }
    }
    const retentions: RetentionEvidence[] = []
    for (const byPeer of this.#retentions.values()) {
      for (const ev of byPeer.values()) retentions.push(ev)
    }
    return {
      ...(options.includeGenesis ? { genesisBytes: this.genesisBytes.slice() } : {}),
      publicOps: [...this.#publicOps.values()].map(v => v.raw.slice()),
      encryptedEnvelopes: [...this.#encryptedEnvelopes.values()].map(v => v.raw.slice()),
      casNodes,
      retentions,
      checkpoints: [...this.#checkpoints.values()],
    }
  }

  async exportPublicControlFacts(): Promise<{ readonly publicOps: readonly Uint8Array[]; readonly casNodes: readonly SessionCasNode[] }> {
    const casNodes: SessionCasNode[] = []
    for (const hash of this.cas.listKnownHashes('public')) {
      const raw = await this.cas.getRaw(hash, 'public')
      if (raw !== null) casNodes.push({ hash, bytes: raw, partition: 'public' })
    }
    return {
      publicOps: [...this.#publicOps.values()].map(v => v.raw.slice()),
      casNodes,
    }
  }

  mergeFacts(facts: SessionFacts): Promise<void> {
    return this.#serial(async () => {
      if (facts.genesisBytes !== undefined) {
        check(sameBytes(facts.genesisBytes, this.genesisBytes), 'FACTS_GENESIS_MISMATCH')
      }

      let changed = false

      for (const node of facts.casNodes ?? []) {
        if (this.cas.hasSync(node.hash, node.partition)) continue
        if (hashCasNode(node.bytes) === node.hash) {
          decodeCasNode(node.bytes)
          await this.cas.putRaw(node.hash, node.bytes, node.partition)
          changed = true
        } else if (computeCasHash(node.bytes, []) === node.hash) {
          await this.cas.put(node.bytes, [], node.partition)
          changed = true
        } else {
          throw new Error(`CAS_NODE_HASH_MISMATCH:${node.hash}`)
        }
      }

      for (const raw of facts.publicOps ?? []) {
        const signed = decodeSignedOperation(raw)
        const verified = await verifySignedOperation(signed)
        if (bytesToHex(verified.core.chainId) !== this.chainId) continue
        if (verified.core.visibility !== 'public') continue
        const opId = bytesToHex(verified.opId)
        if (this.#publicOps.has(opId)) continue
        check(this.#publicOps.size + this.#encryptedEnvelopes.size < this.#maxOperations, 'SESSION_OPERATION_LIMIT')
        await this.#store.put(`${this.#prefix}/public-op/${opId}`, raw.slice())
        this.#publicOps.set(opId, { raw: raw.slice(), signed, core: verified.core })
        changed = true
      }

      for (const raw of facts.encryptedEnvelopes ?? []) {
        const envelope = decodeEncryptedEnvelope(raw)
        if (bytesToHex(envelope.chainId) !== this.chainId) continue
        const digest = bytesToHex(encryptedEnvelopeDigest(raw))
        if (this.#encryptedEnvelopes.has(digest)) continue
        check(this.#publicOps.size + this.#encryptedEnvelopes.size < this.#maxOperations, 'SESSION_OPERATION_LIMIT')
        await this.#store.put(`${this.#prefix}/enc-env/${digest}`, raw.slice())
        this.#encryptedEnvelopes.set(digest, { digest, raw: raw.slice(), envelope })
        changed = true
      }

      for (const ev of facts.retentions ?? []) {
        if (ev.payload.applicationId !== this.applicationId) continue
        await verifyRecord('operation-retention', ev, ev.signer)
        let byPeer = this.#retentions.get(ev.payload.proposalId)
        if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(ev.payload.proposalId, byPeer) }
        if (!byPeer.has(ev.signer)) {
          byPeer.set(ev.signer, ev)
          await this.#store.put(`${this.#prefix}/retention/${ev.payload.proposalId}/${ev.signer}`, encodeRecord(ev))
          changed = true
        }
      }

      for (const cp of facts.checkpoints ?? []) {
        if (cp.payload.chainId !== this.chainId) continue
        const key = await recordDigest(cp.payload)
        if (!this.#checkpoints.has(key)) {
          this.#checkpoints.set(key, cp)
          await this.#store.put(`${this.#prefix}/checkpoint/${key}`, encodeRecord(cp))
          changed = true
        }
      }

      if (changed) {
        await this.#rematerialize()
        this.#emitFacts()
      }
    })
  }

  async collectGarbage(): Promise<{ readonly kept: number; readonly deleted: number }> {
    return this.#serial(async () => {
      const roots = this.#kernel.gcRoots()
      if (this.#finalKernel !== null) {
        for (const r of this.#finalKernel.gcRoots()) roots.add(r)
      }
      for (const src of Object.values(STANDARD_MODULE_SOURCES)) {
        roots.add(computeCasHash(utf8(src), []))
      }
      return this.cas.collectGarbage(roots)
    })
  }

  connectPeer(options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
    return connectApplicationPeer(this, options)
  }

  diagnostics(): readonly ApplicationPeerDiagnostics[] {
    return applicationPeerDiagnostics(this)
  }

  peerLinks(): readonly ApplicationPeerLink[] {
    return applicationPeerLinks(this)
  }

  onPeerLink(listener: (event: { readonly type: 'connected' | 'disconnected'; readonly link: ApplicationPeerLink }) => void): () => void {
    return onApplicationPeerLink(this, listener)
  }

  close(): Promise<void> {
    return this.#closing ??= (async () => {
      this.#closed = true
      this.#lifetime.abort(new Error('SESSION_CLOSED'))
      this.#emitStatus()
      await this.content.close()
      await this.#release()
    })()
  }
}

function sliceEvents(
  events: readonly ApplicationEvent[],
  revision: MaterializedRevision,
  options: ApplicationEventOptions,
): ApplicationEventBatch {
  const limit = options.limit ?? 64
  check(Number.isSafeInteger(limit) && limit >= 1 && limit <= 512, 'EVENT_LIMIT_INVALID')
  const normalizedTopics = options.topics === undefined ? null : [...new Set(options.topics)].sort()
  const topicFilter = normalizedTopics === null ? null : new Set(normalizedTopics)
  const filtered = topicFilter === null ? events : events.filter(ev => topicFilter.has(ev.topic))

  let start = 0
  if (options.cursor !== undefined && options.cursor !== '') {
    check(options.cursor.length <= APPLICATION_EVENT_CURSOR_LIMIT, 'EVENT_CURSOR_INVALID')
    let parsed: { readonly revision?: unknown; readonly view?: unknown; readonly topics?: unknown; readonly after?: unknown }
    try {
      parsed = JSON.parse(options.cursor) as { readonly revision?: unknown; readonly view?: unknown; readonly topics?: unknown; readonly after?: unknown }
    } catch {
      throw Object.assign(new Error('EVENT_CURSOR_INVALID'), { code: 'EVENT_CURSOR_INVALID' })
    }
    if (
      parsed === null || typeof parsed !== 'object' ||
      typeof parsed.after !== 'number' || !Number.isSafeInteger(parsed.after) || parsed.after < 0
    ) {
      throw Object.assign(new Error('EVENT_CURSOR_INVALID'), { code: 'EVENT_CURSOR_INVALID' })
    }
    if (
      parsed.revision !== revision.digest ||
      parsed.view !== revision.view ||
      JSON.stringify(parsed.topics ?? null) !== JSON.stringify(normalizedTopics)
    ) {
      throw Object.assign(new Error('EVENT_CURSOR_STALE'), { code: 'EVENT_CURSOR_STALE' })
    }
    start = parsed.after
  }
  const page = filtered.slice(start, start + limit)
  const nextAfter = start + page.length
  const hasMore = nextAfter < filtered.length
  const cursor = JSON.stringify({
    revision: revision.digest,
    view: revision.view,
    topics: normalizedTopics,
    after: nextAfter,
  })
  return { revision, events: page, cursor, hasMore }
}

export { sha256Sync }

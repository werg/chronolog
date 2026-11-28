import { bytesToHex, hexToBytes, perfTimeAsync, sha256Sync, utf8 } from '@chronolog/canonical'
import { openSqlBranch, type SqlBranch } from './sql-extensions.js'
import { combineShares, decryptEpochPayload, encryptEpochPayload, splitSecret } from '@chronolog/crypto'
import {
  computeCasHash,
  ContentAddressedStore,
  writeBytesMany,
  type BytesStore,
  type BytesStoreEntry,
  type CasPartition,
} from '@chronolog/records'
import {
  assertValidReducersConfig,
  compareOperationOrder,
  decodeEncryptedEnvelope,
  decodeLogGenesis,
  decodeOperationCore,
  decodeSignedOperation,
  encodeEncryptedEnvelope,
  encodeLogGenesis,
  encodeSignedOperation,
  encryptedEnvelopeDigest,
  envelopeAad,
  genesisLogId,
  isControlTopic,
  normalizeAssumptionsConfig,
  normalizeJsonValue,
  operationIdDigest,
  signOperationCore,
  verifySignedOperation,
  type EncryptedOperationEnvelope,
  type LogGenesis,
  type JsonValue,
  type OperationAssumption,
  type OperationAssumptionsConfig,
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
  type KernelMaterializedCache,
  type KernelOperationInput,
  type QuickJsSandboxOptions,
  type SqliteBuiltinDriver,
} from '@chronolog/materializer'
import { SignalChannel, type SignalAuthorization } from '@chronolog/signals'
import { ApplicationContent } from './content.js'
import type { ApplicationDevice } from './device.js'
import { describeApplication, type ApplicationDefinition } from './definition.js'
import { FactIdSet } from './reconcile.js'
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
  type SessionKeyState,
  type SessionStatus,
  type WaitOptions,
} from './session-types.js'

export interface SessionCasNode {
  readonly hash: string
  readonly bytes: Uint8Array
  readonly partition: CasPartition
}

/** Sync-v3 fact scopes: public = public ops + finality checkpoints; private = encrypted envelopes. */
export type FactScope = 'public' | 'private'

/** Facts added since the last `onFacts` notification, tagged with the link that delivered them. */
export interface FactsDelta {
  readonly items: readonly { readonly scope: FactScope; readonly id: string; readonly source?: string }[]
}

/** Map that mirrors its keys into a reconciliation id set and reports additions (with their source). */
class FactMap<V> extends Map<string, V> {
  #source: string | undefined
  constructor(readonly ids: FactIdSet, readonly onAdd: (key: string, source: string | undefined) => void) { super() }
  override set(key: string, value: V): this {
    if (this.ids !== undefined && !super.has(key)) { this.ids.add(key); this.onAdd(key, this.#source) }
    return super.set(key, value)
  }
  /** Insert a fact delivered by peer link `source` (synchronous, so concurrent local writes are never mis-tagged). */
  setFrom(key: string, value: V, source: string | undefined): this {
    this.#source = source
    try { return this.set(key, value) } finally { this.#source = undefined }
  }
  override delete(key: string): boolean {
    this.ids.delete(key)
    return super.delete(key)
  }
  override clear(): void {
    this.ids.clear()
    super.clear()
  }
}

let standardHashes: Set<string> | undefined
function standardModuleHashes(): Set<string> {
  return standardHashes ??= new Set(Object.values(STANDARD_MODULE_SOURCES).map(src => computeCasHash(utf8(src), [])))
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
  readonly label?: string
  readonly scopes?: readonly string[]
  readonly expiresAtMs?: number
  readonly reader: boolean
  readonly writer: boolean
  readonly administrator: boolean
  readonly publisher: boolean
  readonly finalizer: boolean
}

export interface GuardianMember {
  readonly publicKey: string
  readonly wrapKey: string
  readonly label?: string
}

export interface GuardiansConfig {
  readonly threshold: number
  readonly members: readonly GuardianMember[]
}

export interface RecoveryRequestRecord {
  readonly requestId: string
  readonly newPublicKey: string
  readonly newWrapKey: string
  readonly label: string
  readonly verificationCode: string
  readonly approvals: readonly string[]
  readonly status: 'pending' | 'completed'
  readonly createdAtMs: number
}

export interface PermissionsMultisigInfo {
  readonly threshold: number
  readonly signers: readonly string[]
  readonly proposals: Readonly<Record<string, JsonValue>>
}

export interface PermissionsTopicState {
  readonly mode?: 'attested' | 'open' | 'multisig' | 'custom'
  readonly members: readonly MemberRecord[]
  readonly readers?: readonly string[]
  readonly writers?: readonly string[]
  readonly administrators?: readonly string[]
  readonly publishers?: readonly string[]
  readonly openReaders?: boolean
  readonly openWriters?: boolean
  readonly blockedAuthors?: readonly string[]
  readonly admission: { readonly hostKey?: string } | null
  readonly guardians?: GuardiansConfig | null
  readonly recoveryRequests?: Readonly<Record<string, RecoveryRequestRecord>>
  readonly multisig?: PermissionsMultisigInfo | null
}

export interface KeyRingState {
  readonly currentEpoch: number
  readonly epochs: Readonly<Record<string, {
    readonly epoch: number
    readonly keyCommitment: string
    readonly boxes: Readonly<Record<string, EpochKeyBox>>
  }>>
}

export interface KeysTopicState {
  readonly currentEpoch: number
  readonly epochs: Readonly<Record<string, {
    readonly epoch: number
    readonly keyCommitment: string
    readonly boxes: Readonly<Record<string, EpochKeyBox>>
  }>>
  readonly rings?: Readonly<Record<string, KeyRingState>>
  readonly topicRings?: Readonly<Record<string, string>>
  readonly recovery?: {
    readonly vault: { readonly nonce: string; readonly ciphertext: string }
    readonly guardianShares: Readonly<Record<string, { readonly index: number; readonly box: EpochKeyBox }>>
  }
  readonly recoveryGrants?: Readonly<Record<string, Readonly<Record<string, { readonly index: number; readonly box: EpochKeyBox }>>>>
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
  readonly genesis?: LogGenesis | Uint8Array
  readonly logId?: string
  /** Optional host-level application scope ID (defaults to `logId`). */
  readonly applicationId?: string
  readonly casNodes?: readonly SessionCasNode[]
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  readonly definition?: D
  readonly blindHostMode?: boolean
  readonly blockchainVerifier?: BlockchainAnchorVerifier
  readonly sqliteWasmModule?: WebAssembly.Module
  readonly sqliteWasmLoader?: () => Promise<WebAssembly.Module>
  readonly materializedSnapshot?: Uint8Array
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
  readonly mode: 'attested' | 'open' | 'multisig' | 'custom'
  readonly members: readonly MemberRecord[]
  readonly readers: ReadonlySet<string>
  readonly writers: ReadonlySet<string>
  readonly administrators: ReadonlySet<string>
  readonly publishers: ReadonlySet<string>
  readonly openReaders: boolean
  readonly openWriters: boolean
  readonly blockedAuthors: ReadonlySet<string>
  readonly admission: { readonly hostKey?: string } | null
  readonly multisig: PermissionsMultisigInfo | null
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
  readonly logId: string
  readonly genesis: LogGenesis
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
  readonly #sqliteWasmLoader?: () => Promise<WebAssembly.Module>
  readonly #maxOperations: number

  #sqliteDriver?: SqliteBuiltinDriver
  #sqliteLoadPromise?: Promise<SqliteBuiltinDriver>
  #kernel: TopicKernel
  #kernelHasSqlite = false
  #controlKernel: TopicKernel | null = null
  #finalKernel: TopicKernel | null = null

  readonly #publicFactIds = new FactIdSet()
  readonly #privateFactIds = new FactIdSet()
  #pendingDelta: { scope: FactScope; id: string; source?: string }[] = []
  #recordDelta(scope: FactScope, id: string, source: string | undefined): void {
    this.#pendingDelta.push(source === undefined ? { scope, id } : { scope, id, source })
  }
  readonly #publicOps = new FactMap<StoredPublicOp>(this.#publicFactIds, (id, source) => this.#recordDelta('public', id, source))
  readonly #encryptedEnvelopes = new FactMap<StoredEncryptedEnvelope>(this.#privateFactIds, (id, source) => this.#recordDelta('private', id, source))
  readonly #undecryptedEnvelopes = new Set<string>()
  readonly #localPending = new Map<string, LocalPendingOp>()
  readonly #retentions = new Map<string, Map<string, RetentionEvidence>>()
  readonly #checkpoints = new FactMap<FinalityCheckpoint>(this.#publicFactIds, (id, source) => this.#recordDelta('public', id, source))
  readonly #epochKeys = new Map<number, Uint8Array>()
  readonly #ringKeys = new Map<string, Map<number, Uint8Array>>()

  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #changeListeners = new Set<(change: ApplicationChange) => void>()
  readonly #factListeners = new Set<(delta: FactsDelta) => void>()

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
    equivocationProofs: [],
  }
  #cachedSignalPolicy: { stateRoot: string; rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] } | null = null
  #cachedDescription: { stateRoot: string; value: ApplicationDescription } | null = null
  #validationDescription: { readonly key: string; readonly value: ApplicationDescription | null } | null = null
  #evaluatedPermissions: EvaluatedPermissionsSummary | null = null
  #lastPermsStateJson = ''
  #pendingMaterializedCache: KernelMaterializedCache | null = null
  #pendingSnapshotBundle: {
    readonly cache: KernelMaterializedCache
    readonly casNodes: readonly SessionCasNode[]
    readonly maxAuthorTimestampMs: bigint
  } | null = null
  #pendingEncryptedSnapshot: Uint8Array | null = null
  #lastPersistedCacheDigest = ''
  #cachePersistTimer: ReturnType<typeof setTimeout> | undefined
  #materializedCacheHits = 0
  #lastSyncSeq = 0
  #closed = false
  #closing?: Promise<void>
  #tail: Promise<unknown> = Promise.resolve()
  #writeTail: Promise<unknown> = Promise.resolve()
  #materializeDirty = false
  #materializePromise: Promise<void> | null = null

  private constructor(
    options: OpenApplicationSessionOptions<D>,
    genesisBytes: Uint8Array,
    cas: ContentAddressedStore,
  ) {
    this.genesisBytes = genesisBytes.slice()
    this.genesis = decodeLogGenesis(this.genesisBytes)
    this.logId = bytesToHex(genesisLogId(this.genesisBytes))
    this.applicationId = options.applicationId ?? this.logId
    this.device = options.device
    this.identity = Object.freeze({ publicKey: options.device.identity.publicKey })
    if (options.definition !== undefined) this.definition = options.definition
    this.cas = cas
    this.#store = options.store
    this.#prefix = `v2/${this.logId}`
    this.#release = options.release
    this.#blindHostMode = options.blindHostMode ?? false
    if (options.blockchainVerifier !== undefined) this.#blockchainVerifier = options.blockchainVerifier
    if (options.sqliteWasmModule !== undefined) this.#sqliteWasmModule = options.sqliteWasmModule
    if (options.sqliteWasmLoader !== undefined) this.#sqliteWasmLoader = options.sqliteWasmLoader
    if (options.materializedSnapshot !== undefined) this.#pendingEncryptedSnapshot = options.materializedSnapshot.slice()
    this.#maxOperations = options.maxOperations ?? 50_000
    this.#sandboxOptions = {
      ...(options.wasmModule === undefined ? {} : { wasmModule: options.wasmModule }),
      ...(options.sqliteDriver === undefined ? {} : { sqliteDriver: options.sqliteDriver }),
    }
    if (options.sqliteDriver !== undefined) {
      this.#sqliteDriver = options.sqliteDriver
      this.#kernelHasSqlite = true
    }

    this.#kernel = new TopicKernel({
      genesis: this.genesisBytes,
      cas: this.cas,
      blindHostMode: this.#blindHostMode,
      ...this.#sandboxOptions,
    })
    if (this.genesis.privateLog && !this.#blindHostMode) {
      this.#controlKernel = new TopicKernel({
        genesis: this.genesisBytes,
        cas: this.cas,
        blindHostMode: true,
        ...this.#sandboxOptions,
      })
    }
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
    const initialSeq = (await options.store.latestChangeSeq?.()) ?? 0

    // Single-pass store scan: index CAS entries + locate genesis + collect log entries in ONE read!
    const allEntries = await readAllStoreEntries(options.store)
    let discoveredGenesis: Uint8Array | null = null
    const nonCasEntries: BytesStoreEntry[] = []
    for (const entry of allEntries) {
      if (cas.indexPersistedEntry(entry, { verifyHash: false })) continue
      nonCasEntries.push(entry)
      if (discoveredGenesis === null && entry.key.startsWith('v2/') && entry.key.endsWith('/genesis')) {
        discoveredGenesis = entry.value
      }
    }

    if (options.casNodes !== undefined && options.casNodes.length > 0) {
      await cas.putManyVerified(options.casNodes)
    }
    // The audited standard modules are part of every replica; peers never ship them (sync v3).
    const missingStandard = Object.values(STANDARD_MODULE_SOURCES)
      .map(src => utf8(src))
      .filter(bytes => !cas.hasSync(computeCasHash(bytes, []), 'public'))
    for (const bytes of missingStandard) await cas.put(bytes, [], 'public')

    let genesisBytes: Uint8Array | null
    if (options.genesis !== undefined) {
      genesisBytes = options.genesis instanceof Uint8Array
        ? options.genesis.slice()
        : encodeLogGenesis(options.genesis)
      const logId = bytesToHex(genesisLogId(genesisBytes))
      if (options.logId !== undefined && options.logId !== logId) {
        throw new Error('SESSION_CHAIN_ID_MISMATCH')
      }
      const existingEntry = nonCasEntries.find(e => e.key === `v2/${logId}/genesis`)
      const existing = existingEntry?.value ?? null
      if (existing !== null && !sameBytes(existing, genesisBytes)) {
        throw new Error('SESSION_GENESIS_MISMATCH')
      }
      if (existing === null) await options.store.put(`v2/${logId}/genesis`, genesisBytes, { durability: 'strict' })
    } else if (options.logId !== undefined) {
      const found = nonCasEntries.find(e => e.key === `v2/${options.logId}/genesis`)
      genesisBytes = found?.value ?? null
    } else {
      genesisBytes = discoveredGenesis
    }
    if (genesisBytes === null) throw new Error('SESSION_GENESIS_NOT_FOUND')

    const session = new ApplicationSession<D>(options, genesisBytes, cas)
    session.#lastSyncSeq = initialSeq
    if (options.epochKeys !== undefined) {
      for (const [epoch, key] of options.epochKeys) {
        await session.installEpochKey(epoch, key)
      }
    }
    await session.#hydrateFromEntries(nonCasEntries)
    session.#pendingDelta = [] // facts loaded from local storage are not news to any peer
    await session.#rematerialize()
    return session
  }

  get signal(): AbortSignal { return this.#lifetime.signal }

  #computeKeyState(): SessionKeyState {
    if (!this.genesis.privateLog || this.#blindHostMode) return 'public'
    const epoch = this.currentEpoch()
    if (epoch < 0) return 'ready'
    if (this.#epochKeys.has(epoch)) return 'ready'
    const hasBox = this.keysState().epochs?.[String(epoch)]?.boxes?.[this.identity.publicKey] !== undefined
    return hasBox ? 'pending-unseal' : 'missing-lockbox'
  }

  get status(): SessionStatus {
    const pendingOps = this.#countPendingOps()
    const keyState = this.#computeKeyState()
    const pk = this.identity.publicKey
    const isAdmin = this.isAdministrator(pk)
    const isPub = this.#evaluatedPermissions !== null
      ? this.#evaluatedPermissions.publishers.has(pk)
      : this.member(pk)?.publisher === true
    const canAuthorControl = !this.#closed && !this.#blindHostMode && (isAdmin || isPub)
    const canAuthorData = !this.#closed && !this.#blindHostMode && this.isWriter(pk) && (keyState === 'public' || keyState === 'ready')
    const canAuthor = canAuthorData || canAuthorControl
    const awaitingKeys = this.genesis.privateLog && !this.#blindHostMode && this.isReader(pk) && this.currentEpoch() >= 0 && !this.#epochKeys.has(this.currentEpoch())
    return Object.freeze({
      ...(this.#kernel.pendingDependencies.length > 0 ? { pendingDependencies: this.#kernel.pendingDependencies } : {}),
      canAuthor,
      canAuthorData,
      canAuthorControl,
      keyState,
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
      const p = this.#evaluatedPermissions
      return {
        mode: p.mode,
        members: p.members,
        readers: p.openReaders ? ['*'] : [...p.readers].sort(),
        writers: p.openWriters ? ['*'] : [...p.writers].sort(),
        administrators: [...p.administrators].sort(),
        publishers: [...p.publishers].sort(),
        openReaders: p.openReaders,
        openWriters: p.openWriters,
        blockedAuthors: [...p.blockedAuthors].sort(),
        admission: p.admission,
        multisig: p.multisig,
      }
    }
    const raw = this.#kernel.topic('$permissions') as PermissionsTopicState | null
    if (raw === null || typeof raw !== 'object' || !Array.isArray(raw.members)) {
      return { members: [], openReaders: false, openWriters: false, blockedAuthors: [], admission: null, multisig: null }
    }
    return raw
  }

  member(publicKey: string): MemberRecord | null {
    return this.permissions().members.find(m => m.publicKey === publicKey) ?? null
  }

  isBlockedAuthor(publicKey: string): boolean {
    return this.#evaluatedPermissions !== null && this.#evaluatedPermissions.blockedAuthors.has(publicKey)
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
    if (!this.genesis.privateLog) return true
    if (this.#evaluatedPermissions !== null) {
      if (this.#evaluatedPermissions.openReaders) return /^[0-9a-f]{64}$/u.test(publicKey)
      return this.#evaluatedPermissions.readers.has(publicKey)
    }
    return this.member(publicKey)?.reader === true
  }

  isWriter(publicKey: string): boolean {
    if (this.#evaluatedPermissions !== null) {
      if (this.#evaluatedPermissions.blockedAuthors.has(publicKey)) return false
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

  async installRingKey(ring: string, epoch: number, key: Uint8Array): Promise<void> {
    check(typeof ring === 'string' && ring.length > 0 && ring !== 'default', 'RING_NAME_INVALID')
    check(Number.isSafeInteger(epoch) && epoch >= 0 && key instanceof Uint8Array && key.length === 32, 'EPOCH_KEY_INVALID')
    let map = this.#ringKeys.get(ring)
    if (map === undefined) {
      map = new Map()
      this.#ringKeys.set(ring, map)
    }
    map.set(epoch, key.slice())
    await this.#store.put(`${this.#prefix}/ring-key/${ring}/${epoch}`, key.slice())
  }

  ringKey(ring: string, epoch: number): Uint8Array | null {
    if (ring === 'default') return this.epochKey(epoch)
    return this.#ringKeys.get(ring)?.get(epoch)?.slice() ?? null
  }

  /**
   * Heal any admitted reader missing HPKE lockboxes in `$keys` for epochs we hold
   * (e.g. concurrent admission + epoch rotation, multisig approvals, or late wrapKey addition).
   */
  async backfillMissingEpochBoxes(options: { readonly minEpoch?: number } = {}): Promise<number> {
    if (!this.genesis.privateLog || this.#blindHostMode) return 0
    await this.#flushPendingMaterialization()
    const keysState = this.keysState()
    if (keysState.currentEpoch < 0) return 0
    const minEp = Math.max(0, options.minEpoch ?? 0)
    const members = this.permissions().members
    let sealedMembers = 0
    for (const member of members) {
      if (!member.reader || !member.wrapKey) continue
      const epochBoxes: Record<string, EpochKeyBox> = {}
      for (let ep = minEp; ep <= keysState.currentEpoch; ep++) {
        const epKey = this.#epochKeys.get(ep)
        if (epKey === undefined) continue
        if (keysState.epochs?.[String(ep)]?.boxes?.[member.publicKey] !== undefined) continue
        epochBoxes[String(ep)] = await hpkeSealEpochKey(member.wrapKey, epKey, this.logId, ep)
      }
      if (Object.keys(epochBoxes).length === 0) continue
      await this.submit({
        visibility: 'public',
        awaitMaterialized: true,
        updates: [{
          topic: '$keys',
          input: {
            action: 'grantBoxes',
            member: member.publicKey,
            epochBoxes: epochBoxes as unknown as JsonValue,
          },
        }],
      })
      sealedMembers++
    }
    return sealedMembers
  }

  /** Incrementally pull facts written by a sibling tab/PWA into the shared multi-tab BytesStore. */
  async syncFromStore(): Promise<boolean> {
    if (this.#closed || this.#store.readChangesSince === undefined) return false
    return this.#serial(async () => {
      const { latestSeq, changes } = await this.#store.readChangesSince!(this.#lastSyncSeq)
      if (latestSeq <= this.#lastSyncSeq || changes.length === 0) {
        this.#lastSyncSeq = Math.max(this.#lastSyncSeq, latestSeq)
        return false
      }
      this.#lastSyncSeq = latestSeq
      const uniqueKeys = new Set<string>()
      const prefix = `${this.#prefix}/`
      for (const ch of changes) {
        if (ch.deleted) continue
        if (ch.key.startsWith('cas/') || (ch.key.startsWith(prefix) && ch.key !== `${prefix}materialized-cache`)) {
          uniqueKeys.add(ch.key)
        }
      }
      if (uniqueKeys.size === 0) return false
      let changed = false
      for (const key of uniqueKeys) {
        const val = await this.#store.get(key)
        if (val === null) continue
        if (this.cas.indexPersistedEntry({ key, value: val }, { verifyHash: false })) {
          changed = true
          continue
        }
        if (await this.#ingestSingleStoreEntry({ key, value: val })) {
          changed = true
        }
      }
      if (changed) {
        await this.#rematerialize()
        this.#emitFacts()
      }
      return changed
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

  #countPendingOps(): number {
    let count = this.#kernel.pendingDependencies.length + this.#undecryptedEnvelopes.size
    if (this.#materializeDirty) count++
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

  #writeLane<T>(work: () => Promise<T>): Promise<T> {
    const task = this.#writeTail.then(() => {
      if (this.#closed) throw new Error('SESSION_CLOSED')
      return work()
    })
    this.#writeTail = task.catch(() => undefined)
    return task
  }

  #scheduleMaterialize(): Promise<void> {
    this.#materializeDirty = true
    if (this.#materializePromise !== null) return this.#materializePromise
    this.#materializePromise = this.#serial(async () => {
      try {
        while (this.#materializeDirty && !this.#closed) {
          this.#materializeDirty = false
          await this.#rematerialize()
        }
      } finally {
        this.#materializePromise = null
        if (this.#materializeDirty && !this.#closed) {
          void this.#scheduleMaterialize().catch(() => undefined)
        }
      }
    })
    return this.#materializePromise
  }

  async #flushPendingMaterialization(): Promise<void> {
    if (this.#closed) return
    if (this.#materializePromise !== null) {
      await this.#materializePromise
    } else if (this.#materializeDirty) {
      await this.#scheduleMaterialize()
    }
  }

  #scheduleCachePersist(): void {
    if (this.#closed || this.#cachePersistTimer !== undefined) return
    this.#cachePersistTimer = setTimeout(() => {
      this.#cachePersistTimer = undefined
      void this.#persistMaterializedCacheNow().catch(() => undefined)
    }, 1_500)
    this.#cachePersistTimer.unref?.()
  }

  async #persistMaterializedCacheNow(): Promise<void> {
    if (this.#closed) return
    const rev = this.#lastLocalRevision.digest
    if (
      this.#kernel.pendingDependencies.length > 0 ||
      this.#kernel.outcomes.length === 0 ||
      rev === this.#lastPersistedCacheDigest
    ) {
      return
    }
    try {
      await this.#kernel.commitSeenOpsRoot()
      await this.#store.put(
        `${this.#prefix}/materialized-cache`,
        encodeRecord(this.#kernel.exportMaterializedCache()),
        { durability: 'relaxed' },
      )
      this.#lastPersistedCacheDigest = rev
    } catch { /* best-effort cache persistence */ }
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
    const delta: FactsDelta = { items: this.#pendingDelta }
    this.#pendingDelta = []
    for (const listener of this.#factListeners) {
      try { listener(delta) } catch { /* isolate observer */ }
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

  onFacts(listener: (delta: FactsDelta) => void): () => void {
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

  async #ensureSqliteIfNeeded(reducersOverride?: JsonValue | null): Promise<boolean> {
    if (this.#sqliteDriver !== undefined) return !this.#kernelHasSqlite
    const memoKey = reducersOverride !== undefined ? JSON.stringify(reducersOverride) : `hash:${this.#kernel.topicHash('$reducers') ?? ''}`
    if (this.#sqliteScanNegative.has(memoKey)) return false
    const reducersRaw = reducersOverride !== undefined ? reducersOverride : this.#kernel.topic('$reducers')
    if (reducersRaw === null) return false
    let needsSqlite = false, incomplete = false
    try {
      const cfg = assertValidReducersConfig(reducersRaw)
      const queue: string[] = []
      const visited = new Set<string>()
      for (const [topicName, binding] of Object.entries(cfg.topics)) {
        if (this.#blindHostMode && this.genesis.privateLog && !isControlTopic(topicName)) continue
        queue.push(binding.module)
      }
      const importSpecRe = /\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/gu
      while (queue.length > 0) {
        const modSpec = queue.shift()!
        if (visited.has(modSpec)) continue
        visited.add(modSpec)
        if (modSpec === 'chronolog:sqlite' || modSpec === 'chronolog/sql' || modSpec === 'chronolog/sqlite-helpers') {
          needsSqlite = true
          break
        }
        const ref = cfg.imports[modSpec]
        if (ref === undefined || !ref.startsWith('cas:sha256-')) continue
        const hash = ref.slice(11)
        const node = await this.cas.get(hash, 'any')
        if (node === null) { incomplete = true; continue }
        const text = new TextDecoder().decode(node.bytes)
        if (text.includes('chronolog:sqlite') || text.includes('chronolog/sql') || text.includes('chronolog/sqlite-helpers')) {
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
    } catch { return false }
    if (!needsSqlite) {
      if (!incomplete) {
        if (this.#sqliteScanNegative.size > 64) this.#sqliteScanNegative.clear()
        this.#sqliteScanNegative.add(memoKey)
      }
      return false
    }

    this.#sqliteLoadPromise ??= (async () => {
      const wasmModule = this.#sqliteWasmModule ?? (this.#sqliteWasmLoader !== undefined ? await this.#sqliteWasmLoader() : undefined)
      const mod = await import('chronolog-db')
      const driver = await mod.createSqliteCasDriver({
        ...(wasmModule === undefined ? {} : { wasmModule }),
      })
      this.#sqliteDriver = driver
      return driver
    })()
    await this.#sqliteLoadPromise
    return !this.#kernelHasSqlite
  }

  async #refreshPermissionsCache(kernel: TopicKernel = this.#kernel): Promise<void> {
    const rawPerms = kernel.topic('$permissions')
    const rawJson = JSON.stringify(rawPerms)
    if (this.#evaluatedPermissions !== null && rawJson === this.#lastPermsStateJson) {
      return
    }
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
      const summary = await kernel.query('$permissions', { summary: true })
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
        const blocked = parseStringList(s.blockedAuthors)
        const admission = (s.admission !== null && typeof s.admission === 'object' && !Array.isArray(s.admission))
          ? s.admission as { readonly hostKey?: string }
          : null
        const msRaw = s.multisig
        const multisig: PermissionsMultisigInfo | null =
          msRaw !== null && typeof msRaw === 'object' && !Array.isArray(msRaw) &&
          typeof (msRaw as { threshold?: unknown }).threshold === 'number' &&
          Array.isArray((msRaw as { signers?: unknown }).signers)
            ? {
                threshold: (msRaw as { threshold: number }).threshold,
                signers: (msRaw as { signers: string[] }).signers.filter(k => typeof k === 'string'),
                proposals: ((msRaw as { proposals?: Record<string, JsonValue> }).proposals ?? {}),
              }
            : null
        const openReaders = s.openReaders === true || readers.open
        const openWriters = s.openWriters === true || writers.open
        const mode: EvaluatedPermissionsSummary['mode'] =
          s.mode === 'attested' || s.mode === 'open' || s.mode === 'multisig'
            ? s.mode
            : multisig !== null ? 'multisig' : (openReaders || openWriters) ? 'open' : admission !== null ? 'attested' : 'custom'
        this.#evaluatedPermissions = {
          mode,
          members: parseMembers(s.members),
          readers: readers.keys,
          writers: writers.keys,
          administrators: admins.keys,
          publishers: pubs.keys,
          openReaders,
          openWriters,
          blockedAuthors: blocked.keys,
          admission,
          multisig,
        }
        return
      }

      const [rRaw, wRaw, aRaw, pRaw, mRaw, admRaw, blkRaw] = await Promise.all([
        kernel.query('$permissions', { list: 'readers' }).catch(() => null),
        kernel.query('$permissions', { list: 'writers' }).catch(() => null),
        kernel.query('$permissions', { list: 'administrators' }).catch(() => null),
        kernel.query('$permissions', { list: 'publishers' }).catch(() => null),
        kernel.query('$permissions', { list: 'members' }).catch(() => null),
        kernel.query('$permissions', { admission: true }).catch(() => null),
        kernel.query('$permissions', { list: 'blockedAuthors' }).catch(() => null),
      ])
      if (Array.isArray(rRaw) || Array.isArray(wRaw) || Array.isArray(aRaw)) {
        const readers = parseStringList(rRaw)
        const writers = parseStringList(wRaw)
        const admins = parseStringList(aRaw)
        const pubs = parseStringList(pRaw)
        const blocked = parseStringList(blkRaw)
        const admission = (admRaw !== null && typeof admRaw === 'object' && !Array.isArray(admRaw))
          ? admRaw as { readonly hostKey?: string }
          : null
        this.#evaluatedPermissions = {
          mode: (readers.open || writers.open) ? 'open' : admission !== null ? 'attested' : 'custom',
          members: parseMembers(mRaw),
          readers: readers.keys,
          writers: writers.keys,
          administrators: admins.keys,
          publishers: pubs.keys,
          openReaders: readers.open,
          openWriters: writers.open,
          blockedAuthors: blocked.keys,
          admission,
          multisig: null,
        }
        return
      }
    } catch {
      // Fall through to legacy raw topic inspection
    }

    const raw = kernel.topic('$permissions') as PermissionsTopicState | null
    if (raw !== null && typeof raw === 'object' && Array.isArray(raw.members)) {
      const members = parseMembers(raw.members)
      this.#evaluatedPermissions = {
        mode: raw.admission ? 'attested' : 'custom',
        members,
        readers: new Set(members.filter(m => m.reader).map(m => m.publicKey)),
        writers: new Set(members.filter(m => m.writer || m.administrator).map(m => m.publicKey)),
        administrators: new Set(members.filter(m => m.administrator).map(m => m.publicKey)),
        publishers: new Set(members.filter(m => m.publisher || m.administrator).map(m => m.publicKey)),
        openReaders: false,
        openWriters: false,
        blockedAuthors: new Set(),
        admission: raw.admission ?? null,
        multisig: null,
      }
    } else {
      this.#evaluatedPermissions = null
    }
    this.#lastPermsStateJson = JSON.stringify(kernel.topic('$permissions'))
  }

  async #ingestSingleStoreEntry(entry: BytesStoreEntry): Promise<boolean> {
    const prefix = `${this.#prefix}/`
    if (!entry.key.startsWith(prefix)) return false
    const rest = entry.key.slice(prefix.length)
    if (rest.startsWith('epoch-key/')) {
      const ep = Number(rest.slice('epoch-key/'.length))
      if (Number.isSafeInteger(ep) && ep >= 0 && entry.value.length === 32 && !this.#epochKeys.has(ep)) {
        this.#epochKeys.set(ep, entry.value.slice())
        return true
      }
    } else if (rest.startsWith('ring-key/')) {
      const parts = rest.slice('ring-key/'.length).split('/')
      const ring = parts[0]
      const ep = Number(parts[1])
      if (ring && ring !== 'default' && Number.isSafeInteger(ep) && ep >= 0 && entry.value.length === 32) {
        let map = this.#ringKeys.get(ring)
        if (map === undefined) { map = new Map(); this.#ringKeys.set(ring, map) }
        if (!map.has(ep)) { map.set(ep, entry.value.slice()); return true }
      }
    } else if (rest.startsWith('public-op/')) {
      const keyOpId = rest.slice('public-op/'.length)
      if (this.#publicOps.has(keyOpId)) return false
      try {
        // Local BytesStore records are already envelope-SHA256 authenticated and Ed25519-verified at ingress.
        const signed = decodeSignedOperation(entry.value)
        const core = decodeOperationCore(signed.coreBytes)
        const opId = bytesToHex(operationIdDigest(signed.coreBytes))
        if (bytesToHex(core.logId) === this.logId && core.visibility === 'public' && !this.#publicOps.has(opId)) {
          this.#publicOps.set(opId, { raw: entry.value.slice(), signed, core })
          return true
        }
      } catch { /* ignore corrupt entry */ }
    } else if (rest.startsWith('enc-env/')) {
      const keyDigest = rest.slice('enc-env/'.length)
      if (this.#encryptedEnvelopes.has(keyDigest)) return false
      try {
        const envelope = decodeEncryptedEnvelope(entry.value)
        if (bytesToHex(envelope.logId) === this.logId) {
          const digest = bytesToHex(encryptedEnvelopeDigest(entry.value))
          if (!this.#encryptedEnvelopes.has(digest)) {
            this.#encryptedEnvelopes.set(digest, { digest, raw: entry.value.slice(), envelope })
            this.#undecryptedEnvelopes.add(digest)
            return true
          }
        }
      } catch { /* ignore corrupt entry */ }
    } else if (rest.startsWith('local-pending/')) {
      try {
        const rec = decodeRecord<{ readonly raw: Uint8Array; readonly envelopeDigest: string; readonly epoch: number }>(entry.value)
        const signed = decodeSignedOperation(rec.raw)
        const core = decodeOperationCore(signed.coreBytes)
        const opId = bytesToHex(operationIdDigest(signed.coreBytes))
        if (!this.#localPending.has(opId)) {
          this.#localPending.set(opId, {
            raw: rec.raw.slice(),
            signed,
            core,
            currentEnvelopeDigest: rec.envelopeDigest,
            currentEpoch: rec.epoch,
          })
          return true
        }
      } catch { /* ignore */ }
    } else if (rest.startsWith('retention/')) {
      try {
        const ev = decodeRecord<RetentionEvidence>(entry.value)
        if (Array.isArray(ev.payload.items) && this.#indexRetention(ev)) return true
      } catch { /* ignore */ }
    } else if (rest.startsWith('checkpoint/')) {
      const key = rest.slice('checkpoint/'.length)
      if (this.#checkpoints.has(key)) return false
      try {
        const cp = decodeRecord<FinalityCheckpoint>(entry.value)
        const computedKey = await recordDigest(cp.payload)
        if (!this.#checkpoints.has(computedKey)) {
          this.#checkpoints.set(computedKey, cp)
          return true
        }
      } catch { /* ignore */ }
    } else if (rest === 'materialized-cache') {
      try {
        const cached = decodeRecord<KernelMaterializedCache>(entry.value)
        if (cached.v === 1 && cached.logId === this.logId && cached.blindHostMode === this.#blindHostMode) {
          this.#pendingMaterializedCache = cached
        }
      } catch { /* ignore corrupt cache */ }
    }
    return false
  }

  async #hydrateFromEntries(entries: readonly BytesStoreEntry[]): Promise<void> {
    for (const entry of entries) {
      await this.#ingestSingleStoreEntry(entry)
    }
  }

  async #decodeMaterializedSnapshot(bytes: Uint8Array): Promise<{
    readonly cache: KernelMaterializedCache
    readonly casNodes: readonly SessionCasNode[]
    readonly maxAuthorTimestampMs: bigint
  } | null> {
    try {
      const env = decodeRecord<{
        readonly v?: unknown
        readonly private?: unknown
        readonly logId?: unknown
        readonly epoch?: unknown
        readonly nonce?: unknown
        readonly ciphertext?: unknown
        readonly cache?: unknown
        readonly bundle?: unknown
      }>(bytes)
      if ((env.v !== 1 && env.v !== 2) || env.logId !== this.logId) return null
      let plainBytes: Uint8Array | null = null
      if (env.private === true) {
        if (!this.genesis.privateLog || this.#blindHostMode) return null
        if (typeof env.epoch !== 'number' || !Number.isSafeInteger(env.epoch) || env.epoch < 0) return null
        if (!(env.nonce instanceof Uint8Array) || !(env.ciphertext instanceof Uint8Array)) return null
        const epochKey = this.#epochKeys.get(env.epoch)
        if (epochKey === undefined) return null
        const aad = utf8(`chronolog-v${String(env.v)}-snapshot:${this.logId}:${env.epoch}`)
        plainBytes = await decryptEpochPayload(epochKey, {
          epoch: BigInt(env.epoch),
          nonce: env.nonce,
          ciphertext: env.ciphertext,
        }, aad)
      }
      if (env.v === 1) {
        const cached = plainBytes !== null
          ? decodeRecord<KernelMaterializedCache>(plainBytes)
          : (env.cache as KernelMaterializedCache | undefined)
        if (!cached || cached.v !== 1 || cached.logId !== this.logId || cached.blindHostMode !== this.#blindHostMode) return null
        return { cache: cached, casNodes: [], maxAuthorTimestampMs: 0n }
      }
      // v2 self-contained member-signed Snapshot Bundle (includes reachable private SQLite-CAS & seenOps nodes)
      const signedBundle = plainBytes !== null
        ? decodeRecord<{
            readonly payload: {
              readonly logId: string
              readonly cache: KernelMaterializedCache
              readonly casNodes: readonly SessionCasNode[]
              readonly maxAuthorTimestampMs: string
            }
            readonly signer: string
            readonly signature: string
          }>(plainBytes)
        : (env.bundle as {
            readonly payload: {
              readonly logId: string
              readonly cache: KernelMaterializedCache
              readonly casNodes: readonly SessionCasNode[]
              readonly maxAuthorTimestampMs: string
            }
            readonly signer: string
            readonly signature: string
          } | undefined)
      if (!signedBundle || typeof signedBundle !== 'object') return null
      await verifyRecord('materialized-snapshot-v2', signedBundle, signedBundle.signer)
      const payload = signedBundle.payload
      if (!payload || payload.logId !== this.logId) return null
      const cached = payload.cache
      if (!cached || cached.v !== 1 || cached.logId !== this.logId || cached.blindHostMode !== this.#blindHostMode) return null
      // Reject snapshots signed by revoked members when $permissions is already known.
      if (this.#evaluatedPermissions !== null && !this.isMember(signedBundle.signer)) return null
      const casNodes = Array.isArray(payload.casNodes) ? payload.casNodes : []
      const maxTs = typeof payload.maxAuthorTimestampMs === 'string' ? BigInt(payload.maxAuthorTimestampMs) : 0n
      return { cache: cached, casNodes, maxAuthorTimestampMs: maxTs }
    } catch {
      return null
    }
  }

  #keysStateFrom(kernel: TopicKernel): KeysTopicState {
    const raw = kernel.topic('$keys') as KeysTopicState | null
    if (raw === null || typeof raw !== 'object') return { currentEpoch: -1, epochs: {} }
    return raw
  }

  #currentEpochFrom(kernel: TopicKernel): number {
    const state = this.#keysStateFrom(kernel)
    if (state.currentEpoch >= 0) return state.currentEpoch
    if (this.#epochKeys.size > 0) return Math.max(...this.#epochKeys.keys())
    return -1
  }

  async #unsealAvailableEpochKeys(kernel: TopicKernel = this.#kernel): Promise<boolean> {
    if (!this.genesis.privateLog || this.#blindHostMode) return false
    const keys = this.#keysStateFrom(kernel)
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
          this.logId,
          entry.epoch,
        )
        if (epochKeyCommitmentV2(plainKey) !== entry.keyCommitment) continue
        await this.installEpochKey(entry.epoch, plainKey)
        unlockedAny = true
      } catch {
        // Wrong wrap key or corrupted lockbox — ignore
      }
    }
    for (const [ringName, ringState] of Object.entries(keys.rings ?? {})) {
      const existingMap = this.#ringKeys.get(ringName)
      for (const entry of Object.values(ringState.epochs ?? {})) {
        if (existingMap?.has(entry.epoch)) continue
        const box = entry.boxes?.[this.identity.publicKey]
        if (box === undefined) continue
        try {
          const plainKey = await hpkeOpenEpochKey(
            this.device.wrapKey.privateKey,
            this.device.wrapKey.publicKey,
            box,
            `${this.logId}:${ringName}`,
            entry.epoch,
          )
          if (epochKeyCommitmentV2(plainKey) !== entry.keyCommitment) continue
          await this.installRingKey(ringName, entry.epoch, plainKey)
          unlockedAny = true
        } catch {
          // Not a member of this compartment ring — ignore
        }
      }
    }
    return unlockedAny
  }

  async #decryptPendingEnvelopes(): Promise<void> {
    if (!this.genesis.privateLog || this.#blindHostMode || this.#undecryptedEnvelopes.size === 0) return
    const work: Promise<void>[] = []
    for (const digest of [...this.#undecryptedEnvelopes]) {
      const entry = this.#encryptedEnvelopes.get(digest)
      if (entry === undefined || entry.decrypted !== undefined) {
        this.#undecryptedEnvelopes.delete(digest)
        continue
      }
      const ring = entry.envelope.ring ?? 'default'
      const epochKey = ring === 'default'
        ? this.#epochKeys.get(entry.envelope.epoch)
        : this.#ringKeys.get(ring)?.get(entry.envelope.epoch)
      if (epochKey === undefined) continue
      // Decrypt + verify concurrently (WebCrypto runs these off the JS thread where available).
      work.push((async () => {
        try {
          const aad = envelopeAad(entry.envelope.logId, entry.envelope.opId, entry.envelope.author)
          const plaintext = await decryptEpochPayload(epochKey, {
            epoch: BigInt(entry.envelope.epoch),
            nonce: entry.envelope.nonce,
            ciphertext: entry.envelope.ciphertext,
          }, aad)
          const signed = decodeSignedOperation(plaintext)
          const verified = await verifySignedOperation(signed)
          if (bytesToHex(verified.core.logId) !== this.logId) return
          if (verified.core.visibility !== 'encrypted') return
          if (!sameBytes(verified.opId, entry.envelope.opId) || !sameBytes(verified.core.author, entry.envelope.author)) return
          entry.decrypted = { opId: bytesToHex(verified.opId), signed, core: verified.core }
          this.#undecryptedEnvelopes.delete(digest)
        } catch {
          // Cannot decrypt / forged ciphertext — stays undecryptable
        }
      })())
      if (work.length >= 64) await Promise.all(work.splice(0))
    }
    await Promise.all(work)
  }


  /**
   * Reconnect rewrapping: if this device authored offline encrypted ops under an older epoch
   * and $keys has since rotated to a newer epoch that we hold (and we are still a writer),
   * re-encrypt the EXACT original SignedOperation bytes under the newest epoch so peers can
   * decrypt them without changing opId, authorTimestampMs, or signature!
   */
  async #rewrapPendingLocalOps(kernel: TopicKernel = this.#kernel): Promise<boolean> {
    if (!this.genesis.privateLog || this.#blindHostMode) return false
    const newestEpoch = this.#currentEpochFrom(kernel)
    if (newestEpoch < 0) return false
    const newestKey = this.#epochKeys.get(newestEpoch)
    if (newestKey === undefined || !this.isWriter(this.identity.publicKey)) return false

    let rewrapped = false
    for (const [opId, pending] of this.#localPending) {
      if (pending.currentEpoch >= newestEpoch) continue
      const logIdBytes = hexToBytes(this.logId)
      const opIdBytes = hexToBytes(opId)
      const aad = envelopeAad(logIdBytes, opIdBytes, pending.core.author)
      const enc = await encryptEpochPayload(newestKey, BigInt(newestEpoch), pending.raw, aad)
      const env: EncryptedOperationEnvelope = {
        version: 1,
        logId: logIdBytes,
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

  /** Stable kernel input objects per op (lets the kernel memoize id/validation work by identity). */
  readonly #kernelInputs = new Map<string, KernelOperationInput>()
  /** $reducers configurations already scanned and found not to need SQLite. */
  readonly #sqliteScanNegative = new Set<string>()
  /** operationId -> opId for ops authored by this identity (O(1) inspect by caller-chosen id). */
  readonly #ownOperationIds = new Map<string, string>()
  #kernelInput(opId: string, core: OperationCore): KernelOperationInput {
    let input = this.#kernelInputs.get(opId)
    if (input === undefined || input.core !== core) {
      input = { opId: hexToBytes(opId), core, verified: true }
      this.#kernelInputs.set(opId, input)
      if (bytesToHex(core.author) === this.identity.publicKey) this.#ownOperationIds.set(core.operationId, opId)
    }
    return input
  }

  #collectDecryptedKernelInputs(): Map<string, KernelOperationInput> {
    const byOpId = new Map<string, KernelOperationInput>()
    for (const [opId, entry] of this.#publicOps) {
      byOpId.set(opId, this.#kernelInput(opId, entry.core))
    }
    if (!this.#blindHostMode) {
      for (const entry of this.#encryptedEnvelopes.values()) {
        if (entry.decrypted === undefined) continue
        if (!byOpId.has(entry.decrypted.opId)) {
          byOpId.set(entry.decrypted.opId, this.#kernelInput(entry.decrypted.opId, entry.decrypted.core))
        }
      }
    }
    return byOpId
  }

  async #rematerialize(): Promise<void> {
    return perfTimeAsync('session.rematerialize', () => this.#rematerialize__impl())
  }

  async #rematerialize__impl(): Promise<void> {
    const prevDigest = this.#lastLocalRevision.digest
    const prevFinalDigest = this.#lastFinalRevision?.digest ?? null
    const prevKernel = this.#kernel
    const prevOutcomeList = this.#kernel.materializedOutcomes
    const prevRestores = this.#kernel.cacheRestores

    try {
      const publicInputs: KernelOperationInput[] = []
      for (const [opId, entry] of this.#publicOps) {
        publicInputs.push(this.#kernelInput(opId, entry.core))
      }

      let controlKernel: TopicKernel
      let rewrapped = false
      let allByOpId: Map<string, KernelOperationInput>

      if (this.#controlKernel !== null) {
        // Private log full replica: run the public control pass on the isolated #controlKernel
        // so this.#kernel never loses private ops or suffix snapshots mid-rematerialization.
        controlKernel = this.#controlKernel
        await controlKernel.materialize(publicInputs)
        await this.#refreshPermissionsCache(controlKernel)
        await this.#unsealAvailableEpochKeys(controlKernel)
        await this.#decryptPendingEnvelopes()
        rewrapped = await this.#rewrapPendingLocalOps(controlKernel)
        allByOpId = this.#collectDecryptedKernelInputs()
      } else {
        // Public log or blind host: only public ops exist in the local kernel.
        // If finality checkpoints exist, probe $finality on an isolated kernel so this.#kernel
        // never transiently exposes excluded operations.
        allByOpId = this.#collectDecryptedKernelInputs()
        if (this.#checkpoints.size > 0) {
          await this.#ensureSqliteIfNeeded()
          controlKernel = new TopicKernel({
            genesis: this.genesisBytes,
            cas: this.cas,
            blindHostMode: this.#blindHostMode,
            ...this.#sandboxOptions,
            ...(this.#sqliteDriver === undefined ? {} : { sqliteDriver: this.#sqliteDriver }),
          })
          await controlKernel.materialize(publicInputs)
        } else {
          controlKernel = this.#kernel
        }
      }

      const schedule = parseFinalitySchedule(controlKernel.topic('$finality'))
      this.#verifiedFinality = await verifyFinalityV2({
        logId: this.logId,
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

      const needsKernelUpgrade = await this.#ensureSqliteIfNeeded(controlKernel.topic('$reducers'))
      if (needsKernelUpgrade && this.#sqliteDriver !== undefined) {
        this.#kernel.sandbox.dispose()
        const nextKernel = new TopicKernel({
          genesis: this.genesisBytes,
          cas: this.cas,
          blindHostMode: this.#blindHostMode,
          ...this.#sandboxOptions,
          sqliteDriver: this.#sqliteDriver,
        })
        this.#kernel = nextKernel
        this.#kernelHasSqlite = true
        this.#finalKernel?.sandbox.dispose()
        this.#finalKernel = null
      }

      // Attempt O(1) or suffix-only restore from local cache or host-cached encrypted Snapshot Bundle.
      if (this.#pendingEncryptedSnapshot !== null) {
        const decoded = await this.#decodeMaterializedSnapshot(this.#pendingEncryptedSnapshot)
        if (decoded !== null) {
          if (decoded.casNodes.length > 0) {
            await this.cas.putManyVerified(decoded.casNodes)
          }
          this.#pendingSnapshotBundle = decoded
          this.#pendingEncryptedSnapshot = null
        } else if (this.#epochKeys.size > 0 || !this.genesis.privateLog) {
          this.#pendingEncryptedSnapshot = null
        }
      }
      if (this.#pendingSnapshotBundle !== null) {
        const bundle = this.#pendingSnapshotBundle
        this.#pendingSnapshotBundle = null
        if (!this.#kernelHasSqlite && await this.#ensureSqliteIfNeeded(bundle.cache.topics.$reducers) && this.#sqliteDriver !== undefined) {
          this.#kernel.sandbox.dispose()
          this.#kernel = new TopicKernel({
            genesis: this.genesisBytes,
            cas: this.cas,
            blindHostMode: this.#blindHostMode,
            ...this.#sandboxOptions,
            sqliteDriver: this.#sqliteDriver,
          })
          this.#kernelHasSqlite = true
          this.#finalKernel?.sandbox.dispose()
          this.#finalKernel = null
        }
        // Try exact prefix restore first if all ops are local; otherwise bootstrap at the snapshot frontier!
        let restored = eligibleLocal.length >= bundle.cache.orderOpIds.length
          ? await this.#kernel.restoreMaterializedCache(bundle.cache, eligibleLocal)
          : false
        if (!restored && bundle.cache.orderOpIds.length > 0) {
          restored = await this.#kernel.restoreSnapshotFrontier({
            topics: bundle.cache.topics,
            seenOpsRoot: bundle.cache.seenOpsRoot,
            historyDigest: bundle.cache.historyDigest,
            stateRoot: bundle.cache.stateRoot,
            orderOpIds: bundle.cache.orderOpIds,
            maxAuthorTimestampMs: bundle.maxAuthorTimestampMs,
          })
        }
        if (restored) {
          this.#materializedCacheHits++
        }
      }
      if (this.#pendingMaterializedCache !== null && eligibleLocal.length > 0) {
        const cached = this.#pendingMaterializedCache
        this.#pendingMaterializedCache = null
        if (!this.#kernelHasSqlite && await this.#ensureSqliteIfNeeded(cached.topics.$reducers) && this.#sqliteDriver !== undefined) {
          this.#kernel.sandbox.dispose()
          this.#kernel = new TopicKernel({
            genesis: this.genesisBytes,
            cas: this.cas,
            blindHostMode: this.#blindHostMode,
            ...this.#sandboxOptions,
            sqliteDriver: this.#sqliteDriver,
          })
          this.#kernelHasSqlite = true
          this.#finalKernel?.sandbox.dispose()
          this.#finalKernel = null
        }
        const restored = await this.#kernel.restoreMaterializedCache(cached, eligibleLocal)
        if (restored) {
          this.#materializedCacheHits++
        }
      }

      let localResult = await this.#kernel.materialize(eligibleLocal)
      if (!this.#kernelHasSqlite && await this.#ensureSqliteIfNeeded(this.#kernel.topic('$reducers')) && this.#sqliteDriver !== undefined) {
        const nextKernel = new TopicKernel({
          genesis: this.genesisBytes,
          cas: this.cas,
          blindHostMode: this.#blindHostMode,
          ...this.#sandboxOptions,
          sqliteDriver: this.#sqliteDriver,
        })
        localResult = await nextKernel.materialize(eligibleLocal)
        this.#kernel.sandbox.dispose()
        this.#kernel = nextKernel
        this.#kernelHasSqlite = true
        this.#finalKernel?.sandbox.dispose()
        this.#finalKernel = null
      }
      await this.#refreshPermissionsCache(this.#kernel)
      this.#lastLocalRevision = toMaterializedRevision(localResult.revision)

      // Debounce local materialized cache persistence (off the critical write path; flushed on close).
      if (
        localResult.pendingDependencies.length === 0 &&
        (eligibleLocal.length > 0 || this.#kernel.frontierOrderLength > 0) &&
        localResult.revision.digest !== this.#lastPersistedCacheDigest
      ) {
        this.#scheduleCachePersist()
      }

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
      const changedTopicsSet = new Set<string>()
      const changedTablesSet = new Set<string>()
      let hasHistoryRevision = false
      let allNewSqlWithTables = true
      let sawNewSql = false
      // Only the replayed suffix can differ; earlier outcomes are the same objects as before.
      const replayedFrom = this.#kernel === prevKernel && this.#kernel.cacheRestores === prevRestores ? (localResult.replayedFrom ?? 0) : 0
      const prevOutcomes = new Map<string, string>()
      for (let i = replayedFrom; i < prevOutcomeList.length; i++) {
        const o = prevOutcomeList[i]!
        prevOutcomes.set(o.opId, `${o.outcome}:${o.rejectionCode ?? ''}`)
      }
      for (let i = replayedFrom; i < localResult.outcomes.length; i++) {
        const o = localResult.outcomes[i]!
        const key = `${o.outcome}:${o.rejectionCode ?? ''}`
        const prevKey = prevOutcomes.get(o.opId)
        if (prevKey !== key) {
          revised.push(o.opId)
          if (prevKey !== undefined) {
            hasHistoryRevision = true
          } else if (o.outcome === 'accepted') {
            const input = allByOpId.get(o.opId)
            if (input !== undefined) {
              for (const u of input.core.updates) changedTopicsSet.add(u.topic)
            }
            let opHadTableEvent = false
            for (const ev of o.events) {
              if (ev.topic === 'sql.tables_changed' && ev.payload && typeof ev.payload === 'object' && !Array.isArray(ev.payload)) {
                const tbls = (ev.payload as { readonly tables?: unknown }).tables
                if (Array.isArray(tbls)) {
                  opHadTableEvent = true
                  sawNewSql = true
                  for (const t of tbls) {
                    if (typeof t === 'string') changedTablesSet.add(t)
                  }
                }
              }
            }
            if (!opHadTableEvent && o.events.some(ev => ev.topic === 'sql.migrated' || ev.topic === 'sql.rls_updated')) {
              allNewSqlWithTables = false
            }
          }
        }
      }
      const changedTopics = !hasHistoryRevision && changedTopicsSet.size > 0 ? [...changedTopicsSet].sort() : undefined
      const changedTables = !hasHistoryRevision && sawNewSql && allNewSqlWithTables && changedTablesSet.size > 0
        ? [...changedTablesSet].sort()
        : undefined
      if (this.#lastLocalRevision.digest !== prevDigest) {
        this.#emitChange({
          kind: localResult.pendingDependencies.length > 0 ? 'dependency' : 'materialized',
          revision: this.#lastLocalRevision,
          revisedProposalIds: revised,
          ...(changedTopics === undefined ? {} : { changedTopics }),
          ...(changedTables === undefined ? {} : { changedTables }),
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

  /** Author locally and durably before network delivery (fast local-append lane; materializes in background unless awaitMaterialized is true). */
  async submit(input: ApplicationSubmission): Promise<ApplicationOperation> {
    const op = await this.#writeLane(async () => {
      check(!this.#blindHostMode, 'SESSION_BLIND_HOST_CANNOT_AUTHOR')
      check(Array.isArray(input.updates) && input.updates.length > 0, 'OPERATION_UPDATES_REQUIRED')
      const updatesList: readonly TopicUpdate[] = input.updates
      const allControl = updatesList.every(u => isControlTopic(u.topic))
      const anyControl = updatesList.some(u => isControlTopic(u.topic))
      check(!anyControl || allControl, 'OPERATION_CROSS_PARTITION_FORBIDDEN')

      const visibility: OperationVisibility = input.visibility ?? (
        this.genesis.privateLog
          ? (allControl ? 'public' : 'encrypted')
          : 'public'
      )
      if (this.genesis.privateLog) {
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

      const combinedChecks: OperationAssumption[] = [
        ...(input.assumptions?.checks ?? []),
        ...(input.afterOps ?? []).map(opId => ({ kind: 'op_accepted' as const, opId })),
        ...(input.requiresRejected ?? []).map(opId => ({ kind: 'op_rejected' as const, opId })),
      ]
      const onFailed = input.assumptions?.onFailed ?? input.onAssumptionFailed
      const assumptions: OperationAssumptionsConfig | undefined = combinedChecks.length > 0
        ? normalizeAssumptionsConfig({
            checks: combinedChecks,
            ...(onFailed === undefined ? {} : { onFailed }),
          })
        : undefined

      let causalFloorMs = 0n
      if (assumptions !== undefined) {
        const referencedOpIds = new Set<string>()
        for (const chk of assumptions.checks) {
          if (chk.kind === 'op_accepted' || chk.kind === 'op_rejected') referencedOpIds.add(chk.opId)
          else if (chk.kind === 'topic_revision' && chk.lastOpId !== null) referencedOpIds.add(chk.lastOpId)
        }
        for (const refId of referencedOpIds) {
          const pub = this.#publicOps.get(refId)
          if (pub !== undefined && pub.core.authorTimestampMs + 1n > causalFloorMs) {
            causalFloorMs = pub.core.authorTimestampMs + 1n
          }
          for (const enc of this.#encryptedEnvelopes.values()) {
            const dec = enc.decrypted
            if (dec !== null && dec !== undefined && dec.opId === refId && dec.core.authorTimestampMs + 1n > causalFloorMs) {
              causalFloorMs = dec.core.authorTimestampMs + 1n
            }
          }
        }
      }

      const nowMs = BigInt(Date.now())
      const authorTimestampMs = input.authorTimestampMs ?? (nowMs >= causalFloorMs ? nowMs : causalFloorMs)
      const logIdBytes = hexToBytes(this.logId)
      const authorBytes = hexToBytes(this.identity.publicKey)
      const core: OperationCore = {
        version: 1,
        logId: logIdBytes,
        author: authorBytes,
        operationId,
        authorTimestampMs,
        nonce: crypto.getRandomValues(new Uint8Array(16)),
        visibility,
        updates: updatesList.map(u => ({ topic: u.topic, input: normalizeJsonValue(u.input) })),
        ...(assumptions === undefined ? {} : { assumptions }),
      }

      const signed = await signOperationCore(core, this.device.identity.privateKey)
      const opBytes = encodeSignedOperation(signed)
      const opIdBytes = operationIdDigest(signed.coreBytes)
      const opIdHex = bytesToHex(opIdBytes)

      if (visibility === 'public') {
        await this.#store.put(`${this.#prefix}/public-op/${opIdHex}`, opBytes, { durability: 'strict' })
        this.#publicOps.set(opIdHex, { raw: opBytes, signed, core })
      } else {
        const keysState = this.keysState()
        const ringNames = new Set(updatesList.map(u => keysState.topicRings?.[u.topic] ?? 'default'))
        check(ringNames.size === 1, 'OPERATION_CROSS_RING_FORBIDDEN')
        const ring = [...ringNames][0]!
        const epoch = ring === 'default'
          ? this.currentEpoch()
          : (keysState.rings?.[ring]?.currentEpoch ?? -1)
        check(epoch >= 0, 'EPOCH_KEY_REQUIRED')
        const epochKey = ring === 'default'
          ? this.#epochKeys.get(epoch)
          : this.#ringKeys.get(ring)?.get(epoch)
        check(epochKey !== undefined, 'EPOCH_KEY_MISSING')
        const aad = envelopeAad(logIdBytes, opIdBytes, authorBytes)
        const enc = await encryptEpochPayload(epochKey, BigInt(epoch), opBytes, aad)
        const env: EncryptedOperationEnvelope = {
          version: 1,
          logId: logIdBytes,
          opId: opIdBytes,
          author: authorBytes,
          epoch,
          nonce: enc.nonce,
          ciphertext: enc.ciphertext,
          ...(ring === 'default' ? {} : { ring }),
        }
        const envBytes = encodeEncryptedEnvelope(env)
        const envDigest = bytesToHex(encryptedEnvelopeDigest(envBytes))
        // Single atomic multi-key write instead of two sequential transactions!
        await writeBytesMany(this.#store, [
          { key: `${this.#prefix}/enc-env/${envDigest}`, value: envBytes },
          {
            key: `${this.#prefix}/local-pending/${opIdHex}`,
            value: encodeRecord({ raw: opBytes, envelopeDigest: envDigest, epoch }),
          },
        ], { durability: 'strict' })
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

      if (this.#store.latestChangeSeq !== undefined) {
        this.#lastSyncSeq = Math.max(this.#lastSyncSeq, await this.#store.latestChangeSeq())
      }
      this.#emitFacts()
      void this.#scheduleMaterialize().catch(() => undefined)
      return new ApplicationOperation(opIdHex, operationId, this)
    })
    if (input.awaitMaterialized === true) {
      await this.#flushPendingMaterialization()
    }
    return op
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
      const described = await this.#describeForValidation()
      const matchesDescribed = (cName: string): boolean =>
        cName === name || cName === `${topic}.${name}` || cName === `${topic}:${name}`
      if (described && described.commands.length > 0 && !described.commands.some(c => matchesDescribed(c.name))) {
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
    await this.#flushPendingMaterialization()
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
      const described = await this.#describeForValidation()
      const matchesDescribed = (qName: string): boolean =>
        qName === name || qName === `${topic}.${name}` || qName === `${topic}:${name}`
      if (described && described.queries.length > 0 && !described.queries.some(q => matchesDescribed(q.name))) {
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

  /**
   * Command/query name validation only needs the reducer surface, which changes with `$reducers`,
   * not with every application write; cache it per `$reducers` content hash.
   */
  async #describeForValidation(): Promise<ApplicationDescription | null> {
    const key = this.#kernel.topicHash('$reducers') ?? ''
    if (this.#validationDescription !== null && this.#validationDescription.key === key) return this.#validationDescription.value
    const value = await this.describe().catch(() => null)
    this.#validationDescription = { key, value }
    return value
  }

  /** Describe available commands and queries (from local definition or in-chain reducer describe() exports). */
  async describe(): Promise<ApplicationDescription> {
    await this.#flushPendingMaterialization()
    if (this.definition !== undefined) return describeApplication(this.definition)
    const stateRoot = this.#lastLocalRevision.stateRoot
    if (this.#cachedDescription !== null && this.#cachedDescription.stateRoot === stateRoot) {
      return structuredClone(this.#cachedDescription.value)
    }
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
    const description = validateApplicationDescription({
      id: `chain-${this.logId.slice(0, 16)}`,
      version: '2.0.0',
      commands,
      queries,
    })
    this.#cachedDescription = { stateRoot, value: structuredClone(description) }
    return description
  }

  #hasActiveFinalityPolicy(): boolean {
    const schedule = parseFinalitySchedule(this.#kernel.topic('$finality'))
    return schedule.some(entry => entry.policy.kind !== 'none')
  }

  opOutcome(opId: string): 'accepted' | 'rejected' | null {
    return this.#kernel.opOutcome(opId)
  }

  topicLastOpId(topic: string): string | null {
    return this.#kernel.topicLastOpId(topic)
  }

  /**
   * Plain-language finality lifecycle status for UI badges (Pending -> Confirmed -> Needs attention):
   * - 'equivocated': notary/witness equivocation detected (fraud proof available via equivocationProofs())
   * - 'finalized': op is included in a verified $finality checkpoint
   * - 'excluded': closed-time frontier passed op's timestamp without including it
   * - 'synced': op has retention evidence from at least one peer/host
   * - 'local': authored/stored locally, awaiting sync or finality
   */
  finalityStatus(opId: string): 'equivocated' | 'finalized' | 'excluded' | 'synced' | 'local' {
    if (this.#verifiedFinality.equivocationProofs.length > 0) return 'equivocated'
    if (this.#verifiedFinality.includedOpIds.has(opId)) return 'finalized'
    if (this.#verifiedFinality.excludedOpIds.has(opId)) return 'excluded'
    const ret = this.#retentions.get(opId)
    if (ret !== undefined && ret.size > 0) return 'synced'
    return 'local'
  }

  equivocationProofs() {
    return this.#verifiedFinality.equivocationProofs
  }

  /**
   * Time-travel query: run any topic query against a historical opId or timestamp
   * without mutating live session state.
   */
  async queryAsOf(
    topic: string,
    input: JsonValue = null,
    target: { readonly opId: string } | { readonly atTimestampMs: bigint },
  ): Promise<{
    readonly applicationId: string
    readonly revision: MaterializedRevision
    readonly targetOpId: string | null
    readonly value: JsonValue
  }> {
    await this.#flushPendingMaterialization()
    const res = await this.#kernel.queryAt(topic, input, target)
    return {
      applicationId: this.applicationId,
      revision: toMaterializedRevision(res.revision),
      targetOpId: res.targetOpId,
      value: res.value,
    }
  }

  /**
   * Open a zero-copy O(1) SQLite branch over the current dbRoot of a chronolog/sql topic.
   * Run speculative queries/mutations, compute exact row-level diffs, and optionally export a guarded proposal.
   */
  async forkSql(topic: string): Promise<SqlBranch> {
    await this.#flushPendingMaterialization()
    const topicState = this.#kernel.topic(topic) as { readonly dbRoot?: unknown } | null
    const baseRoot = topicState !== null && typeof topicState === 'object' && typeof topicState.dbRoot === 'string'
      ? topicState.dbRoot
      : null
    let driver = this.#sqliteDriver
    if (driver === undefined) {
      const { createSqliteCasDriver } = await import('chronolog-db')
      driver = await createSqliteCasDriver()
      this.#sqliteDriver = driver
    }
    const partition: CasPartition = (this.genesis.privateLog && isControlTopic(topic)) ? 'public' : 'private'
    return openSqlBranch({
      topic,
      baseRoot,
      cas: this.cas,
      partition,
      driver,
      actor: this.identity.publicKey,
    })
  }

  /** Capture a coherent read snapshot for reactive views, queries, and event pagination. */
  async readView(options: { readonly view?: 'local' | 'final' } = {}): Promise<ApplicationReadView> {
    await this.#flushPendingMaterialization()
    const viewKind = options.view ?? 'local'
    if (viewKind === 'final' && !this.#hasActiveFinalityPolicy()) {
      throw Object.assign(new Error('FINALITY_UNSUPPORTED'), { code: 'FINALITY_UNSUPPORTED' })
    }
    const kernel = viewKind === 'final' ? this.#finalKernel : this.#kernel
    const revision = kernel === null ? this.revision(viewKind) : toMaterializedRevision(kernel.revision(viewKind))
    const topicsSnap = kernel === null ? {} : kernel.topics
    const outcomesSnap = kernel === null ? [] : kernel.outcomes
    const opOutcomeSnap = new Map<string, 'accepted' | 'rejected'>()
    for (const o of outcomesSnap) opOutcomeSnap.set(o.opId, o.outcome)
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
      opOutcome(opId: string): 'accepted' | 'rejected' | null {
        checkLive()
        return opOutcomeSnap.get(opId) ?? null
      },
      topicLastOpId(topic: string): string | null {
        checkLive()
        return kernel === null ? null : kernel.topicLastOpId(topic)
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
    const revision = kernel === null ? this.revision(viewKind) : toMaterializedRevision(kernel.revision(viewKind))
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
    readonly label?: string
    readonly subject?: string
    readonly scopes?: readonly string[]
    readonly expiresAtMs?: number
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
      ...(options.label ? { label: options.label } : {}),
      ...(options.subject ? { subject: options.subject } : {}),
      ...(options.scopes && options.scopes.length > 0 ? { scopes: [...options.scopes] } : {}),
      ...(options.expiresAtMs !== undefined ? { expiresAtMs: options.expiresAtMs } : {}),
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

    if (this.genesis.privateLog && (options.reader ?? true) && options.wrapKey) {
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
          boxes[pk] = await hpkeSealEpochKey(wk, epoch0, this.logId, 0)
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
          epochBoxes[String(ep)] = await hpkeSealEpochKey(options.wrapKey, epKey, this.logId, ep)
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
      awaitMaterialized: true,
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
    check(this.genesis.privateLog, 'EPOCH_ROTATION_PRIVATE_LOG_ONLY')
    await this.#flushPendingMaterialization()
    const keysState = this.keysState()
    const nextEpoch = keysState.currentEpoch + 1
    const key = options.newEpochKey ?? crypto.getRandomValues(new Uint8Array(32))
    await this.installEpochKey(nextEpoch, key)

    const exclude = new Set(options.excludeMembers ?? [])
    const boxes: Record<string, EpochKeyBox> = {}
    for (const m of this.permissions().members) {
      if (!m.reader || !m.wrapKey || exclude.has(m.publicKey)) continue
      boxes[m.publicKey] = await hpkeSealEpochKey(m.wrapKey, key, this.logId, nextEpoch)
    }

    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
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

  /**
   * Create or rotate a named compartment key ring in $keys (e.g. 'admins' or 'personal:<pk>'),
   * sealing its epoch key strictly to the chosen members and binding the specified topics to it.
   */
  async createCompartment(
    ringName: string,
    options: {
      readonly topics: readonly string[]
      readonly members: readonly { readonly publicKey: string; readonly wrapKey: string }[]
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    },
  ): Promise<{ readonly ring: string; readonly epoch: number; readonly operation: ApplicationOperation }> {
    check(this.genesis.privateLog, 'COMPARTMENT_PRIVATE_LOG_ONLY')
    check(typeof ringName === 'string' && ringName.length > 0 && ringName !== 'default', 'RING_NAME_INVALID')
    await this.#flushPendingMaterialization()
    const keysState = this.keysState()
    const prevRing = keysState.rings?.[ringName]
    const nextEpoch = (prevRing?.currentEpoch ?? -1) + 1
    const key = crypto.getRandomValues(new Uint8Array(32))
    await this.installRingKey(ringName, nextEpoch, key)

    const boxes: Record<string, EpochKeyBox> = {}
    for (const m of options.members) {
      boxes[m.publicKey] = await hpkeSealEpochKey(m.wrapKey, key, `${this.logId}:${ringName}`, nextEpoch)
    }

    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$keys',
        input: {
          action: 'rotateRingEpoch',
          ring: ringName,
          epoch: nextEpoch,
          keyCommitment: epochKeyCommitmentV2(key),
          boxes: boxes as unknown as JsonValue,
          topics: [...options.topics],
        },
      }],
    })
    return { ring: ringName, epoch: nextEpoch, operation }
  }

  /**
   * Configure threshold Social Recovery ("Trusted Backup Contacts"):
   * - Splits a fresh 32-byte recoveryKey into N Shamir shares (threshold M).
   * - Encrypts all retained epoch + compartment keys inside a recovery vault under recoveryKey.
   * - HPKE-seals each Shamir share strictly to its guardian's wrapKey (guardians cannot read app data).
   * - Atomically updates $permissions.guardians and $keys.recovery.
   */
  async setupSocialRecovery(options: {
    readonly guardians: readonly GuardianMember[]
    readonly threshold: number
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    check(options.guardians.length > 0, 'GUARDIANS_REQUIRED')
    check(Number.isSafeInteger(options.threshold) && options.threshold >= 1 && options.threshold <= options.guardians.length, 'INVALID_GUARDIAN_THRESHOLD')
    const updates: TopicUpdate[] = [{
      topic: '$permissions',
      input: {
        action: 'setGuardians',
        guardians: {
          threshold: options.threshold,
          members: options.guardians.map(g => ({
            publicKey: g.publicKey,
            wrapKey: g.wrapKey,
            ...(g.label ? { label: g.label } : {}),
          })),
        },
      },
    }]

    if (this.genesis.privateLog) {
      const recoveryKey = crypto.getRandomValues(new Uint8Array(32))
      const vaultPayload: {
        readonly epochs: Record<string, string>
        readonly rings: Record<string, Record<string, string>>
      } = { epochs: {}, rings: {} }
      for (const [ep, key] of this.#epochKeys) {
        vaultPayload.epochs[String(ep)] = bytesToHex(key)
      }
      for (const [ring, map] of this.#ringKeys) {
        const ringObj: Record<string, string> = {}
        for (const [ep, key] of map) ringObj[String(ep)] = bytesToHex(key)
        vaultPayload.rings[ring] = ringObj
      }
      const aad = utf8(`chronolog-recovery-vault:${this.logId}`)
      const encVault = await encryptEpochPayload(recoveryKey, 0n, utf8(JSON.stringify(vaultPayload)), aad)

      const shares = splitSecret(recoveryKey, options.threshold, options.guardians.length)
      const guardianShares: Record<string, { readonly index: number; readonly box: EpochKeyBox }> = {}
      for (let i = 0; i < options.guardians.length; i++) {
        const g = options.guardians[i]!
        const share = shares[i]!
        const box = await hpkeSealEpochKey(g.wrapKey, share.bytes, `${this.logId}:recovery-share`, share.index)
        guardianShares[g.publicKey] = { index: share.index, box }
      }
      updates.push({
        topic: '$keys',
        input: {
          action: 'setRecoveryVault',
          vault: {
            nonce: bytesToHex(encVault.nonce),
            ciphertext: bytesToHex(encVault.ciphertext),
          },
          guardianShares: guardianShares as unknown as JsonValue,
        },
      })
    }

    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      updates,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
    })
  }

  /** Fresh device requests recovery from configured guardians with a short human-readable match code. */
  async requestSocialRecovery(options: {
    readonly requestId?: string
    readonly label?: string
    readonly verificationCode?: string
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<{ readonly requestId: string; readonly verificationCode: string; readonly operation: ApplicationOperation }> {
    const requestId = options.requestId ?? crypto.randomUUID()
    const codeBytes = crypto.getRandomValues(new Uint8Array(3))
    const codeNum = ((codeBytes[0]! << 16) | (codeBytes[1]! << 8) | codeBytes[2]!) % 1_000_000
    const verificationCode = options.verificationCode ?? String(codeNum).padStart(6, '0')
    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$permissions',
        input: {
          action: 'requestRecovery',
          requestId,
          newPublicKey: this.identity.publicKey,
          newWrapKey: this.device.wrapKey.publicKey,
          label: options.label ?? 'Recovered device',
          verificationCode,
        },
      }],
    })
    return { requestId, verificationCode, operation }
  }

  /** Guardian approves a pending recovery request and re-seals their Shamir share to the recovering device. */
  async approveSocialRecovery(
    requestId: string,
    options: { readonly operationId?: string; readonly authorTimestampMs?: bigint } = {},
  ): Promise<ApplicationOperation> {
    const permInfo = (await this.#kernel.query('$permissions', { guardians: true })) as {
      readonly recoveryRequests?: Readonly<Record<string, RecoveryRequestRecord>>
    }
    const req = permInfo?.recoveryRequests?.[requestId]
    check(req !== undefined && req.status === 'pending', 'RECOVERY_REQUEST_NOT_FOUND')

    const updates: TopicUpdate[] = [{
      topic: '$permissions',
      input: { action: 'approveRecovery', requestId },
    }]

    if (this.genesis.privateLog) {
      const myShare = (await this.#kernel.query('$keys', { guardianShareFor: this.identity.publicKey })) as {
        readonly index: number
        readonly box: EpochKeyBox
      } | null
      check(myShare !== null, 'GUARDIAN_SHARE_MISSING')
      const shareBytes = await hpkeOpenEpochKey(
        this.device.wrapKey.privateKey,
        this.device.wrapKey.publicKey,
        myShare.box,
        `${this.logId}:recovery-share`,
        myShare.index,
      )
      const resealedBox = await hpkeSealEpochKey(
        req.newWrapKey,
        shareBytes,
        `${this.logId}:recovery-grant`,
        myShare.index,
      )
      updates.push({
        topic: '$keys',
        input: {
          action: 'submitRecoveryShare',
          member: req.newPublicKey,
          index: myShare.index,
          box: resealedBox as unknown as JsonValue,
        },
      })
    }

    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      updates,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
    })
  }

  /**
   * Called by the recovering device once threshold guardians have approved:
   * unseals guardian shares, reconstructs recoveryKey via Shamir interpolation,
   * decrypts the recovery vault, installs all epoch + compartment keys, and rematerializes.
   */
  async completeSocialRecovery(): Promise<{ readonly restoredEpochs: number; readonly restoredRings: number }> {
    return this.#serial(async () => {
      if (!this.genesis.privateLog) return { restoredEpochs: 0, restoredRings: 0 }
      const permInfo = (await this.#kernel.query('$permissions', { guardians: true })) as {
        readonly guardians?: GuardiansConfig | null
      }
      const threshold = permInfo?.guardians?.threshold ?? 1
      const rec = (await this.#kernel.query('$keys', { recoveryFor: this.identity.publicKey })) as unknown as {
        readonly vault: { readonly nonce: string; readonly ciphertext: string } | null
        readonly shares: Readonly<Record<string, { readonly index: number; readonly box: EpochKeyBox }>>
      }
      check(rec?.vault !== null && rec?.vault !== undefined, 'RECOVERY_VAULT_MISSING')
      const shareEntries = Object.values(rec.shares ?? {})
      check(shareEntries.length >= threshold, 'INSUFFICIENT_RECOVERY_SHARES')

      const decodedShares: { index: number; bytes: Uint8Array }[] = []
      for (const entry of shareEntries.slice(0, threshold)) {
        const bytes = await hpkeOpenEpochKey(
          this.device.wrapKey.privateKey,
          this.device.wrapKey.publicKey,
          entry.box,
          `${this.logId}:recovery-grant`,
          entry.index,
        )
        decodedShares.push({ index: entry.index, bytes })
      }
      const recoveryKey = combineShares(decodedShares)
      const aad = utf8(`chronolog-recovery-vault:${this.logId}`)
      const plainBytes = await decryptEpochPayload(recoveryKey, {
        epoch: 0n,
        nonce: hexToBytes(rec.vault.nonce),
        ciphertext: hexToBytes(rec.vault.ciphertext),
      }, aad)
      const parsed = JSON.parse(new TextDecoder().decode(plainBytes)) as {
        readonly epochs: Record<string, string>
        readonly rings: Record<string, Record<string, string>>
      }

      let restoredEpochs = 0
      for (const [epStr, hexKey] of Object.entries(parsed.epochs ?? {})) {
        await this.installEpochKey(Number(epStr), hexToBytes(hexKey))
        restoredEpochs++
      }
      let restoredRings = 0
      for (const [ring, eps] of Object.entries(parsed.rings ?? {})) {
        for (const [epStr, hexKey] of Object.entries(eps)) {
          await this.installRingKey(ring, Number(epStr), hexToBytes(hexKey))
        }
        restoredRings++
      }

      await this.#rematerialize()
      return { restoredEpochs, restoredRings }
    })
  }

  async removeMember(publicKey: string, options: {
    readonly rotateEpoch?: boolean
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<ApplicationOperation> {
    const updates: TopicUpdate[] = [
      { topic: '$permissions', input: { action: 'removeMember', publicKey } },
    ]
    if (this.genesis.privateLog && options.rotateEpoch !== false) {
      const nextEpoch = this.keysState().currentEpoch + 1
      const key = crypto.getRandomValues(new Uint8Array(32))
      await this.installEpochKey(nextEpoch, key)
      const boxes: Record<string, EpochKeyBox> = {}
      for (const m of this.permissions().members) {
        if (!m.reader || !m.wrapKey || m.publicKey === publicKey) continue
        boxes[m.publicKey] = await hpkeSealEpochKey(m.wrapKey, key, this.logId, nextEpoch)
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
      awaitMaterialized: true,
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
        const computedHash = bytesToHex(sha256Sync(f.bytes))
        if (hash !== undefined) check(hash === computedHash, 'PUBLICATION_FILE_HASH_MISMATCH')
        hash = computedHash
        size = f.bytes.length
        if (this.isReader(this.identity.publicKey)) {
          await this.content.putBlob(f.bytes)
        }
      }
      check(hash !== undefined && size !== undefined, 'PUBLICATION_FILE_INVALID')
      descriptors.push({ path: f.path, hash, size, type: f.type })
    }
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
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

  async rollbackRelease(options: {
    readonly revision?: number
    readonly opId?: string
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    check(options.revision !== undefined || options.opId !== undefined, 'PUBLICATION_ROLLBACK_TARGET_REQUIRED')
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$publications',
        input: {
          action: 'rollback',
          ...(options.revision === undefined ? {} : { revision: options.revision }),
          ...(options.opId === undefined ? {} : { opId: options.opId }),
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
      awaitMaterialized: true,
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
      awaitMaterialized: true,
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
        const scopeId = await policyScopeId(this.logId, active)

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
        await tempKernel.commitSeenOpsRoot()
        const snap = tempKernel.snapshot()

        const inclusions = included.map(i => ({
          opId: bytesToHex(i.opId),
          authorTimestampMs: i.core.authorTimestampMs,
          author: bytesToHex(i.core.author),
        }))
        const payload: FinalityCheckpointPayload = {
          logId: this.logId,
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
        check(checkpoint.payload.logId === this.logId, 'CHECKPOINT_CHAIN_MISMATCH')
        check(checkpoint.payload.stateRoot === snapshot.stateRoot && checkpoint.payload.historyDigest === snapshot.historyDigest, 'CHECKPOINT_SNAPSHOT_MISMATCH')
        const key = await recordDigest(checkpoint.payload)
        this.#checkpoints.set(key, checkpoint)
        await this.#store.put(`${this.#prefix}/checkpoint/${key}`, encodeRecord(checkpoint))
        await this.#kernel.bootstrapFromCheckpoint(snapshot)
        if (this.#controlKernel !== null) {
          await this.#controlKernel.bootstrapFromCheckpoint(snapshot)
        }
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
    const known = pub === undefined ? this.#kernelInputs.get(idOrOperationId) ?? this.#kernelInputs.get(this.#ownOperationIds.get(idOrOperationId) ?? '') : undefined
    if (pub !== undefined) {
      core = pub.core
    } else if (known !== undefined) {
      opIdHex = bytesToHex(known.opId); core = known.core
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

    const outcome = this.#kernel.outcomeOf(opIdHex)
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
    const [evidence] = await this.retainMany([{ proposalId, author: subject.author, envelopeDigest: subject.envelopeDigest }])
    return evidence!
  }

  /** Sign and persist a batch of retention receipts in ONE batched store write + ONE fact emission. */
  /** Index a (batch) retention receipt under every proposal it covers; true if anything was new. */
  #indexRetention(ev: RetentionEvidence): boolean {
    let added = false
    for (const proposalId of ev.payload.items) {
      if (typeof proposalId !== 'string') continue
      let byPeer = this.#retentions.get(proposalId)
      if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(proposalId, byPeer) }
      if (!byPeer.has(ev.signer)) { byPeer.set(ev.signer, ev); added = true }
    }
    return added
  }

  /**
   * Sign ONE retention receipt covering every newly retained item (sync v3), instead of one
   * signature, store write and gossip fact per operation.
   */
  async retainMany(
    items: readonly { readonly proposalId: string; readonly author?: string; readonly envelopeDigest?: string }[],
  ): Promise<readonly RetentionEvidence[]> {
    if (items.length === 0) return []
    const fresh = [...new Set(items.map(item => item.proposalId))]
      .filter(proposalId => this.#retentions.get(proposalId)?.get(this.identity.publicKey) === undefined)
    if (fresh.length === 0) return items.map(item => this.#retentions.get(item.proposalId)!.get(this.identity.publicKey)!)
    const evidence = await signRecord('operation-retention', {
      applicationId: this.applicationId,
      peer: this.identity.publicKey,
      storageId: this.device.storageId,
      items: fresh,
    }, this.device.identity)
    for (const proposalId of fresh) {
      let byPeer = this.#retentions.get(proposalId)
      if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(proposalId, byPeer) }
      byPeer.set(this.identity.publicKey, evidence)
    }
    await this.#store.put(`${this.#prefix}/retention/${await recordDigest(evidence.payload)}`, encodeRecord(evidence), { durability: 'relaxed' })
    this.#emitFacts()
    return items.map(item => this.#retentions.get(item.proposalId)!.get(this.identity.publicKey)!)
  }


  // ---- Facts export & merge (P2P + blind host sync) ----

  /** Number of times this session skipped full replay by restoring a verified materialized cache/snapshot. */
  get materializedCacheHits(): number {
    return this.#materializedCacheHits
  }

  /**
   * Export a self-contained, member-signed Snapshot Bundle (v2) including reachable private
   * SQLite-CAS Merkle pages + seenOpsRoot (excluding built-in standard modules).
   * On private logs, AEAD-encrypts under the current epoch key so blind hosts can cache it
   * in R2 with ZERO plaintext at rest and cold browsers can bootstrap in 1 fetch.
   */
  async exportMaterializedSnapshot(options: { readonly includeReachableCas?: boolean } = {}): Promise<Uint8Array | null> {
    await this.#flushPendingMaterialization()
    if (
      (this.#kernel.outcomes.length === 0 && this.#kernel.frontierOrderLength === 0) ||
      this.#kernel.pendingDependencies.length > 0
    ) {
      return null
    }
    await this.#kernel.commitSeenOpsRoot()
    const cache = this.#kernel.exportMaterializedCache()
    const casNodes: SessionCasNode[] = []
    if (options.includeReachableCas !== false) {
      const stdHashes = new Set(Object.values(STANDARD_MODULE_SOURCES).map(src => computeCasHash(utf8(src), [])))
      const roots = this.#kernel.gcRoots()
      const reachable = await this.cas.reachable(roots)
      for (const hash of reachable) {
        if (stdHashes.has(hash)) continue
        const pubRaw = await this.cas.getRaw(hash, 'public')
        if (pubRaw !== null) {
          casNodes.push({ hash, bytes: pubRaw, partition: 'public' })
          continue
        }
        const privRaw = await this.cas.getRaw(hash, 'private')
        if (privRaw !== null) {
          casNodes.push({ hash, bytes: privRaw, partition: 'private' })
        }
      }
    }
    let maxTs = this.#kernel.frontierMaxTimestampMs
    for (const o of cache.outcomes) {
      if (o.authorTimestampMs > maxTs) maxTs = o.authorTimestampMs
    }
    const signedBundle = await signRecord('materialized-snapshot-v2', {
      logId: this.logId,
      cache,
      casNodes,
      maxAuthorTimestampMs: maxTs.toString(),
    }, this.device.identity)

    if (this.genesis.privateLog && !this.#blindHostMode) {
      const epoch = this.#currentEpochFrom(this.#kernel)
      const epochKey = epoch >= 0 ? this.#epochKeys.get(epoch) : undefined
      if (epochKey === undefined) return null
      const plain = encodeRecord(signedBundle)
      const aad = utf8(`chronolog-v2-snapshot:${this.logId}:${epoch}`)
      const enc = await encryptEpochPayload(epochKey, BigInt(epoch), plain, aad)
      return encodeRecord({
        v: 2,
        private: true,
        logId: this.logId,
        epoch,
        nonce: enc.nonce,
        ciphertext: enc.ciphertext,
      })
    }
    return encodeRecord({
      v: 2,
      private: false,
      logId: this.logId,
      bundle: signedBundle,
    })
  }

  /**
   * Stage or immediately apply an exported materialized snapshot bundle (AEAD-decrypted on private logs).
   * Works even on cold browsers with ZERO historical ops downloaded yet (frontier bootstrap)!
   */
  importMaterializedSnapshot(bytes: Uint8Array): Promise<boolean> {
    return this.#serial(async () => {
      const decoded = await this.#decodeMaterializedSnapshot(bytes)
      if (decoded === null) return false
      if (decoded.casNodes.length > 0) {
        await this.cas.putManyVerified(decoded.casNodes)
      }
      this.#pendingSnapshotBundle = decoded
      await this.#rematerialize()
      return true
    })
  }

  async readCasPayload(hash: string, partition: CasPartition | 'any' = 'any'): Promise<{
    readonly hash: string
    readonly payload: Uint8Array
    readonly links: readonly string[]
  } | null> {
    const node = await this.cas.get(hash, partition)
    if (node === null) return null
    return { hash, payload: node.bytes.slice(), links: [...node.links] }
  }

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

  /** Reconciliation id set for a sync-v3 scope (live view; do not mutate). */
  factIds(scope: FactScope): FactIdSet {
    return scope === 'public' ? this.#publicFactIds : this.#privateFactIds
  }

  /** Raw facts for the given ids of one scope (unknown ids are skipped). */
  exportFactsById(scope: FactScope, ids: readonly string[]): SessionFacts {
    // Emit in canonical order (author timestamp first) so a receiver merging batch by batch appends
    // at its tip instead of replaying a suffix per batch. Undecryptable envelopes go last.
    const ops: { ts: bigint; raw: Uint8Array }[] = [], checkpoints: FinalityCheckpoint[] = []
    const LAST = 1n << 62n
    for (const id of ids) {
      if (scope === 'private') {
        const env = this.#encryptedEnvelopes.get(id)
        if (env !== undefined) ops.push({ ts: env.decrypted?.core.authorTimestampMs ?? LAST, raw: env.raw })
        continue
      }
      const op = this.#publicOps.get(id)
      if (op !== undefined) { ops.push({ ts: op.core.authorTimestampMs, raw: op.raw }); continue }
      const cp = this.#checkpoints.get(id)
      if (cp !== undefined) checkpoints.push(cp)
    }
    ops.sort((a, b) => a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0)
    const raws = ops.map(op => op.raw)
    return { publicOps: scope === 'public' ? raws : [], encryptedEnvelopes: scope === 'private' ? raws : [], casNodes: [], retentions: [], checkpoints }
  }

  /** CAS nodes by hash for an on-demand peer pull; private-partition nodes only when allowed. */
  async exportCasNodes(hashes: readonly string[], includePrivate: boolean): Promise<SessionCasNode[]> {
    const out: SessionCasNode[] = []
    for (const hash of hashes) {
      for (const partition of includePrivate ? ['public', 'private'] as const : ['public'] as const) {
        const raw = await this.cas.getRaw(hash, partition)
        if (raw !== null) { out.push({ hash, bytes: raw, partition }); break }
      }
    }
    return out
  }

  /** CAS hashes replay is blocked on (modules, reducer-read nodes, SQLite pages). */
  missingCasDependencies(): string[] {
    const out = new Set<string>()
    for (const kernel of [this.#kernel, this.#controlKernel, this.#finalKernel]) {
      for (const dep of kernel?.pendingDependencies ?? []) {
        const hash = dep.slice(dep.indexOf('/') + 1)
        if (/^[0-9a-f]{64}$/u.test(hash)) out.add(hash)
      }
    }
    return [...out]
  }

  async exportPublicControlFacts(): Promise<{
    readonly publicOps: readonly Uint8Array[]
    readonly casNodes: readonly SessionCasNode[]
    readonly checkpoints: readonly FinalityCheckpoint[]
  }> {
    const casNodes: SessionCasNode[] = []
    const standard = standardModuleHashes()
    for (const hash of this.cas.listKnownHashes('public')) {
      if (standard.has(hash)) continue // every replica and host seeds the audited standard modules itself
      const raw = await this.cas.getRaw(hash, 'public')
      if (raw !== null) casNodes.push({ hash, bytes: raw, partition: 'public' })
    }
    return {
      publicOps: [...this.#publicOps.values()].map(v => v.raw.slice()),
      casNodes,
      checkpoints: [...this.#checkpoints.values()],
    }
  }

  mergeFacts(facts: SessionFacts, options: { readonly source?: string } = {}): Promise<void> {
    return this.#serial(async () => {
      await this.#mergeFactsNow(facts, options.source)
    })
  }

  async #mergeFactsNow(facts: SessionFacts, source: string | undefined): Promise<void> {
    {
      if (facts.genesisBytes !== undefined) {
        check(sameBytes(facts.genesisBytes, this.genesisBytes), 'FACTS_GENESIS_MISMATCH')
      }

      let materializedChanged = false
      let factsChanged = false

      if (facts.casNodes !== undefined && facts.casNodes.length > 0) {
        const addedCas = await this.cas.putManyVerified(facts.casNodes)
        if (addedCas > 0) {
          materializedChanged = true
          factsChanged = true
        }
      }

      const storeBatch: BytesStoreEntry[] = []

      for (const raw of facts.publicOps ?? []) {
        const signed = decodeSignedOperation(raw)
        // Dedupe on the content-derived id before paying for signature verification.
        if (this.#publicOps.has(bytesToHex(operationIdDigest(signed.coreBytes)))) continue
        const verified = await verifySignedOperation(signed)
        if (bytesToHex(verified.core.logId) !== this.logId) continue
        if (verified.core.visibility !== 'public') continue
        const opId = bytesToHex(verified.opId)
        if (this.#publicOps.has(opId)) continue
        check(this.#publicOps.size + this.#encryptedEnvelopes.size < this.#maxOperations, 'SESSION_OPERATION_LIMIT')
        const copy = raw.slice()
        storeBatch.push({ key: `${this.#prefix}/public-op/${opId}`, value: copy })
        this.#publicOps.setFrom(opId, { raw: copy, signed, core: verified.core }, source)
        materializedChanged = true
        factsChanged = true
      }

      for (const raw of facts.encryptedEnvelopes ?? []) {
        const digest = bytesToHex(encryptedEnvelopeDigest(raw))
        if (this.#encryptedEnvelopes.has(digest)) continue
        const envelope = decodeEncryptedEnvelope(raw)
        if (bytesToHex(envelope.logId) !== this.logId) continue
        check(this.#publicOps.size + this.#encryptedEnvelopes.size < this.#maxOperations, 'SESSION_OPERATION_LIMIT')
        const copy = raw.slice()
        storeBatch.push({ key: `${this.#prefix}/enc-env/${digest}`, value: copy })
        this.#encryptedEnvelopes.setFrom(digest, { digest, raw: copy, envelope }, source)
        this.#undecryptedEnvelopes.add(digest)
        materializedChanged = true
        factsChanged = true
      }

      for (const ev of facts.retentions ?? []) {
        if (ev.payload.applicationId !== this.applicationId || !Array.isArray(ev.payload.items)) continue
        // Verify once per batch receipt, and only if it says something new.
        if (ev.payload.items.every((proposalId: string) => this.#retentions.get(proposalId)?.has(ev.signer) === true)) continue
        await verifyRecord('operation-retention', ev, ev.signer)
        if (this.#indexRetention(ev)) {
          storeBatch.push({ key: `${this.#prefix}/retention/${await recordDigest(ev.payload)}`, value: encodeRecord(ev) })
          factsChanged = true
        }
      }

      for (const cp of facts.checkpoints ?? []) {
        if (cp.payload.logId !== this.logId) continue
        const key = await recordDigest(cp.payload)
        if (!this.#checkpoints.has(key)) {
          this.#checkpoints.setFrom(key, cp, source)
          storeBatch.push({ key: `${this.#prefix}/checkpoint/${key}`, value: encodeRecord(cp) })
          materializedChanged = true
          factsChanged = true
        }
      }

      if (storeBatch.length > 0) {
        for (let i = 0; i < storeBatch.length; i += 128) {
          await writeBytesMany(this.#store, storeBatch.slice(i, i + 128), { durability: 'relaxed' })
        }
        if (this.#store.latestChangeSeq !== undefined) {
          this.#lastSyncSeq = Math.max(this.#lastSyncSeq, await this.#store.latestChangeSeq())
        }
      }

      if (materializedChanged) {
        await this.#rematerialize()
      } else if (factsChanged) {
        this.#emitStatus()
      }
      if (factsChanged) {
        this.#emitFacts()
      }
    }
  }

  async collectGarbage(): Promise<{ readonly kept: number; readonly deleted: number }> {
    return this.#serial(async () => {
      await this.#flushPendingMaterialization()
      const roots = this.#kernel.gcRoots()
      if (this.#controlKernel !== null) {
        for (const r of this.#controlKernel.gcRoots()) roots.add(r)
      }
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
      if (this.#cachePersistTimer !== undefined) {
        clearTimeout(this.#cachePersistTimer)
        this.#cachePersistTimer = undefined
      }
      try { await this.#flushPendingMaterialization() } catch { /* ignore on close */ }
      try { await this.#persistMaterializedCacheNow() } catch { /* ignore on close */ }
      this.#closed = true
      this.#lifetime.abort(new Error('SESSION_CLOSED'))
      this.#emitStatus()
      this.#kernel.sandbox.dispose()
      this.#controlKernel?.sandbox.dispose()
      this.#finalKernel?.sandbox.dispose()
      await this.content.close()
      await this.#release()
    })()
  }
}

async function readAllStoreEntries(store: BytesStore): Promise<readonly { readonly key: string; readonly value: Uint8Array }[]> {
  if (store.iterateEntries !== undefined) {
    const entries: { readonly key: string; readonly value: Uint8Array }[] = []
    for await (const entry of store.iterateEntries()) entries.push(entry)
    return entries
  }
  if (store.entries !== undefined) {
    return store.entries()
  }
  return []
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

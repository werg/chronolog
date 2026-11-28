import { bytesToHex, decodeCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, hexToBytes, perfTimeAsync, sha256Sync, utf8 } from '@chronolog/canonical'
import { openSqlBranch, type SqlBranch } from './sql-extensions.js'
import {
  buildTreeEpochUpdate,
  combineShares,
  decryptEpochPayload,
  deriveEpochMailboxKeyPair,
  encryptEpochPayload,
  epochKeyCommitment,
  KEY_BOX_SUITE_X25519,
  KEY_BOX_SUITE_XWING,
  KEY_TREE_SUITE_X25519,
  KEY_TREE_SUITE_XWING,
  openTreeEpoch,
  readKeyTreeFromCas,
  signEd25519Sync,
  splitSecret,
  writeKeyTreeToCas,
  type KeyBoxSuite,
  type KeyTreeEpochPayload,
  type KeyTreeSuite,
} from '@chronolog/crypto'
import {
  casRef,
  computeBlobDagHash,
  computeCasHash,
  ContentAddressedStore,
  encodeTreeNode,
  parseCasRef,
  putPackageDag,
  tryDecodePackageNode,
  tryParseCasRef,
  writeBytesMany,
  type BytesStore,
  type BytesStoreEntry,
  type CasPartition,
  type PutPackageInput,
} from '@chronolog/records'
import {
  ANONYMOUS_AUTHOR,
  assertValidReducersConfig,
  canonicalJson,
  compareOperationOrder,
  decodeEncryptedEnvelope,
  decodeLogGenesis,
  decodeSignedOperation,
  decodeTrustedEncryptedEnvelope,
  decodeTrustedOperationCore,
  decodeTrustedSignedOperation,
  encodeEncryptedEnvelope,
  encodeLogGenesis,
  encodeOperationCore,
  encodeSignedOperation,
  encryptedEnvelopeDigest,
  envelopeAad,
  envelopeMailboxSigningBytes,
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
  computeAdmissionScopeId,
  computeIncludedSetDigest,
  decodeRecord,
  encodeRecord,
  evaluateAdmission,
  evidenceDigest,
  recordDigest,
  signAdmissionCheckpoint,
  signRecord,
  validateApplicationDescription,
  verifyRecord,
  type AdmissionCheckpointPayload,
  type AdmissionDecision,
  type AdmissionEquivocation,
  type AdmissionEvidence,
  type ApplicationDescription,
  type PinnedFrontier,
} from '@chronolog/authority'
import {
  createBytesStoreDerivationMemo,
  decodeMaterializedCache,
  encodeMaterializedCache,
  evaluateDerivation,
  STANDARD_MODULE_SOURCES,
  TopicKernel,
  type DerivationEvalResult,
  type EmittedKernelEvent,
  type KernelMaterializedCache,
  type KernelOperationInput,
  type QuickJsSandboxOptions,
  type SqliteBuiltinDriver,
  type WasiDerivationRunner,
} from '@chronolog/materializer'
import { SignalChannel, type SignalAuthorization } from '@chronolog/signals'
import { decodeSnapshotBundle, encodeSnapshotBundle } from './snapshot-codec.js'
import { ApplicationContent } from './content.js'
import { createCasMirrorClient } from './cas-mirror.js'
import type { ApplicationDevice } from './device.js'
import { describeApplication, type ApplicationDefinition } from './definition.js'
import { FactIdSet } from './reconcile.js'
import { standardModuleHashes } from './standard-modules.js'
import { admissionOpRef, finalizedInputs, materializeControl } from './control-plane.js'
import { EPOCH_KEY_GROUP, KeyStore, parseVaultKeyGroup, ringKeyGroup, TREE_SEED_GROUP, vaultKeyGroup } from './key-store.js'
import {
  hpkeOpenEpochKey,
  hpkeSealEpochKey,
  type EpochKeyBox,
  type KeysPolicy,
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
  FACTS_SOURCE_STORE,
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

/** Sync-v3 fact scopes: public = public ops + admission evidence; private = encrypted envelopes. */
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

/** Envelope map that also indexes the op ids it holds (an op can sit in several rewrapped envelopes). */
class EnvelopeFactMap extends FactMap<StoredEncryptedEnvelope> {
  readonly #opIds = new Map<string, number>()
  holdsOp(opId: string): boolean { return this.#opIds.has(opId) }
  override set(key: string, value: StoredEncryptedEnvelope): this {
    if (!this.has(key)) {
      const opId = bytesToHex(value.envelope.opId)
      this.#opIds.set(opId, (this.#opIds.get(opId) ?? 0) + 1)
    }
    return super.set(key, value)
  }
  override delete(key: string): boolean {
    const value = this.get(key)
    if (value !== undefined) {
      const opId = bytesToHex(value.envelope.opId)
      const count = (this.#opIds.get(opId) ?? 1) - 1
      if (count <= 0) this.#opIds.delete(opId)
      else this.#opIds.set(opId, count)
    }
    return super.delete(key)
  }
  override clear(): void {
    this.#opIds.clear()
    super.clear()
  }
}


export interface SessionFacts {
  readonly genesisBytes?: Uint8Array
  readonly publicOps: readonly Uint8Array[]
  readonly encryptedEnvelopes: readonly Uint8Array[]
  readonly casNodes: readonly SessionCasNode[]
  readonly retentions: readonly RetentionEvidence[]
  readonly evidence: readonly AdmissionEvidence[]
}

export interface AdmissionScheduleEntry {
  readonly effectiveAfterMs: number
  readonly policy: JsonValue
}

export interface SealsTopicState {
  readonly reducers: Readonly<Record<string, true>>
  readonly paths: Readonly<Record<string, Readonly<Record<string, 'frozen' | 'append-only'>>>>
}

export interface SimulationResult {
  readonly ok: boolean
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
  readonly rejectionDetail?: string
  readonly events: readonly ApplicationEvent[]
  readonly changedTopics: readonly string[]
  readonly stateRoot: string
}

export interface MemberRecord {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly pqWrapKey?: string
  readonly label?: string
  readonly scopes?: readonly string[]
  readonly expiresAtMs?: number
  /** Author of the operation that admitted this member (may grant it lockboxes). */
  readonly admittedBy?: string
  readonly reader: boolean
  readonly writer: boolean
  readonly administrator: boolean
  readonly publisher: boolean
}

export interface GuardianMember {
  readonly publicKey: string
  readonly wrapKey?: string
  readonly pqWrapKey?: string
  readonly label?: string
}

export interface GuardiansConfig {
  readonly threshold: number
  readonly members: readonly GuardianMember[]
}

export interface RecoveryRequestRecord {
  readonly requestId: string
  readonly newPublicKey: string
  readonly newWrapKey?: string
  readonly newPqWrapKey?: string
  readonly label: string
  readonly verificationCode: string
  readonly approvals: readonly string[]
  readonly status: 'pending' | 'completed'
  readonly createdAtMs: number
}

export interface AdmissionMultisigInfo {
  readonly threshold: number
  readonly signers: readonly string[]
  readonly proposals: Readonly<Record<string, JsonValue>>
}

export interface AdmissionRoster {
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
  readonly multisig?: AdmissionMultisigInfo | null
}

export interface KeyRingState {
  readonly currentEpoch: number
  readonly epochs: Readonly<Record<string, {
    readonly epoch: number
    readonly suite?: KeyBoxSuite
    readonly keyCommitment: string
    readonly mailboxVerifyKey?: string
    readonly boxes: Readonly<Record<string, EpochKeyBox>>
  }>>
}

export interface KeysTopicState {
  readonly currentEpoch: number
  readonly policy?: KeysPolicy
  readonly epochs: Readonly<Record<string, {
    readonly epoch: number
    readonly suite?: KeyBoxSuite | KeyTreeSuite
    readonly keyCommitment: string
    readonly mailboxVerifyKey?: string
    readonly treeRef?: string
    readonly leafCount?: number
    readonly activeMembers?: readonly string[]
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

export interface SealedRecipientBox {
  readonly format: 'chronolog-sealed/v1'
  readonly encoding: 'json' | 'bytes'
  readonly nonce: string
  readonly ciphertext: string
  readonly boxes: Readonly<Record<string, EpochKeyBox>>
}

export interface VaultSealedBox {
  readonly format: 'chronolog-vault-box/v1'
  readonly vaultId: string
  readonly epoch: number
  readonly encoding: 'json' | 'bytes'
  readonly nonce: string
  readonly ciphertext: string
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
  readonly sqliteWasmModule?: WebAssembly.Module
  readonly sqliteWasmLoader?: () => Promise<WebAssembly.Module>
  readonly materializedSnapshot?: Uint8Array
  /** Ask peers for a signed snapshot when this replica has no history yet (default true). */
  readonly snapshotBootstrap?: boolean
  readonly maxOperations?: number
  /** Optional read-only untrusted HTTP CAS mirror URLs (GET <mirror>/cas/sha256-<hex>). */
  readonly casMirrors?: readonly string[]
  readonly release: () => void | Promise<void>
}

/** One vault in a `chronolog/vaults` topic state. */
interface VaultTopicEntry {
  readonly currentEpoch?: number
  readonly members?: readonly string[]
  readonly epochs?: Readonly<Record<string, { readonly epoch: number; readonly keyCommitment?: string; readonly boxes?: Readonly<Record<string, EpochKeyBox>> }>>
}

/** How a snapshot frontier is trusted on adoption: produced by this deployment, or verified by evidence/replay. */
type SnapshotTrust = 'local' | 'untrusted'

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
  /** Re-read from this device's own store (written by this replica), not received from a peer. */
  readonly fromStore?: true
}

interface LocalPendingOp {
  readonly raw: Uint8Array
  readonly signed: SignedOperation
  readonly core: OperationCore
  currentEnvelopeDigest: string
  currentEpoch: number
  /** Commitment of the epoch key the current envelope is encrypted under. */
  currentCommitment: string
}

interface EvaluatedAdmissionRoster {
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
  readonly guardians: GuardiansConfig | null
  readonly recoveryRequests: Readonly<Record<string, RecoveryRequestRecord>>
  readonly multisig: AdmissionMultisigInfo | null
}

/** Upper bound on op ids one retention receipt may cover (senders batch at most 1024). */
const MAX_RETENTION_ITEMS = 4096

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
    opId: ev.opId,
    operationId: ev.operationId,
    author: ev.author,
    authorTimestampMs: ev.authorTimestampMs.toString(),
    topic: ev.topic,
    payload: structuredClone(ev.payload),
  })
}

/**
 * ApplicationSession: one replica of one log.
 *
 * Built directly on:
 * - Flat timestamp-ordered operation set: (authorTimestampMs, author, opId)
 * - Pure Merkle-DAG CAS (public/private partitions, explicit links, exact GC)
 * - TopicKernel + QuickJS-NG Import-Map ES Module reducers + lazy chronolog:sqlite
 * - Automatic HPKE $keys unsealing + reconnect rewrapping of offline encrypted ops
 * - Unified state-defined $admission (global authorization, history finality, signals, checkpoint pins)
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
  readonly #sandboxOptions: QuickJsSandboxOptions
  readonly #sqliteWasmModule?: WebAssembly.Module
  readonly #sqliteWasmLoader?: () => Promise<WebAssembly.Module>
  readonly #maxOperations: number
  readonly #casMirrors: readonly string[]
  readonly #mirrorAttempted = new Set<string>()

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
  readonly #encryptedEnvelopes = new EnvelopeFactMap(this.#privateFactIds, (id, source) => this.#recordDelta('private', id, source))
  readonly #undecryptedEnvelopes = new Set<string>()
  readonly #localPending = new Map<string, LocalPendingOp>()
  readonly #retentions = new Map<string, Map<string, RetentionEvidence>>()
  readonly #evidence = new FactMap<AdmissionEvidence>(this.#publicFactIds, (id, source) => this.#recordDelta('public', id, source))
  /** Every epoch, ring, vault and TreeKEM seed key this replica holds (commitment-keyed, see key-store.ts). */
  readonly #keys: KeyStore
  /** Topic hash last scanned for lockboxes, per key-bearing topic (unchanged topics are not rescanned). */
  readonly #scannedKeyTopics = new Map<string, string>()
  readonly #missingTreeCasHashes = new Set<string>()

  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #changeListeners = new Set<(change: ApplicationChange) => void>()
  readonly #factListeners = new Set<(delta: FactsDelta) => void>()

  #connectedPeers = 0
  #connectionRevision = 0
  #materializationError: string | null = null
  #lastLocalRevision: MaterializedRevision
  #lastFinalRevision: MaterializedRevision | null = null
  #pinnedFrontier: PinnedFrontier | null = null
  #admissionDecision: AdmissionDecision = {
    closedThroughMs: null,
    includedOpIds: new Set(),
    excludedOpIds: new Set(),
    latestCheckpoint: null,
    verifiedEvidence: [],
    equivocations: [],
  }
  #cachedSignalPolicy: { stateRoot: string; rules: readonly { readonly topicPattern: string; readonly allowedAuthors: readonly string[]; readonly maxTtlMs: number; readonly allowRelay: boolean }[] } | null = null
  #cachedDescription: { stateRoot: string; value: ApplicationDescription } | null = null
  #validationDescription: { readonly key: string; readonly value: ApplicationDescription | null } | null = null
  #evaluatedRoster: EvaluatedAdmissionRoster | null = null
  #lastAdmissionHash = ''
  #pendingMaterializedCache: KernelMaterializedCache | null = null
  #pendingSnapshotBundle: {
    readonly cache: KernelMaterializedCache
    readonly casNodes: readonly SessionCasNode[]
    readonly trust: SnapshotTrust
  } | null = null
  /**
   * Set while this.#kernel's frontier came from an unattested snapshot (first paint only): it is
   * not persisted, not re-exported, its op ids are not trusted, and control decisions read the
   * replica's own control kernel. Cleared once replay of the covered ops reproduces it.
   */
  #provisionalSnapshot: { readonly stateRoot: string; readonly historyDigest: string; readonly opIds: readonly string[] } | null = null
  /** Private full replica: blind kernel folding only admitted public ops (created when evidence excludes one). */
  #admittedControlKernel: TopicKernel | null = null
  /** Public log / blind host with admission evidence: persistent probe folding every public op. */
  #probeKernel: TopicKernel | null = null
  #probeHasSqlite = false
  /**
   * Op ids this replica already verified (signature + id) before folding them into a persisted
   * materialized cache, plus ops it authored. Trust shortcut on cold open: an envelope re-read
   * from the device's own store whose decrypted op id is in this set skips Ed25519 re-verification.
   */
  readonly #trustedOpIds = new Set<string>()
  readonly #snapshotBootstrap: boolean
  #visibilityCleanup: (() => void) | undefined
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
    this.#keys = new KeyStore(this.#store, this.#prefix)
    this.#release = options.release
    this.#blindHostMode = options.blindHostMode ?? false
    if (options.sqliteWasmModule !== undefined) this.#sqliteWasmModule = options.sqliteWasmModule
    if (options.sqliteWasmLoader !== undefined) this.#sqliteWasmLoader = options.sqliteWasmLoader
    if (options.materializedSnapshot !== undefined) this.#pendingEncryptedSnapshot = options.materializedSnapshot.slice()
    this.#snapshotBootstrap = options.snapshotBootstrap ?? true
    this.#installVisibilityFlush()
    this.#maxOperations = options.maxOperations ?? 50_000
    this.#casMirrors = (options.casMirrors ?? []).map(u => u.replace(/\/+$/u, ''))
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
      cas: this.cas,
      identity: this.device.identity,
      storageId: this.device.storageId,
      authority: {
        applicationId: this.applicationId,
        isReader: pk => this.isReader(pk),
        currentEpoch: () => Math.max(0, this.currentEpoch()),
        epochKey: epoch => this.#groupKey('default', epoch) ?? null,
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
    await session.#settleLocalPending()
    return session
  }

  get signal(): AbortSignal { return this.#lifetime.signal }

  #computeKeyState(): SessionKeyState {
    if (!this.genesis.privateLog || this.#blindHostMode) return 'public'
    const epoch = this.currentEpoch()
    if (epoch < 0) return 'ready'
    if (this.hasEpochKey(epoch)) return 'ready'
    const entry = this.keysState().epochs?.[String(epoch)]
    const hasAccess = entry?.boxes?.[this.identity.publicKey] !== undefined ||
      (Array.isArray(entry?.activeMembers) && entry.activeMembers.includes(this.identity.publicKey))
    return hasAccess ? 'pending-unseal' : 'missing-lockbox'
  }

  get status(): SessionStatus {
    const pendingOps = this.#countPendingOps()
    const keyState = this.#computeKeyState()
    const pk = this.identity.publicKey
    const isAdmin = this.isAdministrator(pk)
    const isPub = this.#evaluatedRoster !== null && this.#evaluatedRoster.publishers.has(pk)
    const canAuthorControl = !this.#closed && !this.#blindHostMode && (isAdmin || isPub)
    const canAuthorData = !this.#closed && !this.#blindHostMode && this.isWriter(pk) && (keyState === 'public' || keyState === 'ready')
    const canAuthor = canAuthorData || canAuthorControl
    const awaitingKeys = this.genesis.privateLog && !this.#blindHostMode && this.isReader(pk) && this.currentEpoch() >= 0 && !this.hasEpochKey(this.currentEpoch())
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

  permissions(): AdmissionRoster {
    const p = this.#evaluatedRoster
    if (p === null) {
      return {
        members: [],
        readers: [],
        writers: [],
        administrators: [],
        publishers: [],
        openReaders: false,
        openWriters: false,
        blockedAuthors: [],
        admission: null,
        guardians: null,
        recoveryRequests: {},
        multisig: null,
      }
    }
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
      guardians: p.guardians,
      recoveryRequests: p.recoveryRequests,
      multisig: p.multisig,
    }
  }

  member(publicKey: string): MemberRecord | null {
    return this.permissions().members.find(m => m.publicKey === publicKey) ?? null
  }

  isBlockedAuthor(publicKey: string): boolean {
    return this.#evaluatedRoster !== null && this.#evaluatedRoster.blockedAuthors.has(publicKey)
  }

  isMember(publicKey: string): boolean {
    if (this.#evaluatedRoster === null) return false
    if (this.#evaluatedRoster.openWriters || this.#evaluatedRoster.openReaders) return /^[0-9a-f]{64}$/u.test(publicKey)
    return this.#evaluatedRoster.members.some(m => m.publicKey === publicKey) ||
      this.#evaluatedRoster.readers.has(publicKey) ||
      this.#evaluatedRoster.writers.has(publicKey) ||
      this.#evaluatedRoster.administrators.has(publicKey)
  }

  isReader(publicKey: string): boolean {
    if (!this.genesis.privateLog) return true
    if (this.#evaluatedRoster === null) return false
    if (this.#evaluatedRoster.openReaders) return /^[0-9a-f]{64}$/u.test(publicKey)
    return this.#evaluatedRoster.readers.has(publicKey)
  }

  isWriter(publicKey: string): boolean {
    if (this.#evaluatedRoster === null) return false
    if (this.#evaluatedRoster.blockedAuthors.has(publicKey)) return false
    if (this.#evaluatedRoster.openWriters) return /^[0-9a-f]{64}$/u.test(publicKey)
    return this.#evaluatedRoster.writers.has(publicKey) || this.#evaluatedRoster.administrators.has(publicKey)
  }

  isAdministrator(publicKey: string): boolean {
    return this.#evaluatedRoster !== null && this.#evaluatedRoster.administrators.has(publicKey)
  }

  /** Query any standard or custom capability (including `scope:<name>`) against the log's `$admission` reducer. */
  async can(capability: string, actor = this.identity.publicKey): Promise<boolean> {
    const query = capability.startsWith('scope:')
      ? { kind: 'can', capability: 'scope', scope: capability.slice(6), actor }
      : { kind: 'can', capability, actor }
    const res = await this.#kernel.query('$admission', query).catch(() => null)
    return res === true
  }

  /** Read the log's kernel-enforced monotonic `$seals` table (locked reducers and frozen/append-only JSON paths). */
  seals(): SealsTopicState {
    const raw = this.#kernel.topic('$seals') as Partial<SealsTopicState> | null
    const reducers: Record<string, true> = {}
    const paths: Record<string, Record<string, 'frozen' | 'append-only'>> = {}
    if (raw !== null && typeof raw === 'object') {
      if (raw.reducers && typeof raw.reducers === 'object') {
        for (const [k, v] of Object.entries(raw.reducers)) {
          if (v === true) reducers[k] = true
        }
      }
      if (raw.paths && typeof raw.paths === 'object') {
        for (const [t, rules] of Object.entries(raw.paths)) {
          if (!rules || typeof rules !== 'object') continue
          const clean: Record<string, 'frozen' | 'append-only'> = {}
          for (const [p, mode] of Object.entries(rules)) {
            if (mode === 'frozen' || mode === 'append-only') clean[p] = mode
          }
          if (Object.keys(clean).length > 0) paths[t] = clean
        }
      }
    }
    return { reducers, paths }
  }

  /** Irreversibly add reducer hash locks and/or JSON path locks to `$seals`. */
  async seal(options: {
    readonly reducers?: readonly string[]
    readonly paths?: readonly {
      readonly topic: string
      readonly path: string
      readonly mode?: 'frozen' | 'append-only'
      readonly allowMutableReducer?: boolean
    }[]
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$seals',
        input: {
          action: 'seal',
          ...(options.reducers === undefined ? {} : { reducers: [...options.reducers] }),
          ...(options.paths === undefined ? {} : { paths: options.paths as unknown as JsonValue }),
        },
      }],
    })
  }

  keysState(): KeysTopicState {
    const raw = this.#controlView().topic('$keys') as KeysTopicState | null
    if (raw === null || typeof raw !== 'object') return { currentEpoch: -1, epochs: {} }
    return raw
  }

  keysPolicy(): Required<Pick<KeysPolicy, 'rotateOnRemove' | 'minSuite' | 'paddingBucketBytes' | 'hideEnvelopeAuthor' | 'distribution'>> & {
    readonly maxOpsPerEpoch?: number
  } {
    const raw = this.keysState().policy
    return {
      rotateOnRemove: raw?.rotateOnRemove !== false,
      minSuite: raw?.minSuite === KEY_BOX_SUITE_XWING ? KEY_BOX_SUITE_XWING : KEY_BOX_SUITE_X25519,
      paddingBucketBytes:
        typeof raw?.paddingBucketBytes === 'number' && Number.isSafeInteger(raw.paddingBucketBytes) && raw.paddingBucketBytes >= 0
          ? raw.paddingBucketBytes
          : 0,
      hideEnvelopeAuthor: raw?.hideEnvelopeAuthor === true,
      distribution: raw?.distribution === 'tree' ? 'tree' : 'flat',
      ...(typeof raw?.maxOpsPerEpoch === 'number' && Number.isSafeInteger(raw.maxOpsPerEpoch) && raw.maxOpsPerEpoch >= 1
        ? { maxOpsPerEpoch: raw.maxOpsPerEpoch }
        : {}),
    }
  }

  #mailboxVerifyKey(epochKey: Uint8Array): string {
    return bytesToHex(deriveEpochMailboxKeyPair(epochKey).publicKey)
  }

  async #sealBoxForMember(
    member: { readonly wrapKey?: string; readonly pqWrapKey?: string },
    key: Uint8Array,
    scope: string,
    epoch: number,
    requestedSuite?: KeyBoxSuite,
  ): Promise<EpochKeyBox | null> {
    const policy = this.keysPolicy()
    const requirePq = requestedSuite === KEY_BOX_SUITE_XWING || policy.minSuite === KEY_BOX_SUITE_XWING
    if (requirePq) {
      if (!member.pqWrapKey) return null
      return hpkeSealEpochKey(member.pqWrapKey, key, scope, epoch, KEY_BOX_SUITE_XWING)
    }
    if (member.pqWrapKey && requestedSuite !== KEY_BOX_SUITE_X25519) {
      return hpkeSealEpochKey(member.pqWrapKey, key, scope, epoch, KEY_BOX_SUITE_XWING)
    }
    if (member.wrapKey) {
      return hpkeSealEpochKey(member.wrapKey, key, scope, epoch, KEY_BOX_SUITE_X25519)
    }
    return null
  }

  async #encryptOperationEnvelope(options: {
    readonly epochKey: Uint8Array
    readonly epoch: number
    readonly opBytes: Uint8Array
    readonly logIdBytes: Uint8Array
    readonly opIdBytes: Uint8Array
    readonly authorBytes: Uint8Array
    readonly ring: string
  }): Promise<EncryptedOperationEnvelope> {
    const policy = this.keysPolicy()
    const envAuthor = policy.hideEnvelopeAuthor ? ANONYMOUS_AUTHOR : options.authorBytes
    const aad = envelopeAad(options.logIdBytes, options.opIdBytes, envAuthor, options.ring)
    const enc = await encryptEpochPayload(
      options.epochKey,
      BigInt(options.epoch),
      options.opBytes,
      aad,
      undefined,
      { paddingBucketBytes: policy.paddingBucketBytes },
    )
    const baseEnv: EncryptedOperationEnvelope = {
      version: 1,
      logId: options.logIdBytes,
      opId: options.opIdBytes,
      author: envAuthor,
      epoch: options.epoch,
      nonce: enc.nonce,
      ciphertext: enc.ciphertext,
      ...(options.ring === 'default' ? {} : { ring: options.ring }),
    }
    if (!policy.hideEnvelopeAuthor) return baseEnv
    const mailboxKp = deriveEpochMailboxKeyPair(options.epochKey)
    const mailboxTag = signEd25519Sync(mailboxKp.seed, envelopeMailboxSigningBytes(baseEnv))
    return { ...baseEnv, mailboxTag }
  }

  currentEpoch(): number {
    return this.#currentEpochFrom(this.#kernel)
  }

  /** On-log `keyCommitment` of `(ring, epoch)` in `$keys` (undefined until that epoch materializes). */
  #onLogCommitment(ring: string, epoch: number, kernel: TopicKernel = this.#controlView()): string | undefined {
    const keys = this.#keysStateFrom(kernel)
    const entry = ring === 'default' ? keys.epochs?.[String(epoch)] : keys.rings?.[ring]?.epochs?.[String(epoch)]
    return typeof entry?.keyCommitment === 'string' ? entry.keyCommitment : undefined
  }

  /**
   * The held key for `(ring, epoch)` whose commitment matches `$keys` (before the epoch is on the
   * log, the first installed candidate). A losing concurrent rotation's key is never selected.
   */
  #groupKey(ring: string, epoch: number, kernel: TopicKernel = this.#controlView()): Uint8Array | undefined {
    return this.#keys.get(ringKeyGroup(ring), epoch, this.#onLogCommitment(ring, epoch, kernel))
  }

  epochKey(epoch: number): Uint8Array | null {
    return this.#groupKey('default', epoch)?.slice() ?? null
  }

  hasEpochKey(epoch: number): boolean {
    return this.#groupKey('default', epoch) !== undefined
  }

  exportEpochKeys(): ReadonlyMap<number, Uint8Array> {
    const out = new Map<number, Uint8Array>()
    for (const ep of this.#keys.epochs(EPOCH_KEY_GROUP)) {
      const key = this.#groupKey('default', ep)
      if (key !== undefined) out.set(ep, key.slice())
    }
    return out
  }

  async installEpochKey(epoch: number, key: Uint8Array): Promise<void> {
    check(Number.isSafeInteger(epoch) && epoch >= 0 && key instanceof Uint8Array && key.length === 32, 'EPOCH_KEY_INVALID')
    await this.#keys.install(EPOCH_KEY_GROUP, epoch, key)
  }

  async installRingKey(ring: string, epoch: number, key: Uint8Array): Promise<void> {
    check(typeof ring === 'string' && ring.length > 0 && ring !== 'default', 'RING_NAME_INVALID')
    check(Number.isSafeInteger(epoch) && epoch >= 0 && key instanceof Uint8Array && key.length === 32, 'EPOCH_KEY_INVALID')
    await this.#keys.install(ringKeyGroup(ring), epoch, key)
  }

  ringKey(ring: string, epoch: number): Uint8Array | null {
    return this.#groupKey(ring, epoch)?.slice() ?? null
  }

  /**
   * Zero every symmetric secret this session holds in memory (epoch, ring and vault keys, TreeKEM
   * node seeds). `purgeStore: true` also deletes their persisted copies (ephemeral hosts); a
   * durable device keeps them so it can reopen. `close()` calls this without `purgeStore`.
   */
  async wipeSecrets(options: { readonly purgeStore?: boolean } = {}): Promise<void> {
    this.#keys.wipe()
    this.#scannedKeyTopics.clear()
    if (options.purgeStore === true) await this.#keys.purgePersisted()
  }

  /**
   * Heal any admitted reader missing HPKE lockboxes in `$keys` for epochs we hold
   * (e.g. concurrent admission + epoch rotation, multisig approvals, or late wrapKey addition).
   * Only grants `$keys` accepts are attempted: as an administrator for every reader, otherwise
   * only for members this identity admitted (`admittedBy`).
   */
  async backfillMissingEpochBoxes(options: { readonly minEpoch?: number } = {}): Promise<number> {
    if (!this.genesis.privateLog || this.#blindHostMode) return 0
    await this.#flushPendingMaterialization()
    const keysState = this.keysState()
    if (keysState.currentEpoch < 0) return 0
    const minEp = Math.max(0, options.minEpoch ?? 0)
    const members = this.permissions().members
    const self = this.identity.publicKey
    const isAdmin = this.permissions().administrators?.includes(self) === true
    let sealedMembers = 0
    for (const member of members) {
      if (!member.reader || (!member.wrapKey && !member.pqWrapKey)) continue
      if (!isAdmin && member.admittedBy !== self) continue
      const epochBoxes: Record<string, EpochKeyBox> = {}
      for (let ep = minEp; ep <= keysState.currentEpoch; ep++) {
        const epKey = this.#groupKey('default', ep)
        if (epKey === undefined) continue
        const epEntry = keysState.epochs?.[String(ep)]
        if (epEntry?.boxes?.[member.publicKey] !== undefined) continue
        if (Array.isArray(epEntry?.activeMembers) && epEntry.activeMembers.includes(member.publicKey)) continue
        const sealed = await this.#sealBoxForMember(member, epKey, this.logId, ep)
        if (sealed !== null) epochBoxes[String(ep)] = sealed
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
      const uniqueKeys = new Set<string>()
      const prefix = `${this.#prefix}/`
      // Drain the change feed: stores may page it (IndexedDB returns at most 4096 changes per call).
      // The cursor advances only over changes actually read here, never past a sibling's commit;
      // this replica's own writes are in the feed too and are skipped below without a store read.
      let rescan: number | null = null
      for (;;) {
        const { latestSeq, changes, reset } = await this.#store.readChangesSince!(this.#lastSyncSeq)
        // The store pruned its changelog below our cursor: rescan everything, resume at latestSeq.
        if (reset === true) { rescan = latestSeq; break }
        let next = this.#lastSyncSeq
        for (const ch of changes) {
          if (ch.seq > next) next = ch.seq
          if (ch.deleted) continue
          if (ch.key.startsWith('cas/') || (ch.key.startsWith(prefix) && ch.key !== `${prefix}materialized-cache`)) {
            uniqueKeys.add(ch.key)
          }
        }
        if (changes.length === 0) next = Math.max(next, latestSeq)
        if (next <= this.#lastSyncSeq) break
        this.#lastSyncSeq = next
        if (changes.length === 0) break
      }
      let changed = false
      // `changed` only for entries newly indexed here (sibling writes), never for own or known ones.
      const ingest = async (entry: BytesStoreEntry): Promise<void> => {
        if (entry.key.startsWith('cas/')) {
          const known = this.#holdsStoreKey(entry.key)
          this.cas.indexPersistedEntry(entry, { verifyHash: false })
          if (!known && this.#holdsStoreKey(entry.key)) changed = true
          return
        }
        if (entry.key === `${prefix}materialized-cache` || !entry.key.startsWith(prefix)) return
        if (await this.#ingestSingleStoreEntry(entry, FACTS_SOURCE_STORE)) changed = true
      }
      if (rescan !== null) {
        for (const entry of await readAllStoreEntries(this.#store)) {
          if (!this.#holdsStoreKey(entry.key)) await ingest(entry)
        }
        this.#lastSyncSeq = rescan
      } else {
        for (const key of uniqueKeys) {
          if (this.#holdsStoreKey(key)) continue
          const val = await this.#store.get(key)
          if (val !== null) await ingest({ key, value: val })
        }
      }
      if (changed) {
        await this.#rematerialize()
        this.#emitFacts()
      }
      return changed
    })
  }

  /** True when the fact a store key holds is already in memory (own writes seen in the change feed). */
  #holdsStoreKey(key: string): boolean {
    if (key.startsWith('cas/')) {
      const rest = key.slice('cas/'.length)
      if (rest.startsWith('pub/')) return this.cas.hasSync(rest.slice(4), 'public')
      if (rest.startsWith('priv/')) return this.cas.hasSync(rest.slice(5), 'private')
      return false
    }
    const rest = key.slice(this.#prefix.length + 1)
    if (rest.startsWith('public-op/')) return this.#publicOps.has(rest.slice('public-op/'.length))
    if (rest.startsWith('enc-env/')) return this.#encryptedEnvelopes.has(rest.slice('enc-env/'.length))
    if (rest.startsWith('local-pending/')) return this.#localPending.has(rest.slice('local-pending/'.length))
    if (rest.startsWith('evidence/')) return this.#evidence.has(rest.slice('evidence/'.length))
    return false
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

  /**
   * Persist the materialized cache soon: immediately (next task) when no cache has been written for
   * this replica yet, so a reload right after the first materialization already opens warm;
   * otherwise debounced. Also flushed on close and when the page is hidden.
   */
  #scheduleCachePersist(): void {
    if (this.#closed || this.#cachePersistTimer !== undefined) return
    const delay = this.#lastPersistedCacheDigest === '' ? 0 : 1_500
    this.#cachePersistTimer = setTimeout(() => {
      this.#cachePersistTimer = undefined
      void this.#serial(() => this.#persistMaterializedCacheNow()).catch(() => undefined)
    }, delay)
    this.#cachePersistTimer.unref?.()
  }

  /** Write the materialized cache now (hosts call this on visibility change / before unload). */
  flushMaterializedCache(): Promise<void> {
    if (this.#closed) return Promise.resolve()
    if (this.#cachePersistTimer !== undefined) { clearTimeout(this.#cachePersistTimer); this.#cachePersistTimer = undefined }
    return this.#serial(() => this.#persistMaterializedCacheNow())
  }

  #installVisibilityFlush(): void {
    const doc = (globalThis as { readonly document?: { readonly visibilityState?: string; addEventListener?(type: string, fn: () => void): void; removeEventListener?(type: string, fn: () => void): void } }).document
    const win = globalThis as { addEventListener?(type: string, fn: () => void): void; removeEventListener?(type: string, fn: () => void): void }
    if (doc?.addEventListener === undefined || typeof win.addEventListener !== 'function') return
    const onHidden = (): void => { if (doc.visibilityState !== 'visible') void this.flushMaterializedCache().catch(() => undefined) }
    doc.addEventListener('visibilitychange', onHidden)
    win.addEventListener('pagehide', onHidden)
    this.#visibilityCleanup = () => { doc.removeEventListener?.('visibilitychange', onHidden); win.removeEventListener?.('pagehide', onHidden) }
  }

  async #persistMaterializedCacheNow(): Promise<void> {
    if (this.#closed) return
    const rev = this.#lastLocalRevision.digest
    if (
      this.#provisionalSnapshot !== null || // unverified snapshot state is never persisted
      this.#kernel.pendingDependencies.length > 0 ||
      (this.#kernel.materializedOutcomes.length === 0 && this.#kernel.frontierOrderLength === 0) ||
      rev === this.#lastPersistedCacheDigest
    ) {
      return
    }
    try {
      await this.#kernel.commitSeenOpsRoot()
      const cache = this.#kernel.exportMaterializedCache()
      await this.#store.put(`${this.#prefix}/materialized-cache`, encodeMaterializedCache(cache), { durability: 'relaxed' })
      for (const id of cache.orderOpIds) this.#trustedOpIds.add(id)
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

  async #ensureSqliteIfNeeded(reducersOverride?: JsonValue | null, mountsOverride?: JsonValue | null): Promise<boolean> {
    if (this.#sqliteDriver !== undefined) return !this.#kernelHasSqlite
    const memoKey = `${reducersOverride !== undefined ? JSON.stringify(reducersOverride) : `hash:${this.#kernel.topicHash('$reducers') ?? ''}`}\0${mountsOverride !== undefined ? JSON.stringify(mountsOverride) : `mhash:${this.#kernel.topicHash('$mounts') ?? ''}`}`
    if (this.#sqliteScanNegative.has(memoKey)) return false
    const reducersRaw = reducersOverride !== undefined ? reducersOverride : this.#kernel.topic('$reducers')
    if (reducersRaw === null) return false
    let needsSqlite = false, incomplete = false
    try {
      const queue: string[] = []
      const visited = new Set<string>()
      const checkReducersCfg = (cfgRaw: JsonValue): void => {
        const c = assertValidReducersConfig(cfgRaw)
        for (const [topicName, binding] of Object.entries(c.topics)) {
          if (this.#blindHostMode && this.genesis.privateLog && !isControlTopic(topicName)) continue
          const ref = tryParseCasRef(binding.module) !== null ? binding.module : c.imports[binding.module]
          if (binding.module === 'chronolog:sqlite' || binding.module === 'chronolog/sql' || binding.module === 'chronolog/sqlite-helpers' || binding.module === 'chronolog/registry') {
            needsSqlite = true
            return
          }
          if (ref !== undefined) queue.push(ref)
          queue.push(binding.module)
        }
      }
      const cfg = assertValidReducersConfig(reducersRaw)
      checkReducersCfg(reducersRaw)
      // Also inspect any mounted external logs' $reducers so ctx.mountQuery() against SQLite mounts works!
      const mountsRaw = mountsOverride !== undefined ? mountsOverride : this.#kernel.topic('$mounts')
      if (!needsSqlite && mountsRaw !== null && typeof mountsRaw === 'object' && !Array.isArray(mountsRaw)) {
        const mountsMap = (mountsRaw as Readonly<Record<string, JsonValue>>).mounts
        if (mountsMap !== null && typeof mountsMap === 'object' && !Array.isArray(mountsMap)) {
          for (const mountEntry of Object.values(mountsMap)) {
            if (mountEntry !== null && typeof mountEntry === 'object' && !Array.isArray(mountEntry)) {
              const mt = (mountEntry as Readonly<Record<string, JsonValue>>).topics
              if (mt !== null && typeof mt === 'object' && !Array.isArray(mt)) {
                const mtRec = mt as Readonly<Record<string, JsonValue>>
                if (mtRec.$reducers !== undefined) {
                  try { checkReducersCfg(mtRec.$reducers) } catch { /* ignore invalid mount */ }
                }
              }
            }
          }
        }
      }
      const importSpecRe = /\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/gu
      while (!needsSqlite && queue.length > 0) {
        const item = queue.shift()!
        if (visited.has(item)) continue
        visited.add(item)
        if (item === 'chronolog:sqlite' || item === 'chronolog/sql' || item === 'chronolog/sqlite-helpers' || item === 'chronolog/registry') {
          needsSqlite = true
          break
        }
        const directHash = tryParseCasRef(item)
        const ref = directHash !== null ? item : cfg.imports[item]
        if (ref === undefined || !ref.startsWith('cas:sha256-')) continue
        const hash = ref.slice(11)
        const node = await this.cas.get(hash, 'any')
        if (node === null) { incomplete = true; continue }
        const pkg = tryDecodePackageNode(node.bytes)
        if (pkg !== null) {
          if (pkg.builtins.includes('chronolog:sqlite')) {
            needsSqlite = true
            break
          }
          for (const depRef of Object.values(pkg.dependencies)) {
            if (!visited.has(depRef)) queue.push(depRef)
          }
          continue
        }
        const text = new TextDecoder().decode(node.bytes)
        if (text.includes('chronolog:sqlite') || text.includes('chronolog/sql') || text.includes('chronolog/sqlite-helpers') || text.includes('chronolog/registry')) {
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

  async #refreshAdmissionCache(kernel: TopicKernel = this.#kernel): Promise<void> {
    const admHash = `${kernel.topicHash('$admission') ?? ''}:${kernel.topicHash('$reducers') ?? ''}`
    if (this.#evaluatedRoster !== null && admHash === this.#lastAdmissionHash) {
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
      const roster = await kernel.query('$admission', { kind: 'roster' })
      if (roster !== null && typeof roster === 'object' && !Array.isArray(roster)) {
        const s = roster as Record<string, unknown>
        const readers = parseStringList(s.readers)
        const writers = parseStringList(s.writers)
        const admins = parseStringList(s.administrators)
        const pubs = parseStringList(s.publishers)
        const blocked = parseStringList(s.blockedAuthors)
        const admission = (s.admission !== null && typeof s.admission === 'object' && !Array.isArray(s.admission))
          ? s.admission as { readonly hostKey?: string }
          : null
        const guardians = (s.guardians !== null && typeof s.guardians === 'object' && !Array.isArray(s.guardians))
          ? s.guardians as GuardiansConfig
          : null
        const recoveryRequests = (s.recoveryRequests !== null && typeof s.recoveryRequests === 'object' && !Array.isArray(s.recoveryRequests))
          ? s.recoveryRequests as Record<string, RecoveryRequestRecord>
          : {}
        const msRaw = s.multisig
        const multisig: AdmissionMultisigInfo | null =
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
        const mode: EvaluatedAdmissionRoster['mode'] =
          s.mode === 'attested' || s.mode === 'open' || s.mode === 'multisig'
            ? s.mode
            : multisig !== null ? 'multisig' : (openReaders || openWriters) ? 'open' : admission !== null ? 'attested' : 'custom'
        this.#evaluatedRoster = {
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
          guardians,
          recoveryRequests,
          multisig,
        }
        this.#lastAdmissionHash = admHash
        return
      }
    } catch {
      // Fail closed if $admission cannot be evaluated
    }
    this.#evaluatedRoster = null
    this.#lastAdmissionHash = admHash
  }

  /** Index one persisted store entry; `source` tags facts a sibling tab wrote (FACTS_SOURCE_STORE). */
  async #ingestSingleStoreEntry(entry: BytesStoreEntry, source?: string): Promise<boolean> {
    const prefix = `${this.#prefix}/`
    if (!entry.key.startsWith(prefix)) return false
    const rest = entry.key.slice(prefix.length)
    if (rest.startsWith(KeyStore.STORE_SEGMENT)) {
      return this.#keys.hydrate(rest, entry.value)
    } else if (rest.startsWith('public-op/')) {
      const keyOpId = rest.slice('public-op/'.length)
      if (this.#publicOps.has(keyOpId)) return false
      try {
        // Trust shortcut: public ops in this device's own store were Ed25519-verified and keyed by
        // their verified op id at ingress, so cold open neither re-hashes nor re-verifies them.
        if (!/^[0-9a-f]{64}$/u.test(keyOpId)) return false
        const signed = decodeTrustedSignedOperation(entry.value)
        const core = decodeTrustedOperationCore(signed.coreBytes)
        const opId = keyOpId
        if (bytesToHex(core.logId) === this.logId && core.visibility === 'public' && !this.#publicOps.has(opId)) {
          this.#publicOps.setFrom(opId, { raw: entry.value.slice(), signed, core }, source)
          return true
        }
      } catch { /* ignore corrupt entry */ }
    } else if (rest.startsWith('enc-env/')) {
      const keyDigest = rest.slice('enc-env/'.length)
      if (this.#encryptedEnvelopes.has(keyDigest)) return false
      try {
        // The store key is the envelope digest this replica computed when it stored the bytes.
        if (!/^[0-9a-f]{64}$/u.test(keyDigest)) return false
        const envelope = decodeTrustedEncryptedEnvelope(entry.value)
        if (bytesToHex(envelope.logId) === this.logId) {
          const digest = keyDigest
          if (!this.#encryptedEnvelopes.has(digest)) {
            this.#encryptedEnvelopes.setFrom(digest, { digest, raw: entry.value, envelope, fromStore: true }, source)
            this.#undecryptedEnvelopes.add(digest)
            return true
          }
        }
      } catch { /* ignore corrupt entry */ }
    } else if (rest.startsWith('local-pending/')) {
      try {
        const rec = decodeLocalPending(entry.value)
        const signed = decodeTrustedSignedOperation(rec.raw)
        const core = decodeTrustedOperationCore(signed.coreBytes)
        const opId = rest.slice('local-pending/'.length)
        if (/^[0-9a-f]{64}$/u.test(opId) && !this.#localPending.has(opId)) {
          this.#trustedOpIds.add(opId) // authored and signed by this device
          this.#localPending.set(opId, {
            raw: rec.raw,
            signed,
            core,
            currentEnvelopeDigest: rec.envelopeDigest,
            currentEpoch: rec.epoch,
            currentCommitment: rec.commitment,
          })
          return true
        }
      } catch { /* ignore */ }
    } else if (rest.startsWith('retention/')) {
      try {
        const ev = decodeRecord<RetentionEvidence>(entry.value)
        if (Array.isArray(ev.payload.items) && this.#indexRetention(ev)) return true
      } catch { /* ignore */ }
    } else if (rest.startsWith('evidence/')) {
      const key = rest.slice('evidence/'.length)
      if (this.#evidence.has(key)) return false
      try {
        const ev = decodeRecord<AdmissionEvidence>(entry.value)
        const computedKey = await evidenceDigest(ev)
        if (!this.#evidence.has(computedKey)) {
          this.#evidence.setFrom(computedKey, ev, source)
          return true
        }
      } catch { /* ignore */ }
    } else if (rest === 'pinned-frontier') {
      try {
        const pf = decodeRecord<PinnedFrontier>(entry.value)
        if (pf && typeof pf.closedThroughMs === 'bigint' && typeof pf.stateRoot === 'string' && typeof pf.historyDigest === 'string' && Array.isArray(pf.includedOpIds)) {
          this.#pinnedFrontier = pf
          return true
        }
      } catch { /* ignore */ }
    } else if (rest === 'materialized-cache') {
      const cached = decodeMaterializedCache(entry.value)
      if (cached !== null && cached.logId === this.logId && cached.blindHostMode === this.#blindHostMode) {
        this.#pendingMaterializedCache = cached
        // Suffix ops of a persisted cache passed signature + id verification on this replica before
        // they were folded in. Frontier ids came from a snapshot this replica did not replay, so
        // they never enter the trusted set.
        for (const id of cached.orderOpIds) this.#trustedOpIds.add(id)
      }
    }
    return false
  }

  async #hydrateFromEntries(entries: readonly BytesStoreEntry[]): Promise<void> {
    for (const entry of entries) {
      await this.#ingestSingleStoreEntry(entry)
    }
  }

  /**
   * Decode a v3 snapshot bundle (see snapshot-codec.ts): decrypts private-log bundles with the
   * epoch key and checks the bundle's Ed25519 signature (integrity only; trust is decided by
   * `#adoptSnapshotFrontier`).
   */
  async #decodeMaterializedSnapshot(bytes: Uint8Array): Promise<{
    readonly cache: KernelMaterializedCache
    readonly casNodes: readonly SessionCasNode[]
  } | null> {
    if (this.genesis.privateLog && this.#blindHostMode) return null
    const decoded = await decodeSnapshotBundle(bytes, this.logId, epoch => this.#groupKey('default', epoch))
    if (decoded === null) return null
    if (decoded.cache.blindHostMode !== this.#blindHostMode) return null
    return { cache: decoded.cache, casNodes: decoded.casNodes }
  }

  #keysStateFrom(kernel: TopicKernel): KeysTopicState {
    const raw = kernel.topic('$keys') as KeysTopicState | null
    if (raw === null || typeof raw !== 'object') return { currentEpoch: -1, epochs: {} }
    return raw
  }

  #currentEpochFrom(kernel: TopicKernel): number {
    const state = this.#keysStateFrom(kernel)
    if (state.currentEpoch >= 0) return state.currentEpoch
    const held = this.#keys.epochs(EPOCH_KEY_GROUP)
    return held.length > 0 ? held[held.length - 1]! : -1
  }

  async #storeTreeNodeSeeds(seeds: ReadonlyMap<string, Uint8Array>): Promise<void> {
    for (const [pubKeyHash, seed] of seeds) await this.#keys.install(TREE_SEED_GROUP, 0, seed, pubKeyHash)
  }

  async #installVaultKey(topic: string, vaultId: string, epoch: number, key: Uint8Array): Promise<void> {
    await this.#keys.install(vaultKeyGroup(topic, vaultId), epoch, key)
  }

  #vaultState(topic: string, vaultId: string, kernel: TopicKernel = this.#kernel): VaultTopicEntry | undefined {
    const raw = kernel.topic(topic) as { readonly vaults?: Record<string, unknown> } | null
    const vault = raw !== null && typeof raw === 'object' ? raw.vaults?.[vaultId] : undefined
    return vault !== null && typeof vault === 'object' ? vault : undefined
  }

  /** The held vault key whose commitment matches the vault topic's on-log `keyCommitment`. */
  #getVaultKey(vaultId: string, epoch: number, topic = 'vaults'): Uint8Array | undefined {
    const commitment = this.#vaultState(topic, vaultId)?.epochs?.[String(epoch)]?.keyCommitment
    return this.#keys.get(vaultKeyGroup(topic, vaultId), epoch, commitment)
  }

  /** Topics bound to `chronolog/vaults` (memoized per `$reducers` hash). */
  #vaultTopicsMemo: { readonly reducersHash: string; readonly topics: readonly string[] } | null = null
  #vaultTopics(kernel: TopicKernel): readonly string[] {
    const reducersHash = kernel.topicHash('$reducers') ?? ''
    if (this.#vaultTopicsMemo?.reducersHash === reducersHash) return this.#vaultTopicsMemo.topics
    const reducers = kernel.topic('$reducers') as {
      readonly imports?: Record<string, string>
      readonly topics?: Record<string, { readonly module?: string }>
    } | null
    const importsCfg = reducers?.imports ?? {}
    const topics: string[] = []
    for (const [topicName, binding] of Object.entries(reducers?.topics ?? {})) {
      if (isControlTopic(topicName)) continue
      const mod = binding?.module
      if (topicName === 'vaults' || mod === 'chronolog/vaults' || (typeof mod === 'string' && importsCfg[mod] === 'chronolog/vaults')) topics.push(topicName)
    }
    this.#vaultTopicsMemo = { reducersHash, topics }
    return topics
  }

  /**
   * Open this device's vault lockboxes. A vault topic is rescanned only when its hash changed;
   * a key is installed only when it matches the on-log `keyCommitment`, and a lockbox that failed
   * to open is never retried.
   */
  async #unsealAvailableVaultKeys(kernel: TopicKernel = this.#kernel): Promise<boolean> {
    if (this.#blindHostMode) return false
    let unlockedAny = false
    for (const topicName of this.#vaultTopics(kernel)) {
      const hash = kernel.topicHash(topicName) ?? ''
      const scanKey = `vault-topic:${topicName}`
      if (this.#scannedKeyTopics.get(scanKey) === hash) continue
      this.#scannedKeyTopics.set(scanKey, hash)
      const raw = kernel.topic(topicName) as { readonly vaults?: Record<string, VaultTopicEntry> } | null
      if (!raw || typeof raw !== 'object' || !raw.vaults || typeof raw.vaults !== 'object') continue
      for (const [vaultId, vault] of Object.entries(raw.vaults)) {
        const group = vaultKeyGroup(topicName, vaultId)
        for (const entry of Object.values(vault?.epochs ?? {})) {
          const commitment = entry.keyCommitment
          if (typeof commitment !== 'string') continue
          if (this.#keys.has(group, entry.epoch, commitment)) continue
          const box = entry.boxes?.[this.identity.publicKey]
          if (box === undefined) continue
          const attempt = `${commitment}:${box.encapsulatedKey.slice(0, 64)}`
          if (this.#keys.isFailed(group, entry.epoch, attempt)) continue
          try {
            const plainKey = await hpkeOpenEpochKey(
              this.device.wrapKey.privateKey,
              this.device.wrapKey.publicKey,
              box,
              `${this.logId}:vault:${vaultId}`,
              entry.epoch,
              this.device.pqWrapKey?.secretKey,
            )
            if (epochKeyCommitment(plainKey) !== commitment) { this.#keys.markFailed(group, entry.epoch, attempt); continue }
            await this.#keys.install(group, entry.epoch, plainKey, commitment)
            unlockedAny = true
          } catch {
            this.#keys.markFailed(group, entry.epoch, attempt) // not our box or corrupted
          }
        }
      }
    }
    return unlockedAny
  }

  /** Open one HPKE lockbox for `(group, epoch)` and install it if it matches `commitment`. */
  async #openLockbox(group: string, scope: string, epoch: number, commitment: string, box: EpochKeyBox): Promise<boolean> {
    // A replaced lockbox (wrap-key rotation) is a new attempt; a failed one is never retried.
    const attempt = `${commitment}:${box.encapsulatedKey.slice(0, 64)}`
    if (this.#keys.isFailed(group, epoch, attempt)) return false
    try {
      const plainKey = await hpkeOpenEpochKey(
        this.device.wrapKey.privateKey,
        this.device.wrapKey.publicKey,
        box,
        scope,
        epoch,
        this.device.pqWrapKey?.secretKey,
      )
      if (epochKeyCommitment(plainKey) !== commitment) { this.#keys.markFailed(group, epoch, attempt); return false }
      await this.#keys.install(group, epoch, plainKey, commitment)
      return true
    } catch {
      this.#keys.markFailed(group, epoch, attempt) // wrong wrap key or corrupted lockbox
      return false
    }
  }

  /**
   * Open every default-ring and compartment-ring lockbox (flat or TreeKEM) addressed to this
   * device whose on-log commitment it does not hold yet. Skipped while `$keys` is unchanged and no
   * TreeKEM node is still missing; missing tree nodes are reported via `missingCasDependencies()`
   * (pulled from peers with `cas-want` and from `casMirrors`).
   */
  async #unsealAvailableEpochKeys(kernel: TopicKernel = this.#kernel): Promise<boolean> {
    if (!this.genesis.privateLog || this.#blindHostMode) return false
    const keysHash = kernel.topicHash('$keys') ?? ''
    if (this.#scannedKeyTopics.get('$keys') === keysHash && this.#missingTreeCasHashes.size === 0) return false
    this.#scannedKeyTopics.set('$keys', keysHash)
    this.#missingTreeCasHashes.clear()
    const keys = this.#keysStateFrom(kernel)
    let unlockedAny = false
    for (const entry of Object.values(keys.epochs ?? {})) {
      const commitment = entry.keyCommitment
      if (typeof commitment !== 'string' || this.#keys.has(EPOCH_KEY_GROUP, entry.epoch, commitment)) continue
      if (typeof entry.treeRef === 'string') {
        const hash = tryParseCasRef(entry.treeRef)
        if (hash !== null) {
          const readRes = await readKeyTreeFromCas(hash, async h => (await this.cas.get(h, 'public'))?.bytes ?? null)
          if (!readRes.ok) {
            for (const missing of readRes.missingHashes) this.#missingTreeCasHashes.add(missing)
          } else if (!this.#keys.isFailed(EPOCH_KEY_GROUP, entry.epoch, `${commitment}:${entry.treeRef}`)) {
            try {
              const opened = await openTreeEpoch({
                scope: this.logId,
                payload: readRes.payload,
                keyCommitment: commitment,
                wrapPrivateKey: this.device.wrapKey.privateKey,
                wrapPublicKeyHex: this.device.wrapKey.publicKey,
                ...(this.device.pqWrapKey === undefined ? {} : {
                  pqSecretKey: this.device.pqWrapKey.secretKey,
                  pqPublicKeyHex: this.device.pqWrapKey.publicKey,
                }),
                cachedNodeSeeds: this.#keys.view(TREE_SEED_GROUP, 0),
              })
              if (opened !== null && epochKeyCommitment(opened.epochKey) === commitment) {
                await this.#keys.install(EPOCH_KEY_GROUP, entry.epoch, opened.epochKey, commitment)
                await this.#storeTreeNodeSeeds(opened.derivedSeeds)
                unlockedAny = true
                continue
              }
              this.#keys.markFailed(EPOCH_KEY_GROUP, entry.epoch, `${commitment}:${entry.treeRef}`)
            } catch {
              // Corrupt tree node or not in the active tree; a flat box below may still open.
              this.#keys.markFailed(EPOCH_KEY_GROUP, entry.epoch, `${commitment}:${entry.treeRef}`)
            }
          }
        }
      }
      const box = entry.boxes?.[this.identity.publicKey]
      if (box === undefined) continue
      if (await this.#openLockbox(EPOCH_KEY_GROUP, this.logId, entry.epoch, commitment, box)) unlockedAny = true
    }
    for (const [ringName, ringState] of Object.entries(keys.rings ?? {})) {
      const group = ringKeyGroup(ringName)
      for (const entry of Object.values(ringState.epochs ?? {})) {
        if (typeof entry.keyCommitment !== 'string' || this.#keys.has(group, entry.epoch, entry.keyCommitment)) continue
        const box = entry.boxes?.[this.identity.publicKey]
        if (box === undefined) continue
        if (await this.#openLockbox(group, `${this.logId}:${ringName}`, entry.epoch, entry.keyCommitment, box)) unlockedAny = true
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
      // AES-GCM authenticates the key, so trying every held candidate for this epoch is safe; the
      // on-log commitment goes first (the others only exist after a lost concurrent rotation).
      const candidates = this.#keys.candidates(ringKeyGroup(ring), entry.envelope.epoch, this.#onLogCommitment(ring, entry.envelope.epoch))
      // Own pending ops: the local-pending record already holds the signed plaintext for exactly
      // this envelope, so there is nothing to decrypt or verify.
      const pending = this.#localPending.get(bytesToHex(entry.envelope.opId))
      if (pending !== undefined && pending.currentEnvelopeDigest === digest) {
        entry.decrypted = { opId: bytesToHex(entry.envelope.opId), signed: pending.signed, core: pending.core }
        this.#undecryptedEnvelopes.delete(digest)
        continue
      }
      if (candidates.length === 0) continue
      // Decrypt + verify concurrently (WebCrypto runs these off the JS thread where available).
      work.push((async () => {
        try {
          const aad = envelopeAad(entry.envelope.logId, entry.envelope.opId, entry.envelope.author, ring)
          let plaintext: Uint8Array | undefined
          for (const epochKey of candidates) {
            try {
              plaintext = await decryptEpochPayload(epochKey, {
                epoch: BigInt(entry.envelope.epoch),
                nonce: entry.envelope.nonce,
                ciphertext: entry.envelope.ciphertext,
              }, aad)
              break
            } catch { /* next candidate */ }
          }
          if (plaintext === undefined) return
          let verified: { readonly core: OperationCore; readonly opId: Uint8Array }
          let signed: SignedOperation
          const trustedId = entry.fromStore === true ? bytesToHex(entry.envelope.opId) : null
          if (trustedId !== null && this.#trustedOpIds.has(trustedId)) {
            // Trust shortcut (cold open): this envelope came from our own store and its op id was
            // verified before. Binding the plaintext to that id (op id = hash of the core bytes)
            // is enough; the Ed25519 signature over identical core bytes was already checked.
            signed = decodeTrustedSignedOperation(plaintext)
            const opId = operationIdDigest(signed.coreBytes)
            if (bytesToHex(opId) !== trustedId) return
            verified = { core: decodeTrustedOperationCore(signed.coreBytes), opId }
          } else {
            signed = decodeSignedOperation(plaintext)
            verified = await verifySignedOperation(signed)
          }
          if (bytesToHex(verified.core.logId) !== this.logId) return
          if (verified.core.visibility !== 'encrypted') return
          const isAnonymousEnv = sameBytes(entry.envelope.author, ANONYMOUS_AUTHOR)
          if (!sameBytes(verified.opId, entry.envelope.opId)) return
          if (!isAnonymousEnv && !sameBytes(verified.core.author, entry.envelope.author)) return
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
    const newestKey = this.#groupKey('default', newestEpoch, kernel)
    if (newestKey === undefined || !this.isWriter(this.identity.publicKey)) return false
    const newestCommitment = epochKeyCommitment(newestKey)
    const keysState = this.#keysStateFrom(kernel)

    let rewrapped = false
    // #localPending holds only ops no remote member has retained yet (see #settleLocalPending).
    for (const [opId, pending] of this.#localPending) {
      const pendingRing = keysState.topicRings?.[pending.core.updates[0]?.topic ?? ''] ?? 'default'
      if (pendingRing !== 'default') continue
      if (pending.currentEpoch > newestEpoch) continue
      // Same epoch is only rewrapped when it was sealed under a key that lost a concurrent rotation.
      if (pending.currentEpoch === newestEpoch && (
        pending.currentCommitment === newestCommitment ||
        this.#onLogCommitment('default', pending.currentEpoch, kernel) === pending.currentCommitment
      )) continue
      const logIdBytes = hexToBytes(this.logId)
      const opIdBytes = hexToBytes(opId)
      const env = await this.#encryptOperationEnvelope({
        epochKey: newestKey,
        epoch: newestEpoch,
        opBytes: pending.raw,
        logIdBytes,
        opIdBytes,
        authorBytes: pending.core.author,
        ring: 'default',
      })
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
      pending.currentCommitment = newestCommitment
      await this.#store.put(`${this.#prefix}/local-pending/${opId}`, encodeLocalPending(pending.raw, envDigest, newestEpoch, newestCommitment))
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
  /** `${visibility}\0${operationId}` -> opId for ops authored by this identity (submit idempotency). */
  readonly #ownOpsByIdempotencyKey = new Map<string, string>()
  #kernelInput(opId: string, core: OperationCore, envelope?: { readonly ring: string; readonly epoch: number }): KernelOperationInput {
    let input = this.#kernelInputs.get(opId)
    const ring = envelope?.ring
    const epoch = envelope?.epoch
    if (input === undefined || input.core !== core || input.ring !== ring || input.epoch !== epoch) {
      input = { opId: hexToBytes(opId), core, verified: true, ...(envelope === undefined ? {} : { ring: envelope.ring, epoch: envelope.epoch }) }
      this.#kernelInputs.set(opId, input)
      if (bytesToHex(core.author) === this.identity.publicKey) {
        this.#ownOperationIds.set(core.operationId, opId)
        this.#ownOpsByIdempotencyKey.set(`${core.visibility}\0${core.operationId}`, opId)
      }
    }
    return input
  }

  #collectDecryptedKernelInputs(): Map<string, KernelOperationInput> {
    const byOpId = new Map<string, KernelOperationInput>()
    for (const [opId, entry] of this.#publicOps) {
      byOpId.set(opId, this.#kernelInput(opId, entry.core))
    }
    if (!this.#blindHostMode) {
      // An op held under several envelopes (offline rewrap) counts against the lowest epoch it was
      // sealed under, so the `$keys.policy.maxOpsPerEpoch` input never depends on arrival order.
      const chosen = new Map<string, { readonly core: OperationCore; readonly ring: string; readonly epoch: number }>()
      for (const entry of this.#encryptedEnvelopes.values()) {
        if (entry.decrypted === undefined) continue
        const opId = entry.decrypted.opId
        if (byOpId.has(opId)) continue
        const prev = chosen.get(opId)
        if (prev === undefined || entry.envelope.epoch < prev.epoch) {
          chosen.set(opId, { core: entry.decrypted.core, ring: entry.envelope.ring ?? 'default', epoch: entry.envelope.epoch })
        }
      }
      for (const [opId, c] of chosen) byOpId.set(opId, this.#kernelInput(opId, c.core, { ring: c.ring, epoch: c.epoch }))
    }
    return byOpId
  }

  /** Swap in a SQLite-capable kernel before restoring state whose reducers need chronolog:sqlite. */
  /** A fresh kernel for this log (session blind mode unless `blind` is set; SQLite once loaded). */
  #newKernel(options: { readonly blind?: boolean } = {}): TopicKernel {
    return new TopicKernel({
      genesis: this.genesisBytes,
      cas: this.cas,
      blindHostMode: options.blind ?? this.#blindHostMode,
      ...this.#sandboxOptions,
      ...(this.#sqliteDriver === undefined ? {} : { sqliteDriver: this.#sqliteDriver }),
    })
  }

  /** Swap the main kernel (frontier, final view and provisional snapshot state go with it). */
  #replaceKernel(next: TopicKernel): void {
    if (next !== this.#kernel) this.#kernel.dispose()
    this.#kernel = next
    this.#kernelHasSqlite = this.#sqliteDriver !== undefined
    this.#finalKernel?.dispose()
    this.#finalKernel = null
    this.#provisionalSnapshot = null
  }

  /** Swap in a SQLite-capable kernel before restoring state whose reducers need chronolog:sqlite. */
  async #upgradeKernelForSqlite(reducers: JsonValue | undefined): Promise<void> {
    if (this.#kernelHasSqlite || !await this.#ensureSqliteIfNeeded(reducers) || this.#sqliteDriver === undefined) return
    this.#replaceKernel(this.#newKernel())
  }

  /** Kernel whose `$*` state drives control decisions (own control kernel while a snapshot is provisional). */
  #controlView(): TopicKernel {
    if (this.#provisionalSnapshot !== null) return this.#admittedControlKernel ?? this.#controlKernel ?? this.#kernel
    return this.#kernel
  }

  /**
   * True when `(stateRoot, historyDigest, covered op set)` equals admission checkpoint evidence this
   * replica verified, or the frontier it pinned itself.
   */
  #snapshotIsAttested(snapshot: { readonly stateRoot: string; readonly historyDigest: string; readonly opIds: readonly string[] }): boolean {
    const digest = computeIncludedSetDigest(snapshot.opIds)
    const pf = this.#pinnedFrontier
    if (pf !== null && pf.stateRoot === snapshot.stateRoot && pf.historyDigest === snapshot.historyDigest &&
      computeIncludedSetDigest(pf.includedOpIds) === digest) return true
    for (const ev of this.#admissionDecision.verifiedEvidence) {
      const p = ev.payload as Partial<AdmissionCheckpointPayload> | null
      if (p === null || typeof p !== 'object' || p.logId !== this.logId) continue
      if (p.stateRoot !== snapshot.stateRoot || p.historyDigest !== snapshot.historyDigest) continue
      if (!Array.isArray(p.inclusions)) continue
      const opIds: string[] = []
      let valid = true
      for (const item of p.inclusions as readonly unknown[]) {
        if (typeof item !== 'object' || item === null || typeof (item as { readonly opId?: unknown }).opId !== 'string') {
          valid = false
          break
        }
        opIds.push((item as { readonly opId: string }).opId)
      }
      if (!valid || computeIncludedSetDigest(opIds) !== digest) continue
      return true
    }
    return false
  }

  /**
   * The ONE snapshot adoption path (peer `snapshot` message, `importMaterializedSnapshot`,
   * host-cached `materializedSnapshot`, `admission.bootstrapFromCheckpoint`): the snapshot's state
   * becomes this replica's frontier, so the ops it covers are not replayed. Who signed a bundle
   * grants no trust (on open logs anyone is a member). Trust comes from:
   * - `'local'`: the bundle was produced by this deployment (host-cached `materializedSnapshot`),
   *   like the local materialized cache;
   * - evidence: `#snapshotIsAttested` (verified admission checkpoint or the local pinned frontier);
   * - otherwise the snapshot is provisional: first paint only, until `#verifyProvisionalSnapshot`
   *   replays the covered ops and confirms (or replaces) it.
   */
  async #adoptSnapshotFrontier(
    cache: KernelMaterializedCache,
    casNodes: readonly SessionCasNode[],
    trust: SnapshotTrust,
    options: { readonly force?: boolean } = {},
  ): Promise<boolean> {
    const opIds = [...cache.frontierOpIds, ...cache.orderOpIds]
    // Adopt the snapshot only when it is ahead of what this replica already materialized.
    if (options.force !== true && opIds.length <= this.#kernel.revision('local').orderLength) return false
    if (casNodes.length > 0) await this.cas.putManyVerified(casNodes)
    await this.#upgradeKernelForSqlite(cache.topics.$reducers)
    if (!await this.#kernel.restoreSnapshotFrontier(cache)) return false
    this.#materializedCacheHits++
    const snapshot = { stateRoot: cache.stateRoot, historyDigest: cache.historyDigest, opIds }
    this.#provisionalSnapshot = trust === 'local' || this.#snapshotIsAttested(snapshot) ? null : snapshot
    return true
  }

  /**
   * Confirm a provisional snapshot: as soon as admission evidence attests it, or every covered op is
   * held, replay exactly those ops on a fresh kernel. The replay becomes the main kernel either way;
   * if it does not reproduce the snapshot's stateRoot and historyDigest the snapshot was forged and
   * its state is gone (the next materialize folds the remaining ops on top of the replay).
   */
  async #verifyProvisionalSnapshot(allByOpId: ReadonlyMap<string, KernelOperationInput>): Promise<void> {
    const pending = this.#provisionalSnapshot
    if (pending === null) return
    if (this.#snapshotIsAttested(pending)) { this.#provisionalSnapshot = null; return }
    if (allByOpId.size < pending.opIds.length) return
    const inputs: KernelOperationInput[] = []
    for (const id of pending.opIds) {
      const input = allByOpId.get(id)
      if (input === undefined) return
      inputs.push(input)
    }
    const verifier = this.#newKernel()
    let adopted = false
    try {
      const replay = await verifier.materialize(inputs)
      if (replay.pendingDependencies.length > 0) return
      const rev = verifier.revision('local')
      if (rev.stateRoot !== pending.stateRoot || rev.historyDigest !== pending.historyDigest) this.#rejectedSnapshots++
      this.#replaceKernel(verifier)
      adopted = true
    } finally {
      if (!adopted) verifier.dispose()
    }
  }

  #rejectedSnapshots = 0

  /** True while the local state rests on an unverified snapshot frontier (first paint only). */
  get snapshotProvisional(): boolean {
    return this.#provisionalSnapshot !== null
  }

  /** Snapshots this replica adopted provisionally and then rejected because replay disagreed. */
  get rejectedSnapshots(): number {
    return this.#rejectedSnapshots
  }

  /**
   * Give up on a provisional snapshot that cannot be confirmed yet (call after reconciliation with
   * peers completed): drop the frontier and replay every op this replica holds.
   */
  settleProvisionalSnapshot(): Promise<boolean> {
    return this.#serial(async () => {
      if (this.#provisionalSnapshot === null) return false
      await this.#rematerialize()
      if (this.#provisionalSnapshot === null) return false
      this.#replaceKernel(this.#newKernel())
      await this.#rematerialize()
      return true
    })
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
        // Private log full replica: the public control pass runs on the isolated blind
        // #controlKernel (the admission probe), so this.#kernel never loses private ops or suffix
        // snapshots mid-rematerialization. Lockboxes are opened from the probe state (a superset;
        // keys are commitment-bound, so a key from an excluded rotation is never selected).
        await this.#controlKernel.materialize(publicInputs)
        await this.#unsealAvailableEpochKeys(this.#controlKernel)
        for (let hop = 0; hop < 8 && this.#missingTreeCasHashes.size > 0 && this.#casMirrors.length > 0; hop++) {
          const fetched = await this.#pullMissingFromMirrors()
          if (fetched === 0) break
          await this.#unsealAvailableEpochKeys(this.#controlKernel)
        }
        await this.#decryptPendingEnvelopes()
        allByOpId = this.#collectDecryptedKernelInputs()
        const control = await materializeControl({
          logId: this.logId,
          probe: this.#controlKernel,
          publicOps: publicInputs,
          admissionOps: [...allByOpId.values()].map(admissionOpRef),
          evidence: [...this.#evidence.values()],
          pinnedFrontier: this.#pinnedFrontier,
          admitted: () => this.#admittedControlKernel ??= this.#newKernel({ blind: true }),
        })
        this.#admissionDecision = control.admission
        controlKernel = control.control
        await this.#refreshAdmissionCache(controlKernel)
        rewrapped = await this.#rewrapPendingLocalOps(controlKernel)
      } else {
        // Public log or blind host: only public ops exist in the local kernel. With admission
        // evidence or a pinned frontier, a persistent probe kernel judges history so this.#kernel
        // never transiently exposes excluded operations (it folds only the admitted ops below).
        allByOpId = this.#collectDecryptedKernelInputs()
        if (this.#evidence.size > 0 || this.#pinnedFrontier !== null) {
          await this.#ensureSqliteIfNeeded()
          if (this.#probeKernel !== null && this.#sqliteDriver !== undefined && !this.#probeHasSqlite) {
            this.#probeKernel.dispose()
            this.#probeKernel = null
          }
          if (this.#probeKernel === null) {
            this.#probeKernel = this.#newKernel()
            this.#probeHasSqlite = this.#sqliteDriver !== undefined
          }
          const control = await materializeControl({
            logId: this.logId,
            probe: this.#probeKernel,
            publicOps: publicInputs,
            admissionOps: [...allByOpId.values()].map(admissionOpRef),
            evidence: [...this.#evidence.values()],
            pinnedFrontier: this.#pinnedFrontier,
            admitted: 'caller',
          })
          this.#admissionDecision = control.admission
          controlKernel = control.control
        } else {
          controlKernel = this.#kernel
          this.#admissionDecision = await evaluateAdmission({
            logId: this.logId,
            ops: [...allByOpId.values()].map(admissionOpRef),
            evidence: [],
            pinnedFrontier: null,
            evaluator: controlKernel.createAdmissionEvaluator(),
          })
        }
      }

      const eligibleLocal: KernelOperationInput[] = []
      for (const [opId, input] of allByOpId) {
        if (this.#admissionDecision.excludedOpIds.has(opId)) continue
        eligibleLocal.push(input)
      }

      const needsKernelUpgrade = await this.#ensureSqliteIfNeeded(controlKernel.topic('$reducers'), controlKernel.topic('$mounts'))
      if (needsKernelUpgrade && this.#sqliteDriver !== undefined) this.#replaceKernel(this.#newKernel())

      // Snapshot bootstrap: a host-cached (trusted) or peer-supplied bundle becomes the frontier.
      if (this.#pendingEncryptedSnapshot !== null) {
        const decoded = await this.#decodeMaterializedSnapshot(this.#pendingEncryptedSnapshot)
        if (decoded !== null) {
          this.#pendingSnapshotBundle = { ...decoded, trust: 'local' }
          this.#pendingEncryptedSnapshot = null
        } else if (this.#keys.epochs(EPOCH_KEY_GROUP).length > 0 || !this.genesis.privateLog) {
          this.#pendingEncryptedSnapshot = null
        }
      }
      if (this.#pendingSnapshotBundle !== null) {
        const bundle = this.#pendingSnapshotBundle
        this.#pendingSnapshotBundle = null
        await this.#adoptSnapshotFrontier(bundle.cache, bundle.casNodes, bundle.trust)
      }
      if (this.#provisionalSnapshot !== null) await this.#verifyProvisionalSnapshot(allByOpId)
      if (this.#pendingMaterializedCache !== null && (eligibleLocal.length > 0 || this.#pendingMaterializedCache.frontierOpIds.length > 0)) {
        const cached = this.#pendingMaterializedCache
        this.#pendingMaterializedCache = null
        await this.#upgradeKernelForSqlite(cached.topics.$reducers)
        if (await this.#kernel.restoreMaterializedCache(cached, eligibleLocal)) {
          this.#materializedCacheHits++
          // The stored cache already describes this revision; do not rewrite it unless it changes.
          this.#lastPersistedCacheDigest = this.#kernel.revision('local').digest
        }
      }

      let localResult: Awaited<ReturnType<TopicKernel['materialize']>>
      try {
        localResult = await this.#kernel.materialize(eligibleLocal)
      } catch (error) {
        if (!(error instanceof Error) || error.message !== 'KERNEL_FRONTIER_REWIND') throw error
        // An op sorts before state folded into a snapshot frontier: drop the frontier and replay
        // every op this replica holds (deterministic order wins over bootstrap speed).
        this.#replaceKernel(this.#newKernel())
        localResult = await this.#kernel.materialize(eligibleLocal)
      }
      if (localResult.pendingDependencies.length > 0 && this.#casMirrors.length > 0) {
        const fetched = await this.#pullMissingFromMirrors()
        if (fetched > 0) {
          localResult = await this.#kernel.materialize(eligibleLocal)
        }
      }
      if (!this.#kernelHasSqlite && await this.#ensureSqliteIfNeeded(this.#kernel.topic('$reducers')) && this.#sqliteDriver !== undefined) {
        const nextKernel = this.#newKernel()
        localResult = await nextKernel.materialize(eligibleLocal)
        this.#replaceKernel(nextKernel)
      }
      // While a snapshot is provisional, roles come from this replica's own control replay.
      await this.#refreshAdmissionCache(this.#controlView())
      await this.#unsealAvailableVaultKeys(this.#kernel)
      this.#lastLocalRevision = toMaterializedRevision(localResult.revision)

      // Debounce local materialized cache persistence (off the critical write path; flushed on close).
      if (
        localResult.pendingDependencies.length === 0 &&
        (eligibleLocal.length > 0 || this.#kernel.frontierOrderLength > 0) &&
        localResult.revision.digest !== this.#lastPersistedCacheDigest
      ) {
        this.#scheduleCachePersist()
      }

      if (this.#admissionDecision.closedThroughMs !== null) {
        this.#finalKernel ??= this.#newKernel()
        await this.#finalKernel.materialize(finalizedInputs(allByOpId.values(), this.#admissionDecision))
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
          revisedOpIds: revised,
          ...(changedTopics === undefined ? {} : { changedTopics }),
          ...(changedTables === undefined ? {} : { changedTables }),
        })
      }
      if (this.#lastFinalRevision !== null && this.#lastFinalRevision.digest !== prevFinalDigest) {
        this.#emitChange({
          kind: 'finalized',
          revision: this.#lastFinalRevision,
          revisedOpIds: [],
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
      // Idempotent per (visibility, author, operationId), including ops already settled remotely.
      const existingOpId = this.#ownOpsByIdempotencyKey.get(`${visibility}\0${operationId}`)
      if (existingOpId !== undefined) return new ApplicationOperation(existingOpId, operationId, this)

      const combinedChecks: OperationAssumption[] = [...(input.assumptions?.checks ?? [])]
      const onFailed = input.assumptions?.onFailed
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
          if (chk.kind === 'op_accepted' || chk.kind === 'op_rejected' || chk.kind === 'op_present') referencedOpIds.add(chk.opId)
          else if ((chk.kind === 'topic_revision' || chk.kind === 'author_last_op') && chk.lastOpId !== null) referencedOpIds.add(chk.lastOpId)
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

      this.#ownOpsByIdempotencyKey.set(`${visibility}\0${operationId}`, opIdHex)
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
        const epochKey = this.#groupKey(ring, epoch)
        check(epochKey !== undefined, 'EPOCH_KEY_MISSING')
        const commitment = epochKeyCommitment(epochKey)
        const env = await this.#encryptOperationEnvelope({
          epochKey,
          epoch,
          opBytes,
          logIdBytes,
          opIdBytes,
          authorBytes,
          ring,
        })
        const envBytes = encodeEncryptedEnvelope(env)
        const envDigest = bytesToHex(encryptedEnvelopeDigest(envBytes))
        // Single atomic multi-key write instead of two sequential transactions!
        await writeBytesMany(this.#store, [
          { key: `${this.#prefix}/enc-env/${envDigest}`, value: envBytes },
          {
            key: `${this.#prefix}/local-pending/${opIdHex}`,
            value: encodeLocalPending(opBytes, envDigest, epoch, commitment),
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
          currentCommitment: commitment,
        })
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

  /**
   * Ephemerally dry-run an operation against the current materialized state without signing,
   * persisting, emitting facts, or mutating kernel/CAS state.
   */
  async simulate(input: ApplicationSubmission): Promise<SimulationResult> {
    await this.#flushPendingMaterialization()
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

    const combinedChecks: OperationAssumption[] = [...(input.assumptions?.checks ?? [])]
    const onFailed = input.assumptions?.onFailed
    const assumptions: OperationAssumptionsConfig | undefined = combinedChecks.length > 0
      ? normalizeAssumptionsConfig({
          checks: combinedChecks,
          ...(onFailed === undefined ? {} : { onFailed }),
        })
      : undefined

    const core: OperationCore = {
      version: 1,
      logId: hexToBytes(this.logId),
      author: hexToBytes(this.identity.publicKey),
      operationId: input.operationId ?? `sim:${crypto.randomUUID()}`,
      authorTimestampMs: input.authorTimestampMs ?? BigInt(Date.now()),
      nonce: crypto.getRandomValues(new Uint8Array(16)),
      visibility,
      updates: updatesList.map(u => ({ topic: u.topic, input: normalizeJsonValue(u.input) })),
      ...(assumptions === undefined ? {} : { assumptions }),
    }
    const opIdBytes = operationIdDigest(encodeOperationCore(core))
    let envelope: { readonly ring: string; readonly epoch: number } | undefined
    if (this.genesis.privateLog && visibility === 'encrypted') {
      const keysState = this.keysState()
      const topicRings = keysState.topicRings ?? {}
      const resolvedRings = new Set(updatesList.map(u => topicRings[u.topic] ?? 'default'))
      check(resolvedRings.size === 1, 'OPERATION_CROSS_COMPARTMENT_FORBIDDEN')
      const ring = [...resolvedRings][0]!
      // The epoch submit() would seal under, so a simulation sees the same `maxOpsPerEpoch` budget.
      const epoch = ring === 'default' ? this.currentEpoch() : (keysState.rings?.[ring]?.currentEpoch ?? -1)
      envelope = { ring, epoch }
    }
    const res = await this.#kernel.simulate({
      opId: opIdBytes,
      core,
      verified: true,
      ...(envelope === undefined ? {} : envelope.epoch >= 0 ? envelope : { ring: envelope.ring }),
    })
    return {
      ok: res.ok,
      outcome: res.outcome,
      rejectionCode: res.rejectionCode,
      ...(res.rejectionDetail === undefined ? {} : { rejectionDetail: res.rejectionDetail }),
      events: res.events.map(toApplicationEvent),
      changedTopics: res.changedTopics,
      stateRoot: res.stateRoot,
    }
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
      if (isControlTopic(topic)) continue
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

  #admissionSchedule(): readonly AdmissionScheduleEntry[] {
    const raw = this.#kernel.topic('$admission') as { readonly schedule?: unknown } | null
    if (raw !== null && typeof raw === 'object' && Array.isArray(raw.schedule) && raw.schedule.length > 0) {
      return raw.schedule.filter(
        (entry): entry is AdmissionScheduleEntry =>
          entry !== null && typeof entry === 'object' &&
          typeof (entry as { effectiveAfterMs?: unknown }).effectiveAfterMs === 'number' &&
          (entry as { policy?: unknown }).policy !== undefined,
      )
    }
    return [{ effectiveAfterMs: -1, policy: { kind: 'open' } }]
  }

  #hasActiveAdmissionPolicy(): boolean {
    if (this.#pinnedFrontier !== null) return true
    return this.#admissionSchedule().some(entry => {
      const p = entry.policy as { readonly kind?: unknown } | null
      return p !== null && typeof p === 'object' && p.kind !== 'open'
    })
  }

  opOutcome(opId: string): 'accepted' | 'rejected' | null {
    return this.#kernel.opOutcome(opId)
  }

  topicLastOpId(topic: string): string | null {
    return this.#kernel.topicLastOpId(topic)
  }

  /**
   * Last accepted op of `author` (default: this identity) as an op authored now would observe it in
   * an `author_last_op` assumption: `publicOnly` for a public op on a private log, else the view of
   * an encrypted op of `ring` (default 'default').
   */
  authorLastOpId(author?: string, options: { readonly publicOnly?: boolean; readonly ring?: string } = {}): string | null {
    return this.#kernel.authorLastOpId(author ?? this.identity.publicKey, options)
  }

  /**
   * Plain-language admission lifecycle status for UI badges (Pending -> Confirmed -> Needs attention):
   * - 'equivocated': witness/notary equivocation detected (see admission.equivocations())
   * - 'finalized': op is included in a verified $admission checkpoint or pinned frontier
   * - 'excluded': closed-time frontier passed op's timestamp without including it
   * - 'synced': op has retention evidence from at least one peer/host
   * - 'local': authored/stored locally, awaiting sync or admission checkpoint
   */
  admissionStatus(opId: string): 'equivocated' | 'finalized' | 'excluded' | 'synced' | 'local' {
    if (this.#admissionDecision.equivocations.length > 0) return 'equivocated'
    if (this.#admissionDecision.includedOpIds.has(opId)) return 'finalized'
    if (this.#admissionDecision.excludedOpIds.has(opId)) return 'excluded'
    const ret = this.#retentions.get(opId)
    if (ret !== undefined && ret.size > 0) return 'synced'
    return 'local'
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
    if (viewKind === 'final' && !this.#hasActiveAdmissionPolicy()) {
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
    if (viewKind === 'final' && !this.#hasActiveAdmissionPolicy()) {
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
    readonly pqWrapKey?: string
    readonly label?: string
    readonly subject?: string
    readonly scopes?: readonly string[]
    readonly expiresAtMs?: number
    readonly reader?: boolean
    readonly writer?: boolean
    readonly administrator?: boolean
    readonly publisher?: boolean
    readonly attestation?: { readonly payload: JsonValue; readonly signature: string }
    readonly minEpoch?: number
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    const memberPayload: Record<string, JsonValue> = {
      publicKey: options.publicKey,
      ...(options.wrapKey ? { wrapKey: options.wrapKey } : {}),
      ...(options.pqWrapKey ? { pqWrapKey: options.pqWrapKey } : {}),
      ...(options.label ? { label: options.label } : {}),
      ...(options.subject ? { subject: options.subject } : {}),
      ...(options.scopes && options.scopes.length > 0 ? { scopes: [...options.scopes] } : {}),
      ...(options.expiresAtMs !== undefined ? { expiresAtMs: options.expiresAtMs } : {}),
      reader: options.reader ?? true,
      writer: options.writer ?? true,
      administrator: options.administrator ?? false,
      publisher: options.publisher ?? false,
    }
    const updates: TopicUpdate[] = [
      {
        topic: '$admission',
        input: {
          action: 'setMember',
          member: memberPayload,
          ...(options.attestation ? { attestation: options.attestation as unknown as JsonValue } : {}),
        },
      },
    ]

    if (this.genesis.privateLog && (options.reader ?? true) && (options.wrapKey || options.pqWrapKey)) {
      const keysState = this.keysState()
      if (keysState.currentEpoch < 0) {
        const extraReader = {
          publicKey: options.publicKey,
          ...(options.wrapKey ? { wrapKey: options.wrapKey } : {}),
          ...(options.pqWrapKey ? { pqWrapKey: options.pqWrapKey } : {}),
        }
        const existingEpoch0 = this.#keys.get(EPOCH_KEY_GROUP, 0)
        const built = await this.#buildEpochRotationUpdate({
          extraMembers: [extraReader],
          ...(existingEpoch0 === undefined ? {} : { newEpochKey: existingEpoch0 }),
        })
        updates.push(built.update)
      } else {
        const minEp = options.minEpoch ?? 0
        const epochBoxes: Record<string, EpochKeyBox> = {}
        const targetKeys = {
          ...(options.wrapKey ? { wrapKey: options.wrapKey } : {}),
          ...(options.pqWrapKey ? { pqWrapKey: options.pqWrapKey } : {}),
        }
        for (let ep = minEp; ep <= keysState.currentEpoch; ep++) {
          const epKey = this.#groupKey('default', ep)
          if (epKey === undefined) continue
          const box = await this.#sealBoxForMember(targetKeys, epKey, this.logId, ep)
          if (box !== null) epochBoxes[String(ep)] = box
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
        // `distribution: 'tree'`: retained epochs are granted as flat boxes above (history), and the
        // new reader joins the key tree in the same atomic op via an O(log N) tree rotation, so the
        // current epoch is again a TreeKEM epoch covering every reader. Only administrators may
        // rotate; other admitting members leave the tree join to the next administrator rotation.
        if (this.keysPolicy().distribution === 'tree' && this.isAdministrator(this.identity.publicKey)) {
          const built = await this.#buildEpochRotationUpdate({
            mode: 'tree',
            extraMembers: [{ publicKey: options.publicKey, ...targetKeys }],
          })
          if (built.treeRef !== undefined) updates.push(built.update)
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

  /**
   * Unified epoch rotation builder respecting `$keys.policy` (`distribution: 'flat' | 'tree'`, `minSuite`)
   * for `admitMember` (epoch 0), `rotateEpoch`, `rotateTreeEpoch`, and `removeMember`.
   */
  async #buildEpochRotationUpdate(options: {
    readonly excludeMembers?: readonly string[]
    readonly extraMembers?: readonly { readonly publicKey: string; readonly wrapKey?: string; readonly pqWrapKey?: string }[]
    readonly newEpochKey?: Uint8Array
    readonly suite?: KeyBoxSuite | KeyTreeSuite
    readonly mode?: 'flat' | 'tree'
  } = {}): Promise<{
    readonly epoch: number
    readonly treeRef?: string
    readonly copathBoxes?: number
    readonly update: TopicUpdate
  }> {
    const keysState = this.keysState()
    const policy = this.keysPolicy()
    const nextEpoch = keysState.currentEpoch + 1
    const mode: 'flat' | 'tree' = options.mode ?? (
      options.suite?.startsWith('hpke-tree-')
        ? 'tree'
        : (options.suite !== undefined ? 'flat' : policy.distribution)
    )
    const exclude = new Set(options.excludeMembers ?? [])
    const readersByPk = new Map<string, { readonly publicKey: string; readonly wrapKey?: string; readonly pqWrapKey?: string }>()
    for (const m of this.permissions().members) {
      if (!m.reader || (!m.wrapKey && !m.pqWrapKey) || exclude.has(m.publicKey)) continue
      readersByPk.set(m.publicKey, {
        publicKey: m.publicKey,
        ...(m.wrapKey ? { wrapKey: m.wrapKey } : {}),
        ...(m.pqWrapKey ? { pqWrapKey: m.pqWrapKey } : {}),
      })
    }
    for (const extra of options.extraMembers ?? []) {
      if ((extra.wrapKey || extra.pqWrapKey) && !exclude.has(extra.publicKey)) {
        readersByPk.set(extra.publicKey, extra)
      }
    }

    if (mode === 'tree' && options.newEpochKey === undefined && readersByPk.size > 0) {
      let previousTree: KeyTreeEpochPayload | null = null
      const prevEntry = keysState.currentEpoch >= 0 ? keysState.epochs[String(keysState.currentEpoch)] : undefined
      if (prevEntry?.treeRef) {
        const prevHash = tryParseCasRef(prevEntry.treeRef)
        if (prevHash !== null) {
          const readRes = await readKeyTreeFromCas(prevHash, async h => (await this.cas.get(h, 'public'))?.bytes ?? null)
          if (readRes.ok) previousTree = readRes.payload
        }
      }
      const requestedSuite: KeyTreeSuite | undefined =
        options.suite === KEY_TREE_SUITE_XWING || options.suite === KEY_BOX_SUITE_XWING
          ? KEY_TREE_SUITE_XWING
          : options.suite === KEY_TREE_SUITE_X25519 || options.suite === KEY_BOX_SUITE_X25519
            ? KEY_TREE_SUITE_X25519
            : (policy.minSuite === KEY_BOX_SUITE_XWING ? KEY_TREE_SUITE_XWING : undefined)
      const built = await buildTreeEpochUpdate({
        scope: this.logId,
        epoch: nextEpoch,
        updaterPublicKey: this.identity.publicKey,
        activeMembers: [...readersByPk.values()],
        previousTree,
        ...(requestedSuite === undefined ? {} : { suite: requestedSuite }),
      })
      const treeHash = await writeKeyTreeToCas(built.payload, (bytes, links) => this.cas.put(bytes, links, 'public'))
      const treeRef = casRef(treeHash)
      await this.installEpochKey(nextEpoch, built.epochKey)
      await this.#storeTreeNodeSeeds(built.derivedSeeds)
      return {
        epoch: nextEpoch,
        treeRef,
        copathBoxes: built.payload.copathBoxes.length,
        update: {
          topic: '$keys',
          input: {
            action: 'rotateTreeEpoch',
            epoch: nextEpoch,
            suite: built.payload.suite,
            keyCommitment: epochKeyCommitment(built.epochKey),
            mailboxVerifyKey: this.#mailboxVerifyKey(built.epochKey),
            treeRef,
          },
        },
      }
    }

    const key = options.newEpochKey ?? crypto.getRandomValues(new Uint8Array(32))
    await this.installEpochKey(nextEpoch, key)
    const flatRequestedSuite: KeyBoxSuite | undefined =
      options.suite === KEY_BOX_SUITE_XWING || options.suite === KEY_BOX_SUITE_X25519 ? options.suite : undefined
    const boxes: Record<string, EpochKeyBox> = {}
    let boxCount = 0
    let allPq = true
    for (const m of readersByPk.values()) {
      const box = await this.#sealBoxForMember(m, key, this.logId, nextEpoch, flatRequestedSuite)
      if (box !== null) {
        boxes[m.publicKey] = box
        boxCount++
        if (box.suite !== KEY_BOX_SUITE_XWING) allPq = false
      }
    }
    const epochSuite: KeyBoxSuite = flatRequestedSuite ?? (
      (policy.minSuite === KEY_BOX_SUITE_XWING || (boxCount > 0 && allPq))
        ? KEY_BOX_SUITE_XWING
        : KEY_BOX_SUITE_X25519
    )
    return {
      epoch: nextEpoch,
      update: {
        topic: '$keys',
        input: {
          action: 'rotateEpoch',
          epoch: nextEpoch,
          ...(epochSuite !== KEY_BOX_SUITE_X25519 ? { suite: epochSuite } : {}),
          keyCommitment: epochKeyCommitment(key),
          mailboxVerifyKey: this.#mailboxVerifyKey(key),
          boxes: boxes as unknown as JsonValue,
        },
      },
    }
  }

  async rotateEpoch(options: {
    readonly excludeMembers?: readonly string[]
    readonly newEpochKey?: Uint8Array
    readonly suite?: KeyBoxSuite | KeyTreeSuite
    readonly mode?: 'flat' | 'tree'
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<{ readonly epoch: number; readonly operation: ApplicationOperation }> {
    check(this.genesis.privateLog, 'EPOCH_ROTATION_PRIVATE_LOG_ONLY')
    await this.#flushPendingMaterialization()
    const built = await this.#buildEpochRotationUpdate(options)
    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [built.update],
    })
    return { epoch: built.epoch, operation }
  }

  /**
   * Sub-linear O(log N) Key-Tagged TreeKEM epoch rotation over structural-sharing public CAS DAG.
   * Safe under Chronolog's flat leaderless undo-do-redo order (decoupled epoch roots +
   * `targetPubKeyHash`-tagged copath boxes + deterministic `keysNeedsRotation()` healing).
   */
  async rotateTreeEpoch(options: {
    readonly excludeMembers?: readonly string[]
    readonly suite?: KeyTreeSuite
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<{ readonly epoch: number; readonly treeRef: string; readonly copathBoxes: number; readonly operation: ApplicationOperation }> {
    check(this.genesis.privateLog, 'EPOCH_ROTATION_PRIVATE_LOG_ONLY')
    await this.#flushPendingMaterialization()
    const built = await this.#buildEpochRotationUpdate({ ...options, mode: 'tree' })
    check(built.treeRef !== undefined, 'TREE_EPOCH_MEMBERS_REQUIRED')
    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [built.update],
    })
    return { epoch: built.epoch, treeRef: built.treeRef, copathBoxes: built.copathBoxes ?? 0, operation }
  }

  /** Check whether the latest `$keys` epoch still holds any removed member or exceeded `policy.maxOpsPerEpoch`. */
  async keysNeedsRotation(): Promise<{
    readonly needsRotation: boolean
    readonly staleMembers: readonly string[]
    readonly epochOpsCount: number
    readonly maxOpsPerEpoch: number | null
  }> {
    await this.#flushPendingMaterialization()
    const res = await this.#kernel.query('$keys', { kind: 'needsRotation' }).catch(() => null) as {
      readonly needsRotation?: unknown
      readonly staleMembers?: unknown
    } | null
    const staleMembers = Array.isArray(res?.staleMembers) ? res.staleMembers.filter((s): s is string => typeof s === 'string') : []
    const currentEpoch = this.currentEpoch()
    let epochOpsCount = 0
    if (currentEpoch >= 0) {
      for (const entry of this.#encryptedEnvelopes.values()) {
        if ((entry.envelope.ring ?? 'default') === 'default' && entry.envelope.epoch === currentEpoch) {
          epochOpsCount++
        }
      }
    }
    const maxOpsPerEpoch = this.keysPolicy().maxOpsPerEpoch ?? null
    const opsExceeded = maxOpsPerEpoch !== null && epochOpsCount >= maxOpsPerEpoch
    return {
      needsRotation: res?.needsRotation === true || staleMembers.length > 0 || opsExceeded,
      staleMembers,
      epochOpsCount,
      maxOpsPerEpoch,
    }
  }

  /** Update on-log `$keys.policy` (minSuite, paddingBucketBytes, hideEnvelopeAuthor, rotateOnRemove, maxOpsPerEpoch). */
  async setKeysPolicy(
    policy: KeysPolicy,
    options: { readonly operationId?: string; readonly authorTimestampMs?: bigint } = {},
  ): Promise<ApplicationOperation> {
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$keys',
        input: {
          action: 'setPolicy',
          policy: policy as unknown as JsonValue,
        },
      }],
    })
  }

  /** Self-service member wrap-key rotation (X25519 `wrapKey` and/or hybrid PQ X-Wing `pqWrapKey`). */
  async rotateWrapKey(options: {
    readonly wrapKey?: string
    readonly pqWrapKey?: string
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  } = {}): Promise<ApplicationOperation> {
    const wrapKey = options.wrapKey ?? this.device.wrapKey.publicKey
    const pqWrapKey = options.pqWrapKey ?? this.device.pqWrapKey?.publicKey
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$admission',
        input: {
          action: 'rotateWrapKey',
          wrapKey,
          ...(pqWrapKey === undefined ? {} : { pqWrapKey }),
        },
      }],
    })
  }

  /**
   * Selective per-recipient encryption helper: encrypts a JSON value or raw bytes to a chosen
   * subset of members (by publicKey resolved from `$admission`, or explicit wrapKey/pqWrapKey),
   * automatically upgrading to hybrid PQ X-Wing for recipients with `pqWrapKey`.
   */
  async sealFor(
    recipients: readonly (string | { readonly publicKey: string; readonly wrapKey?: string; readonly pqWrapKey?: string })[],
    payload: JsonValue | Uint8Array,
  ): Promise<SealedRecipientBox> {
    check(recipients.length > 0, 'SEAL_RECIPIENTS_REQUIRED')
    const encoding: 'json' | 'bytes' = payload instanceof Uint8Array ? 'bytes' : 'json'
    const plainBytes = payload instanceof Uint8Array ? payload : utf8(canonicalJson(normalizeJsonValue(payload)))
    const dek = crypto.getRandomValues(new Uint8Array(32))
    const aad = utf8(`chronolog-sealed/v1:${this.logId}:${encoding}`)
    const enc = await encryptEpochPayload(dek, 0n, plainBytes, aad)
    const boxes: Record<string, EpochKeyBox> = {}
    for (const r of recipients) {
      const target = typeof r === 'string'
        ? this.member(r)
        : r
      check(target !== null && (target.wrapKey !== undefined || target.pqWrapKey !== undefined), 'SEAL_RECIPIENT_WRAP_KEY_MISSING')
      const box = await this.#sealBoxForMember(target, dek, `${this.logId}:sealed`, 0)
      check(box !== null, 'SEAL_RECIPIENT_WRAP_KEY_MISSING')
      boxes[target.publicKey] = box
    }
    dek.fill(0)
    return {
      format: 'chronolog-sealed/v1',
      encoding,
      nonce: bytesToHex(enc.nonce),
      ciphertext: bytesToHex(enc.ciphertext),
      boxes,
    }
  }

  /**
   * Unified decoder for both selective-recipient boxes (`chronolog-sealed/v1` from `sealFor()`)
   * and Private Capability Vault boxes (`chronolog-vault-box/v1` from `vaults.seal()`),
   * accepting either an object or a serialized JSON string.
   */
  async unseal<T = JsonValue>(
    box: SealedRecipientBox | VaultSealedBox | string,
    options: { readonly topic?: string } = {},
  ): Promise<T> {
    const parsed: unknown = typeof box === 'string'
      ? (() => { try { return JSON.parse(box) as unknown } catch { return null } })()
      : box
    check(parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed), 'SEALED_BOX_INVALID')
    const fmt = (parsed as { readonly format?: unknown }).format
    if (fmt === 'chronolog-vault-box/v1') {
      const vb = parsed as VaultSealedBox
      const key = this.#getVaultKey(vb.vaultId, vb.epoch, options.topic ?? 'vaults')
      check(key !== undefined, 'VAULT_KEY_MISSING')
      const aad = utf8(`chronolog-vault-box/v1:${this.logId}:${vb.vaultId}:${vb.epoch}:${vb.encoding}`)
      const plainBytes = await decryptEpochPayload(key, {
        epoch: BigInt(vb.epoch),
        nonce: hexToBytes(vb.nonce),
        ciphertext: hexToBytes(vb.ciphertext),
      }, aad)
      if (vb.encoding === 'bytes') return plainBytes as unknown as T
      return JSON.parse(new TextDecoder().decode(plainBytes)) as T
    }
    check(fmt === 'chronolog-sealed/v1', 'SEALED_BOX_INVALID')
    const sb = parsed as SealedRecipientBox
    const myBox = sb.boxes[this.identity.publicKey]
    check(myBox !== undefined, 'SEALED_BOX_NOT_A_RECIPIENT')
    const dek = await hpkeOpenEpochKey(
      this.device.wrapKey.privateKey,
      this.device.wrapKey.publicKey,
      myBox,
      `${this.logId}:sealed`,
      0,
      this.device.pqWrapKey?.secretKey,
    )
    try {
      const aad = utf8(`chronolog-sealed/v1:${this.logId}:${sb.encoding}`)
      const plainBytes = await decryptEpochPayload(dek, {
        epoch: 0n,
        nonce: hexToBytes(sb.nonce),
        ciphertext: hexToBytes(sb.ciphertext),
      }, aad)
      if (sb.encoding === 'bytes') return plainBytes as unknown as T
      return JSON.parse(new TextDecoder().decode(plainBytes)) as T
    } finally {
      dek.fill(0)
    }
  }

  /**
   * Private Capability Vaults (`chronolog/vaults`): fine-grained, encrypted-partition row/project/folder
   * sharing with O(1) member adds, per-vault forward-secret removals, and zero metadata leaked to blind hosts.
   */
  readonly vaults = {
    hasKey: (vaultId: string, epoch?: number, topic = 'vaults'): boolean => {
      if (epoch === undefined) return this.#keys.epochs(vaultKeyGroup(topic, vaultId)).length > 0
      return this.#getVaultKey(vaultId, epoch, topic) !== undefined
    },

    currentEpoch: (vaultId: string, topic = 'vaults'): number => {
      const ep = this.#vaultState(topic, vaultId)?.currentEpoch
      if (typeof ep === 'number' && ep >= 0) return ep
      const held = this.#keys.epochs(vaultKeyGroup(topic, vaultId))
      return held.length > 0 ? held[held.length - 1]! : -1
    },

    create: async (
      vaultId: string,
      options: {
        readonly members?: readonly string[]
        readonly admins?: readonly string[]
        readonly topic?: string
        readonly operationId?: string
        readonly authorTimestampMs?: bigint
      } = {},
    ): Promise<ApplicationOperation> => {
      await this.#flushPendingMaterialization()
      const topic = options.topic ?? 'vaults'
      const key = crypto.getRandomValues(new Uint8Array(32))
      await this.#installVaultKey(topic, vaultId, 0, key)
      const memberKeys = [...new Set([this.identity.publicKey, ...(options.admins ?? []), ...(options.members ?? [])])].sort()
      const boxes: Record<string, EpochKeyBox> = {}
      for (const pk of memberKeys) {
        const m = this.member(pk) ?? (pk === this.identity.publicKey
          ? { wrapKey: this.device.wrapKey.publicKey, ...(this.device.pqWrapKey ? { pqWrapKey: this.device.pqWrapKey.publicKey } : {}) }
          : null)
        check(m !== null && (m.wrapKey !== undefined || m.pqWrapKey !== undefined), 'VAULT_MEMBER_WRAP_KEY_MISSING')
        const box = await this.#sealBoxForMember(m, key, `${this.logId}:vault:${vaultId}`, 0)
        check(box !== null, 'VAULT_MEMBER_PQ_KEY_REQUIRED')
        boxes[pk] = box
      }
      return this.submit({
        awaitMaterialized: true,
        ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
        ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
        updates: [{
          topic,
          input: {
            action: 'createVault',
            vaultId,
            keyCommitment: epochKeyCommitment(key),
            boxes: boxes as unknown as JsonValue,
            members: memberKeys,
            ...(options.admins ? { admins: [...options.admins] } : {}),
          },
        }],
      })
    },

    addMember: async (
      vaultId: string,
      memberPublicKey: string,
      options: {
        readonly minEpoch?: number
        readonly admin?: boolean
        readonly topic?: string
        readonly operationId?: string
        readonly authorTimestampMs?: bigint
      } = {},
    ): Promise<ApplicationOperation> => {
      await this.#flushPendingMaterialization()
      const topic = options.topic ?? 'vaults'
      const target = this.member(memberPublicKey)
      check(target !== null && (target.wrapKey !== undefined || target.pqWrapKey !== undefined), 'VAULT_MEMBER_WRAP_KEY_MISSING')
      const curEp = this.vaults.currentEpoch(vaultId, topic)
      check(curEp >= 0, 'VAULT_NOT_FOUND')
      const minEp = Math.max(0, options.minEpoch ?? 0)
      const epochBoxes: Record<string, EpochKeyBox> = {}
      for (let ep = minEp; ep <= curEp; ep++) {
        const k = this.#getVaultKey(vaultId, ep, topic)
        if (k === undefined) continue
        const box = await this.#sealBoxForMember(target, k, `${this.logId}:vault:${vaultId}`, ep)
        check(box !== null, 'VAULT_MEMBER_PQ_KEY_REQUIRED')
        epochBoxes[String(ep)] = box
      }
      return this.submit({
        awaitMaterialized: true,
        ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
        ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
        updates: [{
          topic,
          input: {
            action: 'addMember',
            vaultId,
            member: memberPublicKey,
            ...(options.admin === true ? { admin: true } : {}),
            epochBoxes: epochBoxes as unknown as JsonValue,
          },
        }],
      })
    },

    removeMember: async (
      vaultId: string,
      memberPublicKey: string,
      options: {
        readonly topic?: string
        readonly operationId?: string
        readonly authorTimestampMs?: bigint
      } = {},
    ): Promise<{ readonly epoch: number; readonly operation: ApplicationOperation }> => {
      await this.#flushPendingMaterialization()
      const topic = options.topic ?? 'vaults'
      const raw = this.#kernel.topic(topic) as { readonly vaults?: Record<string, { readonly currentEpoch: number; readonly members: readonly string[] }> } | null
      const vault = raw?.vaults?.[vaultId]
      check(vault !== undefined, 'VAULT_NOT_FOUND')
      const nextEpoch = vault.currentEpoch + 1
      const key = crypto.getRandomValues(new Uint8Array(32))
      await this.#installVaultKey(topic, vaultId, nextEpoch, key)
      const boxes: Record<string, EpochKeyBox> = {}
      for (const pk of vault.members) {
        if (pk === memberPublicKey) continue
        const m = this.member(pk) ?? (pk === this.identity.publicKey
          ? { wrapKey: this.device.wrapKey.publicKey, ...(this.device.pqWrapKey ? { pqWrapKey: this.device.pqWrapKey.publicKey } : {}) }
          : null)
        if (!m) continue
        const box = await this.#sealBoxForMember(m, key, `${this.logId}:vault:${vaultId}`, nextEpoch)
        check(box !== null, 'VAULT_MEMBER_PQ_KEY_REQUIRED')
        boxes[pk] = box
      }
      const operation = await this.submit({
        awaitMaterialized: true,
        ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
        ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
        updates: [{
          topic,
          input: {
            action: 'removeMember',
            vaultId,
            member: memberPublicKey,
            epoch: nextEpoch,
            keyCommitment: epochKeyCommitment(key),
            boxes: boxes as unknown as JsonValue,
          },
        }],
      })
      return { epoch: nextEpoch, operation }
    },

    seal: async (vaultId: string, payload: JsonValue | Uint8Array, options: { readonly topic?: string } = {}): Promise<VaultSealedBox> => {
      const topic = options.topic ?? 'vaults'
      const vault = this.#vaultState(topic, vaultId)
      const epoch = vault?.currentEpoch ?? -1
      check(epoch >= 0, 'VAULT_NOT_FOUND')
      const commitment = vault?.epochs?.[String(epoch)]?.keyCommitment
      check(typeof commitment === 'string', 'VAULT_KEY_MISSING')
      // Seal only under the key the log commits to (never a losing concurrent rotation's key).
      const key = this.#keys.get(vaultKeyGroup(topic, vaultId), epoch, commitment)
      check(key !== undefined, 'VAULT_KEY_MISSING')
      const encoding: 'json' | 'bytes' = payload instanceof Uint8Array ? 'bytes' : 'json'
      const plainBytes = payload instanceof Uint8Array ? payload : utf8(canonicalJson(normalizeJsonValue(payload)))
      const aad = utf8(`chronolog-vault-box/v1:${this.logId}:${vaultId}:${epoch}:${encoding}`)
      const enc = await encryptEpochPayload(key, BigInt(epoch), plainBytes, aad)
      return {
        format: 'chronolog-vault-box/v1',
        vaultId,
        epoch,
        encoding,
        nonce: bytesToHex(enc.nonce),
        ciphertext: bytesToHex(enc.ciphertext),
      }
    },

    unseal: async <T = JsonValue>(
      box: VaultSealedBox | SealedRecipientBox | string,
      options: { readonly strict?: boolean; readonly topic?: string } = {},
    ): Promise<T | null> => {
      try {
        return await this.unseal<T>(box, options)
      } catch (err) {
        if (options.strict) throw err
        return null
      }
    },

    unsealRows: async <T>(
      rowsOrResult: T,
      options: { readonly topic?: string } = {},
    ): Promise<T> => {
      const unsealCell = async (val: unknown): Promise<unknown> => {
        if (typeof val === 'string') {
          const trimmed = val.trim()
          if (trimmed.startsWith('{') && trimmed.endsWith('}') && (trimmed.includes('"chronolog-vault-box/v1"') || trimmed.includes('"chronolog-sealed/v1"'))) {
            let parsed: unknown
            try { parsed = JSON.parse(trimmed) } catch { return val }
            if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
              const fmt = (parsed as { readonly format?: unknown }).format
              if (fmt === 'chronolog-vault-box/v1' || fmt === 'chronolog-sealed/v1') {
                return this.vaults.unseal(parsed as VaultSealedBox | SealedRecipientBox, { strict: false, ...options })
              }
            }
          }
          return val
        }
        if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
          const fmt = (val as { readonly format?: unknown }).format
          if (fmt === 'chronolog-vault-box/v1' || fmt === 'chronolog-sealed/v1') {
            return this.vaults.unseal(val as VaultSealedBox | SealedRecipientBox, { strict: false, ...options })
          }
        }
        return val
      }
      const unsealRowList = async (list: readonly unknown[]): Promise<unknown[]> => {
        const out: unknown[] = []
        for (const row of list) {
          if (Array.isArray(row)) {
            out.push(await Promise.all(row.map(unsealCell)))
          } else if (row !== null && typeof row === 'object') {
            const next: Record<string, unknown> = {}
            for (const [k, v] of Object.entries(row)) next[k] = await unsealCell(v)
            out.push(next)
          } else {
            out.push(row)
          }
        }
        return out
      }
      if (Array.isArray(rowsOrResult)) {
        return (await unsealRowList(rowsOrResult)) as unknown as T
      }
      if (rowsOrResult !== null && typeof rowsOrResult === 'object' && Array.isArray((rowsOrResult as { readonly rows?: unknown }).rows)) {
        const resObj = rowsOrResult as Record<string, unknown> & { readonly rows: readonly unknown[] }
        return { ...resObj, rows: await unsealRowList(resObj.rows) } as unknown as T
      }
      return rowsOrResult
    },
  }

  /**
   * Create or rotate a named compartment key ring in $keys (e.g. 'admins' or 'personal:<pk>'),
   * sealing its epoch key strictly to the chosen members and binding the specified topics to it.
   */
  async createCompartment(
    ringName: string,
    options: {
      readonly topics: readonly string[]
      readonly members: readonly { readonly publicKey: string; readonly wrapKey?: string; readonly pqWrapKey?: string }[]
      readonly suite?: KeyBoxSuite
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    },
  ): Promise<{ readonly ring: string; readonly epoch: number; readonly operation: ApplicationOperation }> {
    check(this.genesis.privateLog, 'COMPARTMENT_PRIVATE_LOG_ONLY')
    check(typeof ringName === 'string' && ringName.length > 0 && ringName !== 'default', 'RING_NAME_INVALID')
    await this.#flushPendingMaterialization()
    const built = await this.#buildRingRotationUpdate(ringName, options.members, { topics: options.topics, ...(options.suite === undefined ? {} : { suite: options.suite }) })
    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [built.update],
    })
    return { ring: ringName, epoch: built.epoch, operation }
  }

  /** Build a `rotateRingEpoch` update sealing a fresh epoch key of `ringName` to exactly `members`. */
  async #buildRingRotationUpdate(
    ringName: string,
    members: readonly { readonly publicKey: string; readonly wrapKey?: string; readonly pqWrapKey?: string }[],
    options: { readonly topics?: readonly string[]; readonly suite?: KeyBoxSuite } = {},
  ): Promise<{ readonly epoch: number; readonly update: TopicUpdate }> {
    const keysState = this.keysState()
    const policy = this.keysPolicy()
    const prevRing = keysState.rings?.[ringName]
    const nextEpoch = (prevRing?.currentEpoch ?? -1) + 1
    const key = crypto.getRandomValues(new Uint8Array(32))
    await this.installRingKey(ringName, nextEpoch, key)

    const boxes: Record<string, EpochKeyBox> = {}
    let boxCount = 0
    let allPq = true
    for (const m of members) {
      const box = await this.#sealBoxForMember(m, key, `${this.logId}:${ringName}`, nextEpoch, options.suite)
      if (box !== null) {
        boxes[m.publicKey] = box
        boxCount++
        if (box.suite !== KEY_BOX_SUITE_XWING) allPq = false
      }
    }
    const ringSuite: KeyBoxSuite = options.suite ?? (
      (policy.minSuite === KEY_BOX_SUITE_XWING || (boxCount > 0 && allPq))
        ? KEY_BOX_SUITE_XWING
        : KEY_BOX_SUITE_X25519
    )
    return {
      epoch: nextEpoch,
      update: {
        topic: '$keys',
        input: {
          action: 'rotateRingEpoch',
          ring: ringName,
          epoch: nextEpoch,
          ...(ringSuite !== KEY_BOX_SUITE_X25519 ? { suite: ringSuite } : {}),
          keyCommitment: epochKeyCommitment(key),
          mailboxVerifyKey: this.#mailboxVerifyKey(key),
          boxes: boxes as unknown as JsonValue,
          ...(options.topics === undefined ? {} : { topics: [...options.topics] }),
        },
      },
    }
  }

  /**
   * Configure threshold Social Recovery ("Trusted Backup Contacts"):
   * - Splits a fresh 32-byte recoveryKey into N Shamir shares (threshold M).
   * - Encrypts all retained epoch + compartment keys inside a recovery vault under recoveryKey.
   * - HPKE-seals each Shamir share strictly to its guardian's wrapKey (guardians cannot read app data).
   * - Atomically updates $admission.guardians and $keys.recovery.
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
      topic: '$admission',
      input: {
        action: 'setGuardians',
        guardians: {
          threshold: options.threshold,
          members: options.guardians.map(g => ({
            publicKey: g.publicKey,
            ...(g.wrapKey ? { wrapKey: g.wrapKey } : {}),
            ...(g.pqWrapKey ? { pqWrapKey: g.pqWrapKey } : {}),
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
        readonly vaults: Record<string, Record<string, string>>
      } = { epochs: {}, rings: {}, vaults: {} }
      for (const ep of this.#keys.epochs(EPOCH_KEY_GROUP)) {
        const key = this.#groupKey('default', ep)
        if (key !== undefined) vaultPayload.epochs[String(ep)] = bytesToHex(key)
      }
      for (const group of this.#keys.groups('ring:')) {
        const ring = group.slice('ring:'.length)
        const ringObj: Record<string, string> = {}
        for (const ep of this.#keys.epochs(group)) {
          const key = this.#groupKey(ring, ep)
          if (key !== undefined) ringObj[String(ep)] = bytesToHex(key)
        }
        vaultPayload.rings[ring] = ringObj
      }
      for (const group of this.#keys.groups('vault:')) {
        const parsedGroup = parseVaultKeyGroup(group)
        if (parsedGroup === null) continue
        const vObj: Record<string, string> = {}
        for (const ep of this.#keys.epochs(group)) {
          const key = this.#getVaultKey(parsedGroup.vaultId, ep, parsedGroup.topic) ?? this.#keys.get(group, ep)
          if (key !== undefined) vObj[String(ep)] = bytesToHex(key)
        }
        vaultPayload.vaults[`${parsedGroup.topic}:${parsedGroup.vaultId}`] = vObj
      }
      const aad = utf8(`chronolog-recovery-vault:${this.logId}`)
      const encVault = await encryptEpochPayload(recoveryKey, 0n, utf8(JSON.stringify(vaultPayload)), aad)

      const shares = splitSecret(recoveryKey, options.threshold, options.guardians.length)
      const guardianShares: Record<string, { readonly index: number; readonly box: EpochKeyBox }> = {}
      for (let i = 0; i < options.guardians.length; i++) {
        const g = options.guardians[i]!
        const share = shares[i]!
        const box = await this.#sealBoxForMember(g, share.bytes, `${this.logId}:recovery-share`, share.index)
        check(box !== null, 'GUARDIAN_WRAP_KEY_REQUIRED')
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
        topic: '$admission',
        input: {
          action: 'requestRecovery',
          requestId,
          newPublicKey: this.identity.publicKey,
          newWrapKey: this.device.wrapKey.publicKey,
          ...(this.device.pqWrapKey ? { newPqWrapKey: this.device.pqWrapKey.publicKey } : {}),
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
    const admInfo = (await this.#kernel.query('$admission', { kind: 'guardians' })) as {
      readonly recoveryRequests?: Readonly<Record<string, RecoveryRequestRecord>>
    }
    const req = admInfo?.recoveryRequests?.[requestId]
    check(req !== undefined && req.status === 'pending', 'RECOVERY_REQUEST_NOT_FOUND')

    const updates: TopicUpdate[] = [{
      topic: '$admission',
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
        this.device.pqWrapKey?.secretKey,
      )
      const resealedBox = await this.#sealBoxForMember(
        {
          ...(req.newWrapKey ? { wrapKey: req.newWrapKey } : {}),
          ...(req.newPqWrapKey ? { pqWrapKey: req.newPqWrapKey } : {}),
        },
        shareBytes,
        `${this.logId}:recovery-grant`,
        myShare.index,
      )
      check(resealedBox !== null, 'RECOVERY_TARGET_WRAP_KEY_REQUIRED')
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
      const admInfo = (await this.#kernel.query('$admission', { kind: 'guardians' })) as {
        readonly guardians?: GuardiansConfig | null
      }
      const threshold = admInfo?.guardians?.threshold ?? 1
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
          this.device.pqWrapKey?.secretKey,
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
        readonly vaults?: Record<string, Record<string, string>>
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
      for (const [storageKey, eps] of Object.entries(parsed.vaults ?? {})) {
        const sep = storageKey.indexOf(':')
        const topic = sep > 0 ? storageKey.slice(0, sep) : 'vaults'
        const vaultId = sep > 0 ? storageKey.slice(sep + 1) : storageKey
        for (const [epStr, hexKey] of Object.entries(eps)) {
          await this.#installVaultKey(topic, vaultId, Number(epStr), hexToBytes(hexKey))
        }
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
    await this.#flushPendingMaterialization()
    const updates: TopicUpdate[] = []
    const policy = this.keysPolicy()
    const shouldRotate = options.rotateEpoch ?? policy.rotateOnRemove
    // `$admission` only lets a reader lose access after an EARLIER update of the same op rotated
    // every ring whose latest epoch it holds, so the rotation goes first.
    if (this.genesis.privateLog && shouldRotate) {
      const built = await this.#buildEpochRotationUpdate({ excludeMembers: [publicKey] })
      updates.push(built.update)
      // Every compartment ring whose latest epoch the member holds is re-sealed to its other holders.
      const roster = new Map(this.permissions().members.map(m => [m.publicKey, m]))
      for (const [ringName, ring] of Object.entries(this.keysState().rings ?? {}).sort(([a], [b]) => a.localeCompare(b))) {
        const latest = ring.epochs[String(ring.currentEpoch)]
        if (latest === undefined || !Object.hasOwn(latest.boxes, publicKey)) continue
        const holders = Object.keys(latest.boxes)
          .filter(pk => pk !== publicKey)
          .map(pk => roster.get(pk))
          .filter((m): m is MemberRecord => m !== undefined && (m.wrapKey !== undefined || m.pqWrapKey !== undefined))
        updates.push((await this.#buildRingRotationUpdate(ringName, holders)).update)
      }
    }
    updates.push({ topic: '$admission', input: { action: 'removeMember', publicKey } })
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
    readonly includeTreeRoot?: boolean
    readonly expectedRevision?: number
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    const descriptors: { readonly path: string; readonly hash: string; readonly size: number; readonly type: string }[] = []
    const treeEntries: Record<string, string> = {}
    for (const f of options.files) {
      let hash = f.hash
      let size = f.size
      if (f.bytes !== undefined) {
        const computedHash = computeBlobDagHash(f.bytes)
        if (hash !== undefined) check(hash === computedHash, 'PUBLICATION_FILE_HASH_MISMATCH')
        hash = computedHash
        size = f.bytes.length
        if (this.isReader(this.identity.publicKey)) {
          await this.content.putBlob(f.bytes)
        }
      }
      check(hash !== undefined && size !== undefined, 'PUBLICATION_FILE_INVALID')
      descriptors.push({ path: f.path, hash, size, type: f.type })
      treeEntries[f.path] = casRef(hash)
    }
    let treeRoot: string | undefined
    if (options.includeTreeRoot !== false && descriptors.length > 0) {
      const encodedTree = encodeTreeNode({ format: 'chronolog-tree/v1', entries: treeEntries })
      const treeHash = await this.cas.put(encodedTree.bytes, encodedTree.links, 'public')
      treeRoot = casRef(treeHash)
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
          ...(treeRoot === undefined ? {} : { treeRoot }),
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

  async scheduleAdmissionPolicy(options: {
    readonly effectiveAfterMs: bigint | number
    readonly policy: JsonValue
    readonly operationId?: string
    readonly authorTimestampMs?: bigint
  }): Promise<ApplicationOperation> {
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$admission',
        input: {
          action: 'schedulePolicy',
          effectiveAfterMs: Number(options.effectiveAfterMs),
          policy: options.policy,
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

  // ---- Admission & checkpoint operations ----

  readonly admission = {
    status: (): AdmissionDecision & {
      readonly schedule: readonly AdmissionScheduleEntry[]
      readonly pinnedFrontier: PinnedFrontier | null
    } => ({
      ...this.#admissionDecision,
      schedule: this.#admissionSchedule(),
      pinnedFrontier: this.#pinnedFrontier,
    }),

    opStatus: (opId: string): 'equivocated' | 'finalized' | 'excluded' | 'synced' | 'local' =>
      this.admissionStatus(opId),

    equivocations: (): readonly AdmissionEquivocation[] => this.#admissionDecision.equivocations,

    schedulePolicy: (options: {
      readonly effectiveAfterMs: bigint | number
      readonly policy: JsonValue
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    }): Promise<ApplicationOperation> => this.scheduleAdmissionPolicy(options),

    pinCheckpoint: (options: {
      readonly closedThroughMs: bigint | number
      readonly stateRoot: string
      readonly historyDigest: string
      readonly includedOpIds: readonly string[]
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    }): Promise<ApplicationOperation> => this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{
        topic: '$admission',
        input: {
          action: 'pinCheckpoint',
          closedThroughMs: Number(options.closedThroughMs),
          stateRoot: options.stateRoot,
          historyDigest: options.historyDigest,
          includedOpIds: [...options.includedOpIds],
        },
      }],
    }),

    pinFrontier: async (frontier: PinnedFrontier | null): Promise<void> => {
      await this.#serial(async () => {
        this.#pinnedFrontier = frontier
        if (frontier === null) {
          await this.#store.delete?.(`${this.#prefix}/pinned-frontier`)
        } else {
          await this.#store.put(`${this.#prefix}/pinned-frontier`, encodeRecord(frontier), { durability: 'strict' })
        }
        await this.#rematerialize()
      })
    },

    createCheckpoint: async (options: {
      readonly throughMs: bigint
      readonly kind?: string
      readonly scopeId?: string
      readonly data?: JsonValue | ((payload: AdmissionCheckpointPayload) => JsonValue | Promise<JsonValue>)
    }): Promise<{
      readonly evidence: AdmissionEvidence
      readonly snapshot: CheckpointBootstrapSnapshot
    }> => {
      return this.#serial(async () => {
        const schedule = this.#admissionSchedule()
        const scopeEntries = schedule.map(entry => ({
          entry,
          scopeId: computeAdmissionScopeId(this.logId, entry.effectiveAfterMs, entry.policy),
        }))
        const closedByScope = new Map<string, bigint>()
        for (const ev of this.#admissionDecision.verifiedEvidence) {
          const p = ev.payload as Partial<AdmissionCheckpointPayload> | null
          if (!p || typeof p !== 'object' || typeof p.scopeId !== 'string') continue
          const closed = typeof p.closedThroughMs === 'bigint' ? p.closedThroughMs : BigInt(Number(p.closedThroughMs ?? 0))
          const prev = closedByScope.get(p.scopeId)
          if (prev === undefined || closed > prev) closedByScope.set(p.scopeId, closed)
        }
        let activeIdx = 0
        for (let i = 0; i < scopeEntries.length; i++) {
          const cur = scopeEntries[i]!
          if (BigInt(cur.entry.effectiveAfterMs) > options.throughMs) break
          if (i > 0) {
            const prev = scopeEntries[i - 1]!
            const prevKind = (prev.entry.policy as { readonly kind?: string } | null)?.kind
            if (prevKind !== 'open') {
              const prevClosed = closedByScope.get(prev.scopeId)
              if (prevClosed === undefined || prevClosed < BigInt(cur.entry.effectiveAfterMs)) break
            }
          }
          activeIdx = i
        }
        const active = scopeEntries[activeIdx]!
        const activeKind = (active.entry.policy as { readonly kind?: string } | null)?.kind
        check(options.scopeId !== undefined || activeKind !== 'open', 'ADMISSION_CHECKPOINT_POLICY_NOT_ACTIVE')
        const scopeId = options.scopeId ?? active.scopeId

        const all = this.#collectDecryptedKernelInputs()
        const included: KernelOperationInput[] = []
        for (const [opId, input] of all) {
          if (this.#admissionDecision.excludedOpIds.has(opId)) continue
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
        let snap: ReturnType<TopicKernel['snapshot']>
        let seenOpsRoot: string
        try {
          await tempKernel.materialize(included)
          seenOpsRoot = await tempKernel.commitSeenOpsRoot()
          snap = tempKernel.snapshot()
        } finally {
          tempKernel.dispose()
        }

        const inclusions = included.map(i => ({
          opId: bytesToHex(i.opId),
          authorTimestampMs: i.core.authorTimestampMs,
          author: bytesToHex(i.core.author),
        }))
        const payload: AdmissionCheckpointPayload = {
          logId: this.logId,
          scopeId,
          closedThroughMs: options.throughMs,
          includedSetDigest: computeIncludedSetDigest(inclusions.map(i => i.opId)),
          historyDigest: snap.historyDigest,
          stateRoot: snap.stateRoot,
          seenOpsRoot,
          inclusions,
        }
        const data: JsonValue = options.data === undefined
          ? { signatures: [await signAdmissionCheckpoint(payload, this.device.identity)] }
          : typeof options.data === 'function'
            ? await options.data(payload)
            : options.data
        const evidence: AdmissionEvidence = {
          kind: options.kind ?? 'checkpoint',
          payload,
          data,
        }

        const key = await evidenceDigest(evidence)
        this.#evidence.set(key, evidence)
        await this.#store.put(`${this.#prefix}/evidence/${key}`, encodeRecord(evidence))
        await this.#rematerialize()
        this.#emitFacts()
        return { evidence, snapshot: snap }
      })
    },

    submitEvidence: async (evidence: readonly AdmissionEvidence[]): Promise<void> => {
      await this.mergeFacts({
        publicOps: [],
        encryptedEnvelopes: [],
        casNodes: [],
        retentions: [],
        evidence,
      })
    },

    bootstrapFromCheckpoint: async (
      evidence: AdmissionEvidence,
      snapshot: CheckpointBootstrapSnapshot,
    ): Promise<void> => {
      await this.#serial(async () => {
        const payload = evidence.payload as AdmissionCheckpointPayload
        check(payload !== null && typeof payload === 'object' && payload.logId === this.logId, 'CHECKPOINT_CHAIN_MISMATCH')
        check(payload.stateRoot === snapshot.stateRoot && payload.historyDigest === snapshot.historyDigest, 'CHECKPOINT_SNAPSHOT_MISMATCH')
        const key = await evidenceDigest(evidence)
        this.#evidence.set(key, evidence)
        const frontier: PinnedFrontier = {
          closedThroughMs: typeof payload.closedThroughMs === 'bigint' ? payload.closedThroughMs : BigInt(Number(payload.closedThroughMs)),
          stateRoot: payload.stateRoot,
          historyDigest: payload.historyDigest,
          includedOpIds: payload.inclusions.map(i => i.opId),
        }
        this.#pinnedFrontier = frontier
        await writeBytesMany(this.#store, [
          { key: `${this.#prefix}/evidence/${key}`, value: encodeRecord(evidence) },
          { key: `${this.#prefix}/pinned-frontier`, value: encodeRecord(frontier) },
        ], { durability: 'strict' })
        // The checkpoint state becomes the frontier through the one snapshot adoption path: its
        // inclusions are covered (never replayed again), and the pinned frontier attests it.
        const cache: KernelMaterializedCache = {
          v: 2,
          logId: this.logId,
          blindHostMode: this.#blindHostMode,
          topics: snapshot.topics,
          seenOpsRoot: snapshot.seenOpsRoot,
          historyDigest: snapshot.historyDigest,
          stateRoot: snapshot.stateRoot,
          frontierOpIds: frontier.includedOpIds,
          frontierMaxTimestampMs: frontier.closedThroughMs,
          orderOpIds: [],
          outcomes: [],
          topicLastOpIds: {},
        }
        check(await this.#adoptSnapshotFrontier(cache, [], 'untrusted', { force: true }), 'CHECKPOINT_SNAPSHOT_INVALID')
        if (this.#controlKernel !== null) {
          await this.#controlKernel.restoreSnapshotFrontier({ ...cache, blindHostMode: true })
        }
        await this.#rematerialize()
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
      opId: opIdHex,
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
      opId: opIdHex,
      operationId: core === null ? idOrOperationId : core.operationId,
      visibility: core === null ? 'encrypted' : core.visibility,
      stored: core !== null,
      pending,
      materialized,
      retained,
      finalized: this.#admissionDecision.includedOpIds.has(opIdHex),
      excluded: this.#admissionDecision.excludedOpIds.has(opIdHex),
    }
  }

  async waitOperation(
    id: string,
    fact: 'materialized' | 'retained' | 'finalized',
    options: WaitOptions = {},
  ): Promise<OperationInspection> {
    if (fact === 'finalized' && !this.#hasActiveAdmissionPolicy()) {
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
      return info.stored ? new ApplicationOperation(info.opId, info.operationId, this) : null
    },
    retry: async (idOrOperationId: string): Promise<ApplicationOperation> => {
      const existing = this.operations.get(idOrOperationId)
      check(existing !== null, 'OPERATION_UNKNOWN')
      this.#emitFacts()
      return existing
    },
  }

  // ---- Retention ----

  async retain(opId: string, subject: { readonly author: string; readonly envelopeDigest: string }): Promise<RetentionEvidence> {
    const [evidence] = await this.retainMany([{ opId, author: subject.author, envelopeDigest: subject.envelopeDigest }])
    check(evidence !== undefined, 'RETENTION_OP_NOT_HELD')
    return evidence
  }

  /** Index a (batch) retention receipt under every op it covers; true if anything was new. */
  #indexRetention(ev: RetentionEvidence): boolean {
    let added = false
    for (const opId of ev.payload.items) {
      if (typeof opId !== 'string') continue
      let byPeer = this.#retentions.get(opId)
      if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(opId, byPeer) }
      if (!byPeer.has(ev.signer)) { byPeer.set(ev.signer, ev); added = true }
    }
    return added
  }

  /**
   * Sign ONE retention receipt covering every newly retained item (sync v3), instead of one
   * signature, store write and gossip fact per operation.
   */
  async retainMany(
    items: readonly { readonly opId: string; readonly author?: string; readonly envelopeDigest?: string }[],
  ): Promise<readonly RetentionEvidence[]> {
    // A receipt attests durable possession: never sign for ops this replica does not hold (for
    // example facts the merge skipped or rejected).
    const held = [...new Set(items.map(item => item.opId))].filter(opId => this.#holdsOp(opId))
    const own = (): RetentionEvidence[] => [...new Set(held.map(opId => this.#retentions.get(opId)!.get(this.identity.publicKey)!))]
    if (held.length === 0) return []
    const fresh = held.filter(opId => this.#retentions.get(opId)?.get(this.identity.publicKey) === undefined)
    if (fresh.length === 0) return own()
    const evidence = await signRecord('operation-retention', {
      applicationId: this.applicationId,
      peer: this.identity.publicKey,
      storageId: this.device.storageId,
      items: fresh,
    }, this.device.identity)
    for (const opId of fresh) {
      let byPeer = this.#retentions.get(opId)
      if (byPeer === undefined) { byPeer = new Map(); this.#retentions.set(opId, byPeer) }
      byPeer.set(this.identity.publicKey, evidence)
    }
    await this.#store.put(`${this.#prefix}/retention/${await recordDigest(evidence.payload)}`, encodeRecord(evidence), { durability: 'relaxed' })
    this.#emitFacts()
    return own()
  }

  /** True when this replica durably holds the op (as a public op or inside an encrypted envelope). */
  #holdsOp(opId: string): boolean {
    return this.#publicOps.has(opId) || this.#encryptedEnvelopes.holdsOp(opId)
  }

  /**
   * Drop `local-pending` records of own ops that a remote member has retained: they are no longer
   * pending, so they are neither rewrapped on later rotations nor kept as a second plaintext copy.
   */
  async #settleLocalPending(opIds: Iterable<string> = this.#localPending.keys()): Promise<void> {
    const settled: string[] = []
    for (const opId of opIds) {
      if (!this.#localPending.has(opId)) continue
      const byPeer = this.#retentions.get(opId)
      if (byPeer === undefined) continue
      for (const signer of byPeer.keys()) {
        if (signer !== this.identity.publicKey && this.isMember(signer)) { settled.push(opId); break }
      }
    }
    if (settled.length === 0) return
    for (const opId of settled) this.#localPending.delete(opId)
    const keys = settled.map(opId => `${this.#prefix}/local-pending/${opId}`)
    if (this.#store.deleteMany !== undefined) await this.#store.deleteMany(keys)
    else for (const key of keys) await this.#store.delete?.(key)
  }

  /**
   * Return `opId`s authored by `authorPublicKey` that this replica holds durably
   * (public ops and/or encrypted envelopes) and has not yet signed its own retention receipt for.
   * Used after P2P sync reconciliation to attest operations received out-of-band (e.g. host mailbox)
   * without re-signing or resending receipts on unchanged reconnects.
   */
  unreceiptedOpIdsByAuthor(authorPublicKey: string, includePrivate: boolean): string[] {
    const self = this.identity.publicKey
    const ids: string[] = []
    for (const [opId, op] of this.#publicOps) {
      if (bytesToHex(op.core.author) === authorPublicKey && this.#retentions.get(opId)?.get(self) === undefined) {
        ids.push(opId)
      }
    }
    if (includePrivate) {
      for (const env of this.#encryptedEnvelopes.values()) {
        const envAuthor = env.decrypted !== undefined
          ? bytesToHex(env.decrypted.core.author)
          : bytesToHex(env.envelope.author)
        if (envAuthor === authorPublicKey) {
          const opId = bytesToHex(env.envelope.opId)
          if (this.#retentions.get(opId)?.get(self) === undefined) ids.push(opId)
        }
      }
    }
    return ids
  }


  // ---- Facts export & merge (P2P + blind host sync) ----

  /** Number of times this session skipped full replay by restoring a verified materialized cache/snapshot. */
  get materializedCacheHits(): number {
    return this.#materializedCacheHits
  }

  /**
   * Export a member-signed Snapshot Bundle (v3, see snapshot-codec.ts): the current state as a
   * frontier (topics, idempotency set, digests and the covered op ids — no outcomes or events)
   * plus the CAS nodes reachable from it (SQLite pages, seen set; standard modules excluded).
   * On private logs it is AEAD-encrypted under the current epoch key, so blind hosts can cache it
   * and peers can serve it without exposing plaintext.
   */
  async exportMaterializedSnapshot(options: { readonly includeReachableCas?: boolean; readonly minOps?: number } = {}): Promise<Uint8Array | null> {
    await this.#flushPendingMaterialization()
    return this.#serial(() => this.#exportSnapshotNow(options))
  }

  async #exportSnapshotNow(options: { readonly includeReachableCas?: boolean; readonly minOps?: number }): Promise<Uint8Array | null> {
    const totalOps = this.#kernel.materializedOutcomes.length + this.#kernel.frontierOrderLength
    const minOps = options.minOps ?? 1
    if (
      totalOps < minOps ||
      this.#kernel.pendingDependencies.length > 0 ||
      // Never relay state this replica has not verified itself.
      this.#provisionalSnapshot !== null ||
      // Compartment-ring topics would leak to every epoch-key holder (bundles are sealed under the
      // default epoch key only).
      Object.keys(this.keysState().topicRings ?? {}).length > 0
    ) {
      return null
    }
    let encryption: { readonly epoch: number; readonly key: Uint8Array } | undefined
    if (this.genesis.privateLog) {
      if (this.#blindHostMode) return null
      const epoch = this.#currentEpochFrom(this.#kernel)
      const key = epoch >= 0 ? this.#groupKey('default', epoch) : undefined
      if (key === undefined) return null
      encryption = { epoch, key }
    }
    await this.#kernel.commitSeenOpsRoot()
    const cache = this.#kernel.exportMaterializedCache({ suffix: false })
    const casNodes: SessionCasNode[] = []
    const roots = new Set<string>([cache.seenOpsRoot])
    if (options.includeReachableCas !== false) {
      const stdHashes = standardModuleHashes()
      for (const hash of this.#kernel.gcRoots()) roots.add(hash)
      for (const hash of await this.cas.reachable(roots)) {
        if (stdHashes.has(hash)) continue
        const pubRaw = await this.cas.getRaw(hash, 'public')
        if (pubRaw !== null) {
          casNodes.push({ hash, bytes: pubRaw, partition: 'public' })
          continue
        }
        const privRaw = await this.cas.getRaw(hash, 'private')
        if (privRaw !== null) casNodes.push({ hash, bytes: privRaw, partition: 'private' })
      }
    }
    return encodeSnapshotBundle({
      logId: this.logId,
      cache,
      casNodes,
      identity: this.device.identity,
      ...(encryption === undefined ? {} : { encryption }),
    })
  }

  /**
   * True when this replica has no materialized history yet (no ops and no snapshot frontier) and
   * would benefit from adopting a peer's snapshot instead of replaying everything.
   */
  wantsSnapshotBootstrap(): boolean {
    if (!this.#snapshotBootstrap || this.#closed || this.#blindHostMode) return false
    if (this.#kernel.frontierOrderLength > 0 || this.#localPending.size > 0) return false
    if (this.genesis.privateLog) return this.#encryptedEnvelopes.size === 0
    return this.#publicOps.size === 0
  }

  /**
   * Stage and apply an exported materialized snapshot bundle (AEAD-decrypted on private logs).
   * Works on cold replicas with zero historical ops downloaded (frontier bootstrap).
   */
  importMaterializedSnapshot(bytes: Uint8Array): Promise<boolean> {
    return this.#serial(async () => {
      const decoded = await this.#decodeMaterializedSnapshot(bytes)
      if (decoded === null) return false
      this.#pendingSnapshotBundle = { ...decoded, trust: 'untrusted' }
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
      evidence: [...this.#evidence.values()],
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
    const ops: { ts: bigint; raw: Uint8Array }[] = [], evidence: AdmissionEvidence[] = []
    const LAST = 1n << 62n
    for (const id of ids) {
      if (scope === 'private') {
        const env = this.#encryptedEnvelopes.get(id)
        if (env !== undefined) ops.push({ ts: env.decrypted?.core.authorTimestampMs ?? LAST, raw: env.raw })
        continue
      }
      const op = this.#publicOps.get(id)
      if (op !== undefined) { ops.push({ ts: op.core.authorTimestampMs, raw: op.raw }); continue }
      const ev = this.#evidence.get(id)
      if (ev !== undefined) evidence.push(ev)
    }
    ops.sort((a, b) => a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0)
    const raws = ops.map(op => op.raw)
    return { publicOps: scope === 'public' ? raws : [], encryptedEnvelopes: scope === 'private' ? raws : [], casNodes: [], retentions: [], evidence }
  }

  /** CAS nodes by hash for an on-demand peer pull; walks explicit CasNode.links when subgraph=true. */
  async exportCasNodes(
    hashes: readonly string[],
    includePrivate: boolean,
    options: { readonly subgraph?: boolean; readonly maxNodes?: number; readonly maxBytes?: number } = {},
  ): Promise<SessionCasNode[]> {
    if (options.subgraph === true) {
      const sub = await this.cas.collectSubgraph(hashes, {
        allowedPartition: includePrivate ? 'any' : 'public',
        ...(options.maxNodes === undefined ? {} : { maxNodes: options.maxNodes }),
        ...(options.maxBytes === undefined ? {} : { maxBytes: options.maxBytes }),
      })
      return [...sub]
    }
    const out: SessionCasNode[] = []
    for (const hash of hashes) {
      for (const partition of includePrivate ? ['public', 'private'] as const : ['public'] as const) {
        const raw = await this.cas.getRaw(hash, partition)
        if (raw !== null) { out.push({ hash, bytes: raw, partition }); break }
      }
    }
    return out
  }

  /** Fetch missing public CAS subgraphs from configured untrusted HTTP CAS mirrors. */
  async #pullMissingFromMirrors(): Promise<number> {
    if (this.#casMirrors.length === 0) return 0
    let addedTotal = 0
    const missing = this.missingCasDependencies().filter(h => !this.#mirrorAttempted.has(h))
    for (const hash of missing) {
      if (this.cas.hasSync(hash, 'public')) continue
      this.#mirrorAttempted.add(hash)
      for (const mirror of this.#casMirrors) {
        try {
          const client = createCasMirrorClient(mirror)
          const nodes = await client.fetchSubgraph(hash, { maxNodes: 256, maxBytes: 8 * 1024 * 1024 })
          if (nodes.length === 0) continue
          const added = await this.cas.putManyVerified(
            nodes.map(n => ({ hash: n.hash, bytes: n.bytes, partition: 'public' as const })),
          )
          addedTotal += added
          if (this.cas.hasSync(hash, 'public')) break
        } catch { /* try next mirror */ }
      }
    }
    return addedTotal
  }

  /**
   * Install a content-addressed `chronolog-pkg/v1` package (or pre-packed bundle / existing CAS ref)
   * into this log's `$reducers` topic in one ergonomic call.
   */
  async installPackage(
    pkg:
      | string
      | (PutPackageInput & { readonly partition?: CasPartition })
      | { readonly ref: string; readonly casNodes: readonly SessionCasNode[] },
    options: {
      readonly alias: string
      readonly topics?: Readonly<Record<string, { readonly export?: string; readonly config?: JsonValue }>>
      readonly partition?: CasPartition
      readonly attestations?: readonly JsonValue[]
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    },
  ): Promise<{ readonly pkgRef: string; readonly operation: ApplicationOperation }> {
    let pkgRef: string
    if (typeof pkg === 'string') {
      pkgRef = casRef(tryParseCasRef(pkg) ?? pkg)
    } else if ('casNodes' in pkg && 'ref' in pkg) {
      if (pkg.casNodes.length > 0) {
        await this.cas.putManyVerified(pkg.casNodes)
      }
      pkgRef = casRef(parseCasRef(pkg.ref))
    } else {
      const pkgInput = pkg
      const partition: CasPartition = (options.partition ?? pkgInput.partition) === 'private' && this.genesis.privateLog
        ? 'private'
        : 'public'
      const placed = await putPackageDag(this.cas, pkgInput, partition)
      pkgRef = placed.ref
    }

    const topicUpdates: Record<string, JsonValue> = {}
    if (options.topics !== undefined) {
      for (const [topicName, binding] of Object.entries(options.topics)) {
        topicUpdates[topicName] = {
          module: options.alias,
          ...(binding.export === undefined ? {} : { export: binding.export }),
          ...(binding.config === undefined ? {} : { config: binding.config }),
        }
      }
    }
    const payload: Record<string, JsonValue> = {
      imports: { [options.alias]: pkgRef },
      ...(Object.keys(topicUpdates).length > 0 ? { topics: topicUpdates } : {}),
      ...(options.attestations !== undefined ? { attestations: options.attestations } : {}),
    }
    const operation = await this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{ topic: '$reducers', input: payload }],
    })
    return { pkgRef, operation }
  }

  /**
   * Pin a verified snapshot of an external Chronolog log into `$mounts` so reducers can query it
   * deterministically via `ctx.mount(name)` and `ctx.mountQuery(name, topic, input)`.
   */
  async mountLog(
    name: string,
    source: ApplicationSession | {
      readonly logId: string
      readonly stateRoot: string
      readonly topics: Readonly<Record<string, JsonValue>>
      readonly casNodes?: readonly SessionCasNode[]
      readonly trustedSigners?: readonly string[]
      readonly signer?: string
      readonly signature?: string
    },
    options: {
      readonly trustedSigners?: readonly string[]
      readonly operationId?: string
      readonly authorTimestampMs?: bigint
    } = {},
  ): Promise<ApplicationOperation> {
    let logId: string
    let stateRoot: string
    let topics: Readonly<Record<string, JsonValue>>
    let casNodes: readonly SessionCasNode[]
    let signer: string | undefined
    let signature: string | undefined

    if (source instanceof ApplicationSession) {
      const snap = source.#kernel.snapshot()
      logId = source.logId
      stateRoot = snap.stateRoot
      topics = snap.topics
      const exported = await source.exportFacts({ includePrivateCas: !source.genesis.privateLog })
      // Mounted snapshots live inside the public $mounts control topic, so their reachable CAS nodes are placed in public CAS.
      casNodes = exported.casNodes.map(n => ({ hash: n.hash, bytes: n.bytes, partition: 'public' as const }))
      const msg = utf8(`chronolog/mount/v1:${canonicalJson({ logId, stateRoot, topics })}`)
      signer = source.device.identity.publicKey
      signature = bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519', source.device.identity.privateKey, new Uint8Array(msg))))
    } else {
      logId = source.logId
      stateRoot = source.stateRoot
      topics = source.topics
      casNodes = source.casNodes ?? []
      signer = source.signer
      signature = source.signature
    }

    if (casNodes.length > 0) {
      await this.cas.putManyVerified(casNodes)
    }
    const casRoots = [...new Set(casNodes.map(n => n.hash))].sort()
    const payload: Record<string, JsonValue> = {
      action: 'update',
      name,
      logId,
      stateRoot,
      topics,
      casRoots,
      ...(options.trustedSigners !== undefined ? { trustedSigners: [...options.trustedSigners] } : {}),
      ...(signer !== undefined && signature !== undefined ? { signer, signature } : {}),
    }
    return this.submit({
      visibility: 'public',
      awaitMaterialized: true,
      ...(options.operationId === undefined ? {} : { operationId: options.operationId }),
      ...(options.authorTimestampMs === undefined ? {} : { authorTimestampMs: options.authorTimestampMs }),
      updates: [{ topic: '$mounts', input: payload }],
    })
  }

  /**
   * Evaluate (or retrieve from local memo cache or trusted `$builders` derivation mirror)
   * a content-addressed `chronolog-drv/v1` derivation.
   */
  async evaluateDerivation(
    drvRefOrHash: string,
    options: {
      readonly partition?: CasPartition
      readonly skipMemo?: boolean
      readonly skipMirror?: boolean
      readonly mirrors?: readonly string[]
      readonly trustedBuilders?: readonly string[]
      readonly threshold?: number
      readonly wasiRunners?: Readonly<Record<string, WasiDerivationRunner>>
    } = {},
  ): Promise<DerivationEvalResult & { readonly attestedBy?: readonly string[] }> {
    const memo = createBytesStoreDerivationMemo(this.#store, `${this.#prefix}/drv-memo/`)
    const drvHash = tryParseCasRef(drvRefOrHash) ?? drvRefOrHash
    const partition: CasPartition = options.partition ?? 'public'

    // Check trusted mirror derivation cache (against explicit trustedBuilders or log's $builders topic)
    if (!options.skipMirror && partition === 'public') {
      const buildersTopic = this.topic('$builders') as {
        readonly builders?: readonly string[]
        readonly threshold?: number
      } | undefined
      const trustedBuilders = options.trustedBuilders ?? buildersTopic?.builders ?? []
      const threshold = options.threshold ?? buildersTopic?.threshold ?? 1
      const mirrorUrls = options.mirrors ?? this.#casMirrors
      if (trustedBuilders.length > 0 && mirrorUrls.length > 0 && /^[0-9a-f]{64}$/u.test(drvHash)) {
        for (const mirror of mirrorUrls) {
          try {
            const client = createCasMirrorClient(mirror)
            const { trusted } = await client.fetchDerivationAttestations(drvHash, { trustedBuilders, threshold })
            if (trusted === null) continue
            const nodes = await client.fetchSubgraph(trusted.outputHash, { maxNodes: 512, maxBytes: 16 * 1024 * 1024 })
            if (nodes.length === 0) continue
            await this.cas.putManyVerified(
              nodes.map(n => ({ hash: n.hash, bytes: n.bytes, partition: 'public' as const })),
            )
            if (this.cas.hasSync(trusted.outputHash, 'public')) {
              await memo.set(drvHash, trusted.outputHash)
              return {
                drvHash,
                drvRef: casRef(drvHash),
                outputHash: trusted.outputHash,
                outputRef: trusted.outputRef,
                fromCache: true,
                attestedBy: trusted.signers,
              }
            }
          } catch { /* fall through to next mirror or local execution */ }
        }
      }
    }

    return evaluateDerivation({
      drvRefOrHash,
      cas: this.cas,
      sandbox: this.#kernel.sandbox,
      memo,
      ...(options.partition === undefined ? {} : { partition: options.partition }),
      ...(options.skipMemo === undefined ? {} : { skipMemo: options.skipMemo }),
      ...(options.wasiRunners === undefined ? {} : { wasiRunners: options.wasiRunners }),
    })
  }

  /** CAS hashes replay or TreeKEM key unsealing is blocked on (modules, reducer-read nodes, SQLite pages, key-tree DAG nodes). */
  missingCasDependencies(): string[] {
    const out = new Set<string>(this.#missingTreeCasHashes)
    for (const kernel of [this.#kernel, this.#controlKernel, this.#admittedControlKernel, this.#probeKernel, this.#finalKernel]) {
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
    readonly evidence: readonly AdmissionEvidence[]
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
      evidence: [...this.#evidence.values()],
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

      const retainedOpIds: string[] = []
      for (const ev of facts.retentions ?? []) {
        if (ev.payload.applicationId !== this.applicationId || !Array.isArray(ev.payload.items)) continue
        if (ev.payload.items.length > MAX_RETENTION_ITEMS || ev.payload.peer !== ev.signer) continue
        // Receipts from non-members are spam: never verified, persisted or regossiped.
        if (!this.isMember(ev.signer)) continue
        // Verify once per batch receipt, and only if it says something new.
        if (ev.payload.items.every((opId: string) => this.#retentions.get(opId)?.has(ev.signer) === true)) continue
        await verifyRecord('operation-retention', ev, ev.signer)
        if (this.#indexRetention(ev)) {
          storeBatch.push({ key: `${this.#prefix}/retention/${await recordDigest(ev.payload)}`, value: encodeRecord(ev) })
          factsChanged = true
          if (ev.signer !== this.identity.publicKey) for (const opId of ev.payload.items) if (typeof opId === 'string') retainedOpIds.push(opId)
        }
      }

      for (const ev of facts.evidence ?? []) {
        if (ev === null || typeof ev !== 'object' || typeof ev.kind !== 'string') continue
        const payloadLogId = (ev.payload as { readonly logId?: unknown } | null)?.logId
        if (typeof payloadLogId === 'string' && payloadLogId !== this.logId) continue
        const key = await evidenceDigest(ev)
        if (!this.#evidence.has(key)) {
          this.#evidence.setFrom(key, ev, source)
          storeBatch.push({ key: `${this.#prefix}/evidence/${key}`, value: encodeRecord(ev) })
          materializedChanged = true
          factsChanged = true
        }
      }

      if (storeBatch.length > 0) {
        for (let i = 0; i < storeBatch.length; i += 128) {
          await writeBytesMany(this.#store, storeBatch.slice(i, i + 128), { durability: 'relaxed' })
        }
      }

      if (materializedChanged) {
        await this.#rematerialize()
      } else if (factsChanged) {
        this.#emitStatus()
      }
      if (retainedOpIds.length > 0) await this.#settleLocalPending(retainedOpIds)
      if (factsChanged) {
        this.#emitFacts()
      }
    }
  }

  async collectGarbage(): Promise<{ readonly kept: number; readonly deleted: number }> {
    return this.#serial(async () => {
      await this.#flushPendingMaterialization()
      const roots = this.#kernel.gcRoots()
      for (const kernel of [this.#controlKernel, this.#admittedControlKernel, this.#probeKernel, this.#finalKernel]) {
        if (kernel !== null) for (const r of kernel.gcRoots()) roots.add(r)
      }
      for (const hash of standardModuleHashes()) roots.add(hash)
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
      this.#visibilityCleanup?.()
      this.#closed = true
      this.#lifetime.abort(new Error('SESSION_CLOSED'))
      this.#emitStatus()
      this.#kernel.dispose()
      this.#controlKernel?.dispose()
      this.#admittedControlKernel?.dispose()
      this.#probeKernel?.dispose()
      this.#finalKernel?.dispose()
      await this.wipeSecrets()
      await this.content.close()
      await this.#release()
    })()
  }
}

/** Binary local-pending record: CBOR [1, signed op bytes, envelope digest, epoch, epoch-key commitment]. */
function encodeLocalPending(raw: Uint8Array, envelopeDigest: string, epoch: number, commitment: string): Uint8Array {
  return encodeCanonicalCbor([1n, raw, hexToBytes(envelopeDigest), BigInt(epoch), hexToBytes(commitment)])
}

function decodeLocalPending(bytes: Uint8Array): { readonly raw: Uint8Array; readonly envelopeDigest: string; readonly epoch: number; readonly commitment: string } {
  const value = decodeCanonicalCbor(bytes, DEFAULT_DECODE_LIMITS)
  check(Array.isArray(value) && value.length === 5 && value[0] === 1n && value[1] instanceof Uint8Array &&
    value[2] instanceof Uint8Array && value[2].length === 32 && typeof value[3] === 'bigint' &&
    value[4] instanceof Uint8Array && value[4].length === 32, 'LOCAL_PENDING_INVALID')
  const [, raw, digest, epoch, commitment] = value as unknown as readonly [bigint, Uint8Array, Uint8Array, bigint, Uint8Array]
  return { raw, envelopeDigest: bytesToHex(digest), epoch: Number(epoch), commitment: bytesToHex(commitment) }
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

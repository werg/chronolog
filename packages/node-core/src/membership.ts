import {
  capabilityRevisionDigest, decodeSignedGenesis, encodeGenesisManifest, encodeSignedGenesis, isCapabilityActive, signGenesis,
  type CapabilityGrant, type CapabilitySnapshot, type GenesisManifest,
} from '@chronolog/capabilities'
import {
  DOMAINS, assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, equalBytes, exportEd25519PrivateKey,
  generateEd25519KeyPair, hashDomain, importEd25519PrivateKey, importEd25519PublicKey, utf8, type Ed25519KeyPair,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner,
  type ChronologTransport } from '@chronolog/records'

import { Mutex } from './async.js'
import {
  EnrollmentIssuer, verifyEnrollmentDescriptor,
  type EnrollmentDescriptor, type EnrollmentFinalTarget, type SignedEnrollmentRequest,
} from './enrollment.js'
import { GovernanceActivationIndex } from './governance-activation.js'
import { GovernanceControlPlane, GovernanceRecordPendingError, isInvalidGovernanceRecord, orderFinalizedGovernanceRecords } from './governance.js'
import { CoordinatedHistoryPolicy, verifyOrderedEntry, type CoordinatedProgress } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { DurableOperationJournal, validateOperationId, type DurableOperationStore } from './operations.js'
import type { MembershipLedger, MembershipLedgerPage } from './membership-wire.js'

export * from './membership-wire.js'
export { encodeSignedGenesis, decodeSignedGenesis } from '@chronolog/capabilities'
export {
  decodeSignedEnrollmentRequest, decodeSignedEnrollmentApproval, encodeSignedEnrollmentRequest, encodeSignedEnrollmentApproval,
  loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest, enrollmentProgress, verifyEnrollmentApproval, verifySignedEnrollmentRequest,
} from './enrollment.js'
export type { EnrollmentDescriptor, EnrollmentFinalTarget, SignedEnrollmentRequest, SignedEnrollmentApproval, EnrollmentRole } from './enrollment.js'
export type { DurableOperationStore } from './operations.js'

export interface MembershipProvisionOptions {
  readonly store: DurableOperationStore
  readonly executionManifestDigest: Uint8Array
  /** Application schema authority is distinct from the membership administrator. */
  readonly schemaAdministratorPublicKey: Uint8Array
  readonly nativeAuthority: { readonly historyId: string; readonly publicKey: Uint8Array }
  /** Signed selection of the finality verifier; omitted values select the built-in provider. */
  readonly providerId?: string
  readonly providerParameters?: Uint8Array
  /** Public bootstrap grants; joining devices keep their private keys. */
  readonly initialCapabilities?: readonly CapabilityGrant[]
  readonly groupId?: Uint8Array
  readonly groupRoute?: Uint8Array
  readonly now?: () => number
}

export interface ProvisionedMembership {
  readonly descriptor: EnrollmentDescriptor
  /** Private host-only signer, never included in an HTTP provisioning response. */
  readonly identity: Ed25519KeyPair
}

const provisionLocks = new WeakMap<DurableOperationStore, Mutex>()
function provisionLock(store: DurableOperationStore): Mutex {
  let mutex = provisionLocks.get(store)
  if (mutex === undefined) { mutex = new Mutex(); provisionLocks.set(store, mutex) }
  return mutex
}

/** Creates one group and administrator in the host's durable private store. No reader identity or SQL engine is needed. */
export async function provisionMembership(options: MembershipProvisionOptions): Promise<ProvisionedMembership> {
  const store = options.store, now = options.now ?? Date.now
  const input = structuredClone({ executionManifestDigest: options.executionManifestDigest, schemaAdministratorPublicKey: options.schemaAdministratorPublicKey, nativeAuthority: options.nativeAuthority,
    providerId: options.providerId, providerParameters: options.providerParameters,
    initialCapabilities: options.initialCapabilities ?? [], groupId: options.groupId, groupRoute: options.groupRoute })
  for (const value of [input.executionManifestDigest, input.schemaAdministratorPublicKey, input.nativeAuthority.publicKey, input.groupId, input.groupRoute]) {
    if (value !== undefined && (!(value instanceof Uint8Array) || value.length !== 32)) throw new Error('MEMBERSHIP_CONFIGURATION_INVALID')
  }
  if (input.initialCapabilities.some(grant => grant.validFromRevision !== 0n || !['reader', 'writer'].includes(grant.role))) {
    throw new Error('MEMBERSHIP_INITIAL_GRANT_INVALID')
  }
  return provisionLock(store).run(async () => {
    const identity = await loadAdministratorIdentity(store)
    const manifest = (groupId: Uint8Array, createdAtMs: bigint): GenesisManifest => ({
      groupId, schemaId: input.executionManifestDigest, rootAdminPublicKey: identity.publicKeyBytes, schemaAdminPublicKey: input.schemaAdministratorPublicKey,
      capabilityLogFeed: utf8(feedIdFromPublicKey(identity.publicKeyBytes)),
      historyPolicy: { kind: 'coordinated', executionManifestDigest: input.executionManifestDigest,
        historyId: input.nativeAuthority.historyId, authorityPublicKey: input.nativeAuthority.publicKey,
        ...(input.providerId === undefined ? {} : { providerId: input.providerId }),
        ...(input.providerParameters === undefined ? {} : { providerParameters: input.providerParameters }) },
      initialCapabilities: [{ subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes,
        transportAuthor: feedIdFromPublicKey(identity.publicKeyBytes), role: 'administrator', validFromRevision: 0n }, ...input.initialCapabilities],
      validationPolicies: [{ version: 1n, minimumValidators: 1n }],
      clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
      resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
      encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs,
    })
    const fingerprint = encodeCanonicalCbor([encodeGenesisManifest(manifest(input.groupId ?? new Uint8Array(32), 0n)), input.groupRoute ?? null])
    const saved = await store.get('membership/provision')
    if (saved !== null) {
      const value = assertCanonicalCbor(saved)
      if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
          !(value[2] instanceof Uint8Array) || !(value[3] instanceof Uint8Array)) throw new Error('MEMBERSHIP_STORE_INVALID')
      if (!equalBytes(value[1], fingerprint)) throw new Error('MEMBERSHIP_CONFIGURATION_CONFLICT')
      const descriptor = await membershipDescriptor(decodeSignedGenesis(value[2]), value[3])
      if (!equalBytes(descriptor.genesis.manifest.rootAdminPublicKey, identity.publicKeyBytes)) throw new Error('MEMBERSHIP_ROOT_KEY_MISMATCH')
      return { descriptor, identity }
    }
    const timestamp = now()
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('MEMBERSHIP_TIME_INVALID')
    const genesis = await signGenesis(manifest(input.groupId ?? crypto.getRandomValues(new Uint8Array(32)), BigInt(timestamp)), identity.privateKey)
    const descriptor = await membershipDescriptor(genesis, input.groupRoute ?? crypto.getRandomValues(new Uint8Array(32)))
    await store.put('membership/provision', encodeCanonicalCbor([1n, fingerprint, encodeSignedGenesis(genesis), descriptor.groupRoute]))
    return { descriptor, identity }
  })
}

/** Signed genesis is the execution-profile source; no materializer is loaded to describe a group. */
export async function membershipDescriptor(genesis: EnrollmentDescriptor['genesis'], groupRoute: Uint8Array): Promise<EnrollmentDescriptor> {
  genesis = decodeSignedGenesis(encodeSignedGenesis(genesis)); groupRoute = groupRoute.slice()
  const history = genesis.manifest.historyPolicy
  if (history?.kind !== 'coordinated' || history.historyId === undefined || history.authorityPublicKey === undefined) {
    throw new Error('MEMBERSHIP_COORDINATED_HISTORY_REQUIRED')
  }
  const descriptor: EnrollmentDescriptor = { genesis, groupRoute, history: {
    kind: 'coordinated', historyId: history.historyId, authorityPublicKey: history.authorityPublicKey,
    groupId: genesis.manifest.groupId, executionManifestDigest: history.executionManifestDigest,
    genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)),
    ...(history.providerId === undefined ? {} : { providerId: history.providerId }),
    ...(history.providerParameters === undefined ? {} : { providerParameters: history.providerParameters }),
  } }
  await verifyEnrollmentDescriptor(descriptor)
  return descriptor
}

export function encodeMembershipFinalTarget(descriptor: EnrollmentDescriptor, position: number, root: string, closedThroughMs: bigint): Uint8Array {
  if (descriptor.history.kind !== 'coordinated' || !Number.isSafeInteger(position) || position < 0 ||
      !/^[0-9a-f]{64}$/u.test(root) || closedThroughMs < 0n) {
    throw new Error('MEMBERSHIP_TARGET_INVALID')
  }
  return encodeCanonicalCbor([4n, descriptor.history.groupId, 'chronological', descriptor.history.historyId, BigInt(position), root, closedThroughMs])
}

export interface MembershipRevocation {
  readonly membershipRevision: Uint8Array
  readonly epoch: bigint
  readonly target: EnrollmentFinalTarget
}

/**
 * Portable administrator with one control feed, one key service and one durable
 * authoring journal. It verifies every small ordered descriptor, applies inline
 * governance only, and has no application-body fetch or SQL execution capability.
 */
export class MembershipAdministrator {
  readonly #descriptor: EnrollmentDescriptor
  readonly #identity: Ed25519KeyPair
  readonly #store: DurableOperationStore
  readonly #ledger: MembershipLedger
  readonly #local: PortableFeedTransport
  readonly #governance: GovernanceControlPlane
  readonly #policy: CoordinatedHistoryPolicy
  readonly #activation: GovernanceActivationIndex
  readonly #issuer: EnrollmentIssuer
  readonly #revocations: DurableOperationJournal
  readonly #mutex = new Mutex()
  readonly #abort = new AbortController()
  #signal: AbortSignal
  readonly #handledControls = new Set<number>()
  #pendingControls = false
  #published = 0
  #closed = false

  private constructor(options: { descriptor: EnrollmentDescriptor; identity: Ed25519KeyPair; store: DurableOperationStore;
    ledger: MembershipLedger; local: PortableFeedTransport; governance: GovernanceControlPlane; policy: CoordinatedHistoryPolicy }) {
    this.#descriptor = options.descriptor; this.#identity = options.identity; this.#store = options.store; this.#ledger = options.ledger
    this.#local = options.local; this.#governance = options.governance; this.#policy = options.policy
    this.#activation = new GovernanceActivationIndex(options.governance.revisionSnapshots[0]!, 'coordinated')
    this.#signal = this.#abort.signal
    this.#revocations = new DurableOperationJournal(options.store, 'membership/revocations')
    this.#issuer = new EnrollmentIssuer({ descriptor: options.descriptor, governance: options.governance, store: options.store,
      rootPrivateKey: options.identity.privateKey, captureFinalTarget: async () => {
        await this.#sync()
        if (this.#activation.activeSnapshot.revision !== this.#governance.snapshot.revision ||
            this.#policy.closedReceiptThrough < this.#published || this.#pendingControls) throw new Error('MEMBERSHIP_PREFIX_PENDING')
        return this.#target()
      } })
  }

  static async open(input: { readonly descriptor: EnrollmentDescriptor; readonly identity: Ed25519KeyPair;
    readonly store: DurableOperationStore; readonly ledger: MembershipLedger }): Promise<MembershipAdministrator> {
    const descriptor = structuredClone(input.descriptor), identity = { ...input.identity, publicKeyBytes: input.identity.publicKeyBytes.slice() }
    await verifyEnrollmentDescriptor(descriptor)
    if (descriptor.history.kind !== 'coordinated') throw new Error('MEMBERSHIP_COORDINATED_HISTORY_REQUIRED')
    if ((descriptor.history.providerId ?? 'signed-inclusion-v1') !== 'signed-inclusion-v1') throw new Error('FINALITY_PROVIDER_UNAVAILABLE')
    const history = descriptor.history
    if (!equalBytes(identity.publicKeyBytes, descriptor.genesis.manifest.rootAdminPublicKey) ||
        new TextDecoder().decode(descriptor.genesis.manifest.capabilityLogFeed) !== feedIdFromPublicKey(identity.publicKeyBytes)) {
      throw new Error('MEMBERSHIP_ROOT_KEY_REQUIRED')
    }
    const local = new PortableFeedTransport({ store: await DurableFeedStore.open(namespace(input.store, 'membership/control/'), webFeedCrypto),
      crypto: webFeedCrypto, signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const transport: ChronologTransport = {
      identity: local.identity, publish: (bytes, options) => local.publish(bytes, options),
      get: id => local.get(id), history: () => local.history(), subscribe: signal => local.subscribe(signal),
      getPayload: async () => { throw new Error('MEMBERSHIP_APPLICATION_PAYLOAD_DISABLED') },
      status: () => local.status(), close: () => local.close(), requestFeed: feed => local.requestFeed(feed),
      feedContiguousThrough: feed => local.feedContiguousThrough(feed),
      ensurePublished: async record => {
        const saved = await local.get(record.id)
        if (saved === undefined || saved.author !== local.identity || !equalBytes(saved.payload, record.payload)) {
          throw new Error('MEMBERSHIP_CONTROL_NOT_DURABLE')
        }
        const { recordBytes, record: descriptorRecord } = await createLedgerRecord(saved.payload)
        if (descriptorRecord.kind === 'candidate') throw new Error('MEMBERSHIP_CONTROL_RECORD_REQUIRED')
        const entry = await input.ledger.append(recordBytes, { signal: administrator.#signal })
        await verifyOrderedEntry(entry)
        if (entry.historyId !== history.historyId || !equalBytes(entry.bytes, recordBytes)) throw new Error('MEMBERSHIP_APPEND_MISMATCH')
        administrator.#published = Math.max(administrator.#published, entry.position)
      },
    }
    const governance = await GovernanceControlPlane.create({ genesis: descriptor.genesis, groupRoute: descriptor.groupRoute,
      identity, operationStore: input.store, transport, replication: 'administration' })
    const policy = await CoordinatedHistoryPolicy.open(descriptor.history, namespace(input.store, 'membership/ledger/'))
    const administrator = new MembershipAdministrator({ descriptor, identity, store: input.store, ledger: input.ledger, local, governance, policy })
    try {
      await governance.start()
      await administrator.#revocations.recover(bytes => administrator.#applyRevocation(bytes))
      if (governance.currentEpoch === null) await governance.rotateEpoch(identity.privateKey, undefined, { operationId: 'membership-bootstrap-epoch' })
      await administrator.#sync()
      return administrator
    } catch (error) { await administrator.close(); throw error }
  }

  get descriptor(): EnrollmentDescriptor { return structuredClone(this.#descriptor) }
  get snapshot(): CapabilitySnapshot { return this.#activation.activeSnapshot }
  get progress(): CoordinatedProgress { return this.#policy.progress }
  get epochs(): readonly bigint[] { return this.#governance.knownEpochs }

  /** Approved devices obtain verified inline grants/key wraps before their reader-authenticated peer connection. */
  read(options: { readonly after: number; readonly limit?: number }): MembershipLedgerPage {
    const after = options.after, limit = options.limit ?? 128, through = this.#policy.progress.verifiedThrough
    if (!Number.isSafeInteger(after) || after < 0 || after > through || !Number.isSafeInteger(limit) || limit < 1 || limit > 128) {
      throw new Error('MEMBERSHIP_RANGE_INVALID')
    }
    const certificate = this.#policy.evidence().find(evidence => evidence.kind === 'prefix-certificate' && evidence.certificate.position === through)
    if (certificate?.kind !== 'prefix-certificate') throw new Error('MEMBERSHIP_PREFIX_PENDING')
    const entries = []
    let bytes = 0
    for (const entry of this.#policy.entries().slice(after, after + limit)) {
      if (entries.length && bytes + entry.bytes.length > 1024 * 1024) break
      entries.push(entry); bytes += entry.bytes.length
    }
    return { entries, certificate: certificate.certificate, hasMore: after + entries.length < through }
  }

  sync(options: { readonly signal?: AbortSignal } = {}): Promise<CoordinatedProgress> {
    return this.#run(async () => { await this.#sync(); return this.progress }, options.signal)
  }

  approve(request: SignedEnrollmentRequest, decision: Parameters<EnrollmentIssuer['approve']>[1], options: { readonly signal?: AbortSignal } = {}) {
    const capturedRequest = structuredClone(request), capturedDecision = structuredClone(decision)
    return this.#run(async () => {
      await this.#revocations.recover(bytes => this.#applyRevocation(bytes))
      await this.#sync()
      return this.#issuer.approve(capturedRequest, capturedDecision)
    }, options.signal)
  }

  revoke(input: { readonly operationId: string; readonly capabilityIds: readonly Uint8Array[] }, options: { readonly signal?: AbortSignal } = {}): Promise<MembershipRevocation> {
    const captured = structuredClone(input)
    validateOperationId(captured.operationId)
    if (!captured.capabilityIds.length || captured.capabilityIds.length > 128 || captured.capabilityIds.some(id => id.length !== 32)) {
      throw new Error('MEMBERSHIP_REVOCATION_INVALID')
    }
    const ids = [...new Map(captured.capabilityIds.map(id => [bytesToHex(id), id])).entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, id]) => id)
    return this.#run(async () => {
      await this.#sync()
      const payload = await this.#revocations.run({ operationId: captured.operationId, fingerprint: encodeCanonicalCbor(ids),
        prepare: async () => {
          for (const id of ids) {
            const capability = this.#governance.snapshot.capabilities.get(bytesToHex(id))
            if (capability === undefined || !['reader', 'writer'].includes(capability.grant.role) ||
                !isCapabilityActive(capability, this.#governance.snapshot.revision)) throw new Error('MEMBERSHIP_REVOCATION_INVALID')
          }
          const key = bytesToHex(await hashDomain(DOMAINS.capabilityRevision, encodeCanonicalCbor([captured.operationId, ids])))
          return encodeCanonicalCbor([1n, key, ids])
        }, apply: bytes => this.#applyRevocation(bytes) })
      const key = revocationInput(payload).key, result = await this.#store.get(`membership/revocation-result/${key}`)
      if (result === null) throw new Error('MEMBERSHIP_REVOCATION_RESULT_MISSING')
      return decodeRevocation(result)
    }, options.signal)
  }

  async close(): Promise<void> {
    if (this.#closed) return
    this.#closed = true; this.#abort.abort()
    await this.#mutex.run(async () => { await this.#governance.close(); await this.#local.close() })
  }

  #run<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    return this.#mutex.run(async () => {
      if (this.#closed) throw new Error('MEMBERSHIP_CLOSED')
      this.#signal = signal === undefined ? this.#abort.signal : AbortSignal.any([signal, this.#abort.signal])
      this.#signal.throwIfAborted()
      try { return await operation() } finally { this.#signal = this.#abort.signal }
    })
  }

  async #sync(): Promise<void> {
    this.#signal.throwIfAborted()
    let cursor = this.#policy.progress.verifiedThrough, target: number | undefined
    do {
      const page = await this.#ledger.read({ after: cursor, limit: 128, signal: this.#signal })
      if (page.entries.length > 128) throw new Error('MEMBERSHIP_RANGE_TOO_LARGE')
      for (const entry of page.entries) {
        if (entry.position !== cursor + 1) throw new Error('MEMBERSHIP_RANGE_GAP')
        // Ordering authenticates exact bytes, including positions whose
        // descriptor is invalid or belongs to another group. Retain them for
        // the prefix proof; application interpretation cannot create a gap.
        cursor = entry.position
      }
      await this.#policy.ingestBatch([
        ...page.entries.map(entry => ({ kind: 'ordered-entry' as const, entry })),
        { kind: 'prefix-certificate', certificate: page.certificate },
      ])
      target ??= page.certificate.position
      if (cursor < target && page.entries.length === 0) throw new Error('MEMBERSHIP_RANGE_GAP')
      this.#signal.throwIfAborted()
    } while (cursor < target)
    const controls = await orderFinalizedGovernanceRecords(this.#policy.snapshot().records.flatMap(record =>
      record.closureBoundary === null || this.#handledControls.has(record.entry.position) ? []
        : [{ entry: record.entry, cutoffMs: record.closureBoundary.closedThroughMs }]), this.#descriptor.groupRoute)
    this.#pendingControls = false
    for (const { entry, cutoffMs } of controls) {
      try {
        const snapshot = await this.#governance.ingestFinalized(entry, this.#activation.activeSnapshot, cutoffMs)
        if (snapshot !== null && snapshot.revision > this.#activation.activeSnapshot.revision) {
          this.#activation.observe(snapshot); this.#activation.activateFinalized(snapshot, cutoffMs)
        }
      } catch (error) {
        if (error instanceof GovernanceRecordPendingError) { this.#pendingControls = true; continue }
        if (!isInvalidGovernanceRecord(error)) throw error
      }
      this.#handledControls.add(entry.position)
    }
  }

  #target(): EnrollmentFinalTarget {
    const closure = this.#policy.snapshot().closures.at(-1)
    if (closure === undefined || this.#pendingControls) throw new Error('MEMBERSHIP_PREFIX_PENDING')
    return { frontier: encodeMembershipFinalTarget(this.#descriptor, closure.includedThrough, closure.includedRoot, closure.closedThroughMs),
      requiredEpochs: this.#governance.knownEpochs, executionManifestDigest: this.#descriptor.history.executionManifestDigest.slice() }
  }

  async #applyRevocation(bytes: Uint8Array): Promise<void> {
    const { key, ids } = revocationInput(bytes), resultKey = `membership/revocation-result/${key}`
    if (await this.#store.get(resultKey) !== null) return
    const revision = await this.#governance.revoke(ids, this.#identity.privateKey, { operationId: `revoke:${key}` })
    const epoch = await this.#governance.rotateEpoch(this.#identity.privateKey, undefined, { operationId: `rotate:${key}` })
    await this.#sync()
    if (this.#policy.closedReceiptThrough < this.#published || this.#pendingControls) throw new Error('MEMBERSHIP_PREFIX_PENDING')
    const target = this.#target()
    await this.#store.put(resultKey, encodeCanonicalCbor([1n, await capabilityRevisionDigest(revision.revision),
      epoch.manifest.epoch, target.frontier, target.requiredEpochs, target.executionManifestDigest]))
  }
}

async function loadAdministratorIdentity(store: DurableOperationStore): Promise<Ed25519KeyPair> {
  let saved = await store.get('membership/identity')
  if (saved === null) {
    const identity = await generateEd25519KeyPair()
    saved = encodeCanonicalCbor([1n, identity.publicKeyBytes, await exportEd25519PrivateKey(identity.privateKey)])
    await store.put('membership/identity', saved)
  }
  const value = assertCanonicalCbor(saved)
  if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
      value[1].length !== 32 || !(value[2] instanceof Uint8Array)) throw new Error('MEMBERSHIP_IDENTITY_INVALID')
  return { publicKeyBytes: value[1].slice(), publicKey: await importEd25519PublicKey(value[1]), privateKey: await importEd25519PrivateKey(value[2]) }
}

function namespace(store: DurableOperationStore, prefix: string): DurableOperationStore {
  return { get: key => store.get(prefix + key), put: (key, bytes) => store.put(prefix + key, bytes) }
}

function revocationInput(bytes: Uint8Array): { key: string; ids: readonly Uint8Array[] } {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n || typeof value[1] !== 'string' || !/^[0-9a-f]{64}$/u.test(value[1]) ||
      !Array.isArray(value[2]) || !value[2].length || !value[2].every(id => id instanceof Uint8Array && id.length === 32)) {
    throw new Error('MEMBERSHIP_REVOCATION_STORE_INVALID')
  }
  return { key: value[1], ids: value[2] as Uint8Array[] }
}

function decodeRevocation(bytes: Uint8Array): MembershipRevocation {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 6 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
      typeof value[2] !== 'bigint' || !(value[3] instanceof Uint8Array) || !Array.isArray(value[4]) ||
      !value[4].every(epoch => typeof epoch === 'bigint') || !(value[5] instanceof Uint8Array)) throw new Error('MEMBERSHIP_REVOCATION_STORE_INVALID')
  return { membershipRevision: value[1], epoch: value[2], target: { frontier: value[3], requiredEpochs: value[4], executionManifestDigest: value[5] } }
}

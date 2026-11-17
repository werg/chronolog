import {
  applyCapabilityRevision,
  capabilityId,
  capabilityRevisionDigest,
  decodeSignedCapabilityRevision as decodeSignedCapabilityRevisionBytes,
  encodeCapabilityRevision,
  encodeSignedCapabilityRevision as encodeSignedCapabilityRevisionBytes,
  isCapabilityActive,
  reduceCapabilityLog,
  signCapabilityRevision,
  type CapabilityGrantInput,
  type CapabilityRevision,
  type CapabilitySnapshot,
  type SignedCapabilityRevision,
  type SignedGenesis,
  type ValidationPolicy,
} from '@chronolog/capabilities'
import {
  createEpochManifest,
  decodeSignedEpochManifest,
  encodeEpochManifest,
  encodeSignedEpochManifest,
  unwrapEpochKey,
  verifyEpochManifest,
  type SignedEpochManifest,
} from '@chronolog/crypto'
import {
  DOMAINS,
  ProtocolError,
  assertCanonicalCbor,
  bytesToHex,
  decodeEnvelope,
  encodeCanonicalCbor,
  encodeEnvelope,
  equalBytes,
  hashDomain,
  signDomain,
  verifyDomain,
  type CborValue,
  type Ed25519KeyPair,
  type EnvelopeMessageType,
  type ProtocolDomain,
} from '@chronolog/protocol'
import type { ChronologTransport, TransportRecord } from '@chronolog/records'
import type { OrderedRecordEntry } from './history-policy.js'
import { decodeLedgerRecord, verifyLedgerPayload } from './ledger-record.js'

import { Mutex, RevisionBroadcaster } from './async.js'
import { EpochCipherRing } from './cipher.js'
import { DurableOperationJournal, MemoryOperationStore, type DurableOperationStore } from './operations.js'

type GovernanceMessageType = Extract<EnvelopeMessageType, 'capability' | 'epoch-manifest'>

interface FinalizedEpochActivation {
  readonly epoch: bigint
  readonly digest: Uint8Array
  /** The rotation governs author timestamps strictly after this closed bound. */
  readonly after: bigint
  /** Closure proving this epoch and all of its signed predecessors are included. */
  readonly finalizedAt: bigint
  /** Inclusion extent needed for this control and every signed predecessor. */
  readonly includedThrough: number
}

export interface FinalizedGovernanceRecord {
  readonly entry: OrderedRecordEntry
  /** Independently verified closure boundary covering this included control. */
  readonly cutoffMs: bigint
}

export interface GovernanceEvent {
  readonly revision: bigint
  readonly type: 'capability' | 'epoch_rotated' | 'historical_access_granted'
  readonly recordId: string
  readonly membershipRevision: Uint8Array
  readonly epoch?: bigint
}

export interface GovernanceControlPlaneOptions {
  readonly genesis: SignedGenesis
  readonly groupRoute: Uint8Array
  readonly transport: ChronologTransport
  readonly identity: Ed25519KeyPair
  readonly cipherRing?: EpochCipherRing
  readonly recipient?: {
    readonly id: Uint8Array
    readonly privateKey: CryptoKey
  }
  readonly now?: () => number
  /** Required for crash-safe authoring; production runtimes provide persistent storage. */
  readonly operationStore?: DurableOperationStore
  /** Thin administrators follow only the small administration feed. */
  readonly replication?: 'all' | 'administration'
}

export interface GovernanceOperationOptions { readonly operationId?: string }

export interface CapabilityChange {
  readonly grants?: readonly CapabilityGrantInput[]
  readonly revocations?: readonly Uint8Array[]
  readonly validationPolicies?: readonly ValidationPolicy[]
  readonly successorRootPublicKey?: Uint8Array
  readonly successorCapabilityLogFeed?: Uint8Array
}

export class GovernanceControlPlane {
  readonly #options: GovernanceControlPlaneOptions
  readonly #cipherRing: EpochCipherRing
  readonly #snapshots = new Map<string, CapabilitySnapshot>()
  readonly #seen = new Set<string>()
  readonly #pendingRecords = new Map<string, TransportRecord>()
  readonly #mutex = new Mutex()
  // Ingestion and authoring have different locks: publish awaits ingestion,
  // while revision/epoch selection, signing and publication must be one turn.
  readonly #authoring = new Mutex()
  readonly #operationStore: DurableOperationStore
  readonly #operations: DurableOperationJournal
  readonly #operationPrefix: string
  readonly #events = new RevisionBroadcaster<GovernanceEvent>()
  readonly #epochManifests = new Map<bigint, SignedEpochManifest>()
  readonly #epochDigests = new Map<bigint, Uint8Array>()
  readonly #contentKeys = new Map<bigint, Uint8Array>()
  readonly #finalizedEpochs: FinalizedEpochActivation[] = []
  readonly #abort = new AbortController()
  #snapshot: CapabilitySnapshot
  #eventRevision = 0n
  #currentEpoch = -1n
  #consumeTask: Promise<void> | undefined
  #started = false
  #lastError: string | undefined

  private constructor(options: GovernanceControlPlaneOptions, snapshot: CapabilitySnapshot) {
    this.#options = options
    this.#snapshot = snapshot
    this.#cipherRing = options.cipherRing ?? new EpochCipherRing()
    this.#operationStore = options.operationStore ?? new MemoryOperationStore()
    this.#operationPrefix = `governance/${bytesToHex(snapshot.groupId)}`
    this.#operations = new DurableOperationJournal(this.#operationStore, this.#operationPrefix)
    this.#rememberSnapshot(snapshot)
  }

  static async create(options: GovernanceControlPlaneOptions): Promise<GovernanceControlPlane> {
    return new GovernanceControlPlane(options, await reduceCapabilityLog(options.genesis, []))
  }

  get snapshot(): CapabilitySnapshot { return structuredClone(this.#snapshot) }
  get revisionSnapshots(): readonly CapabilitySnapshot[] {
    return [...this.#snapshots.values()].sort((a, b) => compareBigint(a.revision, b.revision)).map((snapshot) => structuredClone(snapshot))
  }
  get pendingRecordCount(): number { return this.#pendingRecords.size }
  get lastError(): string | undefined { return this.#lastError }
  get cipherRing(): EpochCipherRing { return this.#cipherRing }
  get currentEpoch(): bigint | null { return this.#currentEpoch < 0n ? null : this.#currentEpoch }
  get knownEpochs(): readonly bigint[] { return [...this.#epochManifests.keys()].sort(compareBigint) }
  get missingHistoricalEpochs(): readonly bigint[] { return this.knownEpochs.filter((epoch) => !this.#contentKeys.has(epoch)) }
  /** Rebuilt from included controls covered by verified author-time closures. */
  finalizedEpochAt(authorTimestampMs: bigint): Uint8Array | null {
    if (authorTimestampMs < 0n) throw new Error('GOVERNANCE_AUTHOR_TIMESTAMP_INVALID')
    for (let index = this.#finalizedEpochs.length - 1; index >= 0; index--) {
      const activation = this.#finalizedEpochs[index]!
      if (authorTimestampMs > activation.after) return encodeCanonicalCbor(activation.epoch)
    }
    return null
  }
  /** Issuance depends on finalized author time, never received wraps or local keys. */
  finalizedEpochStatusAt(authorTimestampMs: bigint, epochId: Uint8Array | null): 'active' | 'closed' | 'unissued' {
    const active = this.finalizedEpochAt(authorTimestampMs)
    if (epochId === null || active === null) return 'unissued'
    if (equalBytes(active, epochId)) return 'active'
    return this.#finalizedEpochs.some(epoch => epoch.after < authorTimestampMs && equalBytes(encodeCanonicalCbor(epoch.epoch), epochId))
      ? 'closed' : 'unissued'
  }
  /** Availability only: this does not authorize an epoch at an application timestamp. */
  hasFinalizedEpoch(epochId: Uint8Array | null, includedThrough = Number.MAX_SAFE_INTEGER): boolean {
    return epochId !== null && this.#finalizedEpochs.some(epoch => epoch.includedThrough <= includedThrough &&
      equalBytes(encodeCanonicalCbor(epoch.epoch), epochId))
  }
  /** Whether this node's transport feed is the current administration feed. */
  get ownsCapabilityFeed(): boolean { return this.#options.transport.identity === feedAuthor(this.#snapshot.capabilityLogFeed) }

  snapshotForRevision(digest: Uint8Array): CapabilitySnapshot | null {
    const snapshot = this.#snapshots.get(bytesToHex(digest))
    return snapshot === undefined ? null : structuredClone(snapshot)
  }

  async start(): Promise<void> {
    if (this.#started) return
    const history = await this.#options.transport.history()
    for (const record of history) {
      try { await this.ingest(record) }
      catch (error) {
        if (!isInvalidGovernanceRecord(error)) throw error
        this.#seen.add(record.id)
        this.#lastError = error.message
      }
    }
    if (this.ownsCapabilityFeed) await this.#authoring.run(() => this.#operations.recover((prepared) => this.#applyPrepared(prepared)))
    this.#started = true
    this.#consumeTask = this.#consume()
  }

  async close(): Promise<void> {
    this.#abort.abort()
    await this.#consumeTask?.catch(() => undefined)
    this.#events.close()
  }

  events(afterRevision = 0n, signal?: AbortSignal): AsyncIterable<GovernanceEvent> {
    const source = this.#events.subscribe(signal === undefined ? {} : { signal })
    return {
      async *[Symbol.asyncIterator]() {
        for await (const event of source) if (event.revision > afterRevision) yield event
      },
    }
  }

  async publishCapabilityChange(change: CapabilityChange, rootPrivateKey: CryptoKey, options: GovernanceOperationOptions = {}): Promise<SignedCapabilityRevision> {
    const captured = structuredClone(change), capturedOptions = { ...options }
    return this.#authoring.run(() => this.#publishCapabilityChange(captured, rootPrivateKey, capturedOptions))
  }

  async #publishCapabilityChange(change: CapabilityChange, rootPrivateKey: CryptoKey, options: GovernanceOperationOptions): Promise<SignedCapabilityRevision> {
    this.#assertCapabilityFeedOwner()
    this.#assertSupportedChange(change, this.#snapshot)
    const fingerprint = encodeCapabilityRevision({
      groupId: this.#snapshot.groupId, revision: 1n,
      previousRevisionDigest: new Uint8Array(32), issuerRootPublicKey: this.#options.genesis.manifest.rootAdminPublicKey,
      grants: (change.grants ?? []).map((grant) => ({ ...grant, validFromRevision: 1n })),
      revocations: [...(change.revocations ?? [])], validationPolicies: [...(change.validationPolicies ?? [])],
      ...(change.successorRootPublicKey === undefined ? {} : { successorRootPublicKey: change.successorRootPublicKey }),
      ...(change.successorCapabilityLogFeed === undefined ? {} : { successorCapabilityLogFeed: change.successorCapabilityLogFeed }),
    })
    const prepared = await this.#operations.run({
      operationId: options.operationId ?? crypto.randomUUID(),
      fingerprint: encodeCanonicalCbor(['capability', fingerprint]),
      prepare: async () => {
        const revisionNumber = this.#snapshot.revision + 1n
        const revision: CapabilityRevision = {
          groupId: this.#snapshot.groupId,
          revision: revisionNumber,
          previousRevisionDigest: this.#snapshot.revisionDigest,
          issuerRootPublicKey: this.#snapshot.rootAdminPublicKey,
          grants: (change.grants ?? []).map((grant) => ({ ...grant, validFromRevision: revisionNumber })),
          revocations: (change.revocations ?? []).map((id) => id.slice()),
          validationPolicies: [...(change.validationPolicies ?? [])],
          ...(change.successorRootPublicKey === undefined ? {} : { successorRootPublicKey: change.successorRootPublicKey }),
          ...(change.successorCapabilityLogFeed === undefined ? {} : { successorCapabilityLogFeed: change.successorCapabilityLogFeed }),
        }
        const signed = await signCapabilityRevision(revision, rootPrivateKey)
        const result = encodeSignedCapabilityRevisionBytes(signed)
        return this.#prepare(result, [await this.#envelope('capability', encodeCanonicalCbor([1n, result]))])
      },
      apply: (bytes) => this.#applyPrepared(bytes),
    })
    return decodeSignedCapabilityRevisionBytes(preparedResult(prepared))
  }

  async revoke(capabilityIds: readonly Uint8Array[], rootPrivateKey: CryptoKey, options: GovernanceOperationOptions = {}): Promise<SignedCapabilityRevision> {
    return this.publishCapabilityChange({ revocations: capabilityIds }, rootPrivateKey, options)
  }

  async rotateEpoch(rootPrivateKey: CryptoKey, contentKey?: Uint8Array, options: GovernanceOperationOptions = {}): Promise<SignedEpochManifest> {
    const captured = contentKey?.slice(), capturedOptions = { ...options }
    return this.#authoring.run(() => this.#rotateEpoch(rootPrivateKey, captured, capturedOptions))
  }

  async #rotateEpoch(rootPrivateKey: CryptoKey, contentKey: Uint8Array | undefined, options: GovernanceOperationOptions): Promise<SignedEpochManifest> {
    this.#assertCapabilityFeedOwner()
    const prepared = await this.#operations.run({
      operationId: options.operationId ?? crypto.randomUUID(),
      fingerprint: encodeCanonicalCbor(['rotate-epoch', contentKey ?? null]),
      prepare: async () => {
        const recipients = [...this.#snapshot.capabilities.values()]
          .filter((capability) => capability.grant.role === 'reader' && isCapabilityActive(capability, this.#snapshot.revision))
          .map((capability) => ({
            recipientId: capability.grant.subjectId,
            publicKey: capability.grant.hpkePublicKey!,
          }))
        const epoch = this.#currentEpoch + 1n
        const created = await createEpochManifest({
          groupId: this.#snapshot.groupId,
          epoch,
          previousEpochDigest: this.#currentEpoch < 0n ? null : this.#epochDigests.get(this.#currentEpoch) ?? null,
          createdAtMs: BigInt(Math.trunc(this.#options.now?.() ?? Date.now())),
          recipients,
          signerPublicKey: this.#snapshot.rootAdminPublicKey,
          signerPrivateKey: rootPrivateKey,
          ...(contentKey === undefined ? {} : { contentKey }),
        })
        const result = encodeSignedEpochManifest(created.signedManifest)
        return this.#prepare(result, [await this.#envelope('epoch-manifest', encodeCanonicalCbor([1n, result]))], [[epoch, created.contentKey]])
      },
      apply: (bytes) => this.#applyPrepared(bytes),
    })
    return decodeSignedEpochManifest(preparedResult(prepared))
  }

  async grantHistoricalAccess(subjectId: Uint8Array, rootPrivateKey: CryptoKey, options: GovernanceOperationOptions = {}): Promise<number> {
    const captured = subjectId.slice(), capturedOptions = { ...options }
    return this.#authoring.run(() => this.#grantHistoricalAccess(captured, rootPrivateKey, capturedOptions))
  }

  async #grantHistoricalAccess(subjectId: Uint8Array, rootPrivateKey: CryptoKey, options: GovernanceOperationOptions): Promise<number> {
    this.#assertCapabilityFeedOwner()
    const prepared = await this.#operations.run({
      operationId: options.operationId ?? crypto.randomUUID(),
      fingerprint: encodeCanonicalCbor(['historical-access', subjectId]),
      prepare: async () => {
        const reader = [...this.#snapshot.capabilities.values()].find((capability) =>
          capability.grant.role === 'reader' &&
          equalBytes(capability.grant.subjectId, subjectId) && isCapabilityActive(capability, this.#snapshot.revision))
        if (reader === undefined) throw new Error('GOVERNANCE_READER_REQUIRED')
        if (this.missingHistoricalEpochs.length !== 0) throw new Error('GOVERNANCE_HISTORICAL_KEY_UNAVAILABLE')
        let published = 0
        const envelopes: Uint8Array[] = []
        for (const [epoch, key] of [...this.#contentKeys].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) {
          const original = this.#epochManifests.get(epoch)
          if (original === undefined) continue
          const created = await createEpochManifest({
            groupId: this.#snapshot.groupId,
            epoch,
            previousEpochDigest: original.manifest.previousEpochDigest,
            createdAtMs: BigInt(Math.trunc(this.#options.now?.() ?? Date.now())),
            recipients: [{ recipientId: subjectId, publicKey: reader.grant.hpkePublicKey! }],
            signerPublicKey: this.#snapshot.rootAdminPublicKey,
            signerPrivateKey: rootPrivateKey,
            contentKey: key,
          })
          envelopes.push(await this.#envelope('epoch-manifest', encodeCanonicalCbor([2n, encodeSignedEpochManifest(created.signedManifest)])))
          published += 1
        }
        return this.#prepare(encodeCanonicalCbor(BigInt(published)), envelopes)
      },
      apply: (bytes) => this.#applyPrepared(bytes),
    })
    return Number(assertCanonicalCbor(preparedResult(prepared)))
  }

  async ingest(record: TransportRecord): Promise<boolean> {
    return this.#mutex.run(async () => {
      const attempt = async (input: TransportRecord): Promise<boolean> => {
        try {
          const changed = await this.#ingest(input)
          this.#pendingRecords.delete(input.id)
          return changed
        } catch (error) {
          if (!(error instanceof GovernanceRecordPendingError)) throw error
          this.#pendingRecords.set(input.id, input)
          return false
        }
      }
      const changed = await attempt(record)
      let progressed = true
      while (progressed && this.#pendingRecords.size > 0) {
        progressed = false
        for (const pending of [...this.#pendingRecords.values()]) {
          try { if (await attempt(pending)) progressed = true }
          catch (error) {
            if (!isInvalidGovernanceRecord(error)) throw error
            this.#pendingRecords.delete(pending.id)
            this.#seen.add(pending.id)
            this.#lastError = error.message
          }
        }
      }
      return changed
    })
  }

  /** Called only for an included control covered by a verified author-time closure. */
  async ingestFinalized(entry: OrderedRecordEntry, activeSnapshot: CapabilitySnapshot, cutoffMs: bigint): Promise<CapabilitySnapshot | null> {
    if (cutoffMs < 0n) throw new Error('GOVERNANCE_FINALITY_BOUNDARY_INVALID')
    entry = { ...entry, bytes: Uint8Array.from(entry.bytes) }
    const activeDigest = activeSnapshot.revisionDigest.slice(), activeRevision = activeSnapshot.revision
    return this.#mutex.run(async () => {
      const ledger = decodeLedgerRecord(entry.bytes)
      if (ledger.kind === 'candidate') return null
      const bytes = await verifyLedgerPayload(ledger, ledger.inlinePayload)
      const active = this.#snapshots.get(bytesToHex(activeDigest))
      if (active === undefined || active.revision !== activeRevision) throw new Error('GOVERNANCE_CANONICAL_CONTEXT_INVALID')
      const decoded = await decodeGovernanceEnvelope(bytes, this.#options.groupRoute)
      const tagged = assertCanonicalCbor(decoded.payload)
      if (!Array.isArray(tagged) || tagged.length !== 2 || !(tagged[1] instanceof Uint8Array) ||
          (tagged[0] !== 1n && !(decoded.type === 'epoch-manifest' && tagged[0] === 2n))) {
        throw new Error('GOVERNANCE_PAYLOAD_INVALID')
      }
      // Received feeds may already contain later signed controls. Resolve this
      // event against the finalized causal membership chain instead.
      let snapshot: CapabilitySnapshot | null = null
      let epoch: FinalizedEpochActivation | null = null
      if (decoded.type === 'capability') {
        snapshot = await this.#verifyFinalizedRevision(decodeSignedCapabilityRevisionBytes(tagged[1]), active)
      } else {
        epoch = await this.#verifyFinalizedEpoch(decodeSignedEpochManifest(tagged[1]), tagged[0] === 2n, active, cutoffMs, entry.position)
      }
      const record: TransportRecord = { id: `canonical:${entry.historyId}:${entry.position}`, author: '',
        sequence: BigInt(entry.position), receivedAtMs: 0, payload: bytes }
      // Receipt order cannot prove that a signed predecessor is impossible.
      // Keep gaps retriable when another included batch supplies that event.
      await this.#ingest(record, true)
      if (epoch !== null) this.#finalizedEpochs.push(epoch)
      return snapshot === null ? null : structuredClone(snapshot)
    })
  }

  async #verifyFinalizedRevision(signed: SignedCapabilityRevision, active: CapabilitySnapshot): Promise<CapabilitySnapshot> {
    if (!equalBytes(signed.revision.groupId, active.groupId) ||
        !await verifyDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(signed.revision),
          signed.signature, signed.revision.issuerRootPublicKey)) throw new Error('GOVERNANCE_REVISION_CONFLICT')
    this.#assertSupportedChange(signed.revision, active)
    if (signed.revision.revision <= active.revision) {
      const known = this.#snapshots.get(bytesToHex(await capabilityRevisionDigest(signed.revision)))
      if (known === undefined) throw new Error('GOVERNANCE_REVISION_CONFLICT')
      return known
    }
    if (!equalBytes(signed.revision.issuerRootPublicKey, active.rootAdminPublicKey)) throw new Error('GOVERNANCE_REVISION_CONFLICT')
    if (signed.revision.revision !== active.revision + 1n) throw new GovernanceRecordPendingError()
    return applyCapabilityRevision(active, signed)
  }

  async #verifyFinalizedEpoch(signed: SignedEpochManifest, historical: boolean, active: CapabilitySnapshot,
    cutoffMs: bigint, includedPosition: number): Promise<FinalizedEpochActivation | null> {
    if (!equalBytes(signed.manifest.groupId, active.groupId) || !await verifyEpochManifest(signed, active.rootAdminPublicKey)) {
      throw new Error('GOVERNANCE_EPOCH_INVALID')
    }
    const known = this.#finalizedEpochs.find(item => item.epoch === signed.manifest.epoch)
    if (historical) {
      if (known === undefined) throw new GovernanceRecordPendingError()
      return null
    }
    const digest = await hashDomain(DOMAINS.epochManifest, encodeEpochManifest(signed.manifest))
    if (known !== undefined) {
      if (!equalBytes(known.digest, digest)) throw new Error('GOVERNANCE_EPOCH_CHAIN_INVALID')
      return null
    }
    const previous = this.#finalizedEpochs.at(-1)
    if (signed.manifest.epoch !== (previous?.epoch ?? -1n) + 1n) throw new GovernanceRecordPendingError()
    if (!nullableBytesEqual(signed.manifest.previousEpochDigest, previous?.digest ?? null)) throw new Error('GOVERNANCE_EPOCH_CHAIN_INVALID')
    const finalizedAt = previous !== undefined && previous.finalizedAt > cutoffMs ? previous.finalizedAt : cutoffMs
    // Epoch zero supplies the genesis key, not a rotation of an older key.
    // It can authorize genesis writers in its own first closure; the caller
    // still proves issuance within the candidate's immutable inclusion set.
    const after = previous === undefined ? -1n : finalizedAt
    return { epoch: signed.manifest.epoch, digest, after, finalizedAt,
      includedThrough: Math.max(includedPosition, previous?.includedThrough ?? 0) }
  }

  async #ingest(record: TransportRecord, canonical = false): Promise<boolean> {
    if (this.#seen.has(record.id)) return false
    let decoded: { readonly type: GovernanceMessageType; readonly payload: Uint8Array }
    try { decoded = await decodeGovernanceEnvelope(record.payload, this.#options.groupRoute) }
    catch { return false }
    if (!canonical && record.author !== feedAuthor(this.#snapshot.capabilityLogFeed)) {
      throw new Error('GOVERNANCE_CAPABILITY_FEED_UNAUTHORIZED')
    }
    if (!canonical && this.#options.transport.feedContiguousThrough !== undefined &&
        await this.#options.transport.feedContiguousThrough(record.author) < record.sequence) throw new GovernanceRecordPendingError()
    const tagged = assertCanonicalCbor(decoded.payload)
    if (!Array.isArray(tagged) || tagged.length !== 2 || typeof tagged[0] !== 'bigint' || !(tagged[1] instanceof Uint8Array)) {
      throw new Error('GOVERNANCE_PAYLOAD_INVALID')
    }
    if (decoded.type === 'capability') {
      const signed = decodeSignedCapabilityRevisionBytes(tagged[1])
      this.#assertSupportedChange(signed.revision, this.#snapshot)
      if (signed.revision.revision > this.#snapshot.revision + 1n) {
        // An outer envelope signer cannot reserve unbounded future revisions
        // with a forged inner root signature, even on an unordered feed.
        if (!equalBytes(signed.revision.groupId, this.#snapshot.groupId) ||
            !equalBytes(signed.revision.issuerRootPublicKey, this.#snapshot.rootAdminPublicKey) ||
            !await verifyDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(signed.revision),
              signed.signature, this.#snapshot.rootAdminPublicKey)) throw new Error('GOVERNANCE_REVISION_CONFLICT')
        throw new GovernanceRecordPendingError()
      }
      if (signed.revision.revision <= this.#snapshot.revision) {
        const known = this.#snapshots.get(bytesToHex(await capabilityRevisionDigest(signed.revision)))
        if (known === undefined || !await verifyDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(signed.revision), signed.signature, signed.revision.issuerRootPublicKey)) {
          throw new Error('GOVERNANCE_REVISION_CONFLICT')
        }
        this.#seen.add(record.id)
        return false
      }
      this.#snapshot = await applyCapabilityRevision(this.#snapshot, signed)
      this.#rememberSnapshot(this.#snapshot)
      this.#emit('capability', record.id)
    } else {
      const signed = decodeSignedEpochManifest(tagged[1])
      await this.#ingestEpoch(signed, tagged[0] === 2n, record.id)
    }
    this.#seen.add(record.id)
    return true
  }

  async capabilityIdsForSubject(subjectId: Uint8Array): Promise<readonly Uint8Array[]> {
    const ids: Uint8Array[] = []
    for (const capability of this.#snapshot.capabilities.values()) {
      if (equalBytes(capability.grant.subjectId, subjectId) && isCapabilityActive(capability, this.#snapshot.revision)) {
        ids.push(await capabilityId(capability.grant))
      }
    }
    return ids
  }

  async #ingestEpoch(signed: SignedEpochManifest, historical: boolean, recordId: string): Promise<void> {
    if (!equalBytes(signed.manifest.groupId, this.#snapshot.groupId) ||
        !await verifyEpochManifest(signed, this.#snapshot.rootAdminPublicKey)) throw new Error('GOVERNANCE_EPOCH_INVALID')
    const digest = await hashDomain(DOMAINS.epochManifest, encodeEpochManifest(signed.manifest))
    if (!historical) {
      if (nullableBytesEqual(this.#epochDigests.get(signed.manifest.epoch) ?? null, digest)) return
      const expectedEpoch = this.#currentEpoch + 1n
      if (signed.manifest.epoch > expectedEpoch) throw new GovernanceRecordPendingError()
      const expectedPrevious = this.#currentEpoch < 0n ? null : this.#epochDigests.get(this.#currentEpoch) ?? null
      if (signed.manifest.epoch !== expectedEpoch || !nullableBytesEqual(signed.manifest.previousEpochDigest, expectedPrevious)) {
        throw new Error('GOVERNANCE_EPOCH_CHAIN_INVALID')
      }
    } else if (!this.#epochManifests.has(signed.manifest.epoch)) {
      throw new GovernanceRecordPendingError()
    }
    let unwrapped: Uint8Array | undefined
    if (this.#options.recipient !== undefined) {
      try {
        const key = await unwrapEpochKey({
          signedManifest: signed,
          trustedSigner: this.#snapshot.rootAdminPublicKey,
          recipientId: this.#options.recipient.id,
          recipientPrivateKey: this.#options.recipient.privateKey,
        })
        unwrapped = key
      } catch {
        // A valid manifest need not include this participant. Revoked and
        // snapshot-scoped readers intentionally retain only prior epochs.
      }
    }
    const retained = unwrapped ?? this.#contentKeys.get(signed.manifest.epoch) ??
      await this.#operationStore.get(`${this.#operationPrefix}/epoch-key/${signed.manifest.epoch}`)
    if (retained !== null && retained !== undefined && retained.length !== 32) throw new Error('GOVERNANCE_STORED_KEY_INVALID')
    if (!historical) {
      this.#currentEpoch = signed.manifest.epoch
      this.#epochManifests.set(signed.manifest.epoch, signed)
      this.#epochDigests.set(signed.manifest.epoch, digest)
    }
    if (retained !== null && retained !== undefined) {
      this.#contentKeys.set(signed.manifest.epoch, retained.slice())
      this.#cipherRing.install(retained, signed.manifest.epoch, !historical)
    }
    this.#emit(historical ? 'historical_access_granted' : 'epoch_rotated', recordId, signed.manifest.epoch)
  }

  async #envelope(type: GovernanceMessageType, payload: Uint8Array): Promise<Uint8Array> {
    return encodeGovernanceEnvelope(
      this.#options.groupRoute,
      type,
      payload,
      this.#options.identity,
    )
  }

  #prepare(result: Uint8Array, envelopes: readonly Uint8Array[], keys: readonly (readonly [bigint, Uint8Array])[] = []): Uint8Array {
    return encodeCanonicalCbor([1n, result, [...envelopes], keys.map(([epoch, key]) => [epoch, key])])
  }

  async #applyPrepared(bytes: Uint8Array): Promise<void> {
    const prepared = decodePrepared(bytes)
    for (const [epoch, key] of prepared.keys) {
      await this.#operationStore.put(`${this.#operationPrefix}/epoch-key/${epoch}`, key)
      this.#contentKeys.set(epoch, key.slice())
    }
    for (const envelope of prepared.envelopes) {
      // Transport acknowledgments can be lost after durable append. Reconcile
      // against exact locally authored bytes before creating any new feed item.
      const history = await this.#options.transport.history()
      const existing = history.find((record) => record.author === this.#options.transport.identity && equalBytes(record.payload, envelope))
      const record = existing ?? await this.#options.transport.publish(envelope, { timestampMs: this.#options.now?.() ?? Date.now() })
      // A relay can persist the local record before its remote append succeeds.
      // Do not release this lane's successor until the canonical append is durable.
      await this.#options.transport.ensurePublished?.(record)
      await this.ingest(record)
    }
  }

  async #consume(): Promise<void> {
    while (!this.#abort.signal.aborted) {
      try {
        for await (const record of this.#options.transport.subscribe(this.#abort.signal)) {
          if (this.#abort.signal.aborted) return
          try { await this.ingest(record) }
          catch (error) {
            if (!isInvalidGovernanceRecord(error)) throw error
            this.#seen.add(record.id)
            this.#lastError = error.message
          }
        }
      } catch (error) {
        this.#lastError = error instanceof Error ? error.message : String(error)
      }
      if (!this.#abort.signal.aborted) await new Promise<void>((resolve) => {
        const finish = () => { clearTimeout(timer); this.#abort.signal.removeEventListener('abort', finish); resolve() }
        const timer = setTimeout(finish, 100)
        this.#abort.signal.addEventListener('abort', finish, { once: true })
      })
    }
  }

  #rememberSnapshot(snapshot: CapabilitySnapshot): void {
    this.#snapshots.set(bytesToHex(snapshot.revisionDigest), structuredClone(snapshot))
    // Replicate the administration feed and every feed a grant ever named:
    // records written before a revocation remain part of history.
    const request = this.#options.transport.requestFeed?.bind(this.#options.transport)
    if (request === undefined) return
    request(feedAuthor(snapshot.capabilityLogFeed))
    if (this.#options.replication === 'administration') return
    for (const capability of snapshot.capabilities.values()) {
      if (capability.grant.transportAuthor !== undefined) request(capability.grant.transportAuthor)
    }
  }

  #assertCapabilityFeedOwner(): void {
    if (this.#options.transport.identity !== feedAuthor(this.#snapshot.capabilityLogFeed)) {
      throw new Error('GOVERNANCE_CAPABILITY_FEED_OWNER_REQUIRED')
    }
  }

  #assertSupportedChange(change: CapabilityChange, snapshot: CapabilitySnapshot): void {
    if (this.#options.genesis.manifest.historyPolicy === undefined) return
    // These roles are pinned by the signed history configuration. Validate
    // received controls before updating the snapshot, just as for authoring;
    // a root signature cannot turn an unsupported change into activation.
    if (change.successorRootPublicKey !== undefined) throw new Error('GOVERNANCE_FIXED_ROOT')
    if (change.successorCapabilityLogFeed !== undefined) throw new Error('GOVERNANCE_FIXED_ADMINISTRATION_FEED')
    if ((change.validationPolicies?.length ?? 0) > 0) throw new Error('GOVERNANCE_FIXED_VALIDATION_POLICY')
    if (change.grants?.some(grant => grant.role === 'validator') === true ||
        change.revocations?.some(id => snapshot.capabilities.get(bytesToHex(id))?.grant.role === 'validator') === true) {
      throw new Error('GOVERNANCE_FIXED_VALIDATORS')
    }
  }

  #emit(type: GovernanceEvent['type'], recordId: string, epoch?: bigint): void {
    this.#eventRevision += 1n
    this.#events.emit({
      revision: this.#eventRevision,
      type,
      recordId,
      membershipRevision: this.#snapshot.revisionDigest.slice(),
      ...(epoch === undefined ? {} : { epoch }),
    })
  }
}

/**
 * Receipt order is transport metadata, not membership causality. Each control
 * chain is resolved by its signed predecessor/revision; activation still uses
 * the independently proved cutoff attached to the original included event.
 * Malformed/foreign/application entries have no governance effect.
 */
export async function orderFinalizedGovernanceRecords(
  records: readonly FinalizedGovernanceRecord[], groupRoute: Uint8Array,
): Promise<readonly FinalizedGovernanceRecord[]> {
  const route = groupRoute.slice()
  const captured = records.map(input => ({ entry: { ...input.entry, bytes: input.entry.bytes.slice() }, cutoffMs: input.cutoffMs }))
  const controls: Array<{ readonly record: FinalizedGovernanceRecord; readonly kind: number;
    readonly revision: bigint; readonly historical: number; readonly id: string }> = []
  for (const record of captured) {
    try {
      const ledger = decodeLedgerRecord(record.entry.bytes)
      if (ledger.kind === 'candidate' || !equalBytes(ledger.groupRoute, route)) continue
      const bytes = await verifyLedgerPayload(ledger, ledger.inlinePayload)
      const decoded = await decodeGovernanceEnvelope(bytes, route)
      const tagged = assertCanonicalCbor(decoded.payload)
      if (!Array.isArray(tagged) || tagged.length !== 2 || !(tagged[1] instanceof Uint8Array) ||
          (tagged[0] !== 1n && !(decoded.type === 'epoch-manifest' && tagged[0] === 2n))) continue
      const revision = decoded.type === 'capability'
        ? decodeSignedCapabilityRevisionBytes(tagged[1]).revision.revision
        : decodeSignedEpochManifest(tagged[1]).manifest.epoch
      controls.push({ record, kind: decoded.type === 'capability' ? 0 : 1, revision,
        historical: tagged[0] === 2n ? 1 : 0, id: ledger.payloadHash })
    } catch {
      // These operations only decode and authenticate supplied bytes. Invalid
      // records remain in the provider's proof but cannot mutate governance.
    }
  }
  controls.sort((left, right) => left.kind - right.kind || compareBigint(left.revision, right.revision) ||
    left.historical - right.historical || left.id.localeCompare(right.id))
  return controls.map(item => item.record)
}

async function encodeGovernanceEnvelope(
  groupRoute: Uint8Array,
  type: GovernanceMessageType,
  payload: Uint8Array,
  signer: Ed25519KeyPair,
): Promise<Uint8Array> {
  const signature = await signDomain(domainFor(type), payload, signer.privateKey)
  const wire = encodeCanonicalCbor([1n, payload, signer.publicKeyBytes, signature])
  return encodeEnvelope({
    groupRoute,
    messageType: type,
    encryptionEpoch: null,
    payload: wire,
  })
}

async function decodeGovernanceEnvelope(
  bytes: Uint8Array,
  groupRoute: Uint8Array,
): Promise<{ readonly type: GovernanceMessageType; readonly payload: Uint8Array }> {
  const envelope = decodeEnvelope(bytes)
  if (!equalBytes(envelope.groupRoute, groupRoute) || envelope.encryptionEpoch !== null ||
      (envelope.messageType !== 'capability' && envelope.messageType !== 'epoch-manifest')) {
    throw new Error('GOVERNANCE_ENVELOPE_INVALID')
  }
  const value = assertCanonicalCbor(envelope.payload)
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
      !(value[2] instanceof Uint8Array) || !(value[3] instanceof Uint8Array)) throw new Error('GOVERNANCE_ENVELOPE_INVALID')
  const fields = value as readonly CborValue[]
  const payload = fields[1] as Uint8Array
  const signer = fields[2] as Uint8Array
  const signature = fields[3] as Uint8Array
  if (!await verifyDomain(domainFor(envelope.messageType), payload, signature, signer)) throw new Error('GOVERNANCE_ENVELOPE_SIGNATURE_INVALID')
  return { type: envelope.messageType, payload }
}

function domainFor(type: GovernanceMessageType): ProtocolDomain {
  if (type === 'capability') return DOMAINS.capabilityRevision
  return DOMAINS.epochManifest
}

function feedAuthor(value: Uint8Array): string { return new TextDecoder().decode(value) }

function nullableBytesEqual(left: Uint8Array | null, right: Uint8Array | null): boolean {
  return left === null ? right === null : right !== null && equalBytes(left, right)
}

function decodePrepared(bytes: Uint8Array): {
  readonly result: Uint8Array
  readonly envelopes: readonly Uint8Array[]
  readonly keys: readonly (readonly [bigint, Uint8Array])[]
} {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || !(value[1] instanceof Uint8Array) ||
      !Array.isArray(value[2]) || !value[2].every((item) => item instanceof Uint8Array) || !Array.isArray(value[3])) {
    throw new Error('GOVERNANCE_OPERATION_INVALID')
  }
  const keys: Array<readonly [bigint, Uint8Array]> = []
  for (const entry of value[3]) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'bigint' || entry[0] < 0n ||
        !(entry[1] instanceof Uint8Array) || entry[1].length !== 32) throw new Error('GOVERNANCE_OPERATION_INVALID')
    keys.push([entry[0], entry[1]])
  }
  return { result: value[1], envelopes: value[2], keys }
}

function preparedResult(bytes: Uint8Array): Uint8Array { return decodePrepared(bytes).result }
function compareBigint(left: bigint, right: bigint): number { return left < right ? -1 : left > right ? 1 : 0 }

export class GovernanceRecordPendingError extends Error {
  constructor() { super('GOVERNANCE_PREDECESSOR_PENDING'); this.name = 'GovernanceRecordPendingError' }
}

export function isInvalidGovernanceRecord(error: unknown): error is Error {
  return error instanceof ProtocolError || (error instanceof Error && /^GOVERNANCE_(CAPABILITY_FEED_UNAUTHORIZED|PAYLOAD_INVALID|EPOCH_INVALID|EPOCH_CHAIN_INVALID|REVISION_CONFLICT|ENVELOPE_INVALID|ENVELOPE_SIGNATURE_INVALID|FIXED_(ROOT|ADMINISTRATION_FEED|VALIDATION_POLICY|VALIDATORS))$/u.test(error.message))
}

import {
  applyCapabilityRevision,
  capabilityId,
  decodeSignedCapabilityRevision as decodeSignedCapabilityRevisionBytes,
  encodeCapabilityRevision,
  encodeSignedCapabilityRevision as encodeSignedCapabilityRevisionBytes,
  isCapabilityActive,
  reduceCapabilityLog,
  signCapabilityRevision,
  type CapabilityGrant,
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
import type { ChronologTransport, TransportRecord } from '@chronolog/transport-ssb'

import { Mutex, RevisionBroadcaster } from './async.js'
import { EpochCipherRing } from './cipher.js'
import { DurableOperationJournal, MemoryOperationStore, type DurableOperationStore } from './operations.js'

type GovernanceMessageType = Extract<EnvelopeMessageType, 'capability' | 'epoch-manifest'>

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
}

export interface GovernanceOperationOptions { readonly operationId?: string }

export interface CapabilityChange {
  readonly grants?: readonly Omit<CapabilityGrant, 'validFromRevision'>[]
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
  readonly #abort = new AbortController()
  #snapshot: CapabilitySnapshot
  #eventRevision = 0n
  #currentEpoch = -1n
  #consumeTask: Promise<void> | undefined
  #started = false

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
  get cipherRing(): EpochCipherRing { return this.#cipherRing }
  get currentEpoch(): bigint | null { return this.#currentEpoch < 0n ? null : this.#currentEpoch }
  get knownEpochs(): readonly bigint[] { return [...this.#epochManifests.keys()].sort(compareBigint) }
  get missingHistoricalEpochs(): readonly bigint[] { return this.knownEpochs.filter((epoch) => !this.#contentKeys.has(epoch)) }
  /** Whether this node's transport feed is the current administration feed. */
  get ownsCapabilityFeed(): boolean { return this.#options.transport.identity === feedAuthor(this.#snapshot.capabilityLogFeed) }

  snapshotForRevision(digest: Uint8Array): CapabilitySnapshot | null {
    const snapshot = this.#snapshots.get(bytesToHex(digest))
    return snapshot === undefined ? null : structuredClone(snapshot)
  }

  async start(): Promise<void> {
    if (this.#started) return
    this.#started = true
    const history = await this.#options.transport.history()
    for (const record of history) await this.ingest(record)
    if (this.ownsCapabilityFeed) await this.#authoring.run(() => this.#operations.recover((prepared) => this.#applyPrepared(prepared)))
    this.#consumeTask = this.#consume(this.#options.transport.subscribe(this.#abort.signal))
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
    return this.#authoring.run(() => this.#publishCapabilityChange(change, rootPrivateKey, options))
  }

  async #publishCapabilityChange(change: CapabilityChange, rootPrivateKey: CryptoKey, options: GovernanceOperationOptions): Promise<SignedCapabilityRevision> {
    this.#assertCapabilityFeedOwner()
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
    return this.#authoring.run(() => this.#rotateEpoch(rootPrivateKey, contentKey, options))
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
    return this.#authoring.run(() => this.#grantHistoricalAccess(subjectId, rootPrivateKey, options))
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
    return this.#mutex.run(() => this.#ingest(record))
  }

  async #ingest(record: TransportRecord): Promise<boolean> {
    if (this.#seen.has(record.id)) return false
    let decoded: { readonly type: GovernanceMessageType; readonly payload: Uint8Array }
    try { decoded = await decodeGovernanceEnvelope(record.payload, this.#options.groupRoute) }
    catch { return false }
    if (record.author !== feedAuthor(this.#snapshot.capabilityLogFeed)) {
      throw new Error('GOVERNANCE_CAPABILITY_FEED_UNAUTHORIZED')
    }
    const tagged = assertCanonicalCbor(decoded.payload)
    if (!Array.isArray(tagged) || tagged.length !== 2 || typeof tagged[0] !== 'bigint' || !(tagged[1] instanceof Uint8Array)) {
      throw new Error('GOVERNANCE_PAYLOAD_INVALID')
    }
    if (decoded.type === 'capability') {
      const signed = decodeSignedCapabilityRevisionBytes(tagged[1])
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
      const expectedEpoch = this.#currentEpoch + 1n
      const expectedPrevious = this.#currentEpoch < 0n ? null : this.#epochDigests.get(this.#currentEpoch) ?? null
      if (signed.manifest.epoch !== expectedEpoch || !nullableBytesEqual(signed.manifest.previousEpochDigest, expectedPrevious)) {
        throw new Error('GOVERNANCE_EPOCH_CHAIN_INVALID')
      }
      this.#currentEpoch = signed.manifest.epoch
      this.#epochManifests.set(signed.manifest.epoch, signed)
      this.#epochDigests.set(signed.manifest.epoch, digest)
    } else if (!this.#epochManifests.has(signed.manifest.epoch)) {
      throw new Error('GOVERNANCE_HISTORICAL_EPOCH_UNKNOWN')
    }
    if (this.#options.recipient !== undefined) {
      try {
        const key = await unwrapEpochKey({
          signedManifest: signed,
          trustedSigner: this.#snapshot.rootAdminPublicKey,
          recipientId: this.#options.recipient.id,
          recipientPrivateKey: this.#options.recipient.privateKey,
        })
        this.#contentKeys.set(signed.manifest.epoch, key.slice())
        this.#cipherRing.install(key, signed.manifest.epoch, !historical)
      } catch {
        // A valid manifest need not include this participant. Revoked and
        // snapshot-scoped readers intentionally retain only prior epochs.
      }
    }
    const retained = this.#contentKeys.get(signed.manifest.epoch) ??
      await this.#operationStore.get(`${this.#operationPrefix}/epoch-key/${signed.manifest.epoch}`)
    if (retained !== null && retained !== undefined) {
      if (retained.length !== 32) throw new Error('GOVERNANCE_STORED_KEY_INVALID')
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
      await this.ingest(record)
    }
  }

  async #consume(records: AsyncIterable<TransportRecord>): Promise<void> {
    for await (const record of records) {
      if (this.#abort.signal.aborted) return
      await this.ingest(record)
    }
  }

  #rememberSnapshot(snapshot: CapabilitySnapshot): void {
    this.#snapshots.set(bytesToHex(snapshot.revisionDigest), structuredClone(snapshot))
    // Replicate the administration feed and every feed a grant ever named:
    // records written before a revocation remain part of history.
    const request = this.#options.transport.requestFeed?.bind(this.#options.transport)
    if (request === undefined) return
    request(feedAuthor(snapshot.capabilityLogFeed))
    for (const capability of snapshot.capabilities.values()) {
      if (capability.grant.transportAuthor !== undefined) request(capability.grant.transportAuthor)
    }
  }

  #assertCapabilityFeedOwner(): void {
    if (this.#options.transport.identity !== feedAuthor(this.#snapshot.capabilityLogFeed)) {
      throw new Error('GOVERNANCE_CAPABILITY_FEED_OWNER_REQUIRED')
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
  return { result: value[1], envelopes: value[2] as Uint8Array[], keys }
}

function preparedResult(bytes: Uint8Array): Uint8Array { return decodePrepared(bytes).result }
function compareBigint(left: bigint, right: bigint): number { return left < right ? -1 : left > right ? 1 : 0 }

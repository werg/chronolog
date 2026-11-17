import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import {
  assertCanonicalCbor, bytesToHex, decodeEnvelope, decodeValidatorAttestation,
  encodeCanonicalCbor, equalBytes, type Ed25519KeyPair,
} from '@chronolog/protocol'
import type { ChronologTransport, TransportRecord } from '@chronolog/records'

import { Mutex } from './async.js'
import type { WriterAuthorizationContext } from './capability-membership.js'
import {
  decodeSignedGovernanceClosure, verifyGovernanceClosure, verifyPeerGovernanceActivation,
  type SignedGovernanceClosure, type VerifiedGovernanceClosureEvidence,
} from './peer-governance-proof.js'
import { GovernanceActivationIndex } from './governance-activation.js'
import type { GovernanceControlPlane } from './governance.js'
import type { DurableOperationStore } from './operations.js'
import type { ClosedAdmissionRevision, EnvelopeCipher, EnvelopeCipherResolver } from './types.js'
import { decodeSignedEnvelope, WIRE_ENCRYPTION_EPOCH_UNAVAILABLE } from './wire.js'

export interface PeerGovernanceControllerOptions {
  readonly genesis: CapabilitySnapshot
  readonly governance: GovernanceControlPlane
  readonly groupRoute: Uint8Array
  readonly transport: ChronologTransport
  readonly identity: Ed25519KeyPair
  readonly store: DurableOperationStore
  readonly cipher?: EnvelopeCipher | EnvelopeCipherResolver
  /** Node serializes this with admission signing and persists closure first. */
  readonly closeRevision: (previousRevision: Uint8Array, nextRevision: Uint8Array) => Promise<TransportRecord>
  readonly onActivation?: () => void
}

interface ClosureRecord {
  readonly signed: SignedGovernanceClosure
  readonly record: TransportRecord
}

interface ScannedClosure {
  readonly evidence: VerifiedGovernanceClosureEvidence
  readonly transactionIds: readonly Uint8Array[]
}

/** Live fixed-validator governance activation, driven by ordinary peer records. */
export class PeerGovernanceController {
  readonly #options: PeerGovernanceControllerOptions
  readonly #activation: GovernanceActivationIndex
  readonly #mutex = new Mutex()
  readonly #abort = new AbortController()
  readonly #closed = new Map<string, ClosedAdmissionRevision>()
  readonly #checkpointKey: string
  #checkpoint: { readonly revision: bigint; readonly digest: Uint8Array; readonly boundary: bigint } | null = null
  #recordTask: Promise<void> | undefined
  #governanceTask: Promise<void> | undefined
  #initialized = false
  #started = false
  #lastError: string | undefined

  constructor(options: PeerGovernanceControllerOptions) {
    this.#options = options
    this.#activation = new GovernanceActivationIndex(options.genesis)
    this.#checkpointKey = `peer-governance/${bytesToHex(options.genesis.groupId)}/active`
  }

  get activeSnapshot(): CapabilitySnapshot { return this.#activation.activeSnapshot }
  get minimumAuthorTimestampMs(): bigint { return this.#activation.activationBoundary + 1n }
  get lastError(): string | undefined { return this.#lastError }
  get ready(): boolean { return this.#initialized }
  get finalityRevisions(): GovernanceActivationIndex['finalityRevisions'] | null {
    return this.#initialized ? this.#activation.finalityRevisions : null
  }

  snapshotFor(context: WriterAuthorizationContext): CapabilitySnapshot | null {
    return this.#initialized ? this.#activation.snapshotFor(context) : null
  }

  closedAdmissionRevisions(): readonly ClosedAdmissionRevision[] {
    return this.#initialized ? structuredClone([...this.#closed.values()]) : []
  }

  /**
   * Reads the durable feed, rather than trusting subscription scheduling. A
   * post-closure attestation can arrive before this controller's event task.
   * This path never takes the controller lock or invokes node authoring.
   */
  async allowsAttestation(revision: Uint8Array, validatorId: Uint8Array, sequence: bigint): Promise<boolean> {
    if (sequence <= 0n) return false
    for (const record of await this.#options.transport.history()) {
      const closure = await this.#closure(record)
      if (closure === null || !equalBytes(closure.signed.closure.membershipRevision, revision) ||
          !equalBytes(closure.signed.closure.validatorId, validatorId)) continue
      if (sequence > closure.record.sequence) return false
    }
    return true
  }

  async start(): Promise<void> {
    if (this.#started) return
    const saved = await this.#options.store.get(this.#checkpointKey)
    if (saved !== null) {
      const value = assertCanonicalCbor(saved)
      if (!Array.isArray(value) || value.length !== 4 || value[0] !== 1n || typeof value[1] !== 'bigint' ||
          !(value[2] instanceof Uint8Array) || typeof value[3] !== 'bigint') throw new Error('GOVERNANCE_ACTIVATION_CHECKPOINT_INVALID')
      this.#checkpoint = { revision: value[1], digest: value[2], boundary: value[3] }
    }
    await this.refresh()
    this.#started = true
    this.#recordTask = this.#followRecords()
    this.#governanceTask = this.#followGovernance()
  }

  async close(): Promise<void> {
    this.#abort.abort()
    await this.#recordTask?.catch(() => undefined)
    await this.#governanceTask?.catch(() => undefined)
  }

  async refresh(): Promise<void> {
    const changed = await this.#mutex.run(async () => {
      let changed = false
      const snapshots = this.#options.governance.revisionSnapshots
      for (const snapshot of snapshots) this.#activation.observe(snapshot)
      let history = await this.#options.transport.history()
      while (!this.#abort.signal.aborted) {
        const previous = this.#activation.activeSnapshot
        const next = snapshots.find((snapshot) => snapshot.revision === previous.revision + 1n)
        if (next === undefined) break
        let closures = await this.#closingRecords(history, previous.revisionDigest, next.revisionDigest)
        const localValidator = [...previous.capabilities.values()].find((capability) =>
          capability.grant.role === 'validator' && isCapabilityActive(capability, previous.revision) &&
          equalBytes(capability.grant.signingPublicKey, this.#options.identity.publicKeyBytes) &&
          capability.grant.transportAuthor === this.#options.transport.identity)
        if (localValidator !== undefined && !closures.some((item) => equalBytes(item.signed.closure.validatorId, this.#options.identity.publicKeyBytes))) {
          await this.#options.closeRevision(previous.revisionDigest, next.revisionDigest)
          history = await this.#options.transport.history()
          closures = await this.#closingRecords(history, previous.revisionDigest, next.revisionDigest)
        }
        const validators = [...previous.capabilities.values()].filter((capability) => capability.grant.role === 'validator' && isCapabilityActive(capability, previous.revision))
        if (closures.length !== validators.length) break
        const scanned: ScannedClosure[] = []
        let incomplete = false
        for (const closure of closures) {
          const result = await this.#scanClosure(closure, history)
          if (result === null) { incomplete = true; break }
          scanned.push(result)
        }
        if (incomplete) break
        const boundary = await verifyPeerGovernanceActivation({ previous, next,
          evidence: scanned.map((item) => item.evidence), minimumBoundary: this.#activation.activationBoundary })
        this.#activation.activateFinalized(next, boundary)
        const transactions = new Map<string, Uint8Array>()
        for (const item of scanned) for (const txId of item.transactionIds) transactions.set(bytesToHex(txId), txId)
        this.#closed.set(bytesToHex(previous.revisionDigest), {
          membershipRevision: previous.revisionDigest.slice(), nextMembershipRevision: next.revisionDigest.slice(), closedThroughMs: boundary,
          proposalIds: [...transactions.values()],
          feedPrefixes: closures.map(item => ({ author: item.record.author, throughSequence: item.record.sequence })),
        })
        // The proof records are already durable. This checkpoint also detects
        // a later incomplete restore instead of silently reopening old grants.
        if (this.#checkpoint === null || next.revision >= this.#checkpoint.revision) {
          await this.#options.store.put(this.#checkpointKey, encodeCanonicalCbor([1n, next.revision, next.revisionDigest, boundary]))
        }
        changed = true
      }
      const active = this.#activation.activeSnapshot
      if (this.#checkpoint !== null && (active.revision < this.#checkpoint.revision ||
          (active.revision === this.#checkpoint.revision && (!equalBytes(active.revisionDigest, this.#checkpoint.digest) ||
            this.#activation.activationBoundary < this.#checkpoint.boundary)))) {
        this.#initialized = false
        this.#lastError = 'GOVERNANCE_ACTIVATION_RECOVERY_PENDING'
      } else {
        this.#initialized = true
        this.#lastError = undefined
      }
      return changed
    })
    if (changed) this.#options.onActivation?.()
  }

  async #closingRecords(history: readonly TransportRecord[], previous: Uint8Array, next: Uint8Array): Promise<ClosureRecord[]> {
    const records = new Map<string, ClosureRecord>()
    for (const record of history) {
      const closure = await this.#closure(record)
      if (closure === null || !equalBytes(closure.signed.closure.membershipRevision, previous)) continue
      if (!equalBytes(closure.signed.closure.nextMembershipRevision, next)) throw new Error('GOVERNANCE_VALIDATOR_CLOSURE_CONFLICT')
      const key = bytesToHex(closure.signed.closure.validatorId)
      const prior = records.get(key)
      if (prior === undefined || record.sequence < prior.record.sequence) records.set(key, closure)
    }
    return [...records.values()]
  }

  async #closure(record: TransportRecord): Promise<ClosureRecord | null> {
    let signed: SignedGovernanceClosure
    try {
      const envelope = decodeEnvelope(record.payload)
      if (envelope.messageType !== 'proof-bundle' || envelope.encryptionEpoch !== null || !equalBytes(envelope.groupRoute, this.#options.groupRoute)) return null
      signed = decodeSignedGovernanceClosure(envelope.payload)
      if (!await verifyGovernanceClosure(signed)) return null
    } catch { return null }
    const previous = this.#options.governance.snapshotForRevision(signed.closure.membershipRevision)
    const capability = previous?.capabilities.get(bytesToHex(signed.closure.validatorCapability))
    if (previous === null || previous === undefined || capability === undefined || capability.grant.role !== 'validator' ||
        !isCapabilityActive(capability, previous.revision) || !equalBytes(signed.closure.groupId, previous.groupId) ||
        !equalBytes(capability.grant.signingPublicKey, signed.closure.validatorId) || capability.grant.transportAuthor !== record.author) return null
    return { signed, record }
  }

  async #scanClosure(closure: ClosureRecord, history: readonly TransportRecord[]): Promise<ScannedClosure | null> {
    const contiguous = await this.#options.transport.feedContiguousThrough?.(closure.record.author)
    if (contiguous === undefined || contiguous < closure.record.sequence) return null
    let lastAdmissionSequence = 0n
    let maximumAdmittedTimestampMs = 0n
    const transactionIds: Uint8Array[] = []
    for (const record of history) {
      if (record.author !== closure.record.author || record.sequence >= closure.record.sequence) continue
      try {
        const envelope = decodeEnvelope(record.payload)
        if (envelope.messageType !== 'attestation' || !equalBytes(envelope.groupRoute, this.#options.groupRoute)) continue
        const wire = await decodeSignedEnvelope(record.payload, this.#options.groupRoute, this.#options.cipher)
        const attestation = decodeValidatorAttestation(wire.payload)
        if (!equalBytes(attestation.groupId, closure.signed.closure.groupId) ||
            !equalBytes(attestation.membershipRevision, closure.signed.closure.membershipRevision) ||
            !equalBytes(attestation.validatorId, wire.signer) || !equalBytes(wire.signer, closure.signed.closure.validatorId) ||
            !equalBytes(attestation.validatorCapability, closure.signed.closure.validatorCapability)) continue
        if (record.sequence > lastAdmissionSequence) lastAdmissionSequence = record.sequence
        if (attestation.authorTimestampMs > maximumAdmittedTimestampMs) maximumAdmittedTimestampMs = attestation.authorTimestampMs
        transactionIds.push(attestation.txId)
      } catch (error) {
        if (error instanceof Error && error.message === WIRE_ENCRYPTION_EPOCH_UNAVAILABLE) return null
        // Known malformed/invalid-signature records cannot count as admissions.
        if (!(error instanceof Error) || (error.name !== 'ChronologWireError' && error.name !== 'ProtocolError')) throw error
      }
    }
    return { transactionIds, evidence: {
      signed: closure.signed, transportAuthor: closure.record.author, sequence: closure.record.sequence,
      contiguousThrough: contiguous, lastAdmissionSequence, maximumAdmittedTimestampMs,
    } }
  }

  async #followRecords(): Promise<void> {
    while (!this.#abort.signal.aborted) {
      try {
        for await (const _record of this.#options.transport.subscribe(this.#abort.signal)) {
          if (this.#abort.signal.aborted) return
          await this.#refreshAfterEvent()
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

  async #followGovernance(): Promise<void> {
    for await (const _event of this.#options.governance.events(0n, this.#abort.signal)) {
      if (this.#abort.signal.aborted) return
      await this.#refreshAfterEvent()
    }
  }

  async #refreshAfterEvent(): Promise<void> {
    try { await this.refresh() }
    catch (error) { this.#lastError = error instanceof Error ? error.message : String(error) }
  }
}

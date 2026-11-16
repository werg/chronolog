import { isCapabilityActive, type CapabilitySnapshot, type EffectiveCapability } from '@chronolog/capabilities'
import { DOMAINS, assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, equalBytes, signDomain, verifyDomain } from '@chronolog/protocol'

import type { WriterAuthorizationContext } from './capability-membership.js'

/** A validator permanently closes one membership revision before signing this. */
export interface GovernanceClosure {
  readonly groupId: Uint8Array
  readonly membershipRevision: Uint8Array
  readonly nextMembershipRevision: Uint8Array
  readonly validatorId: Uint8Array
  readonly validatorCapability: Uint8Array
  /** Upper bound for all this validator's earlier admissions under the revision. */
  readonly throughMs: bigint
  readonly lastAdmissionSequence: bigint
}

export interface SignedGovernanceClosure {
  readonly closure: GovernanceClosure
  readonly signature: Uint8Array
}

/**
 * Supplied only after the ordinary record verifier has authenticated the
 * closing record and scanned its complete feed prefix for admissions. These
 * are local verification results, not fields trusted from a remote peer.
 */
export interface VerifiedGovernanceClosureEvidence {
  readonly signed: SignedGovernanceClosure
  readonly transportAuthor: string
  readonly sequence: bigint
  readonly contiguousThrough: bigint
  readonly lastAdmissionSequence: bigint
  readonly maximumAdmittedTimestampMs: bigint
}

export function encodeGovernanceClosure(value: GovernanceClosure): Uint8Array {
  for (const bytes of [value.groupId, value.membershipRevision, value.nextMembershipRevision, value.validatorId, value.validatorCapability]) {
    if (bytes.length !== 32) throw new Error('GOVERNANCE_CLOSURE_INVALID')
  }
  if (value.throughMs < 0n || value.lastAdmissionSequence < 0n) throw new Error('GOVERNANCE_CLOSURE_INVALID')
  return encodeCanonicalCbor([
    1n, value.groupId, value.membershipRevision, value.nextMembershipRevision,
    value.validatorId, value.validatorCapability, value.throughMs, value.lastAdmissionSequence,
  ])
}

export function decodeGovernanceClosure(bytes: Uint8Array): GovernanceClosure {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 8 || value[0] !== 1n ||
      !value.slice(1, 6).every((item) => item instanceof Uint8Array) ||
      typeof value[6] !== 'bigint' || typeof value[7] !== 'bigint') throw new Error('GOVERNANCE_CLOSURE_INVALID')
  const closure = {
    groupId: value[1] as Uint8Array, membershipRevision: value[2] as Uint8Array,
    nextMembershipRevision: value[3] as Uint8Array, validatorId: value[4] as Uint8Array,
    validatorCapability: value[5] as Uint8Array, throughMs: value[6], lastAdmissionSequence: value[7],
  }
  encodeGovernanceClosure(closure)
  return closure
}

export function encodeSignedGovernanceClosure(signed: SignedGovernanceClosure): Uint8Array {
  if (signed.signature.length !== 64) throw new Error('GOVERNANCE_CLOSURE_INVALID')
  return encodeCanonicalCbor([encodeGovernanceClosure(signed.closure), signed.signature])
}

export function decodeSignedGovernanceClosure(bytes: Uint8Array): SignedGovernanceClosure {
  const value = assertCanonicalCbor(bytes)
  if (!Array.isArray(value) || value.length !== 2 || !(value[0] instanceof Uint8Array) ||
      !(value[1] instanceof Uint8Array) || value[1].length !== 64) throw new Error('GOVERNANCE_CLOSURE_INVALID')
  return { closure: decodeGovernanceClosure(value[0]), signature: value[1] }
}

export async function signGovernanceClosure(closure: GovernanceClosure, privateKey: CryptoKey): Promise<SignedGovernanceClosure> {
  return { closure, signature: await signDomain(DOMAINS.governanceClosure, encodeGovernanceClosure(closure), privateKey) }
}

export async function verifyGovernanceClosure(signed: SignedGovernanceClosure): Promise<boolean> {
  return verifyDomain(DOMAINS.governanceClosure, encodeGovernanceClosure(signed.closure), signed.signature, signed.closure.validatorId)
}

interface Activation {
  readonly snapshot: CapabilitySnapshot
  /** The new revision governs author timestamps strictly after this closed bound. */
  readonly after: bigint
}

/**
 * Policy activation is separate from receiving a newer governance snapshot.
 * Replay always selects the snapshot at the immutable author timestamp; a later
 * revocation never changes authorization of an earlier final transaction.
 */
export class GovernanceActivationIndex {
  readonly #kind: 'peer' | 'coordinated'
  readonly #groupId: Uint8Array
  readonly #snapshots = new Map<string, CapabilitySnapshot>()
  readonly #activations: Activation[]
  readonly #validators: readonly EffectiveCapability[]

  constructor(genesis: CapabilitySnapshot, kind: 'peer' | 'coordinated') {
    if (genesis.revision !== 0n) throw new Error('GOVERNANCE_ACTIVATION_GENESIS_REQUIRED')
    this.#kind = kind
    this.#groupId = genesis.groupId.slice()
    this.#validators = activeValidators(genesis)
    this.#activations = [{ snapshot: structuredClone(genesis), after: -1n }]
    this.observe(genesis)
  }

  /** Register a snapshot already verified by the signed governance reducer. */
  observe(snapshot: CapabilitySnapshot): void {
    if (!equalBytes(snapshot.groupId, this.#groupId)) throw new Error('GOVERNANCE_ACTIVATION_GROUP_MISMATCH')
    this.#snapshots.set(bytesToHex(snapshot.revisionDigest), structuredClone(snapshot))
  }

  get activeSnapshot(): CapabilitySnapshot { return structuredClone(this.#activations[this.#activations.length - 1]!.snapshot) }
  get activationBoundary(): bigint { return this.#activations[this.#activations.length - 1]!.after }

  /** The provider proved inclusion and closed this author-time boundary. */
  activateFinalized(snapshot: CapabilitySnapshot, cutoffMs: bigint): void {
    if (this.#kind !== 'coordinated' || cutoffMs < 0n) throw new Error('GOVERNANCE_ACTIVATION_POLICY_MISMATCH')
    // A successor whose predecessor arrived in a later closure takes effect
    // with that predecessor, never retroactively inside an already closed view.
    this.#activate(snapshot, cutoffMs < this.activationBoundary ? this.activationBoundary : cutoffMs)
  }

  async activatePeer(snapshot: CapabilitySnapshot, evidence: readonly VerifiedGovernanceClosureEvidence[]): Promise<bigint> {
    if (this.#kind !== 'peer') throw new Error('GOVERNANCE_ACTIVATION_POLICY_MISMATCH')
    const previous = this.activeSnapshot
    this.#assertSuccessor(snapshot)
    if (this.#validators.length === 0 || evidence.length !== this.#validators.length) throw new Error('GOVERNANCE_CLOSURE_INCOMPLETE')
    const expected = new Map(this.#validators.map((item) => [bytesToHex(item.id), item]))
    const remaining = new Set(expected.keys())
    let through = this.activationBoundary
    for (const proof of evidence) {
      const signed = proof.signed
      const closure = signed.closure
      const id = bytesToHex(closure.validatorCapability)
      const validator = expected.get(id)
      if (validator === undefined || !remaining.delete(id) ||
          !equalBytes(closure.groupId, this.#groupId) ||
          !equalBytes(closure.membershipRevision, previous.revisionDigest) ||
          !equalBytes(closure.nextMembershipRevision, snapshot.revisionDigest) ||
          !equalBytes(closure.validatorId, validator.grant.signingPublicKey) ||
          proof.transportAuthor !== validator.grant.transportAuthor || !await verifyGovernanceClosure(signed)) {
        throw new Error('GOVERNANCE_CLOSURE_INVALID')
      }
      if (proof.sequence <= 0n || proof.contiguousThrough < proof.sequence ||
          proof.lastAdmissionSequence !== closure.lastAdmissionSequence || proof.lastAdmissionSequence >= proof.sequence ||
          proof.maximumAdmittedTimestampMs > closure.throughMs) throw new Error('GOVERNANCE_CLOSURE_INCOMPLETE')
      if (closure.throughMs > through) through = closure.throughMs
    }
    if (remaining.size !== 0) throw new Error('GOVERNANCE_CLOSURE_INCOMPLETE')
    this.#activate(snapshot, through)
    return through
  }

  snapshotFor(context: WriterAuthorizationContext): CapabilitySnapshot | null {
    if (!equalBytes(context.groupId, this.#groupId) || !this.#snapshots.has(bytesToHex(context.membershipRevision))) return null
    if (this.#snapshots.get(bytesToHex(context.membershipRevision))!.revision > this.activeSnapshot.revision) return null
    const point = context.authorTimestampMs
    if (point === undefined || point < 0n) return null
    for (let index = this.#activations.length - 1; index >= 0; index -= 1) {
      const activation = this.#activations[index]!
      if (point > activation.after) return structuredClone(activation.snapshot)
    }
    return null
  }

  #activate(snapshot: CapabilitySnapshot, after: bigint): void {
    this.#assertSuccessor(snapshot)
    if (after < this.activationBoundary) throw new Error('GOVERNANCE_ACTIVATION_REGRESSION')
    // Several causal membership revisions may share one closed batch. Their
    // signed revision chain, not receipt order, resolves the effective state.
    this.observe(snapshot)
    this.#activations.push({ snapshot: structuredClone(snapshot), after })
  }

  #assertSuccessor(snapshot: CapabilitySnapshot): void {
    const active = this.activeSnapshot
    if (!equalBytes(snapshot.groupId, this.#groupId) || snapshot.revision !== active.revision + 1n) {
      throw new Error('GOVERNANCE_ACTIVATION_CHAIN_INVALID')
    }
    if (!equalBytes(snapshot.rootAdminPublicKey, active.rootAdminPublicKey) ||
        !equalBytes(snapshot.capabilityLogFeed, active.capabilityLogFeed)) throw new Error('GOVERNANCE_AUTHORITY_RECONFIGURATION_UNSUPPORTED')
    if (snapshot.policies.size !== active.policies.size || [...snapshot.policies.keys()].some((key) => !active.policies.has(key))) {
      throw new Error('GOVERNANCE_POLICY_RECONFIGURATION_UNSUPPORTED')
    }
    // Initial enrollment changes application membership, never consensus roles.
    const validators = activeValidators(snapshot)
    if (validators.length !== this.#validators.length || validators.some((item, index) =>
      !equalBytes(item.id, this.#validators[index]!.id))) throw new Error('GOVERNANCE_VALIDATOR_RECONFIGURATION_UNSUPPORTED')
  }
}

function activeValidators(snapshot: CapabilitySnapshot): EffectiveCapability[] {
  return [...snapshot.capabilities.values()]
    .filter((item) => item.grant.role === 'validator' && isCapabilityActive(item, snapshot.revision))
    .sort((left, right) => bytesToHex(left.id).localeCompare(bytesToHex(right.id)))
}

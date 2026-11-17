import { isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import { DOMAINS, assertCanonicalCbor, bytesToHex, encodeCanonicalCbor, equalBytes, signDomain, verifyDomain } from '@chronolog/protocol'

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

/**
 * Verify the peer provider's closure proof and return its author-time boundary.
 * Activating the successor is a separate shared governance operation. Merely
 * receiving a newer membership revision never activates it.
 */
export async function verifyPeerGovernanceActivation(options: {
  readonly previous: CapabilitySnapshot
  readonly next: CapabilitySnapshot
  readonly evidence: readonly VerifiedGovernanceClosureEvidence[]
  readonly minimumBoundary: bigint
}): Promise<bigint> {
  // Crypto suspends execution; verify one owned view of the caller's evidence.
  const { previous, next: snapshot, evidence, minimumBoundary } = structuredClone(options)
  if (!equalBytes(previous.groupId, snapshot.groupId) || snapshot.revision !== previous.revision + 1n) {
    throw new Error('GOVERNANCE_ACTIVATION_CHAIN_INVALID')
  }
  const validators = [...previous.capabilities.values()].filter(item =>
    item.grant.role === 'validator' && isCapabilityActive(item, previous.revision))
  if (validators.length === 0 || evidence.length !== validators.length) throw new Error('GOVERNANCE_CLOSURE_INCOMPLETE')
  const expected = new Map(validators.map((item) => [bytesToHex(item.id), item]))
  const remaining = new Set(expected.keys())
  let through = minimumBoundary
  for (const proof of evidence) {
    const signed = proof.signed
    const closure = signed.closure
    const id = bytesToHex(closure.validatorCapability)
    const validator = expected.get(id)
    if (validator === undefined || !remaining.delete(id) ||
      !equalBytes(closure.groupId, previous.groupId) ||
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
  return through
}

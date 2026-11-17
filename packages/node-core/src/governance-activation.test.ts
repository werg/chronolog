import type { CapabilitySnapshot, EffectiveCapability } from '@chronolog/capabilities'
import { bytesToHex, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { GovernanceActivationIndex } from './governance-activation.js'
import { signGovernanceClosure, verifyPeerGovernanceActivation, type VerifiedGovernanceClosureEvidence } from './peer-governance-proof.js'

describe('governance activation', () => {
  it('selects membership strictly after a finalized author-time boundary', async () => {
    const { genesis, next, context } = await fixture()
    const index = new GovernanceActivationIndex(genesis)
    index.observe(next)
    expect(index.snapshotFor({ ...context, membershipRevision: next.revisionDigest, authorTimestampMs: 5n })).toBeNull()
    index.activateFinalized(next, 5n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 5n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 6n })?.revision).toBe(1n)
    // Later reception never changes an earlier timestamp's authorization.
    expect(index.snapshotFor({ ...context, authorTimestampMs: 1n })?.revision).toBe(0n)
  })

  it('resolves multiple signed revisions at one closure without receipt positions', async () => {
    const { genesis, next, context } = await fixture()
    const index = new GovernanceActivationIndex(genesis)
    const successor = { ...next, revision: 2n, revisionDigest: bytes(20) }
    index.activateFinalized(next, 100n)
    index.activateFinalized(successor, 100n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 100n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 101n })?.revision).toBe(2n)
  })

  it('does not backdate a successor whose predecessor finalized in a later batch', async () => {
    const { genesis, next, context } = await fixture()
    const index = new GovernanceActivationIndex(genesis)
    index.activateFinalized(next, 200n)
    index.activateFinalized({ ...next, revision: 2n, revisionDigest: bytes(21) }, 100n)
    expect(index.activationBoundary).toBe(200n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 150n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 201n })?.revision).toBe(2n)
  })

  it('requires every fixed validator and complete prior admission evidence to close a peer revision', async () => {
    const { genesis, next, context, proofs } = await fixture()
    const index = new GovernanceActivationIndex(genesis)
    index.observe(next)
    const verify = (evidence: readonly VerifiedGovernanceClosureEvidence[]) => verifyPeerGovernanceActivation({
      previous: index.activeSnapshot, next, evidence, minimumBoundary: index.activationBoundary })
    await expect(verify(proofs.slice(0, 1))).rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    await expect(verify([{ ...proofs[0]!, contiguousThrough: 3n }, proofs[1]!]))
      .rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    await expect(verify([{ ...proofs[0]!, maximumAdmittedTimestampMs: 101n }, proofs[1]!]))
      .rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    const boundary = await verify(proofs)
    expect(boundary).toBe(110n)
    expect(index.activeSnapshot.revision).toBe(0n)
    index.activateFinalized(next, boundary)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 110n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 111n })?.revision).toBe(1n)
  })

  it('rejects a forged closure and a closure for a different proposed revision', async () => {
    const { genesis, next, proofs } = await fixture()
    const forged = { ...proofs[0]!, signed: { ...proofs[0]!.signed, signature: new Uint8Array(64) } }
    await expect(verifyPeerGovernanceActivation({ previous: genesis, next, evidence: [forged, proofs[1]!], minimumBoundary: -1n })).rejects.toThrow('GOVERNANCE_CLOSURE_INVALID')
    await expect(verifyPeerGovernanceActivation({ previous: genesis, next: { ...next, revisionDigest: bytes(99) }, evidence: proofs, minimumBoundary: -1n })).rejects.toThrow('GOVERNANCE_CLOSURE_INVALID')
  })
})

async function fixture() {
  const validators = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const effective: EffectiveCapability[] = validators.map((key, i) => ({
    id: bytes(40 + i), grantedAtRevision: 0n,
    grant: { role: 'validator', subjectId: key.publicKeyBytes, signingPublicKey: key.publicKeyBytes,
      validFromRevision: 0n, minimumAuthorTimestampMs: 0n, transportAuthor: `validator-${i}` },
  }))
  const genesis: CapabilitySnapshot = {
    groupId: bytes(1), revision: 0n, revisionDigest: bytes(2), rootAdminPublicKey: bytes(3),
    capabilityLogFeed: bytes(4), capabilities: new Map(effective.map((item) => [bytesToHex(item.id), item])),
    policies: new Map(), validatorFloorMs: 0n,
  }
  const next = { ...genesis, revision: 1n, revisionDigest: bytes(5) }
  const context = { groupId: genesis.groupId, membershipRevision: genesis.revisionDigest, validationPolicy: bytes(6), writerId: bytes(7) }
  const proofs: VerifiedGovernanceClosureEvidence[] = await Promise.all(validators.map(async (key, i) => ({
    signed: await signGovernanceClosure({
      groupId: genesis.groupId, membershipRevision: genesis.revisionDigest,
      nextMembershipRevision: next.revisionDigest, validatorId: key.publicKeyBytes,
      validatorCapability: effective[i]!.id, throughMs: BigInt(100 + i * 10), lastAdmissionSequence: 3n,
    }, key.privateKey),
    transportAuthor: `validator-${i}`, sequence: 4n, contiguousThrough: 4n,
    lastAdmissionSequence: 3n, maximumAdmittedTimestampMs: 90n,
  })))
  return { genesis, next, context, proofs }
}

function bytes(fill: number): Uint8Array { return new Uint8Array(32).fill(fill) }

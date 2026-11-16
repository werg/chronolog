import type { CapabilitySnapshot, EffectiveCapability } from '@chronolog/capabilities'
import { bytesToHex, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { GovernanceActivationIndex, signGovernanceClosure, type VerifiedGovernanceClosureEvidence } from './governance-activation.js'

describe('governance activation', () => {
  it('selects coordinated membership strictly after the control record position', async () => {
    const { genesis, next, context } = await fixture()
    const index = new GovernanceActivationIndex(genesis, 'coordinated')
    index.observe(next)
    expect(index.snapshotFor({ ...context, membershipRevision: next.revisionDigest, canonicalPosition: 5n })).toBeNull()
    index.activateCoordinated(next, 5n)
    expect(index.snapshotFor({ ...context, canonicalPosition: 5n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, canonicalPosition: 6n })?.revision).toBe(1n)
    // Later reception never changes the preceding position's authorization.
    expect(index.snapshotFor({ ...context, canonicalPosition: 1n })?.revision).toBe(0n)
  })

  it('requires every fixed validator and complete prior admission evidence to close a peer revision', async () => {
    const { genesis, next, context, proofs } = await fixture()
    const index = new GovernanceActivationIndex(genesis, 'peer')
    index.observe(next)
    await expect(index.activatePeer(next, proofs.slice(0, 1))).rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    await expect(index.activatePeer(next, [{ ...proofs[0]!, contiguousThrough: 3n }, proofs[1]!]))
      .rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    await expect(index.activatePeer(next, [{ ...proofs[0]!, maximumAdmittedTimestampMs: 101n }, proofs[1]!]))
      .rejects.toThrow('GOVERNANCE_CLOSURE_INCOMPLETE')
    expect(await index.activatePeer(next, proofs)).toBe(110n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 110n })?.revision).toBe(0n)
    expect(index.snapshotFor({ ...context, authorTimestampMs: 111n })?.revision).toBe(1n)
  })

  it('rejects a forged closure and a closure for a different proposed revision', async () => {
    const { genesis, next, proofs } = await fixture()
    const index = new GovernanceActivationIndex(genesis, 'peer')
    const forged = { ...proofs[0]!, signed: { ...proofs[0]!.signed, signature: new Uint8Array(64) } }
    await expect(index.activatePeer(next, [forged, proofs[1]!])).rejects.toThrow('GOVERNANCE_CLOSURE_INVALID')
    await expect(index.activatePeer({ ...next, revisionDigest: bytes(99) }, proofs)).rejects.toThrow('GOVERNANCE_CLOSURE_INVALID')
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

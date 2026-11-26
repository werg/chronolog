import { describe, expect, it } from 'vitest'
import { createSigningIdentity } from './codec.js'
import {
  computeIncludedSetDigest,
  policyScopeId,
  signFinalityCheckpoint,
  signHostAttestationV2,
  verifyFinalityV2,
  verifyHostAttestationV2,
  type FinalityCheckpoint,
  type ScheduledFinalityEntry,
} from './finality-v2.js'

describe('authority v2 finality schedule & host attestations', () => {
  it('supports none -> P1 bootstrap, enforces P1 -> P2 handoff, and verifies blockchain-anchor providers', async () => {
    const chainId = 'a'.repeat(64)
    const v1 = await createSigningIdentity()
    const v2 = await createSigningIdentity()
    const v3 = await createSigningIdentity()

    const schedule: ScheduledFinalityEntry[] = [
      { effectiveAfterMs: -1n, policy: { kind: 'none' } },
      { effectiveAfterMs: 100n, policy: { kind: 'signed-frontier', signer: v1.publicKey } },
      { effectiveAfterMs: 500n, policy: { kind: 'fixed-validator', validators: [v2.publicKey, v3.publicKey], threshold: 2 } },
      { effectiveAfterMs: 1000n, policy: { kind: 'blockchain-anchor', chain: 'ethereum', anchorId: '0xabc' } },
    ]
    const scope1 = await policyScopeId(chainId, schedule[1]!)
    const scope2 = await policyScopeId(chainId, schedule[2]!)
    const scope3 = await policyScopeId(chainId, schedule[3]!)

    const opEarly = '1'.repeat(64)
    const opLateUnincluded = '2'.repeat(64)
    const opMid = '3'.repeat(64)

    // P2 tries to finalize at t=600 BEFORE P1 sealed the handoff at t=500 -> must be ignored!
    const cp2Payload = {
      chainId,
      policyScopeId: scope2,
      closedThroughMs: 600n,
      includedSetDigest: computeIncludedSetDigest([opEarly, opMid]),
      historyDigest: 'd'.repeat(64),
      stateRoot: 'e'.repeat(64),
      inclusions: [{ opId: opMid, authorTimestampMs: 550n, author: v1.publicKey }],
    }
    const cp2: FinalityCheckpoint = {
      payload: cp2Payload,
      attestation: {
        kind: 'signatures',
        signatures: [await signFinalityCheckpoint(cp2Payload, v2), await signFinalityCheckpoint(cp2Payload, v3)],
      },
    }
    const resPremature = await verifyFinalityV2({ chainId, schedule, checkpoints: [cp2] })
    expect(resPremature.closedThroughMs).toBeNull()

    // P1 bootstraps from none at t=500 (sealing the handoff to P2!)
    const cp1Payload = {
      chainId,
      policyScopeId: scope1,
      closedThroughMs: 500n,
      includedSetDigest: computeIncludedSetDigest([opEarly]),
      historyDigest: 'c'.repeat(64),
      stateRoot: 'b'.repeat(64),
      inclusions: [{ opId: opEarly, authorTimestampMs: 200n, author: v1.publicKey }],
    }
    const cp1: FinalityCheckpoint = {
      payload: cp1Payload,
      attestation: { kind: 'signatures', signatures: [await signFinalityCheckpoint(cp1Payload, v1)] },
    }

    // Now P1 + P2 both verify, and opLateUnincluded (t=300 <= 600, not included) is excluded!
    const resBoth = await verifyFinalityV2({
      chainId,
      schedule,
      checkpoints: [cp2, cp1],
      knownOps: [
        { opId: opEarly, authorTimestampMs: 200n },
        { opId: opLateUnincluded, authorTimestampMs: 300n },
        { opId: opMid, authorTimestampMs: 550n },
      ],
    })
    expect(resBoth.closedThroughMs).toBe(600n)
    expect(resBoth.includedOpIds.has(opEarly)).toBe(true)
    expect(resBoth.includedOpIds.has(opMid)).toBe(true)
    expect(resBoth.excludedOpIds.has(opLateUnincluded)).toBe(true)

    // P2 seals handoff at t=1000, then blockchain-anchor P3 seals t=1500!
    const cp2HandoffPayload = { ...cp2Payload, closedThroughMs: 1000n }
    const cp2Handoff: FinalityCheckpoint = {
      payload: cp2HandoffPayload,
      attestation: {
        kind: 'signatures',
        signatures: [await signFinalityCheckpoint(cp2HandoffPayload, v2), await signFinalityCheckpoint(cp2HandoffPayload, v3)],
      },
    }
    const cp3: FinalityCheckpoint = {
      payload: { ...cp2Payload, policyScopeId: scope3, closedThroughMs: 1500n, inclusions: [] },
      attestation: { kind: 'blockchain', blockHeight: 42, blockTimestampMs: 1600n, proofBytes: 'deadbeef' },
    }
    const resChain = await verifyFinalityV2({
      chainId,
      schedule,
      checkpoints: [cp1, cp2Handoff, cp3],
      blockchainVerifier: (pol, cp) => pol.chain === 'ethereum' && cp.attestation.kind === 'blockchain' && cp.attestation.proofBytes === 'deadbeef',
    })
    expect(resChain.closedThroughMs).toBe(1500n)
  })

  it('signs and verifies v2 host attestations', async () => {
    const host = await createSigningIdentity()
    const att = await signHostAttestationV2({ publicKey: 'f'.repeat(64), accountId: 'acct-42' }, host)
    expect(await verifyHostAttestationV2(att, host.publicKey)).toBe(true)
    expect(await verifyHostAttestationV2(att, '0'.repeat(64))).toBe(false)
  })
})

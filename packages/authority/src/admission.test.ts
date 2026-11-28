import { describe, expect, it } from 'vitest'
import { createSigningIdentity } from './codec.js'
import {
  computeIncludedSetDigest,
  evaluateAdmission,
  signAdmissionCheckpoint,
  signHostAttestationV2,
  verifyHostAttestationV2,
  type AdmissionCheckpointPayload,
  type AdmissionEvidence,
} from './admission.js'

const LOG_ID = 'a'.repeat(64)
const ROOT_A = '1'.repeat(64)
const HIST_A = '2'.repeat(64)

describe('@chronolog/authority admission', () => {
  it('evaluates external evidence via state-defined evaluator and enforces pinned frontier non-rewinding', async () => {
    const signer = await createSigningIdentity()
    const opIncluded = 'b'.repeat(64)
    const opLateBackdated = 'c'.repeat(64)
    const opAfter = 'd'.repeat(64)

    const payload: AdmissionCheckpointPayload = {
      logId: LOG_ID,
      scopeId: 'e'.repeat(64),
      closedThroughMs: 100n,
      includedSetDigest: computeIncludedSetDigest([opIncluded]),
      historyDigest: HIST_A,
      stateRoot: ROOT_A,
      inclusions: [{ opId: opIncluded, authorTimestampMs: 50n, author: signer.publicKey }],
    }
    const sig = await signAdmissionCheckpoint(payload, signer)
    const ev: AdmissionEvidence = { kind: 'checkpoint', payload, data: { signatures: [sig] } }

    const decision = await evaluateAdmission({
      logId: LOG_ID,
      ops: [
        { opId: opIncluded, author: signer.publicKey, authorTimestampMs: 50n, visibility: 'public' },
        { opId: opLateBackdated, author: signer.publicKey, authorTimestampMs: 75n, visibility: 'public' },
        { opId: opAfter, author: signer.publicKey, authorTimestampMs: 150n, visibility: 'public' },
      ],
      evidence: [ev],
      evaluator: async ({ evidence }) => ({
        closedThroughMs: 100,
        includedOpIds: [opIncluded],
        verifiedEvidenceIndices: evidence.length > 0 ? [0] : [],
        latestCheckpointIndex: evidence.length > 0 ? 0 : null,
      }),
    })

    expect(decision.closedThroughMs).toBe(100n)
    expect(decision.includedOpIds.has(opIncluded)).toBe(true)
    expect(decision.excludedOpIds.has(opLateBackdated)).toBe(true)
    expect(decision.excludedOpIds.has(opAfter)).toBe(false)
    expect(decision.verifiedEvidence).toHaveLength(1)

    // Pinned frontier strictly excludes backdated ops even without external evidence
    const pinnedDecision = await evaluateAdmission({
      logId: LOG_ID,
      ops: [
        { opId: opIncluded, author: signer.publicKey, authorTimestampMs: 50n, visibility: 'public' },
        { opId: opLateBackdated, author: signer.publicKey, authorTimestampMs: 75n, visibility: 'public' },
      ],
      evidence: [],
      pinnedFrontier: {
        closedThroughMs: 100n,
        stateRoot: ROOT_A,
        historyDigest: HIST_A,
        includedOpIds: [opIncluded],
      },
    })
    expect(pinnedDecision.closedThroughMs).toBe(100n)
    expect(pinnedDecision.includedOpIds.has(opIncluded)).toBe(true)
    expect(pinnedDecision.excludedOpIds.has(opLateBackdated)).toBe(true)
  })

  it('signs and verifies host attestations in the canonical chronolog/host-attestation/v1 format', async () => {
    const host = await createSigningIdentity()
    const att = await signHostAttestationV2({ publicKey: 'f'.repeat(64), accountId: 'acct-1' }, host)
    expect(await verifyHostAttestationV2(att, host.publicKey)).toBe(true)
    const other = await createSigningIdentity()
    expect(await verifyHostAttestationV2(att, other.publicKey)).toBe(false)
  })
})

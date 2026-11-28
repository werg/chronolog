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
      seenOpsRoot: '3'.repeat(64),
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

    // Later evidence cannot add an operation behind the locally pinned frontier.
    const pinnedDecision = await evaluateAdmission({
      logId: LOG_ID,
      ops: [
        { opId: opIncluded, author: signer.publicKey, authorTimestampMs: 50n, visibility: 'public' },
        { opId: opLateBackdated, author: signer.publicKey, authorTimestampMs: 75n, visibility: 'public' },
      ],
      evidence: [ev],
      evaluator: () => ({ closedThroughMs: 120, includedOpIds: [opLateBackdated], latestCheckpointIndex: 0 }),
      pinnedFrontier: {
        closedThroughMs: 100n,
        stateRoot: ROOT_A,
        historyDigest: HIST_A,
        includedOpIds: [opIncluded],
      },
    })
    expect(pinnedDecision.closedThroughMs).toBe(120n)
    expect(pinnedDecision.includedOpIds.has(opIncluded)).toBe(true)
    expect(pinnedDecision.includedOpIds.has(opLateBackdated)).toBe(false)
    expect(pinnedDecision.excludedOpIds.has(opLateBackdated)).toBe(true)
    expect(pinnedDecision.latestCheckpoint).toBeNull()
  })

  it('signs and verifies host attestations bound to a log and an expiry (chronolog/host-attestation/v2)', async () => {
    const host = await createSigningIdentity()
    const att = await signHostAttestationV2({ logId: LOG_ID, publicKey: 'f'.repeat(64), expiresAtMs: 1_000, accountId: 'acct-1' }, host)
    expect(await verifyHostAttestationV2(att, host.publicKey, { logId: LOG_ID, atMs: 999 })).toBe(true)
    const other = await createSigningIdentity()
    expect(await verifyHostAttestationV2(att, other.publicKey, { logId: LOG_ID, atMs: 999 })).toBe(false)
    // Replay into another log or after expiry is rejected.
    expect(await verifyHostAttestationV2(att, host.publicKey, { logId: 'b'.repeat(64), atMs: 999 })).toBe(false)
    expect(await verifyHostAttestationV2(att, host.publicKey, { logId: LOG_ID, atMs: 1_000 })).toBe(false)
    // Unbound payloads cannot be signed at all.
    await expect(signHostAttestationV2({ logId: LOG_ID, publicKey: 'f'.repeat(64), expiresAtMs: 0 }, host)).rejects.toThrow('HOST_ATTESTATION_EXPIRY_INVALID')
    await expect(signHostAttestationV2({ logId: 'nope', publicKey: 'f'.repeat(64), expiresAtMs: 5 }, host)).rejects.toThrow()
  })
})

import { describe, expect, it } from 'vitest'

import { ControlStore, ControlStoreConflictError } from './control-store.js'
import { MemoryControlStorePersistence } from './persistence.js'
import type {
  PutCandidateInput,
  StoredAttestation,
  ValidatorHeartbeat,
} from './types.js'

const bytes = (...values: number[]) => Uint8Array.from(values)

function candidate(id: number, timestamp: bigint, author = id): PutCandidateInput {
  return {
    txId: bytes(id),
    groupId: bytes(1),
    candidateDigest: bytes(100 + id),
    validationPolicy: bytes(8),
    orderKey: {
      authorTimestampMs: timestamp,
      authorId: bytes(author),
      txId: bytes(id),
    },
    canonicalPayload: bytes(200, id),
    state: 'pending_validation',
  }
}

function attestation(id: number, txId: number, validator = id): StoredAttestation {
  return {
    attestationId: bytes(id),
    txId: bytes(txId),
    validatorId: bytes(validator),
    validatorCapability: bytes(validator, 1),
    membershipRevision: bytes(1),
    candidateDigest: bytes(100 + txId),
    validatorFeedSequence: BigInt(id),
    authorTimestampMs: BigInt(txId),
    acceptedAboveMs: 0n,
    policyVersion: 1n,
    transportAuthor: `@validator-${validator}.ed25519`,
  }
}

function heartbeat(validator: number, cutoff: bigint, contiguous = true): ValidatorHeartbeat {
  return {
    heartbeatId: bytes(validator, Number(cutoff)),
    validatorId: bytes(validator),
    validatorCapability: bytes(validator, 1),
    membershipRevision: bytes(1),
    validatorFeedSequence: cutoff,
    acceptanceCutoffMs: cutoff,
    feedContiguous: contiguous,
  }
}

describe('ControlStore', () => {
  it('keeps provisional selection reversible while preserving proposal identity and admitted decisions', () => {
    const persistence = new MemoryControlStorePersistence(), store = new ControlStore(persistence)
    const early = candidate(1, 10n), late = candidate(2, 20n)
    store.putCandidate(early)
    store.putCandidate({ ...late, state: 'provisional' })
    store.setCandidateState(early.txId, 'provisional')
    expect(store.orderedTransactionIds()).toEqual([early.txId, late.txId])
    expect(store.setCandidateState(early.txId, 'pending_validation', { reason: 'AUTHORIZATION_PENDING' }).at(-1))
      .toMatchObject({ kind: 'order_remove', index: 0, previousLength: 2 })
    expect(store.getCandidate(early.txId)?.canonicalPayload).toEqual(early.canonicalPayload)
    store.setCandidateState(early.txId, 'provisional')
    expect(store.getCandidate(early.txId)?.stateReason).toBeUndefined()
    const resumed = new ControlStore(persistence)
    expect(resumed.orderedTransactionIds()).toEqual([early.txId, late.txId])
    expect(resumed.setCandidateState(early.txId, 'admissible')).toHaveLength(1)
    expect(() => resumed.setCandidateState(early.txId, 'pending_validation')).toThrow('ADMISSION_NOT_MONOTONIC')
    resumed.setCandidateState(late.txId, 'excluded', { reason: 'ADMISSION_CLOSED' })
    expect(resumed.orderedTransactionIds()).toEqual([early.txId])
    expect(resumed.getCandidate(late.txId)?.canonicalPayload).toEqual(late.canonicalPayload)
  })

  it('inserts newly admissible candidates at a stable deterministic position', () => {
    const store = new ControlStore()
    store.putCandidate(candidate(2, 20n))
    store.putCandidate(candidate(3, 30n))
    store.setCandidateState(bytes(2), 'admissible')
    store.setCandidateState(bytes(3), 'admissible')

    store.putCandidate(candidate(1, 10n))
    const deltas = store.setCandidateState(bytes(1), 'admissible')

    expect([...store.orderedTransactionIds()].map((id) => id[0])).toEqual([1, 2, 3])
    expect(deltas.at(-1)).toMatchObject({
      kind: 'order_insert',
      index: 0,
      previousLength: 2,
    })
    expect(store.earliestOrderDifference([bytes(2), bytes(3)])).toBe(0)
  })

  it('uses immutable byte tie-breakers and never lets attestations move order', () => {
    const store = new ControlStore()
    const highAuthor = candidate(1, 10n, 2)
    const lowAuthor = candidate(2, 10n, 1)
    store.putCandidate(highAuthor)
    store.setCandidateState(highAuthor.txId, 'admissible')
    store.putCandidate(lowAuthor)
    store.setCandidateState(lowAuthor.txId, 'admissible')
    const before = store.orderedTransactionIds()

    store.putAttestation(attestation(10, 1))
    store.putAttestation(attestation(11, 1))
    expect(store.putCandidate(highAuthor).added).toBe(false)

    expect(store.orderedTransactionIds()).toEqual(before)
    expect([...store.orderedTransactionIds()].map((id) => id[0])).toEqual([2, 1])
    expect(() => store.setCandidateState(bytes(1), 'pending_validation')).toThrowError(
      new ControlStoreConflictError('CONTROL_STORE_ADMISSION_NOT_MONOTONIC'),
    )
  })

  it('orders concurrent proposals from one author identically under opposite arrival order', () => {
    const proposals = [candidate(2, 10n, 7), candidate(1, 10n, 7)]
    const replicas = [new ControlStore(), new ControlStore()]
    for (const [index, store] of replicas.entries()) {
      for (const proposal of index === 0 ? proposals : [...proposals].reverse()) {
        store.putCandidate(proposal)
        store.setCandidateState(proposal.txId, 'admissible')
      }
    }
    expect(replicas[0]!.orderedTransactionIds()).toEqual([bytes(1), bytes(2)])
    expect(replicas[1]!.orderedTransactionIds()).toEqual(replicas[0]!.orderedTransactionIds())
  })

  it('calculates the exact 2-of-3 blocking watermark from contiguous feeds', () => {
    const store = new ControlStore()
    store.putCandidate(candidate(1, 85n))
    store.setCandidateState(bytes(1), 'admissible')
    store.recordHeartbeat(heartbeat(1, 100n))
    store.recordHeartbeat(heartbeat(2, 90n))
    store.recordHeartbeat(heartbeat(3, 80n))
    const policy = {
      kind: 'threshold' as const,
      policyId: 'two-of-three',
      validatorIds: [bytes(1), bytes(2), bytes(3)],
      threshold: 2,
    }

    const watermark = store.watermark(policy)
    expect(watermark.cutoffMs).toBe(90n)
    expect(watermark.explanation).toBe('established')
    expect(store.settlementEvidence(bytes(1), policy).belowWatermark).toBe(true)

    const incomplete = new ControlStore()
    incomplete.recordHeartbeat(heartbeat(1, 100n, false))
    expect(incomplete.watermark(policy).cutoffMs).toBeNull()
  })

  it('surfaces unresolved attestation references', () => {
    const store = new ControlStore()
    store.putCandidate(candidate(1, 85n))
    store.setCandidateState(bytes(1), 'admissible')
    store.putAttestation(attestation(99, 9, 1))
    store.putAttestation(attestation(98, 9, 2))
    expect(store.missingProposalCount).toBe(1)
    store.recordHeartbeat(heartbeat(1, 100n))

    const evidence = store.settlementEvidence(bytes(1), {
      kind: 'threshold',
      policyId: 'one',
      validatorIds: [bytes(1)],
      threshold: 1,
    })
    expect(evidence.unresolvedAttestationIds).toEqual([bytes(99), bytes(98)])
    store.putCandidate(candidate(9, 9n))
    expect(store.missingProposalCount).toBe(0)
  })

  it('retains a known partial admission as a blocker until the node resolves it', () => {
    const store = new ControlStore(new MemoryControlStorePersistence())
    store.putCandidate(candidate(1, 50n))
    store.putCandidate(candidate(2, 100n))
    store.setCandidateState(bytes(2), 'admissible')
    store.putAttestation({ ...attestation(10, 1, 1), authorTimestampMs: 50n })
    const policy = { kind: 'threshold' as const, policyId: 'two-of-three',
      validatorIds: [bytes(1), bytes(2), bytes(3)], threshold: 2 }
    for (const validator of [1, 2, 3]) store.recordHeartbeat(heartbeat(validator, 100n))

    // Raw heartbeat evidence cannot decide the pending proposal's policy,
    // capability grants or proof validity. The node owns that decision.
    expect(store.settlementEvidence(bytes(2), policy, bytes(1))).toMatchObject({
      belowWatermark: true, pendingCandidateIds: [bytes(1)],
    })
    store.setCandidateState(bytes(1), 'excluded', { reason: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(store.settlementEvidence(bytes(2), policy, bytes(1)).pendingCandidateIds).toEqual([])
    expect(() => store.setCandidateState(bytes(1), 'admissible')).toThrow('CONTROL_STORE_TERMINAL_STATE')
  })

  it('blocks an unknown payload only at or after its signed author timestamp', () => {
    const store = new ControlStore()
    store.putCandidate(candidate(1, 80n))
    store.putCandidate(candidate(2, 200n))
    store.setCandidateState(bytes(1), 'admissible')
    store.setCandidateState(bytes(2), 'admissible')
    store.recordHeartbeat(heartbeat(1, 250n))
    store.putAttestation({ ...attestation(10, 9, 1), authorTimestampMs: 200n })
    const policy = { kind: 'threshold' as const, policyId: 'one', validatorIds: [bytes(1)], threshold: 1 }
    expect(store.settlementEvidence(bytes(1), policy, bytes(1)).unresolvedAttestationIds).toEqual([])
    expect(store.settlementEvidence(bytes(2), policy, bytes(1)).unresolvedAttestationIds).toEqual([bytes(10)])
  })

  it('persists exact bigint/byte state and returns defensive copies', () => {
    const persistence = new MemoryControlStorePersistence()
    const first = new ControlStore(persistence)
    first.putCandidate(candidate(7, 9_007_199_254_740_993n))
    first.setCandidateState(bytes(7), 'admissible')
    const exposed = first.orderedTransactionIds()[0]!
    exposed[0] = 255

    const restored = new ControlStore(persistence)
    expect(restored.orderedTransactionIds()).toEqual([bytes(7)])
    expect(restored.getCandidate(bytes(7))?.orderKey.authorTimestampMs).toBe(
      9_007_199_254_740_993n,
    )
    expect(restored.changesSince(0n).length).toBe(first.changesSince(0n).length)
  })

  it('bounds retained deltas and exposes an explicit snapshot reset floor', () => {
    const store = new ControlStore(null, { maximumRetainedDeltas: 3 })
    for (let id = 1; id <= 5; id += 1) store.putCandidate(candidate(id, BigInt(id)))

    expect(store.deltaFloor).toBe(2n)
    expect(store.changesSince(store.deltaFloor)).toHaveLength(3)
    expect(() => store.changesSince(0n)).toThrowError('CONTROL_STORE_DELTA_HISTORY_RESET')
    expect(store.snapshot().deltas).toHaveLength(3)
  })

  it('scopes heartbeat watermarks to the candidate membership revision', () => {
    const store = new ControlStore()
    store.recordHeartbeat(heartbeat(1, 100n))
    store.recordHeartbeat({
      ...heartbeat(1, 200n),
      heartbeatId: bytes(1, 200),
      membershipRevision: bytes(2),
    })
    const policy = {
      kind: 'threshold' as const,
      policyId: 'one',
      validatorIds: [bytes(1)],
      threshold: 1,
    }

    expect(store.watermark(policy, bytes(1)).cutoffMs).toBe(100n)
    expect(store.watermark(policy, bytes(2)).cutoffMs).toBe(200n)
    expect(store.watermark(policy, bytes(3)).cutoffMs).toBeNull()
  })

  it('advances an existing heartbeat proof after its replication gap is filled', () => {
    const persistence = new MemoryControlStorePersistence()
    const store = new ControlStore(persistence)
    const policy = { kind: 'threshold' as const, policyId: 'one', validatorIds: [bytes(1)], threshold: 1 }
    const incomplete = heartbeat(1, 100n, false)
    store.recordHeartbeat(incomplete)
    expect(store.watermark(policy, bytes(1)).cutoffMs).toBeNull()

    expect(store.recordHeartbeat({ ...incomplete, feedContiguous: true })).toMatchObject({
      kind: 'heartbeat_advanced', feedContiguous: true,
    })
    expect(store.watermark(policy, bytes(1)).cutoffMs).toBe(100n)
    // Replaying a snapshot of the earlier local observation cannot erase proof.
    expect(store.recordHeartbeat(incomplete)).toBeNull()
    const reopened = new ControlStore(persistence)
    expect(reopened.watermark(policy, bytes(1)).cutoffMs).toBe(100n)
    const exposed = reopened.listHeartbeats()[0]!
    exposed.validatorId[0] = 99
    expect(reopened.listHeartbeats()[0]!.validatorId).toEqual(bytes(1))
    expect(() => reopened.recordHeartbeat({ ...incomplete, heartbeatId: bytes(9), feedContiguous: true }))
      .toThrow('CONTROL_STORE_HEARTBEAT_CONFLICT')
  })

  it('requires the current admission index to consume a restored heartbeat prefix', () => {
    const persistence = new MemoryControlStorePersistence()
    const store = new ControlStore(persistence)
    const policy = { kind: 'threshold' as const, policyId: 'two-of-three',
      validatorIds: [bytes(1), bytes(2), bytes(3)], threshold: 2 }
    store.putCandidate(candidate(1, 50n))
    store.putAttestation({ ...attestation(1, 1), authorTimestampMs: 50n })
    for (const validator of [1, 2, 3]) store.recordHeartbeat(heartbeat(validator, 100n))

    const reopened = new ControlStore(persistence)
    const indexed = new Set<string>()
    expect(reopened.watermark(policy, bytes(1), indexed).cutoffMs).toBeNull()
    indexed.add('0164'); indexed.add('0264')
    expect(reopened.watermark(policy, bytes(1), indexed).cutoffMs).toBe(100n)
    // Raw evidence remains separate from resolving this proposal's admission.
    // A current caller can withhold any retained heartbeat whose consumed
    // prefix has not been established in this process.
    indexed.delete('0164')
    expect(reopened.watermark(policy, bytes(1), indexed).cutoffMs).toBeNull()
    indexed.add('0364')
    expect(reopened.watermark(policy, bytes(1), indexed).cutoffMs).toBe(100n)
  })

  it('rejects conflicting duplicate identities and later regressing cutoffs', () => {
    const store = new ControlStore()
    store.putCandidate(candidate(1, 1n))
    expect(() => store.putCandidate(candidate(1, 2n))).toThrowError(
      'CONTROL_STORE_CANDIDATE_CONFLICT',
    )
    store.recordHeartbeat(heartbeat(1, 100n))
    expect(store.recordHeartbeat(heartbeat(1, 99n))).toBeNull()
    expect(() => store.recordHeartbeat({
      ...heartbeat(1, 99n),
      validatorFeedSequence: 101n,
    })).toThrowError(
      'CONTROL_STORE_HEARTBEAT_CUTOFF_REGRESSION',
    )
  })
})

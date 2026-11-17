import { createEventMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, emit, encodeTransactionCore, encodeValidatorAttestation, encodeValidatorHeartbeat,
  equalBytes, generateEd25519KeyPair, program, transactionDigest, utf8, type TransactionCore, type ValidatorAttestation,
} from '@chronolog/protocol'
import { MemoryTransportNetwork, type TransportRecord } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import type { ClosedAdmissionRevision } from './types.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(101), membershipRevision = bytes(102), twoVotes = bytes(103), oneVote = bytes(104)

async function fixture(options: { multiplePolicies?: boolean; completePolicySet?: boolean } = {}) {
  const identities = await Promise.all(Array.from({ length: 5 }, () => generateEd25519KeyPair()))
  const network = new MemoryTransportNetwork()
  const transports = identities.map((_, index) => network.createNode(`live-finality-${index}`))
  const observer = transports[4]!, validatorIds = identities.slice(0, 3).map(item => item.publicKeyBytes)
  const policy = (id: Uint8Array) => ({ kind: 'threshold' as const, policyId: bytesToHex(id), validatorIds,
    threshold: equalBytes(id, oneVote) ? 1 : 2 })
  // Transport retention and node indexing are intentionally independent. This
  // lets a complete feed prefix be present before its subscription is consumed.
  observer.subscribe = (signal) => ({
    [Symbol.asyncIterator]: () => ({ next: () => new Promise<IteratorResult<TransportRecord>>(resolve => {
      if (signal?.aborted) resolve({ done: true, value: undefined })
      else signal?.addEventListener('abort', () => resolve({ done: true, value: undefined }), { once: true })
    }) }),
  })
  const store = new MemoryOperationStore()
  const materialization = await createEventMaterializationRuntime({ store, namespace: 'live-finality' })
  let closures: readonly ClosedAdmissionRevision[] = []
  const node = new ChronologNode({ identity: identities[4]!, groupId, membershipRevision, validationPolicy: twoVotes,
    transport: observer, operationStore: store, materialization,
    membership: {
      canWrite: () => true,
      canValidate: context => validatorIds.some(id => equalBytes(id, context.validatorId)),
      threshold: context => policy(context.validationPolicy).threshold,
      canUseTransportAuthor: context => identities.some((identity, index) =>
        equalBytes(identity.publicKeyBytes, context.signingId) && transports[index]!.identity === context.transportAuthor),
      watermarkPolicy: core => policy(core.validationPolicy),
      ...(options.completePolicySet === false ? {} : {
        liveFinalityPolicies: () => [policy(twoVotes), ...(options.multiplePolicies ? [policy(oneVote)] : [])],
      }),
    },
    peerGovernance: { closedAdmissionRevisions: () => closures, allowsAttestation: async () => true },
  })
  cleanup.push(async () => { await node.close(); await Promise.all(transports.slice(0, 4).map(item => item.close())) })
  await node.start()
  const heads = new Map<string, bigint>()
  const retain = (record: TransportRecord) => {
    observer.receive(record)
    if (record.sequence > (heads.get(record.author) ?? 0n)) heads.set(record.author, record.sequence)
    return record
  }
  const ingest = async (record: TransportRecord) => { retain(record); await node.ingest(record) }
  const candidate = async (name: string, authorTimestampMs: bigint, validationPolicy = twoVotes) => {
    const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: identities[3]!.publicKeyBytes,
      authorTimestampMs, operationId: name, nonce: bytes(105), executionManifestDigest: materialization.queries.executionManifestDigest,
      program: program(emit('changes', name)) }
    const canonical = encodeTransactionCore(core), digest = await transactionDigest(canonical)
    const txId = utf8(`tx_${bytesToHex(digest)}`)
    await ingest(await transports[3]!.publish(await encodeSignedEnvelope(groupId, 'candidate', canonical, identities[3]!)))
    return { txId, core, digest }
  }
  const vote = async (validator: number, proposal: Awaited<ReturnType<typeof candidate>>, deliver = true,
    overrides: Partial<ValidatorAttestation> = {}) => {
    const record = await transports[validator]!.publish(await encodeSignedEnvelope(groupId, 'attestation', encodeValidatorAttestation({
      groupId, membershipRevision, validatorCapability: bytes(110 + validator), txId: proposal.txId,
      validatorId: identities[validator]!.publicKeyBytes, authorTimestampMs: proposal.core.authorTimestampMs,
      acceptedAboveMs: 0n, candidateDigest: proposal.digest, decision: 'admit', policyVersion: 1n,
      ...overrides,
    }), identities[validator]!))
    if (deliver) await ingest(record)
    return record
  }
  const heartbeat = async (validator: number, cutoff = 100n) => {
    await ingest(await transports[validator]!.publish(await encodeSignedEnvelope(groupId, 'heartbeat', encodeValidatorHeartbeat({
      groupId, membershipRevision, validatorCapability: bytes(110 + validator),
      validatorId: identities[validator]!.publicKeyBytes, acceptanceCutoffMs: cutoff,
    }), identities[validator]!)))
  }
  return { node, candidate, vote, heartbeat, ingest, retain,
    closeRevision(proposals: readonly Uint8Array[], closedThroughMs: bigint) {
      closures = [{ membershipRevision, closedThroughMs, proposalIds: proposals,
        feedPrefixes: transports.slice(0, 3).map(transport => ({ author: transport.identity, throughSequence: heads.get(transport.identity) ?? 0n })),
      }]
    } }
}

describe('live chronological finality', () => {
  it('keeps a later outcome provisional until an earlier partial quorum is resolved', async () => {
    const f = await fixture(), a = await f.candidate('earlier', 50n), b = await f.candidate('later', 100n)
    await f.vote(0, a); await f.vote(0, b); await f.vote(1, b)
    await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.outcome(b.txId)?.outcome).toBe('accepted')
    expect(f.node.finalOrderLength).toBe(0)
    expect((await f.node.settlementEvidence(b.txId))?.frontier).toMatchObject({ closedThroughMs: 49n,
      blockers: [{ proposalId: a.txId, reason: 'pending-admission' }] })
    expect((await f.node.events.read()).transactions).toEqual([])

    await f.vote(2, a); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
    expect(f.node.outcome(a.txId)?.orderIndex).toBe(0)
    expect(f.node.outcome(b.txId)?.orderIndex).toBe(1)
    expect((await f.node.events.read()).transactions.flatMap(item => item.events.map(event => event.payload)))
      .toEqual(['earlier', 'later'])
  })

  it('closes against every permitted policy, including an unseen easier-policy proposal', async () => {
    const f = await fixture({ multiplePolicies: true }), b = await f.candidate('later', 100n)
    await f.vote(0, b); await f.vote(1, b); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    const a = await f.candidate('earlier', 50n, oneVote)
    await f.vote(2, a); await f.heartbeat(2); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
    expect(f.node.outcome(a.txId)?.orderIndex).toBe(0)
  })

  it('rejects a known proposal after complete feeds prove its quorum impossible', async () => {
    const f = await fixture(), a = await f.candidate('excluded', 50n), b = await f.candidate('accepted', 100n)
    await f.vote(0, a); await f.vote(0, b); await f.vote(1, b)
    await f.heartbeat(0); await f.heartbeat(1); await f.heartbeat(2); await f.node.waitForIdle()
    expect(f.node.candidate(a.txId)?.state).toBe('inadmissible')
    expect(f.node.outcome(a.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_CLOSED' })
    expect(f.node.isFinal(a.txId)).toBe(true)
    expect(f.node.finalOrderLength).toBe(1)
    expect((await f.node.events.read()).transactions.map(item => item.proposalId)).toEqual([new TextDecoder().decode(b.txId)])
  })

  it('waits for indexed admissions even when the transport already has a contiguous heartbeat prefix', async () => {
    const f = await fixture(), a = await f.candidate('earlier', 50n), b = await f.candidate('later', 100n)
    const delayed = await f.vote(0, a, false)
    f.retain(delayed)
    await f.vote(0, b); await f.vote(1, b); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    expect(f.node.candidate(a.txId)?.state).toBe('provisional')
    expect((await f.node.settlementEvidence(b.txId))?.belowWatermark).toBe(false)
    await f.ingest(delayed); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    await f.vote(2, a); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
  })

  it('uses only candidate-verified votes when deciding whether admission remains possible', async () => {
    const f = await fixture(), a = await f.candidate('invalid-vote', 50n), b = await f.candidate('accepted', 100n)
    await f.vote(0, a, true, { policyVersion: 99n })
    await f.vote(0, b); await f.vote(1, b); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.candidate(a.txId)?.state).toBe('inadmissible')
    expect(f.node.finalOrderLength).toBe(1)
  })

  it('uses a fully consumed governance closure to resolve its old partial admissions', async () => {
    const f = await fixture(), a = await f.candidate('excluded', 50n), b = await f.candidate('accepted', 100n)
    await f.vote(0, a); await f.vote(0, b); await f.vote(1, b)
    f.closeRevision([a.txId, b.txId], 100n)
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect(f.node.candidate(a.txId)?.state).toBe('inadmissible')
    expect(f.node.finalOrderLength).toBe(1)
  })

  it('reuses a retained heartbeat when a missing feed record arrives', async () => {
    const f = await fixture(), a = await f.candidate('gap-filled', 50n)
    const delayed = await f.vote(0, a, false)
    await f.heartbeat(0); await f.vote(1, a); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    expect(f.node.controlStore.listHeartbeats().some(item => !item.feedContiguous)).toBe(true)
    await f.ingest(delayed); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    expect(f.node.controlStore.listHeartbeats().every(item => item.feedContiguous)).toBe(true)
  })

  it('keeps replay available without claiming closure from an incomplete policy description', async () => {
    const f = await fixture({ completePolicySet: false }), a = await f.candidate('provisional', 50n)
    await f.vote(0, a); await f.vote(1, a); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.outcome(a.txId)?.outcome).toBe('accepted')
    expect(f.node.isFinal(a.txId)).toBe(false)
  })
})

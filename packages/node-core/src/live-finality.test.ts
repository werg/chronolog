import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { ControlStore, MemoryControlStorePersistence } from '@chronolog/control-store/browser'
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
  const persistence = new MemoryControlStorePersistence(), control = new ControlStore(persistence)
  const finalPublications: Array<{ length: number; excluded: string[] }> = []
  let revisions = [{ membershipRevision, authorTimeAfterMs: -1n }]
  let closures: readonly ClosedAdmissionRevision[] = []
  const node = new ChronologNode({ identity: identities[4]!, groupId, membershipRevision, validationPolicy: twoVotes,
    transport: observer, operationStore: store, controlStore: control,
    materialization: { ...materialization, coordinator: { ...materialization.coordinator,
      publishFinal: async length => {
        if (length > (materialization.queries.finalOrderLength ?? 0)) finalPublications.push({ length,
          excluded: (persistence.load()?.candidates ?? []).filter(candidate => candidate.state === 'inadmissible').map(candidate => bytesToHex(candidate.txId)) })
        await materialization.coordinator.publishFinal!(length)
      },
    } },
    membershipState: () => ({ membershipRevision: revisions.at(-1)!.membershipRevision, validationPolicy: twoVotes }),
    membership: {
      canWrite: context => revisions.some(revision => equalBytes(revision.membershipRevision, context.membershipRevision) &&
        context.authorTimestampMs !== undefined && context.authorTimestampMs > revision.authorTimeAfterMs),
      canValidate: context => validatorIds.some(id => equalBytes(id, context.validatorId)),
      canHeartbeat: context => validatorIds.some(id => equalBytes(id, context.validatorId)),
      threshold: context => policy(context.validationPolicy).threshold,
      canUseTransportAuthor: context => identities.some((identity, index) =>
        equalBytes(identity.publicKeyBytes, context.signingId) && transports[index]!.identity === context.transportAuthor),
      watermarkPolicy: core => policy(core.validationPolicy),
      ...(options.completePolicySet === false ? {} : {
        admissionScopes: () => revisions.map(revision => ({ ...revision,
          policies: [policy(twoVotes), ...(options.multiplePolicies ? [policy(oneVote)] : [])] })),
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
  const candidate = async (name: string, authorTimestampMs: bigint, validationPolicy = twoVotes, revision: Uint8Array = membershipRevision) => {
    const core: TransactionCore = { groupId, membershipRevision: revision, validationPolicy, authorId: identities[3]!.publicKeyBytes,
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
      groupId, membershipRevision: proposal.core.membershipRevision, validatorCapability: bytes(110 + validator), txId: proposal.txId,
      validatorId: identities[validator]!.publicKeyBytes, authorTimestampMs: proposal.core.authorTimestampMs,
      acceptedAboveMs: 0n, candidateDigest: proposal.digest, decision: 'admit', policyVersion: 1n,
      ...overrides,
    }), identities[validator]!))
    if (deliver) await ingest(record)
    return record
  }
  const heartbeat = async (validator: number, cutoff = 100n, revision: Uint8Array = membershipRevision) => {
    await ingest(await transports[validator]!.publish(await encodeSignedEnvelope(groupId, 'heartbeat', encodeValidatorHeartbeat({
      groupId, membershipRevision: revision, validatorCapability: bytes(110 + validator),
      validatorId: identities[validator]!.publicKeyBytes, acceptanceCutoffMs: cutoff,
    }), identities[validator]!)))
  }
  return { node, control, candidate, vote, heartbeat, ingest, retain, finalPublications,
    setRevisions(value: typeof revisions) { revisions = value },
    closeRevision(proposals: readonly Uint8Array[], closedThroughMs: bigint, revision: Uint8Array = membershipRevision) {
      closures = [...closures.filter(item => !equalBytes(item.membershipRevision, revision)), { membershipRevision: revision, closedThroughMs, proposalIds: proposals,
        feedPrefixes: transports.slice(0, 3).map(transport => ({ author: transport.identity, throughSequence: heads.get(transport.identity) ?? 0n })),
      }]
    } }
}

describe('live chronological finality', () => {
  it('keeps a later outcome provisional until an earlier partial quorum is resolved', async () => {
    const f = await fixture(), a = await f.candidate('earlier', 50n), b = await f.candidate('later', 100n)
    expect(await f.node.liveFinality()).toMatchObject({ provenThroughMs: null, closedThroughMs: null })
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
    expect(f.finalPublications.at(-1)).toEqual({ length: 1, excluded: [bytesToHex(a.txId)] })
    expect((await f.node.events.read()).transactions.map(item => item.proposalId)).toEqual([new TextDecoder().decode(b.txId)])
  })

  it('never finalizes a selected preview merely because its admission becomes impossible', async () => {
    const f = await fixture(), preview = await f.candidate('preview', 50n), admitted = await f.candidate('admitted', 100n)
    // An embedding can supply a selected provisional control state even though
    // this node does not author previews. Its final publication stays fail closed.
    f.control.setCandidateState(preview.txId, 'provisional')
    await f.vote(0, admitted); await f.vote(1, admitted)
    await f.heartbeat(0); await f.heartbeat(1); await f.heartbeat(2); await f.node.waitForIdle()
    expect(await f.node.liveFinality()).toMatchObject({ closedThroughMs: 100n, excludedProposalIds: [preview.txId] })
    expect(f.node.orderLength).toBe(2)
    expect(f.node.outcome(preview.txId)?.outcome).toBe('accepted')
    expect(f.node.finalOrderLength).toBe(0)
    expect(f.finalPublications).toEqual([])
    expect((await f.node.events.read()).transactions).toEqual([])
  })

  it('waits for indexed admissions even when the transport already has a contiguous heartbeat prefix', async () => {
    const f = await fixture(), a = await f.candidate('earlier', 50n), b = await f.candidate('later', 100n)
    const delayed = await f.vote(0, a, false)
    f.retain(delayed)
    await f.vote(0, b); await f.vote(1, b); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    expect(f.node.candidate(a.txId)?.state).toBe('pending_validation')
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

  it('does not infer away an intermediate open revision with no locally known proposals', async () => {
    const f = await fixture(), middle = bytes(120), current = bytes(121)
    f.setRevisions([
      { membershipRevision, authorTimeAfterMs: -1n },
      { membershipRevision: middle, authorTimeAfterMs: 40n },
      { membershipRevision: current, authorTimeAfterMs: 80n },
    ])
    f.closeRevision([], 40n)
    const later = await f.candidate('current-later', 100n, twoVotes, current)
    await f.vote(0, later); await f.vote(1, later)
    await f.heartbeat(0, 200n, current); await f.heartbeat(1, 200n, current)
    await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    expect((await f.node.liveFinality()).closedThroughMs).toBe(40n)

    // The earlier revision really can admit: membership coverage is declared
    // independently of which payloads this observer has encountered.
    const earlier = await f.candidate('middle-earlier', 60n, twoVotes, middle)
    await f.vote(0, earlier); await f.vote(1, earlier)
    await f.heartbeat(0, 70n, middle); await f.heartbeat(1, 70n, middle)
    await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    expect(f.node.outcome(earlier.txId)?.orderIndex).toBe(0)
    expect(f.node.isFinal(later.txId)).toBe(false)

    f.closeRevision([earlier.txId], 80n, middle)
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
    expect(f.node.outcome(later.txId)?.orderIndex).toBe(1)
  })

  it('finalizes the old boundary before a newly activated revision has a heartbeat', async () => {
    const f = await fixture(), next = bytes(122), old = await f.candidate('old-boundary', 100n)
    await f.vote(0, old); await f.vote(1, old)
    f.closeRevision([old.txId], 100n)
    f.setRevisions([{ membershipRevision, authorTimeAfterMs: -1n }, { membershipRevision: next, authorTimeAfterMs: 100n }])
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    expect((await f.node.liveFinality()).closedThroughMs).toBe(100n)
    const later = await f.candidate('new-after-boundary', 101n, twoVotes, next)
    await f.vote(0, later); await f.vote(1, later); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    await f.heartbeat(0, 101n, next); await f.heartbeat(1, 101n, next); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
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

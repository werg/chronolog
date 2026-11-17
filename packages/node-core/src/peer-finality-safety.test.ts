import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { ControlStore, MemoryControlStorePersistence } from '@chronolog/control-store/browser'
import {
  bytesToHex, emit, encodeTransactionCore, encodeValidatorAttestation, encodeValidatorHeartbeat,
  equalBytes, generateEd25519KeyPair, program, transactionDigest, utf8,
  type Ed25519KeyPair, type TransactionCore,
} from '@chronolog/protocol'
import { MemoryTransportNetwork, type MemoryTransport } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import type { ChronologNodeOptions, MembershipResolver } from './types.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(81), membershipRevision = bytes(82), validationPolicy = bytes(83)

async function fixture(overrides: Partial<MembershipResolver> = {}, peerGovernance?: ChronologNodeOptions['peerGovernance']) {
  const network = new MemoryTransportNetwork()
  const writer = await generateEd25519KeyPair()
  const writerTransport = network.createNode('writer')
  const createObserver = () => {
    const transport = network.createNode('observer')
    // This specimen delivers records explicitly, so received and consumed feed
    // prefixes can be varied independently without subscription races.
    transport.subscribe = signal => ({ async *[Symbol.asyncIterator]() {
      if (signal?.aborted) return
      await new Promise<void>(resolve => signal?.addEventListener('abort', () => resolve(), { once: true }))
    } })
    return transport
  }
  let observer = createObserver()
  const validators = await Promise.all([0, 1, 2].map(async index => ({
    identity: await generateEd25519KeyPair(), capability: bytes(90 + index),
    transport: network.createNode(`validator-${index}`),
  })))
  const membership: MembershipResolver = {
    canWrite: context => equalBytes(context.groupId, groupId) &&
      equalBytes(context.membershipRevision, membershipRevision) && equalBytes(context.writerId, writer.publicKeyBytes),
    canValidate: context => equalBytes(context.membershipRevision, membershipRevision) && validators.some(validator =>
      equalBytes(context.validatorId, validator.identity.publicKeyBytes) && equalBytes(context.validatorCapability, validator.capability)),
    canHeartbeat: context => equalBytes(context.membershipRevision, membershipRevision) && validators.some(validator =>
      equalBytes(context.validatorId, validator.identity.publicKeyBytes) && equalBytes(context.validatorCapability, validator.capability)),
    canUseTransportAuthor: context => context.role === 'writer'
      ? equalBytes(context.signingId, writer.publicKeyBytes) && context.transportAuthor === writerTransport.identity
      : validators.some(validator => equalBytes(context.signingId, validator.identity.publicKeyBytes) &&
        context.transportAuthor === validator.transport.identity &&
        equalBytes(context.validatorCapability ?? new Uint8Array(), validator.capability)),
    threshold: () => 2,
    policyVersion: () => 1n,
    watermarkPolicy: context => equalBytes(context.membershipRevision, membershipRevision) &&
      equalBytes(context.validationPolicy, validationPolicy)
      ? { kind: 'threshold', policyId: 'two-of-three', threshold: 2,
        validatorIds: validators.map(validator => validator.identity.publicKeyBytes) } : null,
    admissionScopes: context => equalBytes(context.groupId, groupId)
      ? [{ membershipRevision, authorTimeAfterMs: -1n },
        ...(peerGovernance?.closedAdmissionRevisions() ?? []).map(revision => ({
          membershipRevision: revision.nextMembershipRevision, authorTimeAfterMs: revision.closedThroughMs,
        }))].map(scope => ({ ...scope, policies: [{ kind: 'threshold', policyId: 'two-of-three', threshold: 2,
          validatorIds: validators.map(validator => validator.identity.publicKeyBytes) }] })) : null,
    ...overrides,
  }
  const store = new MemoryOperationStore()
  const persistence = new MemoryControlStorePersistence()
  const open = async () => {
    const materialization = await createEventMaterializationRuntime({ store, namespace: 'peer-finality-safety' })
    const node = new ChronologNode({ identity: writer, groupId, membershipRevision, validationPolicy,
      membershipState: () => ({ membershipRevision: peerGovernance?.closedAdmissionRevisions().at(-1)?.nextMembershipRevision ?? membershipRevision,
        validationPolicy }),
      transport: observer, membership, materialization, controlStore: new ControlStore(persistence),
      operationStore: store, clock: { now: () => 0 }, ...(peerGovernance === undefined ? {} : { peerGovernance }) })
    await node.start()
    return node
  }
  let node = await open()
  cleanup.push(async () => {
    await node.close()
    await writerTransport.close()
    for (const validator of validators) await validator.transport.close()
  })
  const deliver = async (transport: MemoryTransport, identity: Ed25519KeyPair,
    kind: 'candidate' | 'attestation' | 'heartbeat', payload: Uint8Array, publishOnly = false) => {
    const record = await transport.publish(await encodeSignedEnvelope(groupId, kind, payload, identity))
    if (!publishOnly) { observer.receive(record); await node.ingest(record) }
    return record
  }
  const propose = async (name: string, timestamp: bigint, publishOnly = false) => {
    const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: writer.publicKeyBytes,
      authorTimestampMs: timestamp, operationId: name, nonce: bytes(84),
      executionManifestDigest: node.executionManifestDigest, program: program(emit('events', name)) }
    const canonical = encodeTransactionCore(core), candidateDigest = await transactionDigest(canonical)
    const txId = utf8(`tx_${bytesToHex(candidateDigest)}`)
    const record = await deliver(writerTransport, writer, 'candidate', canonical, publishOnly)
    return { core, candidateDigest, txId, record }
  }
  const attest = async (index: number, proposal: Awaited<ReturnType<typeof propose>>, publishOnly = false) => {
    const validator = validators[index]!
    return deliver(validator.transport, validator.identity, 'attestation', encodeValidatorAttestation({
      groupId, membershipRevision, validatorCapability: validator.capability,
      validatorId: validator.identity.publicKeyBytes, txId: proposal.txId, candidateDigest: proposal.candidateDigest,
      authorTimestampMs: proposal.core.authorTimestampMs, acceptedAboveMs: 0n, decision: 'admit', policyVersion: 1n,
    }), publishOnly)
  }
  const heartbeat = async (index: number, cutoff: bigint, publishOnly = false, revision = membershipRevision) => {
    const validator = validators[index]!
    return deliver(validator.transport, validator.identity, 'heartbeat', encodeValidatorHeartbeat({
      groupId, membershipRevision: revision, validatorCapability: validator.capability,
      validatorId: validator.identity.publicKeyBytes, acceptanceCutoffMs: cutoff,
    }), publishOnly)
  }
  return { get node() { return node }, get observer() { return observer }, validators, writer, writerTransport, membership,
    propose, attest, heartbeat,
    async restart() {
      const history = await observer.history()
      await node.close()
      observer = createObserver()
      for (const record of history) observer.receive(record)
      node = await open()
      await node.waitForIdle()
    },
  }
}

async function events(node: ChronologNode) {
  return (await node.events.read()).transactions.flatMap(transaction => transaction.events.map(event => event.payload))
}

describe('fixed-validator finality closes every possible earlier admission', () => {
  it('keeps a known partial quorum pending after a blocking heartbeat quorum, then safely inserts its late vote', async () => {
    const f = await fixture()
    const early = await f.propose('early', 100n)
    await f.attest(0, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()

    expect(f.node.candidate(early.txId)?.state).toBe('pending_validation')
    expect((await f.node.watermark())?.cutoffMs).toBe(250n)
    expect(f.node.orderLength).toBe(1)
    expect(f.node.isFinal(later.txId)).toBe(false)
    expect((await f.node.settlementEvidence(later.txId))?.pendingCandidateIds).toEqual([early.txId])
    expect(await events(f.node)).toEqual([])

    // Validator C never closed author time 100: its later vote is legitimate.
    await f.attest(2, early)
    await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
    expect(await events(f.node)).toEqual(['early', 'later'])
  })

  it('finally excludes a partial quorum when every remaining possible voter has closed, releasing later finality', async () => {
    const f = await fixture(), early = await f.propose('early', 100n)
    await f.attest(0, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(later.txId)).toBe(false)
    await f.heartbeat(2, 250n)
    await f.node.waitForIdle()
    expect(f.node.candidate(early.txId)?.state).toBe('excluded')
    expect(f.node.isFinal(early.txId)).toBe(true)
    expect(f.node.outcome(early.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(f.node.finalOrderLength).toBe(1)
    expect(await events(f.node)).toEqual(['later'])
    await f.restart()
    expect(f.node.isFinal(early.txId)).toBe(true)
    expect(f.node.outcome(early.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(f.node.finalOrderLength).toBe(1)
    expect(await events(f.node)).toEqual(['later'])
  })

  it.each([false, true])('consumes the entire validator prefix before trusting closure (missing vote received: %s)', async received => {
    const f = await fixture(), early = await f.propose('early', 100n)
    const missingVote = await f.attest(0, early, true)
    if (received) f.observer.receive(missingVote)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(later.txId)).toBe(false)
    expect((await f.node.watermark())?.cutoffMs).toBeNull()
    f.observer.receive(missingVote)
    await f.node.ingest(missingVote)
    await f.node.waitForIdle()
    // No replacement heartbeat is needed to complete the recovered prefix.
    expect((await f.node.watermark())?.cutoffMs).toBe(250n)
    expect(f.node.candidate(early.txId)?.state).toBe('pending_validation')
    expect(f.node.isFinal(later.txId)).toBe(false)
    await f.attest(2, early)
    await f.node.waitForIdle()
    expect(await events(f.node)).toEqual(['early', 'later'])
  })

  it('does not freeze later events while an earlier admission lacks its signed proposal body', async () => {
    const f = await fixture(), early = await f.propose('early', 100n, true)
    await f.attest(0, early); await f.attest(2, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(later.txId)).toBe(false)
    expect((await f.node.settlementEvidence(later.txId))?.unresolvedAttestationIds).toHaveLength(2)
    f.observer.receive(early.record)
    await f.node.ingest(early.record)
    await f.node.waitForIdle()
    expect(await events(f.node)).toEqual(['early', 'later'])
  })

  it('does not let an unknown later payload block an already closed earlier prefix', async () => {
    const f = await fixture(), future = await f.propose('future', 500n, true)
    await f.attest(0, future); await f.attest(2, future)
    const earlier = await f.propose('earlier', 100n)
    await f.attest(0, earlier); await f.attest(1, earlier)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(earlier.txId)).toBe(true)
    expect(await events(f.node)).toEqual(['earlier'])
    expect(f.node.candidate(future.txId)).toBeNull()
  })

  it('does not use a newer revision heartbeat to exclude an older partial admission', async () => {
    const f = await fixture(), nextRevision = bytes(123)
    const authorizeHeartbeat = f.membership.canHeartbeat!.bind(f.membership)
    f.membership.canHeartbeat = context => authorizeHeartbeat({ ...context, membershipRevision })
    const early = await f.propose('early', 100n)
    await f.attest(0, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    for (const validator of [0, 1, 2]) await f.heartbeat(validator, 500n, false, nextRevision)
    await f.node.waitForIdle()
    expect(f.node.candidate(early.txId)?.state).toBe('pending_validation')
    expect(f.node.isFinal(later.txId)).toBe(false)
    await f.attest(2, early)
    await f.node.waitForIdle()
    expect(await events(f.node)).toEqual(['early', 'later'])
  })

  it('resolves a partial admission only after every indexed governance closure admission is consumed', async () => {
    let closed = false
    let admissions: readonly Uint8Array[] = []
    let feedPrefixes: readonly { author: string; throughSequence: bigint }[] = []
    const f = await fixture({}, {
      closedAdmissionRevisions: () => closed ? [{ membershipRevision, nextMembershipRevision: bytes(124), closedThroughMs: 350n,
        proposalIds: admissions, feedPrefixes }] : [],
      allowsAttestation: async () => true,
    })
    const early = await f.propose('early', 100n)
    await f.attest(0, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    const missing = await f.propose('missing', 300n, true)
    admissions = [early.txId, later.txId, missing.txId]
    feedPrefixes = await Promise.all(f.validators.map(async validator => ({ author: validator.transport.identity,
      throughSequence: (await validator.transport.history()).reduce((maximum, record) =>
        record.author === validator.transport.identity && record.sequence > maximum ? record.sequence : maximum, 0n) })))
    closed = true
    await f.node.refreshMembership()
    await f.node.waitForIdle()
    expect(f.node.candidate(early.txId)?.state).toBe('pending_validation')
    expect(f.node.isFinal(later.txId)).toBe(false)
    f.observer.receive(missing.record)
    await f.node.ingest(missing.record)
    await f.node.waitForIdle()
    expect(f.node.outcome(early.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(f.node.isFinal(later.txId)).toBe(true)
    expect(await events(f.node)).toEqual(['later'])
  })

  it('keeps custom admission pending until its resolver supplies an impossibility witness', async () => {
    const f = await fixture({ selectAdmission: (_context, proofs) => proofs.length >= 2 ? proofs.slice(0, 2) : [] })
    const early = await f.propose('early', 100n)
    await f.attest(0, early)
    const later = await f.propose('later', 200n)
    await f.attest(0, later); await f.attest(1, later)
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n); await f.heartbeat(2, 250n)
    await f.node.waitForIdle()
    expect(f.node.candidate(early.txId)?.state).toBe('pending_validation')
    expect(f.node.isFinal(later.txId)).toBe(false)
    f.membership.canStillAdmit = (_context, evidence) =>
      new Set([...evidence.attestations.map(vote => bytesToHex(vote.validatorId)), ...evidence.openValidatorIds.map(bytesToHex)]).size >= 2
    await f.heartbeat(2, 300n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(early.txId)).toBe(true)
    expect(await events(f.node)).toEqual(['later'])
  })

  it('observes the current policy cutoff before the first proposal and rejects a newly backdated proposal', async () => {
    const f = await fixture()
    await f.heartbeat(0, 250n); await f.heartbeat(1, 250n)
    await f.node.waitForIdle()
    expect(f.node.orderLength).toBe(0)
    expect((await f.node.watermark())?.cutoffMs).toBe(250n)
    expect(f.node.reserveTransactionContext().authorTimestampMs).toBe(251n)
    const late = await f.propose('too-late', 100n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(late.txId)).toBe(true)
    expect(f.node.outcome(late.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_CLOSED' })
    expect(await events(f.node)).toEqual([])
  })

  it('distinguishes an intrinsically impossible admission policy from a closed timestamp', async () => {
    const f = await fixture({ selectAdmission: () => [], canStillAdmit: () => false })
    const proposal = await f.propose('impossible', 100n)
    await f.node.waitForIdle()
    expect(f.node.isFinal(proposal.txId)).toBe(true)
    expect(f.node.outcome(proposal.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_IMPOSSIBLE' })
    expect((await f.node.watermark())?.cutoffMs).toBeNull()
  })
})

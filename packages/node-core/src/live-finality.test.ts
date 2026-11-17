import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import { ControlStore, MemoryControlStorePersistence } from '@chronolog/control-store/browser'
import {
  bytesToHex, emit, encodeTransactionCore, encodeValidatorAttestation, encodeValidatorHeartbeat,
  equalBytes, generateEd25519KeyPair, program, transactionDigest, utf8, type TransactionCore, type ValidatorAttestation,
} from '@chronolog/protocol'
import { MemoryTransportNetwork, type TransportRecord } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { FeedForkRegistry } from './feed-forks.js'
import { MemoryOperationStore } from './operations.js'
import type { ChronologNodeOptions, ClosedAdmissionRevision } from './types.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(101), membershipRevision = bytes(102), twoVotes = bytes(103), oneVote = bytes(104)

async function fixture(options: { multiplePolicies?: boolean; completePolicySet?: boolean;
  now?: () => number; maxFutureSkewMs?: number } = {}) {
  const identities = await Promise.all(Array.from({ length: 5 }, () => generateEd25519KeyPair()))
  const network = new MemoryTransportNetwork()
  const transports = identities.map((_, index) => network.createNode(`live-finality-${index}`))
  let observer = transports[4]!
  const validatorIds = identities.slice(0, 3).map(item => item.publicKeyBytes)
  const policy = (id: Uint8Array) => ({ kind: 'threshold' as const, policyId: bytesToHex(id), validatorIds,
    threshold: equalBytes(id, oneVote) ? 1 : 2 })
  // Transport retention and node indexing are intentionally independent. This
  // lets a complete feed prefix be present before its subscription is consumed.
  const pauseSubscription = () => { observer.subscribe = (signal) => ({
    [Symbol.asyncIterator]: () => ({ next: () => new Promise<IteratorResult<TransportRecord>>(resolve => {
      if (signal?.aborted) resolve({ done: true, value: undefined })
      else signal?.addEventListener('abort', () => resolve({ done: true, value: undefined }), { once: true })
    }) }),
  }) }
  pauseSubscription()
  const store = new MemoryOperationStore()
  const persistence = new MemoryControlStorePersistence()
  let controlStore = new ControlStore(persistence)
  let materialization = await createEventMaterializationRuntime({ store, namespace: 'live-finality' })
  let feedForkRegistry: FeedForkRegistry | undefined
  const finalPublications: Array<{ length: number; excluded: string[] }> = []
  let revisions = [{ membershipRevision, authorTimeAfterMs: -1n }]
  let closures: readonly ClosedAdmissionRevision[] = []
  const createRuntime = (): ChronologMaterializationRuntime => ({ ...materialization,
    coordinator: { ...materialization.coordinator,
      publishFinal: async length => {
        if (length > (materialization.queries.finalOrderLength ?? 0)) finalPublications.push({ length,
          excluded: (persistence.load()?.candidates ?? []).filter(candidate => candidate.state === 'inadmissible').map(candidate => bytesToHex(candidate.txId)) })
        await materialization.coordinator.publishFinal!(length)
      },
    } })
  let runtime = createRuntime()
  const nodeOptions = (): ChronologNodeOptions => ({ identity: identities[4]!, groupId, membershipRevision, validationPolicy: twoVotes,
    transport: observer, operationStore: store, controlStore, materialization: runtime,
    membershipState: () => ({ membershipRevision: revisions.at(-1)!.membershipRevision, validationPolicy: twoVotes }),
    ...(options.now === undefined ? {} : { clock: { now: options.now } }),
    ...(options.maxFutureSkewMs === undefined ? {} : { live: { maxFutureSkewMs: options.maxFutureSkewMs } }),
    ...(feedForkRegistry === undefined ? {} : { feedForkRegistry }),
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
  let node = new ChronologNode(nodeOptions())
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
  return { get node() { return node }, get control() { return controlStore }, get materialization() { return runtime }, transports, candidate, vote, heartbeat, ingest, retain, finalPublications,
    setRevisions(value: typeof revisions) { revisions = value },
    async reopen(registry?: FeedForkRegistry) {
      const history = await observer.history(), identity = observer.identity
      await node.close()
      observer = network.createNode(identity)
      transports[4] = observer
      pauseSubscription()
      // MemoryTransport has no persistent writer counter. Rebuild its exact
      // local feed before opening the node against the retained state stores.
      for (const record of history.filter(item => item.author === identity).sort((a, b) => a.sequence < b.sequence ? -1 : 1)) {
        expect((await observer.publish(record.payload, { timestampMs: record.receivedAtMs })).id).toBe(record.id)
      }
      for (const record of history) observer.receive(record)
      materialization = await createEventMaterializationRuntime({ store, namespace: 'live-finality' })
      runtime = createRuntime()
      controlStore = new ControlStore(persistence)
      feedForkRegistry = registry
      node = new ChronologNode(nodeOptions())
      await node.start()
    },
    closeRevision(proposals: readonly Uint8Array[], closedThroughMs: bigint, revision: Uint8Array = membershipRevision) {
      closures = [...closures.filter(item => !equalBytes(item.membershipRevision, revision)), { membershipRevision: revision, closedThroughMs, proposalIds: proposals,
        feedPrefixes: transports.slice(0, 3).map(transport => ({ author: transport.identity, throughSequence: heads.get(transport.identity) ?? 0n })),
      }]
    } }
}

describe('live chronological finality', () => {
  it.each(['publication', 'reconciliation', 'finality'] as const)('retains a coherent local view and author clock while %s retries', async stage => {
    const f = await fixture({ now: () => 10, maxFutureSkewMs: 1_000 })
    const local = f.node.changes({ view: 'local' })[Symbol.asyncIterator]()
    const initial = (await local.next()).value!
    const publish = f.materialization.publications.publish.bind(f.materialization.publications)
    const reconcile = f.materialization.publications.reconcile.bind(f.materialization.publications)
    const publishFinal = f.materialization.coordinator.publishFinal!.bind(f.materialization.coordinator)
    const unavailable = () => Promise.reject(new Error('PUBLICATION_RETRY_REQUIRED'))
    if (stage === 'publication') {
      f.materialization.publications.publish = async input => { await publish(input); return unavailable() }
      // Keep a later retry from repairing the clock before it is inspected.
      f.materialization.publications.reconcile = unavailable
    } else if (stage === 'reconciliation') f.materialization.publications.reconcile = unavailable
    else f.materialization.coordinator.publishFinal = unavailable
    try {
      const proposal = await f.candidate('published-local', 50n)
      await f.vote(0, proposal); await f.vote(1, proposal)
      await expect(f.node.waitForIdle()).rejects.toThrow('PUBLICATION_RETRY_REQUIRED')
      const changed = (await local.next()).value!
      const captured = await f.node.readView({ view: 'local' })
      try {
        expect(changed.revision).not.toBe(initial.revision)
        expect(changed.revision).toBe(captured.revision)
        expect(changed.finalRevision).toBe(initial.finalRevision)
        expect(captured.readEvents().transactions.flatMap(item => item.events.map(event => event.payload))).toEqual(['published-local'])
      } finally { captured.release() }
      expect(f.node.finalOrderLength).toBe(0)
      expect(f.node.isFinal(proposal.txId)).toBe(false)
      const dependent = await f.node.publish({ operationId: 'dependent-during-retry', program: program(emit('changes', 'dependent')) })
      expect(dependent.core.authorTimestampMs).toBe(51n)
    } finally {
      f.materialization.publications.publish = publish
      f.materialization.publications.reconcile = reconcile
      f.materialization.coordinator.publishFinal = publishFinal
      await local.return?.()
      await f.node.waitForIdle()
    }
  })

  it('allocates after the applied tail while its publication acknowledgement is still pending', async () => {
    const f = await fixture({ now: () => 10, maxFutureSkewMs: 1_000 })
    const publish = f.materialization.publications.publish.bind(f.materialization.publications)
    let entered!: () => void, release!: () => void, prepared!: () => void
    const blocked = new Promise<void>(resolve => { entered = resolve })
    const resumed = new Promise<void>(resolve => { release = resolve })
    const retained = new Promise<void>(resolve => { prepared = resolve })
    f.materialization.publications.publish = async input => {
      const result = await publish(input)
      entered()
      await resumed
      return result
    }
    const transport = f.transports[4]!, append = transport.publish.bind(transport)
    transport.publish = async (payload, options) => {
      const record = await append(payload, options)
      prepared()
      return record
    }
    const proposal = await f.candidate('visible-before-ack', 50n)
    const progress = f.node.waitForIdle()
    let dependent: ReturnType<ChronologNode['publish']> | undefined
    try {
      await blocked
      expect(f.node.outcome(proposal.txId)).toMatchObject({ outcome: 'accepted', orderKey: { authorTimestampMs: 50n } })
      dependent = f.node.publish({ operationId: 'dependent-before-ack', program: program(emit('changes', 'dependent')) })
      // The exact signed reservation is retained before allowing the older
      // publication to acknowledge or ingestion to acquire the node mutex.
      await retained
    } finally {
      release()
      await progress
      f.materialization.publications.publish = publish
      transport.publish = append
    }
    expect((await dependent).core.authorTimestampMs).toBe(51n)
  })

  it('removes an excluded preview before publishing final rejection or finalizing a later proposal', async () => {
    const f = await fixture(), preview = await f.candidate('preview', 50n), later = await f.candidate('later', 100n)
    await f.vote(0, preview); await f.vote(0, later); await f.vote(1, later)
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect(f.node.candidate(preview.txId)?.state).toBe('provisional')
    expect(f.node.outcome(preview.txId)?.outcome).toBe('accepted')
    const held = await f.node.readView({ view: 'local' }), before = held.readEvents()
    const materialize = f.materialization.coordinator.materialize.bind(f.materialization.coordinator)
    let paused = true
    f.materialization.coordinator.materialize = input => {
      if (paused && !input.some(item => equalBytes(item.txId, preview.txId))) {
        return Promise.reject(new Error('PREVIEW_REMOVAL_TEMPORARILY_UNAVAILABLE'))
      }
      return materialize(input)
    }
    try {
      await f.heartbeat(0); await f.heartbeat(1); await f.heartbeat(2)
      await expect(f.node.waitForIdle()).rejects.toThrow('PREVIEW_REMOVAL_TEMPORARILY_UNAVAILABLE')
      expect(f.node.candidate(preview.txId)?.state).toBe('inadmissible')
      // The control decision cannot relabel the still-applied acceptance final.
      expect(f.node.outcome(preview.txId)?.outcome).toBe('accepted')
      expect(f.node.isFinal(preview.txId)).toBe(false)
      expect(f.node.finalOrderLength).toBe(0)
      const pending = await f.node.readView({ view: 'local' })
      try {
        expect(pending.revision).toBe(held.revision)
        expect(pending.readEvents()).toEqual(before)
      } finally { pending.release() }
      paused = false
      await f.node.waitForIdle()
      expect(f.node.outcome(preview.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_CLOSED' })
      expect(f.node.isFinal(preview.txId)).toBe(true)
      expect(f.node.finalOrderLength).toBe(1)
      expect(f.node.isFinal(later.txId)).toBe(true)
      const final = await f.node.events.read()
      expect(final.transactions.map(item => item.proposalId)).toEqual([new TextDecoder().decode(later.txId)])
      expect(final.transactions[0]!.events[0]).toEqual(before.transactions[1]!.events[0])
      expect(held.readEvents()).toEqual(before)
    } finally { paused = false; held.release() }
  })

  it('promotes provisional selection only after its verified admission proof arrives', async () => {
    const f = await fixture(), proposal = await f.candidate('preview', 50n)
    await f.node.waitForIdle()
    expect(f.node.outcome(proposal.txId)?.outcome).toBe('accepted')
    expect(f.node.finalOrderLength).toBe(0)
    expect((await f.node.status()).admitted).toBe(0)
    await f.vote(0, proposal)
    expect(f.node.candidate(proposal.txId)?.state).toBe('provisional')
    await f.vote(1, proposal)
    expect(f.node.candidate(proposal.txId)?.state).toBe('admissible')
    expect((await f.node.status()).admitted).toBe(1)
    await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    expect((await f.node.events.read()).transactions.map(item => item.proposalId))
      .toEqual([new TextDecoder().decode(proposal.txId)])
  })

  it('removes excluded provisional selection before publishing the remaining final prefix', async () => {
    const f = await fixture(), preview = await f.candidate('preview', 50n), accepted = await f.candidate('accepted', 100n)
    await f.node.waitForIdle()
    expect(f.node.outcome(preview.txId)?.outcome).toBe('accepted')
    await f.vote(0, preview); await f.vote(0, accepted); await f.vote(1, accepted)
    await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.candidate(preview.txId)?.state).toBe('provisional')
    expect((await f.node.liveFinality()).closedThroughMs).toBe(49n)
    expect(f.node.finalOrderLength).toBe(0)

    await f.heartbeat(2); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(1)
    expect(f.node.candidate(preview.txId)?.state).toBe('inadmissible')
    expect(f.node.outcome(preview.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_CLOSED' })
    expect(f.node.isFinal(preview.txId)).toBe(true)
    expect(f.node.orderLength).toBe(1)
    expect(f.node.outcome(accepted.txId)?.orderIndex).toBe(0)
    expect((await f.node.events.read()).transactions.map(item => item.proposalId))
      .toEqual([new TextDecoder().decode(accepted.txId)])
    await f.reopen()
    expect(f.node.candidate(preview.txId)?.state).toBe('inadmissible')
    expect(f.node.finalOrderLength).toBe(1)
  })

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

  it('withdraws an excluded preview before finalizing later admitted work', async () => {
    const f = await fixture(), preview = await f.candidate('preview', 50n), admitted = await f.candidate('admitted', 100n)
    await f.node.waitForIdle()
    expect(f.node.candidate(preview.txId)?.state).toBe('provisional')
    expect(f.node.outcome(preview.txId)?.outcome).toBe('accepted')
    expect(f.node.isFinal(preview.txId)).toBe(false)
    await f.vote(0, admitted); await f.vote(1, admitted)
    await f.heartbeat(0); await f.heartbeat(1); await f.heartbeat(2); await f.node.waitForIdle()
    expect(await f.node.liveFinality()).toMatchObject({ closedThroughMs: 100n })
    expect(f.node.orderLength).toBe(1)
    expect(f.node.outcome(preview.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_CLOSED' })
    expect(f.node.isFinal(preview.txId)).toBe(true)
    expect(f.node.finalOrderLength).toBe(1)
    expect(f.finalPublications.at(-1)).toEqual({ length: 1, excluded: [bytesToHex(preview.txId)] })
    expect((await f.node.events.read()).transactions.map(item => item.proposalId)).toEqual([new TextDecoder().decode(admitted.txId)])
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

  it('waits for indexed revision closure with complete scopes and no heartbeat evidence', async () => {
    const f = await fixture(), a = await f.candidate('excluded', 50n), b = await f.candidate('accepted', 100n)
    const delayed = await f.vote(0, a, false)
    f.retain(delayed)
    await f.vote(0, b); await f.vote(1, b)
    f.closeRevision([a.txId, b.txId], 100n)
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(0)
    expect((await f.node.liveFinality()).closedThroughMs).toBeNull()
    await f.ingest(delayed); await f.node.waitForIdle()
    expect(f.node.candidate(a.txId)?.state).toBe('inadmissible')
    expect(f.node.outcome(a.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ADMISSION_CLOSED' })
    expect(f.node.finalOrderLength).toBe(1)
    expect((await f.node.liveFinality()).closedThroughMs).toBe(100n)
  })

  it('does not credit a discarded fork as an indexed record in the repaired feed', async () => {
    const f = await fixture(), a = await f.candidate('earlier', 50n), b = await f.candidate('later', 100n)
    const winning = await f.vote(0, a, false)
    const fork = new MemoryTransportNetwork().createNode(winning.author)
    const losing = await fork.publish(Uint8Array.of(255))
    await fork.close()
    const registry = new FeedForkRegistry()
    expect(registry.observe(winning)).toBe('accepted')
    expect(registry.observe(losing)).toBe('quarantined')
    registry.applyRepair(registry.createRepairPlan(winning.author, [winning], winning.id))
    await f.reopen(registry)
    f.retain(winning)
    await f.ingest(losing)
    await f.vote(0, b); await f.vote(1, b); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect(f.node.candidate(a.txId)?.state).toBe('provisional')
    expect(f.node.finalOrderLength).toBe(0)
    expect((await f.node.liveFinality()).closedThroughMs).toBeNull()
    await f.ingest(winning); await f.node.waitForIdle()
    expect((await f.node.liveFinality()).closedThroughMs).toBe(49n)
    await f.vote(2, a); await f.node.waitForIdle()
    expect(f.node.finalOrderLength).toBe(2)
    expect(f.node.outcome(a.txId)?.orderIndex).toBe(0)
  })

  it('authors dependent intent after observed final history despite a slow clock and reopen', async () => {
    let now = 10
    const f = await fixture({ now: () => now, maxFutureSkewMs: 1_000 })
    const prerequisite = await f.candidate('prerequisite', 50n)
    await f.vote(0, prerequisite); await f.vote(1, prerequisite); await f.heartbeat(0); await f.heartbeat(1); await f.node.waitForIdle()
    expect((await f.node.events.read()).transactions[0]?.events[0]?.payload).toBe('prerequisite')
    const request = { operationId: 'dependent', program: program(emit('changes', 'dependent')) }
    const dependent = await f.node.publish(request)
    expect(dependent.core.authorTimestampMs).toBe(101n)
    const proposal = { ...dependent, digest: dependent.candidateDigest }
    await f.vote(0, proposal); await f.vote(1, proposal); await f.heartbeat(0, 101n); await f.heartbeat(1, 101n); await f.node.waitForIdle()
    expect((await f.node.events.read()).transactions.flatMap(item => item.events.map(event => event.payload)))
      .toEqual(['prerequisite', 'dependent'])
    now = 1
    await f.reopen()
    expect((await f.node.publish(request)).core).toEqual(dependent.core)
    const later = await f.node.publish({ operationId: 'after-reopen', program: program(emit('changes', 'later')) })
    expect(later.core.authorTimestampMs).toBe(102n)
  })

  it('does not let a merely received future proposal advance the automatic author clock', async () => {
    const f = await fixture({ now: () => 10, maxFutureSkewMs: 100 })
    const future = await f.candidate('unadmitted-future', 1_000_000_000n)
    await f.node.waitForIdle()
    expect(f.node.candidate(future.txId)?.state).toBe('pending_validation')
    const authored = await f.node.publish({ operationId: 'ordinary', program: program(emit('changes', 'ordinary')) })
    expect(authored.core.authorTimestampMs).toBe(10n)
  })

  it('rejects automatic clock jumps beyond policy while preserving exact prepared retries', async () => {
    const f = await fixture({ now: () => 10, maxFutureSkewMs: 100 })
    const request = { operationId: 'original', program: program(emit('changes', 'original')) }
    const original = await f.node.publish(request)
    await f.heartbeat(0, 5_000n); await f.heartbeat(1, 5_000n); await f.node.waitForIdle()
    await expect(f.node.publish({ operationId: 'clock-ahead', program: program(emit('changes', 'new')) })).rejects.toThrow('AUTHOR_CLOCK_AHEAD')
    expect((await f.node.publish(request)).core).toEqual(original.core)
    await f.reopen()
    await expect(f.node.publish({ operationId: 'still-ahead', program: program(emit('changes', 'new')) })).rejects.toThrow('AUTHOR_CLOCK_AHEAD')
    expect((await f.node.publish(request)).core).toEqual(original.core)
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
    // A closure for one revision does not prove that no unlisted revision
    // can still admit. Complete authenticated scopes remain mandatory.
    f.setRevisions([{ membershipRevision, authorTimeAfterMs: -1n },
      { membershipRevision: bytes(122), authorTimeAfterMs: 100n }])
    f.closeRevision([a.txId], 100n)
    await f.node.refreshMembership(); await f.node.waitForIdle()
    expect((await f.node.liveFinality()).closedThroughMs).toBeNull()
    expect(f.node.finalOrderLength).toBe(0)
  })
})

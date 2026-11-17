import { ChronologClient, TransactionHandle } from '@chronolog/client'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { bytesToBase64Url, bytesToHex, emit, encodeTransactionCore, equalBytes, generateEd25519KeyPair, program, transactionDigest, utf8 } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { afterEach, describe, expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { GovernanceEvidencePendingError } from './capability-membership.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture(options: { readonly canWrite?: () => boolean } = {}) {
  const identity = await generateEd25519KeyPair(), groupId = new Uint8Array(32).fill(1), capabilityId = new Uint8Array(32).fill(4)
  const store = new MemoryOperationStore(), clock = { now: 10_000 }
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  const materialization = await createEventMaterializationRuntime({ store, namespace: 'changes' })
  const node = new ChronologNode({ identity, groupId, transport, operationStore: store,
    membershipRevision: new Uint8Array(32).fill(2), validationPolicy: new Uint8Array(32).fill(3),
    materialization,
    clock: { now: () => clock.now }, validator: { capabilityId, cutoffLagMs: 100 },
    membership: {
      canWrite: ({ writerId }) => equalBytes(writerId, identity.publicKeyBytes) && (options.canWrite?.() ?? true),
      canValidate: ({ validatorId, validatorCapability }) => equalBytes(validatorId, identity.publicKeyBytes) && equalBytes(validatorCapability, capabilityId),
      threshold: () => 1,
      watermarkPolicy: () => ({ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }),
      admissionScopes: () => [{ membershipRevision: new Uint8Array(32).fill(2), authorTimeAfterMs: -1n,
        policies: [{ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }] }],
    },
  })
  await node.start()
  const client = new ChronologClient({ groupId: bytesToBase64Url(groupId), transport: new InProcessRpcTransport(new NodeRpcService({ node })) })
  cleanup.push(async () => { await client.close(); await node.close() })
  return { node, client, clock, transport, identity, materialization }
}

async function receiveSignedCandidate(f: Awaited<ReturnType<typeof fixture>>) {
  const core = { groupId: f.node.groupId, membershipRevision: f.node.membershipRevision,
    validationPolicy: f.node.validationPolicy, authorId: f.identity.publicKeyBytes,
    authorTimestampMs: 10_005n, operationId: 'remote-intent', nonce: new Uint8Array(32).fill(9),
    executionManifestDigest: f.node.executionManifestDigest, program: program(emit('chat', 'authenticated remote intent')) }
  const canonical = encodeTransactionCore(core), digest = await transactionDigest(canonical)
  const transactionId = `tx_${bytesToHex(digest)}`
  const record = await f.transport.publish(await encodeSignedEnvelope(f.node.groupId, 'candidate', canonical, f.identity))
  await f.node.ingest(record)
  const handle = new TransactionHandle(f.client, { transactionId, candidateDigest: bytesToBase64Url(digest),
    authorTimestampMs: core.authorTimestampMs.toString(), transactionNonce: bytesToBase64Url(core.nonce),
    executionManifestDigest: bytesToBase64Url(core.executionManifestDigest), durableLocalAppend: true,
    publishedAt: new Date(f.clock.now).toISOString() }, core.operationId)
  return { handle, txId: utf8(transactionId) }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 500; attempt++) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 2))
  }
  throw new Error('Application progress did not arrive')
}

describe('coalesced application view changes', () => {
  it('captures a large published history without copying or decoding untouched entries', async () => {
    const { node, materialization } = await fixture()
    await node.publish({ operationId: 'sample', authorTimestampMs: 10_005n, program: program(emit('chat', 'sample')) })
    await waitFor(() => node.orderLength === 1)
    const captureRead = materialization.queries.captureRead!.bind(materialization.queries)
    const original = captureRead({ view: 'local' }), entry = original.transactionAt(0)!
    original.release()
    let copies = 0
    materialization.queries.captureRead = options => ({ ...captureRead(options), orderLength: 100_000,
      transactionAt(index) {
        if (index < 0 || index >= 100_000) return null
        copies++
        return { ...entry, txId: utf8(`large-history-${index}`), canonicalCandidate: entry.canonicalCandidate.slice() }
      } })
    const held = await node.readView({ view: 'local' })
    try {
      expect(copies).toBe(0)
      const batch = held.readEvents({ limit: 1 })
      expect(batch.transactions[0]?.events[0]?.payload).toBe('sample')
      expect(batch.hasMore).toBe(true)
      expect(copies).toBeLessThanOrEqual(3)
    } finally { held.release() }
  })

  it('captures events, origins and SQL from the applied revision while an earlier admission waits for replay', async () => {
    const { node, materialization } = await fixture()
    // A small SQL snapshot stand-in reads the real event runtime's published
    // order. This exercises node snapshot composition without loading DoltLite.
    const captureRead = materialization.queries.captureRead!.bind(materialization.queries)
    materialization.queries.captureRead = options => {
      const captured = captureRead(options)
      const ids = Array.from({ length: captured.orderLength }, (_, index) =>
        new TextDecoder().decode(materialization.queries.proposalIdAt(index)!))
      return { ...captured, query: () => ({ revision: captured.revision, orderLength: captured.orderLength,
        view: captured.view, finalOrderLength: captured.finalOrderLength,
        columns: [{ name: 'proposal_id' }], rows: ids.map(value => [{ kind: 'text' as const, value }]) }) }
    }
    const later = await node.publish({ operationId: 'later', authorTimestampMs: 10_010n, program: program(emit('chat', 'later')) })
    await waitFor(() => node.orderLength === 1)
    const held = await node.readView({ view: 'local' }), original = held.readEvents().transactions[0]!.events[0]!
    const materialize = materialization.coordinator.materialize.bind(materialization.coordinator)
    let paused = true
    materialization.coordinator.materialize = input => {
      if (paused && input.length > 1) return Promise.reject(new Error('REPLAY_INPUT_TEMPORARILY_UNAVAILABLE'))
      return materialize(input)
    }
    try {
      await node.publish({ operationId: 'earlier', authorTimestampMs: 10_005n, program: program(emit('chat', 'earlier')) })
      await waitFor(() => node.controlStore.orderedTransactionIds().length === 2)
      const pending = await node.readView({ view: 'local' })
      try {
        expect(pending.revision).toBe(held.revision)
        expect(pending.query('SELECT proposal_id FROM applied_proposals').rows).toEqual([[{ kind: 'text', value: later.txIdText }]])
        expect(pending.readEvents().transactions.map(value => value.proposalId)).toEqual([later.txIdText])
        expect(pending.readEvents().transactions[0]!.events[0]).toEqual(original)
      } finally { pending.release() }
      paused = false
      await node.waitForIdle()
      const replayed = await node.readView({ view: 'local' })
      try {
        expect(replayed.revision).not.toBe(held.revision)
        expect(replayed.readEvents().transactions.map(value => value.events[0]!.payload)).toEqual(['earlier', 'later'])
        expect(replayed.readEvents().transactions[1]!.events[0]).toEqual(original)
        expect(held.readEvents().transactions.map(value => value.proposalId)).toEqual([later.txIdText])
        expect(held.query('SELECT proposal_id FROM applied_proposals').rows).toEqual([[{ kind: 'text', value: later.txIdText }]])
      } finally { replayed.release() }
    } finally { paused = false; held.release() }
  })

  it.each(['node', 'client'] as const)('keeps %s final subscribers quiet through provisional replay and catches up a slow local reader', async surface => {
    const { node, client, clock } = await fixture(), source = surface === 'node' ? node : client
    const final = source.changes()[Symbol.asyncIterator](), local = source.changes({ view: 'local' })[Symbol.asyncIterator]()
    const initial = (await final.next()).value!
    expect(initial.view).toBe('final')
    await local.next()
    let finalChanged = false
    const nextFinal = final.next().then(value => { finalChanged = true; return value })
    await node.publish({ operationId: 'later', authorTimestampMs: 10_010n, program: program(emit('chat', { text: 'later' })) })
    await waitFor(() => node.orderLength === 1)
    await node.publish({ operationId: 'earlier', authorTimestampMs: 10_005n, program: program(emit('chat', { text: 'earlier' })) })
    await waitFor(() => node.orderLength === 2)
    const latest = (await local.next()).value!
    const view = await source.readView({ view: 'local' })
    try {
      expect(latest).toEqual({ view: view.view, revision: view.revision, finalRevision: view.finalRevision })
      expect((await view.readEvents()).transactions.map(value => value.events[0]?.payload)).toEqual([{ text: 'earlier' }, { text: 'later' }])
    } finally { await view.release() }
    expect(finalChanged).toBe(false)
    clock.now += 1_000
    await node.publishHeartbeat()
    await waitFor(() => node.finalOrderLength === 2)
    const finalView = await source.readView()
    try {
      expect((await nextFinal).value).toEqual({ view: 'final', revision: finalView.revision, finalRevision: finalView.finalRevision })
      expect(finalView.revision).not.toBe(initial.revision)
    } finally { await finalView.release() }
    await final.return?.(); await local.return?.()
  })

  it.each(['node', 'client'] as const)('releases a quiet pending %s pull when the consumer returns', async surface => {
    const { node, client } = await fixture(), source = surface === 'node' ? node : client
    const iterator = source.changes()[Symbol.asyncIterator]()
    await iterator.next()
    const waiting = iterator.next()
    await iterator.return?.()
    expect(await waiting).toEqual({ done: true, value: undefined })
  })
})

describe('peer authorization outcomes', () => {
  it('keeps a stale applied acceptance provisional until an authorization denial leaves the applied selection', async () => {
    const f = await fixture({ canWrite: () => false }), { handle, txId } = await receiveSignedCandidate(f)
    const outcome = f.materialization.queries.outcome.bind(f.materialization.queries)
    const candidate = f.node.candidate(txId)!
    let selected = true
    f.materialization.queries.outcome = id => selected && equalBytes(id, txId)
      ? { txId, orderKey: candidate.orderKey, orderIndex: 0, outcome: 'accepted', rejectionCode: null, failingStatementIndex: null }
      : outcome(id)
    try {
      expect(f.node.outcome(txId)?.outcome).toBe('accepted')
      expect(f.node.isFinal(txId)).toBe(false)
      await expect(f.client.getTransactionOutcome(handle.transactionId)).resolves.toMatchObject({ final: false, outcome: { type: 'accepted' } })
      f.clock.now += 1_000
      await f.node.publishHeartbeat()
      await f.node.waitForIdle()
      expect(f.node.isFinal(txId)).toBe(false)
      selected = false
      await expect(f.client.getTransactionOutcome(handle.transactionId)).resolves.toMatchObject({ final: true,
        outcome: { type: 'rejected', rejection: { code: 'ADMISSION_CLOSED' } } })
    } finally { f.materialization.queries.outcome = outcome }
  })

  it('returns final rejection when closed admission excludes a denied signed proposal', async () => {
    const f = await fixture({ canWrite: () => false }), { handle, txId } = await receiveSignedCandidate(f)
    expect(f.node.candidate(txId)?.state).toBe('pending_validation')
    expect(f.node.isFinal(txId)).toBe(false)
    f.clock.now += 1_000
    await f.node.publishHeartbeat()
    await f.node.waitForIdle()
    expect(f.node.candidate(txId)?.state).toBe('excluded')
    expect(f.node.isFinal(txId)).toBe(true)
    await expect(handle.final()).resolves.toMatchObject({ final: true,
      outcome: { type: 'rejected', rejection: { code: 'ADMISSION_CLOSED' } } })
    expect((await f.node.events.read()).transactions).toEqual([])
  })

  it.each([true, false])('keeps missing governance retryable until authorization becomes %s', async allowed => {
    let known = false
    const f = await fixture({ canWrite: () => {
      if (!known) throw new GovernanceEvidencePendingError()
      return allowed
    } })
    const { handle, txId } = await receiveSignedCandidate(f)
    expect(f.node.candidate(txId)?.state).toBe('pending_validation')
    expect(f.node.outcome(txId)).toBeNull()
    expect(f.node.isFinal(txId)).toBe(false)
    known = true
    await f.node.refreshMembership()
    if (allowed) {
      await waitFor(() => f.node.orderLength === 1)
      f.clock.now += 1_000
      await f.node.publishHeartbeat()
      await expect(handle.final()).resolves.toMatchObject({ final: true, outcome: { type: 'accepted' } })
    } else {
      f.clock.now += 1_000
      await f.node.publishHeartbeat()
      await f.node.waitForIdle()
      await expect(handle.final()).resolves.toMatchObject({ final: true,
        outcome: { type: 'rejected', rejection: { code: 'ADMISSION_CLOSED' } } })
    }
  })
})

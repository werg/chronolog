import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, emit, encodeTransactionCore, generateEd25519KeyPair, program, transactionDigest, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { EpochCipherRing } from './cipher.js'
import { createFinalityClosureRecord, controlCommitmentForClosure } from './finality.js'
import {
  createPrefixAuthority, decodeOrderingEvidence, encodeOrderingEvidence, ReferenceRecordLog, SignedInclusionFinalityProvider,
} from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => {
  try { for (const close of cleanup.splice(0).reverse()) await close() }
  finally { vi.useRealTimers() }
})
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(71), membershipRevision = bytes(72), validationPolicy = bytes(73)
const emptyCounts = () => ({ materialize: 0, changed: 0, publish: 0, reconcile: 0, publishFinal: 0, proofs: 0, writes: 0 })
type FixtureMode = 'available' | 'missing-body' | 'missing-key' | 'failed-reconcile' | 'failed-retention' | 'failed-final-publication'

async function fixture(mode: FixtureMode, clock?: { readonly now: number; readonly maxFutureSkewMs: number }) {
  const identity = await generateEd25519KeyPair(), finalityIdentity = await generateEd25519KeyPair()
  const store = new MemoryOperationStore(), bodies = new Map<string, Uint8Array | null>(), counts = emptyCounts()
  const put = store.put.bind(store)
  store.put = async (key, value) => { counts.writes++; await put(key, value) }
  const underlying = await createEventMaterializationRuntime({ store, namespace: mode })
  let unavailable = mode !== 'available'
  const materialization: ChronologMaterializationRuntime = {
    ...underlying,
    coordinator: {
      async materialize(input) {
        counts.materialize++
        const result = await underlying.coordinator.materialize(input)
        if (result !== null) counts.changed++
        return result
      },
      async publishFinal(length) {
        counts.publishFinal++; await underlying.coordinator.publishFinal!(length)
        if (unavailable && mode === 'failed-final-publication' && length > 0) throw new Error('FINAL_PUBLICATION_REPLY_LOST')
      },
    },
    publications: {
      async publish(input) { counts.publish++; return underlying.publications.publish(input) },
      async reconcile(input) {
        counts.reconcile++
        if (unavailable && mode === 'failed-reconcile' && input.targetOrderLength > 0) throw new Error('RECONCILIATION_FAILED')
        return underlying.publications.reconcile(input)
      },
    },
  }
  const configuration = { kind: 'coordinated' as const, groupId, genesisDigest: bytes(74),
    executionManifestDigest: underlying.queries.executionManifestDigest,
    historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: finalityIdentity.publicKeyBytes }
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const signer = createPrefixAuthority({ configuration, identity: finalityIdentity, readHead: () => log.head() })
  const policy = await SignedInclusionFinalityProvider.open(configuration, store)
  const ingest = policy.ingestEvidence.bind(policy)
  policy.ingestEvidence = async value => { counts.proofs++; return ingest(value) }
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  const retain = transport.putEvidence.bind(transport)
  transport.putEvidence = async value => {
    if (unavailable && mode === 'failed-retention' && decodeOrderingEvidence(value).kind === 'prefix-certificate') {
      throw new Error('RETENTION_FAILED')
    }
    return retain(value)
  }
  transport.getPayload = async hash => bodies.get(hash)?.slice() ?? null
  // Drive proof delivery explicitly so background subscription echoes cannot
  // obscure the waitForIdle barrier. Retention and its history remain real.
  transport.subscribeEvidence = async function* () {}
  const ring = new EpochCipherRing(), writerRing = new EpochCipherRing()
  writerRing.install(bytes(91), 0n, true)
  const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store, transport,
    historyPolicy: { kind: 'coordinated', policy },
    ...(clock === undefined ? {} : { clock: { now: () => clock.now }, live: { maxFutureSkewMs: clock.maxFutureSkewMs } }),
    // This fixture has one issued epoch; local key availability is separate.
    ...(mode === 'missing-key' ? { encryptionEpochCanAuthorize: () => true, encryptionEpochStatusAt: () => 'active' as const } : {}),
    materialization, membership: { canWrite: () => true, canValidate: () => false, threshold: () => 1 },
    ...(mode === 'missing-key' ? { envelopeCipher: ring } : {}),
  })
  cleanup.push(() => node.close())
  await node.start()
  const core = { groupId, membershipRevision, validationPolicy, authorId: identity.publicKeyBytes,
    authorTimestampMs: 10n, operationId: mode, nonce: bytes(75),
    executionManifestDigest: configuration.executionManifestDigest, program: program(emit('events', mode)) }
  const canonical = encodeTransactionCore(core), txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
  const envelope = await encodeSignedEnvelope(groupId, 'candidate', canonical, identity, mode === 'missing-key' ? writerRing : undefined)
  const descriptor = await createLedgerRecord(envelope)
  bodies.set(descriptor.record.payloadHash, mode === 'missing-body' ? null : envelope)
  await log.append(descriptor.recordBytes)
  await log.append(await createFinalityClosureRecord({ configuration, identity: finalityIdentity,
    includedHead: await log.head(), closedThroughMs: 20n,
    control: await controlCommitmentForClosure(configuration, await log.read(), 20n) }))
  const proof = encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await signer.certify() })
  for (const entry of await log.read()) await node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
  const state = async () => ({ revision: node.materializedRevision, finalRevision: node.finalRevision,
    nodeRevision: node.revision, finalOrderLength: node.finalOrderLength, pending: (await node.status()).materializationPending,
    checkpoint: policy.snapshot().checkpointId, appliedThrough: node.finalThrough, closedReceiptThrough: policy.snapshot().closedReceiptThrough })
  return { node, transport, policy, proof, counts, state, txId,
    reset() { Object.assign(counts, emptyCounts()) },
    restore() { unavailable = false; bodies.set(descriptor.record.payloadHash, envelope); ring.install(bytes(91), 0n, true) } }
}

describe('application reconciliation after finality evidence', () => {
  it.each([30, 5])('preserves verified closed time after transport retention fails with %d ms author skew', async maxFutureSkewMs => {
    const f = await fixture('failed-retention', { now: 10, maxFutureSkewMs })
    await expect(f.node.ingestFinalityEvidence(f.proof)).rejects.toThrow('RETENTION_FAILED')
    expect(f.policy.snapshot().closedThroughMs).toBe(20n)
    expect(await f.state()).toMatchObject({ finalOrderLength: 0, appliedThrough: 0 })
    const input = { operationId: 'after-retained-proof', program: program(emit('events', 'new intent')) }
    if (maxFutureSkewMs < 11) {
      await expect(f.node.publish(input)).rejects.toThrow('AUTHOR_CLOCK_AHEAD')
      expect(await f.node.operation(input.operationId)).toBeNull()
    } else {
      const published = await f.node.publish(input)
      expect(published.core.authorTimestampMs).toBe(21n)
      expect((await f.node.publish(input)).core).toEqual(published.core)
    }
  })

  it.each(['failed-reconcile', 'failed-final-publication'] as const)('keeps published application views coherent while %s acknowledgements retry', async mode => {
    const f = await fixture(mode)
    const local = f.node.changes({ view: 'local' })[Symbol.asyncIterator](), final = f.node.changes()[Symbol.asyncIterator]()
    await local.next()
    const initialFinal = (await final.next()).value!
    const localPending = local.next(), finalPending = final.next()
    // Verified retained evidence is accepted even when an application reply
    // fails. waitForIdle remains the explicit application recovery barrier.
    await f.node.ingestFinalityEvidence(f.proof)
    await expect(f.node.waitForIdle()).rejects.toThrow(
      mode === 'failed-reconcile' ? 'RECONCILIATION_FAILED' : 'FINAL_PUBLICATION_REPLY_LOST')
    const localView = await f.node.readView({ view: 'local' }), finalView = await f.node.readView()
    try {
      const applied = localView.readEvents().transactions
      expect((await f.node.events.read()).transactions).toEqual(finalView.readEvents().transactions)
      expect(applied).toHaveLength(1)
      expect(applied[0]!.proposalId).toBe(new TextDecoder().decode(f.txId))
      expect(applied[0]!.events[0]!.origin.operationId).toBe(mode)
      expect(f.node.outcome(f.txId)).toMatchObject({ outcome: 'accepted', orderIndex: 0 })
      expect(f.node.isFinal(f.txId)).toBe(mode === 'failed-final-publication')
      expect((await localPending).value).toEqual({ view: 'local', revision: localView.revision, finalRevision: finalView.revision })
      if (mode === 'failed-reconcile') {
        expect(finalView.revision).toBe(initialFinal.revision)
        expect(finalView.readEvents().transactions).toEqual([])
      } else {
        // The final materializer commit succeeded before its acknowledgement
        // failed. Its actual immutable view is already readable and final.
        expect(finalView.revision).not.toBe(initialFinal.revision)
        expect(finalView.readEvents().transactions).toEqual(applied)
      }
      const localFinalityChange = mode === 'failed-reconcile' ? local.next() : undefined
      f.restore(); await f.node.waitForIdle()
      const settledLocal = await f.node.readView({ view: 'local' }), settledFinal = await f.node.readView()
      try {
        expect(settledLocal.revision).toBe(localView.revision)
        expect(settledLocal.readEvents().transactions).toEqual(applied)
        expect(settledFinal.readEvents().transactions).toEqual(applied)
        expect((await finalPending).value).toEqual({ view: 'final', revision: settledFinal.revision, finalRevision: settledFinal.revision })
        if (localFinalityChange !== undefined) expect((await localFinalityChange).value)
          .toEqual({ view: 'local', revision: settledLocal.revision, finalRevision: settledFinal.revision })
        expect(f.node.isFinal(f.txId)).toBe(true)
        expect(localView.readEvents().transactions).toEqual(applied)
        expect(finalView.readEvents().transactions).toHaveLength(mode === 'failed-reconcile' ? 0 : 1)
      } finally { settledLocal.release(); settledFinal.release() }
    } finally {
      localView.release(); finalView.release(); await local.return?.(); await final.return?.()
    }
  })

  it('verifies repeated retained proofs without redoing an applied materialization', async () => {
    const f = await fixture('available')
    await f.node.ingestFinalityEvidence(f.proof)
    await f.node.waitForIdle()
    const before = await f.state(), evidence = (await f.transport.evidenceHistory()).length
    expect(before).toMatchObject({ finalOrderLength: 1, pending: false })
    f.reset()
    for (let count = 0; count < 3; count++) await f.node.waitForIdle()
    expect(f.counts).toEqual({ ...emptyCounts(), proofs: evidence * 3 })
    expect(await f.state()).toEqual(before)
  })

  it.each(['missing-body', 'missing-key', 'failed-reconcile'] as const)('retries %s from identical retained evidence', async mode => {
    // Drive this exact retry through retained evidence. A scheduled retry must
    // not enter materialize while status is read and straddle the counter reset.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const f = await fixture(mode)
    const message = { 'missing-body': 'LEDGER_PAYLOAD_UNAVAILABLE', 'missing-key': 'WIRE_ENCRYPTION_EPOCH_UNAVAILABLE',
      'failed-reconcile': 'RECONCILIATION_FAILED' }[mode]
    await f.node.ingestFinalityEvidence(f.proof)
    await expect(f.node.waitForIdle()).rejects.toThrow(message)
    const before = await f.state()
    expect(before).toMatchObject({ pending: true, finalOrderLength: 0, appliedThrough: 0, closedReceiptThrough: 1 })
    f.restore(); f.reset()
    await f.node.waitForIdle()
    expect(f.counts).toMatchObject({ materialize: 1, reconcile: 1, publishFinal: 1 })
    expect(await f.state()).toMatchObject({ checkpoint: before.checkpoint, pending: false, finalOrderLength: 1, appliedThrough: 1 })
    expect(f.node.isFinal(f.txId)).toBe(true)
    expect(f.node.outcome(f.txId)?.outcome).toBe('accepted')
  })

  it('applies a verified frontier after interrupted transport retention even when no materialization was pending', async () => {
    const f = await fixture('failed-retention')
    await expect(f.node.ingestFinalityEvidence(f.proof)).rejects.toThrow('RETENTION_FAILED')
    const before = await f.state()
    expect(before).toMatchObject({ pending: false, finalOrderLength: 0, appliedThrough: 0, closedReceiptThrough: 1 })
    f.restore(); f.reset()
    await f.node.ingestFinalityEvidence(f.proof)
    await f.node.waitForIdle()
    expect(f.counts).toMatchObject({ materialize: 1, reconcile: 1, publishFinal: 1 })
    expect(await f.state()).toMatchObject({ checkpoint: before.checkpoint, pending: false, finalOrderLength: 1, appliedThrough: 1 })
    expect(f.node.isFinal(f.txId)).toBe(true)
    expect(f.node.outcome(f.txId)?.outcome).toBe('accepted')
    expect((await f.transport.evidenceHistory()).some(item => item.bytes.every((value, index) => f.proof[index] === value) &&
      item.bytes.length === f.proof.length)).toBe(true)
  })
})

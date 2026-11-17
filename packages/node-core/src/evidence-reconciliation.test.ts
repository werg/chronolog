import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, emit, encodeTransactionCore, generateEd25519KeyPair, program, transactionDigest, utf8,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

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
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)
const groupId = bytes(71), membershipRevision = bytes(72), validationPolicy = bytes(73)
const emptyCounts = () => ({ materialize: 0, changed: 0, publish: 0, reconcile: 0, publishFinal: 0, proofs: 0, writes: 0 })
type FixtureMode = 'available' | 'missing-body' | 'missing-key' | 'failed-reconcile' | 'failed-retention' | 'failed-final-publication'

async function fixture(mode: FixtureMode) {
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
  const retain = transport.putEvidenceBatch.bind(transport)
  transport.putEvidenceBatch = async values => {
    if (unavailable && mode === 'failed-retention' && values.some(value => decodeOrderingEvidence(value).kind === 'prefix-certificate')) {
      throw new Error('RETENTION_FAILED')
    }
    return retain(values)
  }
  transport.getPayload = async hash => bodies.get(hash)?.slice() ?? null
  // Drive proof delivery explicitly so background subscription echoes cannot
  // obscure the waitForIdle barrier. Retention and its history remain real.
  transport.subscribeEvidenceBatches = async function* () {}
  const ring = new EpochCipherRing(), writerRing = new EpochCipherRing()
  writerRing.install(bytes(91), 0n, true)
  const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store, transport,
    historyPolicy: { kind: 'coordinated', policy,
      // This fixture has one issued epoch; local key availability is separate.
      ...(mode === 'missing-key' ? { hasEncryptionEpoch: () => true, encryptionEpochStatusAt: () => 'active' as const } : {}) },
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
  it.each(['failed-reconcile', 'failed-final-publication'] as const)('does not label an unacknowledged application snapshot after %s', async mode => {
    const f = await fixture(mode)
    const local = f.node.changes({ view: 'local' })[Symbol.asyncIterator](), final = f.node.changes()[Symbol.asyncIterator]()
    await local.next()
    const initialFinal = (await final.next()).value!
    const localPending = local.next(), finalPending = final.next()
    await expect(f.node.ingestFinalityEvidence(f.proof)).rejects.toThrow(
      mode === 'failed-reconcile' ? 'RECONCILIATION_FAILED' : 'FINAL_PUBLICATION_REPLY_LOST')
    await expect(f.node.readView({ view: 'local' })).rejects.toThrow('MATERIALIZER_VIEW_NOT_RECONCILED')
    if (mode === 'failed-final-publication') {
      await expect(f.node.readView()).rejects.toThrow('MATERIALIZER_VIEW_NOT_RECONCILED')
      await expect(f.node.events.read()).rejects.toThrow('MATERIALIZER_VIEW_NOT_RECONCILED')
    } else {
      // A local publication failure need not hide a genuinely unchanged final view.
      const unchanged = await f.node.readView()
      expect(unchanged.revision).toBe(initialFinal.revision)
      expect(unchanged.readEvents().transactions).toEqual([])
      unchanged.release()
    }
    f.restore(); await f.node.waitForIdle()
    const localView = await f.node.readView({ view: 'local' }), finalView = await f.node.readView()
    expect((await localPending).value).toEqual({ view: 'local', revision: localView.revision, finalRevision: finalView.revision })
    expect((await finalPending).value).toEqual({ view: 'final', revision: finalView.revision, finalRevision: finalView.revision })
    expect(localView.readEvents().transactions).toHaveLength(1)
    expect(finalView.readEvents().transactions).toHaveLength(1)
    localView.release(); finalView.release(); await local.return?.(); await final.return?.()
  })

  it('verifies repeated retained proofs without redoing an applied materialization', async () => {
    const f = await fixture('available')
    await f.node.ingestFinalityEvidence(f.proof)
    await f.node.waitForIdle()
    const before = await f.state(), evidence = (await retainedEvidence(f.transport)).length
    expect(before).toMatchObject({ finalOrderLength: 1, pending: false })
    f.reset()
    for (let count = 0; count < 3; count++) await f.node.waitForIdle()
    expect(f.counts).toEqual({ ...emptyCounts(), proofs: evidence * 3 })
    expect(await f.state()).toEqual(before)
  })

  it.each(['missing-body', 'missing-key', 'failed-reconcile'] as const)('retries %s from identical retained evidence', async mode => {
    const f = await fixture(mode)
    const message = { 'missing-body': 'LEDGER_PAYLOAD_UNAVAILABLE', 'missing-key': 'WIRE_ENCRYPTION_EPOCH_UNAVAILABLE',
      'failed-reconcile': 'RECONCILIATION_FAILED' }[mode]
    await expect(f.node.ingestFinalityEvidence(f.proof)).rejects.toThrow(message)
    const before = await f.state()
    expect(before).toMatchObject({ pending: true, finalOrderLength: 0, appliedThrough: 0, closedReceiptThrough: 1 })
    f.restore(); f.reset()
    await f.node.waitForIdle()
    expect(f.counts).toMatchObject({ materialize: 1, reconcile: 1, publishFinal: 1 })
    expect(await f.state()).toMatchObject({ checkpoint: before.checkpoint, pending: false, finalOrderLength: 1, appliedThrough: 1 })
    expect(f.node.isFinal(f.txId)).toBe(true)
    expect(f.node.outcome(f.txId)?.outcome).toBe('accepted')
  })

  it('keeps a fully verified shared batch retryable after a derived-view reconciliation failure', async () => {
    const f = await fixture('failed-reconcile')
    await f.transport.putEvidenceBatch([f.proof])
    await expect(f.node.waitForIdle()).rejects.toThrow('RECONCILIATION_FAILED')
    expect((await f.node.status()).lastError).toBe('RECONCILIATION_FAILED')
    expect(f.policy.snapshot().closedReceiptThrough).toBe(1)
    f.restore()
    await f.node.waitForIdle()
    expect(f.node.isFinal(f.txId)).toBe(true)
    expect(f.node.outcome(f.txId)?.outcome).toBe('accepted')
    expect((await f.node.status()).lastError).toBeUndefined()
  })

  it('does not advance a verified frontier before transport retention succeeds', async () => {
    const f = await fixture('failed-retention')
    const before = await f.state()
    await expect(f.node.ingestFinalityEvidence(f.proof)).rejects.toThrow('RETENTION_FAILED')
    expect(await f.state()).toEqual(before)
    expect(before).toMatchObject({ pending: false, finalOrderLength: 0, appliedThrough: 0, closedReceiptThrough: 0 })
    f.restore(); f.reset()
    await f.node.ingestFinalityEvidence(f.proof)
    await f.node.waitForIdle()
    expect(f.counts).toMatchObject({ materialize: 1, reconcile: 1, publishFinal: 1 })
    expect(await f.state()).toMatchObject({ pending: false, finalOrderLength: 1, appliedThrough: 1, closedReceiptThrough: 1 })
    expect((await f.state()).checkpoint).not.toBe(before.checkpoint)
    expect(f.node.isFinal(f.txId)).toBe(true)
    expect(f.node.outcome(f.txId)?.outcome).toBe('accepted')
    expect((await retainedEvidence(f.transport)).some(item => item.bytes.every((value, index) => f.proof[index] === value) &&
      item.bytes.length === f.proof.length)).toBe(true)
  })
})

async function retainedEvidence(transport: PortableFeedTransport) {
  const evidence = []
  for await (const batch of transport.evidenceHistory()) evidence.push(...batch)
  return evidence
}

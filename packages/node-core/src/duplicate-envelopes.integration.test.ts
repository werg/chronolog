import { controlCommitmentForClosure } from './finality.js'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import {
  bytesToHex, emit, encodeCanonicalCbor, encodeTransactionCore, equalBytes, generateEd25519KeyPair,
  program, transactionDigest, utf8, type TransactionCore,
} from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { EpochCipherRing } from './cipher.js'
import { createFinalityClosureRecord } from './finality.js'
import {
  createPrefixAuthority, ReferenceRecordLog, SignedInclusionFinalityProvider,
  type CoordinatedHistoryConfiguration, type PrefixCertificate,
} from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)

async function fixture(futureAdmissionWindowMs = 31_000) {
  const identity = await generateEd25519KeyPair(), authorityIdentity = await generateEd25519KeyPair()
  const runtime = await createEventMaterializationRuntime({ store: new MemoryOperationStore(), namespace: 'descriptor' })
  const configuration: CoordinatedHistoryConfiguration = {
    kind: 'coordinated', groupId: bytes(80), genesisDigest: bytes(81),
    executionManifestDigest: runtime.queries.executionManifestDigest,
    historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: authorityIdentity.publicKeyBytes,
  }
  await runtime.close()
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
  const bodies = new Map<string, Uint8Array>()
  const cipher = new EpochCipherRing()
  cipher.install(bytes(82), 0n)
  cipher.install(bytes(83), 1n, true)
  const open = async (store = new MemoryOperationStore()) => {
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    transport.getPayload = async hash => bodies.get(hash)?.slice() ?? null
    const node = new ChronologNode({ identity, groupId: configuration.groupId, membershipRevision: bytes(84),
      validationPolicy: bytes(85), transport, operationStore: store, envelopeCipher: cipher,
      materialization: await createEventMaterializationRuntime({ store, namespace: 'duplicate-envelopes' }),
      membership: { canWrite: () => true, canValidate: () => false, threshold: () => 1 },
      historyPolicy: { kind: 'coordinated', policy: await SignedInclusionFinalityProvider.open(configuration, store), futureAdmissionWindowMs,
      },
      // The fixture isolates envelope selection after the two keys have been
      // issued; governance activation itself is covered by the epoch suite.
      encryptionEpochIssuedAt: (_closedThroughMs, epoch) => epoch !== null && [0n, 1n].some(value => equalBytes(epoch, encodeCanonicalCbor(value))),
      encryptionEpochStatusAt: (timestamp, epoch) => epoch !== null &&
        equalBytes(epoch, encodeCanonicalCbor(timestamp > 100n ? 1n : 0n)) ? 'active' : 'closed',
    })
    cleanup.push(() => node.close())
    await node.start()
    return { node, store }
  }
  const include = async (envelope: Uint8Array) => {
    const descriptor = await createLedgerRecord(envelope)
    bodies.set(descriptor.record.payloadHash, envelope.slice())
    const entry = await log.append(descriptor.recordBytes)
    return { entry, hash: descriptor.record.payloadHash }
  }
  const closeThrough = async (closedThroughMs: bigint) => {
    await log.append(await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
      includedHead: await log.head(), closedThroughMs,
      control: await controlCommitmentForClosure(configuration, await log.read(), closedThroughMs) }))
    return authority.certify()
  }
  const deliver = async (peer: Awaited<ReturnType<typeof open>>, certificate: PrefixCertificate) => {
    for (const entry of (await log.read()).slice(0, certificate.position)) {
      await peer.node.ingestOrderingEvidence({ kind: 'ordered-entry', entry })
    }
    await peer.node.ingestOrderingEvidence({ kind: 'prefix-certificate', certificate })
    await peer.node.waitForIdle()
  }
  const proposal = async (timestamp: bigint) => {
    const core: TransactionCore = { groupId: configuration.groupId, membershipRevision: bytes(84), validationPolicy: bytes(85),
      authorId: identity.publicKeyBytes, authorTimestampMs: timestamp, operationId: 'same-signed-operation', nonce: bytes(86),
      executionManifestDigest: configuration.executionManifestDigest, program: program(emit('events', 'exactly one event')) }
    const canonical = encodeTransactionCore(core), txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    const stale = await encodeSignedEnvelope(configuration.groupId, 'candidate', canonical, identity, cipher.resolve(encodeCanonicalCbor(0n)))
    const valid = await encodeSignedEnvelope(configuration.groupId, 'candidate', canonical, identity, cipher.resolve(encodeCanonicalCbor(1n)))
    return { txId, stale, valid }
  }
  return { open, include, closeThrough, deliver, proposal, bodies }
}

async function expectAccepted(node: ChronologNode, txId: Uint8Array) {
  expect(node.outcome(txId)?.outcome).toBe('accepted')
  expect(node.isFinal(txId)).toBe(true)
  expect((await node.events.read()).transactions).toHaveLength(1)
}

describe('deterministic admission of multiple envelopes for one signed proposal', () => {
  it.each([false, true])('prefers a valid wrapping within the first decision batch, reversed=%s', async reversed => {
    const f = await fixture(), live = await f.open()
    await f.deliver(live, await f.closeThrough(100n))
    const proposal = await f.proposal(150n)
    for (const envelope of reversed ? [proposal.valid, proposal.stale] : [proposal.stale, proposal.valid]) await f.include(envelope)
    const certificate = await f.closeThrough(200n)
    await f.deliver(live, certificate)
    await expectAccepted(live.node, proposal.txId)
    const cold = await f.open()
    await f.deliver(cold, certificate)
    await expectAccepted(cold.node, proposal.txId)
    await live.node.close()
    const restarted = await f.open(live.store)
    await expectAccepted(restarted.node, proposal.txId)
  })

  it.each([false, true])('waits for the first closure reaching author time across inclusion batches, reversed=%s', async reversed => {
    const f = await fixture(), live = await f.open()
    await f.deliver(live, await f.closeThrough(100n))
    const proposal = await f.proposal(250n)
    await f.include(reversed ? proposal.valid : proposal.stale)
    await f.deliver(live, await f.closeThrough(200n))
    if (reversed) expect(live.node.outcome(proposal.txId)?.outcome).toBe('accepted')
    else expect(live.node.outcome(proposal.txId)).toBeNull()
    expect(live.node.isFinal(proposal.txId)).toBe(false)
    await f.include(reversed ? proposal.stale : proposal.valid)
    const certificate = await f.closeThrough(300n)
    await f.deliver(live, certificate)
    await expectAccepted(live.node, proposal.txId)
    const cold = await f.open()
    await f.deliver(cold, certificate)
    await expectAccepted(cold.node, proposal.txId)
  })

  it('preserves an earlier final rejection when a valid wrapping arrives in a later decision batch', async () => {
    const f = await fixture(), live = await f.open()
    await f.deliver(live, await f.closeThrough(100n))
    const proposal = await f.proposal(150n)
    await f.include(proposal.stale)
    await f.deliver(live, await f.closeThrough(200n))
    expect(live.node.outcome(proposal.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' })
    await f.include(proposal.valid)
    const certificate = await f.closeThrough(300n)
    await f.deliver(live, certificate)
    const cold = await f.open()
    await f.deliver(cold, certificate)
    for (const peer of [live, cold]) {
      expect(peer.node.outcome(proposal.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'ENCRYPTION_EPOCH_CLOSED' })
      expect(peer.node.isFinal(proposal.txId)).toBe(true)
      expect((await peer.node.events.read()).transactions).toHaveLength(0)
    }
  })

  it('waits for missing alternatives before choosing an envelope in the decision batch', async () => {
    const f = await fixture(), live = await f.open()
    await f.deliver(live, await f.closeThrough(100n))
    const proposal = await f.proposal(150n)
    await f.include(proposal.stale)
    const valid = await f.include(proposal.valid)
    f.bodies.delete(valid.hash)
    const certificate = await f.closeThrough(200n)
    await expect(f.deliver(live, certificate)).rejects.toThrow('LEDGER_PAYLOAD_UNAVAILABLE')
    expect(live.node.isFinal(proposal.txId)).toBe(false)
    expect(live.node.outcome(proposal.txId)).toBeNull()
    f.bodies.set(valid.hash, proposal.valid)
    await f.deliver(live, certificate)
    await expectAccepted(live.node, proposal.txId)
  })

  it('keeps the first excessive-future rejection when a later wrapping enters the allowed window', async () => {
    const f = await fixture(20), live = await f.open()
    await f.deliver(live, await f.closeThrough(100n))
    const proposal = await f.proposal(250n)
    await f.include(proposal.stale)
    await f.deliver(live, await f.closeThrough(200n))
    expect(live.node.outcome(proposal.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_FUTURE' })
    expect(live.node.isFinal(proposal.txId)).toBe(true)
    await f.include(proposal.valid)
    await f.deliver(live, await f.closeThrough(240n))
    const certificate = await f.closeThrough(300n)
    await f.deliver(live, certificate)
    const cold = await f.open()
    await f.deliver(cold, certificate)
    await live.node.close()
    const restarted = await f.open(live.store)
    for (const peer of [cold, restarted]) {
      expect(peer.node.outcome(proposal.txId)).toMatchObject({ outcome: 'rejected', rejectionCode: 'FINALITY_TIMESTAMP_FUTURE' })
      expect(peer.node.isFinal(proposal.txId)).toBe(true)
      expect((await peer.node.events.read()).transactions).toHaveLength(0)
    }
  })
})

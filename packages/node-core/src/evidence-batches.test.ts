import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'
import { bytesToHex, emit, encodeTransactionCore, generateEd25519KeyPair, program, transactionDigest, utf8 } from '@chronolog/protocol'
import { DurableFeedStore, feedIdFromPublicKey, MAX_EVIDENCE_BATCH_SIZE, PortableFeedTransport, webFeedCrypto, webFeedSigner, type ChronologTransport } from '@chronolog/records'
import { afterEach, describe, expect, it } from 'vitest'

import { controlCommitmentForClosure, createFinalityClosureRecord } from './finality.js'
import { createPrefixAuthority, encodeOrderingEvidence, ReferenceRecordLog, SignedInclusionFinalityProvider } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (value: number) => new Uint8Array(32).fill(value)

class ReplyLossStore extends MemoryOperationStore {
  failure: { readonly prefix: string; remaining: number } | undefined

  override async put(key: string, value: Uint8Array): Promise<void> {
    await super.put(key, value)
    if (this.failure !== undefined && key.startsWith(this.failure.prefix) && --this.failure.remaining === 0) {
      this.failure = undefined
      throw new Error('BATCH_COMMIT_REPLY_LOST')
    }
  }
}

/** Signed historical closures exercise real verification and durable application publication. */
async function history(count = 12) {
  const identity = await generateEd25519KeyPair(), authorityIdentity = await generateEd25519KeyPair()
  const groupId = bytes(111), membershipRevision = bytes(112), validationPolicy = bytes(113)
  const manifest = await createEventMaterializationRuntime({ store: new MemoryOperationStore(), namespace: 'manifest' })
  const configuration = { kind: 'coordinated' as const, groupId, genesisDigest: bytes(114),
    executionManifestDigest: manifest.queries.executionManifestDigest,
    historyId: 'h_abcdef0123456789abcdef0123456789', authorityPublicKey: authorityIdentity.publicKeyBytes }
  await manifest.close()
  const log = await ReferenceRecordLog.open(configuration.historyId, new MemoryOperationStore())
  const authority = createPrefixAuthority({ configuration, identity: authorityIdentity, readHead: () => log.head() })
  const proofs: Uint8Array[] = [], transactionIds: Uint8Array[] = [], bodies = new Map<string, Uint8Array>()
  for (let index = 0; index < count; index++) {
    const timestamp = BigInt(index * 100 + 10)
    const canonical = encodeTransactionCore({ groupId, membershipRevision, validationPolicy,
      executionManifestDigest: configuration.executionManifestDigest, authorId: identity.publicKeyBytes,
      authorTimestampMs: timestamp, nonce: bytes(index + 1),
      // The final admitted proposal deterministically rejects as an operation conflict.
      operationId: `history-${index === count - 1 ? 0 : index}`, program: program(emit('history', { index })) })
    transactionIds.push(utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`))
    const envelope = await encodeSignedEnvelope(groupId, 'candidate', canonical, identity)
    const descriptor = await createLedgerRecord(envelope)
    bodies.set(descriptor.record.payloadHash, envelope)
    proofs.push(encodeOrderingEvidence({ kind: 'ordered-entry', entry: await log.append(descriptor.recordBytes) }))
    const closedThroughMs = timestamp + 10n
    const closure = await createFinalityClosureRecord({ configuration, identity: authorityIdentity,
      includedHead: await log.head(), closedThroughMs,
      control: await controlCommitmentForClosure(configuration, await log.read(), closedThroughMs) })
    proofs.push(encodeOrderingEvidence({ kind: 'ordered-entry', entry: await log.append(closure) }))
    proofs.push(encodeOrderingEvidence({ kind: 'prefix-certificate', certificate: await authority.certify() }))
  }

  async function open(options: {
    readonly store?: ReplyLossStore
    readonly initialEvidence?: readonly Uint8Array[]
    readonly live?: boolean
    readonly manual?: boolean
    readonly incompletePort?: boolean
    readonly failProof?: number
  } = {}) {
    const store = options.store ?? new ReplyLossStore()
    const counts = { materializations: 0, finalPublications: 0, retentions: 0 }
    const runtime = await createEventMaterializationRuntime({ store, namespace: 'history' })
    const materialization: ChronologMaterializationRuntime = {
      ...runtime, coordinator: {
        async materialize(input) {
          const result = await runtime.coordinator.materialize(input)
          if (result !== null) counts.materializations++
          return result
        },
        async publishFinal(length) {
          const before = runtime.queries.finalRevision
          await runtime.coordinator.publishFinal!(length)
          if (runtime.queries.finalRevision !== before) counts.finalPublications++
        },
      },
    }
    const policy = await SignedInclusionFinalityProvider.open(configuration, store)
    if (options.failProof !== undefined) {
      const verify = policy.ingestEvidence.bind(policy)
      let calls = 0
      policy.ingestEvidence = async proof => {
        if (++calls === options.failProof) throw new Error('TEMPORARY_PROOF_FAILURE')
        return verify(proof)
      }
    }
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    transport.getPayload = async hash => bodies.get(hash)?.slice() ?? null
    const retain = transport.putEvidenceBatch.bind(transport)
    transport.putEvidenceBatch = async input => { counts.retentions++; return retain(input) }
    if (!options.live) transport.subscribeEvidenceBatches = async function* () {}
    if (options.initialEvidence !== undefined) await transport.putEvidenceBatch(options.initialEvidence)
    counts.retentions = 0
    // A manual embedding has no shared evidence log; the provider owns its
    // durable proofs. This is distinct from a partially implemented write port.
    const manual: ChronologTransport = {
      identity: transport.identity,
      publish: (payload, input) => transport.publish(payload, input), get: id => transport.get(id),
      getPayload: hash => transport.getPayload(hash), history: () => transport.history(),
      subscribe: signal => transport.subscribe(signal), status: () => transport.status(), close: () => transport.close(),
      ...(options.incompletePort ? { putEvidence: (input: Uint8Array) => transport.putEvidence(input) } : {}),
    }
    let node: ChronologNode
    try {
      node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store,
        transport: options.manual || options.incompletePort ? manual : transport,
        historyPolicy: { kind: 'coordinated', policy }, materialization,
        membership: { canWrite: () => true, canValidate: () => false, threshold: () => 1 },
      })
    } catch (error) { await runtime.close(); await transport.close(); throw error }
    cleanup.push(() => node.close())
    try { await node.start() } catch (error) { await node.close(); throw error }
    return { node, transport, policy, store, counts,
      application: () => runtime.queries.captureApplication({ view: 'final' }).transactions,
    }
  }
  return { proofs, transactionIds, open, count }
}

describe('bounded finality evidence publication', () => {
  it('publishes a historical page once with identical final order and accepted/rejected outcomes', async () => {
    const h = await history(), direct = await h.open(), batched = await h.open()
    for (const proof of h.proofs) await direct.node.ingestFinalityEvidence(proof)
    await batched.node.ingestFinalityEvidenceBatch(h.proofs)
    expect(batched.application()).toEqual(direct.application())
    expect(batched.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(batched.application().map(item => item.outcome)).toEqual([...Array<string>(h.count - 1).fill('accepted'), 'rejected'])
    for (const id of h.transactionIds) {
      expect(batched.node.outcome(id)).toEqual(direct.node.outcome(id))
      expect(batched.node.isFinal(id)).toBe(true)
    }
    expect(batched.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 1 })
    expect(batched.node.materializedRevision).toBe(1n)
    expect(batched.node.finalRevision).toBe(1n)
    expect(direct.counts.materializations).toBe(h.count)
    expect(direct.counts.finalPublications).toBe(h.count)
  })

  it.each(['startup', 'idle', 'background'] as const)('drains committed %s batches once and filters invalid bytes within the page', async delivery => {
    const h = await history()
    const retained = [...h.proofs.slice(0, 4), utf8('unrelated peer evidence'), ...h.proofs.slice(4)]
    const replica = await h.open({ ...(delivery === 'startup' ? { initialEvidence: retained } : {}), live: delivery === 'background' })
    if (delivery !== 'startup') {
      await replica.transport.putEvidenceBatch(retained)
      replica.counts.retentions = 0
      if (delivery === 'idle') await replica.node.waitForIdle()
      else await expect.poll(() => replica.node.finalOrderLength).toBe(h.count)
    }
    expect(replica.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(replica.application().at(-1)?.outcome).toBe('rejected')
    expect(replica.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 0 })
    expect((await replica.node.status()).lastError).toBeUndefined()
  })

  it('publishes a larger finite replay once per bounded page, without retaining a whole-history array in the node', async () => {
    const h = await history(23), replica = await h.open()
    expect(h.proofs.length).toBeGreaterThan(MAX_EVIDENCE_BATCH_SIZE)
    for (let start = 0; start < h.proofs.length; start += MAX_EVIDENCE_BATCH_SIZE) {
      await replica.transport.putEvidenceBatch(h.proofs.slice(start, start + MAX_EVIDENCE_BATCH_SIZE))
    }
    replica.counts.retentions = 0
    await replica.node.waitForIdle()
    expect(replica.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(replica.counts).toEqual({ materializations: 2, finalPublications: 2, retentions: 0 })
    expect(replica.node.materializedRevision).toBe(2n)
    expect(replica.node.finalRevision).toBe(2n)
  })

  it('stops a failed live batch visibly without skipping its remaining proof, then recovers the retained backlog on reopen', async () => {
    const h = await history(2), replica = await h.open({ live: true })
    const before = await replica.node.events.read()
    const verify = replica.policy.ingestEvidence.bind(replica.policy)
    let calls = 0
    replica.policy.ingestEvidence = async proof => {
      calls++
      if (calls === 2) throw new Error('TEMPORARY_PROOF_FAILURE')
      return verify(proof)
    }
    // The second proof fails; the third would close the first proposal. The
    // next retained page must not silently make the stopped consumer healthy.
    await replica.transport.putEvidenceBatch(h.proofs.slice(0, 3))
    await expect.poll(async () => (await replica.node.status()).lastError).toBe('NODE_EVIDENCE_REOPEN_REQUIRED: TEMPORARY_PROOF_FAILURE')
    await replica.transport.putEvidenceBatch(h.proofs.slice(3))
    await expect(replica.node.waitForIdle()).rejects.toThrow('NODE_EVIDENCE_REOPEN_REQUIRED')
    await expect(replica.node.ingestFinalityEvidence(h.proofs[2]!)).rejects.toThrow('NODE_EVIDENCE_REOPEN_REQUIRED')
    expect(calls).toBe(2)
    expect(await replica.node.events.read()).toEqual(before)
    expect(replica.node.materializedRevision).toBe(0n)
    expect(replica.node.finalRevision).toBe(0n)
    expect(replica.counts.materializations).toBe(0)
    expect(replica.counts.finalPublications).toBe(0)
    await replica.node.close()
    const reopened = await h.open({ store: replica.store })
    expect(reopened.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(reopened.application().map(item => item.outcome)).toEqual(['accepted', 'rejected'])
    expect(reopened.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 0 })
    expect((await reopened.node.status()).lastError).toBeUndefined()
  })

  it('rejects startup after an unfinished retained proof batch instead of reporting a healthy node', async () => {
    const h = await history(2), store = new ReplyLossStore()
    await expect(h.open({ store, initialEvidence: h.proofs, failProof: 2 })).rejects.toThrow('TEMPORARY_PROOF_FAILURE')
    const reopened = await h.open({ store })
    expect(reopened.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(reopened.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 0 })
  })

  it.each(['retention', 'provider'] as const)('keeps the published view unchanged after an uncertain %s write and recovers on reopen', async failure => {
    const h = await history(), replica = await h.open()
    const before = await replica.node.events.read()
    replica.store.failure = failure === 'retention'
      ? { prefix: 'feed/manifest', remaining: 1 }
      : { prefix: 'history/', remaining: 6 }
    await expect(replica.node.ingestFinalityEvidenceBatch(h.proofs)).rejects.toThrow('BATCH_COMMIT_REPLY_LOST')
    expect(await replica.node.events.read()).toEqual(before)
    expect(replica.node.materializedRevision).toBe(0n)
    expect(replica.node.finalRevision).toBe(0n)
    expect(replica.counts.materializations).toBe(0)
    expect(replica.counts.finalPublications).toBe(0)
    expect(replica.policy.snapshot().includedThrough).toBe(failure === 'retention' ? 0 : 2)
    await expect(replica.node.ingestFinalityEvidenceBatch(h.proofs)).rejects.toThrow(
      failure === 'retention' ? 'FEED_STORE_REOPEN_REQUIRED' : 'HISTORY_STORAGE_UNCERTAIN_REOPEN_REQUIRED')
    expect(await replica.node.events.read()).toEqual(before)
    await replica.node.close()
    const recovered = await h.open({ store: replica.store })
    expect(recovered.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(recovered.application().at(-1)?.outcome).toBe('rejected')
    expect(recovered.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 0 })
  })

  it('supports manual provider-durable ingress but rejects an incomplete evidence publication port', async () => {
    const h = await history(), manual = await h.open({ manual: true })
    await manual.node.ingestFinalityEvidenceBatch(h.proofs)
    expect(manual.application().map(item => item.txId)).toEqual(h.transactionIds)
    expect(manual.counts).toEqual({ materializations: 1, finalPublications: 1, retentions: 0 })
    await manual.node.close()
    const reopened = await h.open({ manual: true, store: manual.store })
    expect(reopened.application().map(item => item.txId)).toEqual(h.transactionIds)
    await expect(h.open({ incompletePort: true })).rejects.toThrow('NODE_EVIDENCE_TRANSPORT_INCOMPLETE')
  })
})

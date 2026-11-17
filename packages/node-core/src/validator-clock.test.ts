import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { bytesToHex, decodeEnvelope, emit, encodeTransactionCore, generateEd25519KeyPair, program, transactionDigest, utf8 } from '@chronolog/protocol'
import type { TransactionCore } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { encodeSignedEnvelope } from './wire.js'

it('attests the exact future boundary without rounding when clock plus allowed skew exceeds a safe number', async () => {
  const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const groupId = new Uint8Array(32).fill(1), membershipRevision = new Uint8Array(32).fill(2), validationPolicy = new Uint8Array(32).fill(3)
  const materialization = await createEventMaterializationRuntime({ store, namespace: 'validator-clock' })
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  const now = 1_002, skew = Number.MAX_SAFE_INTEGER
  const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store,
    materialization, transport, clock: { now: () => now },
    membership: { canWrite: () => true, canValidate: () => true, threshold: () => 1 },
    validator: { capabilityId: new Uint8Array(32).fill(4), cutoffLagMs: 0, maxFutureSkewMs: skew },
  })
  try {
    await node.start()
    const include = async (authorTimestampMs: bigint, operationId: string) => {
      const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: identity.publicKeyBytes,
        authorTimestampMs, operationId, nonce: new Uint8Array(32), executionManifestDigest: materialization.queries.executionManifestDigest,
        program: program(emit('clock', operationId)) }
      const canonical = encodeTransactionCore(core)
      const txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
      const record = await transport.publish(await encodeSignedEnvelope(groupId, 'candidate', canonical, identity))
      await node.ingest(record)
      for (const retained of await transport.history()) await node.ingest(retained)
      await node.waitForIdle()
      return txId
    }
    const boundary = BigInt(now) + BigInt(skew)
    const accepted = await include(boundary, 'at-boundary')
    expect(node.candidate(accepted)?.state).toBe('admissible')
    const beyond = await include(boundary + 1n, 'beyond-boundary')
    expect(node.candidate(beyond)?.state).toBe('pending_validation')
    expect(node.outcome(beyond)).toBeNull()
  } finally { await node.close() }
})

it.each(['pending_validation', 'provisional'] as const)('reevaluates a future-held %s proposal on heartbeat clock progress without a membership change or restart', async state => {
  const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const groupId = new Uint8Array(32).fill(11), membershipRevision = new Uint8Array(32).fill(12), validationPolicy = new Uint8Array(32).fill(13)
  const materialization = await createEventMaterializationRuntime({ store, namespace: 'future-clock-progress' })
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  let now = 1_000
  const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, operationStore: store,
    materialization, transport, clock: { now: () => now },
    membership: { canWrite: () => true, canValidate: () => true, threshold: () => 1,
      watermarkPolicy: () => ({ kind: 'threshold', policyId: 'one-validator', threshold: 1, validatorIds: [identity.publicKeyBytes] }),
      admissionScopes: () => [{ membershipRevision, authorTimeAfterMs: -1n,
        policies: [{ kind: 'threshold', policyId: 'one-validator', threshold: 1, validatorIds: [identity.publicKeyBytes] }] }] },
    validator: { capabilityId: new Uint8Array(32).fill(14), cutoffLagMs: 100, maxFutureSkewMs: 50 },
  })
  try {
    await node.start()
    const core: TransactionCore = { groupId, membershipRevision, validationPolicy, authorId: identity.publicKeyBytes,
      authorTimestampMs: 1_200n, operationId: 'future-held', nonce: new Uint8Array(32),
      executionManifestDigest: materialization.queries.executionManifestDigest, program: program(emit('clock', 'eventually eligible')) }
    const canonical = encodeTransactionCore(core), txId = utf8(`tx_${bytesToHex(await transactionDigest(canonical))}`)
    await node.ingest(await transport.publish(await encodeSignedEnvelope(groupId, 'candidate', canonical, identity)))
    await node.waitForIdle()
    expect(node.candidate(txId)?.state).toBe('pending_validation')
    expect(node.outcome(txId)).toBeNull()
    if (state === 'provisional') node.controlStore.setCandidateState(txId, state)

    now = 1_149
    await node.publishHeartbeat()
    expect(node.candidate(txId)?.state).toBe(state)
    now = 1_150 // The proposal enters the exact future window.
    await node.publishHeartbeat()
    await node.waitForIdle()
    expect(node.candidate(txId)?.state).toBe('admissible')
    expect(node.isFinal(txId)).toBe(false)
    now = 1_300 // The ordinary signed cutoff now covers the admitted proposal.
    await node.publishHeartbeat()
    await node.waitForIdle()
    expect(node.isFinal(txId)).toBe(true)
    expect(node.outcome(txId)?.outcome).toBe('accepted')
    await node.publishHeartbeat()
    expect((await transport.history()).filter(record => decodeEnvelope(record.payload).messageType === 'attestation')).toHaveLength(1)
  } finally { await node.close() }
})

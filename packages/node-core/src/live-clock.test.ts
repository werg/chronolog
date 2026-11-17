import { DEFAULT_LIVE_CLOCK_POLICY } from '@chronolog/capabilities'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { emit, generateEd25519KeyPair, program } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { expect, it } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'

it('advances the applied final prefix on the default idle heartbeat without more application traffic', async () => {
  const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const groupId = new Uint8Array(32).fill(141), membershipRevision = new Uint8Array(32).fill(142)
  const validationPolicy = new Uint8Array(32).fill(143), capabilityId = new Uint8Array(32).fill(144)
  const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
  let now = 10_000
  const policy = { kind: 'threshold' as const, policyId: 'default-live', validatorIds: [identity.publicKeyBytes], threshold: 1 }
  const node = new ChronologNode({ identity, groupId, membershipRevision, validationPolicy, transport,
    operationStore: store, materialization: await createEventMaterializationRuntime({ store, namespace: 'idle-live' }),
    membership: { canWrite: () => true, canValidate: () => true, threshold: () => 1,
      watermarkPolicy: () => policy,
      admissionScopes: () => [{ membershipRevision, authorTimeAfterMs: -1n, policies: [policy] }] },
    clock: { now: () => now }, validator: { capabilityId },
  })
  try {
    await node.start()
    for (const name of ['first', 'second']) {
      const published = await node.publish({ operationId: name, program: program(emit('live', name)) })
      await expect.poll(async () => { await node.waitForIdle(); return node.outcome(published.txId)?.outcome }).toBe('accepted')
      expect(node.isFinal(published.txId)).toBe(false)
      const previousFinalRevision = node.finalRevision
      // Only protocol time advances. The ordinary configured timer supplies
      // the signed heartbeat, consumed proof, replay and final publication.
      now += Number(DEFAULT_LIVE_CLOCK_POLICY.cutoffLagMs) + 1
      await expect.poll(() => node.isFinal(published.txId), { timeout: 5_000 }).toBe(true)
      expect(node.finalRevision).toBeGreaterThan(previousFinalRevision)
    }
    expect((await node.events.read()).transactions.flatMap(value => value.events.map(event => event.payload)))
      .toEqual(['first', 'second'])
  } finally { await node.close() }
}, 15_000)

import { decodeEnvelope, encodeValidatorAttestation, generateEd25519KeyPair } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { describe, expect, it } from 'vitest'

import { decodeSignedGovernanceClosure, verifyGovernanceClosure } from './governance-activation.js'
import { MemoryOperationStore } from './operations.js'
import { ValidatorRevisionClosures } from './validator-closures.js'
import { encodeSignedEnvelope } from './wire.js'

const bytes = (value: number) => new Uint8Array(32).fill(value)

describe('durable validator revision closure', () => {
  it('recovers a lost append reply with the same original signed closure and feed position', async () => {
    const network = new MemoryTransportNetwork()
    const transport = network.createNode('validator')
    const identity = await generateEd25519KeyPair()
    const store = new MemoryOperationStore()
    const previous = bytes(2), next = bytes(3), capability = bytes(4), route = bytes(5), group = bytes(6)
    await transport.publish(await encodeSignedEnvelope(route, 'attestation', encodeValidatorAttestation({
      groupId: group, membershipRevision: previous, validatorCapability: capability,
      txId: bytes(7), validatorId: identity.publicKeyBytes, authorTimestampMs: 9_000n,
      acceptedAboveMs: 10n, candidateDigest: bytes(8), decision: 'admit', policyVersion: 1n,
    }), identity))
    const publish = transport.publish.bind(transport)
    let loseReply = true
    transport.publish = async (payload, options) => {
      const record = await publish(payload, options)
      if (loseReply) { loseReply = false; throw new Error('reply lost after append') }
      return record
    }
    const options = { groupId: group, groupRoute: route, identity, transport, store }
    const first = new ValidatorRevisionClosures(options)
    await expect(first.close(previous, next, capability, 100n)).rejects.toThrow('reply lost')
    expect(first.isClosed(previous)).toBe(true)
    const reopened = new ValidatorRevisionClosures(options)
    await reopened.recover()
    expect(reopened.isClosed(previous)).toBe(true)
    const recovered = await reopened.close(previous, next, capability, 99_000n)
    expect((await transport.history()).length).toBe(2)
    const signed = decodeSignedGovernanceClosure(decodeEnvelope(recovered.payload).payload)
    expect(await verifyGovernanceClosure(signed)).toBe(true)
    expect(signed.closure).toMatchObject({ throughMs: 9_000n, lastAdmissionSequence: 1n })
    await expect(reopened.close(previous, bytes(9), capability, 100n)).rejects.toThrow('VALIDATOR_CLOSURE_SUCCESSOR_CONFLICT')
    await transport.close()
  })

  it('keeps the no-more-admissions promise if the device stops before saving the prepared signature', async () => {
    const store = new MemoryOperationStore()
    const put = store.put.bind(store)
    let crash = true
    store.put = async (key, value) => {
      if (crash && key.endsWith('/publication/pending')) { crash = false; throw new Error('device interrupted') }
      await put(key, value)
    }
    const transport = new MemoryTransportNetwork().createNode('validator')
    const options = { groupId: bytes(1), groupRoute: bytes(2), identity: await generateEd25519KeyPair(), transport, store }
    const original = new ValidatorRevisionClosures(options)
    await expect(original.close(bytes(3), bytes(4), bytes(5), 100n)).rejects.toThrow('device interrupted')
    expect(await transport.history()).toHaveLength(0)
    const reopened = new ValidatorRevisionClosures(options)
    await reopened.recover()
    expect(reopened.isClosed(bytes(3))).toBe(true)
    await reopened.close(bytes(3), bytes(4), bytes(5), 100n)
    expect(await transport.history()).toHaveLength(1)
    await transport.close()
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { encodeGenesisManifest, signGenesis } from '@chronolog/capabilities'
import {
  DOMAINS, bytesToHex, decodeTransactionCore, generateEd25519KeyPair, hashDomain, transactionDigest,
} from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import type { EnrollmentDescriptor } from './enrollment.js'
import { GovernanceControlPlane } from './governance.js'
import { MemoryOperationStore } from './operations.js'
import { approvePublisherRequest, createLimitedPublisher, loadOrCreatePublisherIdentity, preparePublisherRequest } from './publisher.js'
import { decodeSignedEnvelope, decodeSignedMessage, sealSignedMessage, signWireMessage } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (n: number) => new Uint8Array(32).fill(n)

async function publisherFixture() {
  const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const network = new MemoryTransportNetwork(), transport = network.createNode('owner')
  const genesis = await signGenesis({ groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: identity.publicKeyBytes, schemaAdminPublicKey: identity.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode('owner'), initialCapabilities: [], validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 60_000n, cutoffLagMs: 1000n, heartbeatIntervalMs: 1000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.privateKey)
  const descriptor: EnrollmentDescriptor = { genesis, groupRoute: bytes(3), history: { kind: 'peer', groupId: genesis.manifest.groupId,
    executionManifestDigest: genesis.manifest.schemaId, genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)) } }
  const governance = await GovernanceControlPlane.create({ genesis, groupRoute: descriptor.groupRoute, transport, identity, operationStore: store })
  await governance.start(); cleanup.push(() => governance.close())
  const publisherStore = new MemoryOperationStore(), publisherIdentity = await loadOrCreatePublisherIdentity(publisherStore, 'review')
  const request = await preparePublisherRequest({ descriptor, store: publisherStore, identity: publisherIdentity, requestId: 'join', topics: ['chat/message'] })
  const approval = await approvePublisherRequest({ descriptor, governance, store, rootPrivateKey: identity.privateKey, request, topics: ['chat/message'] })
  const sent: Uint8Array[] = []
  const publisher = await createLimitedPublisher({ descriptor, request, approval, identity: publisherIdentity, store: publisherStore,
    send: async (signed) => {
      sent.push(signed.slice())
      const wire = await decodeSignedMessage(signed)
      return { proposalId: `tx_${bytesToHex(await transactionDigest(wire.payload))}` }
    } })
  return { publisher, sent, approval, descriptor, store, governance, identity, publisherStore, publisherIdentity }
}

describe('publisher input ownership review', () => {
  it('keeps the submitted operation identity when caller options change during durable preparation', async () => {
    const f = await publisherFixture(), input = { operationId: 'original-request' }
    const pending = f.publisher.publish('chat/message', { text: 'hello' }, input)
    input.operationId = 'next-request'
    const receipt = await pending
    expect(receipt.operationId).toBe('original-request')
    const wire = await decodeSignedMessage(f.sent[0]!)
    expect(decodeTransactionCore(wire.payload).operationId).toBe('original-request')
    expect(await f.publisher.publish('chat/message', { text: 'hello' }, { operationId: 'original-request' })).toEqual(receipt)
    expect(f.sent).toHaveLength(1)
  })

  it('keeps verified publication scopes independent of caller-owned approval arrays', async () => {
    const f = await publisherFixture()
    const mutableTopics = f.approval.revision.revision.grants[0]!.program!.topics as string[]
    mutableTopics.push('administration/privileged')
    await expect(f.publisher.publish('administration/privileged', null, { operationId: 'denied' })).rejects.toThrow('PUBLISHER_PROGRAM_UNAUTHORIZED')
    expect(f.sent).toHaveLength(0)
  })

  it('captures the reviewed enrollment identity and scopes before verification suspends', async () => {
    const f = await publisherFixture(), topics = ['chat/message']
    const input = { descriptor: f.descriptor, store: f.publisherStore, identity: f.publisherIdentity, requestId: 'reviewed-request', topics }
    const pendingRequest = preparePublisherRequest(input)
    input.requestId = 'changed-request'; topics[0] = 'administration/privileged'
    const request = await pendingRequest
    expect(request.request).toMatchObject({ requestId: 'reviewed-request', topics: ['chat/message'] })
    const expectedSigner = request.request.signer.slice(), approvedTopics = ['chat/message']
    const pendingApproval = approvePublisherRequest({ descriptor: f.descriptor, governance: f.governance, store: f.store,
      rootPrivateKey: f.identity.privateKey, request, topics: approvedTopics })
    request.request.signer.fill(0); approvedTopics[0] = 'administration/privileged'
    const approval = await pendingApproval
    expect(approval.revision.revision.grants).toHaveLength(1)
    expect(approval.revision.revision.grants[0]).toMatchObject({ subjectId: expectedSigner, signingPublicKey: expectedSigner,
      program: { topics: ['chat/message'], sql: false, forwarded: true } })
  })

  it('signs one captured payload and public identity across the crypto suspension', async () => {
    const identity = await generateEd25519KeyPair(), originalSigner = identity.publicKeyBytes.slice()
    const payload = new Uint8Array([1, 2, 3]), expected = payload.slice()
    const pending = signWireMessage('candidate', payload, identity)
    payload.fill(9); identity.publicKeyBytes.fill(0)
    const decoded = await decodeSignedMessage(await pending)
    expect(decoded.payload).toEqual(expected)
    expect(decoded.signer).toEqual(originalSigner)
  })

  it('seals the exact signed bytes that were verified before the asynchronous boundary', async () => {
    const identity = await generateEd25519KeyPair(), groupRoute = bytes(42)
    const expectedRoute = groupRoute.slice()
    const wire = await signWireMessage('candidate', new Uint8Array([1, 2, 3]), identity)
    const original = await decodeSignedMessage(wire)
    const pending = sealSignedMessage(groupRoute, wire)
    wire[wire.length - 1]! ^= 1; groupRoute.fill(0)
    expect(await decodeSignedEnvelope(await pending, expectedRoute)).toEqual(original)
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { capabilityId, encodeGenesisManifest, signGenesis, type CapabilityGrant } from '@chronolog/capabilities'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { DOMAINS, decodeEnvelope, decodeTransactionCore, emit, encodeTransactionCore, hashDomain, platformOp, program, type Ed25519KeyPair } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { CapabilityMembershipResolver } from './capability-membership.js'
import { loadOrCreateEnrollmentIdentity, type EnrollmentDescriptor } from './enrollment.js'
import { GovernanceControlPlane } from './governance.js'
import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'
import { approvePublisherRequest, createLimitedPublisher, decodePublisherApproval, encodePublisherApproval, loadOrCreatePublisherIdentity,
  preparePublisherRequest, verifyPublisherApproval } from './publisher.js'
import { decodeSignedEnvelope, decodeSignedMessage, signWireMessage } from './wire.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const bytes = (n: number) => new Uint8Array(32).fill(n)
async function fixture() {
  const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'owner')
  const runtime = await createEventMaterializationRuntime({ store, namespace: 'materializer' })
  const network = new MemoryTransportNetwork(), transport = network.createNode('owner')
  const initialCapabilities: CapabilityGrant[] = [
    { role: 'writer', subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, transportAuthor: 'owner', validFromRevision: 0n,
      program: { sql: false, topics: ['*'], signals: ['*'] } },
    { role: 'reader', subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, transportAuthor: 'owner', validFromRevision: 0n, hpkePublicKey: identity.reader.publicKeyBytes },
  ]
  const genesis = await signGenesis({ groupId: bytes(1), schemaId: runtime.queries.executionManifestDigest, rootAdminPublicKey: identity.signing.publicKeyBytes, schemaAdminPublicKey: identity.signing.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode('owner'), initialCapabilities, validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 60_000n, cutoffLagMs: 1000n, heartbeatIntervalMs: 1000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }, identity.signing.privateKey)
  const descriptor: EnrollmentDescriptor = { genesis, groupRoute: bytes(2), history: { kind: 'peer', groupId: genesis.manifest.groupId,
    executionManifestDigest: genesis.manifest.schemaId, genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(genesis.manifest)) } }
  const governance = await GovernanceControlPlane.create({ genesis, groupRoute: descriptor.groupRoute, transport, identity: identity.signing, operationStore: store,
    recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
  await governance.start(); cleanup.push(() => governance.close())
  const publisherStore = new MemoryOperationStore(), publisherIdentity = await loadOrCreatePublisherIdentity(publisherStore, 'device')
  const request = await preparePublisherRequest({ descriptor, store: publisherStore, identity: publisherIdentity, requestId: 'join', topics: ['chat/message'], signals: ['chat/typing'] })
  const approve = { descriptor, governance, store, rootPrivateKey: identity.signing.privateKey, request, topics: ['chat/message'], signals: ['chat/typing'] }
  const approval = await approvePublisherRequest(approve)
  return { store, identity, runtime, transport, governance, descriptor, publisherStore, publisherIdentity, request, approval, approve }
}

describe('limited original-signer publishers', () => {
  it('issues only requested publication rights, with no history or reader keys, and preserves approval retries', async () => {
    const f = await fixture()
    expect(f.governance.hasEpochKey(0n)).toBe(false)
    expect(Object.keys(f.publisherIdentity).sort()).toEqual(['privateKey', 'publicKey', 'publicKeyBytes'])
    expect(f.approval.revision.revision.grants).toHaveLength(1)
    expect(f.approval.revision.revision.grants[0]).toMatchObject({ role: 'writer', program: { sql: false, forwarded: true, topics: ['chat/message'], signals: ['chat/typing'] } })
    expect(f.approval.revision.revision.grants[0]?.hpkePublicKey).toBeUndefined()
    await verifyPublisherApproval(f.descriptor, f.request, decodePublisherApproval(encodePublisherApproval(f.approval)))
    const before = (await f.transport.history()).length
    expect(await approvePublisherRequest(f.approve)).toEqual(f.approval)
    expect((await f.transport.history()).length).toBe(before)
    await expect(approvePublisherRequest({ ...f.approve, topics: ['different'] })).rejects.toThrow('UNAUTHORIZED')
    await expect(approvePublisherRequest({ ...f.approve, topics: [] })).rejects.toThrow('DECISION_CONFLICT')
  })

  it('forwards the exact original signature and returns the original proposal after revocation and reopening', async () => {
    const f = await fixture()
    await f.governance.initializeEpochKey(f.identity.signing.privateKey, bytes(3))
    const membership = new CapabilityMembershipResolver({ snapshotForRevision: (digest) => f.governance.snapshotForRevision(digest), authorizationSnapshot: () => f.governance.snapshot })
    const node = new ChronologNode({ groupId: f.descriptor.history.groupId, groupRoute: f.descriptor.groupRoute, identity: f.identity.signing,
      membershipRevision: f.governance.snapshot.revisionDigest, validationPolicy: f.approval.validationPolicy,
      transport: f.transport, materialization: f.runtime, operationStore: f.store, membership, envelopeCipher: f.governance.cipherRing })
    await node.start(); cleanup.push(() => node.close())
    const localGrant = [...f.governance.snapshot.capabilities.values()].find((entry) => entry.grant.role === 'writer' && entry.grant.transportAuthor === 'owner')!
    const mutablePayload = { text: 'captured' }
    const authored = node.publish({ operationId: 'snapshot-input', writerCapability: localGrant.id,
      program: { version: 3, steps: [{ op: 'emit', topic: 'chat/message', payload: mutablePayload }] } })
    mutablePayload.text = 'changed after call'
    const local = await authored
    expect(local.core.program.steps[0]).toMatchObject({ payload: { text: 'captured' } })
    const sent: Uint8Array[] = []
    const options = { descriptor: f.descriptor, request: f.request, approval: f.approval, identity: f.publisherIdentity, store: f.publisherStore,
      send: async (signed: Uint8Array) => { sent.push(signed.slice()); return node.submitSigned(signed) } }
    const publisher = await createLimitedPublisher(options)
    const receipt = await publisher.publish('chat/message', { text: 'hello' }, { operationId: 'message-1' })
    const record = (await f.transport.history()).filter((record) => decodeEnvelope(record.payload).messageType === 'candidate').at(-1)!
    const original = await decodeSignedMessage(sent[0]!), forwarded = await decodeSignedEnvelope(record.payload, f.descriptor.groupRoute, f.governance.cipherRing)
    expect(record.author).toBe('owner')
    expect(forwarded).toEqual(original)
    expect(forwarded.signer).toEqual(f.publisherIdentity.publicKeyBytes)
    const publishedCount = (await f.transport.history()).length
    const capturedCore = decodeTransactionCore(original.payload)
    // Bypass the friendly publisher API: ingress must check actual signed rights.
    for (const [label, denied] of [
      ['topic', program(emit('administration/private', 'outside the grant'))],
      ['sql', program('SELECT 1', emit('chat/message', 'SQL escalation'))],
      ['platform', program(platformOp.endSeeding(), emit('chat/message', 'platform escalation'))],
    ] as const) {
      const signed = await signWireMessage('candidate', encodeTransactionCore({ ...capturedCore,
        operationId: `direct-denied-${label}`, program: denied }), f.publisherIdentity)
      await expect(node.submitSigned(signed)).rejects.toThrow('WRITER_UNAUTHORIZED')
    }
    const changedSignature = sent[0]!.slice()
    changedSignature[changedSignature.length - 1]! ^= 1
    await expect(node.submitSigned(changedSignature)).rejects.toThrow('WIRE_SIGNATURE_INVALID')
    expect((await node.submitSigned(sent[0]!)).txIdText).toBe(receipt.proposalId)
    expect((await f.transport.history()).length).toBe(publishedCount)
    await f.governance.publishCapabilityChange({ revocations: [await capabilityId(f.approval.revision.revision.grants[0]!)] }, f.identity.signing.privateKey)
    const count = (await f.transport.history()).length
    expect((await node.submitSigned(sent[0]!)).txIdText).toBe(receipt.proposalId)
    const reopenedIdentity: Ed25519KeyPair = await loadOrCreatePublisherIdentity(f.publisherStore, 'device')
    const reopened = await createLimitedPublisher({ ...options, identity: reopenedIdentity })
    expect(await reopened.publish('chat/message', { text: 'hello' }, { operationId: 'message-1' })).toEqual(receipt)
    expect((await f.transport.history()).length).toBe(count)
    await expect(reopened.publish('chat/message', { text: 'changed' }, { operationId: 'message-1' })).rejects.toThrow('OPERATION_ID_CONFLICT')
    await expect(reopened.publish('chat/message', { text: 'new' }, { operationId: 'message-2' })).rejects.toThrow('WRITER_UNAUTHORIZED')
    const changed = decodeTransactionCore(original.payload)
    await expect(node.submitSigned(await signWireMessage('candidate', encodeTransactionCore({ ...changed, nonce: bytes(42) }), f.publisherIdentity))).rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('recovers the same signed proposal after an ambiguous ingress acknowledgement and rejects SQL', async () => {
    const f = await fixture()
    let failed = false
    const sent: Uint8Array[] = []
    const options = { descriptor: f.descriptor, request: f.request, approval: f.approval, identity: f.publisherIdentity, store: f.publisherStore,
      send: async (signed: Uint8Array) => {
        sent.push(signed.slice())
        if (!failed) { failed = true; throw new Error('response lost') }
        const wire = await decodeSignedMessage(signed)
        const { bytesToHex, transactionDigest } = await import('@chronolog/protocol')
        return { proposalId: `tx_${bytesToHex(await transactionDigest(wire.payload))}` }
      } }
    const first = await createLimitedPublisher(options)
    await expect(first.publish('chat/message', 'hello', { operationId: 'retry' })).rejects.toThrow('response lost')
    const reopened = await createLimitedPublisher(options)
    await reopened.recover()
    expect(sent).toHaveLength(2)
    expect(sent[0]).toEqual(sent[1])
    await expect(reopened.submit(program('SELECT 1', emit('chat/message', 'no')), { operationId: 'sql' })).rejects.toThrow('PROGRAM_UNAUTHORIZED')
    await expect(reopened.publish('chat/typing', 'durable?', { operationId: 'signal-topic' })).rejects.toThrow('PROGRAM_UNAUTHORIZED')
  })
})

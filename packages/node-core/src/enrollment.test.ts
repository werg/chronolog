import { encodeGenesisManifest, signGenesis, type CapabilityGrant, type GenesisManifest } from '@chronolog/capabilities'
import { DOMAINS, hashDomain } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import {
  EnrollmentIssuer, decodeSignedEnrollmentRequest, encodeSignedEnrollmentRequest, enrollmentProgress,
  loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest, verifySignedEnrollmentRequest,
  type EnrollmentDescriptor, type EnrollmentFinalTarget,
} from './enrollment.js'
import { GovernanceControlPlane } from './governance.js'
import { MemoryOperationStore } from './operations.js'

const controllers: GovernanceControlPlane[] = []
afterEach(async () => { await Promise.all(controllers.splice(0).map((controller) => controller.close())) })

describe('live durable group enrollment', () => {
  it('reopens one device identity and exact signed request and rejects changed request identities', async () => {
    const fixture = await setup()
    const store = new MemoryOperationStore()
    const identity = await loadOrCreateEnrollmentIdentity(store, 'joining-device')
    const reopened = await loadOrCreateEnrollmentIdentity(store, 'joining-device')
    expect(reopened.signing.publicKeyBytes).toEqual(identity.signing.publicKeyBytes)
    expect(reopened.reader.publicKeyBytes).toEqual(identity.reader.publicKeyBytes)
    const options = { descriptor: fixture.descriptor, store, identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: 'joining',
      requestId: 'join-1', requestedRoles: ['reader', 'writer'] as const }
    const request = await prepareEnrollmentRequest(options)
    const retry = await prepareEnrollmentRequest({ ...options, identity: reopened.signing })
    expect(encodeSignedEnrollmentRequest(retry)).toEqual(encodeSignedEnrollmentRequest(request))
    expect(await verifySignedEnrollmentRequest(decodeSignedEnrollmentRequest(encodeSignedEnrollmentRequest(request)))).toBe(true)
    expect(await verifySignedEnrollmentRequest({ ...request, request: { ...request.request, transportAuthor: 'attacker' } })).toBe(false)
    await expect(prepareEnrollmentRequest({ ...options, requestedRoles: ['reader'] })).rejects.toThrow('ENROLLMENT_REQUEST_ID_CONFLICT')
  })

  it('approves a fresh peer live and obtains all historical keys through another peer while the issuer is disconnected', async () => {
    const fixture = await setup()
    await fixture.governance.rotateEpoch(fixture.identity.signing.privateKey, bytes(80))
    await fixture.governance.rotateEpoch(fixture.identity.signing.privateKey, bytes(81))
    const relay = fixture.network.createNode('relay')
    fixture.network.connect(fixture.transport, relay)
    const store = new MemoryOperationStore()
    const identity = await loadOrCreateEnrollmentIdentity(store, 'new-device')
    const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store,
      requestId: 'new-peer', identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
      transportAuthor: 'new-peer', requestedRoles: ['reader', 'writer'] })
    const approval = await fixture.issuer.approve(request, { operationId: 'approve-new-peer', roles: ['reader', 'writer'], grantFullHistory: true })
    fixture.network.disconnect(fixture.transport, relay)
    const transport = fixture.network.createNode('new-peer')
    fixture.network.connect(relay, transport)
    const participant = await GovernanceControlPlane.create({
      genesis: fixture.descriptor.genesis, groupRoute: fixture.descriptor.groupRoute, transport,
      identity: identity.signing, operationStore: store,
      recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey },
    })
    controllers.push(participant)
    await participant.start()
    expect(participant.snapshot.revision).toBe(1n)
    expect(participant.cipherRing.epochs()).toEqual([0n, 1n])
    const base = { descriptor: fixture.descriptor, request, approval,
      activeMembership: participant.snapshot, connected: true,
      availableEpochs: participant.cipherRing.epochs(), executionManifestDigest: fixture.target.executionManifestDigest,
      isFinalTargetApplied: () => false }
    expect((await enrollmentProgress(base)).state).toBe('awaiting-history')
    expect((await enrollmentProgress({ ...base, availableEpochs: [1n] })).state).toBe('awaiting-keys')
    expect((await enrollmentProgress({ ...base, connected: false })).state).toBe('authorized-disconnected')
    expect((await enrollmentProgress({ ...base, executionManifestDigest: bytes(99) })).state).toBe('unsupported-engine')
    expect((await enrollmentProgress({ ...base, isFinalTargetApplied: () => true })).state).toBe('ready')
    const granted = approval.approval.capabilityIds.map((id) => participant.snapshot.capabilities.get(Buffer.from(id).toString('hex'))!.grant.role)
    expect(granted).toEqual(['reader', 'writer'])
  })

  it('resumes interrupted approval without creating another grant and preserves the original decision', async () => {
    const fixture = await setup()
    const store = new MemoryOperationStore()
    const identity = await loadOrCreateEnrollmentIdentity(store, 'device')
    const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store,
      requestId: 'interrupted', identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
      transportAuthor: 'interrupted', requestedRoles: ['reader', 'writer'] })
    const interrupted = new EnrollmentIssuer({ ...fixture.issuerOptions, captureFinalTarget: async () => { throw new Error('interrupted before target') } })
    const decision = { operationId: 'approve-1', roles: ['reader'] as const, grantFullHistory: true }
    await expect(interrupted.approve(request, decision)).rejects.toThrow('interrupted before target')
    expect(fixture.governance.snapshot.revision).toBe(1n)
    const records = (await fixture.transport.history()).length
    const resumed = await new EnrollmentIssuer(fixture.issuerOptions).approve(request, decision)
    expect(resumed.approval.grantedRevision).toBe(1n)
    expect(fixture.governance.snapshot.revision).toBe(1n)
    expect(await fixture.transport.history()).toHaveLength(records)
    await expect(fixture.issuer.approve(request, { ...decision, roles: ['reader', 'writer'] })).rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('serializes concurrent approvals into one revision chain', async () => {
    const fixture = await setup()
    const requests = await Promise.all(['one', 'two'].map(async (name) => {
      const store = new MemoryOperationStore()
      const identity = await loadOrCreateEnrollmentIdentity(store, name)
      return prepareEnrollmentRequest({ descriptor: fixture.descriptor, store, requestId: name,
        identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
        transportAuthor: name, requestedRoles: ['reader'] })
    }))
    const approvals = await Promise.all(requests.map((request, i) => fixture.issuer.approve(request,
      { operationId: `approval-${i}`, roles: ['reader'], grantFullHistory: true })))
    expect(approvals.map((signed) => signed.approval.grantedRevision).sort()).toEqual([1n, 2n])
    expect(fixture.governance.snapshot.revision).toBe(2n)
  })
})

async function setup() {
  const operationStore = new MemoryOperationStore()
  const identity = await loadOrCreateEnrollmentIdentity(operationStore, 'issuer')
  const network = new MemoryTransportNetwork()
  const transport = network.createNode('admin')
  const initialCapabilities: CapabilityGrant[] = [
    { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, role: 'writer', transportAuthor: 'admin', validFromRevision: 0n },
    { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, role: 'reader', transportAuthor: 'admin', hpkePublicKey: identity.reader.publicKeyBytes, validFromRevision: 0n },
    { subjectId: identity.signing.publicKeyBytes, signingPublicKey: identity.signing.publicKeyBytes, role: 'validator', transportAuthor: 'admin', minimumAuthorTimestampMs: 0n, validFromRevision: 0n },
  ]
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: identity.signing.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode('admin'), initialCapabilities,
    validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }
  const genesis = await signGenesis(manifest, identity.signing.privateKey)
  const descriptor: EnrollmentDescriptor = { genesis, groupRoute: bytes(3), history: {
    kind: 'peer', groupId: manifest.groupId, executionManifestDigest: manifest.schemaId,
    genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(manifest)),
  } }
  const governance = await GovernanceControlPlane.create({ genesis, groupRoute: descriptor.groupRoute, transport,
    identity: identity.signing, operationStore, recipient: { id: identity.signing.publicKeyBytes, privateKey: identity.reader.privateKey } })
  controllers.push(governance)
  await governance.start()
  const target: EnrollmentFinalTarget = { frontier: bytes(4), requiredEpochs: [], executionManifestDigest: manifest.schemaId }
  const issuerOptions = { descriptor, governance, store: operationStore, rootPrivateKey: identity.signing.privateKey, captureFinalTarget: async () => target }
  const issuer = new EnrollmentIssuer(issuerOptions)
  return { descriptor, network, transport, governance, identity, issuer, issuerOptions, target }
}

function bytes(fill: number): Uint8Array { return new Uint8Array(32).fill(fill) }

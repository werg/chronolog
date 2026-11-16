import { capabilityId, capabilityRevisionDigest, encodeGenesisManifest, signGenesis, type CapabilityGrant, type GenesisManifest } from '@chronolog/capabilities'
import { DOMAINS, hashDomain, signDomain } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import {
  EnrollmentIssuer, decodeSignedEnrollmentRequest, encodeEnrollmentApproval, encodeSignedEnrollmentRequest, enrollmentProgress,
  loadEnrollmentApproval, loadEnrollmentIdentity, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest, saveEnrollmentApproval, verifyEnrollmentApproval, verifySignedEnrollmentRequest,
  type EnrollmentDescriptor, type EnrollmentFinalTarget,
} from './enrollment.js'
import { GovernanceControlPlane } from './governance.js'
import { MemoryOperationStore } from './operations.js'

const controllers: GovernanceControlPlane[] = []
afterEach(async () => { await Promise.all(controllers.splice(0).map((controller) => controller.close())) })

describe('live durable group enrollment', () => {
  it('never generates replacement keys while reopening a missing or corrupt device identity', async () => {
    const values = new Map<string, Uint8Array>()
    let writes = 0
    const store = {
      async get(key: string) { return values.get(key)?.slice() ?? null },
      async put(key: string, value: Uint8Array) { writes += 1; values.set(key, value.slice()) },
    }
    await expect(loadEnrollmentIdentity(store, 'peer')).rejects.toThrow('ENROLLMENT_IDENTITY_MISSING')
    expect(writes).toBe(0)
    const identity = await loadOrCreateEnrollmentIdentity(store, 'peer')
    const reopened = await loadEnrollmentIdentity(store, 'peer')
    expect(reopened.signing.publicKeyBytes).toEqual(identity.signing.publicKeyBytes)
    expect(reopened.reader.publicKeyBytes).toEqual(identity.reader.publicKeyBytes)
    expect(writes).toBe(1)
    values.set('enrollment/identity/peer', Uint8Array.of(0))
    await expect(loadEnrollmentIdentity(store, 'peer')).rejects.toThrow()
    expect(writes).toBe(1)
  })

  it('captures one request before asynchronous signing and preserves its exact retry identity', async () => {
    const fixture = await setup(), store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'captured-request')
    const signingKey = identity.signing.publicKeyBytes.slice(), readerKey = identity.reader.publicKeyBytes.slice()
    const input = { descriptor: fixture.descriptor, store, requestId: 'original-request', identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: 'original-feed', requestedRoles: ['reader', 'writer'] as const }
    const pending = prepareEnrollmentRequest(input)
    input.requestId = 'changed-request'; input.transportAuthor = 'changed-feed'
    identity.signing.publicKeyBytes.fill(0); identity.reader.publicKeyBytes.fill(0)
    const request = await pending
    expect(request.request).toMatchObject({ requestId: 'original-request', transportAuthor: 'original-feed', signingPublicKey: signingKey, readerPublicKey: readerKey })
    expect(await verifySignedEnrollmentRequest(request)).toBe(true)
    const reopened = await loadOrCreateEnrollmentIdentity(store, 'captured-request')
    const retry = await prepareEnrollmentRequest({ ...input, identity: reopened.signing, readerPublicKey: reopened.reader.publicKeyBytes,
      requestId: 'original-request', transportAuthor: 'original-feed' })
    expect(retry).toEqual(request)
  })

  it('keeps reviewed permissions and history access independent of subsequent decision edits', async () => {
    const fixture = await setup(), store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'reviewed-decision')
    const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store, requestId: 'join', identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: 'reviewed-feed', requestedRoles: ['reader', 'writer'],
      writerProgram: { sql: true, topics: ['*'], signals: ['*'] } })
    const writerProgram = { sql: false, topics: ['chat/message'], signals: [] as string[] }
    const decision = { operationId: 'reviewed-approval', roles: ['reader', 'writer'] as const, grantFullHistory: false, writerProgram }
    const pending = fixture.issuer.approve(request, decision)
    decision.operationId = 'other-approval'; decision.grantFullHistory = true
    writerProgram.sql = true; writerProgram.topics[0] = '*'; writerProgram.signals.push('*')
    const approval = await pending
    expect(approval.approval).toMatchObject({ fullHistoryGranted: false, writerProgram: { sql: false, topics: ['chat/message'], signals: [], forwarded: false } })
    const grant = fixture.governance.snapshot.capabilities.get(Buffer.from(approval.approval.capabilityIds[1]!).toString('hex'))!.grant
    expect(grant.program).toEqual(approval.approval.writerProgram)
    const retry = await fixture.issuer.approve(request, { operationId: 'reviewed-approval', roles: ['reader', 'writer'], grantFullHistory: false,
      writerProgram: { sql: false, topics: ['chat/message'], signals: [] } })
    expect(retry).toEqual(approval)
  })

  it('persists exactly the approval that was verified when caller data changes during verification', async () => {
    const fixture = await setup(), store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'verified-approval')
    const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store, requestId: 'join', identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: 'verified-feed', requestedRoles: ['reader'] })
    const approval = await fixture.issuer.approve(request, { operationId: 'approve', roles: ['reader'], grantFullHistory: true })
    const original = structuredClone(approval)
    const editableApproval = approval.approval as { fullHistoryGranted: boolean }
    const pending = saveEnrollmentApproval({ descriptor: fixture.descriptor, request, approval, store })
    editableApproval.fullHistoryGranted = false
    await pending
    const saved = await loadEnrollmentApproval(store, request.request)
    expect(saved).toEqual(original)
    await expect(verifyEnrollmentApproval(fixture.descriptor, request, saved!)).resolves.toBeUndefined()
  })

  it('binds explicit SQL, durable topic and signal rights to the signed request and approved grant', async () => {
    const fixture = await setup(), store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'scoped')
    const writerProgram = { sql: true, topics: ['task/claimed', 'chat/message'], signals: ['chat/typing'] }
    const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store, requestId: 'scoped', identity: identity.signing,
      readerPublicKey: identity.reader.publicKeyBytes, transportAuthor: 'scoped', requestedRoles: ['reader', 'writer'], writerProgram })
    const approved = await fixture.issuer.approve(request, { operationId: 'approve-scoped', roles: ['reader', 'writer'], grantFullHistory: true, writerProgram })
    await verifyEnrollmentApproval(fixture.descriptor, request, approved)
    const grant = fixture.governance.snapshot.capabilities.get(Buffer.from(approved.approval.capabilityIds[1]!).toString('hex'))!.grant
    expect(grant.program).toEqual({ ...writerProgram, topics: [...writerProgram.topics].sort(), forwarded: false })
    await expect(fixture.issuer.approve(request, { operationId: 'overbroad', roles: ['reader', 'writer'], grantFullHistory: true,
      writerProgram: { ...writerProgram, topics: ['*'] } })).rejects.toThrow('UNAUTHORIZED')
  })
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

  it('serializes applicants with the same device-local request ID and rejects changes by the same applicant', async () => {
    const fixture = await setup()
    const applicants = await Promise.all(['one', 'two'].map(async (name) => {
      const store = new MemoryOperationStore()
      const identity = await loadOrCreateEnrollmentIdentity(store, name)
      const options = { descriptor: fixture.descriptor, store, requestId: 'join',
        identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
        transportAuthor: name, requestedRoles: ['reader'] as const }
      return { options, request: await prepareEnrollmentRequest(options) }
    }))
    const approvals = await Promise.all(applicants.map(({ request }, i) => fixture.issuer.approve(request,
      { operationId: `approval-${i}`, roles: ['reader'], grantFullHistory: true })))
    expect(approvals.map((signed) => signed.approval.grantedRevision).sort()).toEqual([1n, 2n])
    expect(fixture.governance.snapshot.revision).toBe(2n)
    const reopened = new EnrollmentIssuer(fixture.issuerOptions)
    for (let i = 0; i < applicants.length; i += 1) {
      expect(await reopened.approve(applicants[i]!.request,
        { operationId: `approval-${i}`, roles: ['reader'], grantFullHistory: true })).toEqual(approvals[i])
    }
    const altered = await prepareEnrollmentRequest({ ...applicants[0]!.options,
      store: new MemoryOperationStore(), transportAuthor: 'replacement-feed' })
    await expect(reopened.approve(altered, { operationId: 'altered-approval', roles: ['reader'], grantFullHistory: true }))
      .rejects.toThrow('ENROLLMENT_DECISION_CONFLICT')
    expect(fixture.governance.snapshot.revision).toBe(2n)
  })

  it.each(['subject', 'feed', 'missing-feed', 'reader-key', 'grant-revision'] as const)(
    'rejects a root-signed approval referring to a grant with a different %s binding', async (mismatch) => {
      const fixture = await setup()
      const store = new MemoryOperationStore()
      const identity = await loadOrCreateEnrollmentIdentity(store, 'applicant')
      const request = await prepareEnrollmentRequest({ descriptor: fixture.descriptor, store,
        requestId: 'join', identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
        transportAuthor: 'applicant', requestedRoles: ['reader'] })
      const approved = await fixture.issuer.approve(request,
        { operationId: 'approve', roles: ['reader'], grantFullHistory: true })
      const revision = await fixture.governance.publishCapabilityChange({ grants: [{
        subjectId: mismatch === 'subject' ? bytes(90) : identity.signing.publicKeyBytes,
        signingPublicKey: identity.signing.publicKeyBytes,
        role: 'reader',
        ...(mismatch === 'missing-feed' ? {} : { transportAuthor: mismatch === 'feed' ? 'different-feed' : 'applicant' }),
        hpkePublicKey: mismatch === 'reader-key' ? bytes(91) : identity.reader.publicKeyBytes,
      }] }, fixture.identity.signing.privateKey)
      const approval = { ...approved.approval,
        grantedRevision: mismatch === 'grant-revision' ? approved.approval.grantedRevision : revision.revision.revision,
        membershipRevision: mismatch === 'grant-revision' ? approved.approval.membershipRevision : await capabilityRevisionDigest(revision.revision),
        capabilityIds: [await capabilityId(revision.revision.grants[0]!)],
      }
      const signed = { approval, signature: await signDomain(DOMAINS.enrollmentApproval,
        encodeEnrollmentApproval(approval), fixture.identity.signing.privateKey) }
      await expect(verifyEnrollmentApproval(fixture.descriptor, request, signed)).resolves.toBeUndefined()
      const options = { descriptor: fixture.descriptor, request, activeMembership: fixture.governance.snapshot,
        connected: true, availableEpochs: fixture.governance.cipherRing.epochs(),
        executionManifestDigest: fixture.target.executionManifestDigest, isFinalTargetApplied: () => true }
      expect((await enrollmentProgress({ ...options, approval: approved })).state).toBe('ready')
      await expect(enrollmentProgress({ ...options, approval: signed })).rejects.toThrow('ENROLLMENT_APPROVAL_INVALID')
    },
  )
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
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: identity.signing.publicKeyBytes, schemaAdminPublicKey: identity.signing.publicKeyBytes,
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

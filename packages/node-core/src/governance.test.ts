import {
  encodeSignedCapabilityRevision,
  signCapabilityRevision,
  signGenesis,
  validationPolicyId,
  type CapabilityGrant,
  type CapabilityRevision,
  type GenesisManifest,
  type ValidationPolicy,
} from '@chronolog/capabilities'
import { createEpochManifest, encodeSignedEpochManifest, generateX25519KeyPair } from '@chronolog/crypto'
import { DOMAINS, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair, signDomain } from '@chronolog/protocol'
import { MemoryTransportNetwork } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { CapabilityMembershipResolver } from './capability-membership.js'
import { GovernanceActivationIndex } from './governance-activation.js'
import { GovernanceControlPlane, GovernanceRecordPendingError, isInvalidGovernanceRecord, orderFinalizedGovernanceRecords } from './governance.js'
import { ReferenceRecordLog } from './history-policy.js'
import { createLedgerRecord } from './ledger-record.js'
import { MemoryOperationStore, type DurableOperationStore } from './operations.js'

const controllers: GovernanceControlPlane[] = []
afterEach(async () => { await Promise.all(controllers.splice(0).map((controller) => controller.close())) })

describe('replicated governance control plane', () => {
  it.each(['root', 'feed', 'policy', 'validator-grant', 'validator-revoke'] as const)(
    'rejects a root-signed fixed-history %s change before mutating received or canonical membership', async (change) => {
      const f = await governanceFixture(undefined, true)
      await f.admin.close()
      const received = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.adminTransport, identity: f.root })
      const canonical = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.network.createNode('canonical-fixed-reader'), identity: await generateEd25519KeyPair() })
      controllers.push(received, canonical)
      const initial = received.snapshot, activation = new GovernanceActivationIndex(canonical.snapshot, 'coordinated')
      const validator = [...initial.capabilities.values()].find(capability => capability.grant.role === 'validator')!
      const changes: Record<typeof change, Partial<CapabilityRevision>> = {
        root: { successorRootPublicKey: bytes32(101), successorCapabilityLogFeed: initial.capabilityLogFeed },
        feed: { successorRootPublicKey: initial.rootAdminPublicKey, successorCapabilityLogFeed: new TextEncoder().encode('replacement-admin') },
        policy: { validationPolicies: [{ version: 2n, minimumValidators: 1n }] },
        'validator-grant': { grants: [{ ...grant(bytes32(102), 'validator', { minimumAuthorTimestampMs: 0n }), validFromRevision: 1n }] },
        'validator-revoke': { revocations: [validator.id] },
      }
      const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
      const publish = async (fields: Partial<CapabilityRevision>) => {
        const signed = await signCapabilityRevision({ groupId: f.groupId, revision: 1n,
          previousRevisionDigest: initial.revisionDigest, issuerRootPublicKey: f.root.publicKeyBytes,
          grants: [], revocations: [], validationPolicies: [], ...fields }, f.root.privateKey)
        const payload = encodeCanonicalCbor([1n, encodeSignedCapabilityRevision(signed)])
        const signature = await signDomain(DOMAINS.capabilityRevision, payload, f.root.privateKey)
        const envelope = encodeEnvelope({ groupRoute: f.groupRoute, messageType: 'capability', encryptionEpoch: null,
          payload: encodeCanonicalCbor([1n, payload, f.root.publicKeyBytes, signature]) })
        return { record: await f.adminTransport.publish(envelope), entry: await log.append((await createLedgerRecord(envelope)).recordBytes) }
      }
      const invalid = await publish(changes[change])
      const receivedError = await received.ingest(invalid.record).catch((error: unknown) => error)
      const canonicalError = await canonical.ingestFinalized(invalid.entry, activation.activeSnapshot, 100n).catch((error: unknown) => error)
      expect(isInvalidGovernanceRecord(receivedError)).toBe(true)
      expect(isInvalidGovernanceRecord(canonicalError)).toBe(true)
      expect(received.snapshot).toEqual(initial)
      expect(canonical.snapshot).toEqual(initial)
      const valid = await publish({ grants: [{ ...grant(bytes32(103), 'writer'), validFromRevision: 1n }] })
      expect(await received.ingest(valid.record)).toBe(true)
      const next = await canonical.ingestFinalized(valid.entry, activation.activeSnapshot, 100n)
      expect(next?.revision).toBe(1n)
      activation.activateFinalized(next!, 100n)
      expect(activation.activeSnapshot).toEqual(received.snapshot)
      expect(received.snapshot.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    })

  it('rejects forged controls but retains missing causal predecessors as pending', async () => {
    const fixture = await governanceFixture(), attacker = await generateEd25519KeyPair()
    const participant = await GovernanceControlPlane.create({ genesis: fixture.genesis, groupRoute: fixture.groupRoute,
      transport: fixture.network.createNode('canonical-reader'), identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    let active = participant.snapshot
    const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
    const appendControl = async (type: 'capability' | 'epoch-manifest', body: Uint8Array, tag = 1n, signer = fixture.root) => {
      const payload = encodeCanonicalCbor([tag, body])
      const signature = await signDomain(type === 'capability' ? DOMAINS.capabilityRevision : DOMAINS.epochManifest, payload, signer.privateKey)
      const envelope = encodeEnvelope({ groupRoute: fixture.groupRoute, messageType: type, encryptionEpoch: null,
        payload: encodeCanonicalCbor([1n, payload, signer.publicKeyBytes, signature]) })
      return log.append((await createLedgerRecord(envelope)).recordBytes)
    }
    const future = { groupId: fixture.groupId, revision: 999n, previousRevisionDigest: bytes32(90),
      issuerRootPublicKey: fixture.root.publicKeyBytes, grants: [], revocations: [], validationPolicies: [] }
    const forged = await appendControl('capability', encodeSignedCapabilityRevision(await signCapabilityRevision(future, attacker.privateKey)), 1n, attacker)
    await expect(participant.ingestFinalized(forged, active, 100n)).rejects.toThrow('GOVERNANCE_REVISION_CONFLICT')
    const misplaced = await appendControl('capability', encodeSignedCapabilityRevision(await signCapabilityRevision(future, fixture.root.privateKey)))
    await expect(participant.ingestFinalized(misplaced, active, 100n)).rejects.toThrow('GOVERNANCE_PREDECESSOR_PENDING')
    const capability = await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(44), 'writer')] }, fixture.root.privateKey)
    const accepted = await appendControl('capability', encodeSignedCapabilityRevision(capability))
    active = (await participant.ingestFinalized(accepted, active, 100n))!
    expect(active.revision).toBe(1n)
    const futureEpoch = await createEpochManifest({ groupId: fixture.groupId, epoch: 1n, previousEpochDigest: bytes32(91),
      createdAtMs: 1n, recipients: [], signerPublicKey: fixture.root.publicKeyBytes, signerPrivateKey: fixture.root.privateKey })
    for (const tag of [1n, 2n]) {
      const entry = await appendControl('epoch-manifest', encodeSignedEpochManifest(futureEpoch.signedManifest), tag)
      const failure = await participant.ingestFinalized(entry, active, 100n).catch((error: unknown) => error)
      expect(isInvalidGovernanceRecord(failure)).toBe(false)
      expect(failure).toBeInstanceOf(GovernanceRecordPendingError)
    }
    const firstEpoch = await fixture.admin.rotateEpoch(fixture.root.privateKey)
    await participant.ingestFinalized(await appendControl('epoch-manifest', encodeSignedEpochManifest(firstEpoch)), active, 100n)
    expect(participant.currentEpoch).toBe(0n)
    expect(participant.pendingRecordCount).toBe(0)
  })

  it('resolves reversed included membership and epoch events by signed causality', async () => {
    const f = await governanceFixture()
    await f.admin.publishCapabilityChange({ grants: [grant(bytes32(71), 'writer')] }, f.root.privateKey)
    await f.admin.publishCapabilityChange({ grants: [grant(bytes32(72), 'writer')] }, f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    const authored = await f.adminTransport.history()
    const outcomes = []
    for (const reversed of [false, true]) {
      const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.network.createNode(`causal-${reversed}`), identity: await generateEd25519KeyPair() })
      controllers.push(participant)
      const activation = new GovernanceActivationIndex(participant.snapshot, 'coordinated')
      const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
      const records = []
      for (const record of reversed ? [...authored].reverse() : authored) {
        records.push({ entry: await log.append((await createLedgerRecord(record.payload)).recordBytes), cutoffMs: 500n })
      }
      for (const { entry, cutoffMs } of await orderFinalizedGovernanceRecords(records, f.groupRoute)) {
        const next = await participant.ingestFinalized(entry, activation.activeSnapshot, cutoffMs)
        if (next !== null && next.revision > activation.activeSnapshot.revision) activation.activateFinalized(next, cutoffMs)
      }
      outcomes.push({ snapshot: activation.activeSnapshot, epoch: participant.finalizedEpochAt(501n) })
      expect(participant.finalizedEpochAt(500n)).toEqual(encodeCanonicalCbor(0n))
      expect(participant.hasFinalizedEpoch(encodeCanonicalCbor(1n))).toBe(true)
    }
    expect(outcomes[0]).toEqual(outcomes[1])
    expect(outcomes[0]!.snapshot.revision).toBe(2n)
    expect(outcomes[0]!.epoch).toEqual(encodeCanonicalCbor(1n))
  })

  it('requires every epoch predecessor in the candidate inclusion set before treating the key as issued', async () => {
    const f = await governanceFixture()
    await f.admin.rotateEpoch(f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    const authored = await f.adminTransport.history()
    const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport: f.network.createNode('epoch-inclusion-dependencies'), identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
    const successor = await log.append((await createLedgerRecord(authored[1]!.payload)).recordBytes)
    const predecessor = await log.append((await createLedgerRecord(authored[0]!.payload)).recordBytes)
    await participant.ingestFinalized(predecessor, participant.snapshot, 200n)
    await participant.ingestFinalized(successor, participant.snapshot, 100n)
    expect(participant.hasFinalizedEpoch(encodeCanonicalCbor(1n), successor.position)).toBe(false)
    expect(participant.hasFinalizedEpoch(encodeCanonicalCbor(1n), predecessor.position)).toBe(true)
    expect(participant.finalizedEpochAt(150n)).toEqual(encodeCanonicalCbor(0n))
    expect(participant.finalizedEpochAt(201n)).toEqual(encodeCanonicalCbor(1n))
  })

  it('selects finalized causal predecessors and author-time epoch boundaries when received state is ahead', async () => {
    const f = await governanceFixture()
    await f.admin.publishCapabilityChange({ grants: [grant(bytes32(45), 'writer')] }, f.root.privateKey)
    await f.admin.publishCapabilityChange({ grants: [grant(bytes32(46), 'writer')] }, f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    const transport = f.network.createNode('canonical-ahead-reader')
    const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport, identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    let active = participant.snapshot
    const records = await f.adminTransport.history()
    for (const record of records) { transport.receive(record); await participant.ingest(record) }
    expect(participant.snapshot.revision).toBe(2n)
    expect(participant.currentEpoch).toBe(1n)
    expect(participant.finalizedEpochAt(100n)).toBeNull()
    const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
    const order = async (index: number) => log.append((await createLedgerRecord(records[index]!.payload)).recordBytes)
    await expect(participant.ingestFinalized(await order(1), active, 100n)).rejects.toThrow('GOVERNANCE_PREDECESSOR_PENDING')
    active = (await participant.ingestFinalized(await order(0), active, 100n))!
    expect(active.revision).toBe(1n)
    await expect(participant.ingestFinalized(await order(3), active, 100n)).rejects.toThrow('GOVERNANCE_PREDECESSOR_PENDING')
    const initialEpoch = await order(2)
    await participant.ingestFinalized(initialEpoch, active, 100n)
    expect(participant.finalizedEpochAt(100n)).toEqual(encodeCanonicalCbor(0n))
    expect(participant.finalizedEpochAt(101n)).toEqual(encodeCanonicalCbor(0n))
    // Replaying the same already ordered rotation cannot move its activation.
    await participant.ingestFinalized(initialEpoch, active, 100n)
    expect(participant.finalizedEpochAt(101n)).toEqual(encodeCanonicalCbor(0n))
  })

  it('keeps a relayed governance successor pending until its authenticated predecessor arrives', async () => {
    const fixture = await governanceFixture()
    await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(31), 'writer')] }, fixture.root.privateKey)
    await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(32), 'writer')] }, fixture.root.privateKey)
    const records = await fixture.adminTransport.history()
    const transport = fixture.network.createNode('late-reader')
    transport.receive(records[1]!)
    const participant = await GovernanceControlPlane.create({ genesis: fixture.genesis, groupRoute: fixture.groupRoute,
      transport, identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    await participant.start()
    expect(participant.snapshot.revision).toBe(0n)
    expect(participant.pendingRecordCount).toBe(1)
    transport.receive(records[0]!)
    await waitFor(() => participant.snapshot.revision === 2n)
    expect(participant.pendingRecordCount).toBe(0)
    expect(participant.revisionSnapshots.map((snapshot) => snapshot.revision)).toEqual([0n, 1n, 2n])
  })

  it('continues consuming valid governance after an unauthorized feed replays a control record', async () => {
    const fixture = await governanceFixture()
    const transport = fixture.network.createNode('reader')
    const attacker = fixture.network.createNode('attacker')
    fixture.network.connectAll()
    const participant = await GovernanceControlPlane.create({ genesis: fixture.genesis, groupRoute: fixture.groupRoute,
      transport, identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    await participant.start()
    await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(33), 'writer')] }, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 1n)
    await attacker.publish((await fixture.adminTransport.history())[0]!.payload)
    await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(34), 'writer')] }, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 2n)
  })

  it('does not author a successor before a locally retained predecessor reaches the canonical relay', async () => {
    const fixture = await governanceFixture(new MemoryOperationStore())
    let relayAvailable = false
    Object.assign(fixture.adminTransport, {
      ensurePublished: async () => { if (!relayAvailable) throw new Error('relay offline') },
    })
    await expect(fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(40), 'writer')] }, fixture.root.privateKey, { operationId: 'first' }))
      .rejects.toThrow('relay offline')
    await expect(fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(41), 'writer')] }, fixture.root.privateKey, { operationId: 'second' }))
      .rejects.toThrow('relay offline')
    expect(await fixture.adminTransport.history()).toHaveLength(1)
    relayAvailable = true
    const successor = await fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(41), 'writer')] }, fixture.root.privateKey, { operationId: 'second' })
    expect(successor.revision.revision).toBe(2n)
    expect(await fixture.adminTransport.history()).toHaveLength(2)
  })

  it('recovers the original grant after a lost append response and restart', async () => {
    const operationStore = new MemoryOperationStore()
    const fixture = await governanceFixture(operationStore)
    const publish = fixture.adminTransport.publish.bind(fixture.adminTransport)
    let loseResponse = true
    vi.spyOn(fixture.adminTransport, 'publish').mockImplementation(async (...args) => {
      const record = await publish(...args)
      if (loseResponse) { loseResponse = false; throw new Error('lost append response') }
      return record
    })
    const change = { grants: [grant(bytes32(45), 'writer')] }
    await expect(fixture.admin.publishCapabilityChange(change, fixture.root.privateKey, { operationId: 'approval-1' }))
      .rejects.toThrow('lost append response')
    await fixture.admin.close()
    const reopened = await GovernanceControlPlane.create({
      genesis: fixture.genesis, groupRoute: fixture.groupRoute,
      transport: fixture.adminTransport, identity: fixture.root, operationStore,
      recipient: { id: fixture.root.publicKeyBytes, privateKey: fixture.rootHpke.privateKey },
    })
    controllers.push(reopened)
    await reopened.start()
    const original = await reopened.publishCapabilityChange(change, fixture.root.privateKey, { operationId: 'approval-1' })
    expect(original.revision.revision).toBe(1n)
    expect(reopened.snapshot.revision).toBe(1n)
    expect(await fixture.adminTransport.history()).toHaveLength(1)
    await expect(reopened.publishCapabilityChange({ grants: [grant(bytes32(46), 'writer')] }, fixture.root.privateKey, { operationId: 'approval-1' }))
      .rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('serializes concurrent authoring across signing and durable publication', async () => {
    const fixture = await governanceFixture()
    const [first, second] = await Promise.all([
      fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(40), 'writer')] }, fixture.root.privateKey),
      fixture.admin.publishCapabilityChange({ grants: [grant(bytes32(41), 'writer')] }, fixture.root.privateKey),
    ])
    expect([first.revision.revision, second.revision.revision]).toEqual([1n, 2n])
    expect(fixture.admin.snapshot.revision).toBe(2n)
    const epochs = await Promise.all([
      fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(50)),
      fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(51)),
    ])
    expect(epochs.map((signed) => signed.manifest.epoch)).toEqual([0n, 1n])
    expect(fixture.admin.currentEpoch).toBe(1n)
  })

  it('onboards, revokes, rotates epochs, and grants audit history without restart', async () => {
    const fixture = await governanceFixture()
    const participantSigning = await generateEd25519KeyPair()
    const participantHpke = await generateX25519KeyPair()
    const participantTransport = fixture.network.createNode('participant')
    fixture.network.connectAll()
    const participant = await GovernanceControlPlane.create({
      genesis: fixture.genesis,
      groupRoute: fixture.groupRoute,
      transport: participantTransport,
      identity: participantSigning,
      recipient: { id: participantSigning.publicKeyBytes, privateKey: participantHpke.privateKey },
    })
    controllers.push(participant)
    await participant.start()

    await fixture.admin.publishCapabilityChange({ grants: [
      grant(participantSigning.publicKeyBytes, 'reader', { hpkePublicKey: participantHpke.publicKeyBytes, transportAuthor: 'participant' }),
      grant(participantSigning.publicKeyBytes, 'writer', { transportAuthor: 'participant' }),
      grant(participantSigning.publicKeyBytes, 'validator', { minimumAuthorTimestampMs: 0n, transportAuthor: 'participant' }),
    ] }, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 1n)

    const policyId = await validationPolicyId(fixture.policy)
    const resolver = new CapabilityMembershipResolver({
      snapshotForRevision: (digest) => participant.snapshotForRevision(digest),
    })
    const writerCapability = [...participant.snapshot.capabilities.values()].find((item) =>
      item.grant.role === 'writer' && Buffer.from(item.grant.signingPublicKey).equals(participantSigning.publicKeyBytes))!.id
    expect(await resolver.canWrite({
      groupId: fixture.groupId,
      membershipRevision: participant.snapshot.revisionDigest,
      validationPolicy: policyId,
      writerId: participantSigning.publicKeyBytes,
      writerCapability,
    })).toBe(true)

    await fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(90))
    await waitFor(() => participant.cipherRing.resolve(encodeCanonicalCbor(0n)) !== undefined)
    const participantCapabilities = await fixture.admin.capabilityIdsForSubject(participantSigning.publicKeyBytes)
    await fixture.admin.revoke(participantCapabilities, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 2n)
    await fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(91))
    await waitFor(() => participant.currentEpoch === 1n)

    expect(participant.cipherRing.resolve(encodeCanonicalCbor(0n))).toBeDefined()
    expect(participant.cipherRing.resolve(encodeCanonicalCbor(1n))).toBeUndefined()
    expect(await resolver.canWrite({
      groupId: fixture.groupId,
      membershipRevision: participant.snapshot.revisionDigest,
      validationPolicy: policyId,
      writerId: participantSigning.publicKeyBytes,
      writerCapability,
    })).toBe(false)
    const revokedValidator = participantCapabilities.find((id) => {
      const capability = participant.snapshot.capabilities.get(Buffer.from(id).toString('hex'))
      return capability?.grant.role === 'validator'
    })
    expect(revokedValidator).toBeDefined()
    expect(await resolver.canValidate({
      groupId: fixture.groupId,
      membershipRevision: participant.snapshot.revisionDigest,
      validationPolicy: policyId,
      writerId: fixture.root.publicKeyBytes,
      validatorId: participantSigning.publicKeyBytes,
      validatorCapability: revokedValidator!,
    })).toBe(false)

    const auditorSigning = await generateEd25519KeyPair()
    const auditorHpke = await generateX25519KeyPair()
    const auditorTransport = fixture.network.createNode('auditor')
    fixture.network.connectAll()
    const auditor = await GovernanceControlPlane.create({
      genesis: fixture.genesis,
      groupRoute: fixture.groupRoute,
      transport: auditorTransport,
      identity: auditorSigning,
      recipient: { id: auditorSigning.publicKeyBytes, privateKey: auditorHpke.privateKey },
    })
    controllers.push(auditor)
    await auditor.start()
    await fixture.admin.publishCapabilityChange({ grants: [
      grant(auditorSigning.publicKeyBytes, 'reader', { hpkePublicKey: auditorHpke.publicKeyBytes, transportAuthor: 'auditor' }),
    ] }, fixture.root.privateKey)
    await waitFor(() => auditor.snapshot.revision === 3n)
    expect(await fixture.admin.grantHistoricalAccess(auditorSigning.publicKeyBytes, fixture.root.privateKey)).toBe(2)
    await waitFor(() => auditor.cipherRing.epochs().length === 2)
    expect(auditor.cipherRing.epochs()).toEqual([0n, 1n])
  })
})

async function governanceFixture(operationStore?: DurableOperationStore, fixedHistory = false) {
  const network = new MemoryTransportNetwork()
  const adminTransport = network.createNode('admin')
  const root = await generateEd25519KeyPair()
  const rootHpke = await generateX25519KeyPair()
  const groupId = bytes32(1)
  const groupRoute = bytes32(2)
  const policy: ValidationPolicy = { version: 1n, minimumValidators: 1n }
  const manifest: GenesisManifest = {
    groupId,
    schemaId: bytes32(3),
    rootAdminPublicKey: root.publicKeyBytes, schemaAdminPublicKey: root.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode('admin'),
    initialCapabilities: [
      { ...grant(root.publicKeyBytes, 'administrator', { transportAuthor: 'admin' }), validFromRevision: 0n },
      { ...grant(root.publicKeyBytes, 'writer', { transportAuthor: 'admin' }), validFromRevision: 0n },
      { ...grant(root.publicKeyBytes, 'validator', { minimumAuthorTimestampMs: 0n, transportAuthor: 'admin' }), validFromRevision: 0n },
      { ...grant(root.publicKeyBytes, 'reader', { hpkePublicKey: rootHpke.publicKeyBytes, transportAuthor: 'admin' }), validFromRevision: 0n },
    ],
    validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM',
    createdAtMs: 1n,
    ...(fixedHistory ? { historyPolicy: { kind: 'coordinated' as const, executionManifestDigest: bytes32(3),
      historyId: 'h_0123456789abcdef0123456789abcdef', authorityPublicKey: root.publicKeyBytes } } : {}),
  }
  const genesis = await signGenesis(manifest, root.privateKey)
  const admin = await GovernanceControlPlane.create({
    genesis,
    groupRoute,
    transport: adminTransport,
    identity: root,
    recipient: { id: root.publicKeyBytes, privateKey: rootHpke.privateKey },
    ...(operationStore === undefined ? {} : { operationStore }),
  })
  controllers.push(admin)
  await admin.start()
  return { network, root, rootHpke, adminTransport, genesis, admin, groupId, groupRoute, policy }
}

function grant(
  signingPublicKey: Uint8Array,
  role: CapabilityGrant['role'],
  options: Partial<CapabilityGrant> = {},
): Omit<CapabilityGrant, 'validFromRevision'> & { readonly validFromRevision?: bigint } {
  return {
    subjectId: signingPublicKey,
    signingPublicKey,
    role,
    ...options,
  }
}

async function waitFor(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('governance condition timed out')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

function bytes32(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}

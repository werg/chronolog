import {
  capabilityCodecInternals,
  encodeCapabilityRevision,
  encodeSignedCapabilityRevision,
  signCapabilityRevision,
  signGenesis,
  validationPolicyId,
  type CapabilityGrantInput,
  type CapabilityRevision,
  type GenesisManifest,
  type ValidationPolicy,
} from '@chronolog/capabilities'
import { createEpochManifest, encodeSignedEpochManifest, generateX25519KeyPair } from '@chronolog/crypto'
import { DOMAINS, assertCanonicalCbor, encodeCanonicalCbor, encodeEnvelope, generateEd25519KeyPair,
  integerMap, signDomain, type CborValue } from '@chronolog/protocol'
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
  it.each(['policy', 'validator-grant', 'validator-revoke'] as const)(
    'rejects a root-signed fixed-authority %s change even without a history configuration', async (change) => {
      const f = await governanceFixture()
      await f.admin.close()
      const received = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.adminTransport, identity: f.root })
      const canonical = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.network.createNode('canonical-fixed-reader'), identity: await generateEd25519KeyPair() })
      controllers.push(received, canonical)
      const initial = received.snapshot, activation = new GovernanceActivationIndex(canonical.snapshot)
      const validator = [...initial.capabilities.values()].find(capability => capability.grant.role === 'validator')!
      const changes: Record<typeof change, (wire: Map<CborValue, CborValue>) => void> = {
        policy: wire => { wire.set(8n, [[2n, 1n]]) },
        'validator-grant': wire => { wire.set(5n, [capabilityCodecInternals.grantToCbor({
          ...grant(bytes32(102), 'validator', { minimumAuthorTimestampMs: 0n }), validFromRevision: 1n,
        })]) },
        'validator-revoke': wire => { wire.set(6n, [validator.id]) },
      }
      const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
      const publish = async (fields: Partial<CapabilityRevision>, mutate?: (wire: Map<CborValue, CborValue>) => void) => {
        let revisionBytes = encodeCapabilityRevision({ encryptionEpoch: 0n, groupId: f.groupId, revision: 1n,
          previousRevisionDigest: initial.revisionDigest, issuerRootPublicKey: f.root.publicKeyBytes,
          grants: [], revocations: [], ...fields })
        if (mutate !== undefined) {
          const wire = assertCanonicalCbor(revisionBytes)
          if (!(wire instanceof Map)) throw new Error('REVISION_MAP_REQUIRED')
          mutate(wire)
          revisionBytes = encodeCanonicalCbor(wire)
        }
        // Sign the injected bytes directly: the supported encoder refuses these
        // mutations, but authenticated hostile controls must also fail on receipt.
        const signedBytes = encodeCanonicalCbor(integerMap([
          [0, 1n], [1, revisionBytes], [2, await signDomain(DOMAINS.capabilityRevision, revisionBytes, f.root.privateKey)],
        ]))
        const payload = encodeCanonicalCbor([1n, signedBytes])
        const signature = await signDomain(DOMAINS.capabilityRevision, payload, f.root.privateKey)
        const envelope = encodeEnvelope({ groupRoute: f.groupRoute, messageType: 'capability', encryptionEpoch: null,
          payload: encodeCanonicalCbor([1n, payload, f.root.publicKeyBytes, signature]) })
        return { record: await f.adminTransport.publish(envelope), entry: await log.append((await createLedgerRecord(envelope)).recordBytes) }
      }
      const invalid = await publish({}, changes[change])
      const receivedError = await received.ingest(invalid.record).catch((error: unknown) => error)
      const canonicalError = await canonical.ingestFinalized(invalid.entry, activation.activeSnapshot, 100n).catch((error: unknown) => error)
      expect(isInvalidGovernanceRecord(receivedError)).toBe(true)
      expect(isInvalidGovernanceRecord(canonicalError)).toBe(true)
      expect(received.snapshot).toEqual(initial)
      expect(canonical.snapshot).toEqual(initial)
      const valid = await publish({ grants: [{ ...sqlWriter(bytes32(103)), validFromRevision: 1n }] })
      expect(await received.ingest(valid.record)).toBe(true)
      const next = await canonical.ingestFinalized(valid.entry, activation.activeSnapshot, 100n)
      expect(next?.revision).toBe(1n)
      activation.activateFinalized(next!, 100n)
      expect(activation.activeSnapshot).toEqual(received.snapshot)
      expect(received.snapshot.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    })

  it('rejects forged controls and keeps a key distribution pending until its signed issuing revision arrives', async () => {
    const f = await governanceFixture(), attacker = await generateEd25519KeyPair()
    const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport: f.network.createNode('canonical-reader'), identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    const activation = new GovernanceActivationIndex(participant.snapshot)
    const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
    const appendControl = async (type: 'capability' | 'epoch-manifest', body: Uint8Array, signer = f.root) => {
      const payload = encodeCanonicalCbor([1n, body])
      const signature = await signDomain(type === 'capability' ? DOMAINS.capabilityRevision : DOMAINS.epochManifest, payload, signer.privateKey)
      const envelope = encodeEnvelope({ groupRoute: f.groupRoute, messageType: type, encryptionEpoch: null,
        payload: encodeCanonicalCbor([1n, payload, signer.publicKeyBytes, signature]) })
      return log.append((await createLedgerRecord(envelope)).recordBytes)
    }
    const future = { encryptionEpoch: 0n, groupId: f.groupId, revision: 999n, previousRevisionDigest: bytes32(90),
      issuerRootPublicKey: f.root.publicKeyBytes, grants: [], revocations: [] }
    const forged = await appendControl('capability', encodeSignedCapabilityRevision(await signCapabilityRevision(future, attacker.privateKey)), attacker)
    await expect(participant.ingestFinalized(forged, activation.activeSnapshot, 100n)).rejects.toThrow('GOVERNANCE_REVISION_CONFLICT')
    const misplaced = await appendControl('capability', encodeSignedCapabilityRevision(await signCapabilityRevision(future, f.root.privateKey)))
    await expect(participant.ingestFinalized(misplaced, activation.activeSnapshot, 100n)).rejects.toThrow('GOVERNANCE_PREDECESSOR_PENDING')
    const futureKey = await createEpochManifest({ groupId: f.groupId, epoch: 1n, membershipRevision: bytes32(91),
      createdAtMs: 1n, recipients: [], signerPublicKey: f.root.publicKeyBytes, signerPrivateKey: f.root.privateKey })
    const keyEntry = await appendControl('epoch-manifest', encodeSignedEpochManifest(futureKey.signedManifest))
    await expect(participant.ingestFinalized(keyEntry, activation.activeSnapshot, 100n)).rejects.toBeInstanceOf(GovernanceRecordPendingError)
    const firstKey = await f.admin.initializeEpochKey(f.root.privateKey)
    // Genesis authorizes epoch zero independently of whether this replica has a wrap.
    expect(activation.encryptionEpochStatusAt(100n, encodeCanonicalCbor(0n))).toBe('active')
    await participant.ingestFinalized(await appendControl('epoch-manifest', encodeSignedEpochManifest(firstKey)), activation.activeSnapshot, 100n)
    expect(participant.currentEpoch).toBe(0n)
    expect(participant.pendingRecordCount).toBe(0)
    const conflictingKey = await createEpochManifest({ groupId: f.groupId, epoch: 0n,
      membershipRevision: participant.revisionSnapshots[0]!.revisionDigest, createdAtMs: 2n, recipients: [],
      signerPublicKey: f.root.publicKeyBytes, signerPrivateKey: f.root.privateKey })
    await expect(participant.ingestFinalized(await appendControl('epoch-manifest', encodeSignedEpochManifest(conflictingKey.signedManifest)),
      activation.activeSnapshot, 200n)).rejects.toThrow('GOVERNANCE_EPOCH_KEY_CONFLICT')
  })

  it('resolves reversed included controls by governance causality and activates key identity in that same state', async () => {
    const f = await governanceFixture()
    await f.admin.initializeEpochKey(f.root.privateKey)
    await f.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(71))] }, f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    const authored = await f.adminTransport.history(), outcomes = []
    for (const reversed of [false, true]) {
      const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
        transport: f.network.createNode(`causal-${reversed}`), identity: await generateEd25519KeyPair() })
      controllers.push(participant)
      const activation = new GovernanceActivationIndex(participant.snapshot)
      const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
      const records = []
      for (const record of reversed ? [...authored].reverse() : authored) {
        records.push({ entry: await log.append((await createLedgerRecord(record.payload)).recordBytes), cutoffMs: 500n })
      }
      for (const { entry, cutoffMs } of await orderFinalizedGovernanceRecords(records, f.groupRoute)) {
        const next = await participant.ingestFinalized(entry, activation.activeSnapshot, cutoffMs)
        if (next !== null && next.revision > activation.activeSnapshot.revision) activation.activateFinalized(next, cutoffMs)
      }
      outcomes.push(activation.activeSnapshot)
      expect(activation.encryptionEpochStatusAt(500n, encodeCanonicalCbor(0n))).toBe('active')
      expect(activation.encryptionEpochStatusAt(501n, encodeCanonicalCbor(2n))).toBe('active')
      expect(activation.encryptionEpochStatusAt(501n, encodeCanonicalCbor(0n))).toBe('closed')
      expect(participant.knownEpochs).toEqual([0n, 1n, 2n])
    }
    expect(outcomes[0]).toEqual(outcomes[1])
    expect(outcomes[0]!.revision).toBe(3n)
  })

  it('receives a later epoch key before earlier keys without creating an independent key authority chain', async () => {
    const f = await governanceFixture()
    await f.admin.initializeEpochKey(f.root.privateKey, bytes32(80))
    await f.admin.rotateEpoch(f.root.privateKey, bytes32(81))
    const authored = await f.adminTransport.history()
    const transport = f.network.createNode('out-of-order-keys')
    const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport, identity: f.root, recipient: { id: f.root.publicKeyBytes, privateKey: f.rootHpke.privateKey } })
    controllers.push(participant)
    const activation = new GovernanceActivationIndex(participant.snapshot)
    // A transport can prove the feed while this governance consumer has not indexed the predecessor yet.
    for (const record of authored) transport.receive(record)
    await participant.ingest(authored[2]!)
    expect(participant.pendingRecordCount).toBe(1)
    expect(participant.hasEpochKey(1n)).toBe(false)
    await participant.ingest(authored[1]!)
    expect(participant.hasEpochKey(1n)).toBe(true)
    expect(participant.hasEpochKey(0n)).toBe(false)
    expect(activation.encryptionEpochStatusAt(201n, encodeCanonicalCbor(1n))).toBe('unissued')
    activation.observe(participant.snapshot)
    activation.activateFinalized(participant.snapshot, 200n)
    expect(activation.encryptionEpochStatusAt(200n, encodeCanonicalCbor(0n))).toBe('active')
    expect(activation.encryptionEpochStatusAt(201n, encodeCanonicalCbor(1n))).toBe('active')
    await participant.ingest(authored[0]!)
    expect(participant.hasEpochKey(0n)).toBe(true)
    expect(activation.encryptionEpochStatusAt(201n, encodeCanonicalCbor(0n))).toBe('closed')
  })

  it('keeps received keys and later governance separate from the finalized author-time state', async () => {
    const f = await governanceFixture()
    await f.admin.initializeEpochKey(f.root.privateKey)
    await f.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(45))] }, f.root.privateKey)
    await f.admin.rotateEpoch(f.root.privateKey)
    const transport = f.network.createNode('canonical-ahead-reader')
    const participant = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport, identity: await generateEd25519KeyPair() })
    controllers.push(participant)
    const activation = new GovernanceActivationIndex(participant.snapshot)
    const records = await f.adminTransport.history()
    for (const record of records) { transport.receive(record); await participant.ingest(record) }
    expect(participant.snapshot.revision).toBe(2n)
    expect(participant.currentEpoch).toBe(1n)
    const log = await ReferenceRecordLog.open('h_0123456789abcdef0123456789abcdef', new MemoryOperationStore())
    const order = async (index: number) => log.append((await createLedgerRecord(records[index]!.payload)).recordBytes)
    await expect(participant.ingestFinalized(await order(2), activation.activeSnapshot, 100n)).rejects.toThrow('GOVERNANCE_PREDECESSOR_PENDING')
    const grant = (await participant.ingestFinalized(await order(1), activation.activeSnapshot, 100n))!
    activation.activateFinalized(grant, 100n)
    await participant.ingestFinalized(await order(3), activation.activeSnapshot, 100n)
    expect(activation.encryptionEpochStatusAt(101n, encodeCanonicalCbor(0n))).toBe('active')
    const rotation = (await participant.ingestFinalized(await order(2), activation.activeSnapshot, 200n))!
    activation.activateFinalized(rotation, 200n)
    expect(activation.encryptionEpochStatusAt(201n, encodeCanonicalCbor(1n))).toBe('active')
    await participant.ingestFinalized(await order(0), activation.activeSnapshot, 300n)
    expect(activation.encryptionEpochStatusAt(201n, encodeCanonicalCbor(0n))).toBe('closed')
  })

  it('keeps a relayed governance successor pending until its authenticated predecessor arrives', async () => {
    const fixture = await governanceFixture()
    await fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(31))] }, fixture.root.privateKey)
    await fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(32))] }, fixture.root.privateKey)
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
    await fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(33))] }, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 1n)
    await attacker.publish((await fixture.adminTransport.history())[0]!.payload)
    await fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(34))] }, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 2n)
  })

  it('does not author a successor before a locally retained predecessor reaches the canonical relay', async () => {
    const fixture = await governanceFixture(new MemoryOperationStore())
    let relayAvailable = false
    Object.assign(fixture.adminTransport, {
      ensurePublished: async () => { if (!relayAvailable) throw new Error('relay offline') },
    })
    await expect(fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(40))] }, fixture.root.privateKey, { operationId: 'first' }))
      .rejects.toThrow('relay offline')
    await expect(fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(41))] }, fixture.root.privateKey, { operationId: 'second' }))
      .rejects.toThrow('relay offline')
    expect(await fixture.adminTransport.history()).toHaveLength(1)
    relayAvailable = true
    const successor = await fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(41))] }, fixture.root.privateKey, { operationId: 'second' })
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
    const change = { grants: [sqlWriter(bytes32(45))] }
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
    await expect(reopened.publishCapabilityChange({ grants: [sqlWriter(bytes32(46))] }, fixture.root.privateKey, { operationId: 'approval-1' }))
      .rejects.toThrow('OPERATION_ID_CONFLICT')
  })

  it('serializes concurrent authoring across signing and durable publication', async () => {
    const fixture = await governanceFixture()
    const [first, second] = await Promise.all([
      fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(40))] }, fixture.root.privateKey),
      fixture.admin.publishCapabilityChange({ grants: [sqlWriter(bytes32(41))] }, fixture.root.privateKey),
    ])
    expect([first.revision.revision, second.revision.revision]).toEqual([1n, 2n])
    expect(fixture.admin.snapshot.revision).toBe(2n)
    const epochs = await Promise.all([
      fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(50)),
      fixture.admin.rotateEpoch(fixture.root.privateKey, bytes32(51)),
    ])
    expect(epochs.map(signed => signed.revision.encryptionEpoch)).toEqual([1n, 2n])
    expect(fixture.admin.currentEpoch).toBe(2n)
  })

  it('recovers an atomic reader revocation and key rotation after losing the first publication reply', async () => {
    const store = new MemoryOperationStore(), f = await governanceFixture(store)
    await f.admin.initializeEpochKey(f.root.privateKey, bytes32(80), { operationId: 'genesis-key' })
    const reader = [...f.admin.snapshot.capabilities.values()].find(item => item.grant.role === 'reader')!
    const publish = f.adminTransport.publish.bind(f.adminTransport)
    let fail = true
    vi.spyOn(f.adminTransport, 'publish').mockImplementation(async (payload, options) => {
      const record = await publish(payload, options)
      if (fail) { fail = false; throw new Error('publication reply lost') }
      return record
    })
    await expect(f.admin.revoke([reader.id], f.root.privateKey, { operationId: 'revoke-reader' })).rejects.toThrow('publication reply lost')
    await f.admin.close()
    const reopened = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.groupRoute,
      transport: f.adminTransport, identity: f.root, operationStore: store,
      recipient: { id: f.root.publicKeyBytes, privateKey: f.rootHpke.privateKey } })
    controllers.push(reopened)
    await reopened.start()
    expect(reopened.snapshot).toMatchObject({ revision: 1n, encryptionEpoch: 1n })
    expect(reopened.snapshot.capabilities.get(Buffer.from(reader.id).toString('hex'))?.revokedAtRevision).toBe(1n)
    expect(reopened.hasEpochKey(0n)).toBe(true)
    expect(reopened.hasEpochKey(1n)).toBe(true)
    const records = await f.adminTransport.history()
    expect(records).toHaveLength(3)
    const retry = await reopened.revoke([reader.id], f.root.privateKey, { operationId: 'revoke-reader' })
    expect(retry.revision).toMatchObject({ revision: 1n, encryptionEpoch: 1n, revocations: [reader.id] })
    expect(await f.adminTransport.history()).toEqual(records)
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
      sqlWriter(participantSigning.publicKeyBytes, { transportAuthor: 'participant' }),
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

    await fixture.admin.initializeEpochKey(fixture.root.privateKey, bytes32(90))
    await waitFor(() => participant.cipherRing.resolve(encodeCanonicalCbor(0n)) !== undefined)
    const participantCapabilities = await fixture.admin.capabilityIdsForSubject(participantSigning.publicKeyBytes)
    await fixture.admin.revoke(participantCapabilities, fixture.root.privateKey)
    await waitFor(() => participant.snapshot.revision === 2n)
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

async function governanceFixture(operationStore?: DurableOperationStore) {
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
      { ...sqlWriter(root.publicKeyBytes, { transportAuthor: 'admin' }), validFromRevision: 0n },
      { ...grant(root.publicKeyBytes, 'validator', { minimumAuthorTimestampMs: 0n, transportAuthor: 'admin' }), validFromRevision: 0n },
      { ...grant(root.publicKeyBytes, 'reader', { hpkePublicKey: rootHpke.publicKeyBytes, transportAuthor: 'admin' }), validFromRevision: 0n },
    ],
    validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM',
    createdAtMs: 1n,

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

type GrantOptions = { readonly transportAuthor?: string; readonly minimumAuthorTimestampMs?: bigint; readonly hpkePublicKey?: Uint8Array }

function grant(signingPublicKey: Uint8Array, role: 'reader', options?: GrantOptions): CapabilityGrantInput & { readonly role: 'reader' }
function grant(signingPublicKey: Uint8Array, role: 'validator', options?: GrantOptions): CapabilityGrantInput & { readonly role: 'validator' }
function grant(
  signingPublicKey: Uint8Array,
  role: 'reader' | 'validator',
  options: GrantOptions = {},
): CapabilityGrantInput {
  const identity = { subjectId: signingPublicKey, signingPublicKey, ...options }
  return role === 'reader' ? { ...identity, role: 'reader' } : { ...identity, role: 'validator' }
}

function sqlWriter(signingPublicKey: Uint8Array, options: { readonly transportAuthor?: string } = {}): CapabilityGrantInput & { readonly role: 'writer' } {
  return { subjectId: signingPublicKey, signingPublicKey, role: 'writer',
    program: { sql: true, topics: [], signals: [] }, ...options }
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

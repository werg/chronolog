import { encodeGenesisManifest, reduceCapabilityLog, signGenesis, type CapabilityGrant, type GenesisManifest } from '@chronolog/capabilities'
import {
  bytesToHex, decodeValidatorAttestation, encodeEnvelope, encodeValidatorAttestation,
  equalBytes, generateEd25519KeyPair, type Ed25519KeyPair,
} from '@chronolog/protocol'
import { MemoryTransportNetwork, type ChronologTransport } from '@chronolog/transport-ssb'
import { afterEach, describe, expect, it } from 'vitest'

import { encodeSignedGovernanceClosure, signGovernanceClosure } from './peer-governance-proof.js'
import { GovernanceControlPlane } from './governance.js'
import { DurableOperationJournal, MemoryOperationStore } from './operations.js'
import { PeerGovernanceController } from './peer-governance.js'
import { decodeSignedEnvelope, encodeSignedEnvelope } from './wire.js'

const closeables: Array<{ close(): Promise<void> }> = []
afterEach(async () => { for (const item of closeables.splice(0).reverse()) await item.close() })

describe('live peer governance activation controller', () => {
  it('keeps a received grant pending until every fixed validator durably closes the preceding revision', async () => {
    const f = await fixture()
    const first = f.controller(0)
    await first.start()
    await f.governance[0]!.publishCapabilityChange({ grants: [{ subjectId: bytes(60), signingPublicKey: bytes(60), role: 'writer', program: { sql: true, topics: [], signals: [] } }] }, f.identities[0].privateKey)
    await first.refresh()
    expect(first.activeSnapshot.revision).toBe(0n)
    expect(first.closedAdmissionRevisions().some(item => equalBytes(item.membershipRevision, f.initial.revisionDigest))).toBe(false)
    await waitFor(() => f.governance[1]!.snapshot.revision === 1n)
    const second = f.controller(1)
    await second.start()
    await first.refresh()
    expect(first.activeSnapshot.revision).toBe(1n)
    expect(first.minimumAuthorTimestampMs).toBe(1_001n)
    expect(first.closedAdmissionRevisions().some(item => equalBytes(item.membershipRevision, f.initial.revisionDigest))).toBe(true)
    const closure = (await f.transports[0]!.history()).filter((record) => record.author === f.transports[0]!.identity).at(-1)!
    expect(await first.allowsAttestation(f.initial.revisionDigest, f.identities[0].publicKeyBytes, closure.sequence + 1n)).toBe(false)
    expect(await first.allowsAttestation(first.activeSnapshot.revisionDigest, f.identities[0].publicKeyBytes, closure.sequence + 1n)).toBe(true)
  })

  it('requires the full admission feed prefix and reports its referenced transactions', async () => {
    const f = await fixture()
    const validator = [...f.initial.capabilities.values()].find((item) => item.grant.role === 'validator' && equalBytes(item.grant.signingPublicKey, f.identities[1].publicKeyBytes))!
    const txId = new TextEncoder().encode('tx_prior-admission')
    const admission = await f.transports[1]!.publish(await encodeSignedEnvelope(f.route, 'attestation', encodeValidatorAttestation({
      groupId: f.initial.groupId, membershipRevision: f.initial.revisionDigest, validatorCapability: validator.id,
      txId, validatorId: f.identities[1].publicKeyBytes, authorTimestampMs: 900n,
      acceptedAboveMs: 100n, candidateDigest: bytes(90), decision: 'admit', policyVersion: 1n,
    }), f.identities[1]))
    await f.governance[0]!.publishCapabilityChange({ grants: [{ subjectId: bytes(61), signingPublicKey: bytes(61), role: 'writer', program: { sql: true, topics: [], signals: [] } }] }, f.identities[0].privateKey)
    await waitFor(() => f.governance[1]!.snapshot.revision === 1n)
    const a = f.controller(0), b = f.controller(1)
    await a.start(); await b.start(); await a.refresh()
    expect(a.closedAdmissionRevisions().find(item => equalBytes(item.membershipRevision, f.initial.revisionDigest))?.proposalIds).toEqual([txId])

    const transport = f.network.createNode('observer')
    const all = await f.transports[0]!.history()
    for (const record of all) if (record.id !== admission.id) transport.receive(record)
    const identity = await generateEd25519KeyPair()
    const governance = await GovernanceControlPlane.create({ genesis: f.genesis, groupRoute: f.route, transport, identity })
    closeables.push(governance); await governance.start()
    const observer = new PeerGovernanceController({ genesis: f.initial, governance, groupRoute: f.route, transport, identity,
      store: new MemoryOperationStore(), closeRevision: async () => { throw new Error('reader must not sign validator closure') } })
    closeables.push(observer); await observer.start()
    expect(observer.activeSnapshot.revision).toBe(0n)
    transport.receive(admission)
    await observer.refresh()
    expect(observer.activeSnapshot.revision).toBe(1n)
    expect(observer.closedAdmissionRevisions().find(item => equalBytes(item.membershipRevision, f.initial.revisionDigest))?.proposalIds).toEqual([txId])
  })

  it('blocks an incomplete restore instead of reopening already closed membership', async () => {
    const f = await fixture()
    await f.governance[0]!.publishCapabilityChange({ grants: [{ subjectId: bytes(62), signingPublicKey: bytes(62), role: 'writer', program: { sql: true, topics: [], signals: [] } }] }, f.identities[0].privateKey)
    await waitFor(() => f.governance[1]!.snapshot.revision === 1n)
    const a = f.controller(0), b = f.controller(1)
    await a.start(); await b.start(); await a.refresh()
    const identity = await generateEd25519KeyPair()
    const store = new MemoryOperationStore()
    const transport = f.network.createNode('reopening-reader')
    for (const record of await f.transports[0]!.history()) transport.receive(record)
    const options = { genesis: f.initial, governance: f.governance[0]!, groupRoute: f.route, transport, identity, store,
      closeRevision: async () => { throw new Error('reader must not close') } }
    const reader = new PeerGovernanceController(options)
    await reader.start(); expect(reader.activeSnapshot.revision).toBe(1n); await reader.close()
    const empty = f.network.createNode('restored-reader')
    const restored = new PeerGovernanceController({ ...options, transport: empty })
    closeables.push(restored); await restored.start()
    expect(restored.ready).toBe(false)
    expect(restored.lastError).toBe('GOVERNANCE_ACTIVATION_RECOVERY_PENDING')
    for (const record of await transport.history()) empty.receive(record)
    await restored.refresh()
    expect(restored.ready).toBe(true)
    expect(restored.activeSnapshot.revision).toBe(1n)
  })
})

async function fixture() {
  const network = new MemoryTransportNetwork()
  const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
  const transports = [network.createNode('admin'), network.createNode('validator')]
  network.connectAll()
  const initialCapabilities: CapabilityGrant[] = identities.flatMap((identity, i) => [
    { subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes, role: 'writer', program: { sql: true, topics: [], signals: [] }, validFromRevision: 0n, transportAuthor: transports[i]!.identity },
    { subjectId: identity.publicKeyBytes, signingPublicKey: identity.publicKeyBytes, role: 'validator', validFromRevision: 0n, transportAuthor: transports[i]!.identity, minimumAuthorTimestampMs: 0n },
  ])
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: identities[0].publicKeyBytes, schemaAdminPublicKey: identities[0].publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode(transports[0]!.identity), initialCapabilities,
    validationPolicies: [{ version: 1n, minimumValidators: 2n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }
  encodeGenesisManifest(manifest)
  const genesis = await signGenesis(manifest, identities[0].privateKey)
  const initial = await reduceCapabilityLog(genesis, [])
  const route = bytes(3)
  const stores = [new MemoryOperationStore(), new MemoryOperationStore()]
  const governance = await Promise.all(transports.map((transport, i) => GovernanceControlPlane.create({
    genesis, groupRoute: route, transport, identity: identities[i]!, operationStore: stores[i]!,
  })))
  closeables.push(...governance)
  await Promise.all(governance.map((plane) => plane.start()))
  const controller = (index: number) => {
    const store = stores[index]!
    const result = new PeerGovernanceController({ genesis: initial, governance: governance[index]!, groupRoute: route,
      identity: identities[index]!, transport: transports[index]!, store,
      closeRevision: closurePublisher(transports[index]!, identities[index]!, governance[index]!, route, store),
    })
    closeables.push(result)
    return result
  }
  return { network, identities, transports, governance, genesis, initial, route, controller }
}

function closurePublisher(transport: ChronologTransport, identity: Ed25519KeyPair, governance: GovernanceControlPlane, route: Uint8Array, store: MemoryOperationStore) {
  const journal = new DurableOperationJournal(store, 'test-validator-closures')
  return async (previous: Uint8Array, next: Uint8Array) => {
    const payload = await journal.run({
      operationId: bytesToHex(previous), fingerprint: next,
      prepare: async () => {
        const snapshot = governance.snapshotForRevision(previous)!
        const capability = [...snapshot.capabilities.values()].find((item) => item.grant.role === 'validator' && equalBytes(item.grant.signingPublicKey, identity.publicKeyBytes))!
        let lastAdmissionSequence = 0n
        let throughMs = 1_000n
        for (const record of await transport.history()) {
          if (record.author !== transport.identity) continue
          try {
            const wire = await decodeSignedEnvelope(record.payload, route)
            if (wire.type !== 'attestation') continue
            const attestation = decodeValidatorAttestation(wire.payload)
            if (!equalBytes(attestation.membershipRevision, previous)) continue
            lastAdmissionSequence = record.sequence > lastAdmissionSequence ? record.sequence : lastAdmissionSequence
            throughMs = attestation.authorTimestampMs > throughMs ? attestation.authorTimestampMs : throughMs
          } catch { /* only signed transaction envelopes carry admissions */ }
        }
        const signed = await signGovernanceClosure({ groupId: snapshot.groupId, membershipRevision: previous,
          nextMembershipRevision: next, validatorId: identity.publicKeyBytes, validatorCapability: capability.id,
          throughMs, lastAdmissionSequence }, identity.privateKey)
        return encodeEnvelope({ groupRoute: route, messageType: 'proof-bundle', encryptionEpoch: null, payload: encodeSignedGovernanceClosure(signed) })
      },
      apply: async (bytes) => {
        if (!(await transport.history()).some((record) => record.author === transport.identity && equalBytes(record.payload, bytes))) await transport.publish(bytes)
      },
    })
    return (await transport.history()).find((record) => record.author === transport.identity && equalBytes(record.payload, payload))!
  }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const until = Date.now() + 3_000
  while (!predicate()) {
    if (Date.now() > until) throw new Error('governance replication timed out')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}
function bytes(fill: number): Uint8Array { return new Uint8Array(32).fill(fill) }

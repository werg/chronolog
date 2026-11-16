import { encodeGenesisManifest, reduceCapabilityLog, signGenesis, type GenesisManifest } from '@chronolog/capabilities'
import {
  MemoryOperationStore, decodeSignedEnrollmentRequest, loadOrCreateEnrollmentIdentity, prepareEnrollmentRequest,
  type EnrollmentDescriptor, type GovernanceControlPlane,
} from '@chronolog/node-core'
import { DOMAINS, hashDomain } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { createEnrollmentService } from './enrollment-service.js'

describe('live daemon enrollment service', () => {
  it('requests membership using the running replica identity and recovers the exact request', async () => {
    const fixture = await setup()
    const service = createEnrollmentService(fixture.options)
    const first = await service.createRequest({ requestId: 'join', roles: ['reader', 'writer'] })
    const retry = await service.createRequest({ requestId: 'join', roles: ['reader', 'writer'] })
    expect(first).toEqual(retry)
    const signed = decodeSignedEnrollmentRequest(Uint8Array.from(Buffer.from(first.signedRequest, 'base64url')))
    expect(signed.request.signingPublicKey).toEqual(fixture.options.identity.publicKeyBytes)
    expect(signed.request.transportAuthor).toBe('local-feed')
    expect((await service.getStatus({ requestId: 'join' })).state).toBe('requested')
    await expect(service.approveRequest({ requestId: 'approval', signedRequest: first.signedRequest, roles: ['reader'], grantFullHistory: true }))
      .rejects.toThrow('ENROLLMENT_ISSUER_UNAVAILABLE')
  })

  it('does not use this daemon’s keys and history to claim readiness for another device', async () => {
    const fixture = await setup()
    const other = await loadOrCreateEnrollmentIdentity(new MemoryOperationStore(), 'other')
    await prepareEnrollmentRequest({ descriptor: fixture.options.descriptor, store: fixture.options.store,
      requestId: 'other-device', identity: other.signing, readerPublicKey: other.reader.publicKeyBytes,
      transportAuthor: 'other-feed', requestedRoles: ['reader'] })
    await expect(createEnrollmentService(fixture.options).getStatus({ requestId: 'other-device' }))
      .rejects.toThrow('ENROLLMENT_REQUEST_NOT_LOCAL')
  })
})

async function setup() {
  const store = new MemoryOperationStore()
  const identity = await loadOrCreateEnrollmentIdentity(store, 'local')
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: identity.signing.publicKeyBytes,
    capabilityLogFeed: new TextEncoder().encode('admin'), initialCapabilities: [],
    validationPolicies: [{ version: 1n, minimumValidators: 1n }],
    clockPolicy: { maxFutureSkewMs: 30_000n, cutoffLagMs: 1_000n, heartbeatIntervalMs: 1_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'HPKE-X25519-HKDF-SHA256-AES-256-GCM', createdAtMs: 1n,
  }
  const genesis = await signGenesis(manifest, identity.signing.privateKey)
  const snapshot = await reduceCapabilityLog(genesis, [])
  const descriptor: EnrollmentDescriptor = { genesis, groupRoute: bytes(3), history: {
    kind: 'peer', groupId: manifest.groupId, executionManifestDigest: manifest.schemaId,
    genesisDigest: await hashDomain(DOMAINS.genesis, encodeGenesisManifest(manifest)),
  } }
  return { options: { descriptor, store, identity: identity.signing, readerPublicKey: identity.reader.publicKeyBytes,
    transportAuthor: 'local-feed', governance: { cipherRing: { epochs: () => [] } } as unknown as GovernanceControlPlane,
    activeMembership: () => snapshot, connected: () => true, executionManifestDigest: manifest.schemaId,
    isFinalTargetApplied: () => true } }
}

function bytes(fill: number): Uint8Array { return new Uint8Array(32).fill(fill) }

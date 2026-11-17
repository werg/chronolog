import { describe, expect, it } from 'vitest'
import {
  generateEd25519KeyPair,
} from '@chronolog/protocol'
import {
  capabilityId,
  canReaderAccessRevision,
  decodeSignedCapabilityRevision,
  decodeSignedGenesis,
  encodeSignedCapabilityRevision,
  encodeSignedGenesis,
  evaluateValidationPolicy,
  hasRole,
  reduceCapabilityLog,
  signCapabilityRevision,
  signGenesis,
  type CapabilityGrant,
  type GenesisManifest,
  type ValidationPolicy,
  type ValidatorEvidence,
} from './index.js'

const bytes = (value: number, length = 32) => new Uint8Array(length).fill(value)

function validator(subject: number, floor: bigint): CapabilityGrant {
  return {
    subjectId: bytes(subject), signingPublicKey: bytes(subject), role: 'validator', validFromRevision: 0n,
    minimumAuthorTimestampMs: floor,
  }
}

const policy: ValidationPolicy = {
  version: 1n,
  minimumValidators: 3n,
}

async function fixture() {
  const root = await generateEd25519KeyPair()
  const writer: CapabilityGrant = {
    subjectId: bytes(20), signingPublicKey: bytes(20), role: 'writer', program: { sql: true, topics: [], signals: [], forwarded: false }, validFromRevision: 0n,
  }
  const initialValidator = validator(21, 1_000n)
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: root.publicKeyBytes, schemaAdminPublicKey: root.publicKeyBytes,
    capabilityLogFeed: bytes(3),
    initialCapabilities: [writer, initialValidator], validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 60_000n, cutoffLagMs: 300_000n, heartbeatIntervalMs: 30_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM', createdAtMs: 10n,
  }
  return { root, writer, initialValidator, signedGenesis: await signGenesis(manifest, root.privateKey) }
}

describe('capability chain', () => {
  it('rejects implicit SQL authority and nonexistent administration grants at the signed boundary', async () => {
    const f = await fixture()
    const missing = structuredClone(f.writer)
    Reflect.deleteProperty(missing, 'program')
    await expect(signGenesis({ ...f.signedGenesis.manifest, initialCapabilities: [missing] }, f.root.privateKey))
      .rejects.toThrow('Writer grants require explicit program rights')
    const phantom = { subjectId: bytes(20), signingPublicKey: bytes(20), role: 'administrator', validFromRevision: 0n }
    await expect(signGenesis({ ...f.signedGenesis.manifest,
      initialCapabilities: [phantom as unknown as CapabilityGrant] }, f.root.privateKey))
      .rejects.toThrow('Unknown capability role')
  })

  it('reduces grants, prospective revocation and epoch changes deterministically', async () => {
    const f = await fixture()
    expect(decodeSignedGenesis(encodeSignedGenesis(f.signedGenesis))).toEqual(f.signedGenesis)
    const initial = await reduceCapabilityLog(f.signedGenesis, [])
    expect(hasRole(initial, bytes(20), 'writer')).toBe(true)
    const writerId = await capabilityId(f.writer)
    const revision = await signCapabilityRevision({ encryptionEpoch: 0n,
      groupId: bytes(1), revision: 1n, previousRevisionDigest: initial.revisionDigest,
      issuerRootPublicKey: f.root.publicKeyBytes,
      grants: [{ ...f.writer, subjectId: bytes(22), signingPublicKey: bytes(22), validFromRevision: 1n }], revocations: [writerId],
    }, f.root.privateKey)
    const roundTrippedRevision = decodeSignedCapabilityRevision(encodeSignedCapabilityRevision(revision))
    const state = await reduceCapabilityLog(f.signedGenesis, [roundTrippedRevision])
    expect(state.revision).toBe(1n)
    expect(state.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    expect(hasRole(state, bytes(20), 'writer', 0n)).toBe(true)
    expect(hasRole(state, bytes(20), 'writer', 1n)).toBe(false)
    expect(hasRole(state, bytes(22), 'writer')).toBe(true)
    expect(hasRole(state, bytes(21), 'validator')).toBe(true)
    expect(state.policies).toEqual(initial.policies)
    expect([...state.capabilities.values()].find(item => item.grant.role === 'validator')?.grant)
      .toEqual(f.initialValidator)
  })
})

describe('validation policy', () => {
  it('selects the smallest distinct capability ids, independent of evidence order', () => {
    const evidence: ValidatorEvidence[] = [
      { capabilityId: bytes(4), validatorId: bytes(14) },
      { capabilityId: bytes(3), validatorId: bytes(13) },
      { capabilityId: bytes(2), validatorId: bytes(12) },
      { capabilityId: bytes(1), validatorId: bytes(11) },
      { capabilityId: bytes(1), validatorId: bytes(11) },
    ]
    const result = evaluateValidationPolicy(policy, evidence)
    expect(result.satisfied).toBe(true)
    expect(result.selected.map((item) => item.capabilityId[0])).toEqual([1, 2, 3])
    expect(evaluateValidationPolicy(policy, [...evidence].reverse()).selected).toEqual(result.selected)
  })

  it('counts distinct capabilities against the threshold', () => {
    const duplicate = { capabilityId: bytes(1), validatorId: bytes(11) }
    const result = evaluateValidationPolicy(policy, [duplicate, duplicate, duplicate])
    expect(result.satisfied).toBe(false)
    expect(result.missing).toEqual(['validators:2'])
  })
})

describe('reader access', () => {
  it('keeps readers prospective from the revision that granted them', () => {
    const base = {
      id: bytes(1),
      grantedAtRevision: 5n,
      grant: {
        subjectId: bytes(2), signingPublicKey: bytes(2), role: 'reader' as const,
        validFromRevision: 5n, hpkePublicKey: bytes(3),
      },
    }
    expect(canReaderAccessRevision(base, 4n)).toBe(false)
    expect(canReaderAccessRevision(base, 5n)).toBe(true)
  })
})

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

function validator(subject: number, revision: bigint, floor: bigint, organization: string, validatorClass = 'general'): CapabilityGrant {
  return {
    subjectId: bytes(subject), signingPublicKey: bytes(subject), role: 'validator', validFromRevision: revision,
    organization, validatorClass, minimumAuthorTimestampMs: floor,
  }
}

const policy: ValidationPolicy = {
  version: 1n,
  minimumValidators: 3n,
  classMinimums: new Map([['auditor', 1n]]),
  requiredOrganizations: ['A', 'B'],
}

async function fixture() {
  const root = await generateEd25519KeyPair()
  const writer: CapabilityGrant = {
    subjectId: bytes(20), signingPublicKey: bytes(20), role: 'writer', validFromRevision: 0n,
  }
  const initialValidator = validator(21, 0n, 1_000n, 'A', 'auditor')
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: root.publicKeyBytes,
    capabilityLogFeed: bytes(3),
    initialCapabilities: [writer, initialValidator], validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 60_000n, cutoffLagMs: 300_000n, heartbeatIntervalMs: 30_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM', createdAtMs: 10n,
  }
  return { root, writer, initialValidator, signedGenesis: await signGenesis(manifest, root.privateKey) }
}

describe('capability chain', () => {
  it('reduces grants, prospective revocation and root succession deterministically', async () => {
    const f = await fixture()
    expect(decodeSignedGenesis(encodeSignedGenesis(f.signedGenesis))).toEqual(f.signedGenesis)
    const initial = await reduceCapabilityLog(f.signedGenesis, [])
    expect(hasRole(initial, bytes(20), 'writer')).toBe(true)
    const writerId = await capabilityId(f.writer)
    const nextRoot = await generateEd25519KeyPair()
    const revision = await signCapabilityRevision({
      groupId: bytes(1), revision: 1n, previousRevisionDigest: initial.revisionDigest,
      issuerRootPublicKey: f.root.publicKeyBytes,
      grants: [validator(22, 1n, 1_000n, 'B')], revocations: [writerId], validationPolicies: [],
      successorRootPublicKey: nextRoot.publicKeyBytes, successorCapabilityLogFeed: bytes(8),
    }, f.root.privateKey)
    const roundTrippedRevision = decodeSignedCapabilityRevision(encodeSignedCapabilityRevision(revision))
    const state = await reduceCapabilityLog(f.signedGenesis, [roundTrippedRevision])
    expect(state.revision).toBe(1n)
    expect(state.rootAdminPublicKey).toEqual(nextRoot.publicKeyBytes)
    expect(hasRole(state, bytes(20), 'writer', 0n)).toBe(true)
    expect(hasRole(state, bytes(20), 'writer', 1n)).toBe(false)
  })

  it('rejects a new validator whose floor reopens timestamp history', async () => {
    const f = await fixture()
    const initial = await reduceCapabilityLog(f.signedGenesis, [])
    const revision = await signCapabilityRevision({
      groupId: bytes(1), revision: 1n, previousRevisionDigest: initial.revisionDigest,
      issuerRootPublicKey: f.root.publicKeyBytes,
      grants: [validator(22, 1n, 999n, 'B')], revocations: [], validationPolicies: [],
    }, f.root.privateKey)
    await expect(reduceCapabilityLog(f.signedGenesis, [revision])).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })
})

describe('validation policy', () => {
  it('selects a deterministic minimum proof under class and organization constraints', () => {
    const evidence: ValidatorEvidence[] = [
      { capabilityId: bytes(4), validatorId: bytes(14), organization: 'C', validatorClass: 'general' },
      { capabilityId: bytes(3), validatorId: bytes(13), organization: 'B', validatorClass: 'general' },
      { capabilityId: bytes(2), validatorId: bytes(12), organization: 'A', validatorClass: 'auditor' },
      { capabilityId: bytes(1), validatorId: bytes(11), organization: 'A', validatorClass: 'general' },
    ]
    const result = evaluateValidationPolicy(policy, evidence)
    expect(result.satisfied).toBe(true)
    expect(result.selected).toHaveLength(3)
    expect(result.selected.map((item) => item.capabilityId[0])).toEqual([1, 2, 3])
    expect(evaluateValidationPolicy(policy, [...evidence].reverse()).selected).toEqual(result.selected)
  })

  it('reports exact missing policy dimensions', () => {
    const result = evaluateValidationPolicy(policy, [{ capabilityId: bytes(1), validatorId: bytes(11), organization: 'A' }])
    expect(result.satisfied).toBe(false)
    expect(result.missing).toContain('validators:2')
    expect(result.missing).toContain('class:auditor:1')
    expect(result.missing).toContain('organization:B')
  })
})

describe('reader history scopes', () => {
  it('keeps snapshot readers prospective while audit readers may access history', () => {
    const base = {
      id: bytes(1),
      grantedAtRevision: 5n,
      grant: {
        subjectId: bytes(2), signingPublicKey: bytes(2), role: 'reader' as const,
        validFromRevision: 5n, hpkePublicKey: bytes(3),
      },
    }
    expect(canReaderAccessRevision({ ...base, grant: { ...base.grant, readerScope: 'snapshot' } }, 4n)).toBe(false)
    expect(canReaderAccessRevision({ ...base, grant: { ...base.grant, readerScope: 'snapshot' } }, 5n)).toBe(true)
    expect(canReaderAccessRevision({ ...base, grant: { ...base.grant, readerScope: 'audit' } }, 0n)).toBe(true)
  })
})

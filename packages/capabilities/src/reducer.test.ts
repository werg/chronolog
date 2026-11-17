import { describe, expect, it } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor, generateEd25519KeyPair, type Ed25519KeyPair } from '@chronolog/protocol'
import {
  applyCapabilityRevision,
  capabilityId,
  capabilityCodecInternals,
  decodeCapabilityRevision,
  decodeGenesisManifest,
  decodeSignedGenesis,
  encodeGenesisManifest,
  encodeCapabilityRevision,
  encodeSignedGenesis,
  isCapabilityActive,
  reduceCapabilityLog,
  signCapabilityRevision,
  signGenesis,
  verifySignedGenesis,
  type CapabilityGrant,
  type CapabilityRevision,
  type CapabilitySnapshot,
  type GenesisManifest,
  type ValidationPolicy,
} from './index.js'

const bytes = (value: number, length = 32) => new Uint8Array(length).fill(value)

const policy: ValidationPolicy = { version: 1n, minimumValidators: 1n }
const writer: CapabilityGrant = { subjectId: bytes(20), signingPublicKey: bytes(20), role: 'writer', program: { sql: true, topics: [], signals: [] }, validFromRevision: 0n }
const validatorAt = (subject: number, revision: bigint, floor: bigint): CapabilityGrant => ({
  subjectId: bytes(subject), signingPublicKey: bytes(subject), role: 'validator', validFromRevision: revision,
  minimumAuthorTimestampMs: floor,
})

async function fixture(overrides: Partial<GenesisManifest> = {}) {
  const root = await generateEd25519KeyPair()
  const manifest: GenesisManifest = {
    groupId: bytes(1), schemaId: bytes(2), rootAdminPublicKey: root.publicKeyBytes, schemaAdminPublicKey: root.publicKeyBytes, capabilityLogFeed: bytes(3),
    initialCapabilities: [writer, validatorAt(21, 0n, 1_000n)], validationPolicies: [policy],
    clockPolicy: { maxFutureSkewMs: 60_000n, cutoffLagMs: 300_000n, heartbeatIntervalMs: 30_000n },
    resourcePolicy: { maxCandidateBytes: 1_000_000n, maxProgramNodes: 10_000n, maxPreconditions: 100n, maxMutations: 100n },
    encryptionSuite: 'DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM', createdAtMs: 10n,
    ...overrides,
  }
  const genesis = await signGenesis(manifest, root.privateKey)
  return { root, manifest, genesis, snapshot: await reduceCapabilityLog(genesis, []) }
}

function revisionAfter(
  f: { readonly snapshot: CapabilitySnapshot; readonly root: Ed25519KeyPair },
  overrides: Partial<CapabilityRevision> = {},
): CapabilityRevision {
  return { encryptionEpoch: f.snapshot.encryptionEpoch,
    groupId: f.snapshot.groupId, revision: f.snapshot.revision + 1n, previousRevisionDigest: f.snapshot.revisionDigest,
    issuerRootPublicKey: f.root.publicKeyBytes, grants: [], revocations: [], ...overrides,
  }
}

describe('genesis verification', () => {
  it('authenticates an independent SQL schema administrator without changing the roster issuer', async () => {
    const schemaAdministrator = await generateEd25519KeyPair()
    const f = await fixture({ schemaAdminPublicKey: schemaAdministrator.publicKeyBytes })
    const roundTrip = decodeSignedGenesis(encodeSignedGenesis(f.genesis))
    expect(roundTrip.manifest.schemaAdminPublicKey).toEqual(schemaAdministrator.publicKeyBytes)
    expect(roundTrip.manifest.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    expect(f.snapshot.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    expect(await verifySignedGenesis(roundTrip)).toBe(true)
    const changedSchemaOwner = { ...f.genesis, manifest: { ...f.manifest, schemaAdminPublicKey: f.root.publicKeyBytes } }
    expect(await verifySignedGenesis(changedSchemaOwner)).toBe(false)
    const schemaSignedRoster = await signGenesis(f.manifest, schemaAdministrator.privateKey)
    expect(await verifySignedGenesis(schemaSignedRoster)).toBe(false)
  })

  it('requires the explicit schema key and rejects prior genesis wire versions', async () => {
    const f = await fixture(), fields = assertCanonicalCbor(encodeGenesisManifest(f.manifest))
    if (!(fields instanceof Map)) throw new Error('GENESIS_MAP_REQUIRED')
    expect(fields.get(0n)).toBe(2n)
    fields.delete(4n)
    expect(() => decodeGenesisManifest(encodeCanonicalCbor(fields))).toThrow()
    fields.set(4n, new Uint8Array(31))
    expect(() => decodeGenesisManifest(encodeCanonicalCbor(fields))).toThrow()
    fields.set(4n, f.manifest.schemaAdminPublicKey)
    fields.set(0n, 1n)
    expect(() => decodeGenesisManifest(encodeCanonicalCbor(fields))).toThrow()
    const wrapper = assertCanonicalCbor(encodeSignedGenesis(f.genesis))
    if (!(wrapper instanceof Map)) throw new Error('SIGNED_GENESIS_MAP_REQUIRED')
    expect(wrapper.get(0n)).toBe(2n)
    wrapper.set(0n, 1n)
    expect(() => decodeSignedGenesis(encodeCanonicalCbor(wrapper))).toThrow()
    expect(() => encodeGenesisManifest({ ...f.manifest, schemaAdminPublicKey: new Uint8Array(31) })).toThrow()
  })

  it('rejects a genesis whose signature does not cover the manifest', async () => {
    const f = await fixture()
    const tampered = { ...f.genesis, manifest: { ...f.genesis.manifest, createdAtMs: 11n } }
    expect(await verifySignedGenesis(tampered)).toBe(false)
    await expect(reduceCapabilityLog(tampered, [])).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })

  it('rejects a genesis signed by a key other than its declared root', async () => {
    const f = await fixture()
    const imposter = await generateEd25519KeyPair()
    const forged = await signGenesis(f.manifest, imposter.privateKey)
    await expect(reduceCapabilityLog(forged, [])).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })

  it('rejects initial grants that do not begin at revision zero or repeat', async () => {
    const late = await fixture({ initialCapabilities: [{ ...writer, validFromRevision: 1n }] })
      .then(() => undefined, (error: unknown) => error)
    expect(late).toMatchObject({ code: 'SCHEMA_INVALID' })
    const duplicate = await fixture({ initialCapabilities: [writer, writer] }).then(() => undefined, (error: unknown) => error)
    expect(duplicate).toMatchObject({ code: 'SCHEMA_INVALID' })
    const policyRepeat = await fixture({ validationPolicies: [policy, policy] }).then(() => undefined, (error: unknown) => error)
    expect(policyRepeat).toMatchObject({ code: 'SCHEMA_INVALID' })
  })
})

describe('capability revision chain', () => {
  it('rejects every way a revision can fail to extend the signed chain', async () => {
    const f = await fixture()
    const stranger = await generateEd25519KeyPair()
    const cases: readonly [string, Partial<CapabilityRevision>, string, 'root' | 'stranger'][] = [
      ['foreign group', { groupId: bytes(98) }, 'SCHEMA_INVALID', 'root'],
      ['revision gap', { revision: 2n }, 'SCHEMA_INVALID', 'root'],
      ['forked predecessor', { encryptionEpoch: 0n, previousRevisionDigest: bytes(98) }, 'DIGEST_MISMATCH', 'root'],
      ['wrong declared issuer', { issuerRootPublicKey: stranger.publicKeyBytes }, 'INVALID_KEY', 'stranger'],
      ['non-root signature', {}, 'INVALID_SIGNATURE', 'stranger'],
    ]
    for (const [label, override, code, signer] of cases) {
      const signed = await signCapabilityRevision(
        revisionAfter(f, override),
        (signer === 'root' ? f.root : stranger).privateKey,
      )
      await expect(applyCapabilityRevision(f.snapshot, signed), label).rejects.toMatchObject({ code })
    }
  })

  it('rejects a revision whose signature is replayed over different content', async () => {
    const f = await fixture()
    const signed = await signCapabilityRevision(revisionAfter(f), f.root.privateKey)
    const swapped = { revision: revisionAfter(f, { grants: [{ ...writer, subjectId: bytes(50), signingPublicKey: bytes(50), validFromRevision: 1n }] }), signature: signed.signature }
    await expect(applyCapabilityRevision(f.snapshot, swapped)).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })

  it('rejects unknown and repeated revocations, early grants and duplicates', async () => {
    const f = await fixture()
    const writerId = await capabilityId(writer)
    const extra: CapabilityGrant = { ...writer, subjectId: bytes(51), signingPublicKey: bytes(51), validFromRevision: 1n }
    const sign = (revision: CapabilityRevision, snapshot: CapabilitySnapshot = f.snapshot) =>
      signCapabilityRevision(revision, f.root.privateKey).then((signed) => applyCapabilityRevision(snapshot, signed))

    await expect(sign(revisionAfter(f, { revocations: [bytes(98)] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    await expect(sign(revisionAfter(f, { grants: [{ ...extra, validFromRevision: 5n }] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    await expect(sign(revisionAfter(f, { grants: [extra, extra] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })

    const revoked = await sign(revisionAfter(f, { revocations: [writerId] }))
    await expect(sign(revisionAfter({ snapshot: revoked, root: f.root }, { revocations: [writerId] }), revoked))
      .rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })

  it('rejects validator grants at both revision encoding and decoding boundaries', async () => {
    const f = await fixture()
    const validator = validatorAt(22, 1n, 2_000n)
    const invalid = { ...revisionAfter(f), grants: [validator] } as unknown as CapabilityRevision
    expect(() => encodeCapabilityRevision(invalid)).toThrow('Validator capabilities are fixed by genesis')
    const fields = assertCanonicalCbor(encodeCapabilityRevision(revisionAfter(f)))
    if (!(fields instanceof Map)) throw new Error('REVISION_MAP_REQUIRED')
    fields.set(5n, [capabilityCodecInternals.grantToCbor(validator)])
    expect(() => decodeCapabilityRevision(encodeCanonicalCbor(fields))).toThrow('Validator capabilities are fixed by genesis')
  })

  it('rejects validator revocations even with an authentic root signature', async () => {
    const f = await fixture()
    const validatorId = await capabilityId(validatorAt(21, 0n, 1_000n))
    const signed = await signCapabilityRevision(revisionAfter(f, { revocations: [validatorId] }), f.root.privateKey)
    await expect(applyCapabilityRevision(f.snapshot, signed)).rejects.toThrow('Validator capabilities are fixed by genesis')
    expect(f.snapshot.revision).toBe(0n)
    expect([...f.snapshot.capabilities.values()].filter(item => item.grant.role === 'validator')).toHaveLength(1)
  })

  it('accepts only the membership revision wire and rejects policy fields and prior versions', async () => {
    const f = await fixture()
    const revision = revisionAfter(f)
    const fields = assertCanonicalCbor(encodeCapabilityRevision(revision))
    if (!(fields instanceof Map)) throw new Error('REVISION_MAP_REQUIRED')
    expect(fields.get(0n)).toBe(2n)
    expect(decodeCapabilityRevision(encodeCanonicalCbor(fields))).toEqual(revision)
    fields.set(8n, [[2n, 1n]])
    expect(() => decodeCapabilityRevision(encodeCanonicalCbor(fields))).toThrow()
    fields.delete(8n)
    fields.set(0n, 1n)
    expect(() => decodeCapabilityRevision(encodeCanonicalCbor(fields))).toThrow()
  })

  it('advances encryption identity with the signed revision and rejects gaps or reopening', async () => {
    const f = await fixture()
    const rotated = await applyCapabilityRevision(f.snapshot, await signCapabilityRevision(
      revisionAfter(f, { encryptionEpoch: 1n }), f.root.privateKey))
    expect(rotated.encryptionEpoch).toBe(1n)
    expect(rotated.rootAdminPublicKey).toEqual(f.root.publicKeyBytes)
    expect(rotated.capabilityLogFeed).toEqual(f.snapshot.capabilityLogFeed)
    for (const encryptionEpoch of [0n, 3n]) {
      const invalid = await signCapabilityRevision(revisionAfter({ snapshot: rotated, root: f.root }, { encryptionEpoch }), f.root.privateKey)
      await expect(applyCapabilityRevision(rotated, invalid)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    }
  })

  it('orders unsorted input revisions before applying them', async () => {
    const f = await fixture()
    const one = await signCapabilityRevision(revisionAfter(f), f.root.privateKey)
    const stateOne = await applyCapabilityRevision(f.snapshot, one)
    const two = await signCapabilityRevision(revisionAfter({ snapshot: stateOne, root: f.root }), f.root.privateKey)
    expect((await reduceCapabilityLog(f.genesis, [two, one])).revision).toBe(2n)
    await expect(reduceCapabilityLog(f.genesis, [two])).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })
})

describe('capability validity windows', () => {
  it('is active from its start revision until revoked', () => {
    const base = { id: bytes(1), grantedAtRevision: 2n }
    const grant: CapabilityGrant = { ...writer, validFromRevision: 2n }
    expect(isCapabilityActive({ ...base, grant }, 1n)).toBe(false)
    expect(isCapabilityActive({ ...base, grant }, 2n)).toBe(true)
    expect(isCapabilityActive({ ...base, grant }, 50n)).toBe(true)
    expect(isCapabilityActive({ ...base, grant, revokedAtRevision: 3n }, 2n)).toBe(true)
    expect(isCapabilityActive({ ...base, grant, revokedAtRevision: 3n }, 3n)).toBe(false)
  })
})

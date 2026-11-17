import { describe, expect, it } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor, generateEd25519KeyPair, type Ed25519KeyPair } from '@chronolog/protocol'
import {
  applyCapabilityRevision,
  capabilityId,
  decodeGenesisManifest,
  decodeSignedGenesis,
  encodeGenesisManifest,
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
  return {
    groupId: f.snapshot.groupId, revision: f.snapshot.revision + 1n, previousRevisionDigest: f.snapshot.revisionDigest,
    issuerRootPublicKey: f.root.publicKeyBytes, grants: [], revocations: [], validationPolicies: [], ...overrides,
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
      ['forked predecessor', { previousRevisionDigest: bytes(98) }, 'DIGEST_MISMATCH', 'root'],
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

  it('rejects unknown and repeated revocations, early grants, duplicates and repeated policies', async () => {
    const f = await fixture()
    const writerId = await capabilityId(writer)
    const extra: CapabilityGrant = { ...writer, subjectId: bytes(51), signingPublicKey: bytes(51), validFromRevision: 1n }
    const sign = (revision: CapabilityRevision, snapshot: CapabilitySnapshot = f.snapshot) =>
      signCapabilityRevision(revision, f.root.privateKey).then((signed) => applyCapabilityRevision(snapshot, signed))

    await expect(sign(revisionAfter(f, { revocations: [bytes(98)] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    await expect(sign(revisionAfter(f, { grants: [{ ...extra, validFromRevision: 5n }] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    await expect(sign(revisionAfter(f, { grants: [extra, extra] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    await expect(sign(revisionAfter(f, { validationPolicies: [policy] }))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })

    const revoked = await sign(revisionAfter(f, { revocations: [writerId] }))
    await expect(sign(revisionAfter({ snapshot: revoked, root: f.root }, { revocations: [writerId] }), revoked))
      .rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })

  it('prevents a later-granted validator from reopening closed timestamp history', async () => {
    const f = await fixture()
    const lowFloor = validatorAt(22, 1n, 500n)
    const signed = await signCapabilityRevision(revisionAfter(f, { grants: [lowFloor] }), f.root.privateKey)
    await expect(applyCapabilityRevision(f.snapshot, signed)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })

  it('keeps the floor of a validator revoked in the same revision that grants a lower-floor one', async () => {
    const f = await fixture()
    const highFloorId = await capabilityId(validatorAt(21, 0n, 1_000n))
    const swap = await signCapabilityRevision(
      revisionAfter(f, { revocations: [highFloorId], grants: [validatorAt(22, 1n, 500n)] }),
      f.root.privateKey,
    )
    await expect(applyCapabilityRevision(f.snapshot, swap)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    const flooredSwap = await signCapabilityRevision(
      revisionAfter(f, { revocations: [highFloorId], grants: [validatorAt(22, 1n, 1_000n)] }),
      f.root.privateKey,
    )
    expect((await applyCapabilityRevision(f.snapshot, flooredSwap)).revision).toBe(1n)
  })

  it('keeps the floor after every validator is revoked in an earlier revision', async () => {
    const f = await fixture()
    const highFloorId = await capabilityId(validatorAt(21, 0n, 1_000n))
    const emptied = await applyCapabilityRevision(f.snapshot, await signCapabilityRevision(
      revisionAfter(f, { revocations: [highFloorId] }),
      f.root.privateKey,
    ))
    expect(emptied.validatorFloorMs).toBe(1_000n)
    const next = { snapshot: emptied, root: f.root }
    const lowered = await signCapabilityRevision(revisionAfter(next, { grants: [validatorAt(22, 2n, 500n)] }), f.root.privateKey)
    await expect(applyCapabilityRevision(emptied, lowered)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    const raised = await applyCapabilityRevision(emptied, await signCapabilityRevision(
      revisionAfter(next, { grants: [validatorAt(22, 2n, 2_000n)] }),
      f.root.privateKey,
    ))
    expect(raised.validatorFloorMs).toBe(2_000n)
  })

  it('stops honoring the old root after succession', async () => {
    const f = await fixture()
    const successor = await generateEd25519KeyPair()
    const rotated = await applyCapabilityRevision(f.snapshot, await signCapabilityRevision(
      revisionAfter(f, { successorRootPublicKey: successor.publicKeyBytes, successorCapabilityLogFeed: bytes(8) }),
      f.root.privateKey,
    ))
    const oldRootAttempt = await signCapabilityRevision(revisionAfter({ snapshot: rotated, root: f.root }), f.root.privateKey)
    await expect(applyCapabilityRevision(rotated, oldRootAttempt)).rejects.toMatchObject({ code: 'INVALID_KEY' })
    const newRootRevision = await signCapabilityRevision(revisionAfter({ snapshot: rotated, root: successor }), successor.privateKey)
    expect((await applyCapabilityRevision(rotated, newRootRevision)).revision).toBe(2n)
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

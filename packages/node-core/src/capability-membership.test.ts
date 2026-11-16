import type {
  CapabilityGrant,
  CapabilitySnapshot,
  EffectiveCapability,
  EffectivePolicy,
  ValidationPolicy,
} from '@chronolog/capabilities'
import type { StoredAttestation } from '@chronolog/control-store'
import { bytesToHex, type TransactionCore } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { CapabilityMembershipResolver } from './capability-membership.js'

const bytes = (fill: number, length = 32): Uint8Array => new Uint8Array(length).fill(fill)

const groupId = bytes(0x01)
const otherGroupId = bytes(0x02)
const revisionDigest = bytes(0x10)
const otherRevisionDigest = bytes(0x11)
const policyId = bytes(0x20)
const unknownPolicyId = bytes(0x21)
const REVISION = 5n

const writerKey = bytes(0x30)
const revokedWriterKey = bytes(0x31)
const futureWriterKey = bytes(0x33)
const validatorKeys = [bytes(0x40), bytes(0x41), bytes(0x42)] as const
const revokedValidatorKey = bytes(0x43)
const outsiderKey = bytes(0x50)

function capability(
  idFill: number,
  grant: Partial<CapabilityGrant> & Pick<CapabilityGrant, 'role' | 'signingPublicKey'>,
  options: { readonly revokedAtRevision?: bigint } = {},
): EffectiveCapability {
  return {
    id: bytes(idFill),
    grant: { subjectId: grant.signingPublicKey, validFromRevision: 1n, ...grant },
    grantedAtRevision: 1n,
    ...(options.revokedAtRevision === undefined ? {} : { revokedAtRevision: options.revokedAtRevision }),
  }
}

const capabilities = {
  writer: capability(0x60, { role: 'writer', signingPublicKey: writerKey, transportAuthor: '@writer.feed' }),
  revokedWriter: capability(0x61, { role: 'writer', signingPublicKey: revokedWriterKey, transportAuthor: '@revoked.feed' }, { revokedAtRevision: REVISION }),
  futureWriter: capability(0x63, { role: 'writer', signingPublicKey: futureWriterKey, validFromRevision: REVISION + 1n }),
  validator0: capability(0x70, { role: 'validator', signingPublicKey: validatorKeys[0], transportAuthor: '@v0.feed' }),
  validator1: capability(0x71, { role: 'validator', signingPublicKey: validatorKeys[1], minimumAuthorTimestampMs: 1_000n }),
  validator2: capability(0x72, { role: 'validator', signingPublicKey: validatorKeys[2] }),
  revokedValidator: capability(0x73, { role: 'validator', signingPublicKey: revokedValidatorKey }, { revokedAtRevision: REVISION - 2n }),
  // A reader capability for a key that also must not acquire writer or validator rights from it.
  reader: capability(0x80, { role: 'reader', signingPublicKey: outsiderKey }),
}

function policy(overrides: Partial<ValidationPolicy> = {}): ValidationPolicy {
  return { version: 3n, minimumValidators: 2n, ...overrides }
}

function snapshot(
  validationPolicy: ValidationPolicy = policy(),
  extra: readonly EffectiveCapability[] = [],
  overrides: Partial<CapabilitySnapshot> = {},
): CapabilitySnapshot {
  const all = [...Object.values(capabilities), ...extra]
  const effective: EffectivePolicy = { id: policyId, policy: validationPolicy, installedAtRevision: 1n }
  return {
    groupId,
    revision: REVISION,
    revisionDigest,
    rootAdminPublicKey: bytes(0x90),
    capabilityLogFeed: bytes(0x91),
    capabilities: new Map(all.map((item) => [bytesToHex(item.id), item])),
    policies: new Map([[bytesToHex(policyId), effective]]),
    validatorFloorMs: 0n,
    ...overrides,
  }
}

function resolverFor(
  value: CapabilitySnapshot | null,
  options: Omit<ConstructorParameters<typeof CapabilityMembershipResolver>[0], 'snapshotForRevision'> = {},
): CapabilityMembershipResolver {
  return new CapabilityMembershipResolver({
    ...options,
    snapshotForRevision: async (digest) => value !== null && bytesToHex(digest) === bytesToHex(value.revisionDigest) ? value : null,
  })
}

const context = (overrides: Partial<{ groupId: Uint8Array, membershipRevision: Uint8Array, validationPolicy: Uint8Array, writerId: Uint8Array, writerCapability: Uint8Array }> = {}) => ({
  groupId,
  membershipRevision: revisionDigest,
  validationPolicy: policyId,
  writerId: writerKey,
  writerCapability: capabilities.writer.id,
  ...overrides,
})

function attestation(
  validator: EffectiveCapability,
  overrides: Partial<StoredAttestation> = {},
): StoredAttestation {
  return {
    attestationId: bytes(validator.id[0]! ^ 0xff),
    txId: bytes(0xb0),
    validatorId: validator.grant.signingPublicKey,
    validatorCapability: validator.id,
    membershipRevision: revisionDigest,
    candidateDigest: bytes(0xb1),
    validatorFeedSequence: 1n,
    authorTimestampMs: 5_000n,
    acceptedAboveMs: 100n,
    policyVersion: 3n,
    transportAuthor: '@feed',
    ...overrides,
  }
}

function core(overrides: Partial<TransactionCore> = {}): TransactionCore {
  return {
    groupId,
    membershipRevision: revisionDigest,
    validationPolicy: policyId,
    authorId: writerKey,
    writerCapability: capabilities.writer.id,
    ...overrides,
  } as unknown as TransactionCore
}

describe('CapabilityMembershipResolver revision pinning', () => {
  it('denies everything when the revision is unknown', async () => {
    const resolver = resolverFor(null)
    await expect(resolver.canWrite(context())).rejects.toThrow('GOVERNANCE_EVIDENCE_PENDING')
    expect(await resolver.canWrite({ ...context(), canonicalPosition: 1n })).toBe(false)
    expect(await resolver.canValidate({ ...context(), validatorId: validatorKeys[0], validatorCapability: capabilities.validator0.id })).toBe(false)
    expect(await resolver.canHeartbeat({ groupId, membershipRevision: revisionDigest, validatorId: validatorKeys[0], validatorCapability: capabilities.validator0.id })).toBe(false)
    expect(await resolver.threshold(context())).toBe(Number.MAX_SAFE_INTEGER)
    expect(await resolver.policyVersion(context())).toBe(-1n)
    expect(await resolver.selectAdmission(context(), [attestation(capabilities.validator0), attestation(capabilities.validator2)])).toEqual([])
    expect(await resolver.watermarkPolicy(core())).toBeNull()
  })

  it('denies a snapshot that belongs to a different group', async () => {
    const resolver = resolverFor(snapshot())
    const foreign = context({ groupId: otherGroupId })
    expect(await resolver.canWrite(foreign)).toBe(false)
    expect(await resolver.canValidate({ ...foreign, validatorId: validatorKeys[0], validatorCapability: capabilities.validator0.id })).toBe(false)
    expect(await resolver.threshold(foreign)).toBe(Number.MAX_SAFE_INTEGER)
    expect(await resolver.policyVersion(foreign)).toBe(-1n)
    expect(await resolver.selectAdmission(foreign, [attestation(capabilities.validator0), attestation(capabilities.validator2)])).toEqual([])
    expect(await resolver.watermarkPolicy(core({ groupId: otherGroupId }))).toBeNull()
    expect(await resolver.canUseTransportAuthor({ groupId: otherGroupId, membershipRevision: revisionDigest, role: 'writer', signingId: writerKey, transportAuthor: '@writer.feed' })).toBe(false)
  })

  it('rejects a received future revision at a fixed position without waiting for later activation', async () => {
    const resolver = resolverFor(snapshot(), { authorizationSnapshot: () => null })
    await expect(resolver.canWrite(context())).rejects.toThrow('GOVERNANCE_EVIDENCE_PENDING')
    expect(await resolver.canWrite({ ...context(), canonicalPosition: 1n })).toBe(false)
  })

  it('denies a source that returns a snapshot for a different revision than requested', async () => {
    const wrongRevision = snapshot(policy(), [], { revisionDigest: otherRevisionDigest })
    const resolver = new CapabilityMembershipResolver({ snapshotForRevision: () => wrongRevision })
    expect(await resolver.canWrite(context())).toBe(false)
    expect(await resolver.canHeartbeat({ groupId, membershipRevision: revisionDigest, validatorId: validatorKeys[0], validatorCapability: capabilities.validator0.id })).toBe(false)
    expect(await resolver.threshold(context())).toBe(Number.MAX_SAFE_INTEGER)
  })
})

describe('CapabilityMembershipResolver writer authority', () => {
  const resolver = resolverFor(snapshot())

  it('accepts an active writer', async () => {
    expect(await resolver.canWrite(context())).toBe(true)
  })

  it('does not revive an old grant when the same key is regranted', async () => {
    const old = snapshot()
    const revoked = { ...capabilities.writer, revokedAtRevision: REVISION + 1n }
    const regrant = capability(0x64, { role: 'writer', signingPublicKey: writerKey, validFromRevision: REVISION + 2n })
    const current = snapshot(policy(), [regrant], {
      revision: REVISION + 2n,
      revisionDigest: otherRevisionDigest,
      capabilities: new Map([...old.capabilities, [bytesToHex(revoked.id), revoked], [bytesToHex(regrant.id), regrant]]),
    })
    const resolver = new CapabilityMembershipResolver({
      snapshotForRevision: (digest) => bytesToHex(digest) === bytesToHex(revisionDigest) ? old : current,
      authorizationSnapshot: () => current,
    })
    expect(await resolver.canWrite(context())).toBe(false)
    expect(await resolver.canWrite(context({ membershipRevision: otherRevisionDigest, writerCapability: regrant.id }))).toBe(true)
    // A historical author-selected snapshot cannot borrow the newer grant.
    expect(await resolver.canWrite(context({ writerCapability: regrant.id }))).toBe(false)
  })

  it('keeps missing activation evidence pending and checks the exact ordering point', async () => {
    const original = snapshot()
    const revoked = { ...capabilities.writer, revokedAtRevision: REVISION + 1n }
    const after = snapshot(policy(), [], {
      revision: REVISION + 1n,
      capabilities: new Map([...original.capabilities, [bytesToHex(revoked.id), revoked]]),
    })
    const resolver = resolverFor(original, {
      authorizationSnapshot: (input) => input.canonicalPosition === undefined ? null : input.canonicalPosition < 10n ? original : after,
    })
    await expect(resolver.canWrite(context())).rejects.toThrow('GOVERNANCE_EVIDENCE_PENDING')
    expect(await resolver.canWrite({ ...context(), canonicalPosition: 9n })).toBe(true)
    expect(await resolver.canWrite({ ...context(), canonicalPosition: 10n })).toBe(false)
  })

  it('denies revoked, expired, not-yet-valid, unknown and non-writer keys', async () => {
    for (const writerId of [revokedWriterKey, futureWriterKey, outsiderKey, validatorKeys[0]]) {
      expect(await resolver.canWrite(context({ writerId }))).toBe(false)
    }
  })

  it('treats revocation as effective from the revoking revision', async () => {
    const before = resolverFor(snapshot(policy(), [], { revision: REVISION - 1n }))
    expect(await before.canWrite(context({ writerId: revokedWriterKey, writerCapability: capabilities.revokedWriter.id }))).toBe(true)
  })
})

describe('CapabilityMembershipResolver validator authority', () => {
  const resolver = resolverFor(snapshot())
  const validate = (validatorId: Uint8Array, validatorCapability: Uint8Array) =>
    resolver.canValidate({ ...context(), validatorId, validatorCapability })
  const heartbeat = (validatorId: Uint8Array, validatorCapability: Uint8Array) =>
    resolver.canHeartbeat({ groupId, membershipRevision: revisionDigest, validatorId, validatorCapability })

  it('accepts an active validator presenting its own capability', async () => {
    expect(await validate(validatorKeys[0], capabilities.validator0.id)).toBe(true)
    expect(await heartbeat(validatorKeys[0], capabilities.validator0.id)).toBe(true)
  })

  it('denies a validator presenting another validator capability', async () => {
    expect(await validate(validatorKeys[0], capabilities.validator1.id)).toBe(false)
    expect(await heartbeat(validatorKeys[0], capabilities.validator1.id)).toBe(false)
  })

  it('denies revoked validators, writer capabilities and unknown capabilities', async () => {
    expect(await validate(revokedValidatorKey, capabilities.revokedValidator.id)).toBe(false)
    expect(await heartbeat(revokedValidatorKey, capabilities.revokedValidator.id)).toBe(false)
    expect(await validate(writerKey, capabilities.writer.id)).toBe(false)
    expect(await heartbeat(writerKey, capabilities.writer.id)).toBe(false)
    expect(await validate(validatorKeys[0], bytes(0xee))).toBe(false)
    expect(await heartbeat(validatorKeys[0], new Uint8Array())).toBe(false)
  })
})

describe('CapabilityMembershipResolver transport author binding', () => {
  const resolver = resolverFor(snapshot())
  const bind = (overrides: Partial<Parameters<CapabilityMembershipResolver['canUseTransportAuthor']>[0]>) =>
    resolver.canUseTransportAuthor({
      groupId,
      membershipRevision: revisionDigest,
      role: 'writer',
      signingId: writerKey,
      writerCapability: capabilities.writer.id,
      transportAuthor: '@writer.feed',
      ...overrides,
    })

  it('accepts only the feed bound in the grant', async () => {
    expect(await bind({})).toBe(true)
    expect(await bind({ transportAuthor: '@attacker.feed' })).toBe(false)
    expect(await bind({ role: 'validator', signingId: validatorKeys[0], validatorCapability: capabilities.validator0.id, transportAuthor: '@v0.feed' })).toBe(true)
  })

  it('denies revoked members even on their previously bound feed', async () => {
    expect(await bind({ signingId: revokedWriterKey, transportAuthor: '@revoked.feed' })).toBe(false)
  })

  it('denies role confusion and missing validator capabilities', async () => {
    // A validator key cannot use its feed as a writer, and a writer key cannot claim validator role.
    expect(await bind({ signingId: validatorKeys[0], transportAuthor: '@v0.feed' })).toBe(false)
    expect(await bind({ role: 'validator', validatorCapability: capabilities.writer.id })).toBe(false)
    expect(await bind({ role: 'validator', signingId: validatorKeys[0], transportAuthor: '@v0.feed' })).toBe(false)
    // Another key cannot borrow a validator's capability to claim its feed.
    expect(await bind({ role: 'validator', signingId: validatorKeys[1], validatorCapability: capabilities.validator0.id, transportAuthor: '@v0.feed' })).toBe(false)
  })

  it('denies capabilities that carry no transport binding', async () => {
    expect(await bind({ role: 'validator', signingId: validatorKeys[2], validatorCapability: capabilities.validator2.id, transportAuthor: '' })).toBe(false)
  })

  it('defers to the recovery-controlled binding when configured, ignoring the grant field', async () => {
    const seen: string[] = []
    const recovery = resolverFor(snapshot(), {
      transportAuthorForCapability: async (item) => {
        seen.push(bytesToHex(item.id))
        return bytesToHex(item.id) === bytesToHex(capabilities.writer.id) ? '@recovered.feed' : null
      },
    })
    const input = { groupId, membershipRevision: revisionDigest, role: 'writer' as const, signingId: writerKey, writerCapability: capabilities.writer.id }
    expect(await recovery.canUseTransportAuthor({ ...input, transportAuthor: '@recovered.feed' })).toBe(true)
    expect(await recovery.canUseTransportAuthor({ ...input, transportAuthor: '@writer.feed' })).toBe(false)
    // An unauthorized signer never reaches the recovery binding.
    seen.length = 0
    expect(await recovery.canUseTransportAuthor({ ...input, signingId: revokedWriterKey, transportAuthor: '@recovered.feed' })).toBe(false)
    expect(seen).toEqual([])
  })
})

describe('CapabilityMembershipResolver policy lookup', () => {
  it('returns the pinned policy threshold and version', async () => {
    const resolver = resolverFor(snapshot(policy({ minimumValidators: 2n, version: 3n })))
    expect(await resolver.threshold(context())).toBe(2)
    expect(await resolver.policyVersion(context())).toBe(3n)
  })

  it('fails closed for an unknown policy or an unrepresentable threshold', async () => {
    const resolver = resolverFor(snapshot())
    expect(await resolver.threshold(context({ validationPolicy: unknownPolicyId }))).toBe(Number.MAX_SAFE_INTEGER)
    expect(await resolver.policyVersion(context({ validationPolicy: unknownPolicyId }))).toBe(-1n)
    const huge = resolverFor(snapshot(policy({ minimumValidators: BigInt(Number.MAX_SAFE_INTEGER) + 1n })))
    expect(await huge.threshold(context())).toBe(Number.MAX_SAFE_INTEGER)
  })
})

describe('CapabilityMembershipResolver admission selection', () => {
  const resolver = resolverFor(snapshot())
  const ids = (selected: readonly StoredAttestation[]) => selected.map((item) => bytesToHex(item.validatorCapability)).sort()

  it('selects a satisfying set of valid attestations', async () => {
    const selected = await resolver.selectAdmission(context(), [attestation(capabilities.validator0), attestation(capabilities.validator2)])
    expect(ids(selected)).toEqual([bytesToHex(capabilities.validator0.id), bytesToHex(capabilities.validator2.id)])
  })

  it('returns nothing for an unknown policy', async () => {
    expect(await resolver.selectAdmission(context({ validationPolicy: unknownPolicyId }), [
      attestation(capabilities.validator0), attestation(capabilities.validator2),
    ])).toEqual([])
  })

  it('does not count invalid attestations toward the threshold', async () => {
    const valid = attestation(capabilities.validator0)
    const invalid: Array<[string, StoredAttestation]> = [
      ['revoked validator', attestation(capabilities.revokedValidator)],
      ['writer capability', attestation(capabilities.writer)],
      ['unknown capability', attestation(capabilities.validator2, { validatorCapability: bytes(0xee) })],
      ['signer does not hold capability', attestation(capabilities.validator2, { validatorId: validatorKeys[1] })],
      ['other membership revision', attestation(capabilities.validator2, { membershipRevision: otherRevisionDigest })],
      ['stale policy version', attestation(capabilities.validator2, { policyVersion: 2n })],
      ['future policy version', attestation(capabilities.validator2, { policyVersion: 4n })],
      ['timestamp not above accepted floor', attestation(capabilities.validator2, { authorTimestampMs: 100n, acceptedAboveMs: 100n })],
      ['timestamp at capability minimum', attestation(capabilities.validator1, { authorTimestampMs: 1_000n })],
    ]
    for (const [label, item] of invalid) {
      expect(await resolver.selectAdmission(context(), [valid, item]), label).toEqual([])
    }
  })

  it('counts each validator capability at most once', async () => {
    const first = attestation(capabilities.validator0)
    const duplicate = attestation(capabilities.validator0, { attestationId: bytes(0xcc), txId: bytes(0xcd) })
    expect(await resolver.selectAdmission(context(), [first, duplicate])).toEqual([])
    const selected = await resolver.selectAdmission(context(), [first, duplicate, attestation(capabilities.validator2)])
    expect(selected).toHaveLength(2)
    expect(selected).toContain(first)
  })
})

describe('CapabilityMembershipResolver watermark policy', () => {
  it('lists only active validators for a plain threshold policy', async () => {
    const watermark = await resolverFor(snapshot()).watermarkPolicy(core())
    expect(watermark).toEqual({
      kind: 'threshold',
      policyId: bytesToHex(policyId),
      validatorIds: [validatorKeys[0], validatorKeys[1], validatorKeys[2]],
      threshold: 2,
    })
  })

  it('returns null for unknown policies, unsafe thresholds, and too many validators', async () => {
    expect(await resolverFor(snapshot()).watermarkPolicy(core({ validationPolicy: unknownPolicyId }))).toBeNull()
    const unsafe = resolverFor(snapshot(policy({ minimumValidators: BigInt(Number.MAX_SAFE_INTEGER) + 1n })))
    expect(await unsafe.watermarkPolicy(core())).toBeNull()
    expect(await resolverFor(snapshot(), { maximumWatermarkValidators: 2 }).watermarkPolicy(core())).toBeNull()
  })
})

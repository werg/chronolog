import {
  DOMAINS,
  bytesToHex,
  compareBytes,
  encodeCanonicalCbor,
  equalBytes,
  hashDomain,
  hexToBytes,
  integerMap,
  protocolInvariant,
  signDomain,
  verifyDomain,
} from '@chronolog/protocol'
import {
  capabilityCodecInternals,
  decodeCapabilityRevision,
  decodeGenesisManifest,
  encodeCapabilityRevision,
  encodeGenesisManifest,
} from './codec.js'
import type {
  CapabilityGrant,
  CapabilitySnapshot,
  EffectiveCapability,
  GenesisManifest,
  SignedCapabilityRevision,
  SignedGenesis,
  ValidationPolicy,
} from './types.js'

export async function capabilityId(grant: CapabilityGrant): Promise<Uint8Array> {
  return hashDomain(DOMAINS.capabilityGrant, encodeCanonicalCbor(capabilityCodecInternals.grantToCbor(grant)))
}

export async function validationPolicyId(policy: ValidationPolicy): Promise<Uint8Array> {
  return hashDomain(DOMAINS.validationPolicy, encodeCanonicalCbor(capabilityCodecInternals.policyToCbor(policy)))
}

export async function signGenesis(manifest: GenesisManifest, rootPrivateKey: CryptoKey): Promise<SignedGenesis> {
  const bytes = encodeGenesisManifest(manifest)
  return { manifest, signature: await signDomain(DOMAINS.genesis, bytes, rootPrivateKey) }
}

export async function verifySignedGenesis(value: SignedGenesis): Promise<boolean> {
  return verifyDomain(DOMAINS.genesis, encodeGenesisManifest(value.manifest), value.signature, value.manifest.rootAdminPublicKey)
}

export async function signCapabilityRevision(
  revision: SignedCapabilityRevision['revision'],
  rootPrivateKey: CryptoKey,
): Promise<SignedCapabilityRevision> {
  return { revision, signature: await signDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(revision), rootPrivateKey) }
}

export async function capabilityRevisionDigest(revision: SignedCapabilityRevision['revision']): Promise<Uint8Array> {
  return hashDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(revision))
}

async function genesisSnapshot(genesis: SignedGenesis): Promise<CapabilitySnapshot> {
  protocolInvariant(await verifySignedGenesis(genesis), 'INVALID_SIGNATURE', 'Genesis signature is invalid')
  const manifest = decodeGenesisManifest(encodeGenesisManifest(genesis.manifest))
  const genesisDigest = await hashDomain(DOMAINS.genesis, encodeGenesisManifest(manifest))
  const capabilities = new Map<string, EffectiveCapability>()
  for (const grant of manifest.initialCapabilities) {
    protocolInvariant(grant.validFromRevision === 0n, 'SCHEMA_INVALID', 'Genesis capability must begin at revision zero')
    const id = await capabilityId(grant)
    protocolInvariant(!capabilities.has(bytesToHex(id)), 'SCHEMA_INVALID', 'Genesis contains a duplicate capability')
    capabilities.set(bytesToHex(id), { id, grant, grantedAtRevision: 0n })
  }
  const policies = new Map<string, ValidationPolicy>()
  for (const policy of manifest.validationPolicies) {
    const id = await validationPolicyId(policy)
    protocolInvariant(!policies.has(bytesToHex(id)), 'SCHEMA_INVALID', 'Genesis contains a duplicate policy')
    policies.set(bytesToHex(id), policy)
  }
  return {
    groupId: manifest.groupId,
    revision: 0n,
    revisionDigest: genesisDigest,
    rootAdminPublicKey: manifest.rootAdminPublicKey,
    capabilityLogFeed: manifest.capabilityLogFeed,
    capabilities,
    policies,
    encryptionEpoch: 0n,
  }
}

export async function reduceCapabilityLog(
  genesis: SignedGenesis,
  inputRevisions: readonly SignedCapabilityRevision[],
): Promise<CapabilitySnapshot> {
  let snapshot = await genesisSnapshot(genesis)
  const revisions = [...inputRevisions].sort((a, b) => a.revision.revision < b.revision.revision ? -1 : a.revision.revision > b.revision.revision ? 1 : 0)
  for (const signed of revisions) snapshot = await applyCapabilityRevision(snapshot, signed)
  return snapshot
}

/** Applies one verified successor revision. */
export async function applyCapabilityRevision(
  snapshot: CapabilitySnapshot,
  signed: SignedCapabilityRevision,
): Promise<CapabilitySnapshot> {
    const revision = decodeCapabilityRevision(encodeCapabilityRevision(signed.revision))
    protocolInvariant(equalBytes(revision.groupId, snapshot.groupId), 'SCHEMA_INVALID', 'Capability revision belongs to another group')
    protocolInvariant(revision.revision === snapshot.revision + 1n, 'SCHEMA_INVALID', 'Capability log contains a gap or conflicting revision')
    protocolInvariant(equalBytes(revision.previousRevisionDigest, snapshot.revisionDigest), 'DIGEST_MISMATCH', 'Capability revision does not extend current chain')
    protocolInvariant(equalBytes(revision.issuerRootPublicKey, snapshot.rootAdminPublicKey), 'INVALID_KEY', 'Capability revision has the wrong root issuer')
    protocolInvariant(await verifyDomain(DOMAINS.capabilityRevision, encodeCapabilityRevision(revision), signed.signature, snapshot.rootAdminPublicKey), 'INVALID_SIGNATURE', 'Capability revision signature is invalid')
    protocolInvariant(revision.encryptionEpoch === snapshot.encryptionEpoch || revision.encryptionEpoch === snapshot.encryptionEpoch + 1n,
      'SCHEMA_INVALID', 'Encryption epoch must retain or advance the current epoch by one')
    protocolInvariant(!revision.revocations.some(id => snapshot.capabilities.get(bytesToHex(id))?.grant.role === 'reader') ||
      revision.encryptionEpoch === snapshot.encryptionEpoch + 1n,
    'SCHEMA_INVALID', 'Reader revocation must retire its encryption epoch in the same revision')

    const capabilities = new Map(snapshot.capabilities)
    for (const revokedId of revision.revocations) {
      const key = bytesToHex(revokedId)
      const active = capabilities.get(key)
      protocolInvariant(active !== undefined, 'SCHEMA_INVALID', 'Capability revision revokes an unknown capability')
      protocolInvariant(active.grant.role !== 'validator', 'SCHEMA_INVALID', 'Validator capabilities are fixed by genesis')
      protocolInvariant(active.revokedAtRevision === undefined, 'SCHEMA_INVALID', 'Capability is already revoked')
      capabilities.set(key, { ...active, revokedAtRevision: revision.revision })
    }
    for (const grant of revision.grants) {
      protocolInvariant(grant.validFromRevision === revision.revision, 'SCHEMA_INVALID', 'New capability must begin at its containing revision')
      const id = await capabilityId(grant)
      protocolInvariant(!capabilities.has(bytesToHex(id)), 'SCHEMA_INVALID', 'Capability revision contains a duplicate grant')
      capabilities.set(bytesToHex(id), { id, grant, grantedAtRevision: revision.revision })
    }
    const revisionDigest = await capabilityRevisionDigest(revision)
    return {
      ...snapshot,
      revision: revision.revision,
      revisionDigest,
      encryptionEpoch: revision.encryptionEpoch,
      capabilities,
    }
}

export function isCapabilityActive(capability: EffectiveCapability, revision: bigint): boolean {
  return capability.grant.validFromRevision <= revision
    && (capability.revokedAtRevision === undefined || revision < capability.revokedAtRevision)
}

export function capabilitiesForSubject(
  snapshot: CapabilitySnapshot,
  subjectId: Uint8Array,
  revision = snapshot.revision,
): EffectiveCapability[] {
  return [...snapshot.capabilities.values()]
    .filter((capability) => equalBytes(capability.grant.subjectId, subjectId) && isCapabilityActive(capability, revision))
    .sort((a, b) => compareBytes(a.id, b.id))
}

export function hasRole(
  snapshot: CapabilitySnapshot,
  subjectId: Uint8Array,
  role: CapabilityGrant['role'],
  revision = snapshot.revision,
): boolean {
  return capabilitiesForSubject(snapshot, subjectId, revision).some((capability) => capability.grant.role === role)
}

export async function capabilitySnapshotDigest(snapshot: CapabilitySnapshot): Promise<Uint8Array> {
  const entries = [...snapshot.capabilities.values()].sort((a, b) => compareBytes(a.id, b.id))
  const policies = [...snapshot.policies].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
  const value = integerMap([
    [0, snapshot.groupId], [1, snapshot.revision], [2, snapshot.revisionDigest],
    [3, snapshot.rootAdminPublicKey], [4, snapshot.capabilityLogFeed],
    [5, entries.map(effectiveCapabilityToCbor)],
    [6, policies.map(([id, policy]) => integerMap([
      [0, capabilityCodecInternals.policyToCbor(policy)], [1, hexToBytes(id)],
    ]))],
    [7, snapshot.encryptionEpoch],
  ])
  return hashDomain(DOMAINS.capabilitySnapshot, encodeCanonicalCbor(value))
}

function effectiveCapabilityToCbor(entry: EffectiveCapability) {
  return integerMap([
    [0, capabilityCodecInternals.grantToCbor(entry.grant)],
    [1, entry.id],
    [2, entry.grantedAtRevision],
    [3, entry.revokedAtRevision],
  ])
}

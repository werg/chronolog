import {
  DOMAINS,
  assertCanonicalCbor,
  assertKnownIntegerKeys,
  encodeCanonicalCbor,
  expectArray,
  expectBytes,
  expectMap,
  expectString,
  expectUint64,
  expectVersion,
  integerMap,
  optional,
  protocolInvariant,
  required,
  type CborValue,
} from '@chronolog/protocol'
import type {
  CapabilityGrant,
  CapabilityRevision,
  ClockPolicy,
  ForkOrigin,
  GenesisManifest,
  ResourcePolicy,
  SignedCapabilityRevision,
  SignedGenesis,
  ValidationPolicy,
} from './types.js'

// Wire codes are positions in this list; code 4 (formerly 'schema-administrator') is retired.
const ROLES = ['reader', 'writer', 'validator', 'administrator'] as const

function roleIndex(role: CapabilityGrant['role']): bigint {
  const index = ROLES.indexOf(role)
  protocolInvariant(index >= 0, 'SCHEMA_INVALID', 'Unknown capability role')
  return BigInt(index)
}

function grantToCbor(grant: CapabilityGrant): CborValue {
  protocolInvariant(grant.signingPublicKey.length === 32, 'SCHEMA_INVALID', 'Capability signing key must contain 32 bytes')
  protocolInvariant(grant.validFromRevision >= 0n, 'INTEGER_OUT_OF_RANGE', 'Capability revision cannot be negative')
  if (grant.role === 'validator') {
    protocolInvariant(grant.minimumAuthorTimestampMs !== undefined, 'SCHEMA_INVALID', 'Validator capability requires a timestamp floor')
  } else {
    protocolInvariant(grant.minimumAuthorTimestampMs === undefined, 'SCHEMA_INVALID', 'Only validators may carry validator fields')
  }
  if (grant.role === 'reader') {
    protocolInvariant(grant.hpkePublicKey !== undefined, 'SCHEMA_INVALID', 'Reader capability requires an HPKE key')
    protocolInvariant(grant.hpkePublicKey.length === 32, 'SCHEMA_INVALID', 'Reader HPKE key must contain 32 bytes')
  } else {
    protocolInvariant(grant.hpkePublicKey === undefined, 'SCHEMA_INVALID', 'Only readers may carry reader fields')
  }
  if (grant.transportAuthor !== undefined) {
    protocolInvariant(grant.transportAuthor.length > 0, 'SCHEMA_INVALID', 'Capability transport author must not be empty')
  }
  // Keys 4 (valid until), 5 (organization), 6 (validator class) and 8 (reader scope) are retired.
  return integerMap([
    [0, grant.subjectId], [1, grant.signingPublicKey], [2, roleIndex(grant.role)],
    [3, grant.validFromRevision], [7, grant.minimumAuthorTimestampMs], [9, grant.hpkePublicKey],
    [10, grant.transportAuthor],
  ])
}

function grantFromCbor(value: CborValue, field: string): CapabilityGrant {
  const map = expectMap(value, field)
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 7, 9, 10], field)
  const roleValue = expectUint64(required(map, 2, `${field}.role`), `${field}.role`)
  protocolInvariant(roleValue < BigInt(ROLES.length), 'SCHEMA_INVALID', `${field}.role is unknown`)
  const role = ROLES[Number(roleValue)]
  protocolInvariant(role !== undefined, 'SCHEMA_INVALID', `${field}.role is unknown`)
  const floor = optional(map, 7)
  const hpkeKey = optional(map, 9)
  const transportAuthor = optional(map, 10)
  const grant: CapabilityGrant = {
    subjectId: expectBytes(required(map, 0, `${field}.subject_id`), `${field}.subject_id`),
    signingPublicKey: expectBytes(required(map, 1, `${field}.signing_key`), `${field}.signing_key`, 32),
    role,
    validFromRevision: expectUint64(required(map, 3, `${field}.valid_from`), `${field}.valid_from`),
    ...(floor === undefined ? {} : { minimumAuthorTimestampMs: expectUint64(floor, `${field}.minimum_timestamp`) }),
    ...(hpkeKey === undefined ? {} : { hpkePublicKey: expectBytes(hpkeKey, `${field}.hpke_key`, 32) }),
    ...(transportAuthor === undefined ? {} : { transportAuthor: expectString(transportAuthor, `${field}.transport_author`) }),
  }
  grantToCbor(grant)
  return grant
}

function policyToCbor(policy: ValidationPolicy): CborValue {
  protocolInvariant(policy.minimumValidators > 0n, 'SCHEMA_INVALID', 'Validation threshold must be positive')
  // Keys 2 (class minimums) and 3 (required organizations) are retired.
  return integerMap([[0, policy.version], [1, policy.minimumValidators]])
}

function policyFromCbor(value: CborValue, field: string): ValidationPolicy {
  const map = expectMap(value, field)
  assertKnownIntegerKeys(map, [0, 1], field)
  const policy = {
    version: expectUint64(required(map, 0, `${field}.version`), `${field}.version`),
    minimumValidators: expectUint64(required(map, 1, `${field}.minimum`), `${field}.minimum`),
  }
  policyToCbor(policy)
  return policy
}

function clockToCbor(policy: ClockPolicy): CborValue {
  return integerMap([[0, policy.maxFutureSkewMs], [1, policy.cutoffLagMs], [2, policy.heartbeatIntervalMs]])
}

function clockFromCbor(value: CborValue): ClockPolicy {
  const map = expectMap(value, 'genesis.clock_policy')
  assertKnownIntegerKeys(map, [0, 1, 2], 'genesis.clock_policy')
  return {
    maxFutureSkewMs: expectUint64(required(map, 0, 'clock.max_future_skew'), 'clock.max_future_skew'),
    cutoffLagMs: expectUint64(required(map, 1, 'clock.cutoff_lag'), 'clock.cutoff_lag'),
    heartbeatIntervalMs: expectUint64(required(map, 2, 'clock.heartbeat_interval'), 'clock.heartbeat_interval'),
  }
}

function resourceToCbor(policy: ResourcePolicy): CborValue {
  return integerMap([[0, policy.maxCandidateBytes], [1, policy.maxProgramNodes], [2, policy.maxPreconditions], [3, policy.maxMutations]])
}

function resourceFromCbor(value: CborValue): ResourcePolicy {
  const map = expectMap(value, 'genesis.resource_policy')
  assertKnownIntegerKeys(map, [0, 1, 2, 3], 'genesis.resource_policy')
  return {
    maxCandidateBytes: expectUint64(required(map, 0, 'resource.max_candidate_bytes'), 'resource.max_candidate_bytes'),
    maxProgramNodes: expectUint64(required(map, 1, 'resource.max_program_nodes'), 'resource.max_program_nodes'),
    maxPreconditions: expectUint64(required(map, 2, 'resource.max_preconditions'), 'resource.max_preconditions'),
    maxMutations: expectUint64(required(map, 3, 'resource.max_mutations'), 'resource.max_mutations'),
  }
}

function genesisToCbor(value: GenesisManifest): CborValue {
  protocolInvariant(value.rootAdminPublicKey.length === 32, 'SCHEMA_INVALID', 'Genesis root key must contain 32 bytes')
  protocolInvariant(value.validationPolicies.length > 0, 'SCHEMA_INVALID', 'Genesis requires at least one validation policy')
  return integerMap([
    [0, 1n], [1, value.groupId], [2, value.schemaId], [3, value.rootAdminPublicKey],
    [4, value.capabilityLogFeed],
    [7, value.initialCapabilities.map(grantToCbor)], [8, value.validationPolicies.map(policyToCbor)],
    [9, clockToCbor(value.clockPolicy)], [10, resourceToCbor(value.resourcePolicy)],
    [11, value.encryptionSuite], [12, value.createdAtMs],
    [13, value.forkedFrom === undefined ? undefined : integerMap([
      [0, value.forkedFrom.groupId],
      [1, value.forkedFrom.snapshotManifestSha256],
      [2, value.forkedFrom.materializedRevision],
    ])],
    [14, value.historyPolicy === undefined ? undefined : historyPolicyToCbor(value.historyPolicy)],
  ])
}

function historyPolicyToCbor(value: NonNullable<GenesisManifest['historyPolicy']>): CborValue {
  protocolInvariant(value.executionManifestDigest.length === 32, 'SCHEMA_INVALID', 'History requires an execution manifest digest')
  protocolInvariant(value.kind === 'peer' || value.kind === 'coordinated', 'SCHEMA_INVALID', 'Unknown history policy')
  if (value.kind === 'coordinated') {
    protocolInvariant(typeof value.historyId === 'string' && /^h_[0-9a-f]{32}$/u.test(value.historyId), 'SCHEMA_INVALID', 'History identity is invalid')
    protocolInvariant(value.authorityPublicKey?.length === 32, 'SCHEMA_INVALID', 'Authority public key is invalid')
    return [1n, value.executionManifestDigest, value.historyId, value.authorityPublicKey]
  }
  protocolInvariant(value.historyId === undefined && value.authorityPublicKey === undefined, 'SCHEMA_INVALID', 'Peer policy cannot carry an authority')
  return [0n, value.executionManifestDigest]
}

function historyPolicyFromCbor(value: CborValue): NonNullable<GenesisManifest['historyPolicy']> {
  const fields = expectArray(value, 'genesis.history_policy')
  if (fields[0] === 0n && fields.length === 2) return {
    kind: 'peer', executionManifestDigest: expectBytes(fields[1]!, 'genesis.history_policy.manifest', 32),
  }
  protocolInvariant(fields[0] === 1n && fields.length === 4, 'SCHEMA_INVALID', 'History policy is invalid')
  const policy = {
    kind: 'coordinated' as const,
    executionManifestDigest: expectBytes(fields[1]!, 'genesis.history_policy.manifest', 32),
    historyId: expectString(fields[2]!, 'genesis.history_policy.history'),
    authorityPublicKey: expectBytes(fields[3]!, 'genesis.history_policy.authority', 32),
  }
  historyPolicyToCbor(policy)
  return policy
}

function forkOriginFromCbor(value: CborValue): ForkOrigin {
  const map = expectMap(value, 'genesis.forked_from')
  assertKnownIntegerKeys(map, [0, 1, 2], 'genesis.forked_from')
  return {
    groupId: expectBytes(required(map, 0, 'genesis.forked_from.group_id'), 'genesis.forked_from.group_id', 32),
    snapshotManifestSha256: expectBytes(required(map, 1, 'genesis.forked_from.snapshot_sha256'), 'genesis.forked_from.snapshot_sha256', 32),
    materializedRevision: expectUint64(required(map, 2, 'genesis.forked_from.revision'), 'genesis.forked_from.revision'),
  }
}

export function encodeGenesisManifest(value: GenesisManifest): Uint8Array {
  return encodeCanonicalCbor(genesisToCbor(value))
}

export function decodeGenesisManifest(bytes: Uint8Array): GenesisManifest {
  const map = expectMap(assertCanonicalCbor(bytes), 'genesis')
  // Keys 5 and 6 are retired (formerly recovery keys and threshold).
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14], 'genesis')
  expectVersion(map, 1n, 'genesis')
  const forkedFrom = optional(map, 13)
  const historyPolicy = optional(map, 14)
  const manifest: GenesisManifest = {
    groupId: expectBytes(required(map, 1, 'genesis.group_id'), 'genesis.group_id'),
    schemaId: expectBytes(required(map, 2, 'genesis.schema_id'), 'genesis.schema_id'),
    rootAdminPublicKey: expectBytes(required(map, 3, 'genesis.root_key'), 'genesis.root_key', 32),
    capabilityLogFeed: expectBytes(required(map, 4, 'genesis.capability_feed'), 'genesis.capability_feed'),
    initialCapabilities: expectArray(required(map, 7, 'genesis.capabilities'), 'genesis.capabilities').map((item, index) => grantFromCbor(item, `genesis.capabilities[${index}]`)),
    validationPolicies: expectArray(required(map, 8, 'genesis.policies'), 'genesis.policies').map((item, index) => policyFromCbor(item, `genesis.policies[${index}]`)),
    clockPolicy: clockFromCbor(required(map, 9, 'genesis.clock_policy')),
    resourcePolicy: resourceFromCbor(required(map, 10, 'genesis.resource_policy')),
    encryptionSuite: expectString(required(map, 11, 'genesis.encryption_suite'), 'genesis.encryption_suite'),
    createdAtMs: expectUint64(required(map, 12, 'genesis.created_at'), 'genesis.created_at'),
    ...(forkedFrom === undefined ? {} : { forkedFrom: forkOriginFromCbor(forkedFrom) }),
    ...(historyPolicy === undefined ? {} : { historyPolicy: historyPolicyFromCbor(historyPolicy) }),
  }
  genesisToCbor(manifest)
  return manifest
}

export function encodeSignedGenesis(value: SignedGenesis): Uint8Array {
  return encodeCanonicalCbor(integerMap([
    [0, 1n],
    [1, encodeGenesisManifest(value.manifest)],
    [2, value.signature],
  ]))
}

export function decodeSignedGenesis(bytes: Uint8Array): SignedGenesis {
  const map = expectMap(assertCanonicalCbor(bytes), 'signed_genesis')
  assertKnownIntegerKeys(map, [0, 1, 2], 'signed_genesis')
  expectVersion(map, 1n, 'signed_genesis')
  return {
    manifest: decodeGenesisManifest(expectBytes(required(map, 1, 'signed_genesis.manifest'), 'signed_genesis.manifest')),
    signature: expectBytes(required(map, 2, 'signed_genesis.signature'), 'signed_genesis.signature', 64),
  }
}

function revisionToCbor(value: CapabilityRevision): CborValue {
  protocolInvariant(value.revision > 0n, 'SCHEMA_INVALID', 'Capability revision must be positive')
  protocolInvariant(value.issuerRootPublicKey.length === 32, 'SCHEMA_INVALID', 'Revision issuer key must contain 32 bytes')
  protocolInvariant((value.successorRootPublicKey === undefined) === (value.successorCapabilityLogFeed === undefined), 'SCHEMA_INVALID', 'Root and feed succession must be declared together')
  return integerMap([
    [0, 1n], [1, value.groupId], [2, value.revision], [3, value.previousRevisionDigest],
    [4, value.issuerRootPublicKey], [5, value.grants.map(grantToCbor)], [6, value.revocations],
    [7, value.validationPolicies.map(policyToCbor)], [8, value.successorRootPublicKey],
    [9, value.successorCapabilityLogFeed],
  ])
}

export function encodeCapabilityRevision(value: CapabilityRevision): Uint8Array {
  return encodeCanonicalCbor(revisionToCbor(value))
}

export function decodeCapabilityRevision(bytes: Uint8Array): CapabilityRevision {
  const map = expectMap(assertCanonicalCbor(bytes), 'capability_revision')
  assertKnownIntegerKeys(map, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 'capability_revision')
  expectVersion(map, 1n, 'capability_revision')
  const successorRoot = optional(map, 8)
  const successorFeed = optional(map, 9)
  const revision: CapabilityRevision = {
    groupId: expectBytes(required(map, 1, 'revision.group_id'), 'revision.group_id'),
    revision: expectUint64(required(map, 2, 'revision.number'), 'revision.number'),
    previousRevisionDigest: expectBytes(required(map, 3, 'revision.previous_digest'), 'revision.previous_digest', 32),
    issuerRootPublicKey: expectBytes(required(map, 4, 'revision.issuer'), 'revision.issuer', 32),
    grants: expectArray(required(map, 5, 'revision.grants'), 'revision.grants').map((item, index) => grantFromCbor(item, `revision.grants[${index}]`)),
    revocations: expectArray(required(map, 6, 'revision.revocations'), 'revision.revocations').map((item, index) => expectBytes(item, `revision.revocations[${index}]`, 32)),
    validationPolicies: expectArray(required(map, 7, 'revision.policies'), 'revision.policies').map((item, index) => policyFromCbor(item, `revision.policies[${index}]`)),
    ...(successorRoot === undefined ? {} : { successorRootPublicKey: expectBytes(successorRoot, 'revision.successor_root', 32) }),
    ...(successorFeed === undefined ? {} : { successorCapabilityLogFeed: expectBytes(successorFeed, 'revision.successor_feed') }),
  }
  revisionToCbor(revision)
  return revision
}

export function encodeSignedCapabilityRevision(value: SignedCapabilityRevision): Uint8Array {
  return encodeCanonicalCbor(integerMap([
    [0, 1n],
    [1, encodeCapabilityRevision(value.revision)],
    [2, value.signature],
  ]))
}

export function decodeSignedCapabilityRevision(bytes: Uint8Array): SignedCapabilityRevision {
  const map = expectMap(assertCanonicalCbor(bytes), 'signed_capability_revision')
  assertKnownIntegerKeys(map, [0, 1, 2], 'signed_capability_revision')
  expectVersion(map, 1n, 'signed_capability_revision')
  return {
    revision: decodeCapabilityRevision(expectBytes(required(map, 1, 'signed_revision.payload'), 'signed_revision.payload')),
    signature: expectBytes(required(map, 2, 'signed_revision.signature'), 'signed_revision.signature', 64),
  }
}

export const capabilityCodecInternals = {
  grantToCbor,
  policyToCbor,
  genesisToCbor,
  revisionToCbor,
}

export { DOMAINS }

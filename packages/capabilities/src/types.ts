export type CapabilityRole =
  | 'reader'
  | 'writer'
  | 'validator'
  | 'administrator'

export interface CapabilityGrant {
  readonly subjectId: Uint8Array
  readonly signingPublicKey: Uint8Array
  /** Authenticated outer replication feed authorized for this capability. */
  readonly transportAuthor?: string
  readonly role: CapabilityRole
  readonly validFromRevision: bigint
  readonly minimumAuthorTimestampMs?: bigint
  readonly hpkePublicKey?: Uint8Array
}

export interface ValidationPolicy {
  readonly version: bigint
  /** Distinct authorized validators whose attestations admit a candidate. */
  readonly minimumValidators: bigint
}

export interface ClockPolicy {
  readonly maxFutureSkewMs: bigint
  readonly cutoffLagMs: bigint
  readonly heartbeatIntervalMs: bigint
}

export interface ResourcePolicy {
  readonly maxCandidateBytes: bigint
  readonly maxProgramNodes: bigint
  readonly maxPreconditions: bigint
  readonly maxMutations: bigint
}

export interface GenesisManifest {
  readonly groupId: Uint8Array
  readonly schemaId: Uint8Array
  readonly rootAdminPublicKey: Uint8Array
  readonly capabilityLogFeed: Uint8Array
  readonly initialCapabilities: readonly CapabilityGrant[]
  readonly validationPolicies: readonly ValidationPolicy[]
  readonly clockPolicy: ClockPolicy
  readonly resourcePolicy: ResourcePolicy
  readonly encryptionSuite: string
  readonly createdAtMs: bigint
  /** Present when this group was forked from a signed snapshot of another group. */
  readonly forkedFrom?: ForkOrigin
}

export interface ForkOrigin {
  readonly groupId: Uint8Array
  /** SHA-256 of the source snapshot's canonical signed manifest (`snapshot.cbor`). */
  readonly snapshotManifestSha256: Uint8Array
  readonly materializedRevision: bigint
}

export interface SignedGenesis {
  readonly manifest: GenesisManifest
  readonly signature: Uint8Array
}

export interface CapabilityRevision {
  readonly groupId: Uint8Array
  readonly revision: bigint
  readonly previousRevisionDigest: Uint8Array
  readonly issuerRootPublicKey: Uint8Array
  readonly grants: readonly CapabilityGrant[]
  readonly revocations: readonly Uint8Array[]
  readonly validationPolicies: readonly ValidationPolicy[]
  readonly successorRootPublicKey?: Uint8Array
  readonly successorCapabilityLogFeed?: Uint8Array
}

export interface SignedCapabilityRevision {
  readonly revision: CapabilityRevision
  readonly signature: Uint8Array
}

export interface EffectiveCapability {
  readonly id: Uint8Array
  readonly grant: CapabilityGrant
  readonly grantedAtRevision: bigint
  readonly revokedAtRevision?: bigint
}

export interface EffectivePolicy {
  readonly id: Uint8Array
  readonly policy: ValidationPolicy
  readonly installedAtRevision: bigint
}

export interface CapabilitySnapshot {
  readonly groupId: Uint8Array
  readonly revision: bigint
  readonly revisionDigest: Uint8Array
  readonly rootAdminPublicKey: Uint8Array
  readonly capabilityLogFeed: Uint8Array
  readonly capabilities: ReadonlyMap<string, EffectiveCapability>
  readonly policies: ReadonlyMap<string, EffectivePolicy>
  /**
   * Highest minimum author timestamp ever granted to a validator. It only rises:
   * revoking validators never lowers it, so closed history cannot be
   * reopened by membership changes. Admitting older history requires a fork.
   */
  readonly validatorFloorMs: bigint
}

export interface ValidatorEvidence {
  readonly capabilityId: Uint8Array
  readonly validatorId: Uint8Array
}

export interface PolicyEvaluation {
  readonly satisfied: boolean
  readonly selected: readonly ValidatorEvidence[]
  readonly missing: readonly string[]
}

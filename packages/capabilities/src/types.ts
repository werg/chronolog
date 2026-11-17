export type CapabilityRole =
  | 'reader'
  | 'writer'
  | 'validator'

/** The complete publication authority of one writer grant. */
export interface ProgramRights {
  readonly sql: boolean
  readonly topics: readonly string[]
  readonly signals: readonly string[]
  /** Permit this original signer to submit through another enrolled feed. */
  readonly forwarded?: boolean
}

interface CapabilityIdentity {
  readonly subjectId: Uint8Array
  readonly signingPublicKey: Uint8Array
  /** Authenticated outer replication feed authorized for this capability. */
  readonly transportAuthor?: string
  readonly minimumAuthorTimestampMs?: bigint
  readonly hpkePublicKey?: Uint8Array
}

/** Membership administration belongs to the signed root key, not a grant role. */
export type CapabilityGrantInput = CapabilityIdentity & (
  | { readonly role: 'writer'; readonly program: ProgramRights }
  | { readonly role: 'reader'; readonly program?: never }
  | { readonly role: 'validator'; readonly program?: never }
)

export type CapabilityGrant = CapabilityGrantInput & { readonly validFromRevision: bigint }

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
  /** Immutable history semantics and SQL profile, authenticated by the root. */
  readonly historyPolicy?: {
    readonly kind: 'peer' | 'coordinated'
    /** Authenticated verifier selection; it never selects execution ordering. */
    readonly providerId?: string
    readonly providerParameters?: Uint8Array
    readonly executionManifestDigest: Uint8Array
    readonly historyId?: string
    readonly authorityPublicKey?: Uint8Array
  }
  readonly groupId: Uint8Array
  readonly schemaId: Uint8Array
  /** Roster and key-distribution issuer; this key grants no SQL ownership. */
  readonly rootAdminPublicKey: Uint8Array
  /** Initial SQL group administrator, authenticated independently of the roster issuer. */
  readonly schemaAdminPublicKey: Uint8Array
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
  readonly grants: readonly (CapabilityGrant & { readonly role: 'reader' | 'writer' })[]
  readonly revocations: readonly Uint8Array[]
  /** Retain the current epoch or advance it by one in this same authority transition. */
  readonly encryptionEpoch: bigint
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

export interface CapabilitySnapshot {
  readonly groupId: Uint8Array
  readonly revision: bigint
  readonly revisionDigest: Uint8Array
  readonly rootAdminPublicKey: Uint8Array
  readonly capabilityLogFeed: Uint8Array
  readonly capabilities: ReadonlyMap<string, EffectiveCapability>
  /** Fixed genesis policies, indexed by the hexadecimal policy digest. */
  readonly policies: ReadonlyMap<string, ValidationPolicy>
  /** Genesis authorizes epoch zero; later epochs activate with their containing revision. */
  readonly encryptionEpoch: bigint
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

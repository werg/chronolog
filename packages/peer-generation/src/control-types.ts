export const PEER_GENERATION_PROFILE = 'peer-generation-v1' as const
export const PEER_GENERATION_POLICY = 'eligible-members-v1' as const
/** Shared generation guarantees implemented by the replica and application session. */
export const PEER_GENERATION_CAPABILITIES = Object.freeze({
  /** Signed author timestamp, signing public key, then stable proposal ID. */
  ordering: 'author-time',
  finality: false, automaticExternalEffects: false, recovery: 'selected-prefix',
} as const)

/** Hex encodings are lowercase and bounded by the verifier, including over JSON transports. */
export interface PeerIdentity { readonly publicKey: string; readonly privateKey: CryptoKey }
export interface Signed<T> { readonly payload: T; readonly signature: string }
export interface ApplicationDescriptor {
  readonly applicationId: string
  readonly historyId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly policy: typeof PEER_GENERATION_POLICY
  readonly controlPublicKey: string
  readonly schemaAdministrator: string
  readonly executionManifestDigest: string
  readonly definitionDigest: string
  readonly schemaDigest: string | null
}
export type SignedApplicationDescriptor = Signed<ApplicationDescriptor>
export interface ApplicationSchema {
  readonly applicationId: string
  readonly definitionDigest: string
  readonly executionManifestDigest: string
  /** Exact canonical ChangeProgram bytes, not executable host callbacks. */
  readonly program: string
}
export type SignedApplicationSchema = Signed<ApplicationSchema>

/** Rights are independent. In particular, reader/writer does not imply recovery. */
export interface PeerGrant {
  readonly publicKey: string
  readonly reader: boolean
  readonly writer: boolean
  readonly coordinator: boolean
  readonly recovery: boolean
  readonly administrator: boolean
  /** Membership of the durable application data collective, independent of coordination. */
  readonly dataRole: 'member' | 'admin' | null
}
/** A position in authenticated inclusion evidence, not an application replay index. */
export interface HistoryPoint {
  readonly generation: string
  readonly sequence: number
  readonly root: string
}
export interface ControlRevision {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly policy: typeof PEER_GENERATION_POLICY
  readonly revision: number
  readonly previous: string | null
  readonly epoch: number
  readonly keyDigest: string
  readonly grants: readonly PeerGrant[]
  /** Preserves selected evidence membership; it does not freeze execution outcomes. */
  readonly recoveryFloor: HistoryPoint | null
}
export type SignedControlRevision = Signed<ControlRevision>

/**
 * The host verifies these inclusion headers without receiving application bodies.
 * Sequence authenticates receipt ancestry; application replay uses author-time order.
 */
export interface OrderHeader {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly generation: string
  readonly sequence: number
  readonly previousRoot: string
  readonly attemptId: string
  readonly author: string
  readonly operationId: string
  readonly bodyHash: string
  readonly bodyBytes: number
}
export interface OrderReceipt extends Signed<OrderHeader> { readonly root: string }

/** bridge proves a strict prefix against an inherited generation's selected cutoff. */
export interface PrefixProof {
  readonly point: HistoryPoint
  readonly receipt: OrderReceipt | null
  readonly bridge: readonly OrderReceipt[]
}
export type TransitionReason = 'create' | 'handover' | 'takeover' | 'control-change'
export interface TransitionRequest {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly policy: typeof PEER_GENERATION_POLICY
  readonly transitionId: string
  readonly expectedGeneration: string | null
  readonly coordinator: string
  readonly requester: string
  readonly controlRevision: number
  /** Domain-separated digest of the exact unsigned referenced control payload. */
  readonly controlIntentDigest: string
  /** Caller-verifiable external transition context, such as host enrollment bindings. */
  readonly contextDigest: string | null
  readonly reason: TransitionReason
  readonly base: PrefixProof | null
}
export type SignedTransitionRequest = Signed<TransitionRequest>
export interface GenerationRecord {
  readonly applicationId: string
  readonly profile: typeof PEER_GENERATION_PROFILE
  readonly policy: typeof PEER_GENERATION_POLICY
  readonly number: number
  readonly previous: string | null
  readonly coordinator: string
  readonly controlRevision: number
  readonly controlDigest: string
  readonly adopted: HistoryPoint | null
  /** A minimum adopted evidence prefix, with no application-finality guarantee. */
  readonly recoveryFloor: HistoryPoint | null
  readonly executionManifestDigest: string
  readonly transition: SignedTransitionRequest
}
export interface SignedGeneration extends Signed<GenerationRecord> { readonly id: string }
export interface AuthorityBundle {
  readonly descriptor: SignedApplicationDescriptor
  readonly controls: readonly SignedControlRevision[]
  readonly generations: readonly SignedGeneration[]
}


/** One exclusive durable owner; put is atomic and durable on acknowledgment. */
export interface PeerStore {
  get(key: string): Promise<Uint8Array | null>
  put(key: string, value: Uint8Array): Promise<void>
}

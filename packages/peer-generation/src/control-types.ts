export const PEER_GENERATION_PROFILE = 'peer-generation-v1' as const
export const PEER_GENERATION_POLICY = 'eligible-members-v1' as const
/** Qualified envelope shared by indexed storage, recovery, and transfer. */
export const PEER_MAX_RECORDS = 16384
export const PEER_MAX_HISTORY_BYTES = 128 * 1024 * 1024
export const PEER_GENERATION_CAPABILITIES = Object.freeze({
  ordering: 'generation-sequence', applied: true, shared: true,
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
  /** May sign code/page releases; independent of controls, data access and sequencing. */
  readonly publisher: boolean
  /** May carry independently signed attempts from current writers. */
  readonly relay?: true
  /** Membership of the durable application data collective, independent of coordination. */
  readonly dataRole: 'member' | 'admin' | null
}
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
  readonly recoveryFloor: HistoryPoint | null
  /** Optional signed definition evolution digest; inherits prior revision or descriptor when omitted. */
  readonly definitionDigest?: string
}
export type SignedControlRevision = Signed<ControlRevision>

/** The host verifies these headers without receiving any application body. */
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


export type { BytesStore } from '@chronolog/records'

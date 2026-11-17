import type { BytesStore } from '@chronolog/records'
import type { PeerIdentity, Signed } from './control-types.js'

export const RELEASE_PROFILE = 'chronolog-release-v1' as const
export const RELEASE_LIMITS = Object.freeze({
  publishers: 128, policies: 256, activations: 1024, publications: 1024,
  assets: 256, fileBytes: 32 * 1024 * 1024, totalBytes: 128 * 1024 * 1024,
  chunkBytes: 65_536, manifestBytes: 256 * 1024, pathCharacters: 512,
  verificationMs: 30_000,
})

/** Pinned independently of application membership, encrypted data and recovery. */
export interface ReleaseTrust {
  readonly applicationId: string
  readonly controlPublicKey: string
}
export interface ReleasePolicy {
  readonly profile: typeof RELEASE_PROFILE
  readonly applicationId: string
  /** Page access controls delivery; the serving participant can read these assets. */
  readonly scope: 'page'
  readonly revision: number
  readonly previous: string | null
  readonly requestId: string
  readonly publishers: readonly string[]
}
export type SignedReleasePolicy = Signed<ReleasePolicy>
export interface ReleasePolicyRequest {
  readonly requestId: string
  readonly expectedPolicy: string | null
  readonly publishers: readonly string[]
}
export interface ReleaseApplicationBinding {
  readonly historyId: string
  readonly definitionDigest: string
  readonly executionManifestDigest: string
  readonly schemaDigest: string | null
}
export interface ReleaseAsset {
  readonly path: string
  readonly digest: string
  readonly bytes: number
  readonly mediaType: string
}
/** Complete immutable authored assets. Trusted bootstrap injection is separate. */
export interface ReleaseManifest {
  readonly profile: typeof RELEASE_PROFILE
  readonly applicationId: string
  readonly scope: 'page'
  readonly publisher: string
  readonly policyRevision: number
  readonly entry: string
  readonly assets: readonly ReleaseAsset[]
  /** Null only for a shell published before an application is configured. */
  readonly application: ReleaseApplicationBinding | null
}
export type SignedReleaseManifest = Signed<ReleaseManifest>
export interface ReleasePublication {
  readonly id: string
  readonly manifest: SignedReleaseManifest
}
export interface ReleaseActivationRequest {
  readonly profile: typeof RELEASE_PROFILE
  readonly applicationId: string
  readonly requestId: string
  readonly publisher: string
  readonly policyRevision: number
  readonly expectedActivation: string | null
  readonly releaseId: string
}
export type SignedReleaseActivationRequest = Signed<ReleaseActivationRequest>
export interface ReleaseActivation {
  readonly profile: typeof RELEASE_PROFILE
  readonly applicationId: string
  readonly revision: number
  readonly previous: string | null
  readonly policyRevision: number
  readonly policyDigest: string
  readonly releaseId: string
  readonly request: SignedReleaseActivationRequest
}
export interface SignedReleaseActivation extends Signed<ReleaseActivation> { readonly id: string }
export interface ReleaseState extends ReleaseTrust {
  readonly profile: typeof RELEASE_PROFILE
  readonly policies: readonly SignedReleasePolicy[]
  readonly activations: readonly SignedReleaseActivation[]
}

/** Read exact immutable bytes in bounded chunks. No application epoch key is involved. */
export interface ReleaseContentSource {
  read(asset: ReleaseAsset, options?: { readonly signal?: AbortSignal }): AsyncIterable<Uint8Array>
}
export interface ReleaseRegistry {
  read(): Promise<ReleaseState>
  configure(request: ReleasePolicyRequest): Promise<SignedReleasePolicy>
  publish(manifest: SignedReleaseManifest): Promise<ReleasePublication>
  manifest(id: string): Promise<SignedReleaseManifest | null>
  activate(request: SignedReleaseActivationRequest): Promise<SignedReleaseActivation>
}
export interface ReleaseRegistryOptions {
  readonly store: BytesStore
  readonly applicationId: string
  readonly signer: PeerIdentity
  readonly content: ReleaseContentSource
  /** When supplied, activation must match the currently configured application. */
  readonly application?: () => Promise<ReleaseApplicationBinding | null>
  readonly requireExisting?: boolean
}

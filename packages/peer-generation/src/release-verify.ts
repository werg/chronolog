import { bytesToHex, createSha256 } from '@chronolog/canonical'
import { DOMAINS } from '@chronolog/protocol'
import {
  boundedText, check, encodePeerValue, hex, isArray, object, peerDigest,
  samePeerValue, signPeerValue, uint, verifyPeerValue,
} from './codec.js'
import type { PeerIdentity } from './control-types.js'
import {
  RELEASE_LIMITS, RELEASE_PROFILE, type ReleaseActivationRequest, type ReleaseApplicationBinding,
  type ReleaseAsset, type ReleaseContentSource, type ReleaseManifest, type ReleasePolicy,
  type ReleasePolicyRequest, type ReleaseState, type ReleaseTrust, type SignedReleaseActivation,
  type SignedReleaseActivationRequest, type SignedReleaseManifest, type SignedReleasePolicy,
} from './release-types.js'

function scoped(value: { readonly applicationId: string; readonly profile: string }, trust: ReleaseTrust): void {
  hex(trust.applicationId); hex(trust.controlPublicKey)
  check(value.profile === RELEASE_PROFILE && value.applicationId === trust.applicationId, 'RELEASE_SCOPE_MISMATCH')
}
function optionalDigest(value: string | null): void { if (value !== null) hex(value) }
export function validateReleasePath(value: string): void {
  boundedText(value, RELEASE_LIMITS.pathCharacters)
  check(/^[A-Za-z0-9._~!$&'()+,;=@/-]+$/u.test(value) &&
    value.split('/').every(part => part.length > 0 && part !== '.' && part !== '..') &&
    !['_publications', '_tendril', '_tendriller', '__tendriller', 'peers', 'members'].includes(value.split('/')[0]!), 'RELEASE_PATH_INVALID')
}
export function validateReleaseApplicationBinding(value: ReleaseApplicationBinding): void {
  object(value, ['historyId', 'definitionDigest', 'executionManifestDigest', 'schemaDigest'])
  boundedText(value.historyId, 128); hex(value.definitionDigest); hex(value.executionManifestDigest); optionalDigest(value.schemaDigest)
}
export function validateReleaseAsset(value: ReleaseAsset): void {
  object(value, ['path', 'digest', 'bytes', 'mediaType']); validateReleasePath(value.path); hex(value.digest)
  uint(value.bytes, RELEASE_LIMITS.fileBytes); boundedText(value.mediaType, 128)
  check(/^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:;[\x20-\x7e]+)?$/u.test(value.mediaType), 'RELEASE_MEDIA_TYPE_INVALID')
}
function publishers(values: readonly string[]): void {
  check(isArray(values) && values.length <= RELEASE_LIMITS.publishers, 'RELEASE_PUBLISHER_LIMIT')
  let prior = ''
  for (const value of values) { hex(value); check(value > prior, 'RELEASE_PUBLISHERS_NOT_SORTED'); prior = value }
}
export function validateReleasePolicyRequest(value: ReleasePolicyRequest): void {
  object(value, ['requestId', 'expectedPolicy', 'publishers']); boundedText(value.requestId, 128)
  optionalDigest(value.expectedPolicy); publishers(value.publishers)
}
export function validateReleasePolicy(value: ReleasePolicy): void {
  object(value, ['profile', 'applicationId', 'scope', 'revision', 'previous', 'requestId', 'publishers'])
  hex(value.applicationId); uint(value.revision, RELEASE_LIMITS.policies - 1); optionalDigest(value.previous)
  boundedText(value.requestId, 128); publishers(value.publishers)
  check(value.profile === RELEASE_PROFILE && value.scope === 'page', 'RELEASE_PROFILE_UNSUPPORTED')
  check((value.revision === 0) === (value.previous === null), 'RELEASE_POLICY_CHAIN_INVALID')
}
export function validateReleaseManifest(value: ReleaseManifest): void {
  object(value, ['profile', 'applicationId', 'scope', 'publisher', 'policyRevision', 'entry', 'assets', 'application'])
  hex(value.applicationId); hex(value.publisher); uint(value.policyRevision, RELEASE_LIMITS.policies - 1)
  check(value.profile === RELEASE_PROFILE && value.scope === 'page', 'RELEASE_PROFILE_UNSUPPORTED')
  validateReleasePath(value.entry)
  check(isArray(value.assets) && value.assets.length > 0 && value.assets.length <= RELEASE_LIMITS.assets, 'RELEASE_ASSET_LIMIT')
  let prior = '', total = 0
  const sizes = new Map<string, number>()
  for (const asset of value.assets) {
    validateReleaseAsset(asset); check(asset.path > prior, 'RELEASE_ASSETS_NOT_SORTED'); prior = asset.path
    const size = sizes.get(asset.digest)
    check(size === undefined || size === asset.bytes, 'RELEASE_CONTENT_LENGTH_MISMATCH'); sizes.set(asset.digest, asset.bytes)
    total += asset.bytes; check(total <= RELEASE_LIMITS.totalBytes, 'RELEASE_CONTENT_LIMIT')
  }
  check(value.assets.some(asset => asset.path === value.entry && asset.mediaType.split(';')[0] === 'text/html'), 'RELEASE_HTML_ENTRY_REQUIRED')
  if (value.application !== null) validateReleaseApplicationBinding(value.application)
  check(encodePeerValue(value).length <= RELEASE_LIMITS.manifestBytes, 'RELEASE_MANIFEST_LIMIT')
}
export function validateReleaseActivationRequest(value: ReleaseActivationRequest): void {
  object(value, ['profile', 'applicationId', 'requestId', 'publisher', 'policyRevision', 'expectedActivation', 'releaseId'])
  hex(value.applicationId); boundedText(value.requestId, 128); hex(value.publisher); hex(value.releaseId)
  uint(value.policyRevision, RELEASE_LIMITS.policies - 1); optionalDigest(value.expectedActivation)
  check(value.profile === RELEASE_PROFILE, 'RELEASE_PROFILE_UNSUPPORTED')
}
export async function signReleasePolicy(value: ReleasePolicy, signer: PeerIdentity): Promise<SignedReleasePolicy> {
  validateReleasePolicy(value); return signPeerValue(DOMAINS.releasePolicy, value, signer)
}
export async function signReleaseManifest(value: ReleaseManifest, signer: PeerIdentity): Promise<SignedReleaseManifest> {
  validateReleaseManifest(value); check(value.publisher === signer.publicKey, 'RELEASE_PUBLISHER_KEY_MISMATCH')
  return signPeerValue(DOMAINS.releaseManifest, value, signer)
}
export async function signReleaseActivationRequest(value: ReleaseActivationRequest, signer: PeerIdentity): Promise<SignedReleaseActivationRequest> {
  validateReleaseActivationRequest(value); check(value.publisher === signer.publicKey, 'RELEASE_PUBLISHER_KEY_MISMATCH')
  return signPeerValue(DOMAINS.releaseRequest, value, signer)
}
export async function verifyReleasePolicy(value: SignedReleasePolicy, trust: ReleaseTrust): Promise<void> {
  validateReleasePolicy(value.payload); scoped(value.payload, trust)
  await verifyPeerValue(DOMAINS.releasePolicy, value, trust.controlPublicKey)
}
export async function verifyReleaseManifest(value: SignedReleaseManifest, policy: SignedReleasePolicy, trust: ReleaseTrust): Promise<string> {
  validateReleaseManifest(value.payload); scoped(value.payload, trust); await verifyReleasePolicy(policy, trust)
  check(value.payload.policyRevision === policy.payload.revision && policy.payload.publishers.includes(value.payload.publisher), 'RELEASE_PUBLISHER_DENIED')
  await verifyPeerValue(DOMAINS.releaseManifest, value, value.payload.publisher)
  return peerDigest(value)
}
export async function verifyReleaseActivationRequest(value: SignedReleaseActivationRequest, policy: SignedReleasePolicy, trust: ReleaseTrust): Promise<void> {
  validateReleaseActivationRequest(value.payload); scoped(value.payload, trust); await verifyReleasePolicy(policy, trust)
  check(value.payload.policyRevision === policy.payload.revision && policy.payload.publishers.includes(value.payload.publisher), 'RELEASE_PUBLISHER_DENIED')
  await verifyPeerValue(DOMAINS.releaseRequest, value, value.payload.publisher)
}
export async function verifyReleaseActivation(value: SignedReleaseActivation, policy: SignedReleasePolicy, trust: ReleaseTrust): Promise<void> {
  object(value, ['payload', 'signature', 'id']); hex(value.id)
  const payload = value.payload
  object(payload, ['profile', 'applicationId', 'revision', 'previous', 'policyRevision', 'policyDigest', 'releaseId', 'request'])
  scoped(payload, trust); uint(payload.revision, RELEASE_LIMITS.activations - 1); optionalDigest(payload.previous)
  uint(payload.policyRevision, RELEASE_LIMITS.policies - 1); hex(payload.policyDigest); hex(payload.releaseId)
  check((payload.revision === 0) === (payload.previous === null), 'RELEASE_ACTIVATION_CHAIN_INVALID')
  await verifyReleaseActivationRequest(payload.request, policy, trust)
  check(payload.policyRevision === policy.payload.revision && payload.policyDigest === await peerDigest(policy) &&
    payload.request.payload.expectedActivation === payload.previous && payload.request.payload.releaseId === payload.releaseId, 'RELEASE_ACTIVATION_MISMATCH')
  const signed = { payload, signature: value.signature }
  await verifyPeerValue(DOMAINS.releaseActivation, signed, trust.controlPublicKey)
  check(value.id === await peerDigest(signed), 'RELEASE_ACTIVATION_ID_INVALID')
}
/** Verifies the separate monotonic policy and activation histories, never a data generation. */
export async function verifyReleaseState(input: ReleaseState, trust: ReleaseTrust): Promise<ReleaseState> {
  const value = structuredClone(input)
  object(value, ['profile', 'applicationId', 'controlPublicKey', 'policies', 'activations']); scoped(value, trust)
  check(value.controlPublicKey === trust.controlPublicKey, 'RELEASE_CONTROL_KEY_MISMATCH')
  check(isArray(value.policies) && value.policies.length <= RELEASE_LIMITS.policies, 'RELEASE_POLICY_LIMIT')
  check(isArray(value.activations) && value.activations.length <= RELEASE_LIMITS.activations, 'RELEASE_ACTIVATION_LIMIT')
  const policyRequests = new Set<string>(), requests = new Set<string>()
  for (let index = 0; index < value.policies.length; index++) {
    const policy = value.policies[index]!
    await verifyReleasePolicy(policy, trust)
    check(policy.payload.revision === index && policy.payload.previous === (index === 0 ? null : await peerDigest(value.policies[index - 1])), 'RELEASE_POLICY_CHAIN_INVALID')
    check(!policyRequests.has(policy.payload.requestId), 'RELEASE_POLICY_REQUEST_REUSED'); policyRequests.add(policy.payload.requestId)
  }
  let priorPolicy = 0
  for (let index = 0; index < value.activations.length; index++) {
    const activation = value.activations[index]!, policy = value.policies[activation.payload.policyRevision]
    check(policy !== undefined, 'RELEASE_POLICY_MISSING'); await verifyReleaseActivation(activation, policy, trust)
    check(activation.payload.revision === index && activation.payload.previous === (value.activations[index - 1]?.id ?? null) &&
      activation.payload.policyRevision >= priorPolicy, 'RELEASE_ACTIVATION_CHAIN_INVALID')
    const request = activation.payload.request.payload, key = `${request.publisher}/${request.requestId}`
    check(!requests.has(key), 'RELEASE_ACTIVATION_REQUEST_REUSED'); requests.add(key); priorPolicy = activation.payload.policyRevision
  }
  return value
}
/** A learned publisher revocation or code activation cannot be replaced by an old signed state. */
export function assertReleaseStateExtension(previous: ReleaseState, next: ReleaseState): void {
  check(previous.applicationId === next.applicationId && previous.controlPublicKey === next.controlPublicKey &&
    previous.profile === next.profile, 'RELEASE_SCOPE_MISMATCH')
  check(next.policies.length >= previous.policies.length && next.activations.length >= previous.activations.length, 'RELEASE_STATE_REGRESSION')
  for (let index = 0; index < previous.policies.length; index++) check(samePeerValue(previous.policies[index], next.policies[index]), 'RELEASE_POLICY_EQUIVOCATION')
  for (let index = 0; index < previous.activations.length; index++) check(samePeerValue(previous.activations[index], next.activations[index]), 'RELEASE_ACTIVATION_EQUIVOCATION')
  for (const activation of next.activations.slice(previous.activations.length)) {
    check(activation.payload.policyRevision >= previous.policies.length - 1, 'RELEASE_ACTIVATION_STALE_POLICY')
  }
}
/** Incremental verification limits memory to one source chunk and one hash state. */
export async function verifyReleaseContent(manifest: SignedReleaseManifest, content: ReleaseContentSource): Promise<void> {
  validateReleaseManifest(manifest.payload)
  const verified = new Set<string>()
  for (const asset of manifest.payload.assets) {
    if (verified.has(asset.digest)) continue
    const hash = createSha256(); let bytes = 0
    for await (const chunk of content.read(structuredClone(asset))) {
      check(chunk instanceof Uint8Array && chunk.byteLength > 0 && chunk.byteLength <= RELEASE_LIMITS.chunkBytes, 'RELEASE_CONTENT_CHUNK_INVALID')
      bytes += chunk.byteLength; check(bytes <= asset.bytes, 'RELEASE_CONTENT_LENGTH_MISMATCH'); hash.update(chunk)
    }
    check(bytes === asset.bytes, 'RELEASE_CONTENT_INCOMPLETE')
    check(bytesToHex(hash.digest()) === asset.digest, 'RELEASE_CONTENT_DIGEST_MISMATCH'); verified.add(asset.digest)
  }
}

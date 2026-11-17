import { describe, expect, it } from 'vitest'
import { DOMAINS } from '@chronolog/protocol'
import {
  assertReleaseStateExtension, bytesDigest, createPeerIdentity, peerDigest, RELEASE_LIMITS, RELEASE_PROFILE,
  signReleaseActivationRequest, signReleaseManifest, signReleasePolicy, validateReleaseManifest,
  verifyReleaseActivation, verifyReleaseAsset, verifyReleaseContent, verifyReleaseManifest, verifyReleaseState,
  type ReleaseManifest, type ReleaseState, type SignedReleaseActivation,
} from './control.js'
import { signPeerValue } from './codec.js'

async function fixture() {
  const host = await createPeerIdentity(), publisher = await createPeerIdentity(), stranger = await createPeerIdentity()
  const trust = { applicationId: 'ab'.repeat(32), controlPublicKey: host.publicKey }
  const policy = await signReleasePolicy({ profile: RELEASE_PROFILE, applicationId: trust.applicationId,
    scope: 'page', revision: 0, previous: null, requestId: 'initial-policy', publishers: [publisher.publicKey] }, host)
  const bytes = new TextEncoder().encode('<!doctype html><title>Verified release</title>')
  const manifest: ReleaseManifest = { profile: RELEASE_PROFILE, applicationId: trust.applicationId, scope: 'page',
    publisher: publisher.publicKey, policyRevision: 0, entry: 'index.html', application: null,
    assets: [{ path: 'index.html', digest: await bytesDigest(bytes), bytes: bytes.length, mediaType: 'text/html; charset=utf-8' }] }
  const signed = await signReleaseManifest(manifest, publisher), id = await peerDigest(signed)
  const request = await signReleaseActivationRequest({ profile: RELEASE_PROFILE, applicationId: trust.applicationId,
    requestId: 'activate-first', publisher: publisher.publicKey, policyRevision: 0, expectedActivation: null, releaseId: id }, publisher)
  const activationSigned = await signPeerValue(DOMAINS.releaseActivation, { profile: RELEASE_PROFILE, applicationId: trust.applicationId,
    revision: 0, previous: null, policyRevision: 0, policyDigest: await peerDigest(policy), releaseId: id, request }, host)
  const activation: SignedReleaseActivation = { ...activationSigned, id: await peerDigest(activationSigned) }
  const state: ReleaseState = { ...trust, profile: RELEASE_PROFILE, policies: [policy], activations: [activation] }
  return { host, publisher, stranger, trust, policy, bytes, manifest, signed, id, request, activation, state }
}

describe('separate signed release authority', () => {
  it('verifies a binary storage asset incrementally before exposing its bytes', async () => {
    const bytes = new Uint8Array(70_000).fill(255), digest = await bytesDigest(bytes)
    const asset = { path: 'assets/binary.dat', digest, bytes: bytes.length, mediaType: 'application/octet-stream' }
    let requestedSignal: AbortSignal | undefined
    await verifyReleaseAsset(asset, { async *read(value, options) {
      expect(value).toEqual(asset); requestedSignal = options?.signal
      yield bytes.subarray(0, RELEASE_LIMITS.chunkBytes); yield bytes.subarray(RELEASE_LIMITS.chunkBytes)
    } })
    expect(requestedSignal?.aborted).toBe(false)
    const corrupt = bytes.slice(); corrupt[0] = 0
    await expect(verifyReleaseAsset(asset, { async *read() {
      yield corrupt.subarray(0, RELEASE_LIMITS.chunkBytes); yield corrupt.subarray(RELEASE_LIMITS.chunkBytes)
    } })).rejects.toThrow('RELEASE_CONTENT_DIGEST_MISMATCH')
    await expect(verifyReleaseAsset(asset, { async *read() { yield bytes } })).rejects.toThrow('RELEASE_CONTENT_CHUNK_INVALID')
  })

  it('binds code to the publisher policy, scope, exact manifest and explicit activation', async () => {
    const f = await fixture()
    expect(await verifyReleaseManifest(f.signed, f.policy, f.trust)).toBe(f.id)
    await expect(verifyReleaseActivation(f.activation, f.policy, f.trust)).resolves.toBeUndefined()
    expect(await verifyReleaseState(f.state, f.trust)).toEqual(f.state)
    await expect(verifyReleaseManifest({ ...f.signed, payload: { ...f.manifest, entry: 'different.html' } }, f.policy, f.trust))
      .rejects.toThrow('RELEASE_HTML_ENTRY_REQUIRED')
    await expect(verifyReleaseManifest({ ...f.signed, payload: { ...f.manifest, application: {
      historyId: 'other', definitionDigest: 'cd'.repeat(32), executionManifestDigest: 'ef'.repeat(32), schemaDigest: null,
    } } }, f.policy, f.trust)).rejects.toThrow('PEER_SIGNATURE_INVALID')
    await expect(verifyReleaseManifest(f.signed, f.policy, { ...f.trust, applicationId: 'cd'.repeat(32) })).rejects.toThrow('RELEASE_SCOPE_MISMATCH')
    await expect(verifyReleaseManifest(f.signed, f.policy, { ...f.trust, controlPublicKey: f.stranger.publicKey })).rejects.toThrow('PEER_SIGNATURE_INVALID')
  })

  it('does not infer publishing permission from another signing identity or application role', async () => {
    const f = await fixture()
    const unauthorized = await signReleaseManifest({ ...f.manifest, publisher: f.stranger.publicKey }, f.stranger)
    await expect(verifyReleaseManifest(unauthorized, f.policy, f.trust)).rejects.toThrow('RELEASE_PUBLISHER_DENIED')
    const confused = await signPeerValue(DOMAINS.peerControl, f.manifest, f.publisher)
    await expect(verifyReleaseManifest(confused, f.policy, f.trust)).rejects.toThrow('PEER_SIGNATURE_INVALID')
    await expect(signReleaseManifest(f.manifest, f.stranger)).rejects.toThrow('RELEASE_PUBLISHER_KEY_MISMATCH')
  })

  it.each(['../index.html', '/index.html', 'a//b.html', 'a/./b.html', 'a/../b.html', 'a\\b.html', '%2e%2e/index.html', 'index.html?x=1', '_publications/x', '_tendril/api'])('rejects ambiguous or reserved asset path %s', async path => {
    const f = await fixture()
    expect(() => validateReleaseManifest({ ...f.manifest, entry: path, assets: [{ ...f.manifest.assets[0]!, path }] })).toThrow('RELEASE_PATH_INVALID')
  })

  it('requires complete sorted bounded assets and an HTML entry', async () => {
    const f = await fixture(), asset = f.manifest.assets[0]!
    expect(() => validateReleaseManifest({ ...f.manifest, assets: [asset, asset] })).toThrow('RELEASE_ASSETS_NOT_SORTED')
    expect(() => validateReleaseManifest({ ...f.manifest, assets: [{ ...asset, mediaType: 'application/javascript' }] })).toThrow('RELEASE_HTML_ENTRY_REQUIRED')
    expect(() => validateReleaseManifest({ ...f.manifest, assets: [{ ...asset, bytes: RELEASE_LIMITS.fileBytes + 1 }] })).toThrow('PEER_INTEGER_INVALID')
    expect(() => validateReleaseManifest({ ...f.manifest, assets: [{ ...asset, mediaType: 'text/html\r\nHeader: injected' }] })).toThrow('PEER_TEXT_INVALID')
    expect(() => validateReleaseManifest({ ...f.manifest, assets: Array.from({ length: RELEASE_LIMITS.assets + 1 }, () => asset) })).toThrow('RELEASE_ASSET_LIMIT')
  })

  it('checks exact content incrementally and refuses corrupt or partial copies', async () => {
    const f = await fixture()
    await expect(verifyReleaseContent(f.signed, { async *read() { yield f.bytes.slice(0, 4); yield f.bytes.slice(4) } })).resolves.toBeUndefined()
    await expect(verifyReleaseContent(f.signed, { async *read() { yield f.bytes.slice(1) } })).rejects.toThrow('RELEASE_CONTENT_INCOMPLETE')
    const corrupt = f.bytes.slice(); corrupt[0] = corrupt[0]! ^ 1
    await expect(verifyReleaseContent(f.signed, { async *read() { yield corrupt } })).rejects.toThrow('RELEASE_CONTENT_DIGEST_MISMATCH')
    await expect(verifyReleaseContent(f.signed, { async *read() { yield new Uint8Array(RELEASE_LIMITS.chunkBytes + 1) } })).rejects.toThrow('RELEASE_CONTENT_CHUNK_INVALID')
  })

  it('retains learned revocations and activation history independently of application recovery', async () => {
    const f = await fixture()
    const revoked = await signReleasePolicy({ ...f.policy.payload, revision: 1, previous: await peerDigest(f.policy),
      requestId: 'freeze-publishing', publishers: [] }, f.host)
    const next: ReleaseState = { ...f.state, policies: [f.policy, revoked] }
    await expect(verifyReleaseState(next, f.trust)).resolves.toEqual(next)
    expect(() => assertReleaseStateExtension(f.state, next)).not.toThrow()
    expect(() => assertReleaseStateExtension(next, f.state)).toThrow('RELEASE_STATE_REGRESSION')
    expect(() => assertReleaseStateExtension(next, { ...next, activations: [] })).toThrow('RELEASE_STATE_REGRESSION')
    const forked = await signReleasePolicy({ ...revoked.payload, publishers: [f.stranger.publicKey] }, f.host)
    expect(() => assertReleaseStateExtension(next, { ...next, policies: [f.policy, forked] })).toThrow('RELEASE_POLICY_EQUIVOCATION')
    const staleRequest = await signReleaseActivationRequest({ ...f.request.payload, requestId: 'after-revocation', expectedActivation: f.activation.id }, f.publisher)
    const signed = await signPeerValue(DOMAINS.releaseActivation, { ...f.activation.payload, revision: 1,
      previous: f.activation.id, request: staleRequest }, f.host)
    const stale = { ...signed, id: await peerDigest(signed) }
    expect(() => assertReleaseStateExtension(next, { ...next, activations: [f.activation, stale] })).toThrow('RELEASE_ACTIVATION_STALE_POLICY')
  })
})

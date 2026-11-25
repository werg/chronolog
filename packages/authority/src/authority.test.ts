import { expect, it } from 'vitest'
import { sha256, bytesToHex } from '@chronolog/canonical'
import { createSigningIdentity, signEnrollmentRequest, verifyEnrollmentRequest, signPublicationManifest, verifyPublicationManifest, authorizePublication, verifyPublicationAsset, validateFinalityPolicy, encodeRecord, decodeRecord, type PublicationAuthority } from './index.js'
it('publishes and verifies signed assets under an independent publisher grant before a data owner or schema exists', async () => {
  const publisher = await createSigningIdentity(), asset = new TextEncoder().encode('<main>Public application UI</main>'), authority: PublicationAuthority = { applicationId: '01'.repeat(32), executionManifestDigest: '02'.repeat(32), grantId: '03'.repeat(32), publisherKeys: [publisher.publicKey] }
  const publication = await signPublicationManifest({ applicationId: authority.applicationId, membershipId: authority.grantId, author: publisher.publicKey, operationId: 'publish-before-owner', revision: 0, previous: null, executionManifestDigest: authority.executionManifestDigest, entry: 'index.html', files: [{ path: 'index.html', hash: bytesToHex(await sha256(asset)), size: asset.length, type: 'text/html' }] }, publisher)
  await verifyPublicationManifest(publication, authority); await authorizePublication(publication, authority, null); await verifyPublicationAsset(publication.payload.files[0]!, asset)
  expect('rootPrincipal' in publication.payload).toBe(false); expect('schemaDigest' in publication.payload).toBe(false)
  await expect(verifyPublicationManifest(publication, { ...authority, publisherKeys: [] })).rejects.toThrow('PUBLICATION_PUBLISHER_REQUIRED')
  await expect(authorizePublication(publication, { ...authority, grantId: '04'.repeat(32) }, null)).rejects.toThrow('PUBLICATION_PUBLISHER_REQUIRED')
})
it('binds enrollment to the actual signing key, its key-wrap key and the host challenge', async () => {
  const identity = await createSigningIdentity(), request = await signEnrollmentRequest({ applicationId: '05'.repeat(32), publicKey: identity.publicKey, wrapKey: '06'.repeat(32), challenge: 'host-challenge' }, identity)
  await verifyEnrollmentRequest(request)
  const changed = { ...request, payload: { ...request.payload, wrapKey: '07'.repeat(32) } }
  await expect(verifyEnrollmentRequest(changed)).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
  const other = await createSigningIdentity(); await expect(signEnrollmentRequest(request.payload, other)).rejects.toThrow('ENROLLMENT_REQUEST_INVALID')
})
it('canonical authority wire bytes retain exact bigint activation and typed byte fields', () => {
  const value = { authorTimeAfterMs: (1n << 63n) - 1n, bytes: Uint8Array.of(0, 127, 255) }
  expect(decodeRecord(encodeRecord(value))).toEqual(value)
  expect(() => decodeRecord(new TextEncoder().encode('{"z":1,"a":2}'))).toThrow('RECORD_NOT_CANONICAL')
})
it('validates bounded exact-key finality policies without fabricating a data root descriptor', () => {
  expect(validateFinalityPolicy({ kind: 'none' })).toEqual({ kind: 'none' })
  const policy = { kind: 'signed-frontier', signer: '08'.repeat(32), scopes: [{ id: '09'.repeat(32), authorTimeAfterMs: -1n }] }
  expect(validateFinalityPolicy(policy)).toEqual(policy)
  expect(() => validateFinalityPolicy({ ...policy, comparator: 'host-clock' })).toThrow('FINALITY_POLICY_FIELDS_INVALID')
  expect(() => validateFinalityPolicy({ kind: 'none', validators: [] })).toThrow('FINALITY_POLICY_FIELDS_INVALID')
  expect(() => validateFinalityPolicy({ kind: 'fixed-validator', validators: ['08'.repeat(32)], threshold: 2, scopes: policy.scopes })).toThrow('FINALITY_VALIDATORS_INVALID')
  expect(() => validateFinalityPolicy({ ...policy, scopes: [{ ...policy.scopes[0], authorTimeAfterMs: -1 }] })).toThrow('FINALITY_SCOPE_INVALID')
})

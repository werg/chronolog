import { expect, it } from 'vitest'
import { bytesToHex, sha256 } from '@chronolog/canonical'
import { createSigningIdentity, signAppDescriptor, signMembership, signHostAttestation, verifyHostAttestation, attestedAccountAuthorized, verifyAuthorityBundle, recordDigest, inviteRedemptions, type AdmissionPolicy, type HostAttestation, type Membership, type SignedMembership, type MemberGrant, type PageInvite, type SigningIdentity } from './index.js'
const applicationId = 'a1'.repeat(32), hex = (byte: string) => byte.repeat(32)
async function chain(mode: AdmissionPolicy['mode'] = 'attested', invites: PageInvite[] = []) {
  const creator = await createSigningIdentity(), host = await createSigningIdentity(), agent = await createSigningIdentity()
  const admission: AdmissionPolicy = { mode, hostKey: host.publicKey, accounts: ['acct_owner', 'email:owner@example.test'], grant: { reader: true, writer: true } }
  const descriptor = await signAppDescriptor({ applicationId, rootPrincipal: creator.publicKey, authorityPublicKey: creator.publicKey, executionManifestDigest: hex('b2'), finalityPolicy: { kind: 'none' } }, creator)
  const grant = (publicKey: string, wrapKey: string, administrator: boolean): MemberGrant => ({ publicKey, wrapKey, reader: true, writer: true, administrator, publisher: false, finalizer: false })
  const genesis = await signMembership({ applicationId, revision: 0, previous: null, authorTimeAfterMs: -1n, epoch: 0, epochKeyDigest: hex('c3'), members: [grant(creator.publicKey, hex('d4'), true), grant(agent.publicKey, hex('d5'), false)], admission, admitted: [], invites }, creator)
  const attest = async (device: SigningIdentity, overrides: Partial<HostAttestation> = {}, signer = host) => signHostAttestation({ subject: 'device', pageId: 'abcdefghijkl', applicationId, accountId: 'acct_owner', email: 'owner@example.test', publicKey: device.publicKey, wrapKey: hex('e6'), label: 'Phone', inviteId: null, issuedAt: 1_000n, expiresAt: 600_000n, nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(32))), ...overrides }, signer)
  const extend = async (memberships: SignedMembership[], change: (head: Membership) => Partial<Membership>, signer: SigningIdentity) => {
    const head = memberships.at(-1)!
    return [...memberships, await signMembership({ ...head.payload, admitted: [], revision: head.payload.revision + 1, previous: await recordDigest(head), authorTimeAfterMs: 5_000n + BigInt(memberships.length), ...change(head.payload) }, signer)]
  }
  return { creator, host, agent, admission, descriptor, genesis, grant, attest, extend }
}
it('host attestations verify only against the pinned key, scope and authorized account', async () => {
  const c = await chain(), device = await createSigningIdentity(), forger = await createSigningIdentity()
  const attestation = await c.attest(device)
  expect((await verifyHostAttestation(attestation, { hostKey: c.host.publicKey, applicationId, pageId: 'abcdefghijkl' })).publicKey).toBe(device.publicKey)
  await expect(verifyHostAttestation(await c.attest(device, {}, forger), { hostKey: c.host.publicKey, applicationId })).rejects.toThrow('AUTHORITY_SIGNER_MISMATCH')
  const forged = { ...attestation, signer: c.host.publicKey, payload: { ...attestation.payload, accountId: 'acct_other' } }
  await expect(verifyHostAttestation(forged, { hostKey: c.host.publicKey, applicationId })).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
  await expect(verifyHostAttestation(attestation, { hostKey: c.host.publicKey, applicationId, pageId: 'otherpageidx' })).rejects.toThrow('ATTESTATION_SCOPE_MISMATCH')
  await expect(verifyHostAttestation(attestation, { hostKey: c.host.publicKey, applicationId: 'f0'.repeat(32) })).rejects.toThrow('ATTESTATION_SCOPE_MISMATCH')
  expect(attestedAccountAuthorized(c.admission, attestation.payload)).toBe(true)
  expect(attestedAccountAuthorized(c.admission, { ...attestation.payload, accountId: 'acct_guest', email: 'guest@example.test' })).toBe(false)
  expect(attestedAccountAuthorized(c.admission, { ...attestation.payload, accountId: 'acct_new', email: 'owner@example.test' })).toBe(true)
})
it('any reader member admits an attested owner device with exactly the policy grant; the host cannot', async () => {
  const c = await chain(), device = await createSigningIdentity(), attestation = await c.attest(device)
  const admit = (signer: SigningIdentity, grant = c.grant(device.publicKey, hex('e6'), false), via: 'attested' | 'approved' = 'attested', att = attestation) =>
    c.extend([c.genesis], head => ({ members: [...head.members, grant], admitted: [{ publicKey: device.publicKey, via, attestation: att }] }), signer)
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent) })
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.creator) })
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.host) })).rejects.toThrow('AUTHORITY_ADMIN_REQUIRED')
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, c.grant(device.publicKey, hex('e6'), true)) })).rejects.toThrow('AUTHORITY_ADMIN_REQUIRED')
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, undefined, 'approved') })).rejects.toThrow('AUTHORITY_ADMIN_REQUIRED')
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, undefined, 'attested', await c.attest(device, { accountId: 'acct_guest', email: null })) })).rejects.toThrow('AUTHORITY_ADMISSION_ACCOUNT_FORBIDDEN')
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, undefined, 'attested', await c.attest(device, { issuedAt: 1n, expiresAt: 2_000n })) })).rejects.toThrow('AUTHORITY_ADMISSION_EXPIRED')
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, undefined, 'attested', await c.attest(device, {}, await createSigningIdentity())) })).rejects.toThrow('AUTHORITY_SIGNER_MISMATCH')
  // A guest account still needs an administrator's explicit approval.
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.creator, undefined, 'approved', await c.attest(device, { accountId: 'acct_guest', email: null })) })
})
it('strict mode keeps attested devices pending until an administrator approves them', async () => {
  const c = await chain('strict'), device = await createSigningIdentity(), attestation = await c.attest(device)
  const admit = (signer: SigningIdentity, via: 'attested' | 'approved') => c.extend([c.genesis], head => ({ members: [...head.members, c.grant(device.publicKey, hex('e6'), false)], admitted: [{ publicKey: device.publicKey, via, attestation }] }), signer)
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.agent, 'attested') })).rejects.toThrow('AUTHORITY_ADMIN_REQUIRED')
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await admit(c.creator, 'approved') })
  // Mode changes are ordinary administrator-signed policy revisions.
  const relaxed = await c.extend([c.genesis], head => ({ admission: { ...head.admission, mode: 'attested' } }), c.creator)
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: relaxed })
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await c.extend([c.genesis], head => ({ admission: { ...head.admission, mode: 'attested' } }), c.agent) })).rejects.toThrow('AUTHORITY_ADMIN_REQUIRED')
})
it('replayed attestations and re-admission of a member are rejected deterministically', async () => {
  const c = await chain(), device = await createSigningIdentity(), attestation = await c.attest(device)
  const admitted = await c.extend([c.genesis], head => ({ members: [...head.members, c.grant(device.publicKey, hex('e6'), false)], admitted: [{ publicKey: device.publicKey, via: 'attested', attestation }] }), c.agent)
  const removed = await c.extend(admitted, head => ({ members: head.members.filter(member => member.publicKey !== device.publicKey), epoch: 1, epochKeyDigest: hex('f7') }), c.creator)
  await verifyAuthorityBundle({ descriptor: c.descriptor, memberships: removed })
  const replay = await c.extend(removed, head => ({ members: [...head.members, c.grant(device.publicKey, hex('e6'), false)], admitted: [{ publicKey: device.publicKey, via: 'attested', attestation }] }), c.agent)
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: replay })).rejects.toThrow('AUTHORITY_ADMISSION_REPLAYED')
  const duplicate = await c.extend(admitted, head => ({ members: [...head.members], admitted: [{ publicKey: device.publicKey, via: 'attested', attestation }] }), c.creator)
  await expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: duplicate })).rejects.toThrow('AUTHORITY_ADMISSION_INVALID')
})
it('invites admit only within binding, role, expiry and capacity; overuse by an administrator stays visible', async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32)), secretDigest = bytesToHex(await sha256(secret))
  const invites: PageInvite[] = [
    { inviteId: '11'.repeat(16), role: 'reader', binding: { kind: 'email', email: 'friend@example.test' }, expiresAt: 900_000n, secretDigest, revoked: false },
    { inviteId: '22'.repeat(16), role: 'writer', binding: { kind: 'open' }, expiresAt: 900_000n, secretDigest, revoked: false },
    { inviteId: '33'.repeat(16), role: 'reader', binding: { kind: 'public', max: 2 }, expiresAt: 900_000n, secretDigest, revoked: false },
    { inviteId: '44'.repeat(16), role: 'reader', binding: { kind: 'open' }, expiresAt: 900_000n, secretDigest, revoked: true },
    { inviteId: '55'.repeat(16), role: 'reader', binding: { kind: 'open' }, expiresAt: 3_000n, secretDigest, revoked: false },
  ]
  const c = await chain('attested', invites)
  const redeem = async (memberships: SignedMembership[], inviteId: string, account: { accountId: string; email: string | null }, signer = c.agent, role: 'reader' | 'writer' = 'reader') => {
    const device = await createSigningIdentity(), attestation = await c.attest(device, { ...account, inviteId })
    return c.extend(memberships, head => ({ members: [...head.members, { ...c.grant(device.publicKey, hex('e6'), false), writer: role === 'writer' }], admitted: [{ publicKey: device.publicKey, via: 'invited', attestation }] }), signer)
  }
  const ok = async (value: Promise<SignedMembership[]>) => { const memberships = await value; await verifyAuthorityBundle({ descriptor: c.descriptor, memberships }); return memberships }
  const bad = async (value: Promise<SignedMembership[]>, code: string) => expect(verifyAuthorityBundle({ descriptor: c.descriptor, memberships: await value })).rejects.toThrow(code)
  await ok(redeem([c.genesis], '11'.repeat(16), { accountId: 'acct_friend', email: 'friend@example.test' }))
  await bad(redeem([c.genesis], '11'.repeat(16), { accountId: 'acct_mallory', email: 'mallory@example.test' }), 'AUTHORITY_INVITE_INVALID')
  const once = await ok(redeem([c.genesis], '22'.repeat(16), { accountId: 'acct_a', email: null }, c.agent, 'writer'))
  await bad(redeem(once, '22'.repeat(16), { accountId: 'acct_b', email: null }, c.agent, 'writer'), 'AUTHORITY_INVITE_EXHAUSTED')
  // A misbehaving host's second redemption can only enter through a visible administrator decision.
  const doubled = await ok(redeem(once, '22'.repeat(16), { accountId: 'acct_b', email: null }, c.creator, 'writer'))
  expect(inviteRedemptions(doubled, '22'.repeat(16))).toBe(2)
  await bad(redeem([c.genesis], '22'.repeat(16), { accountId: 'acct_a', email: null }, c.agent, 'reader'), 'AUTHORITY_ADMIN_REQUIRED')
  const first = await ok(redeem([c.genesis], '33'.repeat(16), { accountId: 'acct_1', email: null })), second = await ok(redeem(first, '33'.repeat(16), { accountId: 'acct_2', email: null }))
  await bad(redeem(second, '33'.repeat(16), { accountId: 'acct_3', email: null }), 'AUTHORITY_INVITE_EXHAUSTED')
  await bad(redeem([c.genesis], '44'.repeat(16), { accountId: 'acct_1', email: null }), 'AUTHORITY_INVITE_INVALID')
  await bad(redeem([c.genesis], '55'.repeat(16), { accountId: 'acct_1', email: null }), 'AUTHORITY_INVITE_INVALID')
  await bad(redeem([c.genesis], '66'.repeat(16), { accountId: 'acct_1', email: null }), 'AUTHORITY_INVITE_INVALID')
  // Creating or revoking invites is an administrator change.
  await bad(c.extend([c.genesis], head => ({ invites: head.invites.map(invite => ({ ...invite, revoked: true })) }), c.agent), 'AUTHORITY_ADMIN_REQUIRED')
  await ok(c.extend([c.genesis], head => ({ invites: head.invites.map(invite => ({ ...invite, revoked: true })) }), c.creator))
})

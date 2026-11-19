import {
  createGenerationRegistry, createPeerIdentity, participantGrant, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, type PeerIdentity,
} from '@chronolog/peer-generation/control'
import { MemoryBytesStore } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { acceptCelldApplicationInvitation, signCelldApplicationInvitation } from './celld.js'
import { openApplicationDevice } from './device.js'

async function fixture() {
  const host = await createPeerIdentity(), owner = await createPeerIdentity(), member = await createPeerIdentity()
  const descriptor = await signApplicationDescriptor({
    applicationId: 'a'.repeat(64), historyId: 'celld-invitation-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1',
    controlPublicKey: host.publicKey, schemaAdministrator: owner.publicKey,
    definitionDigest: 'b'.repeat(64), executionManifestDigest: 'c'.repeat(64), schemaDigest: null,
  }, host)
  const { applicationId, profile, policy } = descriptor.payload
  const control = await signControlRevision({
    applicationId, profile, policy, revision: 0, previous: null, epoch: 0,
    keyDigest: 'd'.repeat(64), recoveryFloor: null,
    grants: [participantGrant(owner.publicKey, { administrator: true }), participantGrant(member.publicKey)],
  }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({
    applicationId, profile, policy, transitionId: 'create', reason: 'create',
    expectedGeneration: null, controlRevision: 0, base: null,
    coordinator: owner.publicKey, requester: owner.publicKey,
  }, owner))
  const authority = await registry.read()
  const endpoint = { nodeId: 'e'.repeat(64), addrs: ['127.0.0.1:21080'] }
  const sign = (changes: { memberPublicKey?: string; inviter?: PeerIdentity } = {}) =>
    signCelldApplicationInvitation({ authority, endpoint, memberPublicKey: member.publicKey, inviter: owner, ...changes })
  return { owner, member, authority, endpoint, sign }
}

describe('celld application enrollment', () => {
  it('accepts the signed route and exact authority for the invited device across restart', async () => {
    const f = await fixture(), store = new MemoryBytesStore()
    const device = await openApplicationDevice({ store, create: true, managedSigner: f.member })
    const invitation = await f.sign()
    const expected = {
      authority: f.authority, endpoint: f.endpoint,
      peer: { identity: f.owner.publicKey, route: f.endpoint.nodeId },
    }
    expect(await acceptCelldApplicationInvitation(device, invitation)).toEqual(expected)
    expect(await store.get(`peer-session/authority/${f.authority.descriptor.payload.applicationId}`)).not.toBeNull()
    await device.close()
    const restarted = await openApplicationDevice({ store, managedSigner: f.member })
    try {
      expect(await acceptCelldApplicationInvitation(restarted, invitation)).toEqual(expected)
    } finally {
      await restarted.close()
    }
  })

  it('rejects an altered route, another device, or an unadmitted issuer or member', async () => {
    const f = await fixture()
    const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true, managedSigner: f.member })
    const outsider = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
    try {
      const invitation = await f.sign()
      await expect(f.sign({ memberPublicKey: outsider.identity.publicKey })).rejects.toThrow('CELLD_INVITATION_MEMBER_FORBIDDEN')
      await expect(f.sign({ inviter: f.member })).rejects.toThrow('CELLD_INVITATION_ADMINISTRATOR_REQUIRED')
      await expect(acceptCelldApplicationInvitation(outsider, invitation)).rejects.toThrow('CELLD_INVITATION_MEMBER_MISMATCH')
      const changed = { ...invitation, payload: { ...invitation.payload, endpoint: { nodeId: 'f'.repeat(64) } } }
      await expect(acceptCelldApplicationInvitation(device, changed)).rejects.toThrow('CELLD_INVITATION_SIGNATURE_INVALID')
      expect(await device.store.get(`peer-session/authority/${f.authority.descriptor.payload.applicationId}`)).toBeNull()
    } finally {
      await Promise.all([device.close(), outsider.close()])
    }
  })
})

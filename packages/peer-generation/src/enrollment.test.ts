import { describe, expect, it } from 'vitest'
import { createPeerIdentity, peerDigest } from './codec.js'
import { createGenerationRegistry, generationStartRoot, PeerAuthority, signApplicationDescriptor, signControlRevision, signTransitionRequest, type SignedControlRevision } from './control.js'
import { MemoryPeerStore } from './memory.js'
import { signApplicationRecipient, signEpochKeyPackage, verifyApplicationRecipient, verifyEpochKeyPackage } from './enrollment.js'

async function fixture() {
  const host = await createPeerIdentity(), admin = await createPeerIdentity(), reader = await createPeerIdentity()
  const descriptor = await signApplicationDescriptor({ applicationId: 'ab'.repeat(32), historyId: 'enrollment',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: admin.publicKey, executionManifestDigest: '11'.repeat(32), definitionDigest: '22'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: '33'.repeat(32), recoveryFloor: null,
    grants: [admin, reader].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true,
      coordinator: true, recovery: true, administrator: identity === admin, dataRole: 'member' as const })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'create', expectedGeneration: null, coordinator: admin.publicKey,
    requester: admin.publicKey, controlRevision: 0, reason: 'create', base: null }, admin))
  const authority = await PeerAuthority.verify(await registry.read())
  const recipient = await signApplicationRecipient({ applicationId: descriptor.payload.applicationId,
    profile: 'peer-generation-v1', publicKey: reader.publicKey, encryptionKey: '44'.repeat(32) }, reader)
  const envelope = await signEpochKeyPackage({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    controlRevision: 0, controlDigest: await peerDigest(control), epoch: 0, keyDigest: control.payload.keyDigest,
    sender: admin.publicKey, recipient, encapsulatedKey: '55'.repeat(32), ciphertext: '66'.repeat(48) }, admin)
  const activate = async (next: SignedControlRevision) => {
    const current = (await registry.read()).generations.at(-1)!
    await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, transitionId: `control-${next.payload.revision}`, expectedGeneration: current.id, coordinator: admin.publicKey,
      requester: admin.publicKey, controlRevision: next.payload.revision, reason: 'control-change',
      base: { point: { generation: current.id, sequence: 0, root: await generationStartRoot(current) }, receipt: null, bridge: [] } }, admin), { control: next })
    return PeerAuthority.verify(await registry.read())
  }
  return { host, admin, reader, descriptor, control, authority, recipient, envelope, activate }
}

describe('opaque application epoch enrollment', () => {
  it('binds the recipient encryption key to its actual signer and application', async () => {
    const f = await fixture()
    await verifyApplicationRecipient(f.recipient, f.descriptor.payload)
    await verifyEpochKeyPackage(f.envelope, f.authority)
    await expect(verifyApplicationRecipient({ ...f.recipient, payload: { ...f.recipient.payload, encryptionKey: '77'.repeat(32) } }, f.descriptor.payload))
      .rejects.toThrow('PEER_SIGNATURE_INVALID')
    await expect(verifyApplicationRecipient(f.recipient, { ...f.descriptor.payload, applicationId: '99'.repeat(32) })).rejects.toThrow('PEER_SCOPE_MISMATCH')
  })

  it('keeps coordination and writing separate from permission to issue reader keys', async () => {
    const f = await fixture()
    const writer = await signEpochKeyPackage({ ...f.envelope.payload, sender: f.reader.publicKey }, f.reader)
    await expect(verifyEpochKeyPackage(writer, f.authority)).rejects.toThrow('PEER_KEY_SENDER_FORBIDDEN')
    await expect(verifyEpochKeyPackage({ ...f.envelope, payload: { ...f.envelope.payload, ciphertext: 'aa'.repeat(48) } }, f.authority)).rejects.toThrow('PEER_SIGNATURE_INVALID')
  })

  it('permits an explicit historical key grant and rejects a package after recipient revocation', async () => {
    const f = await fixture()
    const next = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1, keyDigest: '88'.repeat(32) }, f.host)
    const authority = await f.activate(next)
    const historical = await signEpochKeyPackage({ ...f.envelope.payload, controlRevision: 1, controlDigest: await peerDigest(next) }, f.admin)
    await verifyEpochKeyPackage(historical, authority)
    const revoked = await signControlRevision({ ...next.payload, revision: 2, previous: await peerDigest(next), epoch: 2, keyDigest: '99'.repeat(32),
      grants: next.payload.grants.filter(grant => grant.publicKey !== f.reader.publicKey) }, f.host)
    await expect(verifyEpochKeyPackage(historical, await f.activate(revoked)))
      .rejects.toThrow('PEER_KEY_RECIPIENT_FORBIDDEN')
  })
})

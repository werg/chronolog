import { describe, expect, it } from 'vitest'
import {
  controlParticipantGrant, createGenerationRegistry, createPeerIdentity, generationStartRoot, participantGrant,
  peerDigest, signApplicationDescriptor, signControlRevision, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerIdentity,
} from './control.js'
import { bytesDigest } from './codec.js'
import { MemoryBytesStore } from '@chronolog/records'
import {
  authorizePublication, createPublicationRegistry, signPublicationManifest, validatePublicationManifest,
  verifyPublicationAsset, verifyPublicationManifest, type PublicationManifest, type SignedPublication,
} from './publication.js'

async function fixture() {
  const host = await createPeerIdentity(), admin = await createPeerIdentity(), writer = await createPeerIdentity()
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'publication-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: admin.publicKey, executionManifestDigest: '33'.repeat(32), definitionDigest: '44'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: '55'.repeat(32), recoveryFloor: null,
    grants: [controlParticipantGrant(host.publicKey), participantGrant(admin.publicKey, { administrator: true }), participantGrant(writer.publicKey)] }, host)
  const generations = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  const first = await generations.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    requester: admin.publicKey, coordinator: admin.publicKey, controlRevision: 0, reason: 'create', base: null }, admin))
  const authority = () => generations.read(), store = new MemoryBytesStore(), publications = await createPublicationRegistry({ store, authority })
  const bytes = new TextEncoder().encode('<!doctype html><title>A</title>')
  const manifest = async (operationId: string, previous: SignedPublication | null = null, signer: PeerIdentity = admin,
    changes: Partial<PublicationManifest> = {}) => signPublicationManifest({ applicationId: descriptor.payload.applicationId,
    historyId: descriptor.payload.historyId, profile: descriptor.payload.profile, controlRevision: 0, author: signer.publicKey, operationId,
    revision: previous === null ? 0 : previous.payload.revision + 1, previous: previous?.id ?? null,
    definitionDigest: descriptor.payload.definitionDigest, executionManifestDigest: descriptor.payload.executionManifestDigest,
    entry: 'index.html', files: [{ path: 'index.html', hash: await bytesDigest(bytes), size: bytes.length, type: 'text/html' }], ...changes }, signer)
  const revoke = async () => {
    const next = await signControlRevision({ ...control.payload, revision: 1, previous: await peerDigest(control),
      grants: control.payload.grants.map(grant => grant.publicKey === admin.publicKey ? { ...grant, administrator: false } : grant) }, host)
    const transition = await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, transitionId: 'revoke-admin', expectedGeneration: first.id, requester: host.publicKey,
      coordinator: admin.publicKey, controlRevision: 1, reason: 'control-change', base: {
        point: { generation: first.id, sequence: 0, root: await generationStartRoot(first) }, receipt: null, bridge: [],
      } }, host)
    await generations.select(transition, { control: next })
  }
  return { host, admin, writer, descriptor, authority, store, publications, bytes, manifest, revoke }
}

describe('signed code publication independent of lossy database history', () => {
  it('requires publication administration separately from writing, sequencing and data access', async () => {
    const f = await fixture(), authority = await verifyAuthorityBundle(await f.authority())
    const authorized = await f.manifest('admin-release')
    await expect(authorizePublication(authorized, authority, null)).resolves.toBeUndefined()
    await expect(authorizePublication(await f.manifest('writer-release', null, f.writer), authority, null)).rejects.toThrow('PEER_PUBLICATION_FORBIDDEN')
    // A host granted only administration/recovery can publish without reader keys or SQL rights.
    await expect(authorizePublication(await f.manifest('host-release', null, f.host), authority, null)).resolves.toBeUndefined()
    expect(authority.grant(f.host.publicKey)).toMatchObject({ reader: false, writer: false, coordinator: false, administrator: true })
  })
  it('authenticates code bytes and binds definition, execution, history and exact publisher', async () => {
    const f = await fixture(), authority = await verifyAuthorityBundle(await f.authority()), publication = await f.manifest('release')
    await expect(verifyPublicationAsset(publication.payload.files[0]!, f.bytes)).resolves.toBeUndefined()
    await expect(verifyPublicationAsset(publication.payload.files[0]!, new TextEncoder().encode('changed'))).rejects.toThrow('PEER_PUBLICATION_ASSET_MISMATCH')
    await expect(verifyPublicationManifest({ ...publication, signature: '00'.repeat(64) }, authority)).rejects.toThrow('PEER_SIGNATURE_INVALID')
    for (const changes of [{ definitionDigest: 'aa'.repeat(32) }, { executionManifestDigest: 'bb'.repeat(32) }]) {
      await expect(verifyPublicationManifest(await f.manifest('changed', null, f.admin, changes), authority)).rejects.toThrow('PEER_PUBLICATION_SEMANTICS_MISMATCH')
    }
    await expect(verifyPublicationManifest(await f.manifest('wrong-history', null, f.admin, { historyId: 'another' }), authority))
      .rejects.toThrow('PEER_PUBLICATION_SCOPE_MISMATCH')
    expect(() => validatePublicationManifest({ ...publication.payload, files: [{ ...publication.payload.files[0]!, path: '../index.html' }] }))
      .toThrow('PEER_PUBLICATION_PATH_INVALID')
  })
  it('selects one competing publication, reopens, and recovers exact lost replies after later releases', async () => {
    const f = await fixture(), first = await f.manifest('first'), rival = await f.manifest('rival')
    const other = await createPublicationRegistry({ store: f.store, authority: f.authority, requireExisting: true })
    const results = await Promise.allSettled([f.publications.publish(first), other.publish(rival)])
    expect(results.map(value => value.status).sort()).toEqual(['fulfilled', 'rejected'])
    const selected = (await f.publications.read())[0]!
    const second = await f.publications.publish(await f.manifest('second', selected))
    const reopened = await createPublicationRegistry({ store: f.store, authority: f.authority, requireExisting: true })
    expect(await reopened.publish(selected)).toEqual(selected)
    expect(await reopened.read()).toEqual([selected, second])
    await expect(reopened.publish(await f.manifest(selected.payload.operationId, selected))).rejects.toThrow('PEER_PUBLICATION_OPERATION_REUSED')
    await expect(createPublicationRegistry({ store: new MemoryBytesStore(), authority: f.authority, requireExisting: true })).rejects.toThrow('PEER_PUBLICATION_STATE_MISSING')
  })
  it('retains historical signatures after revocation but rejects new releases under stale controls', async () => {
    const f = await fixture(), first = await f.publications.publish(await f.manifest('first'))
    await f.revoke()
    const authority = await verifyAuthorityBundle(await f.authority())
    await expect(verifyPublicationManifest(first, authority)).resolves.toBeUndefined()
    expect(await f.publications.publish(first)).toEqual(first)
    await expect(f.publications.publish(await f.manifest('stale', first))).rejects.toThrow('PEER_PUBLICATION_CONTROL_CHANGED')
    await expect(f.publications.publish(await f.manifest('revoked', first, f.admin, { controlRevision: 1 }))).rejects.toThrow('PEER_PUBLICATION_FORBIDDEN')
    const second = await f.publications.publish(await f.manifest('host-successor', first, f.host, { controlRevision: 1 }))
    expect((await f.publications.read()).map(value => value.id)).toEqual([first.id, second.id])
  })
  it('recovers a durable publication whose storage acknowledgment was lost', async () => {
    const f = await fixture(), backing = new MemoryBytesStore()
    let loseReply = false
    const store = { get: backing.get.bind(backing), async put(key: string, value: Uint8Array) {
      await backing.put(key, value)
      if (loseReply) { loseReply = false; throw new Error('reply lost') }
    } }
    const registry = await createPublicationRegistry({ store, authority: f.authority }), first = await f.manifest('lost-reply')
    loseReply = true
    await expect(registry.publish(first)).rejects.toThrow('reply lost')
    expect(await registry.publish(first)).toEqual(first)
    expect(await registry.read()).toHaveLength(1)
  })
  it('rechecks authority after asynchronous preparation and rejects a newly revoked administrator', async () => {
    const f = await fixture(), stale = await f.authority(), publication = await f.manifest('racing')
    await f.revoke()
    const current = await f.authority()
    let calls = 0
    const registry = await createPublicationRegistry({ store: new MemoryBytesStore(), authority: async (): Promise<AuthorityBundle> => {
      calls++; return calls <= 3 ? stale : current
    } })
    await expect(registry.publish(publication)).rejects.toThrow('PEER_PUBLICATION_CONTROL_CHANGED')
    expect(await registry.read()).toEqual([])
  })
})

import { describe, expect, it } from 'vitest'
import { DOMAINS } from '@chronolog/protocol'
import {
  controlParticipantGrant, createGenerationRegistry, createPeerIdentity, generationStartRoot, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type OrderReceipt, type PeerIdentity, type PrefixProof, type SignedGeneration,
} from './control.js'
import { signPeerValue } from './codec.js'
import { MemoryBytesStore } from '@chronolog/records'

const digest = '11'.repeat(32)
async function fixture() {
  const [host, a, b, c, writer] = await Promise.all(Array.from({ length: 5 }, () => createPeerIdentity())) as [PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity]
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'test-history',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: digest, definitionDigest: digest, schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: digest, recoveryFloor: null,
    grants: [a, b, c, writer].map(key => ({ publicKey: key.publicKey, reader: true, writer: true,
      coordinator: key !== writer, recovery: key !== writer, administrator: key === a, publisher: false, dataRole: 'member' as const })) }, host)
  const store = new MemoryBytesStore()
  const registry = await createGenerationRegistry({ store, descriptor, controls: [control], signer: host })
  const transition = async (who: PeerIdentity, coordinator: PeerIdentity, expected: string | null, base: PrefixProof | null, id: string, reason: 'create' | 'takeover' | 'control-change' = 'takeover', revision = 0) => signTransitionRequest({
    applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    transitionId: id, expectedGeneration: expected, coordinator: coordinator.publicKey, requester: who.publicKey,
    controlRevision: revision, reason, base,
  }, who)
  const request = await transition(a, a, null, null, 'create', 'create')
  const g1 = await registry.select(request)
  return { host, a, b, c, writer, descriptor, control, store, registry, transition, request, g1 }
}
async function receipts(generation: SignedGeneration, identity: PeerIdentity, length: number): Promise<OrderReceipt[]> {
  let root = await generationStartRoot(generation)
  const result: OrderReceipt[] = []
  for (let sequence = 1; sequence <= length; sequence++) {
    const payload = { applicationId: generation.payload.applicationId, profile: 'peer-generation-v1' as const,
      generation: generation.id, sequence, previousRoot: root, attemptId: sequence.toString(16).padStart(64, '0'),
      author: identity.publicKey, operationId: `op-${sequence}`, bodyHash: digest, bodyBytes: 500 }
    const signature = await signPeerValue(DOMAINS.peerOrder, payload, identity)
    root = await peerDigest(['chronolog/peer-generation/order/v1', payload])
    result.push({ ...signature, root })
  }
  return result
}
function proof(receipt: OrderReceipt, bridge: readonly OrderReceipt[] = []): PrefixProof {
  return { point: { generation: receipt.payload.generation, sequence: receipt.payload.sequence, root: receipt.root }, receipt, bridge }
}

describe('portable peer generation authority', () => {
  it('requires an explicit publisher grant independently of every other role', async () => {
    const f = await fixture()
    expect(participantGrant(f.a.publicKey, { administrator: true })).toMatchObject({ administrator: true, publisher: false })
    expect(participantGrant(f.a.publicKey, { publisher: true })).toMatchObject({ administrator: false, publisher: true })
    expect(controlParticipantGrant(f.host.publicKey)).toMatchObject({ administrator: true, publisher: false, reader: false, writer: false })
    const missing = structuredClone(f.control.payload)
    delete (missing.grants[0] as { publisher?: boolean }).publisher
    await expect(signControlRevision(missing, f.host)).rejects.toThrow('PEER_RECORD_FIELDS_INVALID')
    const malformed = { ...f.control.payload, grants: f.control.payload.grants.map(grant => ({ ...grant, publisher: 1 as unknown as boolean })) }
    await expect(signControlRevision(malformed, f.host)).rejects.toThrow('PEER_GRANT_INVALID')
  })
  it('recovers through an explicit control participant without creator or data authority', async () => {
    const f = await fixture()
    const control = await signControlRevision({ ...f.control.payload,
      grants: [controlParticipantGrant(f.host.publicKey), participantGrant(f.a.publicKey), participantGrant(f.b.publicKey)],
    }, f.host)
    const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor: f.descriptor, controls: [control], signer: f.host })
    const first = await registry.select(f.request)
    const head = (await receipts(first, f.a, 1))[0]!
    const next = await registry.select(await f.transition(f.host, f.b, first.id, proof(head), 'owner-recovery'))
    expect(next.payload.coordinator).toBe(f.b.publicKey)
    expect((await verifyAuthorityBundle(await registry.read())).grant(f.host.publicKey)).toMatchObject({
      reader: false, writer: false, coordinator: false, recovery: true, administrator: true, publisher: false, dataRole: null,
    })
    await expect(registry.select(await f.transition(f.host, f.host, next.id, proof(head), 'host-is-not-a-peer'))).rejects.toThrow('PEER_COORDINATOR_FORBIDDEN')
  })
  it('recovers lost replies exactly and allows one competing successor', async () => {
    const f = await fixture(), [head] = await receipts(f.g1, f.a, 1)
    const first = await f.transition(f.b, f.b, f.g1.id, proof(head!), 'second')
    const second = await f.transition(f.c, f.c, f.g1.id, proof(head!), 'other')
    const results = await Promise.allSettled([f.registry.select(first), f.registry.select(second)])
    expect(results.map(value => value.status).sort()).toEqual(['fulfilled', 'rejected'])
    const selected = (await f.registry.read()).generations.at(-1)!
    expect(await f.registry.select(selected.payload.transition)).toEqual(selected)
    expect(await f.registry.select(f.request)).toEqual(f.g1)
    const reopened = await createGenerationRegistry({ store: f.store, descriptor: f.descriptor, controls: [f.control], signer: f.host, requireExisting: true })
    expect((await reopened.read()).generations.at(-1)).toEqual(selected)
  })
  it('requires independent recovery permission and sequencing eligibility', async () => {
    const f = await fixture(), head = (await receipts(f.g1, f.a, 1))[0]!
    await expect(f.registry.select(await f.transition(f.writer, f.b, f.g1.id, proof(head), 'unauthorized'))).rejects.toThrow('PEER_RECOVERY_FORBIDDEN')
    await expect(f.registry.select(await f.transition(f.b, f.writer, f.g1.id, proof(head), 'ineligible'))).rejects.toThrow('PEER_COORDINATOR_FORBIDDEN')
  })
  it('never readopts an excluded old suffix across three generations', async () => {
    const f = await fixture(), old = await receipts(f.g1, f.a, 100)
    const g2 = await f.registry.select(await f.transition(f.b, f.b, f.g1.id, proof(old[79]!), 'second'))
    await expect(f.registry.select(await f.transition(f.c, f.c, g2.id, proof(old[99]!), 'resurrection'))).rejects.toThrow('PEER_PREFIX_EXCLUDED')
    const inherited = proof(old[59]!, old.slice(60, 80))
    const g3 = await f.registry.select(await f.transition(f.c, f.c, g2.id, inherited, 'third'))
    const verified = await verifyAuthorityBundle(await f.registry.read())
    expect(verified.current).toEqual(g3)
    expect(verified.contains(proof(old[60]!).point)).toBe(false)
    expect(verified.selectedSegments().map(value => value.generation.id)).toEqual([f.g1.id, g3.id])
  })
  it('requires a complete root bridge for an earlier inherited prefix', async () => {
    const f = await fixture(), old = await receipts(f.g1, f.a, 3)
    const g2 = await f.registry.select(await f.transition(f.b, f.b, f.g1.id, proof(old[2]!), 'second'))
    await expect(f.registry.select(await f.transition(f.c, f.c, g2.id, proof(old[0]!), 'incomplete'))).rejects.toThrow('PEER_PREFIX_BRIDGE_INCOMPLETE')
    const forged = proof(old[0]!, [old[2]!])
    await expect(f.registry.select(await f.transition(f.c, f.c, g2.id, forged, 'hole'))).rejects.toThrow('PEER_PREFIX_BRIDGE_INVALID')
  })
  it('pins exact profile, application and execution identity', async () => {
    const f = await fixture(), bundle = await f.registry.read()
    for (const mutate of [
      (value: AuthorityBundle) => { (value.descriptor.payload as { profile: string }).profile = 'signed-inclusion-v2' },
      (value: AuthorityBundle) => { (value.generations[0]!.payload as { executionManifestDigest: string }).executionManifestDigest = '33'.repeat(32) },
    ]) {
      const changed = structuredClone(bundle); mutate(changed)
      await expect(verifyAuthorityBundle(changed)).rejects.toThrow()
    }
  })
  it('activates restrictive controls atomically and retains a protected recovery floor', async () => {
    const f = await fixture(), history = await receipts(f.g1, f.a, 3), floor = proof(history[1]!).point
    const next = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1,
      keyDigest: '44'.repeat(32), recoveryFloor: floor,
      grants: f.control.payload.grants.filter(grant => grant.publicKey !== f.writer.publicKey) }, f.host)
    const g2 = await f.registry.select(await f.transition(f.a, f.b, f.g1.id, proof(history[1]!), 'revoke', 'control-change', 1), { control: next })
    await expect(f.registry.select(await f.transition(f.b, f.b, g2.id, proof(history[0]!, [history[1]!]), 'rollback', 'takeover', 1))).rejects.toThrow('PEER_RECOVERY_FLOOR_UNAVAILABLE')
    const authority = await verifyAuthorityBundle(await f.registry.read())
    expect(authority.grant(f.writer.publicKey)).toBe(null)
    expect(authority.grant(f.writer.publicKey, 0)?.writer).toBe(true)
  })
  it('requires rotating encryption when a reader is removed', async () => {
    const f = await fixture(), history = await receipts(f.g1, f.a, 1)
    const next = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: f.control.payload.grants.filter(grant => grant.publicKey !== f.writer.publicKey) }, f.host)
    await expect(f.registry.select(await f.transition(f.a, f.b, f.g1.id, proof(history[0]!), 'revoke', 'control-change', 1), { control: next })).rejects.toThrow('PEER_REVOCATION_REQUIRES_KEY_ROTATION')
  })
  it('refuses to recreate lost established control state', async () => {
    const f = await fixture()
    await expect(createGenerationRegistry({ store: new MemoryBytesStore(), descriptor: f.descriptor, controls: [f.control], signer: f.host, requireExisting: true })).rejects.toThrow('PEER_CONTROL_STATE_MISSING')
  })
})

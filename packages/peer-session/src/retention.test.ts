import { afterEach, expect, it, vi } from 'vitest'
import { encodeRecord, signRecord, recordDigest, signMembership, epochKeyCommitment } from '@chronolog/authority'
import { sessionFixture } from './test-fixture.js'
import { unwrapOperation, wrapOperation } from './operation-codec.js'
import { contentFixture, payload } from './content-test-fixture.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { vi.restoreAllMocks(); for (const close of closes.splice(0).reverse()) await close() })
it('does not count local, self-echo, or same-storage availability as operation peer retention', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); closes.push(() => a.close(), () => b.close())
  const operation = await a.command('say', 'local only', { authorTimestampMs: 1n }); await operation.materialized(); expect(a.status.connectedPeers).toBe(0)
  const self = await a.retain(operation.id)
  const echo = await signRecord('retention', { ...self.payload, storageId: 'claimed-another-store' }, f.identities[0]!)
  const sameStorage = await signRecord('retention', { ...self.payload, peer: f.identities[1]!.publicKey }, f.identities[1]!)
  await a.mergeFacts({ envelopes: [], retentions: [self, echo, sameStorage], finality: [] }); expect(a.exportFacts().retentions).toHaveLength(3); expect(operation.inspect().retained).toEqual([])
  await expect(operation.retained({ timeoutMs: 20 })).rejects.toThrow('OPERATION_WAIT_TIMEOUT')
  await b.mergeFacts(a.exportFacts()); const remote = await b.retain(operation.id); expect(remote.signer).not.toBe(a.identity.publicKey); expect(remote.payload.storageId).not.toBe(a.device.storageId)
  await a.mergeFacts(b.exportFacts()); expect(await operation.retained({ timeoutMs: 100 })).toEqual([remote]); expect(operation.inspect().retained).toEqual([remote])
  const forged = { ...remote, signature: '00'.repeat(64) }; await expect(a.mergeFacts({ envelopes: [], retentions: [forged], finality: [] })).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
  const revoke = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, authorTimeAfterMs: 2n, members: f.membership.payload.members.filter(member => member.publicKey !== b.identity.publicKey) }, f.authorityIdentity)
  await a.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, revoke] }); await a.retryMaterialization(); expect(operation.inspect().retained).toEqual([])
  await a.close(); const reopened = await f.open(0); closes.push(() => reopened.close()); expect((await reopened.readEvents()).events).toHaveLength(1); expect(reopened.operations.get(operation.id)!.inspect().retained).toEqual([])
})
it('content peer retention also excludes self-echo and same storage while preserving genuine signed remote proofs', async () => {
  const f = await contentFixture(); closes.push(async () => { await f.close() }); const a = f.contents[0]!, b = f.contents[1]!, reference = await a.putBytes(payload(9)), self = await a.retain(reference)
  expect(await a.retained(reference)).toEqual([])
  const echo = await signRecord('content-retention', { ...self.payload, storageId: 'claimed-another-store' }, f.identities[0]!)
  const sameStorage = await signRecord('content-retention', { ...self.payload, peer: f.identities[1]!.publicKey }, f.identities[1]!)
  const source = a.source(); a.attachSource('self-echo', { ...source, retained: async () => echo }); a.attachSource('same-storage', { ...source, retained: async () => sameStorage })
  await f.stores[0]!.put(`content/${f.applicationId}/retentions/${reference.id}`, encodeRecord([self, echo, sameStorage]))
  expect(await a.retained(reference)).toEqual([]); expect(await a.retention(reference)).toEqual([])
  b.attachSource('source', source); const remote = await b.retain(reference); a.attachSource('independent-peer', b.source())
  expect(await a.retention(reference)).toEqual([remote]); expect(await a.retained(reference)).toEqual([remote])
})

it('cross-author claims cannot poison retention, wrapper slots, canonical exclusion or the private default clock', async () => {
  const f = await sessionFixture({ count: 3 }), a = await f.open(0), b = await f.open(1), opaque = await f.open(2, false); closes.push(() => a.close(), () => b.close(), () => opaque.close())
  vi.spyOn(Date, 'now').mockReturnValue(1000)
  const target = await a.command('say', 'A original', { operationId: 'default-original' }); await target.materialized()
  const other = await b.command('say', 'B different core', { operationId: 'different-B', authorTimestampMs: 2n }); await other.materialized()
  const bEnvelope = b.exportFacts().envelopes[0]!, aEnvelope = a.exportFacts().envelopes[0]!
  const claims = await Promise.all(Array.from({ length: 8 }, (_, index) => signRecord('operation-envelope', { ...bEnvelope.payload, proposalId: target.id, authorTimestampMs: ((1n << 63n) - 1n) - BigInt(index) }, f.identities[1]!)))
  await a.mergeFacts({ envelopes: claims, retentions: [], finality: [] }); await a.retryMaterialization(); expect(target.inspect().excluded).toBe(false)
  const next = await a.command('say', 'after malicious claim', { operationId: 'default-after' }); await next.materialized(); expect(next.inspect().authorTimestampMs).toBe('1001')
  await opaque.mergeFacts({ envelopes: claims, retentions: [], finality: [] }); await opaque.retryMaterialization()
  expect(opaque.inspectOperation(target.id)).toMatchObject({ pending: 'key', excluded: false })
  const badSubject = await opaque.retain(target.id); expect(badSubject.payload.author).toBe(f.identities[1]!.publicKey)
  await a.mergeFacts({ envelopes: [], retentions: [badSubject], finality: [] }); expect(target.inspect().retained).toEqual([])
  const ninth = await signRecord('operation-envelope', { ...bEnvelope.payload, proposalId: target.id, authorTimestampMs: 100n }, f.identities[1]!)
  await expect(opaque.mergeFacts({ envelopes: [ninth], retentions: [], finality: [] })).rejects.toThrow('OPERATION_ENVELOPE_LIMIT')
  const body = await unwrapOperation(aEnvelope, a.authority); if (typeof body === 'string') throw new Error(body)
  const key1 = crypto.getRandomValues(new Uint8Array(32)), membership1 = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, epoch: 1, epochKeyDigest: await epochKeyCommitment(f.applicationId, 1, key1), authorTimeAfterMs: 2000n }, f.authorityIdentity), bundle1 = { descriptor: f.descriptor, memberships: [f.membership, membership1] }
  await a.mergeAuthority(bundle1); await opaque.mergeAuthority(bundle1); await a.authority.installEpochKey(1, key1)
  const alternate = await wrapOperation(body.body, f.identities[0]!, 1, key1), alternateDigest = await recordDigest(alternate)
  expect(alternate.payload.proposalId).toBe(target.id); expect(alternateDigest).not.toBe(await recordDigest(aEnvelope))
  const nextEnvelope = a.exportFacts().envelopes.find(envelope => envelope.payload.proposalId === next.id)!
  await opaque.mergeFacts({ envelopes: [alternate, nextEnvelope], retentions: [], finality: [] })
  await opaque.authority.installEpochKey(0, f.epochKey); await opaque.retryMaterialization()
  // B's ciphertext can now be proved invalid; genuine A still needs epoch 1. Neither state poisons A.
  expect(opaque.inspectOperation(target.id)).toMatchObject({ author: a.identity.publicKey, pending: 'key', excluded: false })
  const genuine = await opaque.retain(target.id, { author: a.identity.publicKey, envelopeDigest: alternateDigest })
  expect(opaque.authority.epochKey(1)).toBeNull()
  await a.mergeFacts({ envelopes: [], retentions: [genuine], finality: [] }); expect(target.inspect().retained).toEqual([])
  await a.mergeFacts({ envelopes: [alternate], retentions: [], finality: [] }); expect(await target.retained({ timeoutMs: 100 })).toEqual([genuine])
  await opaque.authority.installEpochKey(1, key1); await opaque.retryMaterialization()
  expect(opaque.inspectOperation(target.id)).toMatchObject({ excluded: false, pending: null, author: a.identity.publicKey, materialized: { outcome: 'accepted' } })
  expect((await opaque.readEvents()).events.map(event => event.payload)).toEqual(['A original', 'after malicious claim'])
})

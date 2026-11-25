import { afterEach, expect, it } from 'vitest'
import { createSigningIdentity, recordDigest, signMembership, type SignedMembership, type MemberGrant } from '@chronolog/authority'
import { sessionFixture } from './test-fixture.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
it('keeps offline intent through unchanged roles and unrelated readers, but never revives old certificates across revoke/regrant', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); closes.push(() => a.close(), () => b.close())
  const past = await b.command('say', 'before revoke', { operationId: 'before', authorTimestampMs: 2n }), future = await b.command('say', 'offline unchanged writer', { operationId: 'offline', authorTimestampMs: 10n }); await past.materialized(); await future.materialized(); const signed = await recordDigest(b.exportFacts().envelopes)
  const memberships: SignedMembership[] = [f.membership]
  const update = async (floor: bigint, members: readonly MemberGrant[]) => { const previous = memberships.at(-1)!; memberships.push(await signMembership({ ...previous.payload, revision: previous.payload.revision + 1, previous: await recordDigest(previous), authorTimeAfterMs: floor, members }, f.authorityIdentity)); const bundle = { descriptor: f.descriptor, memberships }; await a.mergeAuthority(bundle); await b.mergeAuthority(bundle); await a.mergeFacts(b.exportFacts()); await a.retryMaterialization(); await b.retryMaterialization() }
  await update(5n, f.membership.payload.members)
  expect(future.inspect().materialized?.outcome).toBe('accepted'); expect((await a.readEvents()).events.map(event => event.payload)).toEqual(['before revoke', 'offline unchanged writer'])
  const unrelated = await createSigningIdentity(); await update(6n, [...f.membership.payload.members, { publicKey: unrelated.publicKey, wrapKey: null, reader: true, writer: false, administrator: false, publisher: false, finalizer: false }])
  expect(future.inspect().excluded).toBe(false); expect(await recordDigest(b.exportFacts().envelopes)).toBe(signed)
  await update(7n, memberships.at(-1)!.payload.members.map(member => ({ ...member, writer: member.publicKey === f.identities[1]!.publicKey ? false : member.writer })))
  expect(future.inspect()).toMatchObject({ stored: true, excluded: true, materialized: null }); expect(past.inspect().materialized?.outcome).toBe('accepted'); expect(b.status.materializationError).toBeNull()
  await b.close(); const resumed = await f.open(1); closes.push(() => resumed.close()); await resumed.retryMaterialization(); expect(resumed.operations.get('offline')!.inspect()).toMatchObject({ stored: true, excluded: true, materialized: null })
  const previous = memberships.at(-1)!; memberships.push(await signMembership({ ...previous.payload, revision: 4, previous: await recordDigest(previous), authorTimeAfterMs: 8n, members: previous.payload.members.map(member => ({ ...member, writer: member.publicKey === f.identities[1]!.publicKey ? true : member.writer })) }, f.authorityIdentity)); await resumed.mergeAuthority({ descriptor: f.descriptor, memberships }); await resumed.retryMaterialization()
  expect(resumed.operations.get('offline')!.inspect().excluded).toBe(true)
  const exactRetry = await resumed.command('say', 'offline unchanged writer', { operationId: 'offline', authorTimestampMs: 10n }); expect(exactRetry.id).toBe(future.id); expect(await recordDigest(resumed.exportFacts().envelopes)).toBe(signed)
  const deliberateNew = await resumed.command('say', 'deliberately new intent', { operationId: 'new-after-regrant', authorTimestampMs: 10n }); expect(deliberateNew.id).not.toBe(future.id); expect((await deliberateNew.materialized()).outcome).toBe('accepted')
})
it('finalizes carried offline certificates in their original scope and preserves final state through later revocation and reload', async () => {
  const identity = await createSigningIdentity(), f = await sessionFixture({ identities: [identity], finalityPolicy: { kind: 'signed-frontier', signer: identity.publicKey, scopes: [{ id: '99'.repeat(32), authorTimeAfterMs: -1n }] } }), session = await f.open(0); closes.push(() => session.close())
  const operation = await session.command('say', 'old certificate', { operationId: 'carried', authorTimestampMs: 10n }); await operation.materialized()
  const unchanged = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, authorTimeAfterMs: 5n }, f.authorityIdentity); await session.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, unchanged] }); await session.retryMaterialization(); expect(operation.inspect().materialized?.outcome).toBe('accepted')
  const result = await session.finality.closeAuthorTime({ throughMs: 12n }); expect(result.closedThroughMs).toBe(12n); expect(operation.inspect().finalized).toBe(true)
  for (const inclusion of result.proofs.flatMap(proof => proof.statement.inclusions)) expect(inclusion).toMatchObject({ proposalId: operation.id, membershipId: f.membershipId, author: identity.publicKey })
  const later = await session.command('say', 'future revoked', { operationId: 'revoked', authorTimestampMs: 16n }); await later.materialized()
  const revoke = await signMembership({ ...unchanged.payload, revision: 2, previous: await recordDigest(unchanged), authorTimeAfterMs: 15n, members: unchanged.payload.members.map(member => ({ ...member, writer: false })) }, f.authorityIdentity); await session.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, unchanged, revoke] }); await session.retryMaterialization()
  expect(later.inspect().excluded).toBe(true); expect(operation.inspect().finalized).toBe(true); const read = await session.readView({ view: 'final' }); expect(read.readEvents().events.map(event => event.payload)).toEqual(['old certificate']); read.release()
  await session.close(); const reopened = await f.open(0); closes.push(() => reopened.close()); await reopened.retryMaterialization(); expect(reopened.operations.get('carried')!.inspect().finalized).toBe(true); expect(reopened.operations.get('revoked')!.inspect()).toMatchObject({ stored: true, excluded: true, materialized: null })
})

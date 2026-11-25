import { afterEach, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { createSigningIdentity, signMembership, epochKeyCommitment, recordDigest } from '@chronolog/authority'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { createWrapKeyPair, importWrapPrivateKey } from './provisioning.js'
import { eventDefinition, sessionFixture } from './test-fixture.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
it('wraps every committed epoch key to a member’s signed wrap key, and the recipient resumes offline', async () => {
  const fixture = await sessionFixture({ count: 1 }), source = await fixture.open(0), recipient = await createSigningIdentity(), wrap = await createWrapKeyPair(), store = new MemoryBytesStore(); closes.push(() => source.close())
  const open = async () => createApplicationSession({ device: await openApplicationDevice({ store, create: true, managedSigner: recipient }), definition: eventDefinition, authority: fixture.bundle })
  const target = await open(); closes.push(() => target.close()); expect(target.status.canAuthor).toBe(false)
  await expect(source.provisioning.wrapKeys(recipient.publicKey)).rejects.toThrow('PROVISIONING_SCOPE_INVALID')
  const membership = await signMembership({ ...fixture.membership.payload, revision: 1, previous: fixture.membershipId, authorTimeAfterMs: 100n, members: [...fixture.membership.payload.members, { publicKey: recipient.publicKey, wrapKey: wrap.publicKey, reader: true, writer: true, administrator: false, publisher: false, finalizer: false }] }, fixture.authorityIdentity)
  await source.mergeAuthority({ descriptor: fixture.descriptor, memberships: [fixture.membership, membership] })
  const packageValue = await source.provisioning.wrapKeys(recipient.publicKey), encoded = JSON.stringify(packageValue, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value)
  expect(encoded.includes(Buffer.from(fixture.epochKey).toString('hex'))).toBe(false)
  await target.close(); const resumed = await open(); closes.push(() => resumed.close())
  // The package carries the membership that admitted the recipient; the recipient needs nothing else.
  const privateKey = await importWrapPrivateKey(wrap.privateKey)
  expect(await resumed.provisioning.unwrapKeys(packageValue, privateKey)).toEqual([0]); expect(await resumed.provisioning.unwrapKeys(packageValue, privateKey)).toEqual([]); expect(resumed.status.canAuthor).toBe(true)
  expect(await epochKeyCommitment(fixture.applicationId, 0, resumed.authority.epochKey(0)!)).toBe(membership.payload.epochKeyDigest)
  const before = await recordDigest(resumed.exportFacts()), operation = await resumed.command('say', 'recipient offline', { operationId: 'recipient-operation', authorTimestampMs: 101n }); await operation.materialized(); expect(operation.inspect().author).toBe(recipient.publicKey); expect(await recordDigest(resumed.exportFacts())).not.toBe(before)
  await source.mergeFacts(resumed.exportFacts()); await source.retryMaterialization(); expect((await source.readEvents()).events[0]?.payload).toBe('recipient offline')
  await resumed.close(); const cached = await createApplicationSession({ device: await openApplicationDevice({ store, managedSigner: recipient }), definition: eventDefinition, applicationId: fixture.applicationId }); closes.push(() => cached.close()); expect(cached.status.canAuthor).toBe(true); expect((await cached.readEvents()).events[0]?.payload).toBe('recipient offline')
})
it('rejects wrong commitments, wrong recipients, wrong wrap keys and altered packages', async () => {
  const f = await sessionFixture(), source = await f.open(0), recipient = await f.open(1, false); closes.push(() => source.close(), () => recipient.close())
  await expect(recipient.authority.installEpochKey(0, crypto.getRandomValues(new Uint8Array(32)))).rejects.toThrow('AUTHORITY_EPOCH_KEY_COMMITMENT_MISMATCH'); expect(recipient.authority.epochKey(0)).toBeNull()
  const packageValue = await source.provisioning.wrapKeys(f.identities[1]!.publicKey)
  await expect(source.provisioning.unwrapKeys(packageValue, await importWrapPrivateKey(f.wrapPairs[0]!.privateKey))).rejects.toThrow('PROVISIONING_RECIPIENT_MISMATCH')
  await expect(recipient.provisioning.unwrapKeys(packageValue, await importWrapPrivateKey((await createWrapKeyPair()).privateKey))).rejects.toThrow()
  const altered = structuredClone(packageValue); altered.payload.encrypted.ciphertext[0] = altered.payload.encrypted.ciphertext[0]! ^ 1
  await expect(recipient.provisioning.unwrapKeys(altered, await importWrapPrivateKey(f.wrapPairs[1]!.privateKey))).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID'); expect(recipient.status.canAuthor).toBe(false)
  await recipient.provisioning.unwrapKeys(packageValue, await importWrapPrivateKey(f.wrapPairs[1]!.privateKey)); expect(recipient.status.canAuthor).toBe(true)
})
it('rotation wraps the new epoch only to remaining members; a removed member cannot unwrap it', async () => {
  const f = await sessionFixture({ count: 3 }), admin = await f.open(0), stays = await f.open(1), removed = await f.open(2); closes.push(() => admin.close(), () => stays.close(), () => removed.close())
  const next = crypto.getRandomValues(new Uint8Array(32))
  const rotated = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, authorTimeAfterMs: 50n, epoch: 1, epochKeyDigest: await epochKeyCommitment(f.applicationId, 1, next), members: f.membership.payload.members.filter(member => member.publicKey !== f.identities[2]!.publicKey) }, f.identities[0]!)
  await admin.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, rotated] }); await admin.authority.installEpochKey(1, next)
  await expect(admin.provisioning.wrapKeys(f.identities[2]!.publicKey)).rejects.toThrow('PROVISIONING_SCOPE_INVALID')
  const wrapped = await admin.provisioning.wrapKeys(f.identities[1]!.publicKey)
  expect(await stays.provisioning.unwrapKeys(wrapped, await importWrapPrivateKey(f.wrapPairs[1]!.privateKey))).toEqual([1])
  await expect(removed.provisioning.unwrapKeys(wrapped, await importWrapPrivateKey(f.wrapPairs[2]!.privateKey))).rejects.toThrow('PROVISIONING_RECIPIENT_MISMATCH')
  expect(removed.authority.epochKey(1)).toBeNull()
  const later = await stays.command('say', 'after rotation', { authorTimestampMs: 60n }); await later.materialized()
  await expect(removed.mergeFacts(stays.exportFacts())).resolves.toBeUndefined(); expect(removed.status.canAuthor).toBe(false)
})

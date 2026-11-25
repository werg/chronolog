import { afterEach, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { createSigningIdentity, signMembership, epochKeyCommitment, recordDigest } from '@chronolog/authority'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { eventDefinition, sessionFixture } from './test-fixture.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
it('provisions a newly enrolled browser key with recipient-encrypted committed epoch keys and resumes offline', async () => {
  const fixture = await sessionFixture({ count: 1 }), source = await fixture.open(0), recipient = await createSigningIdentity(), store = new MemoryBytesStore(); closes.push(() => source.close())
  const open = async () => createApplicationSession({ device: await openApplicationDevice({ store, create: true, managedSigner: recipient }), definition: eventDefinition, authority: fixture.bundle })
  const target = await open(); closes.push(() => target.close()); expect(target.status.canAuthor).toBe(false)
  const request = await target.provisioning.createProvisioningRequest(); expect(request.payload.recipient).toBe(recipient.publicKey)
  await expect(source.provisioning.exportProvisioning(request)).rejects.toThrow('PROVISIONING_SCOPE_INVALID')
  const membership = await signMembership({ ...fixture.membership.payload, revision: 1, previous: fixture.membershipId, authorTimeAfterMs: 100n, members: [...fixture.membership.payload.members, { publicKey: recipient.publicKey, reader: true, writer: true, administrator: false, publisher: false, finalizer: false }] }, fixture.authorityIdentity)
  await source.mergeAuthority({ descriptor: fixture.descriptor, memberships: [fixture.membership, membership] })
  const packageValue = await source.provisioning.exportProvisioning(request), encoded = JSON.stringify(packageValue, (_key, value: unknown) => typeof value === 'bigint' ? value.toString() : value)
  expect(encoded.includes(Buffer.from(fixture.epochKey).toString('hex'))).toBe(false)
  await target.close(); const resumed = await open(); closes.push(() => resumed.close())
  await resumed.provisioning.importProvisioning(packageValue); await resumed.provisioning.importProvisioning(packageValue); expect(resumed.status.canAuthor).toBe(true)
  expect(await epochKeyCommitment(fixture.applicationId, 0, resumed.authority.epochKey(0)!)).toBe(membership.payload.epochKeyDigest)
  const before = await recordDigest(resumed.exportFacts()), operation = await resumed.command('say', 'recipient offline', { operationId: 'recipient-operation', authorTimestampMs: 101n }); await operation.materialized(); expect(operation.inspect().author).toBe(recipient.publicKey); expect(await recordDigest(resumed.exportFacts())).not.toBe(before)
  await source.mergeFacts(resumed.exportFacts()); await source.retryMaterialization(); expect((await source.readEvents()).events[0]?.payload).toBe('recipient offline')
  await resumed.close(); const cached = await createApplicationSession({ device: await openApplicationDevice({ store, managedSigner: recipient }), definition: eventDefinition, applicationId: fixture.applicationId }); closes.push(() => cached.close()); expect(cached.status.canAuthor).toBe(true); expect((await cached.readEvents()).events[0]?.payload).toBe('recipient offline')
})
it('rejects wrong epoch key commitments and wrong-target provisioning imports', async () => {
  const f = await sessionFixture(), source = await f.open(0), recipient = await f.open(1, false); closes.push(() => source.close(), () => recipient.close())
  await expect(recipient.authority.installEpochKey(0, crypto.getRandomValues(new Uint8Array(32)))).rejects.toThrow('AUTHORITY_EPOCH_KEY_COMMITMENT_MISMATCH'); expect(recipient.authority.epochKey(0)).toBeNull()
  const request = await recipient.provisioning.createProvisioningRequest(), packageValue = await source.provisioning.exportProvisioning(request)
  await expect(source.provisioning.importProvisioning(packageValue)).rejects.toThrow('AUTHORITY_SIGNER_MISMATCH')
  const altered = structuredClone(packageValue); altered.payload.encrypted.ciphertext[0] = altered.payload.encrypted.ciphertext[0]! ^ 1
  await expect(recipient.provisioning.importProvisioning(altered)).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID'); expect(recipient.status.canAuthor).toBe(false)
})

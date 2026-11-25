import { createSigningIdentity, signAppDescriptor, signMembership, epochKeyCommitment, recordDigest, type AuthorityBundle, type FinalityPolicy, type SigningIdentity } from '@chronolog/authority'
import { executionManifestArtifacts, bytesToHex, emit, program } from '@chronolog/protocol'
import { eventExecutionManifest } from '@chronolog/materializer/manifest'
import { MemoryBytesStore } from '@chronolog/records'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { defineApplication, defineCommand, defineQuery } from './definition.js'
import type { ApplicationReadView } from './session-types.js'
export const eventDefinition = defineApplication({ id: 'authored-test', version: '1', commands: { say: defineCommand({ description: 'Say', input: { type: 'string' }, prepare: text => program(emit('message', text)) }) }, queries: { messages: defineQuery({ description: 'Messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }) } })
export async function sessionFixture(options: { readonly count?: number; readonly finalityPolicy?: FinalityPolicy; readonly identities?: readonly SigningIdentity[]; readonly manifestDigest?: string } = {}) {
  const identities = options.identities ?? await Promise.all(Array.from({ length: options.count ?? 2 }, () => createSigningIdentity())), authorityIdentity = await createSigningIdentity(), applicationId = 'ab'.repeat(32), epochKey = crypto.getRandomValues(new Uint8Array(32))
  const digest = options.manifestDigest ?? bytesToHex((await executionManifestArtifacts(await eventExecutionManifest())).executionManifestDigest)
  const descriptor = await signAppDescriptor({ applicationId, rootPrincipal: identities[0]!.publicKey, authorityPublicKey: authorityIdentity.publicKey, executionManifestDigest: digest, finalityPolicy: options.finalityPolicy ?? { kind: 'none' } }, authorityIdentity)
  const membership = await signMembership({ applicationId, revision: 0, previous: null, authorTimeAfterMs: -1n, epoch: 0, epochKeyDigest: await epochKeyCommitment(applicationId, 0, epochKey), members: identities.map((identity, i) => ({ publicKey: identity.publicKey, reader: true, writer: true, administrator: i === 0, publisher: i === 0, finalizer: options.finalityPolicy?.kind === 'signed-frontier' ? options.finalityPolicy.signer === identity.publicKey : options.finalityPolicy?.kind === 'fixed-validator' ? options.finalityPolicy.validators.includes(identity.publicKey) : false })) }, authorityIdentity)
  const bundle: AuthorityBundle = { descriptor, memberships: [membership] }, stores = identities.map(() => new MemoryBytesStore())
  const open = async (index: number, keys = true) => createApplicationSession({ device: await openApplicationDevice({ store: stores[index]!, create: true, managedSigner: identities[index]! }), definition: eventDefinition, authority: bundle, ...(keys ? { epochKeys: new Map([[0, epochKey]]) } : {}) })
  return { identities, authorityIdentity, applicationId, descriptor, membership, membershipId: await recordDigest(membership), epochKey, bundle, stores, open }
}

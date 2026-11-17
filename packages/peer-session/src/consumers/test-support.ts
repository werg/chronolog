import { createGenerationRegistry, createPeerIdentity, MemoryPeerStore, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, bytesDigest, participantGrant, type PeerIdentity, type PrefixProof } from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program, type EventPayload } from '@chronolog/protocol'

import { defineApplication, defineCommand, applicationDefinitionDigest } from '../definition.js'
import { openApplicationDevice } from '../device.js'
import { openPeerApplication } from '../runtime.js'
import { connectApplications, type ApplicationSession } from '../session.js'

export const definition = defineApplication({ id: 'consumer-contract', version: '1', commands: {
  record: defineCommand({ description: 'Publish a test domain event', input: { type: 'object', properties: {
    topic: { type: 'string' }, payload: { type: 'string' },
  }, required: ['topic', 'payload'] }, prepare: input => program(emit(input.topic, JSON.parse(input.payload) as EventPayload)) }),
}, queries: {} })

export async function consumerFixture() {
  const host = await createPeerIdentity()
  const aDevice = await openApplicationDevice({ store: new MemoryPeerStore(), create: true })
  const bDevice = await openApplicationDevice({ store: new MemoryPeerStore(), create: true })
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: 'cc'.repeat(32), historyId: 'consumer-contract', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: aDevice.identity.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [aDevice, bDevice].map(device => participantGrant(device.identity.publicKey, { administrator: true })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(aDevice.identity, null, 'create')
  const a = await openPeerApplication({ device: aDevice, definition, authority: await registry.read(), epochKeys })
  const b = await openPeerApplication({ device: bDevice, definition, authority: await registry.read(), epochKeys })
  const links: Array<{ close(): void | Promise<void> }> = []
  return { a, b, aDevice, bDevice, registry,
    async synchronize() { const link = await connectApplications(a, b); links.push(link); return link },
    async recover(point: PrefixProof) {
      await select(bDevice.identity, point, `recover-${(await registry.read()).generations.length}`)
      await b.adopt(await registry.read()); await a.adopt(await registry.read())
    },
    async close() { for (const link of links) await link.close(); await a.close(); await b.close() },
  }
}

export async function publish(session: ApplicationSession<typeof definition>, topic: string, payload: EventPayload, operationId: string) {
  const operation = await session.command('record', { topic, payload: JSON.stringify(payload) }, { operationId })
  await operation.applied({ signal: AbortSignal.timeout(5000) }); return operation
}

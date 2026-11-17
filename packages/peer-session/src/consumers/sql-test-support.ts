import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { applicationDescriptionDigest, bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest } from '@chronolog/peer-generation'

import type { ApplicationDefinition } from '../definition.js'
import { openApplicationDevice } from '../device.js'
import { openNativeSqlApplication, prepareNativeSqlApplication } from '../sql-native.js'

export async function consumerSqlFixture<const D extends ApplicationDefinition>(definition: D) {
  const directory = await mkdtemp(join(tmpdir(), 'application-consumers-'))
  const device = await openApplicationDevice({ store: new MemoryPeerStore(), create: true })
  const signer = await createPeerIdentity(), key = crypto.getRandomValues(new Uint8Array(32)), applicationId = 'ed'.repeat(32)
  const prepared = await prepareNativeSqlApplication({ applicationId, definition, schemaAdministrator: device.identity })
  const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'consumer-sql', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
    controlPublicKey: signer.publicKey, schemaAdministrator: prepared.schemaAdministrator, executionManifestDigest: prepared.executionManifestDigest,
    definitionDigest: await applicationDescriptionDigest(prepared.definition), schemaDigest: await peerDigest(prepared.schema) }, signer)
  const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [participantGrant(device.identity.publicKey, { administrator: true })] }, signer)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer })
  await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    transitionId: 'create', expectedGeneration: null, requester: device.identity.publicKey, coordinator: device.identity.publicKey,
    controlRevision: 0, reason: 'create', base: null }, device.identity))
  const session = await openNativeSqlApplication({ device, definition, authority: await registry.read(), epochKeys: new Map([[0, key]]),
    databasePath: join(directory, 'application.sqlite'), schema: prepared.schema })
  return { session, device,
    async close() { await session.close(); await rm(directory, { recursive: true, force: true }) },
  }
}

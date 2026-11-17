import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it, vi } from 'vitest'
import { DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant, peerDigest,
  signApplicationDescriptor, signApplicationSchema, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { bytesToHex, encodeChangeProgram, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication } from './definition.js'
import { openApplicationDevice } from './device.js'
import { createNativeSqlManifest, openNativeSqlApplication } from './sql-native.js'
import type { ApplicationSession } from './session.js'

it('claims the SQL session before opening a second materializer or disturbing an existing read lease', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peer-sql-owner-'))
  const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  let session: ApplicationSession | undefined
  try {
    const host = await createPeerIdentity(), key = crypto.getRandomValues(new Uint8Array(32))
    const definition = defineApplication({ id: 'sql-owner', version: '1',
      schema: program('CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)'), commands: {}, queries: {} })
    const { executionManifestDigest } = await executionManifestArtifacts(createNativeSqlManifest())
    const applicationId = 'cd'.repeat(32), definitionDigest = await applicationDefinitionDigest(definition)
    const schema = await signApplicationSchema({ applicationId, definitionDigest, executionManifestDigest: bytesToHex(executionManifestDigest),
      program: bytesToHex(encodeChangeProgram(definition.schema!)) }, device.identity)
    const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'sql-owner', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      controlPublicKey: host.publicKey, schemaAdministrator: device.identity.publicKey, executionManifestDigest: bytesToHex(executionManifestDigest),
      definitionDigest, schemaDigest: await peerDigest(schema) }, host)
    const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
      grants: [participantGrant(device.identity.publicKey, { administrator: true })] }, host)
    const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'initial', expectedGeneration: null, requester: device.identity.publicKey, coordinator: device.identity.publicKey,
      controlRevision: 0, reason: 'create', base: null }, device.identity))
    const options = { device, authority: await registry.read(), definition, epochKeys: new Map([[0, key]]),
      databasePath: join(directory, 'application.db'), schema }
    session = await openNativeSqlApplication(options)
    const captured = await session.readView()
    const opening = vi.spyOn(DeterministicMaterializer, 'open')
    try {
      await expect(openNativeSqlApplication(options)).rejects.toThrow('APPLICATION_DEVICE_IN_USE')
      expect(opening).not.toHaveBeenCalled()
      expect(captured.query('SELECT id,value FROM items').rows).toEqual([])
      const current = await session.readView()
      try { expect(current.revision).toEqual(captured.revision) } finally { current.release() }
    } finally { opening.mockRestore(); captured.release() }
  } finally {
    await session?.close(); await device.close()
    await rm(directory, { recursive: true, force: true })
  }
})

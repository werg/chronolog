import { access, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it, vi } from 'vitest'
import type { PeerApplicationConfiguration } from '@tendriller/core/peers'
import { DeterministicMaterializer } from '@chronolog/materializer-doltlite'
import {
  applicationDescriptionDigest, bytesDigest, controlParticipantGrant, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant, peerDigest,
  signApplicationDescriptor, signApplicationSchema, signControlRevision, signTransitionRequest, verifyApplicationSchema,
  type GenerationRegistry,
} from '@chronolog/peer-generation'
import { program } from '@chronolog/protocol'
import { defineApplication, defineCommand, defineQuery, describeApplication } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openNativeSqlApplication, openNativeSqlSession, prepareNativeSqlApplication } from './sql-native.js'
import type { ApplicationReadView, ApplicationSession } from './session.js'
import type { ApplicationBootstrapHost, ApplicationPublication } from './bootstrap.js'
import { openNativeDevice } from './native.js'

it('rejects mismatched engines and duplicate owners before creating or disturbing durable SQL', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peer-sql-owner-'))
  const device = await openApplicationDevice({ store: new MemoryPeerStore(), create: true })
  let session: ApplicationSession | undefined
  try {
    const host = await createPeerIdentity(), key = crypto.getRandomValues(new Uint8Array(32))
    const definition = defineApplication({ id: 'sql-owner', version: '1',
      schema: program('CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)'), commands: {}, queries: {} })
    const applicationId = 'cd'.repeat(32)
    const prepared = await prepareNativeSqlApplication({ applicationId, definition, schemaAdministrator: device.identity })
    const configuration = { ...prepared, historyId: 'sql-owner', epoch: 0, keyDigest: await bytesDigest(key),
      members: [{ publicKey: device.identity.publicKey }] } satisfies PeerApplicationConfiguration
    expect(Object.keys(prepared).sort()).toEqual(['definition', 'executionManifestDigest', 'schema', 'schemaAdministrator'])
    expect(configuration.definition).toEqual(describeApplication(definition))
    const { schema } = prepared
    const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'sql-owner', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      controlPublicKey: host.publicKey, schemaAdministrator: prepared.schemaAdministrator, executionManifestDigest: prepared.executionManifestDigest,
      definitionDigest: await applicationDescriptionDigest(prepared.definition), schemaDigest: await peerDigest(schema) }, host)
    expect(await verifyApplicationSchema(schema, descriptor.payload)).toEqual(definition.schema)
    const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
      grants: [participantGrant(device.identity.publicKey, { administrator: true })] }, host)
    const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
    const initialRequest = await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'initial', expectedGeneration: null, requester: device.identity.publicKey, coordinator: device.identity.publicKey,
      controlRevision: 0, reason: 'create', base: null }, device.identity)
    await registry.select(initialRequest)
    const options = { device, authority: await registry.read(), definition, epochKeys: new Map([[0, key]]),
      databasePath: join(directory, 'application.db'), schema }
    const incompatibleSchema = await signApplicationSchema({ ...schema.payload, executionManifestDigest: 'ab'.repeat(32) }, device.identity)
    const incompatibleDescriptor = await signApplicationDescriptor({ ...descriptor.payload,
      executionManifestDigest: incompatibleSchema.payload.executionManifestDigest, schemaDigest: await peerDigest(incompatibleSchema) }, host)
    const incompatibleRegistry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor: incompatibleDescriptor, controls: [control], signer: host })
    await incompatibleRegistry.select(initialRequest)
    const openingIncompatible = vi.spyOn(DeterministicMaterializer, 'open')
    try {
      await expect(openNativeSqlApplication({ ...options, schema: incompatibleSchema,
        authority: await incompatibleRegistry.read() })).rejects.toThrow('PEER_EXECUTION_MANIFEST_MISMATCH')
      expect(openingIncompatible).not.toHaveBeenCalled()
      await expect(access(options.databasePath)).rejects.toMatchObject({ code: 'ENOENT' })
    } finally { openingIncompatible.mockRestore() }
    // A corrected open can use the retained device identity and a pristine database path.
    options.device = await openApplicationDevice({ store: device.store })
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

it('creates a signed SQL application through the canonical session opener and resumes without the host', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peer-sql-bootstrap-')), path = join(directory, 'device.sqlite')
  const device = await openNativeDevice({ path, create: true }), signer = await createPeerIdentity(), applicationId = 'ce'.repeat(32)
  let session: ApplicationSession | undefined, registry: GenerationRegistry | undefined, publication: ApplicationPublication | undefined
  const definition = defineApplication({ id: 'sql-bootstrap', version: '1', schema: program('CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)'),
    commands: { insert: defineCommand({ description: 'Insert an item', input: { type: 'null' }, prepare: () => program("INSERT INTO items(id,value) VALUES(1,'owned')") }) },
    queries: { items: defineQuery({ description: 'Read items', input: { type: 'null' }, read: (view: ApplicationReadView) => view.query('SELECT id,value FROM items ORDER BY id') }) } })
  const host: ApplicationBootstrapHost = {
    async configureApplication(configuration) {
      const hostedConfiguration: PeerApplicationConfiguration = configuration
      expect(Object.keys(hostedConfiguration).sort()).toEqual([
        'definition', 'epoch', 'executionManifestDigest', 'historyId', 'keyDigest', 'members', 'schema', 'schemaAdministrator',
      ])
      const descriptor = await signApplicationDescriptor({ applicationId, historyId: configuration.historyId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
        controlPublicKey: signer.publicKey, schemaAdministrator: configuration.schemaAdministrator, executionManifestDigest: configuration.executionManifestDigest,
        definitionDigest: await applicationDescriptionDigest(configuration.definition), schemaDigest: await peerDigest(configuration.schema) }, signer)
      const control = await signControlRevision({ applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1', revision: 0, previous: null,
        epoch: configuration.epoch, keyDigest: configuration.keyDigest, recoveryFloor: null,
        grants: [controlParticipantGrant(signer.publicKey), participantGrant(device.identity.publicKey)] }, signer)
      registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer })
      publication = { descriptor, definition: configuration.definition, schema: configuration.schema }
      return registry.read()
    },
    async application() { if (registry === undefined) throw new Error('NOT_CONFIGURED'); return registry.read() },
    async definition() { if (publication === undefined) throw new Error('NOT_CONFIGURED'); return publication },
    async selectGeneration(request) { if (registry === undefined) throw new Error('NOT_CONFIGURED'); return registry.select(request) },
  }
  try {
    const created = await openNativeSqlSession({ device, definition, applicationId, host, create: {}, databasePath: join(directory, 'application.db') })
    session = created
    const operation = await created.command('insert', null, { operationId: 'once' })
    expect((await operation.applied()).outcome).toBe('accepted')
    const read = await session.readView()
    expect(read.query('SELECT id,value FROM items').rows).toEqual([[1, 'owned']]); read.release()
    const identity = session.deviceId
    await session.close()
    session = await openNativeSqlSession({ device: await openNativeDevice({ path }), definition, applicationId, databasePath: join(directory, 'application.db') })
    expect(session.deviceId).toBe(identity)
    expect(await session.operations.get('once')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    const resumed = await session.readView()
    expect(resumed.query('SELECT id,value FROM items').rows).toEqual([[1, 'owned']]); resumed.release()
  } finally { await session?.close(); await device.close(); await rm(directory, { recursive: true, force: true }) }
})

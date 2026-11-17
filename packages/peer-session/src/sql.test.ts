import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it, vi } from 'vitest'
import { DeterministicMaterializer } from '@chronolog/materializer-doltlite/browser'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { program } from '@chronolog/protocol'
import { defineApplication } from './definition.js'
import { openApplicationDevice } from './device.js'
import { createNativeSqlEngine } from './sql-native.js'
import { openSqlApplication, prepareSqlApplication, type SqlEngine } from './sql.js'
import { openPeerApplication } from './runtime.js'
import { createApplicationBackend } from './tendriller.js'
import { connectApplicationWorker, serveApplicationWorker } from './worker-application.js'

const cleanups: (() => Promise<void>)[] = []
afterEach(async () => { for (const close of cleanups.splice(0).reverse()) await close() })

async function fixture(executionManifest?: SqlEngine['executionManifest']) {
  const directory = await mkdtemp(join(tmpdir(), 'peer-sql-owner-'))
  cleanups.push(() => rm(directory, { recursive: true, force: true }))
  const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  cleanups.push(async () => { await device.close() })
  const host = await createPeerIdentity(), key = crypto.getRandomValues(new Uint8Array(32)), native = createNativeSqlEngine()
  const engine = executionManifest === undefined ? native : { ...native, executionManifest }
  const definition = defineApplication({ id: 'sql-owner', version: '1',
    schema: program('CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)'), commands: {}, queries: {} })
  const applicationId = 'cd'.repeat(32)
  const prepared = await prepareSqlApplication({ engine, applicationId, definition, schemaAdministrator: device.identity })
  const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'sql-owner', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
    controlPublicKey: host.publicKey, ...prepared.binding }, host)
  const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [participantGrant(device.identity.publicKey, { administrator: true })] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    transitionId: 'initial', expectedGeneration: null, requester: device.identity.publicKey, coordinator: device.identity.publicKey,
    controlRevision: 0, reason: 'create', base: null }, device.identity))
  return { engine, options: { engine, device, authority: await registry.read(), definition, epochKeys: new Map([[0, key]]),
    databasePath: join(directory, 'application.db'), schema: prepared.schema } }
}

it('claims the shared SQL session before opening another materializer or disturbing an existing read lease', async () => {
  const { options } = await fixture()
  const session = await openSqlApplication(options)
  cleanups.push(() => session.close())
  const captured = await session.readView(), opening = vi.spyOn(DeterministicMaterializer, 'open')
  try {
    await expect(openSqlApplication(options)).rejects.toThrow('APPLICATION_DEVICE_IN_USE')
    expect(opening).not.toHaveBeenCalled()
    expect(captured.query('SELECT id,value FROM items').rows).toEqual([])
    const current = await session.readView()
    try { expect(current.revision).toEqual(captured.revision) } finally { current.release() }
  } finally { opening.mockRestore(); captured.release() }
})

it('rejects a mismatched engine capability before it opens or initializes a database', async () => {
  const { options, engine } = await fixture(), openDatabase = vi.fn(engine.openDatabase.bind(engine))
  const executionManifest = structuredClone(engine.executionManifest)
  executionManifest.engineDigest[0] = executionManifest.engineDigest[0]! ^ 1
  await expect(openSqlApplication({ ...options, engine: { executionManifest, openDatabase } })).rejects.toThrow('APPLICATION_EXECUTION_MANIFEST_MISMATCH')
  expect(openDatabase).not.toHaveBeenCalled()
})

it('captures the engine and signed schema before asynchronous ownership and verification', async () => {
  const { options, engine } = await fixture(), openDatabase = vi.fn(engine.openDatabase.bind(engine))
  const suppliedEngine = { executionManifest: structuredClone(engine.executionManifest), openDatabase }
  const schema = structuredClone(options.schema)
  const opening = openSqlApplication({ ...options, engine: suppliedEngine, schema })
  suppliedEngine.executionManifest.engineDigest.fill(0)
  suppliedEngine.openDatabase = vi.fn(() => { throw new Error('late substituted factory') })
  Object.assign(schema.payload, { program: '00' })
  const session = await opening
  cleanups.push(() => session.close())
  const view = await session.readView()
  try { expect(view.query('SELECT id,value FROM items').rows).toEqual([]) } finally { view.release() }
  expect(openDatabase).toHaveBeenCalled()
  expect(suppliedEngine.openDatabase).not.toHaveBeenCalled()
})

it.each([false, true])('rejects schema-bound applications with event-only execution (explicit factory: %s)', async explicit => {
  // Even a descriptor signed with the event execution digest must not silently
  // skip the definition's independently signed schema program.
  const { options } = await fixture(await eventExecutionManifest())
  await expect(openPeerApplication({ ...options, ...(explicit ? {
    createMaterializer: () => createEventMaterializationRuntime({ store: options.device.store, namespace: options.authority.descriptor.payload.historyId }),
  } : {}) })).rejects.toThrow('APPLICATION_SCHEMA_REQUIRES_SQL')
})

it('derives native and Worker-backed SQL adapter capabilities from the actual materializer', async () => {
  const { options } = await fixture(), session = await openSqlApplication(options)
  cleanups.push(() => session.close())
  const endpoint = new MessageChannel()
  const server = serveApplicationWorker(session, endpoint.port1)
  cleanups.push(async () => { await server.close(); endpoint.port1.close(); endpoint.port2.close() })
  const client = await connectApplicationWorker(endpoint.port2)
  cleanups.push(() => client.close())
  for (const owner of [session, client]) {
    expect(owner.capabilities.sql).toBe(true)
    expect(owner.describe().capabilities.sql).toBe(true)
    const backend = createApplicationBackend({ id: owner.applicationId, session: owner })
    expect(backend.capabilities).toContain('sql')
    const view = await backend.readView()
    try { expect((await view.query('SELECT id,value FROM items')).rows).toEqual([]) }
    finally { await view.release() }
  }
})

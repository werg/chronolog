import { existsSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import { MemoryBytesStore } from '@chronolog/records'
import { NativeBytesStore } from '@chronolog/records/native'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { eventExecutionManifest } from '@chronolog/materializer/manifest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import type { ApplicationReadView } from './session-types.js'
import {
  createAppClient, describeOperationLifecycle, exportDeviceCheckpoint, generateCheckpointKey,
  encodeCheckpointKeyHex, decodeCheckpointKeyHex, isDeviceRetired, openApplicationDevice,
  openPeerApplication, restoreDeviceCheckpoint, submitBatch,
} from './index.js'
import { openDisposableNativeDevice, openNativeDevice } from './native.js'

const demoDefinition = defineApplication({
  id: 'ergonomics-demo',
  version: '1',
  commands: {
    addItem: defineCommand({
      description: 'Add an item',
      input: { type: 'object', properties: { text: { type: 'string', minLength: 1 } }, required: ['text'], additionalProperties: false },
      prepare: (input) => program(emit('item.added', { text: (input as { text: string }).text })),
    }),
  },
  queries: {
    items: defineQuery({
      description: 'List items',
      input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['item.added'] }).events.map(e => (e.payload as { text: string }).text),
    }),
  },
})

async function openReadySession(device: Awaited<ReturnType<typeof openDisposableNativeDevice>>) {
  const host = await createPeerIdentity()
  const epochKey = crypto.getRandomValues(new Uint8Array(32))
  const applicationId = '11'.repeat(32)
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({
    applicationId,
    historyId: 'ergonomics-history',
    profile: 'peer-generation-v1',
    policy: 'eligible-members-v1',
    controlPublicKey: host.publicKey,
    schemaAdministrator: device.identity.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(demoDefinition),
    schemaDigest: null,
  }, host)
  const control = await signControlRevision({
    applicationId,
    profile: 'peer-generation-v1',
    policy: 'eligible-members-v1',
    revision: 0,
    previous: null,
    epoch: 0,
    keyDigest: await bytesDigest(epochKey),
    recoveryFloor: null,
    grants: [participantGrant(device.identity.publicKey, { administrator: true })],
  }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({
    applicationId,
    profile: 'peer-generation-v1',
    policy: 'eligible-members-v1',
    transitionId: 'initial',
    expectedGeneration: null,
    requester: device.identity.publicKey,
    coordinator: device.identity.publicKey,
    controlRevision: 0,
    reason: 'create',
    base: null,
  }, device.identity))
  const authority = await registry.read()
  const session = await openPeerApplication({ device, definition: demoDefinition, authority, epochKeys: new Map([[0, epochKey]]) })
  return { session, authority, epochKey }
}

describe('ergonomics, batch submission, checkpoints, and disposable storage', () => {
  it('maps operation journal states cleanly and submits idempotent batches via createAppClient', async () => {
    expect(describeOperationLifecycle('op-unknown', null).lifecycle).toBe('unknown')
    expect(describeOperationLifecycle('op-rec', { status: 'saved', attemptId: 'a', operationId: 'op-rec', generation: 'g1' }).lifecycle).toBe('recorded')
    expect(describeOperationLifecycle('op-sub', { status: 'saved', attemptId: 'a', operationId: 'op-sub', generation: 'g1' }, { transmitted: true }).lifecycle).toBe('submitted')

    const device = await openDisposableNativeDevice()
    expect(device.ephemeral).toBe(true)
    expect(device.resumable).toBe(false)
    expect(device.storageMode).toBe('disposable-events')
    const { session } = await openReadySession(device)
    const outboxLog: string[] = []
    const app = createAppClient(session, { beforeSubmit: entry => { outboxLog.push(entry.operationId) } })
    try {
      const results = await app.submitBatch([
        { operationId: 'batch-1', command: 'addItem', input: { text: 'alpha' } },
        { operationId: 'batch-2', command: 'addItem', input: { text: 'beta' } },
      ])
      expect(outboxLog).toEqual(['batch-1', 'batch-2'])
      expect(results.map(r => r.lifecycle)).toEqual(['applied', 'applied'])
      const inspected = await app.inspectOperation('batch-1')
      expect(inspected.lifecycle).toBe('applied')
      expect(inspected.outcome).toBe('accepted')
      const queried = await app.query('items', null)
      expect(queried.value).toEqual(['alpha', 'beta'])
      await expect(submitBatch(session, [
        { operationId: 'dup', command: 'addItem', input: { text: 'a' } },
        { operationId: 'dup', command: 'addItem', input: { text: 'b' } },
      ])).rejects.toMatchObject({ code: 'BATCH_DUPLICATE_OPERATION_ID' })
    } finally {
      await app.close()
      await device.close()
    }
  })

  it('exports and restores AES-256-GCM device checkpoints and retires source stores against split-brain', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'chronolog-cp-'))
    try {
      const sourcePath = join(dir, 'source.sqlite')
      const targetPath = join(dir, 'target.sqlite')
      const sourceDevice = await openNativeDevice({ path: sourcePath, create: true })
      const originalPublicKey = sourceDevice.identity.publicKey
      const originalStorageId = sourceDevice.storageId
      await sourceDevice.store.put('custom/note', new TextEncoder().encode('preserved-bytes'))
      const rawKey = generateCheckpointKey()
      expect(decodeCheckpointKeyHex(encodeCheckpointKeyHex(rawKey))).toEqual(rawKey)

      const exported = await exportDeviceCheckpoint(sourceDevice.store, {
        secret: rawKey,
        applicationId: '22'.repeat(32),
        deviceId: originalPublicKey,
        outbox: [{ operationId: 'pending-op-1', command: 'addItem', createdAt: new Date().toISOString() }],
      })
      expect(exported.retiredSource).toBe(true)
      expect((await isDeviceRetired(sourceDevice.store)).retired).toBe(true)
      await sourceDevice.close()

      // Reopening retired source fails closed with DEVICE_RETIRED_BY_CHECKPOINT
      await expect(openNativeDevice({ path: sourcePath })).rejects.toMatchObject({ code: 'DEVICE_RETIRED_BY_CHECKPOINT' })

      // Wrong key or tampered bytes fail authentication
      const badStore = new MemoryBytesStore()
      await expect(restoreDeviceCheckpoint(badStore, exported.bytes, { secret: generateCheckpointKey() }))
        .rejects.toMatchObject({ code: 'CHECKPOINT_DECRYPT_FAILED' })

      // Restore into fresh NativeBytesStore preserves exact identity and data
      const targetStore = new NativeBytesStore(targetPath)
      const restored = await restoreDeviceCheckpoint(targetStore, exported.bytes, { secret: rawKey })
      expect(restored.metadata.deviceId).toBe(originalPublicKey)
      expect(restored.outbox).toHaveLength(1)
      expect(new TextDecoder().decode((await targetStore.get('custom/note'))!)).toBe('preserved-bytes')
      // Non-empty target refuses accidental overwrite
      await expect(restoreDeviceCheckpoint(targetStore, exported.bytes, { secret: rawKey }))
        .rejects.toMatchObject({ code: 'CHECKPOINT_TARGET_NOT_EMPTY' })
      targetStore.close()

      // Reopening restored NativeBytesStore as an ApplicationDevice preserves identity verbatim
      const reopened = await openNativeDevice({ path: targetPath })
      expect(reopened.identity.publicKey).toBe(originalPublicKey)
      expect(reopened.storageId).toBe(originalStorageId)
      await reopened.close()

      // Passphrase mode also works round-trip on MemoryBytesStore
      const memA = new MemoryBytesStore()
      const memDev = await openApplicationDevice({ store: memA, create: true })
      const passExport = await exportDeviceCheckpoint(memDev.store, { secret: 'long-enough-secret-passphrase', retireSource: false })
      const memB = new MemoryBytesStore()
      const passRestore = await restoreDeviceCheckpoint(memB, passExport.bytes, { secret: 'long-enough-secret-passphrase' })
      expect(passRestore.restoredEntries).toBe(passExport.metadata.entryCount)
      await memDev.close()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  it('allocates and cleans up a managed temp directory for disposable SQL devices', async () => {
    const device = await openDisposableNativeDevice({ sql: true })
    expect(device.storageMode).toBe('disposable-sql')
    expect(device.temporaryDirectory).toBeTruthy()
    expect(device.databasePath).toBeTruthy()
    expect(existsSync(device.temporaryDirectory!)).toBe(true)
    const dir = device.temporaryDirectory!
    await device.close()
    expect(existsSync(dir)).toBe(false)
  })
})

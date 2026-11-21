import { describe, expect, it } from 'vitest'
import { createPeerIdentity, bytesDigest, participantGrant, signApplicationDescriptor, signControlRevision, createGenerationRegistry, signTransitionRequest } from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer/manifest'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { MemoryBytesStore } from '@chronolog/records'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import type { ApplicationReadView } from './session-types.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { createLiveView } from './live-view.js'
import { canonicalJson, createViewStore, operationReference, SessionError } from './view-store.js'
import { forwardSessionEvents } from './event-forwarder.js'
import { createScopedApplicationTools } from './tools.js'

const definition = defineApplication({
  id: 'pipe-extensions-test',
  version: '1',
  commands: {
    addNote: defineCommand({
      description: 'Add a note',
      input: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
      prepare: ({ text }) => program(emit('note', { text })),
    }),
    adminNote: defineCommand({
      description: 'Admin note',
      input: { type: 'string' },
      prepare: text => program(emit('admin', { text })),
    }),
  },
  queries: {
    notes: defineQuery({
      description: 'Read notes',
      input: { type: 'null' },
      read: (view: ApplicationReadView) => view.readEvents({ topics: ['note'] }).events.map(e => e.payload),
    }),
    secret: defineQuery({
      description: 'Secret query',
      input: { type: 'null' },
      read: () => 'hidden',
    }),
  },
})

async function openTestSession() {
  const device = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  const host = await createPeerIdentity()
  const key = crypto.getRandomValues(new Uint8Array(32))
  const applicationId = 'ab'.repeat(32)
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({
    applicationId,
    historyId: 'pipe-test-history',
    profile: 'peer-generation-v1',
    policy: 'eligible-members-v1',
    controlPublicKey: host.publicKey,
    schemaAdministrator: device.identity.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition),
    schemaDigest: null,
  }, host)
  const control = await signControlRevision({
    applicationId,
    profile: 'peer-generation-v1',
    policy: 'eligible-members-v1',
    revision: 0,
    previous: null,
    epoch: 0,
    keyDigest: await bytesDigest(key),
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
  return openPeerApplication({ device, definition, authority: await registry.read(), epochKeys: new Map([[0, key]]) })
}

describe('peer-session central pipe extensions', () => {
  it('createLiveView observes initial coherent reads and updates on commands', async () => {
    const session = await openTestSession()
    try {
      const seen: unknown[] = []
      const view = createLiveView(session, {
        query: 'notes',
        input: null,
        onSnapshot: snap => { seen.push(snap.value) },
      })
      const initial = await view.ready({ timeoutMs: 5000 })
      expect(initial.value).toEqual([])
      const op = await session.command('addNote', { text: 'hello' }, { operationId: 'op-1' })
      await op.applied()
      await expect.poll(() => view.snapshot?.value).toEqual([{ text: 'hello' }])
      expect(seen.at(-1)).toEqual([{ text: 'hello' }])
      view.close()
    } finally {
      await session.close()
    }
  })

  it('forwardSessionEvents pumps topic batches and saves checkpoints only after delivery', async () => {
    const session = await openTestSession()
    try {
      const delivered: unknown[] = []
      let savedCursor: string | undefined
      const stop = new AbortController()
      const pump = forwardSessionEvents({
        session,
        topics: ['note'],
        checkpoint: {
          load: () => savedCursor,
          save: cursor => { savedCursor = cursor; if (delivered.length >= 2) stop.abort() },
        },
        project: event => event.payload,
        deliver: async payload => { delivered.push(payload) },
        signal: stop.signal,
      })
      await (await session.command('addNote', { text: 'one' }, { operationId: 'ev-1' })).applied()
      await (await session.command('adminNote', 'ignored', { operationId: 'ev-admin' })).applied()
      await (await session.command('addNote', { text: 'two' }, { operationId: 'ev-2' })).applied()
      await pump.catch(() => undefined)
      expect(delivered).toEqual([{ text: 'one' }, { text: 'two' }])
      expect(typeof savedCursor).toBe('string')
    } finally {
      await session.close()
    }
  })

  it('createScopedApplicationTools enforces allowed operations, generation pin, and attaches operationReference', async () => {
    const session = await openTestSession()
    try {
      const scoped = createScopedApplicationTools(session, { queries: ['notes'], commands: ['addNote'] })
      await expect(scoped.execute({ kind: 'query', name: 'secret', input: null })).rejects.toThrow('APPLICATION_TOOL_NOT_ALLOWED')
      await expect(scoped.execute({ kind: 'command', name: 'adminNote', input: 'x', operationId: 'a' })).rejects.toThrow('APPLICATION_TOOL_NOT_ALLOWED')
      await expect(scoped.execute({ kind: 'query', name: 'notes', input: null, generation: '0'.repeat(64) })).rejects.toThrow('APPLICATION_TOOL_GENERATION_CHANGED')

      const written = await scoped.execute({
        kind: 'command',
        name: 'addNote',
        input: { text: 'scoped' },
        operationId: 'scoped-1',
        generation: session.status.generation,
      }) as { operationReference: { applicationId: string; historyId: string; author: string; operationId: string } }
      expect(written.operationReference).toMatchObject({
        applicationId: session.applicationId,
        historyId: session.historyId,
        author: session.deviceId,
        operationId: 'scoped-1',
      })
      for (const kind of ['operation', 'retry', 'wait'] as const) {
        const own = await scoped.execute({ kind, name: 'addNote', operationId: 'scoped-1' }) as { operationReference: { author: string; attemptId: string } }
        expect(own.operationReference.author).toBe(session.deviceId)
        expect(own.operationReference.attemptId).toMatch(/^[0-9a-f]{64}$/u)
      }
      const read = await scoped.execute({ kind: 'query', name: 'notes', input: null, generation: session.status.generation }) as { value: unknown }
      expect(read.value).toEqual([{ text: 'scoped' }])
    } finally {
      await session.close()
    }
  })

  it('cannot use an allowed label to inspect, retry, wait for or reapply a forbidden command', async () => {
    const session = await openTestSession()
    try {
      await (await session.command('adminNote', 'private', { operationId: 'admin-op' })).applied()
      const scoped = createScopedApplicationTools(session, { commands: ['addNote'] })
      for (const kind of ['operation', 'retry', 'wait', 'reapply'] as const) {
        await expect(scoped.execute({ kind, name: 'addNote', operationId: kind === 'reapply' ? 'replacement' : 'admin-op',
          originalOperationId: 'admin-op', input: { text: 'forged label' } })).rejects.toThrow('APPLICATION_TOOL_NOT_ALLOWED')
      }
      expect(await session.operations.get('replacement')).toBeNull()
    } finally { await session.close() }
  })

  it('preserves every supported journal operation ID through saved commands, inspection and retry', async () => {
    const session = await openTestSession()
    try {
      const scoped = createScopedApplicationTools(session, { commands: ['addNote'] })
      for (const id of ['invoice#42', 'a'.repeat(201), 'b'.repeat(512), 'job 42 🧪']) {
        const written = await scoped.execute({ kind: 'command', name: 'addNote', input: { text: id }, operationId: id }) as { operationReference: { operationId: string; attemptId: string } }
        expect(written.operationReference.operationId).toBe(id)
        await session.operations.wait(id)
        for (const kind of ['operation', 'retry', 'wait'] as const) {
          const result = await scoped.execute({ kind, name: 'addNote', operationId: id }) as typeof written
          expect(result.operationReference.operationId).toBe(id)
          expect(result.operationReference.attemptId).toBe(written.operationReference.attemptId)
        }
      }
    } finally { await session.close() }
  })

  it('createViewStore and operationReference isolate views and reject conflicting retained intents', () => {
    const data = new Map<string, string>()
    const storage = {
      get length() { return data.size },
      key: (index: number) => [...data.keys()][index] ?? null,
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => { data.set(key, value) },
      removeItem: (key: string) => { data.delete(key) },
    }
    const signer = 'a'.repeat(64)
    const ref = operationReference({ applicationId: 'app', historyId: 'hist', deviceId: signer }, 'op-1')
    const storeA = createViewStore<{ text: string }>({ storage, applicationId: 'app', historyId: 'hist', profileId: 'p', viewId: 'a' })
    const storeB = createViewStore<{ text: string }>({ storage, applicationId: 'app', historyId: 'hist', profileId: 'p', viewId: 'b' })
    storeA.writeDraft({ text: 'draft-a' })
    storeB.writeDraft({ text: 'draft-b' })
    expect(storeA.readDraft()).toEqual({ text: 'draft-a' })
    storeA.retainOperation(ref, { text: 'v1' })
    expect(() => storeA.retainOperation(ref, { text: 'v2' })).toThrow(SessionError)
    expect(storeB.pending()).toEqual([])
    expect(storeB.pending({ allViews: true })).toHaveLength(1)
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}')
  })
})

import { describe, expect, it } from 'vitest'
import { MemoryBytesStore, writeBytesMany } from '@chronolog/records'
import { SignalChannel, generateSignalIdentity } from '@chronolog/signals'
import {
  assertCompatibleDefinitionEvolution, bytesDigest, createGenerationRegistry,
  createPeerIdentity, participantGrant, peerDigest, signApplicationDescriptor,
  signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation/control'
import {
  applicationDefinitionDigest, bytesToHex, defineApplication, defineCommand,
  defineQuery, describeApplication, emit, eventExecutionManifest, executionManifestArtifacts,
  openApplicationDevice, openPeerApplication, program,
} from './index.js'

describe('Chronolog evolution, compaction, and live-signal ergonomics', () => {
  it('supports atomic putMany on BytesStore', async () => {
    const store = new MemoryBytesStore()
    await writeBytesMany(store, [
      { key: 'a', value: new Uint8Array([1, 2]) },
      { key: 'b', value: new Uint8Array([3, 4, 5]) },
    ])
    expect(await store.get('a')).toEqual(new Uint8Array([1, 2]))
    expect(await store.get('b')).toEqual(new Uint8Array([3, 4, 5]))
  })

  it('delivers fresh retained latest signals to late-joining subscribers', async () => {
    const id = await generateSignalIdentity()
    let now = 10_000
    const channel = new SignalChannel({
      scope: 'dash-app',
      identity: id,
      authorize: () => true,
      localEcho: true,
      now: () => now,
    })
    await channel.send('feed/cpu', { pct: 42 }, { ttlMs: 10_000 })
    await channel.send('feed/cpu', { pct: 55 }, { ttlMs: 10_000 })
    await channel.send('feed/temp', { c: 21 }, { ttlMs: 1_000 })
    now += 2_000 // feed/temp expired, feed/cpu still fresh

    const sub = channel.subscribe({
      topics: ['feed/cpu', 'feed/temp'],
      mode: 'latest',
      includeLatest: true,
      signal: AbortSignal.timeout(2_000),
    })[Symbol.asyncIterator]()
    const first = await sub.next()
    expect(first.done).toBe(false)
    expect(first.value?.topic).toBe('feed/cpu')
    expect(first.value?.payload).toEqual({ pct: 55 })
    await sub.return?.()
    channel.close()
  })

  it('evolves application definitions via signed control revision without changing applicationId', async () => {
    const controlKey = await createPeerIdentity()
    const store = new MemoryBytesStore()
    const device = await openApplicationDevice({ store, create: true })
    const epochKey = crypto.getRandomValues(new Uint8Array(32))
    const applicationId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
    const execution = await executionManifestArtifacts(await eventExecutionManifest())

    const v1 = defineApplication({
      id: 'dashboard',
      version: '1',
      commands: {
        addNote: defineCommand({
          description: 'Add a note',
          input: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
          prepare: ({ text }) => program(emit('note', { text })),
        }),
      },
      queries: {
        notes: defineQuery({
          description: 'Read notes',
          input: { type: 'null' },
          read(view: { readEvents: (o?: { topics?: string[]; limit?: number }) => { events: Array<{ payload: { text: string } }> } }) {
            return view.readEvents({ topics: ['note'], limit: 128 }).events.map(e => e.payload.text)
          },
        }),
      },
    })

    const v2 = defineApplication({
      id: 'dashboard',
      version: '2',
      commands: {
        ...v1.commands,
        pinMetric: defineCommand({
          description: 'Pin a metric snapshot',
          input: { type: 'object', properties: { name: { type: 'string' }, value: { type: 'number' } }, required: ['name', 'value'] },
          prepare: ({ name, value }) => program(emit('metric', { name, value })),
        }),
      },
      queries: {
        ...v1.queries,
        metrics: defineQuery({
          description: 'Read metrics',
          input: { type: 'null' },
          read(view: { readEvents: (o?: { topics?: string[]; limit?: number }) => { events: Array<{ payload: { name: string; value: number } }> } }) {
            return view.readEvents({ topics: ['metric'], limit: 128 }).events.map(e => e.payload)
          },
        }),
      },
    })

    assertCompatibleDefinitionEvolution(describeApplication(v1), describeApplication(v2))
    const v1Digest = await applicationDefinitionDigest(v1)
    const v2Digest = await applicationDefinitionDigest(v2)
    expect(v1Digest).not.toBe(v2Digest)

    const descriptor = await signApplicationDescriptor({
      applicationId,
      historyId: 'hist-evolve',
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      controlPublicKey: controlKey.publicKey,
      schemaAdministrator: device.identity.publicKey,
      executionManifestDigest: bytesToHex(execution.executionManifestDigest),
      definitionDigest: v1Digest,
      schemaDigest: null,
    }, controlKey)

    const control0 = await signControlRevision({
      applicationId,
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      revision: 0,
      previous: null,
      epoch: 0,
      keyDigest: await bytesDigest(epochKey),
      grants: [participantGrant(device.identity.publicKey, { administrator: true, publisher: true })],
      recoveryFloor: null,
    }, controlKey)

    const registry = await createGenerationRegistry({
      store: new MemoryBytesStore(),
      descriptor,
      controls: [control0],
      signer: controlKey,
    })

    const createReq = await signTransitionRequest({
      applicationId,
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      transitionId: 'create-1',
      expectedGeneration: null,
      coordinator: device.identity.publicKey,
      requester: device.identity.publicKey,
      controlRevision: 0,
      reason: 'create',
      base: null,
    }, device.identity)
    const gen0 = await registry.select(createReq)

    const session1 = await openPeerApplication({
      device,
      definition: v1,
      authority: await registry.read(),
      epochKeys: new Map([[0, epochKey]]),
    })
    const op1 = await session1.command('addNote', { text: 'hello v1' }, { operationId: 'op-1' })
    expect((await op1.applied()).outcome).toBe('accepted')
    const base = await session1.recoveryPoint()

    // Evolve definition to v2 via signed control revision 1
    const control1 = await signControlRevision({
      applicationId,
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      revision: 1,
      previous: await peerDigest(control0),
      epoch: 0,
      keyDigest: await bytesDigest(epochKey),
      grants: control0.payload.grants,
      recoveryFloor: null,
      definitionDigest: v2Digest,
    }, controlKey)

    const evolveReq = await signTransitionRequest({
      applicationId,
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      transitionId: 'evolve-2',
      expectedGeneration: gen0.id,
      coordinator: device.identity.publicKey,
      requester: device.identity.publicKey,
      controlRevision: 1,
      reason: 'control-change',
      base,
    }, device.identity)
    await registry.select(evolveReq, { control: control1 })
    const authority2 = await registry.read()
    await session1.close()

    // Reopen same applicationId with v2 definition from the exact same retained device store!
    const device2 = await openApplicationDevice({ store })
    const session2 = await openPeerApplication({
      device: device2,
      definition: v2,
      authority: authority2,
      epochKeys: new Map([[0, epochKey]]),
    })
    // Historical v1 event survived and verified cleanly!
    expect((await session2.query('notes', null)).value).toEqual(['hello v1'])
    // New v2 command works on the exact same applicationId!
    const op2 = await session2.command('pinMetric', { name: 'cpu', value: 12 }, { operationId: 'op-2' })
    expect((await op2.applied()).outcome).toBe('accepted')
    expect((await session2.query('metrics', null)).value).toEqual([{ name: 'cpu', value: 12 }])
    await session2.close()
  })

  it('compacts history with summarize and reopens cleanly past maxRecords', async () => {
    const controlKey = await createPeerIdentity()
    const store = new MemoryBytesStore()
    const device = await openApplicationDevice({ store, create: true })
    const epochKey = crypto.getRandomValues(new Uint8Array(32))
    const applicationId = bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
    const execution = await executionManifestArtifacts(await eventExecutionManifest())

    const app = defineApplication({
      id: 'compacting-log',
      version: '1',
      commands: {
        tick: defineCommand({
          description: 'Record a value',
          input: { type: 'object', properties: { n: { type: 'integer' } }, required: ['n'] },
          prepare: ({ n }) => program(emit('tick', { n })),
        }),
      },
      queries: {
        all: defineQuery({
          description: 'Read ticks and summaries',
          input: { type: 'null' },
          read(view: { readEvents: (o?: { limit?: number }) => { events: Array<{ topic: string; payload: Record<string, unknown> }> } }) {
            return view.readEvents({ limit: 128 }).events.map(e => ({ topic: e.topic, payload: e.payload }))
          },
        }),
      },
    })

    const descriptor = await signApplicationDescriptor({
      applicationId,
      historyId: 'hist-compact',
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      controlPublicKey: controlKey.publicKey,
      schemaAdministrator: device.identity.publicKey,
      executionManifestDigest: bytesToHex(execution.executionManifestDigest),
      definitionDigest: await applicationDefinitionDigest(app),
      schemaDigest: null,
    }, controlKey)

    const control0 = await signControlRevision({
      applicationId,
      profile: 'peer-generation-v1',
      policy: 'eligible-members-v1',
      revision: 0,
      previous: null,
      epoch: 0,
      keyDigest: await bytesDigest(epochKey),
      grants: [participantGrant(device.identity.publicKey, { administrator: true })],
      recoveryFloor: null,
    }, controlKey)

    const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control0], signer: controlKey })
    const createReq = await signTransitionRequest({
      applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      transitionId: 'create-compact', expectedGeneration: null, coordinator: device.identity.publicKey,
      requester: device.identity.publicKey, controlRevision: 0, reason: 'create', base: null,
    }, device.identity)
    await registry.select(createReq)
    const authority = await registry.read()

    // Deliberately tight maxRecords=12 to prove compaction reclaims quota!
    const session = await openPeerApplication({
      device, definition: app, authority, epochKeys: new Map([[0, epochKey]]), maxRecords: 12,
    })
    for (let i = 1; i <= 10; i++) {
      const op = await session.command('tick', { n: i }, { operationId: `tick-${i}` })
      expect((await op.applied()).outcome).toBe('accepted')
    }
    const result = await session.compact({
      keepTail: 2,
      operationId: 'compact-summary-1',
      summarize: events => {
        const sum = events.reduce((acc, e) => acc + Number((e.payload as { n?: number }).n ?? 0), 0)
        return program(emit('summary', { count: events.length, sum }))
      },
    })
    expect(result.compactedRecords).toBe(8)
    expect(result.retainedRecords).toBe(3) // 2 tail ticks + 1 summary command
    expect(result.reclaimedKeys).toBeGreaterThan(0)

    // Write 6 more commands (total 17 > maxRecords=12!) — succeeds because quota was reclaimed!
    for (let i = 11; i <= 16; i++) {
      const op = await session.command('tick', { n: i }, { operationId: `tick-${i}` })
      expect((await op.applied()).outcome).toBe('accepted')
    }
    await session.close()

    // Reopen from the same compacted store and verify clean load!
    const reopenedDevice = await openApplicationDevice({ store })
    const reopened = await openPeerApplication({
      device: reopenedDevice, definition: app, authority, epochKeys: new Map([[0, epochKey]]), maxRecords: 12,
    })
    const rows = (await reopened.query('all', null)).value
    expect(rows.some(r => r.topic === 'summary' && r.payload.sum === 55)).toBe(true)
    expect(rows.some(r => r.topic === 'tick' && r.payload.n === 16)).toBe(true)
    expect(rows.length).toBe(9) // 2 tail + 1 summary + 6 new ticks
    await reopened.close()
  })
})

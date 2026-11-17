import { afterEach, describe, expect, it } from 'vitest'
import { frameLivePeerStream, framePeerStream } from '@chronolog/agent-service/framing'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PeerIdentity, type PrefixProof } from '@chronolog/peer-generation'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import type { FramedPeerConnection } from '@chronolog/records'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import { connectApplicationTransport } from './network.js'
import { openPeerApplication } from './runtime.js'
import { connectApplications, type ApplicationReadView, type ApplicationSession } from './session.js'

const definition = defineApplication({ id: 'network-messages', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture() {
  const host = await createPeerIdentity(), devices = await Promise.all([0, 1, 2].map(() => openApplicationDevice({ store: new MemoryPeerStore(), create: true })))
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '81'.repeat(32), historyId: 'network-test', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: devices[0]!.identity.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.map((device, index) => participantGrant(device.identity.publicKey, { administrator: index === 0 })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(devices[0]!.identity, null, 'create')
  const open = async (index: number) => {
    const app = await openPeerApplication({ device: devices[index]!, authority: await registry.read(), definition, epochKeys })
    cleanup.push(() => app.close()); return app
  }
  return { devices, open, select, registry }
}

function pair(): readonly [FramedPeerConnection, FramedPeerConnection] {
  const a = new TransformStream<Uint8Array>(), b = new TransformStream<Uint8Array>(), liveA = new TransformStream<Uint8Array>(), liveB = new TransformStream<Uint8Array>()
  const left = framePeerStream({ readable: a.readable, writable: b.writable }), right = framePeerStream({ readable: b.readable, writable: a.writable })
  const leftLive = frameLivePeerStream({ readable: liveA.readable, writable: liveB.writable }), rightLive = frameLivePeerStream({ readable: liveB.readable, writable: liveA.writable })
  return [
    { ...left, live: leftLive, close: async () => { await Promise.all([left.close(), leftLive.close()]) } },
    { ...right, live: rightLive, close: async () => { await Promise.all([right.close(), rightLive.close()]) } },
  ]
}

async function connect(a: ApplicationSession, b: ApplicationSession) {
  const channels = pair()
  const links = await Promise.all([
    connectApplicationTransport(a, { connection: channels[0], expectedPeerId: b.deviceId, timeoutMs: 5000 }),
    connectApplicationTransport(b, { connection: channels[1], expectedPeerId: a.deviceId, timeoutMs: 5000 }),
  ])
  cleanup.push(() => links[0].close(), () => links[1].close())
  return links
}

describe('authenticated application transport', () => {
  it('owns ordered delivery, signed independent live traffic and durable retained acknowledgements', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const [left, right] = await connect(a, b)
    expect([left.peerId, right.peerId]).toEqual([b.deviceId, a.deviceId])
    const operation = await b.command('say', 'over bytes', { operationId: 'once' })
    expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    await right.synchronize()
    expect(await operation.shared({ signal: AbortSignal.timeout(5000) })).toHaveLength(1)
    expect((await a.query('messages', null)).value.events[0]).toMatchObject({ author: b.deviceId, payload: { text: 'over bytes' } })
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), receiving = stream.next()
    const revision = a.revision
    await b.signals.send('typing', { active: true })
    expect((await receiving).value).toMatchObject({ authorId: b.deviceId, topic: 'typing', payload: { active: true } })
    expect(a.revision).toEqual(revision)
    await stream.return?.()
    expect(left.stats.receivedBytes).toBeGreaterThan(0)
    expect(right.stats.sentRequests).toBeGreaterThan(0)
    await left.close()
    expect(left.signal.aborted).toBe(true)
    await expect(b.signals.send('typing', { active: false })).rejects.toThrow()
  })

  it('does not accept a discovery hint for another authenticated signer', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    const results = await Promise.allSettled([
      connectApplicationTransport(a, { connection: channels[0], expectedPeerId: f.devices[2]!.identity.publicKey, timeoutMs: 1000 }),
      connectApplicationTransport(b, { connection: channels[1], expectedPeerId: a.deviceId, timeoutMs: 1000 }),
    ])
    expect(results.every(result => result.status === 'rejected')).toBe(true)
    expect(a.status.connectedPeers).toBe(0)
    expect(b.status.connectedPeers).toBe(0)
  })

  it('connects an empty peer to a selected retained prefix before exposing a ready view', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const original = await connect(a, b)
    await (await a.command('say', 'retained', { operationId: 'retained' })).applied()
    await original[1].synchronize()
    await Promise.all(original.map(link => link.close()))
    await f.select(f.devices[1]!.identity, await b.recoveryPoint(), 'move')
    await b.adopt(await f.registry.read())
    const c = await f.open(2)
    expect(c.status.phase).toBe('recovering')
    await expect(c.query('messages', null)).rejects.toThrow('PEER_RECOVERING')
    await connect(b, c)
    expect(c.status.phase).toBe('ready')
    expect((await c.query('messages', null)).value.events).toHaveLength(1)
    const oldLink = await connectApplications(a, c)
    cleanup.push(() => oldLink.close())
    expect(a.revision.generation).toBe(c.revision.generation)
  })

  it('resumes encrypted content over bounded peer chunks without changing application history', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const bytes = new Uint8Array(65_536 + 19).fill(43), upload = await a.content.stage({ bytes: bytes.length })
    await upload.write(0, bytes.slice(0, 65_536)); await upload.write(1, bytes.slice(65_536))
    const reference = await upload.commit(), revision = b.revision
    const first = await connect(a, b)
    const prefix: Uint8Array[] = []
    for await (const chunk of b.content.read(reference, { length: 65_536 })) prefix.push(chunk)
    expect(prefix).toEqual([bytes.slice(0, 65_536)])
    await Promise.all(first.map(link => link.close()))
    await expect(async () => { for await (const _chunk of b.content.read(reference)) { /* Complete content is required. */ } }).rejects.toThrow('CONTENT_UNAVAILABLE')
    await connect(a, b)
    await b.content.retain(reference)
    expect(await a.content.retention(reference)).toEqual([expect.objectContaining({ payload: expect.objectContaining({ peer: b.deviceId }) })])
    expect(b.revision).toEqual(revision)
    const copied: Uint8Array[] = []
    for await (const chunk of b.content.read(reference)) copied.push(chunk)
    expect(copied).toEqual([bytes.slice(0, 65_536), bytes.slice(65_536)])
  })
})

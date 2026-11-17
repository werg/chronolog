import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { frameLivePeerStream, framePeerStream } from '@chronolog/agent-service/framing'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  peerDigest, signApplicationDescriptor, signControlRevision, signTransitionRequest, type OrderedCommand, type PeerIdentity, type PeerRevision, type PrefixProof } from '@chronolog/peer-generation'
import { bytesToHex, DOMAINS, emit, executionManifestArtifacts, hexToBytes, program, transactionDigest, type TransactionCore } from '@chronolog/protocol'
import type { FramedPeerConnection } from '@chronolog/records'
import { createSignedAttempt } from '../../peer-generation/src/attempt.js'
import { encodePeerValue, signPeerValue } from '../../peer-generation/src/codec.js'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { sessionInternals } from './internals.js'
import { openNativeDevice } from './native.js'
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

async function fixture(initialMembers = [0, 1, 2]) {
  const directory = await mkdtemp(join(tmpdir(), 'peer-network-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const host = await createPeerIdentity(), devices = await Promise.all([0, 1, 2].map(index => openNativeDevice({ path: join(directory, `${index}.sqlite`), create: true })))
  for (const device of devices) cleanup.push(() => device.close())
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '81'.repeat(32), historyId: 'network-test', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: devices[0]!.identity.publicKey,
    executionManifestDigest: bytesToHex(manifest.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.filter((_device, index) => initialMembers.includes(index)).map((device, index) => participantGrant(device.identity.publicKey, { administrator: index === 0 })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(devices[0]!.identity, null, 'create')
  const open = async (index: number, seedKeys = true) => {
    const app = await openPeerApplication({ device: devices[index]!, authority: await registry.read(), definition, ...(seedKeys ? { epochKeys } : {}) })
    cleanup.push(() => app.close()); return app
  }
  return { devices, open, select, registry, host, descriptor, control, key, directory }
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

async function connect(a: ApplicationSession, b: ApplicationSession, channels = pair()) {
  const links = await Promise.all([
    connectApplicationTransport(a, { connection: channels[0], expectedPeerId: b.deviceId, timeoutMs: 5000 }),
    connectApplicationTransport(b, { connection: channels[1], expectedPeerId: a.deviceId, timeoutMs: 5000 }),
  ])
  cleanup.push(() => links[0].close(), () => links[1].close())
  return links
}

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(yes => { resolve = yes })
  return { promise, resolve }
}
function packet(frame: Uint8Array): { readonly type: string; readonly method?: string; readonly value?: { readonly limit: number }; readonly result?: { readonly authority?: unknown } | readonly OrderedCommand[] | null } {
  return JSON.parse(new TextDecoder().decode(frame)) as ReturnType<typeof packet>
}

async function seed(session: ApplicationSession, count: number, key: Uint8Array): Promise<void> {
  const replica = sessionInternals.get(session)!.replica, descriptor = replica.descriptor, generation = replica.generation
  const control = replica.authority.controls[generation.payload.controlRevision]!
  const membershipRevision = hexToBytes(await peerDigest(control)), validationPolicy = hexToBytes(await peerDigest([descriptor.profile, descriptor.policy]))
  let root = replica.revision.point.root
  const commands: OrderedCommand[] = []
  for (let offset = 0; offset < count; offset += 32) {
    const attempts = await Promise.all(Array.from({ length: Math.min(32, count - offset) }, async (_, position) => {
      const index = offset + position
      const core: TransactionCore = { operationId: `bulk-${index}`, groupId: hexToBytes(descriptor.applicationId),
        membershipRevision, validationPolicy, authorId: hexToBytes(replica.device.publicKey), authorTimestampMs: BigInt(index),
        nonce: crypto.getRandomValues(new Uint8Array(16)), executionManifestDigest: hexToBytes(descriptor.executionManifestDigest),
        program: program(emit('message', { index })) }
      return createSignedAttempt({ applicationId: descriptor.applicationId, profile: descriptor.profile, generation: generation.id,
        controlRevision: control.payload.revision, epoch: control.payload.epoch, author: replica.device.publicKey,
        operationId: core.operationId, definitionDigest: descriptor.definitionDigest, command: 'say', commandVersion: '1',
        basedOn: null, reapplyOf: null, coreDigest: bytesToHex(await transactionDigest(core)) }, core, key, replica.device)
    }))
    const receipts: Array<Promise<OrderedCommand>> = []
    for (const [position, attempt] of attempts.entries()) {
      const body = encodePeerValue(attempt)
      const payload = { applicationId: descriptor.applicationId, profile: descriptor.profile,
        generation: generation.id, sequence: offset + position + 1, previousRoot: root, attemptId: attempt.id,
        author: attempt.payload.header.author, operationId: attempt.payload.header.operationId,
        bodyHash: await bytesDigest(body), bodyBytes: body.length }
      const receiptRoot = await peerDigest([DOMAINS.peerOrder, payload]); root = receiptRoot
      receipts.push(signPeerValue(DOMAINS.peerOrder, payload, replica.device).then(receipt => ({ attempt, receipt: { ...receipt, root: receiptRoot } })))
    }
    commands.push(...await Promise.all(receipts))
  }
  // Fixture signing is bounded and parallel; production import still verifies
  // every body and receipt and publishes through the real event materializer.
  await replica.synchronize(replica.authority, commands)
}

describe('authenticated application transport', () => {
  it('learns signed controls from a newly granted reader before authentication and supplies its inherited prefix', async () => {
    const f = await fixture([0, 1]), a = await f.open(0)
    await (await a.command('say', 'surviving prefix', { operationId: 'before-grant' })).applied()
    const before = await f.registry.read(), previous = before.controls[0]!
    const control = await signControlRevision({ ...previous.payload, revision: 1, previous: await peerDigest(previous),
      grants: [...previous.payload.grants, participantGrant(f.devices[2]!.identity.publicKey)] }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: before.generations.at(-1)!.id, coordinator: a.deviceId, requester: a.deviceId,
      controlRevision: 1, base: await a.recoveryPoint(), transitionId: 'enroll-reader', reason: 'control-change' }, f.devices[0]!.identity), { control })
    const c = await f.open(2, false)
    expect(a.status.generation).not.toBe(c.status.generation)
    expect(c.status.phase).toBe('awaiting-keys')
    await connect(a, c)
    expect(a.status.generation).toBe(c.status.generation)
    expect(c.status.phase).toBe('ready')
    expect((await c.query('messages', null)).value.events).toHaveLength(1)
    const operation = await c.command('say', 'newly enrolled', { operationId: 'after-grant' })
    expect(await operation.applied({ signal: AbortSignal.timeout(5000) })).toMatchObject({ status: 'applied', author: c.deviceId })
  })

  it('enrolls a reader without application-managed epoch keys and reopens its durable keys and history', async () => {
    const f = await fixture(), a = await f.open(0)
    await (await a.command('say', 'before enrollment', { operationId: 'retained' })).applied()
    const b = await f.open(1, false), phases: string[] = []
    cleanup.push(b.onStatus(status => { phases.push(status.phase) }))
    expect(b.status.phase).toBe('awaiting-keys')
    expect(b.keys.missing()).toEqual([0])
    const links = await connect(a, b)
    expect(b.keys.missing()).toEqual([])
    expect(b.status.phase).toBe('ready')
    expect((await b.query('messages', null)).value.events).toHaveLength(1)
    const operation = await b.command('say', 'after enrollment', { operationId: 'enrolled' })
    await operation.applied({ signal: AbortSignal.timeout(5000) })
    await links[1].synchronize()
    const identity = b.deviceId
    await b.close()
    const device = await openNativeDevice({ path: join(f.directory, '1.sqlite') })
    const reopened = await openPeerApplication({ device, authority: await f.registry.read(), definition })
    cleanup.push(() => reopened.close())
    expect(reopened.deviceId).toBe(identity)
    expect(reopened.keys.missing()).toEqual([])
    expect((await reopened.query('messages', null)).value.events).toHaveLength(2)
    expect(await reopened.operations.get('enrolled')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(phases[0]).toBe('awaiting-keys')
    expect(phases).toContain('ready')
  })

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

  it.each(['current', 'previous'] as const)('hydrates an empty peer from the %s generation without restoring an excluded suffix or old controls', async sourceGeneration => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const original = await connect(a, b)
    await (await a.command('say', 'retained', { operationId: 'retained' })).applied()
    await original[1].synchronize()
    const base = await b.recoveryPoint(), retained = await a.operations.inspect('retained')
    for (const operationId of ['tail-one', 'tail-two']) await (await a.command('say', 'excluded', { operationId })).applied()
    await original[1].synchronize()
    const excluded = await b.operations.inspect('tail-two', { author: a.deviceId })
    expect((await b.query('messages', null)).value.events).toHaveLength(3)
    await Promise.all(original.map(link => link.close()))

    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      grants: f.control.payload.grants.map(grant => grant.publicKey === a.deviceId ? { ...grant, writer: false } : grant) }, f.host)
    const generation = await f.registry.select(await signTransitionRequest({ applicationId: f.descriptor.payload.applicationId,
      profile: f.descriptor.payload.profile, policy: f.descriptor.payload.policy, expectedGeneration: base.point.generation,
      coordinator: b.deviceId, requester: a.deviceId, controlRevision: 1, base, transitionId: 'move', reason: 'control-change',
    }, f.devices[0]!.identity), { control })
    if (sourceGeneration === 'current') await b.adopt(await f.registry.read())
    const c = await f.open(2)
    expect(c.status.phase).toBe('recovering')
    await expect(c.query('messages', null)).rejects.toThrow('PEER_RECOVERING')
    const links = await connect(b, c)
    await Promise.all(links.map(link => link.synchronize()))
    expect(c.status.phase).toBe('ready')
    expect(c.revision).toMatchObject({ generation: generation.id, controlRevision: 1 })
    expect(b.revision).toMatchObject({ generation: generation.id, controlRevision: 1 })
    expect((await c.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['retained'])
    expect((await b.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['retained'])
    expect((await c.operations.inspect('retained', { author: a.deviceId }))?.attempt).toEqual(retained?.attempt)
    expect(await b.operations.inspect('tail-two', { author: a.deviceId })).toMatchObject({
      state: { status: 'abandoned', selectedGeneration: generation.id }, attempt: excluded?.attempt,
    })

    const oldLink = await connectApplications(a, c)
    cleanup.push(() => oldLink.close())
    expect(a.revision.generation).toBe(c.revision.generation)
    await expect(a.command('say', 'revoked writer', { operationId: 'forbidden' })).rejects.toThrow('PEER_AUTHOR_FORBIDDEN')
    const next = await c.command('say', 'after recovery', { operationId: 'after' })
    expect((await next.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    await Promise.all(links.map(link => link.synchronize()))
    expect((await c.operations.inspect('after'))?.attempt.payload.header.controlRevision).toBe(1)
    expect((await b.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['retained', 'after'])
    expect((await next.shared({ signal: AbortSignal.timeout(5000) })).some(value => value.payload.peer === b.deviceId && value.payload.generation === generation.id)).toBe(true)
    expect(links.every(link => !link.signal.aborted)).toBe(true)
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

  it('completes a captured synchronization before a later source change finishes', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    await (await a.command('say', 'captured', { operationId: 'captured' })).applied()
    let enabled = false, states = 0
    const nextState = deferred(), release = deferred()
    const left: FramedPeerConnection = { ...channels[0], async send(frame, options) {
      const value = packet(frame)
      if (enabled && value.type === 'response' && value.result !== undefined && value.result !== null && 'authority' in value.result) {
        states++
        if (states === 1) await (await a.command('say', 'later', { operationId: 'later' })).applied()
        else if (states === 2) { nextState.resolve(); await release.promise }
      }
      await channels[0].send(frame, options)
    } }
    const links = await connect(a, b, [left, channels[1]])
    await Promise.all(links.map(link => link.synchronize()))
    enabled = true
    let completed = false
    const first = links[1].synchronize().then(() => { completed = true })
    try {
      await nextState.promise
      expect(completed, 'new hints must not extend the promise for an earlier captured target').toBe(true)
      expect((await b.query('messages', null)).value.events).toHaveLength(1)
    } finally { release.resolve(); await first }
    await links[1].synchronize()
    expect((await b.query('messages', null)).value.events).toHaveLength(2)
  })

  it('retires a live lane at EOF while keeping reliable command replication usable', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    const left: FramedPeerConnection = { ...channels[0], live: { ...channels[0].live!,
      async *frames() { yield* [] },
    } }
    const links = await connect(a, b, [left, channels[1]])
    await expect(a.signals.send('typing', { active: true })).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    expect(links.every(link => !link.signal.aborted)).toBe(true)
    const operation = await b.command('say', 'after live EOF', { operationId: 'after-eof' })
    expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    await links[1].synchronize()
    expect((await a.query('messages', null)).value.events[0]?.payload).toEqual({ text: 'after live EOF' })
  })

  it('refuses live congestion without retiring the authenticated peer or retrying the refused frame', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    let congested = true, dispatched = 0
    const right: FramedPeerConnection = { ...channels[1], live: { ...channels[1].live!,
      async trySend(frame, options) {
        if (congested) return false
        dispatched++
        return channels[1].live!.trySend(frame, options)
      },
    } }
    const links = await connect(a, b, [channels[0], right])
    await expect(b.signals.send('typing', { active: true })).rejects.toThrow('SIGNAL_BACKPRESSURE')
    expect(dispatched).toBe(0)
    expect(links.every(link => !link.signal.aborted)).toBe(true)
    congested = false
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), receiving = stream.next()
    await b.signals.send('typing', { active: false })
    expect((await receiving).value?.payload).toEqual({ active: false })
    await stream.return?.()
    expect(dispatched).toBe(1)
    expect((await (await b.command('say', 'healthy', { operationId: 'after-pressure' })).applied()).outcome).toBe('accepted')
  })

  it('retires the physical owner when a dispatched live write ignores cancellation', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    const entered = deferred(), release = deferred(), controller = new AbortController()
    const right: FramedPeerConnection = { ...channels[1], live: { ...channels[1].live!,
      async trySend() { entered.resolve(); await release.promise; return true },
    } }
    const links = await connect(a, b, [channels[0], right])
    const failure = new Error('cancel the live attempt')
    const sending = b.signals.send('typing', { active: true }, { signal: controller.signal })
    const rejected = expect(sending).rejects.toBe(failure)
    try {
      await entered.promise; controller.abort(failure)
      await rejected
      await expect.poll(() => links[1].signal.aborted).toBe(true)
      expect(channels[1].signal.aborted).toBe(true)
    } finally { release.resolve() }
  })

  it('closes the previous physical connection when the same authenticated peer reconnects', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    const previous = await connect(a, b), replacement = await connect(a, b)
    expect(previous.every(link => link.signal.aborted)).toBe(true)
    expect(replacement.every(link => !link.signal.aborted)).toBe(true)
    expect(a.status.connectedPeers).toBe(1)
    expect(b.status.connectedPeers).toBe(1)
    const operation = await b.command('say', 'replacement', { operationId: 'replacement' })
    expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
  })

  it('fully verifies a captured 65-command history in three bounded pages', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1)
    await seed(a, 65, f.key)
    const channels = pair(), pageSizes: number[] = [], responseBytes: number[] = []
    const left: FramedPeerConnection = { ...channels[0], async send(frame, options) {
      const value = packet(frame)
      if (value.type === 'response' && Array.isArray(value.result)) { pageSizes.push(value.result.length); responseBytes.push(frame.length) }
      await channels[0].send(frame, options)
    } }
    await connect(a, b, [left, channels[1]])
    expect(b.revision.point).toEqual(a.revision.point)
    expect(b.revision.point.sequence).toBe(65)
    expect(pageSizes).toEqual([32, 32, 1])
    expect(Math.max(...pageSizes)).toBeLessThanOrEqual(32)
    expect(Math.max(...responseBytes)).toBeLessThanOrEqual(1_048_576)
    expect(await b.operations.get('bulk-64', { author: a.deviceId })).toMatchObject({ status: 'applied', outcome: 'accepted' })
  })

  it('bounds fetching from an authenticated over-quota history advertisement and cancels before retention', async () => {
    const f = await fixture(), a = await f.open(0), b = await f.open(1), channels = pair()
    const requested = deferred(), release = deferred(), controller = new AbortController()
    let limit: number | undefined
    const left: FramedPeerConnection = { ...channels[0], async send(frame, options) {
      const value = packet(frame)
      if (value.type === 'response' && value.result !== undefined && value.result !== null && 'authority' in value.result) {
        const state = value.result as { readonly revision: PeerRevision }
        // An authenticated advertisement is not retained evidence or permission
        // to exceed the 4096-record storage ceiling. Stop before a page arrives;
        // the real 65-command case checks completed transfer within that quota.
        const result = { ...value.result, count: 4097, revision: { ...state.revision,
          point: { ...state.revision.point, sequence: 4097 } } }
        frame = new TextEncoder().encode(JSON.stringify({ ...value, result }))
      }
      await channels[0].send(frame, options)
    } }
    const right: FramedPeerConnection = { ...channels[1], async send(frame, options) {
      const value = packet(frame)
      if (value.type === 'request' && value.method === 'range') {
        limit = value.value?.limit; requested.resolve(); await release.promise
      }
      await channels[1].send(frame, options)
    } }
    const opening = Promise.allSettled([
      connectApplicationTransport(a, { connection: left, expectedPeerId: b.deviceId, timeoutMs: 5000 }),
      connectApplicationTransport(b, { connection: right, expectedPeerId: a.deviceId, timeoutMs: 5000, signal: controller.signal }),
    ])
    try {
      await Promise.race([requested.promise, opening.then(() => { throw new Error('Expected bounded range fetch before closure') })])
      expect(limit).toBe(32)
      controller.abort(new Error('cancel before a retained page'))
      const results = await opening
      expect(results[1]).toMatchObject({ status: 'rejected', reason: expect.objectContaining({ message: 'cancel before a retained page' }) })
      expect(b.revision.point.sequence).toBe(0)
    } finally {
      controller.abort(); release.resolve()
      await Promise.all(channels.map(channel => channel.close()))
      await opening
    }
  })

})

import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, controlParticipantGrant, createGenerationRegistry, createParticipantResponse, createPeerIdentity, decodePeerValue, encodePeerValue,
  MemoryBytesStore, participantGrant, peerDigest, signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type OrderedCommand, type ParticipantRequest,
} from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { assertCanonicalCbor, bytesToHex, emit, encodeCanonicalCbor, executionManifestArtifacts, program, type CborValue } from '@chronolog/protocol'
import { defineApplication, defineCommand, applicationDefinitionDigest } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication, type OpenPeerApplicationOptions } from './runtime.js'
import { createFramedPeerConnectionPair, type FramedPeerConnection } from './network.js'
import { observePeerWire, observePeerSignals } from './network.test-helpers.js'
import { ApplicationKeyring } from './keys.js'

const definition = defineApplication({ id: 'network', version: '1', commands: {
  say: defineCommand({ description: 'Say', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
  bulk: defineCommand({ description: 'Send a fragmented command', input: { type: 'string' },
    prepare: text => program(...Array.from({ length: 8 }, (_, index) => emit('chunk', { index, text }))) }),
}, queries: {} })
const closing: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0).reverse()) await close() })
async function fixture(options: { readerOnly?: boolean; relay?: true; localEcho?: boolean } = {}) {
  const host = await createPeerIdentity(), account = await createPeerIdentity(), a = await openApplicationDevice({ store: new MemoryBytesStore(), create: true }),
    b = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: 'cc'.repeat(32), historyId: 'network',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.identity.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [controlParticipantGrant(host.publicKey), participantGrant(a.identity.publicKey, { dataRole: 'admin' }),
      participantGrant(account.publicKey),
      { ...participantGrant(b.identity.publicKey, options.relay === true ? { relay: true } : {}), ...(options.readerOnly === true ? { writer: false, coordinator: false, recovery: false } : {}) }] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    coordinator: a.identity.publicKey, requester: a.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, a.identity))
  const openCold = async (device: typeof a, epochKeys = keys, createMaterializer?: OpenPeerApplicationOptions['createMaterializer']) => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys,
      ...(options.localEcho === undefined ? {} : { signals: { localEcho: options.localEcho } }),
      ...(createMaterializer === undefined ? {} : { createMaterializer }) })
    closing.push(() => session.close()); return session
  }
  const open = async (...args: Parameters<typeof openCold>) => {
    const session = await openCold(...args)
    await session.keys.missing(); return session
  }
  return { a, b, host, account, keys, descriptor, control, registry, open, openCold }
}

/** The public handshake remains visible to an untrusted relay. */
function rewrite(connection: FramedPeerConnection, change: (value: Record<string, unknown>) => unknown): FramedPeerConnection {
  return { ...connection, async send(bytes, options) {
    let frame
    try { frame = assertCanonicalCbor(bytes) } catch { await connection.send(bytes, options); return }
    if (Array.isArray(frame) && frame.length === 5 && frame[2] === 0n && frame[4] instanceof Uint8Array && frame[3] === BigInt(frame[4].length)) {
      const value = decodePeerValue<Record<string, unknown>>(frame[4]), encoded = encodePeerValue(change(value))
      await connection.send(encodeCanonicalCbor([frame[0]!, frame[1]!, 0n, BigInt(encoded.length), encoded]), options)
    } else await connection.send(bytes, options)
  } }
}

function rewriteParticipant(connection: FramedPeerConnection, identity: string, change: (value: Record<string, unknown>) => unknown): FramedPeerConnection {
  observePeerWire(identity, value => change(value) as typeof value)
  return connection
}

describe('authenticated peer application connections', () => {
  it('keeps reliable replication and later signals alive after signed clock and expiry rejects', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    let mode: 'future' | 'expired' | 'valid' = 'future'
    observePeerSignals(b.deviceId, async bytes => {
      if (mode === 'valid') return bytes
      const frame = assertCanonicalCbor(bytes) as CborValue[], now = Date.now()
      frame[7] = BigInt(mode === 'future' ? now + 10_000 : now - 2000)
      frame[8] = frame[7] + 1000n
      frame[frame.length - 1] = new Uint8Array(await crypto.subtle.sign('Ed25519', f.b.identity.privateKey,
        encodeCanonicalCbor(frame.slice(0, -1)).slice().buffer))
      return encodeCanonicalCbor(frame)
    })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), incoming = stream.next()
    await b.signals.send('typing', 'future')
    await expect.poll(() => links[0].stats.signalRejections?.clockSkew).toBe(1)
    mode = 'expired'; await b.signals.send('typing', 'expired')
    await expect.poll(() => links[0].stats.signalRejections?.expired).toBe(1)
    expect(links.every(link => !link.signal.aborted)).toBe(true)
    const work = await b.command('say', 'durable work after clock skew', { operationId: 'after-clock-skew' })
    await work.applied({ signal: AbortSignal.timeout(5000) }); await links[0].synchronize()
    const view = await a.readView()
    try { expect(view.readEvents().events.map(event => event.payload)).toContainEqual({ text: 'durable work after clock skew' }) }
    finally { view.release() }
    mode = 'valid'; const valid = await b.signals.send('typing', 'fresh')
    expect((await incoming).value).toEqual(valid); await stream.return?.()
    expect(links[0].stats.signalRejections).toEqual({ total: 2, clockSkew: 1, expired: 1, unauthorized: 0, duplicate: 0, capacity: 0 })
    expect(links.every(link => !link.signal.aborted)).toBe(true)
  })

  it.each(['signature', 'timestamp'] as const)('retains fatal live-frame policy for invalid %s after clock rejection isolation', async fault => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    observePeerSignals(b.deviceId, bytes => {
      const frame = assertCanonicalCbor(bytes) as CborValue[]
      if (fault === 'timestamp') frame[8] = frame[7]!
      else { const signature = (frame.at(-1) as Uint8Array).slice(); signature[0] = signature[0]! ^ 1; frame[frame.length - 1] = signature }
      return encodeCanonicalCbor(frame)
    })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await b.signals.send('typing', 'invalid')
    await expect.poll(() => links[0].signal.aborted).toBe(true)
    expect(links[0].signal.reason).toMatchObject({ code: fault === 'signature' ? 'SIGNAL_SIGNATURE_INVALID' : 'SIGNAL_CLOCK_INVALID' })
    expect(a.signal.aborted).toBe(false)
  })

  it.each(['suffix', 'bundle'] as const)('exchanges authority using %s mode for peers sharing a verified head', async authorityExchange => {
    const f = await fixture(), a = await f.openCold(f.a), b = await f.openCold(f.b)
    const hello: unknown[] = [], states: unknown[] = []
    const [left, right] = createFramedPeerConnectionPair()
    const observed = rewrite(left, packet => { if (packet.kind === 'hello') hello.push((packet.value as { authority: unknown }).authority); return packet })
    observePeerWire(a.deviceId, packet => { if (packet.kind === 'response' && packet.message?.action === 'state') states.push((packet.message.payload as { authority: unknown }).authority) })
    const links = await Promise.all([a.connectPeer({ connection: observed, authorityExchange }), b.connectPeer({ connection: right, authorityExchange })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    expect(hello).toEqual([expect.objectContaining(authorityExchange === 'suffix' ? { format: 'authority-summary-v1', controls: 1, generations: 1 } : { controls: expect.any(Array), generations: expect.any(Array) })])
    expect(states.length).toBeGreaterThan(0)
    const expected = authorityExchange === 'suffix' ? 0 : 1
    expect(states.every(state => (state as { controls: unknown[]; generations: unknown[] }).controls.length === expected && (state as { generations: unknown[] }).generations.length === expected)).toBe(true)
  })

  it('preserves a submitted command and its pending reply across authenticated replacement without duplicating history', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    let entered!: () => void, release!: () => void, hold = false
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    observePeerWire(a.deviceId, async packet => {
      if (hold && packet.kind === 'response' && packet.message?.action === 'submit') {
        hold = false; entered(); await gate
      }
    })
    const connect = async () => {
      const [left, right] = createFramedPeerConnectionPair()
      const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
      closing.push(async () => { await Promise.all(links.map(link => link.close())) })
      await Promise.all(links.map(link => link.synchronize())); return links
    }
    const old = await connect(); hold = true
    const operation = await b.command('say', 'pending handover', { operationId: 'handover' })
    await started
    try {
      const fresh = await connect()
      expect(old.every(link => !link.signal.aborted)).toBe(true)
      expect([a.status.connectedPeers, b.status.connectedPeers]).toEqual([1, 1])
      release()
      expect((await operation.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
      await Promise.all(fresh.map(link => link.synchronize()))
      for (const session of [a, b]) {
        const view = await session.readView()
        expect(view.readEvents().events.map(event => event.payload)).toEqual([{ text: 'pending handover' }]); view.release()
      }
      expect(await b.operations.get('handover')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    } finally { release() }
  })

  it('keeps shared replication alive when a local-echo caller aborts during asynchronous live encryption', async () => {
    const f = await fixture({ localEcho: true }), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair(), frames: Uint8Array[] = []
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: { ...right,
      live: { ...right.live!, async trySend(frame, options) { frames.push(frame); return right.live!.trySend(frame, options) } },
    } })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    let entered!: () => void, release!: () => void, finished!: () => void, hold = true
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve }),
      encrypted = new Promise<void>(resolve => { finished = resolve })
    const actualEncrypt = crypto.subtle.encrypt.bind(crypto.subtle)
    const encryption = vi.spyOn(crypto.subtle, 'encrypt').mockImplementation((algorithm, key, data) => {
      const result = actualEncrypt(algorithm, key, data)
      const aad = typeof algorithm === 'object' && 'additionalData' in algorithm ? algorithm.additionalData : undefined
      // Execute real WebCrypto, then control its asynchronous completion. Only
      // this live lane is held; encrypted reliable RPC remains independent.
      if (hold && aad instanceof ArrayBuffer && new Uint8Array(aad)[1] === 2) {
        hold = false; entered()
        return result.then(async value => { await gate; finished(); return value })
      }
      return result
    })
    const reviewer = new AbortController(), reason = new Error('reviewer finished after local progress')
    const turn = async (): Promise<void> => new Promise(resolve => { setTimeout(resolve, 0) })
    try {
      const echoed = await b.signals.send('progress', { runId: 'reviewer', completed: 1 }, { signal: reviewer.signal, ttlMs: 5000 })
      expect(echoed.payload).toEqual({ runId: 'reviewer', completed: 1 }); await started
      reviewer.abort(reason); await turn(); await turn()
      expect(links.map(link => link.signal.reason)).toEqual([undefined, undefined])
      expect(frames).toHaveLength(0)
      const sibling = await b.command('say', 'sibling durable work survives a reviewer cancellation', { operationId: 'after-reviewer-abort' })
      await sibling.applied({ signal: AbortSignal.timeout(5000) }); await links[0].synchronize()
      const view = await a.readView()
      expect(view.readEvents().events.map(event => event.payload)).toContainEqual({ text: 'sibling durable work survives a reviewer cancellation' })
      view.release()
      release(); await encrypted; await turn()
      expect(frames).toHaveLength(0)
      const observations = a.signals.subscribe({ topics: ['progress'], signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = observations.next()
      const fresh = await b.signals.send('progress', { runId: 'sibling', completed: 1 })
      expect((await received).value).toEqual(fresh); await observations.return?.()
      expect(frames).toHaveLength(1); expect(links.every(link => !link.signal.aborted)).toBe(true)
    } finally { release(); encryption.mockRestore() }
  })

  it('preserves the actual live transport retirement reason without closing the application session', async () => {
    const f = await fixture({ localEcho: true }), a = await f.openCold(f.a), b = await f.openCold(f.b)
    const [left, right] = createFramedPeerConnectionPair(), failure = new Error('physical live dispatch failed')
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: { ...right,
      live: { ...right.live!, async trySend() { throw failure } },
    } })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await b.signals.send('progress', { completed: 1 })
    await expect.poll(() => links[1].signal.aborted).toBe(true)
    expect(links[1].signal.reason).toBe(failure)
    expect(a.signal.aborted).toBe(false); expect(b.signal.aborted).toBe(false)
  })

  it('keeps authentication, state and live traffic cold, then adds data on the same connection only after local demand', async () => {
    const f = await fixture(), openA = vi.fn(() => f.a.openStorage()), openB = vi.fn(() => f.b.openStorage())
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold({ ...f.b, openStorage: openB })
    const states: unknown[] = [], requests: ParticipantRequest[] = []
    for (const session of [a, b]) observePeerWire(session.deviceId, value => {
      if (value.kind === 'request' && value.message !== undefined) requests.push(value.message)
      if (value.kind === 'response' && value.message?.action === 'state') states.push(value.message.payload)
    })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = stream.next()
    const signal = await b.signals.send('typing', { active: true })
    expect((await received).value).toEqual(signal); await stream.return?.()
    expect(states.length).toBeGreaterThan(0)
    expect(states.every(value => value !== null && typeof value === 'object' && 'data' in value && value.data === false &&
      'point' in value && value.point === null && 'revision' in value && value.revision === null)).toBe(true)
    expect(requests.every(value => value.facet === 'control' && value.action === 'state')).toBe(true)
    expect([a.status.database, b.status.database]).toEqual(['idle', 'idle'])
    expect(links.map(link => link.data)).toEqual(['idle', 'idle'])
    expect([a.revision, b.revision]).toEqual([null, null])
    expect(openA).not.toHaveBeenCalled(); expect(openB).not.toHaveBeenCalled()

    await (await a.command('say', 'local data demand', { operationId: 'first' })).applied()
    await Promise.all(links.map(link => link.synchronize()))
    expect(openA).toHaveBeenCalledTimes(1); expect(openB).not.toHaveBeenCalled()
    expect(links.map(link => link.data)).toEqual(['idle', 'active'])
    expect(b.status.database).toBe('idle'); expect(b.revision).toBeNull()
    const [view] = await Promise.all([b.readView(), b.operations.get('first', { author: a.deviceId })]); view.release()
    await Promise.all(links.map(link => link.synchronize()))
    expect(openB).toHaveBeenCalledTimes(1)
    const populated = await b.readView()
    expect(populated.readEvents().events).toHaveLength(1); populated.release()
    expect(links.every(link => !link.signal.aborted)).toBe(true)
    expect(links.map(link => link.data)).toEqual(['active', 'active'])
    expect([a.status.connectedPeers, b.status.connectedPeers]).toEqual([1, 1])
  })

  it('lets actual follower demand activate its selected cold coordinator once without reconnecting', async () => {
    const f = await fixture(), openA = vi.fn(() => f.a.openStorage()), openB = vi.fn(() => f.b.openStorage())
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold({ ...f.b, openStorage: openB })
    const opens: ParticipantRequest[] = []
    observePeerWire(b.deviceId, value => { if (value.kind === 'request' && value.message?.action === 'open') opens.push(value.message) })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    expect(openA).not.toHaveBeenCalled(); expect(openB).not.toHaveBeenCalled()
    const operation = await b.command('say', 'coordinator service', { operationId: 'first' })
    await operation.applied({ signal: AbortSignal.timeout(5000) })
    await links[1].synchronize()
    expect(opens).toHaveLength(1)
    expect(openA).toHaveBeenCalledTimes(1); expect(openB).toHaveBeenCalledTimes(1)
    expect(await b.operations.get('first')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(links.every(link => !link.signal.aborted)).toBe(true)
  })

  it('isolates failed coordinator storage from its authenticated control and live connection without retrying acquisition', async () => {
    const f = await fixture(), failure = new Error('STORAGE_DENIED'), openA = vi.fn(async () => { throw failure })
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    expect(openA).not.toHaveBeenCalled()
    const view = await b.readView(); view.release()
    await expect(links[1].synchronize()).rejects.toThrow('APPLICATION_DATA_UNAVAILABLE')
    expect(links[1].data).toBe('unavailable')
    expect(a.status.database).toBe('failed'); expect(a.revision).toBeNull()
    await expect(a.readView()).rejects.toBe(failure)
    await expect(a.readView()).rejects.toBe(failure)
    await links[0].synchronize()
    const stream = a.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = stream.next()
    const sent = await b.signals.send('typing', { active: true })
    expect((await received).value).toEqual(sent); await stream.return?.()
    expect(links.every(link => !link.signal.aborted)).toBe(true)
    expect(openA).toHaveBeenCalledTimes(1)
  })

  it('retires a failed active database and its waiters while keeping authority and live traffic on the same connection', async () => {
    const f = await fixture(), runtime = await createEventMaterializationRuntime({ store: f.a.store, namespace: f.descriptor.payload.historyId })
    const released = vi.fn(), closeRuntime = vi.fn(() => runtime.close())
    const openStorage = vi.fn(async () => {
      const resource = await f.a.openStorage()
      return { store: resource.store, async close() { released(); await resource.close() } }
    })
    const createMaterializer = vi.fn(() => ({ ...runtime, close: closeRuntime }))
    const a = await f.open({ ...f.a, openStorage }, f.keys, createMaterializer), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize()))
    const view = await a.readView()
    let entered!: () => void, release!: () => void
    const materializing = new Promise<void>(resolve => { entered = resolve }), blocked = new Promise<void>(resolve => { release = resolve })
    const materialize = vi.spyOn(runtime.coordinator, 'materialize').mockImplementationOnce(async () => {
      entered(); await blocked; throw new Error('ENGINE_FAILED')
    })
    try {
      const operation = await a.command('say', 'saved before the engine failed', { operationId: 'engine-failed' })
      const checked = expect(operation.applied({ signal: AbortSignal.timeout(5000) })).rejects.toThrow('APPLICATION_DATA_UNAVAILABLE')
      await materializing; await new Promise(resolve => setTimeout(resolve, 0)); release()
      await checked
      await expect.poll(() => released.mock.calls.length).toBe(1)
      expect(closeRuntime).toHaveBeenCalledTimes(1)
      expect(a.status.database).toBe('failed'); expect(a.revision).toBeNull(); expect(a.signal.aborted).toBe(false)
      expect(() => view.readEvents()).toThrow('APPLICATION_VIEW_RELEASED')
      await expect(a.readView()).rejects.toThrow('APPLICATION_DATA_UNAVAILABLE')
      expect(links.every(link => !link.signal.aborted)).toBe(true)
      await expect(links[1].synchronize()).rejects.toThrow('APPLICATION_DATA_UNAVAILABLE')
      await links[0].synchronize()
      const control = a.connectControlParticipant({ exchange: async request => createParticipantResponse(request, await f.registry.read()) })
      expect((await control.application()).descriptor).toEqual(f.descriptor)
      const stream = b.signals.subscribe({ signal: AbortSignal.timeout(5000) })[Symbol.asyncIterator](), received = stream.next()
      const sent = await a.signals.send('typing', { active: true })
      expect((await received).value).toEqual(sent); await stream.return?.()
      expect(links.every(link => !link.signal.aborted)).toBe(true)
      expect(createMaterializer).toHaveBeenCalledTimes(1); expect(openStorage).toHaveBeenCalledTimes(1)
      let reentered: Promise<void> | undefined
      a.onStatus(status => { if (status.phase === 'closed') reentered = a.close() })
      const closing = a.close()
      expect(reentered).toBe(closing); await closing
      expect(closeRuntime).toHaveBeenCalledTimes(1); expect(released).toHaveBeenCalledTimes(1)
    } finally { release(); materialize.mockRestore(); view.release() }
  })

  it('rejects an invalid advertised data prefix even while both participants remain cold', async () => {
    const f = await fixture(), openA = vi.fn(() => f.a.openStorage()), openB = vi.fn(() => f.b.openStorage())
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold({ ...f.b, openStorage: openB })
    let inject = false
    observePeerWire(a.deviceId, value => {
      const message = value.message
      if (inject && value.kind === 'response' && message?.action === 'state') return { ...value,
        message: { ...message, payload: { ...message.payload as object, data: true,
          point: { generation: '00'.repeat(32), sequence: 0, root: '00'.repeat(32) } } } }
    })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize())); inject = true
    await expect(links[1].synchronize()).rejects.toThrow('APPLICATION_NETWORK_CURSOR_INVALID')
    // Explicit synchronization fences invalid input before returning its error;
    // correctness cannot depend on a coincident background hint sharing the pull.
    expect(links[1].signal.aborted).toBe(true)
    expect(openA).not.toHaveBeenCalled(); expect(openB).not.toHaveBeenCalled()
  })

  it.each([
    ['database', 'open', 'PEER_NOT_COORDINATOR'],
    ['control', 'keyShare', 'APPLICATION_DATA_NOT_ACTIVE'],
  ] as const)('does not let an unsolicited %s/%s request activate a cold follower', async (facet, action, code) => {
    const f = await fixture(), openB = vi.fn(() => f.b.openStorage())
    const a = await f.openCold(f.a), b = await f.openCold({ ...f.b, openStorage: openB }), responses: unknown[] = []
    let inject = false
    observePeerWire(a.deviceId, value => inject && value.kind === 'request' && value.message?.action === 'state'
      ? { ...value, message: { ...value.message, facet, action, payload: null } } : value)
    observePeerWire(b.deviceId, value => { if (value.kind === 'response') responses.push(value.message?.payload) })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize())); inject = true
    await expect(links[0].synchronize()).rejects.toThrow('PEER_PARTICIPANT_RESPONSE_MISMATCH')
    expect(responses).toContain(code)
    expect(openB).not.toHaveBeenCalled(); expect(b.status.database).toBe('idle')
  })

  it('checks writer authority before an unsolicited submit can activate a cold coordinator', async () => {
    const f = await fixture({ readerOnly: true }), openA = vi.fn(() => f.a.openStorage())
    const a = await f.openCold({ ...f.a, openStorage: openA }), b = await f.openCold(f.b), responses: unknown[] = []
    let inject = false
    observePeerWire(b.deviceId, value => inject && value.kind === 'request' && value.message?.action === 'state'
      ? { ...value, message: { ...value.message, facet: 'database', action: 'submit', payload: { payload: { header: { author: b.deviceId } } } } } : value)
    observePeerWire(a.deviceId, value => { if (value.kind === 'response') responses.push(value.message?.payload) })
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    await Promise.all(links.map(link => link.synchronize())); inject = true
    await expect(links[1].synchronize()).rejects.toThrow('PEER_PARTICIPANT_RESPONSE_MISMATCH')
    expect(responses).toContain('PEER_AUTHOR_FORBIDDEN')
    expect(openA).not.toHaveBeenCalled(); expect(a.status.database).toBe('idle')
  })

  it('resumes an independently signed account write on a relay and keeps operation IDs separate by author', async () => {
    const f = await fixture({ relay: true }), a = await f.open(f.a), offline = await f.open(f.b)
    const input = program(emit('message', { text: 'account write' }))
    const operation = await offline.submitProgramAs(input, f.account, { operationId: 'same-id' })
    const saved = await offline.operations.inspect('same-id', { author: f.account.publicKey })
    expect(saved?.attempt.payload.header.author).toBe(f.account.publicKey)
    await offline.command('say', 'device write', { operationId: 'same-id' })
    await offline.close()

    await expect(a.submitProgramAs(input, f.account, { operationId: 'same-id' })).rejects.toThrow('PEER_AUTHOR_FORBIDDEN')
    const b = await f.open(await openApplicationDevice({ store: f.b.store })), [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    const resumed = await b.submitProgramAs(input, f.account, { operationId: 'same-id' })
    await resumed.applied({ signal: AbortSignal.timeout(5000) })
    await b.operations.wait('same-id', { signal: AbortSignal.timeout(5000) })
    expect(await b.operations.inspect('same-id', { author: f.account.publicKey })).toMatchObject({ attempt: saved?.attempt })
    expect(await a.operations.inspect('same-id', { author: f.account.publicKey })).toMatchObject({
      attempt: saved?.attempt, state: { status: 'applied', outcome: 'accepted' },
    })
    expect(await a.operations.get('same-id', { author: b.deviceId })).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(operation.author).toBe(f.account.publicKey)
    const view = await a.readView()
    try { expect(view.readEvents().events.map(event => event.author)).toEqual(expect.arrayContaining([f.account.publicKey, b.deviceId])) }
    finally { view.release() }
  })

  it('routes original saved commands, fragmented ciphertext, exact coverage and live signals over separate lanes', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const operation = await b.command('bulk', 'private payload '.repeat(500), { operationId: 'fragmented' })
    const saved = await b.operations.inspect('fragmented')
    const [left, right] = createFramedPeerConnectionPair(), sizes: number[] = [], reliableText: string[] = [], liveText: string[] = []
    const counted = { ...right, async send(bytes: Uint8Array, options?: { signal?: AbortSignal }) {
      sizes.push(bytes.length); reliableText.push(new TextDecoder().decode(bytes)); await right.send(bytes, options)
    }, live: { ...right.live!, async trySend(bytes: Uint8Array, options?: { signal?: AbortSignal }) {
      liveText.push(new TextDecoder().decode(bytes)); return right.live!.trySend(bytes, options)
    } } }
    const links = await Promise.all([a.connectPeer({ connection: left, peerIdentity: b.deviceId }),
      b.connectPeer({ connection: counted, peerIdentity: a.deviceId })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    expect(links.map(link => link.peerId)).toEqual([b.deviceId, a.deviceId])
    expect(await operation.applied({ signal: AbortSignal.timeout(5000) })).toMatchObject({ status: 'applied', outcome: 'accepted' })
    await Promise.all(links.map(link => link.synchronize()))
    expect((await b.operations.inspect('fragmented'))?.attempt).toEqual(saved?.attempt)
    expect(sizes.length).toBeGreaterThan(4)
    expect(Math.max(...sizes)).toBeLessThan(50_000)
    expect(reliableText.join('')).not.toContain('private payload')
    const view = await a.readView()
    expect(view.readEvents().events).toHaveLength(8); view.release()
    expect(await operation.shared({ signal: AbortSignal.timeout(5000) })).toHaveLength(1)
    const subscription = a.signals.subscribe({ topics: ['typing'] })[Symbol.asyncIterator](), received = subscription.next()
    const sent = await b.signals.send('typing', { active: true, cursor: 'private live marker' })
    expect((await received).value).toEqual(sent)
    expect(liveText).toHaveLength(1); expect(liveText[0]).not.toContain('private live marker')
    expect(reliableText.join('')).not.toContain('requestId')
    await subscription.return?.()
    await b.close()
    expect(links[0].signal.aborted).toBe(true); expect(links[1].signal.aborted).toBe(true)
    expect(a.status.connectedPeers).toBe(0)
  })

  it('requires a fresh signed proof from the advertised reader identity', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const forged = rewrite(right, value => value.kind === 'proof' ? { ...value, signature: '00'.repeat(64) } : value)
    const results = await Promise.allSettled([a.connectPeer({ connection: left }), b.connectPeer({ connection: forged })])
    expect(results[0]).toMatchObject({ status: 'rejected', reason: new Error('APPLICATION_PEER_PROOF_INVALID') })
    for (const result of results) if (result.status === 'fulfilled') await result.value.close()
    expect(a.status.connectedPeers).toBe(0)
    expect(left.signal.aborted).toBe(true)
  })

  it.each(['suite', 'receiver key', 'encapsulation'] as const)('rejects a relay substituting the handshake %s', async fault => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const forged = rewrite(right, value => {
      if (value.kind === 'proof' && fault === 'encapsulation') return { ...value, encapsulatedKey: '11'.repeat(32) }
      if (value.kind !== 'hello' || fault === 'encapsulation') return value
      const hello = value.value as { readonly channel: object }
      return { ...value, value: { ...hello, channel: { ...hello.channel,
        ...(fault === 'suite' ? { suite: 'plaintext' } : { receiverKey: '22'.repeat(32) }) } } }
    })
    const results = await Promise.allSettled([a.connectPeer({ connection: left }), b.connectPeer({ connection: forged })])
    expect(results.some(result => result.status === 'rejected')).toBe(true)
    for (const result of results) if (result.status === 'fulfilled') await result.value.close()
    expect(a.status.connectedPeers).toBe(0); expect(b.status.connectedPeers).toBe(0)
    expect(left.signal.aborted).toBe(true)
  })

  it.each(['tamper', 'replay', 'plaintext'] as const)('retires the authenticated owner when a relay attempts %s', async fault => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    let inject = false
    const hostile: FramedPeerConnection = { ...left, async send(frame, options) {
      if (!inject) return left.send(frame, options)
      const changed = frame.slice()
      if (fault === 'tamper') changed[changed.length - 1]! ^= 1
      if (fault === 'plaintext') changed[0] = 0x85
      await left.send(changed, options)
      if (fault === 'replay') await left.send(changed, options)
    } }
    const links = await Promise.all([a.connectPeer({ connection: hostile }), b.connectPeer({ connection: right })])
    await Promise.all(links.map(link => link.synchronize()))
    const revision = b.revision; inject = true
    await expect(links[1].synchronize()).rejects.toThrow(/^APPLICATION_CHANNEL_/u)
    expect(b.revision).toEqual(revision); expect(links[1].signal.aborted).toBe(true)
    expect(left.signal.aborted).toBe(true); expect(b.status.connectedPeers).toBe(0)
    await Promise.all(links.map(link => link.close()))
  })

  it.each([
    ['scope', 'APPLICATION_NETWORK_SCOPE_MISMATCH'],
    ['control action', 'PEER_PARTICIPANT_FACET_FORBIDDEN'],
    ['response interest', 'PEER_PARTICIPANT_RESPONSE_MISMATCH'],
    ['error payload', 'APPLICATION_NETWORK_RESPONSE_INVALID'],
  ])('fences a peer transport with a substituted %s before changing its view', async (fault, code) => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    let inject = false
    const malicious = rewriteParticipant(left, a.deviceId, value => {
      if (!inject || value.kind !== 'response') return value
      const message = value.message as ParticipantRequest
      if (fault === 'error payload') return { ...value, ok: false, message: { ...message, payload: null } }
      return { ...value, message: { ...message, ...(fault === 'scope' ? { applicationId: 'fe'.repeat(32) }
        : fault === 'control action' ? { facet: 'control', action: 'configure' } : { facet: 'database', action: 'coverage' }) } }
    })
    const links = await Promise.all([a.connectPeer({ connection: malicious }), b.connectPeer({ connection: right })])
    await Promise.all(links.map(link => link.synchronize()))
    const before = b.revision
    inject = true
    await expect(links[1].synchronize()).rejects.toThrow(code)
    expect(b.revision).toEqual(before)
    expect(links[1].signal.aborted).toBe(true)
    await Promise.all(links.map(link => link.close()))
  })

  it('bounds authentication even when the first transport write never completes', async () => {
    const f = await fixture(), a = await f.open(f.a), lifetime = new AbortController()
    const connection: FramedPeerConnection = { signal: lifetime.signal,
      send: () => new Promise<void>(() => {}), close: async () => { lifetime.abort(new Error('closed')) },
      frames: () => ({ [Symbol.asyncIterator]: () => ({ next: () => new Promise<IteratorResult<Uint8Array>>(() => {}) }) }),
    }
    await expect(a.connectPeer({ connection, handshakeTimeoutMs: 20 })).rejects.toThrow('APPLICATION_PEER_HANDSHAKE_TIMEOUT')
    expect(lifetime.signal.aborted).toBe(true); expect(a.status.connectedPeers).toBe(0)
  })

  it('keeps control ownership separate from reader and writer access', async () => {
    const f = await fixture({ readerOnly: true }), a = await f.open(f.a), b = await f.open(f.b)
    const hostStore = new MemoryBytesStore()
    const host = await f.openCold({ identity: f.host, storageId: 'control-only', store: hostStore, openStorage: async () => ({ store: hostStore, close() {} }), close: async () => {} })
    const [forbidden, unused] = createFramedPeerConnectionPair()
    await expect(host.connectPeer({ connection: forbidden, peerIdentity: a.deviceId })).rejects.toThrow('APPLICATION_PEER_NOT_AUTHORIZED')
    await unused.close()
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    await (await a.command('say', 'reader receives', { operationId: 'read-only' })).applied()
    await Promise.all(links.map(link => link.synchronize()))
    expect(await b.operations.get('read-only', { author: a.deviceId })).toMatchObject({ status: 'applied', outcome: 'accepted' })
    await expect(b.command('say', 'forbidden', { operationId: 'writer-required' })).rejects.toThrow('PEER_AUTHOR_FORBIDDEN')
    expect(links[1].signal.aborted).toBe(false)
    await Promise.all(links.map(link => link.close()))
  })

  it('rejects a transport that authenticates a different expected peer', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const results = await Promise.allSettled([a.connectPeer({ connection: left, peerIdentity: '11'.repeat(32) }), b.connectPeer({ connection: right })])
    expect(results[0]).toMatchObject({ status: 'rejected', reason: new Error('APPLICATION_NETWORK_SCOPE_MISMATCH') })
    for (const result of results) if (result.status === 'fulfilled') await result.value.close()
    expect(a.status.connectedPeers).toBe(0); expect(b.status.connectedPeers).toBe(0)
  })

  it.each(['overrun', 'root mismatch'])('rejects a signed page with %s against its fixed target before retaining any command', async fault => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await (await a.command('say', 'one', { operationId: 'one' })).applied()
    const one = a.revision!.point
    await (await a.command('say', 'two', { operationId: 'two' })).applied()
    // Obtain real ordered ciphertext from the owned store, not fabricated valid receipts.
    const commands: OrderedCommand[] = []
    for (let sequence = 1; sequence <= 2; sequence++) {
      const bytes = await f.a.store.get(`peer-generation/replica/${f.descriptor.payload.applicationId}/record/${a.revision!.generation}/${sequence}`)
      expect(bytes).not.toBeNull(); commands.push(decodePeerValue<OrderedCommand>(bytes!))
    }
    const [left, right] = createFramedPeerConnectionPair()
    const malicious = rewriteParticipant(left, a.deviceId, value => {
      if (value.kind !== 'response') return value
      const message = value.message as ParticipantRequest
      if (fault === 'root mismatch' && value.ok === false && message.payload === 'PEER_VIEW_RECOVERY_REQUIRED') {
        return { ...value, ok: true, message: { ...message, payload: commands.slice(0, 1) } }
      }
      if (value.ok !== true) return value
      const body = message.payload
      if (body !== null && typeof body === 'object' && 'authority' in body && 'revision' in body) {
        const point = fault === 'overrun' ? one : { ...one, root: 'ff'.repeat(32) }
        return { ...value, message: { ...message, payload: { ...body, point, revision: { ...body.revision as object, point } } } }
      }
      if (Array.isArray(body)) return { ...value, message: { ...message, payload: fault === 'overrun' ? commands : commands.slice(0, 1) } }
      return value
    })
    const links = await Promise.all([a.connectPeer({ connection: malicious }), b.connectPeer({ connection: right })])
    await expect(links[1].synchronize()).rejects.toThrow('APPLICATION_NETWORK_RANGE_INVALID')
    expect(await b.operations.get('one', { author: a.deviceId })).toBeNull()
    expect(await b.operations.get('two', { author: a.deviceId })).toBeNull()
    const view = await b.readView(); expect(view.readEvents().events).toHaveLength(0); view.release()
    await Promise.all(links.map(link => link.close()))
  })

  it('enrolls a verified reader with confidential key shares and reopens its durable keys', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b, new Map())
    await (await a.command('say', 'encrypted history', { operationId: 'secret' })).applied()
    const original = await a.operations.inspect('secret')
    const [left, right] = createFramedPeerConnectionPair(), wire: string[] = []
    const observed = { ...left, async send(bytes: Uint8Array, options?: { signal?: AbortSignal }) {
      wire.push(new TextDecoder().decode(bytes)); await left.send(bytes, options)
    } }
    const links = await Promise.all([a.connectPeer({ connection: observed }), b.connectPeer({ connection: right })])
    await links[1].synchronize()
    expect(await b.keys.missing()).toEqual([])
    expect(wire.join('')).not.toContain(bytesToHex(f.keys.get(0)!))
    expect((await b.operations.inspect('secret', { author: a.deviceId }))?.attempt).toEqual(original?.attempt)
    await Promise.all(links.map(link => link.close())); await b.close()
    const enrolled = await f.open(await openApplicationDevice({ store: f.b.store }), new Map())
    expect(await enrolled.keys.missing()).toEqual([])
    expect((await enrolled.operations.inspect('secret', { author: a.deviceId }))?.attempt).toEqual(original?.attempt)
  })

  it.each(['recipient', 'issuer'] as const)('binds the key-share %s to the authenticated peer', async field => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b, new Map())
    const [left, right] = createFramedPeerConnectionPair()
    const request = rewriteParticipant(right, b.deviceId, value => {
      const message = value.message as ParticipantRequest | undefined
      if (field !== 'recipient' || value.kind !== 'request' || message?.action !== 'keyShare') return value
      const envelope = message.payload as { readonly payload: object }
      return { ...value, message: { ...message, payload: { ...envelope, payload: { ...envelope.payload, recipient: a.deviceId } } } }
    })
    const response = rewriteParticipant(left, a.deviceId, value => {
      const message = value.message as ParticipantRequest | undefined
      const envelope = message?.payload as { readonly payload?: { readonly requestDigest?: string } } | null
      if (field !== 'issuer' || value.kind !== 'response' || envelope?.payload?.requestDigest === undefined) return value
      return { ...value, message: { ...message, payload: { ...envelope, payload: { ...envelope.payload, issuer: f.host.publicKey } } } }
    })
    const links = await Promise.all([a.connectPeer({ connection: response }), b.connectPeer({ connection: request })])
    await expect(links[1].synchronize()).rejects.toThrow(field === 'recipient' ? 'APPLICATION_KEY_REQUEST_INVALID' : 'APPLICATION_KEY_SHARE_INVALID')
    expect(await b.keys.missing()).toEqual([0])
    await Promise.all(links.map(link => link.close()))
  })

  it('keeps enrollment connected but cannot hand over to a retained peer until it holds the rotated key', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [originalLeft, originalRight] = createFramedPeerConnectionPair()
    const original = await Promise.all([a.connectPeer({ connection: originalLeft }), b.connectPeer({ connection: originalRight })])
    await (await a.command('say', 'retained before rotation', { operationId: 'retained' })).applied()
    await Promise.all(original.map(link => link.synchronize())); await Promise.all(original.map(link => link.close()))
    const key = crypto.getRandomValues(new Uint8Array(32))
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1,
      keyDigest: await bytesDigest(key) }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      transitionId: 'rotate', expectedGeneration: a.revision!.generation, requester: f.host.publicKey, coordinator: a.deviceId,
      controlRevision: 1, reason: 'control-change', base: await a.recoveryPoint() }, f.host), { control })
    const authority = await f.registry.read(); await a.adopt(authority); await b.adopt(authority)
    await a.keys.install(new Map([[1, key]]))
    expect(await b.keys.missing()).toEqual([1])
    const view = await b.readView()
    try { expect(view.readEvents().events).toHaveLength(1) } finally { view.release() }

    let entered!: () => void, release!: () => void
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    // Delay the resource, not a serialized reliable write that would also block state replies.
    // eslint-disable-next-line @typescript-eslint/unbound-method -- The spy invokes the original with its actual keyring.
    const offer = ApplicationKeyring.prototype.offer
    const delayed = vi.spyOn(ApplicationKeyring.prototype, 'offer').mockImplementation(async function (this: ApplicationKeyring, request) {
      if (request.payload.recipient === b.deviceId) { entered(); await gate }
      return offer.call(this, request)
    })
    const coverage: unknown[] = [], [left, right] = createFramedPeerConnectionPair()
    const observed = rewriteParticipant(right, b.deviceId, value => {
      const message = value.message as ParticipantRequest | undefined
      if (value.kind === 'response' && message?.action === 'coverage') coverage.push(message.payload)
      return value
    })
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: observed })])
    closing.push(async () => { await Promise.all(links.map(link => link.close())) })
    const receiving = links[1].synchronize()
    try {
      await started; await links[0].synchronize()
      expect(coverage).toContain(null)
      expect(links.every(link => !link.signal.aborted)).toBe(true)
      const host = { application: () => f.registry.read(), selectGeneration: (request: Parameters<typeof f.registry.select>[0]) => f.registry.select(request) }
      await expect(a.recovery.handover(host, { coordinator: b.deviceId, transitionId: 'after-key' })).rejects.toThrow('APPLICATION_HANDOVER_REQUIRES_RETAINED_PREFIX')
      expect(await a.recovery.inspect()).toEqual([])
      release(); await receiving; await links[0].synchronize()
      expect(await b.keys.missing()).toEqual([])
      expect(coverage.at(-1)).toMatchObject({ payload: { peer: b.deviceId, generation: a.revision!.generation, point: a.revision!.point } })
      await a.recovery.handover(host, { coordinator: b.deviceId, transitionId: 'after-key' })
      expect((await f.registry.read()).generations.at(-1)?.payload.coordinator).toBe(b.deviceId)
      expect((await a.recovery.inspect())[0]?.selected).toBe(a.revision!.generation)
    } finally { release(); delayed.mockRestore(); await receiving.catch(() => undefined) }
  })

  it('revokes an attached reader on the currently authenticated control transition', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    const links = await Promise.all([a.connectPeer({ connection: left }), b.connectPeer({ connection: right })])
    await Promise.all(links.map(link => link.synchronize()))
    const next = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control),
      epoch: 1, keyDigest: await bytesDigest(crypto.getRandomValues(new Uint8Array(32))),
      grants: f.control.payload.grants.filter(value => value.publicKey !== b.deviceId) }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: f.descriptor.payload.applicationId,
      profile: f.descriptor.payload.profile, policy: f.descriptor.payload.policy, transitionId: 'revoke', expectedGeneration: a.revision!.generation,
      coordinator: a.deviceId, requester: f.host.publicKey, controlRevision: 1, reason: 'control-change', base: await a.recoveryPoint() }, f.host), { control: next })
    await a.adopt(await f.registry.read())
    expect(links[0].signal.aborted).toBe(true)
    expect(a.status.connectedPeers).toBe(0)
    await Promise.all(links.map(link => link.close()))
  })
})

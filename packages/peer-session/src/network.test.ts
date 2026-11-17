import { afterEach, describe, expect, it } from 'vitest'
import {
  bytesDigest, controlParticipantGrant, createGenerationRegistry, createPeerIdentity, decodePeerValue, encodePeerValue,
  MemoryBytesStore, participantGrant, peerDigest, signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type OrderedCommand, type ParticipantRequest,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { assertCanonicalCbor, bytesToHex, emit, encodeCanonicalCbor, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, applicationDefinitionDigest } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { createFramedPeerConnectionPair, type FramedPeerConnection } from './network.js'

const definition = defineApplication({ id: 'network', version: '1', commands: {
  say: defineCommand({ description: 'Say', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
  bulk: defineCommand({ description: 'Send a fragmented command', input: { type: 'string' },
    prepare: text => program(...Array.from({ length: 8 }, (_, index) => emit('chunk', { index, text }))) }),
}, queries: {} })
const closing: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0).reverse()) await close() })
async function fixture(options: { readerOnly?: boolean } = {}) {
  const host = await createPeerIdentity(), a = await openApplicationDevice({ store: new MemoryBytesStore(), create: true }),
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
      { ...participantGrant(b.identity.publicKey), ...(options.readerOnly === true ? { writer: false, coordinator: false, recovery: false } : {}) }] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    coordinator: a.identity.publicKey, requester: a.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, a.identity))
  const open = async (device: typeof a, epochKeys = keys) => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys })
    closing.push(() => session.close()); return session
  }
  return { a, b, host, keys, descriptor, control, registry, open }
}

/** Fault injection at an existing single-fragment control response, preserving framing IDs. */
function rewrite(connection: FramedPeerConnection, change: (value: Record<string, unknown>) => unknown): FramedPeerConnection {
  return { ...connection, async send(bytes, options) {
    const frame = assertCanonicalCbor(bytes)
    if (Array.isArray(frame) && frame.length === 5 && frame[2] === 0n && frame[4] instanceof Uint8Array && frame[3] === BigInt(frame[4].length)) {
      const value = decodePeerValue<Record<string, unknown>>(frame[4]), encoded = encodePeerValue(change(value))
      await connection.send(encodeCanonicalCbor([frame[0]!, frame[1]!, 0n, BigInt(encoded.length), encoded]), options)
    } else await connection.send(bytes, options)
  } }
}

describe('authenticated peer application connections', () => {
  it('routes original saved commands, fragmented ciphertext, exact coverage and live signals over separate lanes', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const operation = await b.command('bulk', 'private payload '.repeat(500), { operationId: 'fragmented' })
    const saved = await b.operations.inspect('fragmented')
    const [left, right] = createFramedPeerConnectionPair(), sizes: number[] = [], reliableText: string[] = []
    const counted = { ...right, async send(bytes: Uint8Array, options?: { signal?: AbortSignal }) {
      sizes.push(bytes.length); reliableText.push(new TextDecoder().decode(bytes)); await right.send(bytes, options)
    } }
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
    const sent = await b.signals.send('typing', { active: true })
    expect((await received).value).toEqual(sent)
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

  it.each([
    ['scope', 'APPLICATION_NETWORK_SCOPE_MISMATCH'],
    ['control action', 'PEER_PARTICIPANT_FACET_FORBIDDEN'],
    ['response interest', 'PEER_PARTICIPANT_RESPONSE_MISMATCH'],
    ['error payload', 'APPLICATION_NETWORK_RESPONSE_INVALID'],
  ])('fences a peer transport with a substituted %s before changing its view', async (fault, code) => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const [left, right] = createFramedPeerConnectionPair()
    let inject = false
    const malicious = rewrite(left, value => {
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
    const host = await f.open({ identity: f.host, storageId: 'control-only', store: new MemoryBytesStore(), close: async () => {} })
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
    const one = a.revision.point
    await (await a.command('say', 'two', { operationId: 'two' })).applied()
    // Obtain real ordered ciphertext from the owned store, not fabricated valid receipts.
    const commands: OrderedCommand[] = []
    for (let sequence = 1; sequence <= 2; sequence++) {
      const bytes = await f.a.store.get(`peer-generation/replica/${f.descriptor.payload.applicationId}/record/${a.revision.generation}/${sequence}`)
      expect(bytes).not.toBeNull(); commands.push(decodePeerValue<OrderedCommand>(bytes!))
    }
    const [left, right] = createFramedPeerConnectionPair()
    const malicious = rewrite(left, value => {
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
    expect(b.keys.missing()).toEqual([])
    expect(wire.join('')).not.toContain(bytesToHex(f.keys.get(0)!))
    expect((await b.operations.inspect('secret', { author: a.deviceId }))?.attempt).toEqual(original?.attempt)
    await Promise.all(links.map(link => link.close())); await b.close()
    const enrolled = await f.open(await openApplicationDevice({ store: f.b.store }), new Map())
    expect(enrolled.keys.missing()).toEqual([])
    expect((await enrolled.operations.inspect('secret', { author: a.deviceId }))?.attempt).toEqual(original?.attempt)
  })

  it.each(['recipient', 'issuer'] as const)('binds the key-share %s to the authenticated peer', async field => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b, new Map())
    const [left, right] = createFramedPeerConnectionPair()
    const request = rewrite(right, value => {
      const message = value.message as ParticipantRequest | undefined
      if (field !== 'recipient' || value.kind !== 'request' || message?.action !== 'keyShare') return value
      const envelope = message.payload as { readonly payload: object }
      return { ...value, message: { ...message, payload: { ...envelope, payload: { ...envelope.payload, recipient: a.deviceId } } } }
    })
    const response = rewrite(left, value => {
      const message = value.message as ParticipantRequest | undefined
      const envelope = message?.payload as { readonly payload?: { readonly requestDigest?: string } } | null
      if (field !== 'issuer' || value.kind !== 'response' || envelope?.payload?.requestDigest === undefined) return value
      return { ...value, message: { ...message, payload: { ...envelope, payload: { ...envelope.payload, issuer: f.host.publicKey } } } }
    })
    const links = await Promise.all([a.connectPeer({ connection: response }), b.connectPeer({ connection: request })])
    await expect(links[1].synchronize()).rejects.toThrow(field === 'recipient' ? 'APPLICATION_KEY_REQUEST_INVALID' : 'APPLICATION_KEY_SHARE_INVALID')
    expect(b.keys.missing()).toEqual([0])
    await Promise.all(links.map(link => link.close()))
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
      profile: f.descriptor.payload.profile, policy: f.descriptor.payload.policy, transitionId: 'revoke', expectedGeneration: a.revision.generation,
      coordinator: a.deviceId, requester: f.host.publicKey, controlRevision: 1, reason: 'control-change', base: await a.recoveryPoint() }, f.host), { control: next })
    await a.adopt(await f.registry.read())
    expect(links[0].signal.aborted).toBe(true)
    expect(a.status.connectedPeers).toBe(0)
    await Promise.all(links.map(link => link.close()))
  })
})

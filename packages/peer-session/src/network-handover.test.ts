import { afterEach, describe, expect, it, vi } from 'vitest'
import { bytesToHex, hexToBytes, assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/protocol'
import { SignalChannel } from '@chronolog/signals'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, decodePeerValue, encodePeerValue, MemoryBytesStore,
  participantGrant, signApplicationDescriptor, signControlRevision, signTransitionRequest, verifyAuthorityBundle,
  type PeerIdentity,
} from '@chronolog/peer-generation'
import { connectApplicationPeer, connectedApplicationPeers, createFramedPeerConnectionPair,
  type ApplicationPeerConnectOptions, type ApplicationPeerLink, type ApplicationPeerPort, type FramedPeerConnection } from './network.js'
import { observePeerWire } from './network.test-helpers.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close(); vi.useRealTimers() })
function gate() {
  let release!: () => void
  const promise = new Promise<void>(resolve => { release = resolve })
  return { promise, release }
}
async function fixture() {
  const host = await createPeerIdentity(), a = await createPeerIdentity(), b = await createPeerIdentity()
  const descriptor = await signApplicationDescriptor({ applicationId: 'bb'.repeat(32), historyId: 'handover',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: 'cc'.repeat(32), definitionDigest: 'dd'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(new Uint8Array(32)), recoveryFloor: null,
    grants: [participantGrant(a.publicKey, { administrator: true }), participantGrant(b.publicKey)] }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'create', expectedGeneration: null, coordinator: a.publicKey,
    requester: a.publicKey, controlRevision: 0, reason: 'create', base: null }, a))
  const initial = await verifyAuthorityBundle(await registry.read())
  function port(device: PeerIdentity) {
    let authority = initial
    const lifetime = new AbortController(), listeners = new Set<() => void>(), attachments = new Set<ApplicationPeerLink>()
    let current: { link: { close(): Promise<void>; retire?(): Promise<void> }; submit: Parameters<ApplicationPeerPort['attach']>[1] } | undefined
    const signals = new SignalChannel({ scope: descriptor.payload.applicationId,
      identity: { publicKeyBytes: hexToBytes(device.publicKey), privateKey: device.privateKey },
      authorize: ({ authorId }) => authority.grant(bytesToHex(authorId))?.reader === true })
    const value: ApplicationPeerPort = { signal: lifetime.signal, signals, resume: async () => {},
      participant: { device, storageId: device.publicKey, descriptor: descriptor.payload,
        get authority() { return authority.bundle }, get generation() { return authority.current! },
        get isCoordinator() { return authority.current!.payload.coordinator === device.publicKey },
        grant: key => authority.grant(key), data: undefined,
        openData: async () => { throw new Error('APPLICATION_DATA_NOT_ACTIVE') },
        adoptAuthority: async bundle => { authority = await verifyAuthorityBundle(bundle); for (const listener of listeners) listener() },
        subscribe: listener => { listeners.add(listener); return () => { listeners.delete(listener) } },
      },
      attach: (_peerId, submit, link) => {
        const previous = current, attached = { submit, link }; current = attached
        // The session owner uses this same optional graceful retirement hook.
        if (previous !== undefined) void (previous.link.retire?.() ?? previous.link.close()).catch(() => undefined)
        return () => { if (current === attached) current = undefined }
      },
    }
    cleanup.push(async () => { lifetime.abort(); signals.close(); await Promise.all([...attachments].map(link => link.close())) })
    return { value, attachments, listeners, lifetime }
  }
  const left = port(a), right = port(b), failures: unknown[] = []
  const connect = async (channels = createFramedPeerConnectionPair(), options: Partial<ApplicationPeerConnectOptions> = {}) => {
    const results = await Promise.allSettled([
      connectApplicationPeer(left.value, { ...options, connection: channels[0], peerIdentity: b.publicKey }),
      connectApplicationPeer(right.value, { ...options, connection: channels[1], peerIdentity: a.publicKey }),
    ])
    for (const [index, result] of results.entries()) if (result.status === 'fulfilled')
      (index === 0 ? left : right).attachments.add(result.value)
    failures.push(...results.filter(result => result.status === 'rejected').map(result => result.reason as unknown))
    if (results[0].status !== 'fulfilled' || results[1].status !== 'fulfilled') {
      await Promise.all(channels.map(channel => channel.close()))
      throw (results.find(result => result.status === 'rejected') as PromiseRejectedResult).reason
    }
    return [results[0].value, results[1].value] as const
  }
  return { a, b, left, right, connect, host, registry, control, failures }
}
function proof(connection: FramedPeerConnection, run: (value: Record<string, unknown>) => Promise<Record<string, unknown>>): FramedPeerConnection {
  return { ...connection, async send(bytes, options) {
    if (bytes[0] === 1) { await connection.send(bytes, options); return }
    const frame = assertCanonicalCbor(bytes)
    if (Array.isArray(frame) && frame.length === 5 && frame[4] instanceof Uint8Array) {
      const value = decodePeerValue<Record<string, unknown>>(frame[4])
      if (value.kind === 'proof') {
        const encoded = encodePeerValue(await run(value))
        bytes = encodeCanonicalCbor([frame[0]!, frame[1]!, 0n, BigInt(encoded.length), encoded])
      }
    }
    await connection.send(bytes, options)
  } }
}
async function synchronize(links: readonly ApplicationPeerLink[]) { await Promise.all(links.map(link => link.synchronize())) }

describe('bounded authenticated link handover', () => {
  it('has no idle heartbeats or idle timers once a connection is authenticated', async () => {
    const f = await fixture()
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const links = await f.connect(); await synchronize(links)
    await vi.waitFor(() => { expect(vi.getTimerCount()).toBe(0) }, { interval: 1, timeout: 1000 })
    const before = links.map(link => link.stats)
    await vi.advanceTimersByTimeAsync(120_000)
    expect(links.map(link => link.stats)).toEqual(before)
    expect(links.every(link => !link.signal.aborted)).toBe(true)
  })

  it('preserves the old route when authenticated candidate route preparation fails', async () => {
    const f = await fixture(), old = await f.connect(); await synchronize(old)
    const routes = vi.spyOn(f.left.value.signals, 'attachRoute').mockImplementationOnce(() => { throw new Error('SIGNAL_ROUTE_QUOTA_EXCEEDED') })
    await expect(f.connect()).rejects.toThrow(/SIGNAL_ROUTE_QUOTA_EXCEEDED|APPLICATION_NETWORK_CLOSED/u)
    routes.mockRestore()
    expect(old.every(link => !link.signal.aborted)).toBe(true)
    expect(connectedApplicationPeers(f.left.value)).toEqual([old[0]])
    expect(connectedApplicationPeers(f.right.value)).toEqual([old[1]])
    await synchronize(old)
  })

  it('counts control framing and only accepted live sends and actual received live frames, retaining stats after close', async () => {
    const f = await fixture(), [left, right] = createFramedPeerConnectionPair()
    let accept = true, attempts = 0
    const links = await f.connect([left, { ...right, live: { ...right.live!, async trySend(frame, options) {
      attempts++
      return accept && await right.live!.trySend(frame, options)
    } } }])
    await synchronize(links)
    expect(links.every(link => link.stats.sentBytes > 0 && link.stats.receivedBytes > 0 && link.stats.sentRequests > 0)).toBe(true)
    expect(links.map(link => [link.stats.sentLiveBytes, link.stats.receivedLiveBytes])).toEqual([[0, 0], [0, 0]])
    const observations = f.left.value.signals.subscribe({ signal: AbortSignal.timeout(2000) })[Symbol.asyncIterator]()
    const received = observations.next()
    await f.right.value.signals.send('progress', { completed: 1 }); await received; await observations.return?.()
    const sent = links[1].stats.sentLiveBytes, receivedBytes = links[0].stats.receivedLiveBytes
    expect(sent).toBeGreaterThan(0); expect(receivedBytes).toBe(sent)
    accept = false
    await expect(f.right.value.signals.send('progress', { completed: 2 })).rejects.toThrow('SIGNAL_BACKPRESSURE')
    expect(attempts).toBe(2)
    expect(links[1].stats.sentLiveBytes).toBe(sent); expect(links[0].stats.receivedLiveBytes).toBe(receivedBytes)
    await Promise.all(links.map(link => link.close()))
    expect(links[1].stats.sentLiveBytes).toBe(sent); expect(links[0].stats.receivedLiveBytes).toBe(receivedBytes)
    await expect(f.right.value.signals.send('progress', { completed: 3 })).rejects.toThrow('SIGNAL_ROUTE_UNAVAILABLE')
    expect(attempts).toBe(2)
  })

  it('expires a stalled old RPC at the drain deadline and keeps the new route usable', async () => {
    const f = await fixture(), entered = gate(), release = gate()
    let hold = false
    observePeerWire(f.a.publicKey, async packet => {
      if (hold && packet.kind === 'response' && packet.message?.action === 'state') {
        hold = false; entered.release(); await release.promise
      }
    })
    const old = await f.connect(undefined, { drainTimeoutMs: 1000 }); await synchronize(old)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    hold = true
    const pending = old[1].synchronize(), rejected = expect(pending).rejects.toThrow('APPLICATION_NETWORK_CLOSED')
    await entered.promise
    try {
      const fresh = await f.connect(); await synchronize(fresh)
      await vi.advanceTimersByTimeAsync(999)
      expect(old.every(link => !link.signal.aborted)).toBe(true)
      await vi.advanceTimersByTimeAsync(1); await rejected
      expect(old.every(link => link.signal.aborted)).toBe(true)
      await synchronize(fresh)
    } finally { release.release() }
  })

  it('rechecks revoked grants during drain and cancels all retirement resources immediately', async () => {
    const f = await fixture(), old = await f.connect(); await synchronize(old)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const fresh = await f.connect(); await synchronize(fresh)
    const original = f.left.value.participant.grant.bind(f.left.value.participant)
    vi.spyOn(f.left.value.participant, 'grant').mockImplementation(key => key === f.b.publicKey ? null : original(key))
    for (const listener of f.left.listeners) listener()
    expect(old[0].signal.reason).toEqual(new Error('APPLICATION_PEER_NOT_AUTHORIZED'))
    expect(fresh[0].signal.reason).toEqual(new Error('APPLICATION_PEER_NOT_AUTHORIZED'))
    await Promise.all([...old, ...fresh].map(link => link.close()))
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('finishes a real pending RPC on the old connection while new routing and live delivery are active', async () => {
    const f = await fixture(), entered = gate(), release = gate()
    let hold = false
    observePeerWire(f.a.publicKey, async packet => {
      if (hold && packet.kind === 'response' && packet.message?.action === 'state') {
        hold = false; entered.release(); await release.promise
      }
    })
    const old = await f.connect(); await synchronize(old)
    hold = true
    const pending = old[1].synchronize(); await entered.promise
    const fresh = await f.connect()
    expect(old.every(link => !link.signal.aborted)).toBe(true)
    expect(connectedApplicationPeers(f.left.value)).toEqual([fresh[0]])
    expect(connectedApplicationPeers(f.right.value)).toEqual([fresh[1]])
    const oldLive = old.map(link => [link.stats.sentLiveBytes, link.stats.receivedLiveBytes])
    const observations = f.left.value.signals.subscribe({ signal: AbortSignal.timeout(2000) })[Symbol.asyncIterator]()
    const received = observations.next(), signal = await f.right.value.signals.send('typing', { active: true })
    expect((await received).value).toEqual(signal); await observations.return?.()
    expect(old.map(link => [link.stats.sentLiveBytes, link.stats.receivedLiveBytes])).toEqual(oldLive)
    expect(fresh[1].stats.sentLiveBytes).toBe(fresh[0].stats.receivedLiveBytes)
    release.release(); await pending
    await synchronize(fresh)
    expect(old[1].stats.receivedBytes).toBeGreaterThan(0)
    // There is no protocol-level drain acknowledgement: the bounded grace
    // window also protects replies still in the opposite transport's queue.
    await Promise.all(old.map(link => link.close()))
  })

  it('keeps the working link usable while a candidate proof is pending or invalid, and sends no candidate application data', async () => {
    const f = await fixture(), old = await f.connect(), entered = gate(), release = gate()
    await synchronize(old)
    const [left, right] = createFramedPeerConnectionPair()
    let encrypted = 0
    const candidate = f.connect([{ ...left, async send(bytes, options) {
      if (bytes[0] === 1 && bytes[1] === 1) encrypted++
      await left.send(bytes, options)
    } }, proof(right, async value => { entered.release(); await release.promise; return { ...value, signature: '00'.repeat(64) } })])
    const rejected = expect(candidate).rejects.toThrow('APPLICATION_PEER_PROOF_INVALID')
    await entered.promise
    await synchronize(old)
    expect(connectedApplicationPeers(f.left.value)).toEqual([old[0]])
    expect(encrypted).toBe(0)
    release.release(); await rejected
    expect(old.every(link => !link.signal.aborted)).toBe(true)
    await synchronize(old)
  })

  it('fences an older late authenticated winner after a newer replacement', async () => {
    const f = await fixture(), old = await f.connect(), entered = gate(), release = gate()
    await synchronize(old)
    const [left, right] = createFramedPeerConnectionPair()
    const slow = f.connect([proof(left, async value => { entered.release(); await release.promise; return value }),
      proof(right, async value => { await release.promise; return value })])
    const rejected = expect(slow).rejects.toThrow(/APPLICATION_PEER_SUPERSEDED|APPLICATION_NETWORK_CLOSED/u)
    await entered.promise
    const winner = await f.connect()
    release.release(); await rejected
    expect(f.failures.map(error => error instanceof Error ? error.message : error)).toContain('APPLICATION_PEER_SUPERSEDED')
    expect(connectedApplicationPeers(f.left.value)).toEqual([winner[0]])
    expect(connectedApplicationPeers(f.right.value)).toEqual([winner[1]])
    await synchronize(winner)
  })

  it('bounds retiring resources during churn and cancels drain deadlines on owner close', async () => {
    const f = await fixture(), first = await f.connect(); await synchronize(first)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const second = await f.connect(); await synchronize(second)
    const third = await f.connect(); await synchronize(third)
    expect(first.every(link => link.signal.aborted)).toBe(true)
    expect(second.every(link => !link.signal.aborted)).toBe(true)
    expect(connectedApplicationPeers(f.left.value)).toEqual([third[0]])
    const completion = second[0].retire()
    expect(second[0].retire()).toBe(completion)
    await vi.advanceTimersByTimeAsync(4999)
    expect(second.every(link => !link.signal.aborted)).toBe(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(second.every(link => link.signal.aborted)).toBe(true)
    for (const link of third) void link.retire()
    f.left.lifetime.abort(); f.right.lifetime.abort()
    await Promise.all(third.map(link => link.close()))
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(0)
  })
})

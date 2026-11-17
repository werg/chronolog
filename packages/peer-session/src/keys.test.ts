import { afterEach, describe, expect, it } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PeerReplica, type PeerStore,
} from '@chronolog/peer-generation'
import { openApplicationDevice } from './device.js'
import { ApplicationKeyring } from './keys.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
async function fixture(options: { loseKeyReply?: boolean; beforeKeyRead?: () => Promise<void> } = {}) {
  const host = await createPeerIdentity(), stores: PeerStore[] = [new MemoryPeerStore(), new MemoryPeerStore(), new MemoryPeerStore()]
  let loseReply = options.loseKeyReply ?? false
  if (loseReply || options.beforeKeyRead !== undefined) {
    const saved = stores[1]!
    stores[1] = { async get(key) {
      if (key.startsWith('peer-session/keys/')) await options.beforeKeyRead?.()
      return saved.get(key)
    }, async put(key, value) {
      await saved.put(key, value)
      if (loseReply && key.startsWith('peer-session/keys/')) { loseReply = false; throw new Error('LOST_KEY_STORAGE_REPLY') }
    } }
  }
  const devices = await Promise.all(stores.map(store => openApplicationDevice({ store, create: true })))
  const key = crypto.getRandomValues(new Uint8Array(32)), artifacts = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '68'.repeat(32), historyId: 'key-enrollment',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: devices[0]!.identity.publicKey,
    definitionDigest: '01'.repeat(32), schemaDigest: null, executionManifestDigest: bytesToHex(artifacts.executionManifestDigest) }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.slice(0, 2).map((device, index) => participantGrant(device.identity.publicKey, { administrator: index === 0 })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, requester: devices[0]!.identity.publicKey,
    coordinator: devices[0]!.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, devices[0]!.identity))
  const open = async (index: number, initial?: ReadonlyMap<number, Uint8Array>) => {
    const device = await openApplicationDevice({ store: stores[index]! }), authority = await registry.read()
    const keys = await ApplicationKeyring.open({ device, authority, ...(initial === undefined ? {} : { epochKeys: initial }) })
    const runtime = await createEventMaterializationRuntime({ store: device.store, namespace: 'keys', historyProfile: 'peer-generation-v1' })
    const replica: PeerReplica = await createPeerReplica({ authority, device: device.identity, storageId: device.storageId,
      store: device.store, materializer: runtime, epochKeys: keys.epochKeys })
    keys.bind(replica); await keys.validate()
    const close = async () => { await keys.close(); await replica.close(); await device.close() }
    cleanup.push(close)
    return { device, keys, replica, close }
  }
  return { host, devices, key, control, registry, open }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

describe('durable peer key enrollment', () => {
  it('wraps committed keys to the signed recipient and resumes without bootstrap keys or the issuing peer', async () => {
    const f = await fixture(), a = await f.open(0, new Map([[0, f.key]])); let b = await f.open(1)
    const attempt = await a.replica.prepare({ operationId: 'before-enrollment', program: program(emit('message', 'secret history')) })
    await a.replica.order(attempt)
    await expect(b.replica.ingest(await a.replica.exportCommands())).rejects.toThrow('PEER_EPOCH_KEY_UNAVAILABLE')
    const ticket = (await b.keys.request())!
    const share = await a.keys.offer(ticket.request)
    expect(share.payload.keys[0]!.ciphertext).not.toContain(bytesToHex(f.key))
    await ticket.accept(share)
    expect(b.keys.missing()).toEqual([])
    await b.replica.ingest(await a.replica.exportCommands())
    expect(await b.replica.operation('before-enrollment', a.device.identity.publicKey)).toMatchObject({ status: 'applied', outcome: 'accepted' })
    const signer = b.device.identity.publicKey
    await a.close(); await b.close(); b = await f.open(1)
    expect(b.device.identity.publicKey).toBe(signer)
    expect(b.keys.missing()).toEqual([])
    expect(await b.replica.operation('before-enrollment', a.device.identity.publicKey)).toMatchObject({ outcome: 'accepted' })
  })

  it('rejects substituted receivers and replay into a different request', async () => {
    const f = await fixture(), a = await f.open(0, new Map([[0, f.key]])), b = await f.open(1)
    const ticket = (await b.keys.request())!, substituted = structuredClone(ticket.request)
    ;(substituted.payload as { receiverKey: string }).receiverKey = '01'.repeat(32)
    await expect(a.keys.offer(substituted)).rejects.toThrow('APPLICATION_KEY_SIGNATURE_INVALID')
    const share = await a.keys.offer(ticket.request)
    ticket.cancel()
    const another = (await b.keys.request())!
    await expect(another.accept(share)).rejects.toThrow('APPLICATION_KEY_SHARE_INVALID')
    expect(b.keys.missing()).toEqual([0])
  })

  it('fences in-flight enrollment at revocation and needs no keys for an entirely excluded epoch', async () => {
    const f = await fixture(), a = await f.open(0, new Map([[0, f.key]])), b = await f.open(1)
    const ticket = (await b.keys.request())!, oldShare = await a.keys.offer(ticket.request), nextKey = crypto.getRandomValues(new Uint8Array(32))
    const control = await signControlRevision({ ...f.control.payload, revision: 1, previous: await peerDigest(f.control), epoch: 1,
      keyDigest: await bytesDigest(nextKey), grants: [participantGrant(a.device.identity.publicKey, { administrator: true }), participantGrant(f.devices[2]!.identity.publicKey)] }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.replica.descriptor.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      transitionId: 'rotate', expectedGeneration: a.replica.generation.id, requester: a.device.identity.publicKey, coordinator: a.device.identity.publicKey,
      controlRevision: 1, reason: 'control-change', base: await a.replica.recoveryPoint() }, a.device.identity), { control })
    const authority = await f.registry.read(); await a.replica.adopt(authority); await b.replica.adopt(authority)
    await a.keys.install(new Map([[1, nextKey]]))
    await expect(ticket.accept(oldShare)).rejects.toThrow('APPLICATION_KEY_REQUEST_INVALID')
    await expect(b.keys.request()).rejects.toThrow('APPLICATION_KEY_ACCESS_DENIED')
    const c = await f.open(2)
    expect(c.replica.requiredEpochs).toEqual([1])
    expect(c.keys.missing()).toEqual([1])
    const enrollment = (await c.keys.request())!
    await enrollment.accept(await a.keys.offer(enrollment.request))
    expect(c.keys.epochKeys.has(0)).toBe(false)
    const command = await c.replica.prepare({ operationId: 'new-epoch', program: program(emit('message', 'current')) })
    await a.replica.order(command)
    // An optional old attachment may still name epoch 0 even though selected
    // application history needs only epoch 1. Its key is fetched on demand.
    const detach = c.keys.attachSource(a.device.identity.publicKey, request => a.keys.offer(request))
    await c.keys.ensure([0])
    expect(c.keys.epochKeys.get(0)).toEqual(f.key)
    detach()
  })

  it('recovers a durably installed key after its storage acknowledgment is lost', async () => {
    const f = await fixture({ loseKeyReply: true }), a = await f.open(0, new Map([[0, f.key]])); let b = await f.open(1)
    const ticket = (await b.keys.request())!
    await expect(ticket.accept(await a.keys.offer(ticket.request))).rejects.toThrow('LOST_KEY_STORAGE_REPLY')
    await b.close(); b = await f.open(1)
    expect(b.keys.missing()).toEqual([])
    expect(await b.keys.request()).toBeNull()
  })

  it('bounds physical key providers and closes an unanswered enrollment before a late share arrives', async () => {
    const f = await fixture(), a = await f.open(0, new Map([[0, f.key]])); let b = await f.open(1)
    const started = Array.from({ length: 9 }, () => deferred<void>())
    const responses = Array.from({ length: 9 }, () => deferred<Awaited<ReturnType<typeof a.keys.offer>>>())
    const requests: Parameters<typeof a.keys.offer>[0][] = []
    const offer = (request: Parameters<typeof a.keys.offer>[0]) => {
      const index = requests.length; requests.push(request); started[index]!.resolve(); return responses[index]!.promise
    }
    for (let index = 0; index < 8; index++) {
      const detach = b.keys.attachSource(a.device.identity.publicKey, offer)
      const result = b.keys.ensure().catch((error: unknown) => error)
      await started[index]!.promise; detach()
      expect(await result).toMatchObject({ message: 'APPLICATION_KEY_SOURCE_DETACHED' })
    }
    b.keys.attachSource(a.device.identity.publicKey, offer)
    await expect(b.keys.ensure()).rejects.toThrow('APPLICATION_KEY_SOURCE_BUSY')
    expect(requests).toHaveLength(8)
    await b.close(); b = await f.open(1)
    b.keys.attachSource(a.device.identity.publicKey, offer)
    const result = b.keys.ensure().catch((error: unknown) => error)
    await started[8]!.promise
    await b.keys.close()
    expect(await result).toMatchObject({ message: 'APPLICATION_KEYRING_CLOSED' })
    const share = await a.keys.offer(requests[8]!)
    responses[8]!.resolve(share); await responses[8]!.promise
    expect(b.keys.epochKeys.size).toBe(0)
    expect(requests).toHaveLength(9)
    await b.close()
    const reopened = await f.open(1)
    expect(reopened.keys.missing()).toEqual([0])
  })

  it('cancels an in-flight accepted share before its queued durable installation', async () => {
    let pause = false
    const entered = deferred<void>(), release = deferred<void>()
    const f = await fixture({ beforeKeyRead: async () => { if (pause) { entered.resolve(); await release.promise } } })
    const a = await f.open(0, new Map([[0, f.key]])), b = await f.open(1)
    const ticket = (await b.keys.request())!, share = await a.keys.offer(ticket.request)
    pause = true
    const result = ticket.accept(share).catch((error: unknown) => error)
    await entered.promise
    ticket.cancel()
    expect(await result).toMatchObject({ message: 'APPLICATION_KEY_REQUEST_CLOSED' })
    release.resolve(); pause = false
    await b.close()
    const reopened = await f.open(1)
    expect(reopened.keys.missing()).toEqual([0])
  })
})

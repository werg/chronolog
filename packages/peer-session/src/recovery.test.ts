import { afterEach, expect, it } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PeerReplica, type PrefixProof, type SignedTransitionRequest,
} from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { ApplicationRecovery } from './recovery.js'

const closing: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0).reverse()) await close() })

it.each([false, true])('does not rebind a delayed ancestor candidate to newer authority (displayed expectation: %s)', async explicit => {
  const [host, author, survivor] = await Promise.all([0, 1, 2].map(() => createPeerIdentity()))
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest()), applicationId = 'c9'.repeat(32)
  const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'recovery-race', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
    controlPublicKey: host!.publicKey, schemaAdministrator: author!.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: 'c8'.repeat(32), schemaDigest: null,
  }, host!)
  const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [author!, survivor!].map(identity => participantGrant(identity.publicKey, { administrator: identity === author })),
  }, host!)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host! })
  const select = async (base: PrefixProof | null, transitionId: string) => registry.select(await signTransitionRequest({
    applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId,
    expectedGeneration: (await registry.read()).generations.at(-1)?.id ?? null, coordinator: author!.publicKey,
    requester: author!.publicKey, controlRevision: 0, base, reason: base === null ? 'create' : 'takeover',
  }, author!))
  await select(null, 'first')
  const stores = [new MemoryBytesStore(), new MemoryBytesStore()]
  const peers = await Promise.all([author!, survivor!].map(async (device, index) => {
    const store = stores[index]!, materializer = await createEventMaterializationRuntime({ store, namespace: descriptor.payload.historyId })
    const replica = await createPeerReplica({ authority: await registry.read(), device, store, storageId: device.publicKey, materializer, epochKeys })
    closing.push(() => replica.close()); return replica
  }))
  const [a, b] = peers as [PeerReplica, PeerReplica]
  await a.order(await a.prepare({ operationId: 'ancestor', program: program(emit('message', 'ancestor')) }))
  await b.ingest(await a.exportCommands()); const ancestor = await b.recoveryPoint()
  await select(ancestor, 'second'); await a.adopt(await registry.read())
  await a.order(await a.prepare({ operationId: 'unavailable', program: program(emit('message', 'unavailable')) }))
  const current = await select(await a.recoveryPoint(), 'third')
  await a.adopt(await registry.read()); await b.receiveHistory(await registry.read(), [])

  let entered!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
  const delayed = new Proxy(b, { get(target, property) {
    if (property === 'recoveryPoint') return async () => { entered(); await gate; return target.recoveryPoint() }
    const value: unknown = Reflect.get(target, property, target)
    return typeof value === 'function' ? value.bind(target) : value
  } })
  const recovery = new ApplicationRecovery({ replica: delayed, store: stores[1]!, signal: new AbortController().signal })
  closing.push(() => recovery.close())
  const requests: SignedTransitionRequest[] = []
  const pending = recovery.takeover({ application: () => registry.read(), selectGeneration(request) { requests.push(request); return registry.select(request) } }, {
    transitionId: 'delayed', ...(explicit ? { expected: { generation: current.id, controlRevision: 0, point: ancestor.point } } : {}),
  })
  const rejected = expect(pending).rejects.toThrow('APPLICATION_RECOVERY_PROPOSAL_CHANGED')
  await started
  try {
    const newer = await select(await a.recoveryPoint(), 'fourth')
    await b.receiveHistory(await registry.read(), [])
    expect(b.generation.id).toBe(newer.id)
    expect(await b.recoveryPoint()).toEqual(ancestor)
  } finally { release() }
  await rejected
  expect(requests).toEqual([]); expect(await recovery.inspect()).toEqual([])
  expect(b.ready).toBe(false)
})

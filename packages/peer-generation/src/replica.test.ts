import { afterEach, describe, expect, it } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type PeerStore, type PrefixProof,
} from './index.js'
import { bytesToHex, signPeerValue } from './codec.js'

const opened: PeerReplica[] = []
afterEach(async () => { for (const peer of opened.splice(0)) await peer.close() })
async function fixture() {
  const [host, a, b, c] = await Promise.all(Array.from({ length: 4 }, () => createPeerIdentity())) as [PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity]
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'replica-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: '11'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (who: PeerIdentity, base: PrefixProof | null, id: string) => {
    const authority = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
      profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: id,
      expectedGeneration: authority.generations.at(-1)?.id ?? null, coordinator: who.publicKey,
      requester: who.publicKey, controlRevision: 0, reason: base === null ? 'create' : 'takeover', base }, who))
  }
  await select(a, null, 'initial')
  const open = async (identity: PeerIdentity, store: PeerStore = new MemoryPeerStore(), authority?: AuthorityBundle, storageId = identity.publicKey) => {
    const materializer = await createEventMaterializationRuntime({ store, namespace: 'test', historyProfile: 'peer-generation-v1' })
    const peer = await createPeerReplica({ authority: authority ?? await registry.read(), device: identity, store, storageId, materializer, epochKeys: keys })
    opened.push(peer); return peer
  }
  return { host, a, b, c, key, keys, control, registry, select, open }
}
const event = (name: string) => program(emit('message', { name }))

describe('peer-owned encrypted history and tolerant recovery', () => {
  it('executes delegated order without altering author times and replays identically', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = await a.prepare({ operationId: 'first', program: event('first'), authorTimestampMs: 500n })
    const second = await a.prepare({ operationId: 'second', program: event('second'), authorTimestampMs: 100n })
    await a.order(first); await a.order(second); await b.ingest(await a.exportCommands())
    const av = await a.capture(), bv = await b.capture()
    try {
      expect(av.read.orderLength).toBe(2)
      expect(av.outcomes).toEqual(bv.outcomes)
      expect(av.outcomes.map(value => value.orderKey.authorTimestampMs)).toEqual([500n, 100n])
      expect(av.read.transactionAt(0)).toEqual(bv.read.transactionAt(0))
    } finally { av.release(); bv.release() }
    expect(await a.order(first)).toEqual((await a.exportCommands())[0])
    expect((await a.exportCommands()).length).toBe(2)
    await b.observeCoverage(await a.retainedCoverage())
    expect(b.shared()).toHaveLength(1)
  })
  it('adopts an older complete prefix, seeds a fresh peer and quarantines the returning suffix', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const one = await a.prepare({ operationId: 'one', program: event('one') })
    await a.order(one); await b.ingest(await a.exportCommands())
    const two = await a.prepare({ operationId: 'two', program: event('two') })
    await a.order(two)
    const held = await a.capture(), oldRevision = held.revision
    const base = await b.recoveryPoint(), g2 = await f.select(f.b, base, 'second')
    await b.adopt(await f.registry.read())
    const three = await b.prepare({ operationId: 'three', program: event('three') }); await b.order(three)
    const c = await f.open(f.c)
    await expect(c.capture()).rejects.toThrow('PEER_RECOVERING')
    await c.synchronize(await f.registry.read(), await b.exportCommands())
    expect((await c.operation('one', f.a.publicKey))?.status).toBe('applied')
    const notice = await a.synchronize(await f.registry.read(), await b.exportCommands())
    expect(notice?.abandoned).toContainEqual(expect.objectContaining({ operationId: 'two', status: 'abandoned' }))
    expect((await a.operation('two'))?.status).toBe('abandoned')
    expect(held.read.orderLength).toBe(2); held.release()
    await expect(a.prepare({ operationId: 'stale-view', program: event('stale'), basedOn: oldRevision })).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
    await expect(b.order(two)).rejects.toThrow('PEER_ATTEMPT_NEEDS_REAPPLY')
    expect(await b.order(one)).toEqual((await b.exportCommands())[0])
    const reapplied = await a.prepare({ operationId: 'two-reapplied', program: event('two'), reapplyOf: two.id })
    await b.order(reapplied); await a.ingest(await b.exportCommands())
    expect(await a.operation('two-reapplied')).toMatchObject({ status: 'applied', generation: g2.id })
    expect((await a.operation('two'))?.status).toBe('abandoned')
    const g3 = await f.select(f.c, await b.recoveryPoint(), 'third')
    await c.synchronize(await f.registry.read(), await b.exportCommands())
    expect(c.generation.id).toBe(g3.id)
    const before = (await c.exportCommands()).map(value => value.attempt.id)
    expect(before).not.toContain(two.id); expect(before).toContain(reapplied.id)
  })
  it('reopens a locally committed receipt after its acknowledgment is lost', async () => {
    const f = await fixture(), retained = new MemoryPeerStore()
    let fail = false
    const store: PeerStore = { get: key => retained.get(key), async put(key, value) { await retained.put(key, value); if (fail && key.includes('/head/')) { fail = false; throw new Error('LOST_STORAGE_ACK') } } }
    const a = await f.open(f.a, store), attempt = await a.prepare({ operationId: 'once', program: event('once') })
    fail = true
    await expect(a.order(attempt)).rejects.toThrow('LOST_STORAGE_ACK')
    await a.close()
    const reopened = await f.open(f.a, store)
    const exact = await reopened.prepare({ operationId: 'once', program: event('once') })
    expect(exact).toEqual(attempt)
    expect((await reopened.order(exact)).receipt.payload.sequence).toBe(1)
    expect(await reopened.operation('once')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(await reopened.exportCommands()).toHaveLength(1)
  })
  it('rejects missing bodies, gaps, wrong signatures and altered operation reuse', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const first = await a.prepare({ operationId: 'stable', program: event('one') }); await a.order(first)
    await a.order(await a.prepare({ operationId: 'other', program: event('two') }))
    const commands = await a.exportCommands()
    await expect(b.ingest([commands[1]!])).rejects.toThrow('PEER_HISTORY_GAP')
    const broken = structuredClone(commands[0]!); (broken.attempt.payload as { ciphertext: string }).ciphertext = '00'.repeat(32)
    await expect(b.ingest([broken])).rejects.toThrow('PEER_ATTEMPT_ID_INVALID')
    await expect(a.prepare({ operationId: 'stable', program: event('changed') })).rejects.toThrow('PEER_OPERATION_ID_REUSED')
    expect((await b.recoveryPoint()).point.sequence).toBe(0)
  })
  it('detects coordinator equivocation and fences further ordering', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const attempt = await a.prepare({ operationId: 'one', program: event('one') }), ordered = await a.order(attempt)
    await b.ingest([ordered])
    const payload = { ...ordered.receipt.payload, previousRoot: 'ff'.repeat(32) }
    const forged = { attempt, receipt: { ...await signPeerValue('chronolog/peer-generation/order/v1', payload, f.a), root: await peerDigest(['chronolog/peer-generation/order/v1', payload]) } }
    await expect(a.ingest([forged])).rejects.toThrow('PEER_COORDINATOR_EQUIVOCATION')
    const another = await a.prepare({ operationId: 'two', program: event('two') })
    await expect(a.order(another)).rejects.toThrow('PEER_COORDINATOR_FENCED')
  })
  it('does not count a second tab on the same storage owner as a separate copy', async () => {
    const f = await fixture(), a = await f.open(f.a, undefined, undefined, 'same-device'), b = await f.open(f.b, undefined, undefined, 'same-device')
    await a.observeCoverage(await b.retainedCoverage())
    expect(a.shared()).toHaveLength(0)
  })
})

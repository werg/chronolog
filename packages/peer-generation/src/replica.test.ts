import { afterEach, describe, expect, it } from 'vitest'
import { createAppliedEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { compareTransactionOrder, decodeTransactionCore, emit, executionManifestArtifacts, program, transactionOrderKey } from '@chronolog/protocol'
import {
  bytesDigest, controlIntentDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, peerDigest,
  encodePeerValue, signApplicationDescriptor, signControlRevision, signTransitionRequest, verifyAuthorityBundle,
  type AuthorityBundle, type PeerIdentity, type PeerReplica, type PeerStore, type PrefixProof,
} from './index.js'
import { bytesToHex, hexToBytes, signPeerValue } from './codec.js'
import { createSignedAttempt, verifyAttempt } from './attempt.js'

const opened: PeerReplica[] = []
afterEach(async () => { for (const peer of opened.splice(0)) await peer.close() })
async function fixture() {
  const [host, a, b, c] = await Promise.all(Array.from({ length: 4 }, () => createPeerIdentity())) as [PeerIdentity, PeerIdentity, PeerIdentity, PeerIdentity]
  const key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '22'.repeat(32), historyId: 'replica-test',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: '11'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a, dataRole: 'member' as const })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (who: PeerIdentity, base: PrefixProof | null, id: string) => {
    const authority = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
      profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: id,
      expectedGeneration: authority.generations.at(-1)?.id ?? null, coordinator: who.publicKey,
      requester: who.publicKey, controlRevision: 0, controlIntentDigest: await controlIntentDigest(control.payload), contextDigest: null,
      reason: base === null ? 'create' : 'takeover', base }, who))
  }
  await select(a, null, 'initial')
  const open = async (identity: PeerIdentity, store: PeerStore = new MemoryPeerStore(), authority?: AuthorityBundle, storageId = identity.publicKey, now?: () => number) => {
    const materializer = await createAppliedEventMaterializationRuntime({ store, namespace: 'test' })
    const peer = await createPeerReplica({ authority: authority ?? await registry.read(), device: identity, store, storageId, materializer, epochKeys: keys,
      ...(now === undefined ? {} : { now }) })
    opened.push(peer); return peer
  }
  return { host, a, b, c, key, keys, control, registry, select, open }
}
const event = (name: string) => program(emit('message', { name }))

describe('peer-owned encrypted history and tolerant recovery', () => {
  it('authors after durable own intents and applied observations across same-clock retries, recovery and reopen', async () => {
    const f = await fixture(), store = new MemoryPeerStore(), now = () => 100
    const a = await f.open(f.a, store, undefined, undefined, now), b = await f.open(f.b)
    const timestamp = async (attempt: Awaited<ReturnType<PeerReplica['prepare']>>) =>
      (await verifyAttempt(attempt, await verifyAuthorityBundle(await f.registry.read()), f.keys)).authorTimestampMs
    const first = await a.prepare({ operationId: 'first', program: event('first') })
    const second = await a.prepare({ operationId: 'second', program: event('second') })
    expect(await timestamp(first)).toBe(100n)
    expect(await timestamp(second)).toBe(101n)
    const empty = await a.recoveryPoint()
    const remote = await b.prepare({ operationId: 'observed', program: event('observed'), authorTimestampMs: 900n })
    await a.order(remote)
    const retained = await a.exportCommands()
    await f.select(f.b, empty, 'recovered-empty')
    await a.adopt(await f.registry.read())
    await a.close()
    const reopened = await f.open(f.a, store, undefined, undefined, now)
    expect(await reopened.prepare({ operationId: 'first', program: event('first') })).toEqual(first)
    const afterObserved = await reopened.prepare({ operationId: 'after-observed', program: event('after-observed') })
    expect(await timestamp(afterObserved)).toBe(901n)
    await reopened.close()
    const again = await f.open(f.a, store, undefined, undefined, now)
    expect(await again.prepare({ operationId: 'after-observed', program: event('after-observed') })).toEqual(afterObserved)
    expect(await timestamp(await again.prepare({ operationId: 'after-saved', program: event('after-saved') }))).toBe(902n)
    expect(await timestamp(await again.prepare({ operationId: 'explicit', program: event('explicit'), authorTimestampMs: 7n }))).toBe(7n)
    // An old remote body retained only as recovery evidence was never observed
    // as applied by this fresh peer and must not move its author clock.
    const fresh = await f.open(f.c, undefined, undefined, undefined, now)
    await fresh.synchronize(await f.registry.read(), retained)
    expect(await timestamp(await fresh.prepare({ operationId: 'unobserved', program: event('unobserved') }))).toBe(100n)
  })
  it('replays author-time order independently of receipt sequence and retains exact intent through reopen', async () => {
    const f = await fixture(), store = new MemoryPeerStore(), a = await f.open(f.a, store), b = await f.open(f.b)
    const first = await a.prepare({ operationId: 'first', program: event('first'), authorTimestampMs: 500n, observedRevision: a.revision })
    const second = await a.prepare({ operationId: 'second', program: event('second'), authorTimestampMs: 100n })
    await a.order(first)
    const held = await a.capture(), initial = await a.operation('first')
    await a.order(second); await b.ingest(await a.exportCommands())
    expect(await a.exportCommands({ at: held.revision })).toHaveLength(1)
    await expect(a.exportCommands({ at: held.revision, offset: 2 })).rejects.toThrow('PEER_RANGE_OFFSET_INVALID')
    const av = await a.capture(), bv = await b.capture()
    try {
      expect(av.read.orderLength).toBe(2)
      expect(av.outcomes).toEqual(bv.outcomes)
      expect(av.outcomes.map(value => value.orderKey.authorTimestampMs)).toEqual([100n, 500n])
      expect([0, 1].map(index => decodeTransactionCore(av.read.transactionAt(index)!.canonicalCandidate).operationId)).toEqual(['second', 'first'])
      expect(av.read.transactionAt(0)).toEqual(bv.read.transactionAt(0))
      expect(held.read.orderLength).toBe(1)
      expect(decodeTransactionCore(held.read.transactionAt(0)!.canonicalCandidate).operationId).toBe('first')
      expect('finalOrderLength' in av.read).toBe(false)
      expect('finalRevision' in av.read).toBe(false)
      expect(await a.operation('first')).toMatchObject({ attemptId: first.id, sequence: 1, revision: av.revision })
      expect(initial).toMatchObject({ attemptId: first.id, sequence: 1, revision: held.revision })
    } finally { av.release(); bv.release(); held.release() }
    expect(await a.order(first)).toEqual((await a.exportCommands())[0])
    expect((await a.exportCommands()).map(value => value.attempt.id)).toEqual([first.id, second.id])
    await b.observeCoverage(await a.retainedCoverage())
    expect(b.shared()).toHaveLength(1)
    await a.close()
    const reopened = await f.open(f.a, store)
    expect(await reopened.prepare({ operationId: 'first', program: event('first') })).toEqual(first)
    await expect(reopened.prepare({ operationId: 'first', program: event('first'), authorTimestampMs: 501n })).rejects.toThrow('PEER_OPERATION_ID_REUSED')
    const restored = await reopened.capture()
    try { expect(restored.outcomes.map(value => value.orderKey.authorTimestampMs)).toEqual([100n, 500n]) } finally { restored.release() }
  })
  it('uses the signing key and stable proposal identity to break equal authored timestamps', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const attempts = await Promise.all([
      a.prepare({ operationId: 'a-one', program: event('a-one'), authorTimestampMs: 100n }),
      a.prepare({ operationId: 'a-two', program: event('a-two'), authorTimestampMs: 100n }),
      b.prepare({ operationId: 'b-one', program: event('b-one'), authorTimestampMs: 100n }),
    ])
    const keys = attempts.map(value => transactionOrderKey({ authorTimestampMs: 100n, authorId: hexToBytes(value.payload.header.author) }, hexToBytes(value.id)))
      .sort(compareTransactionOrder)
    const expected = keys.map(value => bytesToHex(value.txId))
    for (const id of [...expected].reverse()) await a.order(attempts.find(value => value.id === id)!)
    const captured = await a.capture()
    try { expect(captured.outcomes.map(value => bytesToHex(value.txId))).toEqual(expected) } finally { captured.release() }
  })
  it('authenticates observed ancestry without treating a peer-local materialization counter as a state guard', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await a.order(await a.prepare({ operationId: 'first', program: event('first'), authorTimestampMs: 500n }))
    await b.ingest(await a.exportCommands())
    const observedRevision = b.revision
    await a.order(await a.prepare({ operationId: 'earlier', program: event('earlier'), authorTimestampMs: 100n }))
    expect(a.revision.point).not.toEqual(observedRevision.point)
    const later = await a.prepare({ operationId: 'contextual', program: event('contextual'), observedRevision, authorTimestampMs: 700n })
    await a.order(later)
    expect(later.payload.header.observedRevision).toEqual(observedRevision)
    expect(await a.operation('contextual')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    await expect(a.prepare({ operationId: 'wrong-control', program: event('bad'), observedRevision: { ...observedRevision, controlRevision: 1 } })).rejects.toThrow('PEER_REVISION_INVALID')
    await expect(a.prepare({ operationId: 'wrong-generation', program: event('bad'), observedRevision: { ...observedRevision, generation: 'ff'.repeat(32) } })).rejects.toThrow('PEER_REVISION_INVALID')
    const legacy = { operationId: 'legacy-option', program: event('bad'), basedOn: observedRevision }
    await expect(a.prepare(legacy)).rejects.toThrow('PEER_COMMAND_OPTIONS_INVALID')
    expect(await a.attempt('legacy-option')).toBeNull()
  })
  it('rechecks observed ancestry on received history even with valid author and coordinator signatures', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await a.order(await a.prepare({ operationId: 'base', program: event('base') }))
    const base = await a.exportCommands(), observedRevision = a.revision
    await b.ingest(base)
    const original = await b.prepare({ operationId: 'contextual', program: event('contextual'), observedRevision })
    const core = await verifyAttempt(original, await verifyAuthorityBundle(await f.registry.read()), f.keys)
    for (const point of [
      { ...observedRevision.point, root: 'ff'.repeat(32) },
      { ...observedRevision.point, sequence: 2 },
    ]) {
      const attempt = await createSignedAttempt({ ...original.payload.header, observedRevision: { ...observedRevision, point } }, core, f.key, f.b)
      await expect(a.order(attempt)).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
      const payload = { ...base[0]!.receipt.payload, sequence: 2, previousRoot: observedRevision.point.root,
        attemptId: attempt.id, author: f.b.publicKey, operationId: 'contextual',
        bodyHash: await bytesDigest(encodePeerValue(attempt)), bodyBytes: encodePeerValue(attempt).length }
      const receipt = { ...await signPeerValue('chronolog/peer-generation/order/v1', payload, f.a),
        root: await peerDigest(['chronolog/peer-generation/order/v1', payload]) }
      const follower = await f.open(f.c)
      await follower.ingest(base)
      const captured = await follower.capture()
      try {
        await expect(follower.ingest([{ attempt, receipt }])).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
        expect(follower.ready).toBe(false)
        expect(follower.revision).toEqual(captured.revision)
        expect(captured.read.orderLength).toBe(1)
        expect(decodeTransactionCore(captured.read.transactionAt(0)!.canonicalCandidate).operationId).toBe('base')
      } finally { captured.release(); await follower.close() }
    }
  })
  it('adopts an older complete prefix, seeds a fresh peer and quarantines the returning suffix', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const one = await a.prepare({ operationId: 'one', program: event('one') })
    await a.order(one); await b.ingest(await a.exportCommands())
    const inheritedView = await b.capture(); const inheritedRevision = inheritedView.revision; inheritedView.release()
    const two = await a.prepare({ operationId: 'two', program: event('two') })
    await a.order(two)
    const held = await a.capture(), oldRevision = held.revision
    const base = await b.recoveryPoint(), g2 = await f.select(f.b, base, 'second')
    await b.adopt(await f.registry.read())
    await expect(b.exportCommands({ at: inheritedRevision })).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
    const three = await b.prepare({ operationId: 'three', program: event('three'), observedRevision: inheritedRevision }); await b.order(three)
    const c = await f.open(f.c)
    await expect(c.capture()).rejects.toThrow('PEER_RECOVERING')
    await c.synchronize(await f.registry.read(), await b.exportCommands())
    expect((await c.operation('one', f.a.publicKey))?.status).toBe('applied')
    const notice = await a.synchronize(await f.registry.read(), await b.exportCommands())
    expect(notice?.abandoned).toContainEqual(expect.objectContaining({ operationId: 'two', status: 'abandoned' }))
    expect((await a.operation('two'))?.status).toBe('abandoned')
    expect(held.read.orderLength).toBe(2); held.release()
    await expect(a.prepare({ operationId: 'stale-view', program: event('stale'), observedRevision: oldRevision })).rejects.toThrow('PEER_VIEW_RECOVERY_REQUIRED')
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

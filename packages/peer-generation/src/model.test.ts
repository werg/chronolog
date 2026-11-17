import { expect, it } from 'vitest'
import { createEventMaterializationRuntime, eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryBytesStore, participantGrant, peerDigest,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, verifyAuthorityBundle,
  type OrderedCommand, type PeerIdentity, type PeerReplica, type PrefixProof,
} from './index.js'

/** Independent list oracle: selected prefixes can shrink; excluded identities never return. */
class HistoryModel {
  selected: string[] = []
  readonly excluded = new Set<string>()
  append(id: string): void { if (this.excluded.has(id)) throw new Error('MODEL_EXCLUDED_IDENTITY'); this.selected.push(id) }
  adopt(length: number): void {
    if (length < 0 || length > this.selected.length) throw new Error('MODEL_INVALID_PREFIX')
    for (const id of this.selected.slice(length)) this.excluded.add(id)
    this.selected = this.selected.slice(0, length)
  }
}
function random(seed: number) { let state = seed; return (bound: number) => { state = Math.imul(state, 1664525) + 1013904223 | 0; return (state >>> 0) % bound } }
function point(command: OrderedCommand) { const value = command.receipt; return { generation: value.payload.generation, sequence: value.payload.sequence, root: value.root } }

it.each([7, 29, 101, 997])('matches the independent prefix model across bounded fault trace seed %s', async seed => {
  const choose = random(seed), model = new HistoryModel(), opened: PeerReplica[] = []
  const host = await createPeerIdentity(), identities = await Promise.all([0, 1, 2].map(() => createPeerIdentity()))
  const [a, b, c] = identities as [PeerIdentity, PeerIdentity, PeerIdentity]
  const stores = identities.map(() => new MemoryBytesStore()), key = crypto.getRandomValues(new Uint8Array(32)), keys = new Map([[0, key]])
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: seed.toString(16).padStart(64, '0'), historyId: `model-${seed}`,
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: '01'.repeat(32), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: identities.map(identity => participantGrant(identity.publicKey, { administrator: identity === a })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  const request = (identity: PeerIdentity, expectedGeneration: string | null, base: PrefixProof | null, transitionId: string,
    controlRevision = 0, reason: 'create' | 'takeover' | 'control-change' = 'takeover') => signTransitionRequest({
    applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    requester: identity.publicKey, coordinator: identity.publicKey, expectedGeneration, controlRevision, reason, transitionId, base }, identity)
  await registry.select(await request(a, null, null, 'initial', 0, 'create'))
  const open = async (index: number) => {
    const store = stores[index]!, materializer = await createEventMaterializationRuntime({ store, namespace: 'model' })
    const peer = await createPeerReplica({ store, materializer, storageId: identities[index]!.publicKey, device: identities[index]!, authority: await registry.read(), epochKeys: keys })
    opened.push(peer); return peer
  }
  try {
    const pa = await open(0); let pb = await open(1); const pc = await open(2)
    const old: OrderedCommand[] = []
    for (let index = 0; index < 6 + choose(3); index++) {
      const attempt = await pa.prepare({ operationId: `g1-${index}`, authorTimestampMs: BigInt(1000 - index), program: program(emit('model', { index })) })
      old.push(await pa.order(attempt)); model.append(attempt.id)
    }
    // Reordered delivery persists only the valid first body, without exposing a mixed view.
    await expect(pb.ingest([old[0]!, old[2]!])).rejects.toThrow('PEER_HISTORY_GAP')
    const unpublished = await pb.capture(); expect(unpublished.read.orderLength).toBe(0); unpublished.release()
    const retained = 2 + choose(3)
    await pb.ingest(old.slice(0, retained)); await pc.ingest(old.slice(0, retained))
    const base = await pb.recoveryPoint(), expected = pa.generation.id
    const winner = await request(b, expected, base, 'second'), loser = await request(c, expected, base, 'competing')
    const race = await Promise.allSettled([registry.select(winner), registry.select(loser)])
    expect(race.map(result => result.status)).toEqual(['fulfilled', 'rejected'])
    const second = await registry.select(winner) // Simulated lost successful control reply, exact retry.
    expect(second.payload.number).toBe(1)
    await pb.adopt(await registry.read()); model.adopt(retained)
    const isolated = await pa.prepare({ operationId: 'partitioned-old-a', program: program(emit('model', 'isolated')) })
    await pa.order(isolated)
    for (let index = 0; index < 2 + choose(2); index++) {
      const attempt = await pb.prepare({ operationId: `g2-${index}`, program: program(emit('model', { second: index })) })
      const receipt = await pb.order(attempt)
      expect(await pb.order(attempt)).toEqual(receipt)
      model.append(attempt.id)
    }
    await pa.synchronize(await registry.read(), await pb.exportCommands())
    expect((await pa.operation('partitioned-old-a'))?.status).toBe('abandoned')
    expect((await pa.exportCommands()).map(command => command.attempt.id)).toEqual(model.selected)

    // A later transition deliberately chooses an earlier inherited G1 prefix,
    // while a restrictive control revision remains independent of that tail.
    const earlier = 1 + choose(retained - 1), nextKey = crypto.getRandomValues(new Uint8Array(32)); keys.set(1, nextKey)
    const nextControl = await signControlRevision({ ...control.payload, revision: 1, previous: await peerDigest(control), epoch: 1,
      keyDigest: await bytesDigest(nextKey), grants: control.payload.grants.filter(grant => grant.publicKey !== c.publicKey) }, host)
    const thirdRequest = await request(a, second.id, await pb.prefixProof(point(old[earlier - 1]!)), 'third', 1, 'control-change')
    const third = await registry.select(thirdRequest, { control: nextControl })
    const selected = await registry.read()
    await pa.adopt(selected); await pb.adopt(selected); await pc.adopt(selected); model.adopt(earlier)
    expect(third.payload.number).toBe(2)
    expect((await pa.exportCommands()).map(command => command.attempt.id)).toEqual(model.selected)
    expect((await verifyAuthorityBundle(selected)).grant(c.publicKey)).toBeNull()
    await expect(pc.capture()).rejects.toThrow('PEER_READER_FORBIDDEN')
    const excluded = old[retained]!
    await expect(registry.select(await request(b, third.id, { point: point(excluded), receipt: excluded.receipt, bridge: [] }, 'resurrect', 1))).rejects.toThrow('PEER_PREFIX_EXCLUDED')
    await expect(pa.order(excluded.attempt)).rejects.toThrow('PEER_ATTEMPT_ABANDONED')
    await pb.close(); pb = await open(1)
    const av = await pa.capture(), bv = await pb.capture()
    try {
      expect(Array.from({ length: bv.read.orderLength }, (_, index) => bv.read.transactionAt(index)))
        .toEqual(Array.from({ length: av.read.orderLength }, (_, index) => av.read.transactionAt(index)))
      expect(bv.read.orderLength).toBe(model.selected.length)
    }
    finally { av.release(); bv.release() }
    expect((await pb.exportCommands()).map(command => command.attempt.id)).toEqual(model.selected)
    for (const id of model.excluded) expect(model.selected).not.toContain(id)
  } finally { for (const peer of opened) await peer.close() }
}, 60_000)

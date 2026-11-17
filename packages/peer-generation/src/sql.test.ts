import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { expect, it } from 'vitest'
import {
  AppliedMaterializer, createDoltLiteExecutionManifest, createDoltLiteAppliedMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { emit, encodeChangeProgram, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, peerDigest,
  signApplicationDescriptor, signApplicationSchema, signControlRevision, signTransitionRequest, verifyApplicationSchema,
  type OperationState, type PeerIdentity, type PeerReplica,
} from './index.js'
import { bytesToHex, hexToBytes } from './codec.js'

it('revises SQL conflicts by author time and selected ancestry while preserving captured views and exact intents', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peer-generation-sql-'))
  const peers: PeerReplica[] = []
  try {
    const host = await createPeerIdentity(), a = await createPeerIdentity(), b = await createPeerIdentity()
    const key = crypto.getRandomValues(new Uint8Array(32)), manifest = createDoltLiteExecutionManifest({ sqlPolicy: 'data-only' })
    const { executionManifestDigest } = await executionManifestArtifacts(manifest), applicationId = 'aa'.repeat(32), definitionDigest = 'bb'.repeat(32)
    const schema = await signApplicationSchema({ applicationId, definitionDigest, executionManifestDigest: bytesToHex(executionManifestDigest),
      program: bytesToHex(encodeChangeProgram(program('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT NOT NULL UNIQUE)'))) }, a)
    const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'sql-recovery', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      controlPublicKey: host.publicKey, schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(executionManifestDigest), definitionDigest,
      schemaDigest: await peerDigest(schema) }, host)
    const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
      grants: [a, b].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a })) }, host)
    const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'initial', expectedGeneration: null, requester: a.publicKey, coordinator: a.publicKey, controlRevision: 0, reason: 'create', base: null }, a))
    const stores = new Map<string, MemoryPeerStore>()
    const open = async (identity: PeerIdentity, name: string) => {
      const materializer = await AppliedMaterializer.open({ path: join(directory, `${name}.db`), executionManifest: manifest,
        rootAdministrator: hexToBytes(a.publicKey), sqlPolicy: 'data-only',
        bootstrapGroupId: hexToBytes(applicationId), bootstrapProgram: await verifyApplicationSchema(schema, descriptor.payload), checkpointEvery: 1 })
      const runtime = createDoltLiteAppliedMaterializationRuntime(materializer)
      const store = stores.get(name) ?? new MemoryPeerStore(); stores.set(name, store)
      const replica = await createPeerReplica({ authority: await registry.read(), device: identity, store,
        storageId: name, materializer: runtime, epochKeys: new Map([[0, key]]) })
      peers.push(replica); return { replica, runtime }
    }
    const pa = await open(a, 'a'), pb = await open(b, 'b')
    const observations: Array<Promise<OperationState | null>> = []
    const stop = pa.replica.subscribe(() => observations.push(pa.replica.operation('first')))
    const first = await pa.replica.prepare({ operationId: 'first', authorTimestampMs: 500n,
      program: program("INSERT INTO tasks (id,title) VALUES (1,'first')", emit('task.created', { id: 1 })) })
    await pa.replica.order(first)
    const initial = await pa.replica.operation('first'), heldFirst = await pa.replica.capture()
    expect(initial).toMatchObject({ status: 'applied', attemptId: first.id, outcome: 'accepted', revision: heldFirst.revision })
    const base = await pa.replica.recoveryPoint()
    const duplicate = await pa.replica.prepare({ operationId: 'duplicate', authorTimestampMs: 100n,
      program: program("INSERT INTO tasks (id,title) VALUES (2,'first')", emit('task.created', { id: 2 })) })
    await pa.replica.order(duplicate); await pb.replica.ingest(await pa.replica.exportCommands())
    expect(await pa.replica.operation('first')).toMatchObject({ status: 'applied', attemptId: first.id, outcome: 'rejected', rejectionCode: 'constraint' })
    expect(await observations.at(-1)!).toMatchObject({ attemptId: first.id, outcome: 'rejected' })
    expect(await pa.replica.operation('duplicate')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    const av = await pa.replica.capture(), bv = await pb.replica.capture()
    try {
      expect(av.read.query('SELECT id,title FROM tasks ORDER BY id').rows).toEqual(bv.read.query('SELECT id,title FROM tasks ORDER BY id').rows)
      expect(av.read.query('SELECT id FROM tasks').rows).toEqual([[{ kind: 'integer', value: '2' }]])
      expect(heldFirst.read.query('SELECT id FROM tasks').rows).toEqual([[{ kind: 'integer', value: '1' }]])
      expect(av.outcomes.map(value => value.orderKey.authorTimestampMs)).toEqual([100n, 500n])
      expect(av.outcomes).toEqual(bv.outcomes)
    } finally { bv.release(); heldFirst.release() }
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'takeover', expectedGeneration: pa.replica.generation.id, requester: b.publicKey, coordinator: b.publicKey,
      controlRevision: 0, reason: 'takeover', base }, b))
    await pb.replica.adopt(await registry.read()); await pa.replica.adopt(await registry.read())
    expect(await pa.replica.operation('duplicate')).toMatchObject({ status: 'abandoned', previous: { outcome: 'accepted', revision: av.revision } })
    expect(await pa.replica.operation('first')).toMatchObject({ status: 'applied', attemptId: first.id, outcome: 'accepted', revision: pa.replica.revision })
    expect(await observations.at(-1)!).toMatchObject({ attemptId: first.id, outcome: 'accepted' })
    expect(av.read.query('SELECT id FROM tasks').rows).toEqual([[{ kind: 'integer', value: '2' }]])
    av.release(); stop()
    await pa.replica.close()
    const reopened = await open(a, 'a')
    expect(await reopened.replica.prepare({ operationId: 'first', program: program("INSERT INTO tasks (id,title) VALUES (1,'first')", emit('task.created', { id: 1 })) })).toEqual(first)
    expect(await reopened.replica.operation('first')).toMatchObject({ attemptId: first.id, outcome: 'accepted', revision: reopened.replica.revision })
    expect(await reopened.replica.operation('duplicate')).toMatchObject({ status: 'abandoned', previous: { outcome: 'accepted', revision: av.revision } })
    const forbidden = await reopened.replica.prepare({ operationId: 'lossy-schema', program: program('CREATE TABLE forbidden (id INTEGER PRIMARY KEY)') })
    await pb.replica.order(forbidden)
    expect(await pb.replica.operation('lossy-schema', a.publicKey)).toMatchObject({ status: 'applied', outcome: 'rejected', rejectionCode: 'denied' })
    const overwrite = await pb.replica.prepare({ operationId: 'not-owner', program: program("UPDATE tasks SET title='stolen' WHERE id=1") })
    await pb.replica.order(overwrite)
    const view = await pb.replica.capture()
    try { expect(view.read.query('SELECT title FROM tasks').rows).toEqual([[{ kind: 'text', value: 'first' }]]) } finally { view.release() }
    expect('publishFinal' in pb.runtime.coordinator).toBe(false)
    expect('finalRevision' in pb.runtime.queries).toBe(false)
  } finally {
    for (const peer of peers) await peer.close()
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)

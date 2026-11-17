import { mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { expect, it } from 'vitest'
import {
  DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime,
} from '@chronolog/materializer-doltlite'
import { APPLICATION_COLLECTIVE_ID, emit, encodeChangeProgram, executionManifestArtifacts, program } from '@chronolog/protocol'
import {
  bytesDigest, controlParticipantGrant, createGenerationRegistry, createPeerIdentity, createPeerReplica, MemoryPeerStore, peerDigest,
  signApplicationDescriptor, signApplicationSchema, signControlRevision, signTransitionRequest, verifyApplicationSchema,
  type PeerIdentity, type PeerReplica,
} from './index.js'
import { bytesToHex, hexToBytes } from './codec.js'

it('uses real deterministic SQL, protected signed genesis and coherent rollback under delegated order', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'peer-generation-sql-'))
  const peers: PeerReplica[] = []
  try {
    const host = await createPeerIdentity(), a = await createPeerIdentity(), b = await createPeerIdentity()
    const key = crypto.getRandomValues(new Uint8Array(32)), manifest = createDoltLiteExecutionManifest()
    const { executionManifestDigest } = await executionManifestArtifacts(manifest), applicationId = 'aa'.repeat(32), definitionDigest = 'bb'.repeat(32)
    const schema = await signApplicationSchema({ applicationId, definitionDigest, executionManifestDigest: bytesToHex(executionManifestDigest),
      program: bytesToHex(encodeChangeProgram(program('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT NOT NULL UNIQUE)'))) }, a)
    const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'sql-recovery', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      controlPublicKey: host.publicKey, schemaAdministrator: a.publicKey, executionManifestDigest: bytesToHex(executionManifestDigest), definitionDigest,
      schemaDigest: await peerDigest(schema) }, host)
    const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
      grants: [controlParticipantGrant(host.publicKey), ...[a, b].map(identity => ({ publicKey: identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: identity === a, dataRole: 'member' as const }))] }, host)
    const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'initial', expectedGeneration: null, requester: a.publicKey, coordinator: a.publicKey, controlRevision: 0, reason: 'create', base: null }, a))
    const open = async (identity: PeerIdentity, name: string) => {
      const materializer = await DeterministicMaterializer.open({ path: join(directory, `${name}.db`), executionManifest: manifest,
        rootAdministrator: hexToBytes(a.publicKey), historyProfile: 'peer-generation-v1',
        bootstrapGroupId: hexToBytes(applicationId), bootstrapProgram: await verifyApplicationSchema(schema, descriptor.payload), checkpointEvery: 1 })
      const runtime = createDoltLiteMaterializationRuntime(materializer)
      const replica = await createPeerReplica({ authority: await registry.read(), device: identity, store: new MemoryPeerStore(),
        storageId: name, materializer: runtime, epochKeys: new Map([[0, key]]) })
      peers.push(replica); return { replica, runtime }
    }
    const pa = await open(a, 'a'), pb = await open(b, 'b')
    const first = await pa.replica.prepare({ operationId: 'first', authorTimestampMs: 500n,
      program: program("INSERT INTO tasks (id,title) VALUES (1,'first')", emit('task.created', { id: 1 })) })
    await pa.replica.order(first)
    const base = await pa.replica.recoveryPoint()
    const duplicate = await pa.replica.prepare({ operationId: 'duplicate', authorTimestampMs: 100n,
      program: program("INSERT INTO tasks (id,title) VALUES (2,'first')", emit('task.created', { id: 2 })) })
    await pa.replica.order(duplicate); await pb.replica.ingest(await pa.replica.exportCommands())
    expect(await pa.replica.operation('first')).toMatchObject({ status: 'applied', outcome: 'accepted' })
    expect(await pa.replica.operation('duplicate')).toMatchObject({ status: 'applied', outcome: 'rejected', rejectionCode: 'constraint' })
    const av = await pa.replica.capture(), bv = await pb.replica.capture()
    try {
      expect(av.read.query('SELECT id,title FROM tasks ORDER BY id').rows).toEqual(bv.read.query('SELECT id,title FROM tasks ORDER BY id').rows)
      expect(av.outcomes).toEqual(bv.outcomes)
    } finally { av.release(); bv.release() }
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'takeover', expectedGeneration: pa.replica.generation.id, requester: b.publicKey, coordinator: b.publicKey,
      controlRevision: 0, reason: 'takeover', base }, b))
    await pb.replica.adopt(await registry.read()); await pa.replica.adopt(await registry.read())
    expect((await pa.replica.operation('duplicate'))?.status).toBe('abandoned')
    const forbidden = await pa.replica.prepare({ operationId: 'lossy-schema', program: program('CREATE TABLE forbidden (id INTEGER PRIMARY KEY)') })
    await pb.replica.order(forbidden)
    expect(await pb.replica.operation('lossy-schema', a.publicKey)).toMatchObject({ status: 'applied', outcome: 'rejected', rejectionCode: 'denied' })
    const overwrite = await pb.replica.prepare({ operationId: 'not-owner', program: program("UPDATE tasks SET title='stolen' WHERE id=1") })
    await pb.replica.order(overwrite)
    const view = await pb.replica.capture()
    try { expect(view.read.query('SELECT title FROM tasks').rows).toEqual([[{ kind: 'text', value: 'first' }]]) } finally { view.release() }
    const team = bytesToHex(APPLICATION_COLLECTIVE_ID)
    const shared = await pa.replica.prepare({ operationId: 'shared', program: program(
      `INSERT INTO tasks (id,title,chronolog_owner) VALUES (3,'shared',(SELECT id FROM chronolog_principals WHERE key=X'${team}'))`) })
    await pb.replica.order(shared)
    const sharedPoint = (await pb.replica.recoveryPoint()).point
    await pa.replica.close()
    const move = await pb.replica.prepare({ operationId: 'after-creator-loss', program: program("UPDATE tasks SET title='moved' WHERE id=3") })
    await pb.replica.order(move)
    expect(await pb.replica.operation('after-creator-loss')).toMatchObject({ outcome: 'accepted' })
    const nextControl = await signControlRevision({ ...control.payload, revision: 1, previous: await peerDigest(control),
      grants: control.payload.grants.map(grant => grant.publicKey === b.publicKey ? { ...grant, dataRole: null } : grant) }, host)
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'restrict-data', expectedGeneration: pb.replica.generation.id, requester: host.publicKey, coordinator: b.publicKey,
      controlRevision: 1, reason: 'control-change', base: await pb.replica.recoveryPoint() }, host), { control: nextControl })
    await pb.replica.adopt(await registry.read())
    const beforeRollback = await pb.replica.prefixProof(sharedPoint)
    await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
      transitionId: 'rollback-with-current-rights', expectedGeneration: pb.replica.generation.id, requester: host.publicKey, coordinator: b.publicKey,
      controlRevision: 1, reason: 'takeover', base: beforeRollback }, host))
    await pb.replica.adopt(await registry.read())
    const forbiddenMove = await pb.replica.prepare({ operationId: 'cannot-revive-data-role', program: program("UPDATE tasks SET title='stolen-team' WHERE id=3") })
    await pb.replica.order(forbiddenMove)
    expect(await pb.replica.operation('cannot-revive-data-role')).toMatchObject({ outcome: 'rejected' })
    const recovered = await pb.replica.capture()
    try { expect(recovered.read.query('SELECT title FROM tasks WHERE id=3').rows).toEqual([[{ kind: 'text', value: 'shared' }]]) } finally { recovered.release() }
    await expect(pb.runtime.coordinator.publishFinal!(1)).rejects.toThrow('FINALITY_UNSUPPORTED')
  } finally {
    for (const peer of peers) await peer.close()
    await rm(directory, { recursive: true, force: true })
  }
}, 60_000)

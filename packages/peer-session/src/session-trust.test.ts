import { afterEach, describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { createSigningIdentity, signRecord } from '@chronolog/authority'
import { decodeOperationCore, decodeSignedOperation, operationIdDigest } from '@chronolog/protocol'
import { createLogGenesis } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { createWrapKeyPair, importWrapPrivateKey } from './wrap-keys.js'
import { decodeSnapshotBundle, encodeSnapshotBundle } from './snapshot-codec.js'
import { replayBlindHostControl } from './kernel.js'
import { runEphemeralHostedSession } from './hosted-runner.js'
import type { ApplicationSession } from './session.js'

const KV = `
export default {
  reduce(state, tx) {
    const next = Object.assign({}, state || {});
    next[tx.payload.key] = tx.payload.value;
    return { ok: true, state: next };
  },
  query(state, input) { return input && input.key ? (state || {})[input.key] ?? null : null; },
};
`

async function member() {
  const identity = await createSigningIdentity()
  const pair = await createWrapKeyPair()
  return { identity, wrap: { publicKey: pair.publicKey, privateKey: await importWrapPrivateKey(pair.privateKey) } }
}
type Member = Awaited<ReturnType<typeof member>>

const closes: (() => Promise<void>)[] = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close().catch(() => undefined) })

async function fixture(privateLog: boolean, admins = 1, admissionModule?: string) {
  const [a, b] = await Promise.all([member(), member()])
  const created = await createLogGenesis({
    creator: { publicKey: a.identity.publicKey, wrapKey: a.wrap.publicKey, reader: true, writer: true, administrator: true },
    members: [{ publicKey: b.identity.publicKey, wrapKey: b.wrap.publicKey, reader: true, writer: true, administrator: admins > 1 }],
    privateLog,
    imports: { 'app/kv': KV, ...(admissionModule === undefined ? {} : { 'app/admission': admissionModule }) },
    topics: {
      kv: { module: 'app/kv', initialState: {} },
      ...(admissionModule === undefined ? {} : { $admission: { module: 'app/admission' } }),
    },
  })
  const epochKeys = created.epoch0Key === undefined ? undefined : new Map([[0, created.epoch0Key]])
  const open = async (store: MemoryBytesStore, m: Member, extra: { readonly snapshotBootstrap?: boolean } = {}): Promise<ApplicationSession> => {
    const session = await createApplicationSession({
      device: await openApplicationDevice({ store, create: true, managedSigner: m.identity, managedWrapKey: m.wrap }),
      genesis: created.genesisBytes, casNodes: created.casNodes, ...(epochKeys === undefined ? {} : { epochKeys }), ...extra,
    })
    closes.push(() => session.close())
    return session
  }
  return { a, b, created, open }
}

async function set(session: ApplicationSession, key: string, value: number, ts: number): Promise<string> {
  const op = await session.command('set', { key, value }, { authorTimestampMs: BigInt(ts) })
  expect((await op.materialized()).outcome).toBe('accepted')
  return op.id
}

const opIdOf = (raw: Uint8Array): string => Buffer.from(operationIdDigest(decodeSignedOperation(raw).coreBytes)).toString('hex')

describe('snapshot trust (S1/S2)', () => {
  it('keeps a member-signed snapshot provisional and drops it when replay disagrees', async () => {
    const { a, b, open } = await fixture(false)
    const sessA = await open(new MemoryBytesStore(), a)
    for (let i = 0; i < 20; i++) await set(sessA, `k${i % 3}`, i, 1_000 + i)
    // The attacker (a member: on open logs anyone is) builds a bundle whose topics come from a
    // different history but which claims to cover exactly A's ops.
    const scratch = await open(new MemoryBytesStore(), b)
    for (let i = 0; i < 20; i++) await set(scratch, `k${i % 3}`, 999, 2_000 + i)
    const forgedSource = (await decodeSnapshotBundle((await scratch.exportMaterializedSnapshot())!, scratch.logId, () => undefined))!
    const facts = await sessA.exportFacts()
    const forged = await encodeSnapshotBundle({
      logId: sessA.logId,
      cache: { ...forgedSource.cache, frontierOpIds: facts.publicOps.map(opIdOf), frontierMaxTimestampMs: 1_019n },
      casNodes: forgedSource.casNodes,
      identity: b.identity,
    })

    const victim = await open(new MemoryBytesStore(), a, { snapshotBootstrap: false })
    expect(await victim.importMaterializedSnapshot(forged)).toBe(true)
    expect(victim.snapshotProvisional).toBe(true)
    // Unverified state is never re-exported or persisted.
    expect(await victim.exportMaterializedSnapshot()).toBeNull()

    await victim.mergeFacts({ ...facts, casNodes: [], retentions: [] })
    expect(victim.snapshotProvisional).toBe(false)
    expect(victim.rejectedSnapshots).toBe(1)
    expect(await victim.query('kv', { key: 'k1' })).toEqual(await sessA.query('kv', { key: 'k1' }))
    expect(victim.revision().stateRoot).toBe(sessA.revision().stateRoot)
  })
})

describe('multi-tab store sync (B1)', () => {
  it('never skips a sibling commit that landed before this tab wrote', async () => {
    const { a, open } = await fixture(false)
    const shared = new MemoryBytesStore()
    const tab1 = await open(shared, a)
    const tab2 = await open(shared, a)
    const sibling = await set(tab2, 'sibling', 1, 1_000)
    await set(tab1, 'own', 2, 2_000) // tab1's own write advances the store sequence past the sibling commit
    await tab1.syncFromStore()
    expect(tab1.inspectOperation(sibling).materialized?.outcome).toBe('accepted')
    expect((await tab1.query('kv', { key: 'sibling' })).value).toBe(1)
  })
})

describe('retention receipts and local-pending (B5)', () => {
  it('signs only for held ops, ignores non-member receipts and settles retained pending ops', async () => {
    const { a, b, open } = await fixture(true)
    const storeA = new MemoryBytesStore()
    const sessA = await open(storeA, a)
    const sessB = await open(new MemoryBytesStore(), b)
    const opId = await set(sessA, 'x', 1, 1_000)
    expect(await sessA.retainMany([{ opId: 'ab'.repeat(32) }])).toEqual([])
    await expect(sessA.retain('ab'.repeat(32), { author: a.identity.publicKey, envelopeDigest: 'aa'.repeat(32) })).rejects.toThrow('RETENTION_OP_NOT_HELD')

    const pendingKey = `v2/${sessA.logId}/local-pending/${opId}`
    expect(await storeA.get(pendingKey)).not.toBeNull()

    const outsider = await createSigningIdentity()
    const spam = await signRecord('operation-retention', { applicationId: sessA.applicationId, peer: outsider.publicKey, storageId: 'x', items: [opId] }, outsider)
    await sessA.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: [], retentions: [spam], evidence: [] })
    expect((await sessA.exportFacts()).retentions.some(r => r.signer === outsider.publicKey)).toBe(false)
    expect(await storeA.get(pendingKey)).not.toBeNull()

    await sessB.mergeFacts(await sessA.exportFacts())
    const [receipt] = await sessB.retainMany([{ opId }])
    await sessA.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: [], retentions: [receipt!], evidence: [] })
    expect(await storeA.get(pendingKey)).toBeNull()
    // Idempotency survives settlement.
    const again = await sessA.command('set', { key: 'x', value: 1 }, { operationId: (sessA.inspectOperation(opId)).operationId })
    expect(again.id).toBe(opId)
  })
})

describe('control plane (B7)', () => {
  it('gives history policy the same operation metadata on blind and decrypting replicas', async () => {
    const { a, open, created } = await fixture(true, 1, `
      import { attestedAdmission } from 'chronolog/admission';
      export default { ...attestedAdmission, admit(_state, { ops }) {
        return { excludedOpIds: ops.some(op => op.visibility === 'encrypted') ? ops.map(op => op.opId) : [] };
      } };
    `)
    const session = await open(new MemoryBytesStore(), a)
    const next = await member()
    const admission = await session.admitMember({ publicKey: next.identity.publicKey, authorTimestampMs: 10n })
    expect((await admission.materialized()).outcome).toBe('accepted')
    await set(session, 'private', 1, 20)
    const facts = await session.exportPublicControlFacts()
    const blind = await replayBlindHostControl({
      genesis: created.genesis,
      publicOps: facts.publicOps.map(raw => {
        const signed = decodeSignedOperation(raw)
        return { opId: operationIdDigest(signed.coreBytes), core: decodeOperationCore(signed.coreBytes), verified: true }
      }),
      publicCasNodes: facts.casNodes,
    })
    expect(blind.topics.$admission).toEqual(session.topic('$admission'))
    expect(session.isMember(next.identity.publicKey)).toBe(true)
  })

  it('blind host and full replica derive identical control state when evidence excludes an op', async () => {
    const { a, open, created } = await fixture(false)
    const sessA = await open(new MemoryBytesStore(), a)
    const [x, y] = await Promise.all([member(), member()])
    const first = await sessA.admitMember({ publicKey: x.identity.publicKey, authorTimestampMs: 10n })
    await sessA.admitMember({ publicKey: y.identity.publicKey, authorTimestampMs: 20n })
    const facts = await sessA.exportPublicControlFacts()
    const included = facts.publicOps.map(opIdOf).filter(id => id === first.id)
    const pinned = { closedThroughMs: 25n, stateRoot: '00'.repeat(32), historyDigest: '00'.repeat(32), includedOpIds: included }
    await sessA.admission.pinFrontier(pinned)
    expect(sessA.isMember(y.identity.publicKey)).toBe(false)

    const blind = await replayBlindHostControl({
      genesis: created.genesis,
      publicOps: facts.publicOps.map(raw => {
        const signed = decodeSignedOperation(raw)
        return { opId: operationIdDigest(signed.coreBytes), core: decodeOperationCore(signed.coreBytes), verified: true }
      }),
      publicCasNodes: facts.casNodes.map(n => ({ hash: n.hash, bytes: n.bytes })),
      pinnedFrontier: pinned,
    })
    expect(blind.admission.excludedOpIds.size).toBe(1)
    expect(blind.topics.$admission).toEqual(sessA.topic('$admission'))
    expect(blind.roster.members.map(m => m.publicKey)).not.toContain(y.identity.publicKey)
  })
})

describe('commitment-bound keys', () => {
  it('a member whose concurrent rotation lost adopts the winning key and rewraps its pending op', async () => {
    const { a, b, open } = await fixture(true, 2)
    const sessA = await open(new MemoryBytesStore(), a)
    const sessB = await open(new MemoryBytesStore(), b)
    await sessA.rotateEpoch({ authorTimestampMs: 100n })
    await sessB.rotateEpoch({ authorTimestampMs: 200n }) // loses: epoch 1 already taken by A once merged
    const pending = await set(sessB, 'from-b', 7, 300)
    await sessB.mergeFacts(await sessA.exportFacts())
    await sessA.mergeFacts(await sessB.exportFacts())
    expect(sessB.epochKey(1)).toEqual(sessA.epochKey(1))
    expect(sessA.inspectOperation(pending).materialized?.outcome).toBe('accepted')
    expect((await sessA.query('kv', { key: 'from-b' })).value).toBe(7)
  })

  it('wipeSecrets zeroes every held key', async () => {
    const { a, open } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    expect(sessA.hasEpochKey(0)).toBe(true)
    await sessA.wipeSecrets()
    expect(sessA.hasEpochKey(0)).toBe(false)
    expect(sessA.exportEpochKeys().size).toBe(0)
  })
})

describe('hosted runner (B4)', () => {
  it('does not report hydrated private CAS as pruned for a non-reader runner', async () => {
    const { a, open, created } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    await set(sessA, 'k', 1, 1_000)
    const outsider = await createSigningIdentity()
    const plain = new TextEncoder().encode('private node')
    const hash = await sessA.cas.put(plain, [], 'private')
    const raw = (await sessA.cas.getRaw(hash, 'private'))!
    const facts = await sessA.exportFacts()
    const { delta } = await runEphemeralHostedSession({
      genesisBytes: created.genesisBytes,
      signer: outsider,
      epochKeys: new Map(),
      publicOps: facts.publicOps,
      encryptedEnvelopes: facts.encryptedEnvelopes,
      publicCasNodes: [],
      sealedPrivateCas: [{ hash, sealed: raw }],
      unsealPrivateCas: async (_h, sealed) => sealed,
      sealPrivateCas: async (_h, bytes) => bytes,
    }, async () => null)
    expect(delta.prunedPrivateCasHashes).toEqual([])
    expect(delta.newEnvelopes).toEqual([])
    expect(delta.newPublicOps).toEqual([])
  })
})


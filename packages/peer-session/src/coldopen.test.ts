import { describe, expect, it } from 'vitest'
import { MemoryBytesStore } from '@chronolog/records'
import { createSigningIdentity } from '@chronolog/authority'
import { decodeMaterializedCache, encodeMaterializedCache } from '@chronolog/materializer'
import { perfCounters, resetPerfCounters } from '@chronolog/canonical'
import { createLogGenesis } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import { createFramedPeerConnectionPair } from './network-wire.js'
import { createWrapKeyPair, importWrapPrivateKey } from './wrap-keys.js'
import type { ApplicationSession } from './session.js'

const KV = `
export default {
  reduce(state, tx) {
    const next = Object.assign({}, state || {});
    const p = tx.payload || {};
    next[p.key] = p.value;
    return { ok: true, state: next, events: [{ topic: 'kv.set', payload: { key: p.key } }] };
  },
  query(state, input) { return input && input.key ? (state || {})[input.key] ?? null : Object.keys(state || {}).length; },
};
`

async function member() {
  const identity = await createSigningIdentity()
  const pair = await createWrapKeyPair()
  return { identity, wrap: { publicKey: pair.publicKey, privateKey: await importWrapPrivateKey(pair.privateKey) } }
}

async function until(predicate: () => boolean, timeoutMs = 20_000): Promise<void> {
  const start = Date.now()
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error('timeout')
    await new Promise(resolve => setTimeout(resolve, 2))
  }
}

async function fixture(privateLog: boolean) {
  const [a, b] = await Promise.all([member(), member()])
  const created = await createLogGenesis({
    creator: { publicKey: a.identity.publicKey, wrapKey: a.wrap.publicKey, reader: true, writer: true, administrator: true },
    members: [{ publicKey: b.identity.publicKey, wrapKey: b.wrap.publicKey, reader: true, writer: true }],
    privateLog,
    imports: { 'app/kv': KV },
    topics: { kv: { module: 'app/kv', initialState: {} } },
  })
  const epochKeys = created.epoch0Key === undefined ? undefined : new Map([[0, created.epoch0Key]])
  const open = async (store: MemoryBytesStore, m: typeof a, extra: { readonly snapshotBootstrap?: boolean } = {}): Promise<ApplicationSession> => createApplicationSession({
    device: await openApplicationDevice({ store, create: true, managedSigner: m.identity, managedWrapKey: m.wrap }),
    genesis: created.genesisBytes, casNodes: created.casNodes, ...(epochKeys === undefined ? {} : { epochKeys }), ...extra,
  })
  return { a, b, open }
}

async function author(session: ApplicationSession, from: number, count: number, tsBase = 1_000): Promise<void> {
  for (let i = from; i < from + count; i++) {
    const op = await session.command('set', { key: `k${i % 7}`, value: i }, { authorTimestampMs: BigInt(tsBase + i) })
    expect((await op.materialized()).outcome).toBe('accepted')
  }
}

async function link(x: ApplicationSession, y: ApplicationSession) {
  const [cx, cy] = createFramedPeerConnectionPair()
  return Promise.all([x.connectPeer({ connection: cx }), y.connectPeer({ connection: cy })])
}

describe('cold open and snapshot bootstrap', () => {
  it('round-trips the binary materialized cache', () => {
    const cache = {
      v: 2 as const, logId: 'ab'.repeat(32), blindHostMode: false, topics: { kv: { a: 1, b: [true, null, 'x'] } },
      seenOpsRoot: 'cd'.repeat(32), historyDigest: 'ef'.repeat(32), stateRoot: '01'.repeat(32),
      frontierOpIds: ['02'.repeat(32)], frontierMaxTimestampMs: 7n, orderOpIds: ['03'.repeat(32)],
      outcomes: [{
        opId: '03'.repeat(32), author: '04'.repeat(32), operationId: 'op-1', authorTimestampMs: 9n, visibility: 'encrypted' as const,
        outcome: 'rejected' as const, rejectionCode: 'x', rejectionDetail: 'why', conflictRecorded: true,
        events: [{ opId: '03'.repeat(32), eventOrdinal: 0, topic: 't', payload: { k: 1 }, author: '04'.repeat(32), operationId: 'op-1', authorTimestampMs: 9n }],
      }],
      topicLastOpIds: { kv: '03'.repeat(32) },
    }
    expect(decodeMaterializedCache(encodeMaterializedCache(cache))).toEqual(cache)
    expect(decodeMaterializedCache(Uint8Array.of(1, 2, 3))).toBeNull()
  })

  it('persists the cache right after the first materialization and reopens from it', async () => {
    const { a, open } = await fixture(true)
    const store = new MemoryBytesStore()
    const session = await open(store, a)
    await author(session, 0, 5)
    const keyOf = async () => (await store.entries()).some(e => e.key.endsWith('/materialized-cache'))
    await new Promise(resolve => setTimeout(resolve, 50))
    expect(await keyOf()).toBe(true)
    const digest = session.revision().digest
    await session.close()
    resetPerfCounters()
    const reopened = await open(store, a)
    try {
      expect(reopened.revision().digest).toBe(digest)
      // Own-store envelopes covered by the cache are neither replayed nor re-verified.
      expect(perfCounters()['vm.reduce'] ?? 0).toBe(0)
      expect(perfCounters()['ed25519.verify'] ?? 0).toBe(0)
      expect(reopened.readEvents({ limit: 512 }).events).toHaveLength(5)
    } finally {
      await reopened.close()
    }
  })

  for (const privateLog of [true, false]) {
    it(`bootstraps a fresh peer from a snapshot, then confirms it by one replay (${privateLog ? 'private' : 'public'} log)`, async () => {
      const { a, b, open } = await fixture(privateLog)
      const sessA = await open(new MemoryBytesStore(), a)
      await author(sessA, 0, 30)
      const sessB = await open(new MemoryBytesStore(), b)
      try {
        resetPerfCounters()
        const [la, lb] = await link(sessA, sessB)
        await Promise.all([la.synchronize(), lb.synchronize()])
        await until(() => sessB.revision().digest === sessA.revision().digest)
        expect(perfCounters()['wire.send.snapshot'] ?? 0).toBe(1)
        // A peer snapshot without admission evidence is first paint only: once B holds every op it
        // covers, B replays them exactly once and keeps its own replay (30 ops, never more).
        await until(() => !sessB.snapshotProvisional)
        expect(sessB.rejectedSnapshots).toBe(0)
        expect(perfCounters()['vm.reduce'] ?? 0).toBeLessThanOrEqual(35)
        expect(await sessB.query('kv', { key: 'k3' })).toEqual(await sessA.query('kv', { key: 'k3' }))
        // B keeps authoring on top of the frontier and A converges.
        await author(sessB, 30, 2, 100_000)
        await until(() => sessA.revision().digest === sessB.revision().digest)
        // A late op that sorts before the frontier forces a full, deterministic replay on B.
        await author(sessA, 40, 1, 500)
        await until(() => sessB.revision().digest === sessA.revision().digest)
        await Promise.all([la.close(), lb.close()])
      } finally {
        await Promise.all([sessA.close(), sessB.close()])
      }
    })
  }

  it('exports one snapshot per revision for any number of bootstrapping links', async () => {
    const { a, b, open } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    await author(sessA, 0, 20)
    let exports = 0
    const original = sessA.exportMaterializedSnapshot.bind(sessA)
    sessA.exportMaterializedSnapshot = (options => { exports++; return original(options) })
    const fresh = await Promise.all([open(new MemoryBytesStore(), b), open(new MemoryBytesStore(), b), open(new MemoryBytesStore(), b)])
    try {
      resetPerfCounters()
      const links = await Promise.all(fresh.map(peer => link(sessA, peer)))
      await Promise.all(links.flat().map(l => l.synchronize()))
      for (const peer of fresh) await until(() => peer.revision().digest === sessA.revision().digest)
      expect(perfCounters()['wire.send.snapshot'] ?? 0).toBe(3)
      expect(exports).toBe(1)
      await Promise.all(links.flat().map(l => l.close()))
    } finally {
      await Promise.all([sessA.close(), ...fresh.map(peer => peer.close())])
    }
  })

  it('replays history when snapshot bootstrap is disabled', async () => {
    const { a, b, open } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    await author(sessA, 0, 10)
    const sessB = await open(new MemoryBytesStore(), b, { snapshotBootstrap: false })
    try {
      resetPerfCounters()
      const [la, lb] = await link(sessA, sessB)
      await until(() => sessB.revision().digest === sessA.revision().digest)
      expect(perfCounters()['wire.send.snapshot'] ?? 0).toBe(0)
      expect(perfCounters()['vm.reduce'] ?? 0).toBeGreaterThanOrEqual(10)
      await Promise.all([la.close(), lb.close()])
    } finally {
      await Promise.all([sessA.close(), sessB.close()])
    }
  })

  it('skips P2P snapshot bootstrap for tiny logs (<16 ops) so replay is faster and preserves events', async () => {
    const { a, b, open } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    await author(sessA, 0, 3)
    const sessB = await open(new MemoryBytesStore(), b)
    try {
      resetPerfCounters()
      const [la, lb] = await link(sessA, sessB)
      await Promise.all([la.synchronize(), lb.synchronize()])
      await until(() => sessB.revision().digest === sessA.revision().digest)
      expect(perfCounters()['wire.send.snapshot'] ?? 0).toBe(1) // null snapshot reply
      expect(sessB.readEvents({ limit: 32 }).events).toHaveLength(3)
      await Promise.all([la.close(), lb.close()])
    } finally {
      await Promise.all([sessA.close(), sessB.close()])
    }
  })

  it('attests retention over P2P for peer-authored ops previously synced out-of-band (e.g. host mailbox)', async () => {
    const { a, b, open } = await fixture(true)
    const sessA = await open(new MemoryBytesStore(), a)
    const op = await sessA.command('set', { key: 'k0', value: 42 }, { operationId: 'mailbox-op-1' })
    expect((await op.materialized()).outcome).toBe('accepted')
    const exported = await sessA.exportFacts()
    const sessB = await open(new MemoryBytesStore(), b)
    try {
      // Simulate host mailbox delivery before P2P connects
      await sessB.mergeFacts(exported)
      expect((await sessB.query('kv', { key: 'k0' })).value).toBe(42)
      const [la, lb] = await link(sessA, sessB)
      await Promise.all([la.synchronize(), lb.synchronize()])
      await until(() => sessA.inspectOperation('mailbox-op-1').retained.some(r => r.signer === b.identity.publicKey))
      expect(sessA.inspectOperation('mailbox-op-1').retained.some(r => r.signer === b.identity.publicKey)).toBe(true)
      await Promise.all([la.close(), lb.close()])
    } finally {
      await Promise.all([sessA.close(), sessB.close()])
    }
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { bytesToHex, hexToBytes } from '@chronolog/canonical'
import { MemoryBytesStore } from '@chronolog/records'
import { createLogGenesis, hpkeSealEpochKey, epochKeyCommitmentV2 } from './genesis.js'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationSession, SessionFacts } from './session.js'

const closes: Array<() => Promise<void>> = []
afterEach(async () => {
  for (const close of closes.splice(0).reverse()) {
    try { await close() } catch { /* ignore cleanup */ }
  }
})

/** Deterministic Mulberry32 PRNG so every chaos seed is 100% reproducible. */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6D2B79F5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function shuffle<T>(items: readonly T[], rng: () => number): T[] {
  const arr = items.slice()
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1))
    const tmp = arr[i]!
    arr[i] = arr[j]!
    arr[j] = tmp
  }
  return arr
}

function shuffleFacts(facts: SessionFacts, rng: () => number): SessionFacts {
  return {
    ...(facts.genesisBytes === undefined ? {} : { genesisBytes: facts.genesisBytes }),
    publicOps: shuffle(facts.publicOps, rng),
    encryptedEnvelopes: shuffle(facts.encryptedEnvelopes, rng),
    casNodes: shuffle(facts.casNodes, rng),
    retentions: shuffle(facts.retentions, rng),
    checkpoints: shuffle(facts.checkpoints, rng),
  }
}

async function gossipPair(a: ApplicationSession, b: ApplicationSession, rng: () => number): Promise<void> {
  const fa = shuffleFacts(await a.exportFacts(), rng)
  const fb = shuffleFacts(await b.exportFacts(), rng)
  await b.mergeFacts(fa)
  await a.mergeFacts(fb)
}

const COUNTER_REDUCER = `
export default {
  reduce(state, tx) {
    const cur = state && typeof state === 'object' ? { ...state } : { total: 0, log: [] };
    const delta = Number(tx.payload && tx.payload.delta || 0);
    if (!Number.isFinite(delta) || cur.total + delta < 0) return { ok: false, code: 'negative_total' };
    return {
      ok: true,
      state: { total: cur.total + delta, log: cur.log.concat([tx.operationId]).slice(-20) },
      events: [{ topic: 'counter.changed', payload: { delta, total: cur.total + delta } }],
    };
  },
  query(state) { return state || { total: 0, log: [] }; },
};
`.trimStart()

describe('Chronolog v2 Multi-Replica Chaos Suite', () => {
  it.each([42, 1337])(
    'converges bit-for-bit under random concurrent SQL/JSON ops, partitions, out-of-order gossip, epoch rotation + offline rewrapping, GC, and blind-host parity (seed=%i)',
    async (seed) => {
      const rng = mulberry32(seed)

      const devAdmin = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const devB = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const devC = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const devRevoked = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const devBlind = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })

      const created = await createLogGenesis({
        creator: {
          publicKey: devAdmin.identity.publicKey,
          wrapKey: devAdmin.wrapKey.publicKey,
          reader: true,
          writer: true,
          administrator: true,
          publisher: true,
        },
        members: [
          { publicKey: devB.identity.publicKey, wrapKey: devB.wrapKey.publicKey, reader: true, writer: true },
          { publicKey: devC.identity.publicKey, wrapKey: devC.wrapKey.publicKey, reader: true, writer: true },
          { publicKey: devRevoked.identity.publicKey, wrapKey: devRevoked.wrapKey.publicKey, reader: true, writer: true },
        ],
        privateLog: true,
        imports: { 'app/counter': COUNTER_REDUCER },
        topics: {
          counter: { module: 'app/counter', initialState: { total: 100, log: [] } },
          ledger: { module: 'chronolog/sql' },
        },
      })

      const epoch0 = created.epoch0Key!
      const openPeer = async (device: typeof devAdmin, blindHostMode = false, withKey = true) => {
        const s = await createApplicationSession({
          device,
          genesis: created.genesisBytes,
          casNodes: created.casNodes,
          blindHostMode,
          ...(withKey && !blindHostMode ? { epochKeys: new Map([[0, epoch0]]) } : {}),
        })
        closes.push(() => s.close())
        return s
      }

      const admin = await openPeer(devAdmin)
      const peerB = await openPeer(devB)
      const peerC = await openPeer(devC)
      const peerRevoked = await openPeer(devRevoked)
      const blindHost = await openPeer(devBlind, true, false)

      // Publish epoch 0 boxes on $keys so everyone has formal epoch 0 state
      const epoch0Boxes: Record<string, { encapsulatedKey: string; ciphertext: string }> = {}
      for (const dev of [devAdmin, devB, devC, devRevoked]) {
        epoch0Boxes[dev.identity.publicKey] = await hpkeSealEpochKey(dev.wrapKey.publicKey, epoch0, created.logId, 0)
      }
      await admin.submit({
        authorTimestampMs: 10n,
        visibility: 'public',
        updates: [{
          topic: '$keys',
          input: {
            action: 'rotateEpoch',
            epoch: 0,
            keyCommitment: epochKeyCommitmentV2(epoch0),
            boxes: epoch0Boxes,
          },
        }],
      })

      // Initialize ledger SQL schema + write RLS
      const mig = await admin.submit({
        authorTimestampMs: 20n,
        updates: [{
          topic: 'ledger',
          input: {
            action: 'migrate',
            statements: [
              'CREATE TABLE accounts (id TEXT PRIMARY KEY, owner TEXT NOT NULL, balance INTEGER NOT NULL CHECK(balance >= 0))',
              `INSERT INTO accounts (id, owner, balance) VALUES ('shared', '${devAdmin.identity.publicKey}', 50)`,
              `INSERT INTO accounts (id, owner, balance) VALUES ('acctB', '${devB.identity.publicKey}', 50)`,
              `INSERT INTO accounts (id, owner, balance) VALUES ('acctC', '${devC.identity.publicKey}', 50)`,
            ],
            policies: {
              accounts: {
                insert: 'NEW.owner = actor()',
                update: 'OLD.owner = actor() AND NEW.owner = actor()',
                delete: 'OLD.owner = actor()',
              },
            },
          },
        }],
      })
      expect((await mig.materialized()).outcome).toBe('accepted')

      // Initial sync to all replicas including blind host
      for (const p of [peerB, peerC, peerRevoked, blindHost]) {
        await gossipPair(admin, p, rng)
      }

      // PHASE 1: Network partition — Partition 1: {admin, peerC}, Partition 2: {peerB, peerRevoked}
      // Random concurrent ops with overlapping timestamps, failing preconditions, and RLS violation probes
      const allPeers = [admin, peerB, peerC, peerRevoked]
      const acctByPeer = new Map<ApplicationSession, string>([
        [admin, 'shared'],
        [peerB, 'acctB'],
        [peerC, 'acctC'],
        [peerRevoked, 'acctB'], // intentionally wrong owner -> will hit RLS denial on update!
      ])

      for (let step = 0; step < 24; step++) {
        const actor = allPeers[Math.floor(rng() * allPeers.length)]!
        const ts = BigInt(100 + Math.floor(rng() * 40)) // deliberate timestamp interleaving!
        const roll = rng()

        if (roll < 0.4) {
          const delta = Math.floor(rng() * 15) - 5 // some negative, some positive
          await actor.submit({
            authorTimestampMs: ts,
            updates: [{ topic: 'counter', input: { delta } }],
          })
        } else if (roll < 0.85) {
          const acct = acctByPeer.get(actor)!
          const amount = Math.floor(rng() * 20) + 1
          const withdraw = rng() < 0.6
          await actor.submit({
            authorTimestampMs: ts,
            updates: [{
              topic: 'ledger',
              input: withdraw
                ? {
                    preconditions: [{
                      sql: 'SELECT balance >= ? FROM accounts WHERE id = ?',
                      params: [amount, acct],
                      code: 'insufficient_funds',
                    }],
                    statements: [{ sql: 'UPDATE accounts SET balance = balance - ? WHERE id = ?', params: [amount, acct] }],
                  }
                : {
                    statements: [{ sql: 'UPDATE accounts SET balance = balance + ? WHERE id = ?', params: [amount, acct] }],
                  },
            }],
          })
        } else {
          // Non-admin user-owned table creation
          const tbl = `note_${step}_${Math.floor(rng() * 100)}`
          await actor.submit({
            authorTimestampMs: ts,
            updates: [{
              topic: 'ledger',
              input: {
                statements: [
                  `CREATE TABLE IF NOT EXISTS ${tbl} (k TEXT PRIMARY KEY, v INTEGER)`,
                  { sql: `INSERT OR REPLACE INTO ${tbl} (k, v) VALUES (?, ?)`, params: ['x', step] },
                ],
              },
            }],
          })
        }

        // Intra-partition shuffled gossip only
        if (step % 4 === 0) {
          await gossipPair(admin, peerC, rng)
          await gossipPair(peerB, peerRevoked, rng)
        }
      }

      // PHASE 2: While peerB is still partitioned offline, admin revokes peerRevoked & rotates to epoch 1!
      await admin.removeMember(devRevoked.identity.publicKey, { rotateEpoch: true, authorTimestampMs: 200n })
      expect(admin.currentEpoch()).toBe(1)

      // peerB authors an offline encrypted op under epoch 0 BEFORE hearing about epoch 1
      const offlineOpB = await peerB.submit({
        authorTimestampMs: 210n,
        updates: [{
          topic: 'ledger',
          input: {
            statements: [{ sql: 'UPDATE accounts SET balance = balance + 7 WHERE id = ?', params: ['acctB'] }],
          },
        }],
      })

      // PHASE 3: Partition heals! Shuffled multi-round gossip across all authorized peers + blind host
      for (let round = 0; round < 4; round++) {
        const pairs: [ApplicationSession, ApplicationSession][] = [
          [admin, peerB],
          [peerB, peerC],
          [peerC, admin],
          [admin, blindHost],
          [peerB, blindHost],
        ]
        for (const [x, y] of shuffle(pairs, rng)) {
          await gossipPair(x, y, rng)
        }
      }

      // Verify peerB unlocked epoch 1, automatically rewrapped its offline op, and all 3 active peers converged!
      expect(peerB.currentEpoch()).toBe(1)
      expect(peerB.hasEpochKey(1)).toBe(true)
      expect((await offlineOpB.materialized()).outcome).toBe('accepted')

      // Run CAS GC on admin and ensure queries still work identically after sweep
      const gcStats = await admin.collectGarbage()
      expect(gcStats.kept).toBeGreaterThan(0)

      // Assert exact bit-for-bit convergence across admin, peerB, peerC!
      const refRev = admin.revision()
      const refAccounts = await admin.query('ledger', { sql: 'SELECT id, balance FROM accounts ORDER BY id', format: 'objects' })
      const refCounter = admin.topic('counter')

      for (const peer of [peerB, peerC]) {
        expect(peer.revision().stateRoot).toBe(refRev.stateRoot)
        expect(peer.revision().historyDigest).toBe(refRev.historyDigest)
        expect(peer.revision().digest).toBe(refRev.digest)
        expect(peer.topic('counter')).toEqual(refCounter)
        expect(await peer.query('ledger', { sql: 'SELECT id, balance FROM accounts ORDER BY id', format: 'objects' })).toEqual(refAccounts)
      }

      // Assert Blind Host derived IDENTICAL control topics ($permissions, $keys, $reducers) without holding any epoch keys!
      expect(blindHost.hasEpochKey(0)).toBe(false)
      expect(blindHost.hasEpochKey(1)).toBe(false)
      expect(blindHost.topic('$permissions')).toEqual(admin.topic('$permissions'))
      expect(blindHost.topic('$keys')).toEqual(admin.topic('$keys'))
      expect(blindHost.topic('$reducers')).toEqual(admin.topic('$reducers'))
      expect(blindHost.isReader(devRevoked.identity.publicKey)).toBe(false)

      // PHASE 4: Fresh peer joins from cold start using exported facts and verifies bit-for-bit parity!
      const devFresh = await openApplicationDevice({ store: new MemoryBytesStore(), create: true })
      const fresh = await createApplicationSession({
        device: devFresh,
        genesis: created.genesisBytes,
        casNodes: created.casNodes,
        epochKeys: new Map([[0, epoch0], [1, admin.epochKey(1)!]]),
      })
      closes.push(() => fresh.close())
      await fresh.mergeFacts(shuffleFacts(await admin.exportFacts(), rng))
      expect(fresh.revision().stateRoot).toBe(refRev.stateRoot)
      expect(fresh.revision().digest).toBe(refRev.digest)
      expect(await fresh.query('ledger', { sql: 'SELECT id, balance FROM accounts ORDER BY id', format: 'objects' })).toEqual(refAccounts)

      // Silence unused import warning for hexToBytes/bytesToHex if not needed
      expect(bytesToHex(hexToBytes(refRev.stateRoot))).toBe(refRev.stateRoot)
    },
    90_000,
  )
})

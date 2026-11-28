/**
 * Chronolog cold-open and fresh-device bootstrap benchmark.
 *
 *   pnpm tsx bench/coldopen.bench.ts
 *   pnpm tsx bench/coldopen.bench.ts --sizes 400,2000,5000 --stores memory,native --json bench/results/coldopen.json
 *
 * Scenarios (each per log size N, SQL reducer, private log by default):
 *   reopen          close + reopen the authoring device + session from its store (median of 3),
 *                   per store kind (MemoryBytesStore, NativeBytesStore over node:sqlite)
 *   reopenNoCache   same, with the persisted materialized cache deleted (full replay from history)
 *   fresh           a fresh peer connects and reaches the author's revision (full history replay)
 *   freshSnapshot   same, with sync-v3 snapshot bootstrap (frontier restore + suffix only)
 */
import { performance } from 'node:perf_hooks'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir, loadavg } from 'node:os'
import { join } from 'node:path'
import { Session as InspectorSession } from 'node:inspector/promises'
import type { BytesStore } from '@chronolog/records'
import { MemoryBytesStore } from '@chronolog/records'
import { NativeBytesStore } from '@chronolog/records/native'
import { createSigningIdentity } from '@chronolog/authority'
import { createLogGenesis } from '../packages/peer-session/src/genesis.js'
import { openApplicationDevice } from '../packages/peer-session/src/device.js'
import { createApplicationSession } from '../packages/peer-session/src/runtime.js'
import type { ApplicationSession } from '../packages/peer-session/src/session.js'
import { createFramedPeerConnectionPair } from '../packages/peer-session/src/network-wire.js'
import { createWrapKeyPair, importWrapPrivateKey } from '../packages/peer-session/src/wrap-keys.js'
import { perfCounters, resetPerfCounters } from '../packages/canonical/src/perf.js'

const SQL_REDUCER = `
import { openDb } from 'chronolog:sqlite';
export default {
  reduce(state, tx) {
    const db = openDb(state);
    db.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)', [], { mode: 'admin' });
    const p = tx.payload || {};
    db.exec('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', [p.key, String(p.value)], { mode: 'admin' });
    return { ok: true, state: db.commit() };
  },
  query(state) {
    const db = openDb(state);
    if (db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='kv'").rows.length === 0) return null;
    return db.query('SELECT count(*) FROM kv').rows[0][0];
  },
};
`

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1]! : fallback
}
const sizes = arg('sizes', '400,2000').split(',').map(Number)
const storeKinds = arg('stores', 'memory,native').split(',')
const scenarios = new Set(arg('scenarios', 'reopen,reopenNoCache,fresh,freshSnapshot').split(','))
const jsonOut = process.argv.includes('--json') ? arg('json', 'coldopen-results.json') : undefined
const privateLog = arg('private', 'true') === 'true'
const reps = Number(arg('reps', '3'))
const profileDir = process.argv.includes('--profile') ? arg('profile', '.') : undefined

/** Optional CPU profile of one measured phase (`--profile <dir>`), written as `<label>.cpuprofile`. */
async function profiled<T>(label: string, fn: () => Promise<T>): Promise<T> {
  if (profileDir === undefined) return fn()
  const inspector = new InspectorSession()
  inspector.connect()
  await inspector.post('Profiler.enable')
  await inspector.post('Profiler.start')
  try { return await fn() } finally {
    const { profile } = await inspector.post('Profiler.stop')
    await writeFile(join(profileDir, `${label}.cpuprofile`), JSON.stringify(profile))
    inspector.disconnect()
  }
}

type Counters = Record<string, number>
interface Timed { ms: number; medianMs: number; counters: Counters }

async function member() {
  const identity = await createSigningIdentity()
  const pair = await createWrapKeyPair()
  return { identity, wrap: { publicKey: pair.publicKey, privateKey: await importWrapPrivateKey(pair.privateKey) } }
}
type Member = Awaited<ReturnType<typeof member>>

async function until(predicate: () => boolean, timeoutMs = 600_000): Promise<void> {
  const start = performance.now()
  while (!predicate()) {
    if (performance.now() - start > timeoutMs) throw new Error('timeout waiting for convergence')
    await new Promise(resolve => setTimeout(resolve, 1))
  }
}
const median = (values: number[]): number => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)]!

interface Fixture {
  readonly created: Awaited<ReturnType<typeof createLogGenesis>>
  readonly a: Member
  readonly b: Member
  readonly epochKeys: Map<number, Uint8Array> | undefined
  readonly entries: readonly { key: string; value: Uint8Array }[]
  readonly digest: string
  readonly n: number
}

async function openSession(store: BytesStore, m: Member, f: Pick<Fixture, 'created' | 'epochKeys'>, extra: Record<string, unknown> = {}): Promise<ApplicationSession> {
  return createApplicationSession({
    device: await openApplicationDevice({ store, create: true, managedSigner: m.identity, managedWrapKey: m.wrap }),
    genesis: f.created.genesisBytes, casNodes: f.created.casNodes, ...(f.epochKeys === undefined ? {} : { epochKeys: f.epochKeys }),
    ...extra,
  })
}

async function buildFixture(n: number): Promise<Fixture> {
  const [a, b] = await Promise.all([member(), member()])
  const created = await createLogGenesis({
    creator: { publicKey: a.identity.publicKey, wrapKey: a.wrap.publicKey, reader: true, writer: true, administrator: true },
    members: [{ publicKey: b.identity.publicKey, wrapKey: b.wrap.publicKey, reader: true, writer: true }],
    privateLog,
    imports: { 'app/kv': SQL_REDUCER },
    topics: { kv: { module: 'app/kv', initialState: null } },
  })
  const epochKeys = created.epoch0Key === undefined ? undefined : new Map([[0, created.epoch0Key]])
  const store = new MemoryBytesStore()
  const session = await openSession(store, a, { created, epochKeys })
  for (let i = 0; i < n; i++) {
    const op = await session.command('set', { key: `k${i % 200}`, value: i }, { authorTimestampMs: BigInt(1_000 + i) })
    if ((await op.materialized()).outcome !== 'accepted') throw new Error('bench op rejected')
  }
  const digest = session.revision().digest
  await session.close()
  return { created, a, b, epochKeys, entries: await store.entries(), digest, n }
}

async function storeFrom(kind: string, entries: Fixture['entries'], dir: string, label: string): Promise<{ store: BytesStore; close(): Promise<void> }> {
  if (kind === 'memory') {
    const store = new MemoryBytesStore()
    await store.putAllIfEmpty(entries)
    return { store, async close() {} }
  }
  const store = await NativeBytesStore.open(join(dir, `${label}.sqlite`))
  await store.putAllIfEmpty(entries)
  return { store, close: () => store.close() }
}

async function timedReopen(f: Fixture, kind: string, dir: string, dropCache: boolean): Promise<Timed> {
  const times: number[] = []
  let counters: Counters = {}
  const entries = dropCache ? f.entries.filter(e => !e.key.endsWith('/materialized-cache')) : f.entries
  for (let r = 0; r < reps; r++) {
    const { store, close } = await storeFrom(kind, entries, dir, `reopen-${dropCache ? 'nc' : 'c'}-${r}-${f.entries.length}`)
    resetPerfCounters()
    const t = performance.now()
    const session = await profiled(`reopen-${kind}-${dropCache ? 'nocache' : 'cache'}-${f.n}-${r}`, () => openSession(store, f.a, f))
    const ms = performance.now() - t
    counters = perfCounters()
    if (session.revision().digest !== f.digest) throw new Error('reopen digest mismatch')
    times.push(ms)
    await session.close()
    await close()
  }
  return { ms: times[0]!, medianMs: median(times), counters }
}

async function timedFresh(f: Fixture, snapshot: boolean): Promise<Timed & { fullSyncMs: number; fullSyncCounters: Counters; bytesAtoB: number; bytesBtoA: number }> {
  const storeA = new MemoryBytesStore()
  await storeA.putAllIfEmpty(f.entries)
  const sessA = await openSession(storeA, f.a, f)
  const sessB = await openSession(new MemoryBytesStore(), f.b, f, snapshot ? {} : { snapshotBootstrap: false })
  const meter = { a: 0, b: 0 }
  const [cA, cB] = createFramedPeerConnectionPair()
  const wrap = (conn: typeof cA, side: 'a' | 'b'): typeof cA => ({ ...conn, async send(frame, o) { meter[side] += frame.byteLength; return conn.send(frame, o) } })
  resetPerfCounters()
  const t = performance.now()
  const [linkA, linkB] = await Promise.all([
    sessA.connectPeer({ connection: wrap(cA, 'a') }),
    sessB.connectPeer({ connection: wrap(cB, 'b') }),
  ])
  await profiled(`fresh-${snapshot ? 'snapshot' : 'replay'}-${f.n}`, () => until(() => sessB.revision().digest === f.digest))
  const ms = performance.now() - t
  const counters = perfCounters()
  // Full sync: history facts (still individually verified on B) have all been received and merged.
  await Promise.all([linkA.synchronize(), linkB.synchronize()])
  const fullSyncMs = performance.now() - t
  const fullSyncCounters = perfCounters()
  await Promise.all([linkA.close(), linkB.close()])
  await Promise.all([sessA.close(), sessB.close()])
  return { ms, medianMs: ms, counters, fullSyncMs, fullSyncCounters, bytesAtoB: meter.a, bytesBtoA: meter.b }
}

const results: unknown[] = []
const dir = await mkdtemp(join(tmpdir(), 'chronolog-coldopen-'))
console.log(`load average ${loadavg().map(x => x.toFixed(1)).join(' ')}`)
try {
  for (const n of sizes) {
    const tb = performance.now()
    const f = await buildFixture(n)
    console.log(`N=${n} fixture built in ${((performance.now() - tb) / 1000).toFixed(1)}s, ${f.entries.length} store entries`)
    const row: Record<string, unknown> = { n, privateLog, loadavg: loadavg()[0] }
    for (const kind of storeKinds) {
      if (scenarios.has('reopen')) {
        const r = await timedReopen(f, kind, dir, false)
        row[`reopen.${kind}`] = r
        console.log(`  reopen ${kind}: median ${r.medianMs.toFixed(0)} ms (first ${r.ms.toFixed(0)})`)
      }
      if (scenarios.has('reopenNoCache')) {
        const r = await timedReopen(f, kind, dir, true)
        row[`reopenNoCache.${kind}`] = r
        console.log(`  reopen without cache ${kind}: median ${r.medianMs.toFixed(0)} ms`)
      }
    }
    if (scenarios.has('fresh')) {
      const r = await timedFresh(f, false)
      row.fresh = r
      console.log(`  fresh peer (replay): first state ${r.ms.toFixed(0)} ms, full sync ${r.fullSyncMs.toFixed(0)} ms, ${(r.bytesAtoB / 1024).toFixed(0)} KiB A→B`)
    }
    if (scenarios.has('freshSnapshot')) {
      const r = await timedFresh(f, true)
      row.freshSnapshot = r
      console.log(`  fresh peer (snapshot): first state ${r.ms.toFixed(0)} ms, full sync ${r.fullSyncMs.toFixed(0)} ms, ${(r.bytesAtoB / 1024).toFixed(0)} KiB A→B`)
    }
    results.push(row)
  }
} finally {
  await rm(dir, { recursive: true, force: true })
}
if (jsonOut !== undefined) await writeFile(jsonOut, JSON.stringify(results, (_k, v: unknown) => typeof v === 'bigint' ? v.toString() : v, 2))

/**
 * Chronolog end-to-end performance benchmark.
 *
 *   pnpm bench                 # default sizes
 *   pnpm bench -- --sizes 200,1000 --json out.json
 *
 * Scenarios (each per log size N):
 *   submit      author N ops locally; reports ms/op for the first and last decile (O(N) growth shows here)
 *   reopen      close + reopen the authoring session from its store
 *   coldSync    fresh peer connects and synchronizes the full log; wall time + wire bytes/frames
 *   liveLatency steady-state: one op authored on A until materialized on B (median of 20)
 *   reconnect   B disconnects and reconnects with nothing new; wall time + wire bytes
 */
import { performance } from 'node:perf_hooks'
import { writeFile } from 'node:fs/promises'
import type { FramedPeerConnection } from '@chronolog/records'
import { MemoryBytesStore } from '@chronolog/records'
import { createSigningIdentity } from '@chronolog/authority'
import { createLogGenesis } from '../packages/peer-session/src/genesis.js'
import { openApplicationDevice } from '../packages/peer-session/src/device.js'
import { createApplicationSession } from '../packages/peer-session/src/runtime.js'
import { createFramedPeerConnectionPair } from '../packages/peer-session/src/network-wire.js'
import { createWrapKeyPair, importWrapPrivateKey } from '../packages/peer-session/src/wrap-keys.js'
import { perfCounters, resetPerfCounters } from '../packages/canonical/src/perf.js'

const KV_REDUCER = `
export default {
  reduce(state, tx) {
    const next = Object.assign({}, state || {});
    const p = tx.payload || {};
    next[p.key] = p.value;
    return { ok: true, state: next };
  },
  query(state, input) { return input && input.key ? (state || {})[input.key] ?? null : Object.keys(state || {}).length; },
  describe() { return { commands: [{ name: 'set', description: 'set', input: { type: 'object' } }], queries: [{ name: 'get', description: 'get', input: { type: 'object' } }] }; },
};
`

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
  query(state, input) {
    const db = openDb(state);
    if (db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='kv'").rows.length === 0) return null;
    return db.query('SELECT count(*) FROM kv').rows[0][0];
  },
  describe() { return { commands: [{ name: 'set', description: 'set', input: { type: 'object' } }], queries: [{ name: 'get', description: 'get', input: { type: 'object' } }] }; },
};
`

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1]! : fallback
}
const sizes = arg('sizes', '100,500,1000').split(',').map(Number)
const reducers = arg('reducers', 'kv,sql').split(',')
const jsonOut = process.argv.includes('--json') ? arg('json', 'bench-results.json') : undefined
const privateLog = arg('private', 'true') === 'true'

interface Meter { bytes: number; frames: number }
function metered(conn: FramedPeerConnection, meter: Meter): FramedPeerConnection {
  return {
    ...conn,
    async send(frame, options) { meter.bytes += frame.byteLength; meter.frames++; return conn.send(frame, options) },
  }
}

async function member() {
  const identity = await createSigningIdentity()
  const pair = await createWrapKeyPair()
  return { identity, wrap: { publicKey: pair.publicKey, privateKey: await importWrapPrivateKey(pair.privateKey) } }
}

async function until(predicate: () => Promise<boolean> | boolean, timeoutMs = 600_000): Promise<void> {
  const start = performance.now()
  while (!(await predicate())) {
    if (performance.now() - start > timeoutMs) throw new Error('timeout waiting for convergence')
    await new Promise(resolve => setTimeout(resolve, 1))
  }
}

const debug = (...args: unknown[]): void => { if (process.env.BENCH_DEBUG) console.error('[bench]', ...args) }

type Counters = Record<string, number>
interface ScenarioResult {
  reducer: string; n: number; privateLog: boolean
  submit: { totalMs: number; firstDecileMsPerOp: number; lastDecileMsPerOp: number; counters: Counters }
  reopen: { ms: number; counters: Counters }
  coldSync: { ms: number; bytesAtoB: number; bytesBtoA: number; framesAtoB: number; framesBtoA: number; counters: Counters }
  liveLatency: { medianMs: number; maxMs: number; bytesPerOpAtoB: number; counters: Counters }
  reconnect: { ms: number; bytesAtoB: number; bytesBtoA: number; counters: Counters }
}

function median(values: number[]): number { const s = [...values].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]! }

async function scenario(reducer: string, n: number): Promise<ScenarioResult> {
  const [a, b] = await Promise.all([member(), member()])
  const created = await createLogGenesis({
    creator: { publicKey: a.identity.publicKey, wrapKey: a.wrap.publicKey, reader: true, writer: true, administrator: true },
    members: [{ publicKey: b.identity.publicKey, wrapKey: b.wrap.publicKey, reader: true, writer: true }],
    privateLog,
    imports: { 'app/kv': reducer === 'sql' ? SQL_REDUCER : KV_REDUCER },
    topics: { kv: { module: 'app/kv', initialState: reducer === 'sql' ? null : {} } },
  })
  const epochKeys = created.epoch0Key === undefined ? undefined : new Map([[0, created.epoch0Key]])
  const storeA = new MemoryBytesStore(), storeB = new MemoryBytesStore()
  const open = async (store: MemoryBytesStore, m: Awaited<ReturnType<typeof member>>) => createApplicationSession({
    device: await openApplicationDevice({ store, create: true, managedSigner: m.identity, managedWrapKey: m.wrap }),
    genesis: created.genesisBytes, casNodes: created.casNodes, ...(epochKeys === undefined ? {} : { epochKeys }),
  })
  const result = { reducer, n, privateLog } as ScenarioResult

  // submit
  let sessA = await open(storeA, a)
  resetPerfCounters()
  const perOp: number[] = []
  const submitStart = performance.now()
  for (let i = 0; i < n; i++) {
    const t = performance.now()
    const op = await sessA.command('set', { key: `k${i % 50}`, value: i }, { authorTimestampMs: BigInt(1_000 + i) })
    const materialized = await op.materialized()
    if (materialized.outcome !== 'accepted') throw new Error(`bench op rejected: ${materialized.rejectionCode ?? ''} ${materialized.rejectionDetail ?? ''}`)
    perOp.push(performance.now() - t)
  }
  const decile = Math.max(1, Math.floor(n / 10))
  result.submit = {
    totalMs: performance.now() - submitStart,
    firstDecileMsPerOp: perOp.slice(0, decile).reduce((x, y) => x + y, 0) / decile,
    lastDecileMsPerOp: perOp.slice(-decile).reduce((x, y) => x + y, 0) / decile,
    counters: perfCounters(),
  }

  debug('submitted')
  // reopen
  await sessA.close()
  resetPerfCounters()
  let t = performance.now()
  sessA = await open(storeA, a)
  const reopenRevision = sessA.revision().digest
  result.reopen = { ms: performance.now() - t, counters: perfCounters() }

  debug('reopened')
  // cold sync
  const sessB = await open(storeB, b)
  const meterA: Meter = { bytes: 0, frames: 0 }, meterB: Meter = { bytes: 0, frames: 0 }
  let [cA, cB] = createFramedPeerConnectionPair()
  resetPerfCounters()
  t = performance.now()
  let [linkA, linkB] = await Promise.all([
    sessA.connectPeer({ connection: metered(cA, meterA) }),
    sessB.connectPeer({ connection: metered(cB, meterB) }),
  ])
  debug('connected')
  await Promise.all([linkA.synchronize(), linkB.synchronize()])
  debug('synchronized', sessB.revision().digest === reopenRevision)
  await until(() => sessB.revision().digest === reopenRevision)
  result.coldSync = { ms: performance.now() - t, bytesAtoB: meterA.bytes, bytesBtoA: meterB.bytes, framesAtoB: meterA.frames, framesBtoA: meterB.frames, counters: perfCounters() }

  debug('cold synced')
  // live latency
  const lat: number[] = []
  resetPerfCounters()
  const liveMeter = { ...meterA }
  for (let i = 0; i < 20; i++) {
    t = performance.now()
    const op = await sessA.command('set', { key: 'live', value: i }, { authorTimestampMs: BigInt(10_000_000 + i) })
    await op.materialized()
    const target = sessA.revision().digest
    await until(() => sessB.revision().digest === target, Number(process.env.BENCH_LIVE_TIMEOUT ?? 600_000)).catch((error: unknown) => {
      debug('live stall', i, { a: sessA.revision(), b: sessB.revision(), aStatus: sessA.status, bStatus: sessB.status })
      throw error
    })
    lat.push(performance.now() - t)
  }
  result.liveLatency = { medianMs: median(lat), maxMs: Math.max(...lat), bytesPerOpAtoB: (meterA.bytes - liveMeter.bytes) / 20, counters: perfCounters() }

  debug('live done')
  // reconnect with nothing new
  await Promise.all([linkA.close(), linkB.close()])
  ;[cA, cB] = createFramedPeerConnectionPair()
  const rA: Meter = { bytes: 0, frames: 0 }, rB: Meter = { bytes: 0, frames: 0 }
  resetPerfCounters()
  t = performance.now()
  ;[linkA, linkB] = await Promise.all([
    sessA.connectPeer({ connection: metered(cA, rA) }),
    sessB.connectPeer({ connection: metered(cB, rB) }),
  ])
  await Promise.all([linkA.synchronize(), linkB.synchronize()])
  result.reconnect = { ms: performance.now() - t, bytesAtoB: rA.bytes, bytesBtoA: rB.bytes, counters: perfCounters() }

  await Promise.all([linkA.close(), linkB.close()])
  await Promise.all([sessA.close(), sessB.close()])
  return result
}

function fmt(r: ScenarioResult): string {
  const kb = (x: number) => `${(x / 1024).toFixed(1)}KiB`
  return [
    `${r.reducer} N=${r.n}`,
    `submit ${r.submit.totalMs.toFixed(0)}ms (${r.submit.firstDecileMsPerOp.toFixed(2)}→${r.submit.lastDecileMsPerOp.toFixed(2)} ms/op)`,
    `reopen ${r.reopen.ms.toFixed(0)}ms`,
    `coldSync ${r.coldSync.ms.toFixed(0)}ms ${kb(r.coldSync.bytesAtoB)}↓ ${kb(r.coldSync.bytesBtoA)}↑`,
    `live p50 ${r.liveLatency.medianMs.toFixed(1)}ms ${kb(r.liveLatency.bytesPerOpAtoB)}/op`,
    `reconnect ${r.reconnect.ms.toFixed(0)}ms ${kb(r.reconnect.bytesAtoB + r.reconnect.bytesBtoA)}`,
  ].join(' | ')
}

const results: ScenarioResult[] = []
for (const reducer of reducers) for (const n of sizes) {
  const r = await scenario(reducer, n)
  results.push(r)
  console.log(fmt(r))
}
if (jsonOut !== undefined) await writeFile(jsonOut, JSON.stringify(results, (_k, v: unknown) => typeof v === 'bigint' ? v.toString() : v, 2))

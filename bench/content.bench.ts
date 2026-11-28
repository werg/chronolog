/**
 * Chronolog content/blob transfer benchmark.
 *
 *   pnpm tsx bench/content.bench.ts
 *   pnpm tsx bench/content.bench.ts --sizes 1,16 --rtt 0,50 --json bench/results/content.json
 *
 * For every (visibility, size MiB, RTT ms) combination: peer A stores the blob, peer B (fresh store,
 * already synchronized) pulls it with `content.get` over `createFramedPeerConnectionPair`. RTT > 0
 * wraps both directions in an unbounded-bandwidth link that delays every frame by RTT/2.
 * Reports pull wall time, throughput, wire bytes each way (framed, i.e. what a transport carries),
 * wire inflation (A→B bytes / payload bytes) and the deterministic SHA-256 counters.
 */
import { performance } from 'node:perf_hooks'
import { writeFile } from 'node:fs/promises'
import type { FramedPeerConnection } from '@chronolog/records'
import { createFramedPeerConnectionPair } from '../packages/peer-session/src/network-wire.js'
import { sessionFixture } from '../packages/peer-session/src/test-fixture.js'
import { perfCounters, resetPerfCounters } from '../packages/canonical/src/perf.js'

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1]! : fallback
}
const sizes = arg('sizes', '1,16').split(',').map(Number)
const rtts = arg('rtt', '0,50').split(',').map(Number)
const visibilities = arg('visibility', 'public,private').split(',') as Array<'public' | 'private'>
const jsonOut = process.argv.includes('--json') ? arg('json', 'content-bench.json') : undefined

interface Meter { bytes: number; frames: number }

/** Meter (and optionally delay) frames sent by one side. Delayed frames keep their order. */
function link(conn: FramedPeerConnection, meter: Meter, delayMs: number): FramedPeerConnection {
  if (delayMs <= 0) {
    return { ...conn, async send(frame, options) { meter.bytes += frame.byteLength; meter.frames++; return conn.send(frame, options) } }
  }
  const queue: Array<{ frame: Uint8Array; at: number }> = []
  let wake: (() => void) | undefined
  void (async () => {
    while (!conn.signal.aborted) {
      const next = queue.shift()
      if (next === undefined) { await new Promise<void>(resolve => { wake = resolve }); continue }
      const wait = next.at - performance.now()
      if (wait > 0) await new Promise(resolve => setTimeout(resolve, wait))
      await conn.send(next.frame).catch(() => undefined)
    }
  })()
  return {
    ...conn,
    async send(frame, options) {
      options?.signal?.throwIfAborted()
      meter.bytes += frame.byteLength; meter.frames++
      queue.push({ frame, at: performance.now() + delayMs }); wake?.(); wake = undefined
    },
  }
}

function payload(size: number): Uint8Array {
  const out = new Uint8Array(size)
  let x = 0x9e3779b9
  for (let i = 0; i < size; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; out[i] = x & 0xff }
  return out
}

interface Result {
  visibility: string; mib: number; rttMs: number
  putMs: number; pullMs: number; mibPerSec: number
  bytesAtoB: number; bytesBtoA: number; framesAtoB: number; framesBtoA: number; inflation: number
  sha256Calls: number; sha256Bytes: number
}

async function run(visibility: 'public' | 'private', mib: number, rttMs: number): Promise<Result> {
  const f = await sessionFixture()
  const a = await f.open(0), b = await f.open(1)
  const meterA: Meter = { bytes: 0, frames: 0 }, meterB: Meter = { bytes: 0, frames: 0 }
  const [cA, cB] = createFramedPeerConnectionPair()
  const [linkA, linkB] = await Promise.all([
    a.connectPeer({ connection: link(cA, meterA, rttMs / 2) }),
    b.connectPeer({ connection: link(cB, meterB, rttMs / 2) }),
  ])
  await Promise.all([linkA.synchronize(), linkB.synchronize()])
  const bytes = payload(mib * 1024 * 1024)
  let t = performance.now()
  const reference = await a.content.put(bytes, { visibility })
  const putMs = performance.now() - t
  const base = { a: { ...meterA }, b: { ...meterB } }
  resetPerfCounters()
  t = performance.now()
  const got = await b.content.get(reference, { maxBytes: bytes.length })
  const pullMs = performance.now() - t
  const counters = perfCounters()
  if (got === null || got.length !== bytes.length || Buffer.compare(Buffer.from(got), Buffer.from(bytes)) !== 0) throw new Error('content mismatch')
  const result: Result = {
    visibility, mib, rttMs, putMs: Math.round(putMs), pullMs: Math.round(pullMs), mibPerSec: Number((mib / (pullMs / 1000)).toFixed(2)),
    bytesAtoB: meterA.bytes - base.a.bytes, bytesBtoA: meterB.bytes - base.b.bytes,
    framesAtoB: meterA.frames - base.a.frames, framesBtoA: meterB.frames - base.b.frames,
    inflation: Number(((meterA.bytes - base.a.bytes) / bytes.length).toFixed(3)),
    sha256Calls: counters['sha256Sync'] ?? 0, sha256Bytes: counters['sha256Sync.bytes'] ?? 0,
  }
  await Promise.all([linkA.close(), linkB.close()])
  await Promise.all([a.close(), b.close()])
  return result
}

const results: Result[] = []
for (const visibility of visibilities) {
  for (const mib of sizes) {
    for (const rttMs of rtts) {
      const result = await run(visibility, mib, rttMs)
      results.push(result)
      console.log(`${visibility.padEnd(7)} ${String(mib).padStart(3)} MiB rtt ${String(rttMs).padStart(3)} ms: ` +
        `pull ${result.pullMs} ms (${result.mibPerSec} MiB/s), A→B ${(result.bytesAtoB / 1048576).toFixed(2)} MiB ` +
        `(x${result.inflation}, ${result.framesAtoB} frames), B→A ${(result.bytesBtoA / 1024).toFixed(1)} KiB, ` +
        `put ${result.putMs} ms, sha256 ${result.sha256Calls} calls / ${(result.sha256Bytes / 1048576).toFixed(1)} MiB`)
    }
  }
}
if (jsonOut !== undefined) await writeFile(jsonOut, JSON.stringify({ date: new Date().toISOString(), results }, null, 2))

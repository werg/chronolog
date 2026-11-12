/**
 * Local single-node ingest latency benchmark.
 *
 *   nice pnpm exec tsx tools/bench-ingest.ts [--transport ssb|memory]
 *     [--control file|memory] [--count 40] [--warmup 5]
 *     [--write-timeout <ms>] [--flush-debounce <ms>]
 *
 * One node is writer and validator with threshold 1, which is the daemon's
 * single-node shape. For each candidate it measures, from the start of
 * node.publish(): when publish() resolves (candidate durably appended and
 * ingested, attestation published), when the candidate becomes admissible and
 * when its outcome is visible in the materialized DoltLite revision. Run with
 * `node --cpu-prof --import tsx` to profile.
 */
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseArgs } from 'node:util'

import { ControlStore, JsonFileControlStorePersistence } from '@chronolog/control-store'
import { createCoreExecutionManifest } from '@chronolog/compiler-sqlite'
import {
  DeterministicMaterializer,
  createDoltLiteMaterializationRuntime,
  readNativeEngineInfo,
} from '@chronolog/materializer-doltlite'
import {
  ChronologNode,
  FeedForkRegistry,
  JsonFeedForkPersistence,
  type MembershipResolver,
} from '@chronolog/node-core'
import { equalBytes, generateEd25519KeyPair, type SqlTransactionProgram } from '@chronolog/protocol'
import { type ChronologTransport, MemoryTransportNetwork, SsbDb2Transport } from '@chronolog/transport-ssb'

const { values } = parseArgs({
  options: {
    transport: { type: 'string', default: 'ssb' },
    control: { type: 'string', default: 'file' },
    count: { type: 'string', default: '40' },
    warmup: { type: 'string', default: '5' },
    'write-timeout': { type: 'string' },
    'flush-debounce': { type: 'string' },
  },
})
const count = Number(values.count)
const warmup = Number(values.warmup)

const directory = await mkdtemp(join(tmpdir(), 'chronolog-bench-ingest-'))
const identity = await generateEd25519KeyPair()
const capability = Uint8Array.of(7)
const native = readNativeEngineInfo()
const materializer = await DeterministicMaterializer.open({
  path: join(directory, 'application.db'),
  executionManifest: createCoreExecutionManifest({
    profile: 'chronolog-core-portable',
    engine: native.descriptor,
    engineDigest: native.digest,
  }),
})
const membership: MembershipResolver = {
  canWrite: ({ writerId }) => equalBytes(writerId, identity.publicKeyBytes),
  canValidate: ({ validatorId, validatorCapability }) =>
    equalBytes(validatorId, identity.publicKeyBytes) && equalBytes(validatorCapability, capability),
  threshold: () => 1,
}
const transport: ChronologTransport = values.transport === 'memory'
  ? new MemoryTransportNetwork().createNode('bench')
  : await SsbDb2Transport.open({
    path: join(directory, 'ssb'),
    config: {
      db2: {
        ...(values['write-timeout'] === undefined ? {} : { writeTimeout: Number(values['write-timeout']) }),
        ...(values['flush-debounce'] === undefined ? {} : { flushDebounce: Number(values['flush-debounce']) }),
      },
    },
  })
const controlStore = values.control === 'file'
  ? new ControlStore(new JsonFileControlStorePersistence(join(directory, 'control.json')))
  : new ControlStore()
// Admission emits no node event, so record the transition time directly.
const admittedAt = new Map<string, number>()
const setCandidateState = controlStore.setCandidateState.bind(controlStore)
controlStore.setCandidateState = (txId, state, options) => {
  const deltas = setCandidateState(txId, state, options)
  if (state === 'admissible') admittedAt.set(Buffer.from(txId).toString('hex'), performance.now())
  return deltas
}
const node = new ChronologNode({
  groupId: bytes32(1),
  membershipRevision: bytes32(2),
  validationPolicy: bytes32(3),
  identity,
  transport,
  materialization: createDoltLiteMaterializationRuntime(materializer),
  membership,
  validator: { capabilityId: capability, cutoffLagMs: 60_000 },
  controlStore,
  ...(values.control === 'file'
    ? {
        feedForkRegistry: new FeedForkRegistry(new JsonFeedForkPersistence(join(directory, 'feed-continuity.json'))),
      }
    : {}),
})

interface Sample { publish: number; admitted: number; materialized: number }
const samples: Sample[] = []
try {
  await node.start()
  // Consume events continuously so none are missed between waits.
  let wake: (() => void) | undefined
  const stop = new AbortController()
  // Node timers are unref'd; keep the process alive while waiting on them.
  const keepAlive = setInterval(() => {}, 1_000)
  stop.signal.addEventListener('abort', () => clearInterval(keepAlive))
  void (async () => {
    for await (const _event of node.events(0n, stop.signal)) { wake?.() }
  })().catch(() => {})
  const pump = async (predicate: () => boolean): Promise<number> => {
    while (!predicate()) await new Promise<void>((resolve) => { wake = resolve })
    return performance.now()
  }
  for (let index = 0; index < warmup + count; index += 1) {
    const started = performance.now()
    const published = await node.publish({ program: index === 0 ? createProgram() : insertProgram(index) })
    const publish = performance.now()
    const materialized = await pump(() => node.outcome(published.txId) !== null)
    const admitted = admittedAt.get(Buffer.from(published.txId).toString('hex'))!
    if (node.outcome(published.txId)?.outcome !== 'accepted') throw new Error(`rejected ${index}`)
    if (index >= warmup) {
      samples.push({ publish: publish - started, admitted: admitted - started, materialized: materialized - started })
    }
  }
  stop.abort()
} finally {
  await node.close()
  await rm(directory, { recursive: true, force: true })
}

const summarize = (key: keyof Sample, from = 0, to = samples.length) => {
  const sorted = samples.slice(from, to).map((sample) => sample[key]).sort((left, right) => left - right)
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length
  return { mean: round(mean), p50: round(sorted[Math.floor(sorted.length / 2)]!), max: round(sorted.at(-1)!) }
}
console.log(JSON.stringify({
  transport: values.transport,
  control: values.control,
  writeTimeout: values['write-timeout'] ?? 'default',
  flushDebounce: values['flush-debounce'] ?? 'default',
  candidates: samples.length,
  publishResolvedMs: summarize('publish'),
  admittedMs: summarize('admitted'),
  materializedMs: summarize('materialized'),
  // Growth with history: the first and last ten measured candidates.
  materializedFirst10Ms: summarize('materialized', 0, 10),
  materializedLast10Ms: summarize('materialized', -10),
}))

function round(value: number): number { return Math.round(value * 10) / 10 }
function bytes32(seed: number): Uint8Array { return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff) }
function createProgram(): SqlTransactionProgram {
  return {
    version: 1,
    preconditions: [{
      id: 1,
      query: { sql: 'SELECT 1', bindings: [] },
      resultMode: 'scalar',
      expectation: { kind: 'assert_true' },
    }],
    body: [{ sql: 'CREATE TABLE items (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT', bindings: [] }],
  }
}
function insertProgram(id: number): SqlTransactionProgram {
  return {
    version: 1,
    preconditions: [{
      id: 1,
      query: { sql: 'SELECT 1', bindings: [] },
      resultMode: 'scalar',
      expectation: { kind: 'assert_true' },
    }],
    body: [{
      sql: 'INSERT INTO items (id, value) VALUES (?, ?)',
      bindings: [indexed(1, BigInt(id)), indexed(2, BigInt(id * 10))],
    }],
  }
}
function indexed(index: number, value: bigint) {
  return { parameter: { kind: 'index' as const, index }, value: { kind: 'int64' as const, value } }
}

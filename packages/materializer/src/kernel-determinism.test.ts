import { describe, expect, it } from 'vitest'
import { bytesToHex, utf8 } from '@chronolog/canonical'
import {
  operationIdDigest,
  type JsonValue,
  type LogGenesis,
  type OperationAssumptionsConfig,
  type OperationCore,
  type TopicUpdate,
} from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { TopicKernel, type KernelOperationInput } from './kernel.js'
import { CAS_BUILTIN_ID, QUICKJS_RUNTIME_ID } from './quickjs-sandbox.js'

const ALICE = new Uint8Array(32).fill(0xa1)
const ALICE_HEX = bytesToHex(ALICE)
const LIMITS = { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 2, maxFuel: 200_000 }

function op(
  kernel: TopicKernel,
  operationId: string,
  ts: bigint,
  updates: readonly TopicUpdate[],
  extra: { readonly visibility?: 'public' | 'encrypted'; readonly ring?: string; readonly epoch?: number; readonly assumptions?: OperationAssumptionsConfig } = {},
): KernelOperationInput {
  const core: OperationCore = {
    version: 1,
    logId: kernel.logId,
    author: ALICE,
    operationId,
    authorTimestampMs: ts,
    nonce: new Uint8Array(16).fill(Number(ts % 200n) + 1),
    visibility: extra.visibility ?? 'public',
    updates,
    ...(extra.assumptions === undefined ? {} : { assumptions: extra.assumptions }),
  }
  return {
    opId: operationIdDigest(core),
    core,
    ...(extra.ring === undefined ? {} : { ring: extra.ring }),
    ...(extra.epoch === undefined ? {} : { epoch: extra.epoch }),
  }
}

async function put(cas: ContentAddressedStore, source: string): Promise<string> {
  return `cas:sha256-${await cas.put(utf8(source), [], 'public')}`
}

const SET_MODULE = `export default { reduce(_s, tx) { return { ok: true, state: tx.payload }; } };`

function genesis(
  topics: Readonly<Record<string, JsonValue>>,
  imports: Readonly<Record<string, string>>,
  bindings: Readonly<Record<string, JsonValue>>,
  privateLog = false,
): LogGenesis {
  return {
    version: 1,
    privateLog,
    initialTopics: {
      $reducers: {
        runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:cas': CAS_BUILTIN_ID } },
        imports,
        topics: bindings,
      },
      ...topics,
    },
    limits: LIMITS,
    salt: new Uint8Array(16).fill(9),
  }
}

describe('TopicKernel consensus determinism', () => {
  it('re-evaluates nested control queries after another topic changes', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    const rule = await put(cas, `export default { query(_state, _input, ctx) { return ctx.topic('$builders'); } };`)
    const consumer = await put(cas, `export default {
      reduce(_state, _tx, ctx) { return { ok: true, state: ctx.query('$mounts', null) }; },
    };`)
    const g = genesis({ $builders: 1 }, {}, {
      $builders: { module: set }, $mounts: { module: rule }, $publications: { module: consumer },
    }, true)
    const warm = new TopicKernel({ genesis: g, cas })
    const cold = new TopicKernel({ genesis: g, cas })
    const first = op(warm, 'first', 10n, [{ topic: '$publications', input: null }])
    const update = op(warm, 'settings', 20n, [{ topic: '$builders', input: 2 }])
    const second = op(warm, 'second', 30n, [{ topic: '$publications', input: null }])
    const firstResult = await warm.materialize([first])
    expect(firstResult.outcomes[0]).toMatchObject({ outcome: 'accepted', rejectionCode: null })
    expect(warm.topic('$publications')).toBe(1)
    await warm.materialize([first, update, second])
    await cold.materialize([update, second])
    expect(warm.topic('$publications')).toBe(2)
    expect(warm.topic('$publications')).toBe(cold.topic('$publications'))
  })

  it('pins sealed reducers to the full import map, including chronolog/* overrides (no CAS-dependent resolution)', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    const helperA = await put(cas, `export const allow = () => true;`)
    const helperB = await put(cas, `export const allow = () => false;`)
    const admission = await put(cas, `import { allow } from 'chronolog/helper'; export default { authorize() { return allow(); } };`)
    const reducers = {
      runtime: { js: QUICKJS_RUNTIME_ID, builtins: { 'chronolog:cas': CAS_BUILTIN_ID } },
      imports: { 'app/set': set, 'app/admission': admission, 'chronolog/helper': helperA },
      topics: { $reducers: { module: 'app/set' }, $admission: { module: 'app/admission' }, note: { module: 'app/set' } },
    }
    const g = genesis({ $seals: { reducers: { $admission: true } } }, reducers.imports, reducers.topics)
    const kernel = new TopicKernel({ genesis: g, cas })
    const swapHelper = op(kernel, 'swap-helper', 10n, [{ topic: '$reducers', input: { ...reducers, imports: { ...reducers.imports, 'chronolog/helper': helperB } } }])
    const addImport = op(kernel, 'add-import', 11n, [{ topic: '$reducers', input: { ...reducers, imports: { ...reducers.imports, 'app/extra': set } } }])
    const newTopicByRef = op(kernel, 'new-topic', 12n, [{ topic: '$reducers', input: { ...reducers, topics: { ...reducers.topics, extra: { module: set } } } }])
    const res = await kernel.materialize([swapHelper, addImport, newTopicByRef])
    expect(res.outcomes.map(o => [o.outcome, o.rejectionCode])).toEqual([
      ['rejected', 'seal:reducer_locked'],
      ['rejected', 'seal:reducer_locked'],
      ['accepted', null],
    ])
  })

  it('runs onConflict through the same authorize/seal/verify/$reducers pipeline as normal commits', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    // authorize must see every update of the op (previously only the primary one).
    const admission = await put(cas, `export default {
      authorize(_s, tx) { return tx.updates.some(u => u.topic === 'locked') ? { ok: false, code: 'locked_topic' } : true; },
    };`)
    const conflicting = await put(cas, `export default {
      reduce(_s, tx) { return { ok: true, state: tx.payload }; },
      onConflict(_s, tx) { return { ok: true, state: tx.payload }; },
    };`)
    const bindings = { $reducers: { module: conflicting }, $admission: { module: admission }, note: { module: conflicting }, locked: { module: set } }
    const kernel = new TopicKernel({ genesis: genesis({}, {}, bindings), cas })
    const stale: OperationAssumptionsConfig = { checks: [{ kind: 'topic_revision', topic: 'note', lastOpId: 'f'.repeat(64) }], onFailed: 'record_conflict' }
    const ops = [
      op(kernel, 'conflict-ok', 10n, [{ topic: 'note', input: 'recorded' }], { assumptions: stale }),
      op(kernel, 'conflict-hidden-update', 11n, [{ topic: 'note', input: 'sneaky' }, { topic: 'locked', input: 1 }], { assumptions: stale }),
      // A conflict-produced $reducers state must pass assertValidReducersConfig like any other.
      op(kernel, 'conflict-bad-reducers', 12n, [{ topic: '$reducers', input: { not: 'a config' } }], { assumptions: stale }),
    ]
    const res = await kernel.materialize(ops)
    expect(res.outcomes.map(o => [o.rejectionCode, o.conflictRecorded ?? false])).toEqual([
      ['assumption:topic_modified', true],
      ['assumption:topic_modified', false],
      ['assumption:topic_modified', false],
    ])
    expect(kernel.topic('note')).toBe('recorded')
  })

  it('consumes the idempotency key for every rejection except operation_conflict', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    const kernel = new TopicKernel({ genesis: genesis({}, {}, { note: { module: set } }), cas })
    const res = await kernel.materialize([
      op(kernel, 'k1', 10n, [{ topic: 'unbound', input: 1 }]),
      op(kernel, 'k1', 11n, [{ topic: 'note', input: 1 }]),
      op(kernel, 'k2', 12n, [{ topic: 'note', input: 1 }, { topic: 'note', input: 2 }, { topic: 'note', input: 3 }]),
      op(kernel, 'k2', 13n, [{ topic: 'note', input: 4 }]),
    ])
    expect(res.outcomes.map(o => o.rejectionCode)).toEqual(['no_reducer:unbound', 'operation_conflict', 'limit:max_updates_per_op', 'operation_conflict'])
  })

  it('does not consume the idempotency key when an onConflict hits a missing dependency', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const blob = utf8('late blob')
    const blobHash = await new ContentAddressedStore({ store: new MemoryBytesStore() }).put(blob, [], 'public')
    const mod = await put(cas, `import { get } from 'chronolog:cas';
      export default {
        reduce(_s, tx) { return { ok: true, state: tx.payload }; },
        onConflict() { get('${blobHash}'); return { ok: true, state: 'conflict' }; },
      };`)
    const kernel = new TopicKernel({ genesis: genesis({}, {}, { note: { module: mod } }), cas })
    const stale: OperationAssumptionsConfig = { checks: [{ kind: 'topic_revision', topic: 'note', lastOpId: 'f'.repeat(64) }], onFailed: 'record_conflict' }
    const ops = [op(kernel, 'c1', 10n, [{ topic: 'note', input: 'x' }], { assumptions: stale })]
    const first = await kernel.materialize(ops)
    expect(first.pendingDependencies.length).toBe(1)
    await cas.put(blob, [], 'public')
    const second = await kernel.materialize(ops)
    expect(second.outcomes.map(o => [o.rejectionCode, o.conflictRecorded ?? false])).toEqual([['assumption:topic_modified', true]])
    expect(kernel.topic('note')).toBe('conflict')
  })

  it('scopes topics, outcomes and last-op ids to the op key ring so results never depend on decryptable rings', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    const mirror = await put(cas, `export default {
      reduce(_s, tx, ctx) {
        return { ok: true, state: {
          secret: ctx.topic('secret'),
          secretLast: ctx.topicLastOpId('secret'),
          secretOutcome: ctx.opOutcome(tx.payload.secretOp),
          authorLast: ctx.authorLastOpId(),
        } };
      },
    };`)
    const bindings = { $reducers: { module: set }, $keys: { module: set }, secret: { module: set }, mirror: { module: mirror } }
    const g = genesis({ $keys: { topicRings: { secret: 'x' } } }, {}, bindings, true)
    const withRing = new TopicKernel({ genesis: g, cas })
    const withoutRing = new TopicKernel({ genesis: g, cas })
    const secretOp = op(withRing, 's1', 10n, [{ topic: 'secret', input: 'classified' }], { visibility: 'encrypted', ring: 'x' })
    const secretOpId = bytesToHex(secretOp.opId)
    const mirrorOp = op(withRing, 'm1', 20n, [{ topic: 'mirror', input: { secretOp: secretOpId } }], { visibility: 'encrypted' })
    const a = await withRing.materialize([secretOp, mirrorOp])
    const b = await withoutRing.materialize([mirrorOp])
    expect(a.outcomes.map(o => o.outcome)).toEqual(['accepted', 'accepted'])
    expect(b.outcomes.map(o => o.outcome)).toEqual(['accepted'])
    expect(withRing.topic('mirror')).toEqual({ secret: null, secretLast: null, secretOutcome: null, authorLast: null })
    expect(withRing.topic('mirror')).toEqual(withoutRing.topic('mirror'))
    expect(withRing.topicHash('mirror')).toBe(withoutRing.topicHash('mirror'))
    // Ring-scoped author history: the default-ring view excludes the ring-x op, the x view includes it.
    expect(withRing.authorLastOpId(ALICE_HEX)).toBe(bytesToHex(mirrorOp.opId))
    expect(withRing.authorLastOpId(ALICE_HEX, { ring: 'x' })).toBe(secretOpId)
    // A public op supersedes ring-scoped history for every ring.
    const pub = op(withRing, 'p1', 30n, [{ topic: '$keys', input: { topicRings: { secret: 'x' } } }])
    await withRing.materialize([secretOp, mirrorOp, pub])
    expect(withRing.authorLastOpId(ALICE_HEX, { ring: 'x' })).toBe(bytesToHex(pub.opId))
    // Assumptions on a foreign-ring topic fail closed.
    const peek = op(withRing, 'peek', 40n, [{ topic: 'mirror', input: { secretOp: secretOpId } }], {
      visibility: 'encrypted',
      assumptions: { checks: [{ kind: 'topic_revision', topic: 'secret', lastOpId: secretOpId }] },
    })
    const c = await withRing.materialize([secretOp, mirrorOp, pub, peek])
    expect(c.outcomes.at(-1)!.rejectionCode).toBe('ring:foreign_assumption')
  })

  it('enforces $keys.policy.maxOpsPerEpoch per (ring, epoch) in canonical order, independent of arrival', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const set = await put(cas, SET_MODULE)
    const bindings = { $reducers: { module: set }, $keys: { module: set }, note: { module: set }, secret: { module: set } }
    const g = genesis({ $keys: { policy: { maxOpsPerEpoch: 2 }, topicRings: { secret: 'x' } } }, {}, bindings, true)
    const k = new TopicKernel({ genesis: g, cas })
    const enc = (id: string, ts: bigint, epoch: number | undefined, topic = 'note', ring?: string) =>
      op(k, id, ts, [{ topic, input: id }], { visibility: 'encrypted', ...(epoch === undefined ? {} : { epoch }), ...(ring === undefined ? {} : { ring }) })
    const e0a = enc('e0a', 10n, 0), e0b = enc('e0b', 20n, 0), e0c = enc('e0c', 30n, 0)
    const e1a = enc('e1a', 40n, 1)
    const x0a = enc('x0a', 50n, 0, 'secret', 'x')
    const noEpoch = enc('none', 60n, undefined)

    const res = await k.materialize([noEpoch, x0a, e1a, e0c, e0b, e0a])
    expect(res.outcomes.map(o => [o.operationId, o.outcome, o.rejectionCode])).toEqual([
      ['e0a', 'accepted', null],
      ['e0b', 'accepted', null],
      ['e0c', 'rejected', 'epoch_op_budget_exhausted'],
      ['e1a', 'accepted', null],
      ['x0a', 'accepted', null],
      ['none', 'rejected', 'epoch_op_budget_exhausted'],
    ])
    expect(k.topic('note')).toBe('e1a')

    // A late earlier op takes a slot of its epoch and pushes a later one out, on every replica.
    const early = enc('early', 5n, 0)
    const replay = await k.materialize([noEpoch, x0a, e1a, e0c, e0b, e0a, early])
    expect(replay.outcomes.filter(o => o.outcome === 'rejected').map(o => o.operationId)).toEqual(['e0b', 'e0c', 'none'])
    const fresh = new TopicKernel({ genesis: g, cas })
    await fresh.materialize([early, e0a, e0b, e0c, e1a, x0a, noEpoch])
    expect(fresh.revision('local').digest).toBe(k.revision('local').digest)

    // Counts survive an exact cache restore.
    const restored = new TopicKernel({ genesis: g, cas })
    expect(await restored.restoreMaterializedCache(k.exportMaterializedCache(), [early, e0a, e0b, e0c, e1a, x0a, noEpoch])).toBe(true)
    const next = enc('e1b', 70n, 1), over = enc('e1c', 80n, 1)
    const after = await restored.materialize([early, e0a, e0b, e0c, e1a, x0a, noEpoch, next, over])
    expect(after.outcomes.slice(-2).map(o => o.rejectionCode)).toEqual([null, 'epoch_op_budget_exhausted'])
  })
})

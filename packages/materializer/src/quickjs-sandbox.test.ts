import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import type { JsonValue } from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { CRYPTO_BUILTIN_ID, QuickJsSandbox, type ReducerInvocationInput } from './quickjs-sandbox.js'

const TX = { opId: '0'.repeat(64), author: '1'.repeat(64), authorTimestampMs: 5, operationId: 'op' }

async function setup(source: string): Promise<{ sandbox: QuickJsSandbox; input: (over?: Partial<ReducerInvocationInput>) => ReducerInvocationInput }> {
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const hash = await cas.put(utf8(source), [], 'private')
  const sandbox = new QuickJsSandbox()
  const input = (over: Partial<ReducerInvocationInput> = {}): ReducerInvocationInput => ({
    imports: { 'app/m': `cas:sha256-${hash}` }, builtins: {}, moduleSpecifier: 'app/m', exportName: 'default',
    method: 'reduce', state: null, payload: null, tx: TX, topics: {}, cas, casPartition: 'private', readOnly: false,
    maxMemoryBytes: 16 * 1024 * 1024, ...over,
  })
  return { sandbox, input }
}

async function value(sandbox: QuickJsSandbox, input: ReducerInvocationInput): Promise<JsonValue> {
  const res = await sandbox.invoke(input)
  if (!res.ok) throw new Error(`${res.code}:${res.detail ?? ''}`)
  return res.value
}

describe('QuickJsSandbox isolation', () => {
  it('gives every invocation a pristine global environment and fresh module instances', async () => {
    const { sandbox, input } = await setup(`
      let calls = 0;
      export default {
        reduce(state, tx, ctx) {
          calls += 1;
          const seen = {
            calls,
            globalX: typeof globalThis.leakX,
            protoPolluted: ({}).polluted === true,
            mathPatched: typeof Math.leak,
            jsonPatched: JSON.leak === true,
            hostTampered: globalThis.__chronologHost && globalThis.__chronologHost.leak === true,
            topicMutated: ctx.topic('t') && ctx.topic('t').mutated === true,
          };
          globalThis.leakX = 1;
          Object.prototype.polluted = true;
          Math.leak = () => 1;
          JSON.leak = true;
          if (globalThis.__chronologHost) globalThis.__chronologHost.leak = true;
          const t = ctx.topic('t');
          let topicFreezeThrew = false;
          try { if (t) t.mutated = true; } catch (e) { topicFreezeThrew = e instanceof TypeError; }
          return { ok: true, state: { ...seen, topicFreezeThrew } };
        },
      };
    `)
    const expected = { calls: 1, globalX: 'undefined', protoPolluted: false, mathPatched: 'undefined', jsonPatched: false, hostTampered: false, topicMutated: false, topicFreezeThrew: true }
    for (let i = 0; i < 3; i++) {
      expect(await value(sandbox, input({ topics: { t: { a: 1 } } }))).toEqual({ ok: true, state: expected })
    }
  })

  it('strips non-deterministic globals, including the quickjs-ng performance clock', async () => {
    const { sandbox, input } = await setup(`
      export default {
        reduce() {
          let random = 'ok';
          try { Math.random(); } catch (e) { random = e.message; }
          return { ok: true, state: {
            date: typeof Date, dateOwn: Object.getOwnPropertyDescriptor(globalThis, 'Date'),
            intl: typeof Intl, performance: typeof performance,
            weakRef: typeof WeakRef, finalizationRegistry: typeof FinalizationRegistry,
            bigInt: String(BigInt(42) + 1n), random,
          } };
        },
      };
    `)
    expect(await value(sandbox, input())).toEqual({ ok: true, state: {
      date: 'undefined', dateOwn: { writable: false, enumerable: false, configurable: false },
      intl: 'undefined', performance: 'undefined',
      weakRef: 'undefined', finalizationRegistry: 'undefined',
      bigInt: '43', random: 'NONDETERMINISTIC_MATH_RANDOM',
    } })
  })

  it('exposes builtin host bridges only through enabled, imported builtins', async () => {
    const { sandbox, input } = await setup(`
      import { sha256 } from 'chronolog:crypto';
      export default {
        reduce() {
          return { ok: true, state: { digest: sha256('abc'), cas: typeof globalThis.__chronologHost.casGet } };
        },
      };
    `)
    expect(await value(sandbox, input({ builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID } }))).toEqual({ ok: true, state: {
      digest: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', cas: 'undefined',
    } })
  })
})

describe('QuickJsSandbox ctx', () => {
  const CTX_PROBE = `
    export default {
      reduce(state, tx, ctx) {
        const before = ctx.topic('t');
        return { ok: true, state: {
          frozen: Object.isFrozen(ctx),
          keys: Object.keys(ctx),
          sameTopic: ctx.topic('t') === before && ctx.topic({ toString() { return 't' } }) === before,
          topic: before, missing: ctx.topic('nope'),
          outcome: [ctx.opOutcome('a'), ctx.opOutcome('b'), ctx.opOutcome('c')],
          lastOp: [ctx.topicLastOpId('t'), ctx.topicLastOpId('u')],
          query: ctx.query('t', { k: 1 }),
          mount: [ctx.mount('m1'), ctx.mount('m2')],
          config: ctx.config,
          tx, state,
          coercionThrows: (() => { const err = new TypeError('bad key'); try { ctx.topic({ toString() { throw err } }); return 'no-throw' } catch (e) { return e === err } })(),
        } };
      },
      query(state, input, ctx) { return { state, input, config: ctx.config } },
      describe(state, ctx) { return { described: state, config: ctx.config } },
      onConflict(state, tx, ctx, conflict) { return { ok: true, state: { conflict, op: tx.operationId } } },
    };
  `

  it('matches the former in-VM ctx semantics for reduce', async () => {
    const { sandbox, input } = await setup(CTX_PROBE)
    const out = await value(sandbox, input({
      state: { s: 1 }, payload: { p: 2 }, config: { c: 3 },
      topics: { t: { v: 1 }, $mounts: { mounts: { m1: { topics: {} } } } },
      opOutcomes: { a: 'accepted', b: 'rejected' },
      topicLastOpIds: { t: 'f'.repeat(64) },
    }))
    expect(out).toEqual({ ok: true, state: {
      frozen: true,
      keys: ['topic', 'query', 'can', 'reject', 'mount', 'mountQuery', 'opOutcome', 'topicLastOpId', 'authorLastOpId', 'config'],
      sameTopic: true,
      topic: { v: 1 }, missing: null,
      outcome: ['accepted', 'rejected', null],
      lastOp: ['f'.repeat(64), null],
      query: { v: 1 },
      mount: [{ topics: {} }, null],
      config: { c: 3 },
      tx: { ...TX, payload: { p: 2 } }, state: { s: 1 },
      coercionThrows: true,
    } })
  })

  it('passes query/describe/onConflict arguments in their documented positions', async () => {
    const { sandbox, input } = await setup(CTX_PROBE)
    expect(await value(sandbox, input({ method: 'query', state: 1, payload: { q: 2 }, config: 'c' }))).toEqual({ state: 1, input: { q: 2 }, config: 'c' })
    expect(await value(sandbox, input({ method: 'describe', state: 7 }))).toEqual({ described: 7, config: null })
    expect(await value(sandbox, input({ method: 'onConflict', conflict: { code: 'x' } }))).toEqual({ ok: true, state: { conflict: { code: 'x' }, op: 'op' } })
  })

  it('distinguishes intentional ctx.reject() from uncaught reducer crashes and enforces deepFreeze + strict JSON output', async () => {
    const { sandbox, input } = await setup(`
      export default { reduce() { throw new RangeError('boom') } };
      export const zero = 0;
      export const nothing = null;
      export const undef = undefined;
      export const rejecter = { reduce(s, tx, ctx) { ctx.reject('insufficient_funds', 'need 50'); } };
      export const mutator = { reduce(state) { state.nested.x = 99; return { ok: true, state }; } };
      export const badNaN = { reduce() { return { ok: true, state: { balance: NaN } }; } };
      export const badMap = { reduce() { return { ok: true, state: { items: new Map([['a', 1]]) } }; } };
    `)
    expect(await sandbox.invoke(input({ method: 'query' }))).toEqual({ ok: false, code: 'vm:missing_method:query' })
    for (const exportName of ['zero', 'nothing', 'undef']) {
      expect(await sandbox.invoke(input({ exportName }))).toEqual({ ok: false, code: 'vm:missing_method:reduce' })
    }
    const missingExport = await sandbox.invoke(input({ exportName: 'absent' }))
    expect(missingExport.ok ? null : missingExport.code).toBe('vm:module_load_error')
    expect(await sandbox.invoke(input())).toMatchObject({ ok: false, code: 'reducer:crash', detail: expect.stringContaining('boom') })
    expect(await sandbox.invoke(input({ exportName: 'rejecter' }))).toEqual({ ok: true, value: { ok: false, code: 'insufficient_funds', detail: 'need 50' } })
    expect(await sandbox.invoke(input({ exportName: 'mutator', state: { nested: { x: 1 } } }))).toMatchObject({ ok: false, code: 'reducer:crash' })
    expect(await sandbox.invoke(input({ exportName: 'badNaN' }))).toMatchObject({ ok: false, code: 'vm:invalid_output', detail: expect.stringContaining('$.state.balance') })
    expect(await sandbox.invoke(input({ exportName: 'badMap' }))).toMatchObject({ ok: false, code: 'vm:invalid_output', detail: expect.stringContaining('$.state.items') })
  })
})

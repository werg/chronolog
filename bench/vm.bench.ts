/**
 * Micro-benchmark: cost breakdown of one QuickJS reducer invocation. `pnpm tsx bench/vm.bench.ts`
 *
 * Part 1 times `QuickJsSandbox.invoke` end to end for a trivial KV reducer, the 600-line standard
 * `chronolog/permissions` module (query path) and a SQL reducer (`chronolog:sqlite` builtin).
 * Part 2 times the raw QuickJS primitives one invocation is built from, so the fixed cost can be
 * attributed (context creation with/without the Date intrinsic, prelude eval, per-function compile
 * cost, host function creation, FFI calls, module load, std-module compile).
 *
 * Every figure is the minimum over interleaved rounds (`--rounds`, default 15), which is far more
 * stable than a single mean on a loaded machine. `--n` sets iterations per round.
 */
import { performance } from 'node:perf_hooks'
import { MemoryBytesStore, ContentAddressedStore } from '@chronolog/records'
import { utf8 } from '@chronolog/canonical'
import { QuickJsSandbox, loadQuickJsModule, CRYPTO_BUILTIN_ID, type ReducerInvocationInput } from '../packages/materializer/src/quickjs-sandbox.js'
import { STD_ADMISSION_SOURCE } from '../packages/materializer/src/std-modules.js'
import { createSqliteCasDriver, SQLITE_CAS_BUILTIN_ID } from '../packages/sqlite-cas/src/index.js'

const argNum = (name: string, fallback: number): number => { const i = process.argv.indexOf(`--${name}`); return i >= 0 ? Number(process.argv[i + 1]) || fallback : fallback }
const N = argNum('n', 100)
const ROUNDS = argNum('rounds', 15)
const SOURCE = `export default { reduce(state, tx) { const next = Object.assign({}, state || {}); next[tx.payload.key] = tx.payload.value; return { ok: true, state: next } } }`
const SQL_SOURCE = `
import { openDb } from 'chronolog:sqlite';
export default {
  reduce(state, tx) {
    const db = openDb(state);
    db.exec('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)', [], { mode: 'admin' });
    db.exec('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', [tx.payload.key, String(tx.payload.value)], { mode: 'admin' });
    return { ok: true, state: db.commit() };
  },
}`
const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
const hash = await cas.put(utf8(SOURCE), [], 'private')
const permHash = await cas.put(utf8(STD_ADMISSION_SOURCE), [], 'public')
const sqlHash = await cas.put(utf8(SQL_SOURCE), [], 'private')

type Case = readonly [label: string, run: () => unknown]
/** Min-of-rounds per case, cases interleaved within each round. */
async function measure(title: string, cases: readonly Case[], n = N): Promise<void> {
  console.log(`\n# ${title} (min of ${ROUNDS} rounds x ${n})`)
  const best = new Map<string, number>()
  for (const [, run] of cases) for (let i = 0; i < 20; i++) await run()
  for (let round = 0; round < ROUNDS; round++) {
    for (const [label, run] of cases) {
      const t = performance.now()
      for (let i = 0; i < n; i++) await run()
      best.set(label, Math.min(best.get(label) ?? Infinity, (performance.now() - t) / n))
    }
  }
  for (const [label, ms] of best) console.log(`${label.padEnd(48)} ${ms.toFixed(4)} ms`)
}

const base = {
  builtins: {}, exportName: 'default', logId: 'ab'.repeat(32), topics: {}, cas, casPartition: 'private' as const, readOnly: false,
  maxMemoryBytes: 64 * 1024 * 1024, maxFuel: 200_000,
  tx: { opId: '0'.repeat(64), author: '1'.repeat(64), authorTimestampMs: 1, operationId: 'x' },
}
const kvInput: ReducerInvocationInput = {
  ...base, imports: { 'app/kv': `cas:sha256-${hash}` }, moduleSpecifier: 'app/kv',
  method: 'reduce', state: {}, payload: { key: 'a', value: 1 },
}
const permInput: ReducerInvocationInput = {
  ...base, imports: { 'chronolog/admission': `cas:sha256-${permHash}` }, moduleSpecifier: 'chronolog/admission',
  exportName: 'attestedAdmission', builtins: { 'chronolog:crypto': CRYPTO_BUILTIN_ID }, method: 'query', state: null,
  payload: { kind: 'roster' }, casPartition: 'public', readOnly: true,
}
const sqlInput: ReducerInvocationInput = {
  ...kvInput, imports: { 'app/sql': `cas:sha256-${sqlHash}` }, moduleSpecifier: 'app/sql',
  builtins: { 'chronolog:sqlite': SQLITE_CAS_BUILTIN_ID }, state: null,
}
const sandbox = new QuickJsSandbox({ sqliteDriver: await createSqliteCasDriver() })
await measure('QuickJsSandbox.invoke', [
  ['invoke kv reduce', () => sandbox.invoke(kvInput)],
  ['invoke permissions query (600-line std module)', () => sandbox.invoke(permInput)],
  ['invoke sql reduce (fresh db)', () => sandbox.invoke(sqlInput)],
])

const qjs = await loadQuickJsModule()
const rt = qjs.newRuntime()
rt.setMemoryLimit(64 * 1024 * 1024)
rt.setMaxStackSize(512 * 1024)
rt.setInterruptHandler(() => false)
rt.setModuleLoader((name: string) => name === 'perm' ? STD_ADMISSION_SOURCE
  : name === 'chronolog:crypto' ? 'export function sha256() {} export function verifyEd25519() {} export function canonicalJson() {}'
    : SOURCE)
// quickjs-emscripten DefaultIntrinsics minus Date (what QuickJsSandbox uses).
const NO_DATE = { intrinsics: { BaseObjects: true, Date: false, Eval: true, StringNormalize: true, RegExp: true, JSON: true, Proxy: true, MapSet: true, TypedArrays: true, Promise: true } }
type QuickJSContext = ReturnType<typeof rt.newContext>
/** Fresh context per iteration; `fn` runs in it, context creation included in the figure. */
const inFresh = (fn: (ctx: QuickJSContext) => void) => (): void => {
  const ctx = rt.newContext(NO_DATE)
  try { fn(ctx) } finally { ctx.dispose() }
}
const evalDispose = (ctx: QuickJSContext, code: string, module = false): void => {
  const r = ctx.evalCode(code, module ? 'b.mjs' : 'p.js', module ? { type: 'module' } : undefined)
  if (r.error) { const e = JSON.stringify(ctx.dump(r.error)); r.error.dispose(); throw new Error(`eval failed: ${e}`) }
  r.value.dispose()
}
const PRELUDE = `Object.defineProperty(globalThis, 'Date', { value: undefined, writable: false, configurable: false });
Object.defineProperty(Math, 'random', { value: () => { throw new Error('NONDETERMINISTIC_MATH_RANDOM'); }, writable: false, configurable: false });
if (typeof Intl !== 'undefined') { Object.defineProperty(globalThis, 'Intl', { value: undefined, writable: false, configurable: false }); }`
await measure('Raw QuickJS primitives (each includes a fresh context unless noted)', [
  ['newContext+dispose (default intrinsics)', () => rt.newContext().dispose()],
  ['newContext+dispose (no Date intrinsic)', () => rt.newContext(NO_DATE).dispose()],
  ['+ eval "1"', inFresh(ctx => evalDispose(ctx, '1'))],
  ['+ determinism prelude eval', inFresh(ctx => evalDispose(ctx, PRELUDE))],
  ['+ compile 8 empty closures', inFresh(ctx => evalDispose(ctx, '[' + Array.from({ length: 8 }, () => '() => {}').join(',') + ']'))],
  ['+ 8 host newFunction', inFresh(ctx => { for (let i = 0; i < 8; i++) ctx.newFunction('f', () => ctx.undefined).dispose() })],
  ['+ 8 getProp(global, name)', inFresh(ctx => { for (let i = 0; i < 8; i++) ctx.getProp(ctx.global, 'JSON').dispose() })],
  ['+ module import of kv reducer', inFresh(ctx => evalDispose(ctx, `import m from 'kv'; export default m;`, true))],
  ['+ module import of permissions std module', inFresh(ctx => evalDispose(ctx, `import { attestedMembers } from 'perm'; export default attestedMembers;`, true))],
])
rt.dispose()

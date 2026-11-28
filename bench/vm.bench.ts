/** Micro-benchmark: cost breakdown of one QuickJS reducer invocation. `pnpm tsx bench/vm.bench.ts` */
import { performance } from 'node:perf_hooks'
import { MemoryBytesStore, ContentAddressedStore } from '@chronolog/records'
import { utf8 } from '@chronolog/canonical'
import { QuickJsSandbox, loadQuickJsModule } from '../packages/materializer/src/quickjs-sandbox.js'

const SOURCE = `export default { reduce(state, tx) { const next = Object.assign({}, state || {}); next[tx.payload.key] = tx.payload.value; return { ok: true, state: next } } }`
const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
const hash = await cas.put(utf8(SOURCE), [], 'private')
const sandbox = new QuickJsSandbox()
const input = {
  imports: { 'app/kv': `cas:sha256-${hash}` }, builtins: {}, moduleSpecifier: 'app/kv', exportName: 'default',
  method: 'reduce' as const, state: {}, payload: { key: 'a', value: 1 }, topics: {},
  tx: { opId: '0'.repeat(64), author: '1'.repeat(64), authorTimestampMs: 1, operationId: 'x' },
  cas, casPartition: 'private' as const, readOnly: false, maxMemoryBytes: 64 * 1024 * 1024,
}
for (let i = 0; i < 50; i++) await sandbox.invoke(input)
const n = 500
let t = performance.now()
for (let i = 0; i < n; i++) await sandbox.invoke(input)
console.log(`invoke: ${((performance.now() - t) / n).toFixed(3)} ms`)

const qjs = await loadQuickJsModule()
const rt = qjs.newRuntime()
t = performance.now()
for (let i = 0; i < n; i++) rt.newContext().dispose()
console.log(`newContext+dispose: ${((performance.now() - t) / n).toFixed(3)} ms`)
const ctx = rt.newContext()
t = performance.now()
for (let i = 0; i < n; i++) { const r = ctx.evalCode(SOURCE.replace('export default', 'const m ='), 'm.js'); if (r.error) r.error.dispose(); else r.value.dispose() }
console.log(`compile+eval reducer source: ${((performance.now() - t) / n).toFixed(3)} ms`)

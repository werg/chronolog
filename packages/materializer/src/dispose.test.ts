import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import { generateEd25519KeyPair, operationIdDigest, type LogGenesis, type OperationCore } from '@chronolog/protocol'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import { TopicKernel } from './kernel.js'
import { loadQuickJsModule, QUICKJS_RUNTIME_ID } from './quickjs-sandbox.js'

const COUNTER = `export default { reduce(state, tx) { return { ok: true, state: (state ?? 0) + tx.payload.delta } } }`

async function counterKernel(): Promise<{ kernel: TopicKernel; op: (id: string, ts: bigint) => { opId: Uint8Array; core: OperationCore } }> {
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const hash = await cas.put(utf8(COUNTER), [], 'private')
  const author = await generateEd25519KeyPair()
  const genesis: LogGenesis = {
    version: 1,
    privateLog: false,
    initialTopics: {
      $reducers: { runtime: { js: QUICKJS_RUNTIME_ID, builtins: {} }, imports: { '@app/counter': `cas:sha256-${hash}` }, topics: { counter: { module: '@app/counter' } } },
      counter: 0,
    },
    limits: { maxMemoryBytes: 16 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 16, maxFuel: 200_000 },
    salt: new Uint8Array(16).fill(7),
  }
  const kernel = new TopicKernel({ genesis, cas })
  const op = (operationId: string, authorTimestampMs: bigint) => {
    const core: OperationCore = {
      version: 1, logId: kernel.logId, author: author.publicKeyBytes, operationId, authorTimestampMs,
      nonce: new Uint8Array(16).fill(1), visibility: 'public', updates: [{ topic: 'counter', input: { delta: 2 } }],
    }
    return { opId: operationIdDigest(core), core }
  }
  return { kernel, op }
}

describe('TopicKernel.dispose', () => {
  it('releases the VM, keeps committed revision readable, and rejects further execution', async () => {
    const { kernel, op } = await counterKernel()
    const first = op('a', 1n)
    await kernel.materialize([first])
    expect(kernel.topic('counter')).toBe(2)
    const revision = kernel.revision()

    kernel.dispose()
    kernel.dispose() // idempotent
    expect(kernel.disposed).toBe(true)
    expect(kernel.sandbox.disposed).toBe(true)
    expect(kernel.revision().stateRoot).toBe(revision.stateRoot)
    expect(kernel.topic('counter')).toBe(2)
    await expect(kernel.materialize([first, op('b', 2n)])).rejects.toThrow('SANDBOX_DISPOSED')
    await expect(kernel.query('counter')).rejects.toThrow('SANDBOX_DISPOSED')
  })

  it('shares one QuickJS instance per compiled WebAssembly module across kernels', async () => {
    const qjs = await loadQuickJsModule()
    const { createRequire } = await import('node:module')
    const { readFile } = await import('node:fs/promises')
    const wasmPath = createRequire(import.meta.url).resolve('@jitl/quickjs-ng-wasmfile-release-sync/wasm')
    const wasmModule = await WebAssembly.compile(await readFile(wasmPath))
    const [a, b] = await Promise.all([loadQuickJsModule(wasmModule), loadQuickJsModule(wasmModule)])
    expect(a).toBe(b)
    expect(a).not.toBe(qjs)
  })
})

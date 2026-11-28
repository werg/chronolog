import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import {
  casRef,
  ContentAddressedStore,
  decodeTreeNode,
  MemoryBytesStore,
  parseCasRef,
  putDerivationNode,
  putTreeDag,
  readBlobDag,
} from '@chronolog/records'
import { evaluateDerivation } from './derivation.js'
import { QuickJsSandbox } from './quickjs-sandbox.js'
import { createWasiCasRunner } from './wasi-cas-runner.js'

/** Minimal unsigned LEB128 encoder for hand-assembled deterministic WASM test binaries. */
function uleb(n: number): number[] {
  const out: number[] = []
  let v = n >>> 0
  do {
    let b = v & 0x7f
    v >>>= 7
    if (v !== 0) b |= 0x80
    out.push(b)
  } while (v !== 0)
  return out
}

function sleb(n: number): number[] {
  const out: number[] = []
  let v = n | 0
  let more = true
  while (more) {
    let b = v & 0x7f
    v >>= 7
    if ((v === 0 && (b & 0x40) === 0) || (v === -1 && (b & 0x40) !== 0)) more = false
    else b |= 0x80
    out.push(b)
  }
  return out
}

function section(id: number, body: number[]): number[] {
  return [id, ...uleb(body.length), ...body]
}

function strBytes(s: string): number[] {
  const b = [...utf8(s)]
  return [...uleb(b.length), ...b]
}

/**
 * Hand-assemble a pure `wasi_snapshot_preview1` WASM module that:
 * 1. Opens `/inputs/src/hello.txt` via `path_open(3, 0, ptr, len, 0, 0n, 0n, 0, fdOutPtr)`
 * 2. Reads up to 64 bytes into memory[512] via `fd_read`
 * 3. Opens `/out/copied.txt` with O_CREAT|O_TRUNC (9) via `path_open`
 * 4. Writes the exact read bytes via `fd_write`
 * 5. Calls `proc_exit(0)`
 */
function buildWasiCopyModule(): Uint8Array {
  // Types:
  // 0: path_open(i32,i32,i32,i32,i32,i64,i64,i32,i32) -> i32
  // 1: fd_read/fd_write(i32,i32,i32,i32) -> i32
  // 2: proc_exit(i32) -> ()
  // 3: _start() -> ()
  const types = [
    4,
    0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 1, 0x7f, 0,
    0x60, 0, 0,
  ]
  const imports = [
    4,
    ...strBytes('wasi_snapshot_preview1'), ...strBytes('path_open'), 0x00, 0,
    ...strBytes('wasi_snapshot_preview1'), ...strBytes('fd_read'), 0x00, 1,
    ...strBytes('wasi_snapshot_preview1'), ...strBytes('fd_write'), 0x00, 1,
    ...strBytes('wasi_snapshot_preview1'), ...strBytes('proc_exit'), 0x00, 2,
  ]
  const funcs = [1, 3]
  const mem = [1, 0x00, 1] // 1 page (64 KiB)
  const exportsSec = [
    2,
    ...strBytes('memory'), 0x02, 0,
    ...strBytes('_start'), 0x00, 4,
  ]

  // Data layout:
  // 0..19:   "inputs/src/hello.txt" (20 bytes)
  // 32..45:  "out/copied.txt" (14 bytes)
  // 100:     inFd (u32)
  // 104:     outFd (u32)
  // 108:     nread (u32)
  // 112:     nwritten (u32)
  // 128:     iov { ptr: 512, len: 64 }
  // 512..:   buffer
  const inPath = [...utf8('inputs/src/hello.txt')]
  const outPath = [...utf8('out/copied.txt')]
  const iovInit = [
    0x00, 0x02, 0x00, 0x00, // ptr = 512
    0x40, 0x00, 0x00, 0x00, // len = 64
  ]
  const data = [
    3,
    0, 0x41, ...sleb(0), 0x0b, ...uleb(inPath.length), ...inPath,
    0, 0x41, ...sleb(32), 0x0b, ...uleb(outPath.length), ...outPath,
    0, 0x41, ...sleb(128), 0x0b, ...uleb(iovInit.length), ...iovInit,
  ]

  const codeBody = [
    0, // 0 locals
    // path_open(3, 0, 0, 20, 0, 0n, 0n, 0, 100); drop
    0x41, ...sleb(3), 0x41, ...sleb(0), 0x41, ...sleb(0), 0x41, ...sleb(inPath.length),
    0x41, ...sleb(0), 0x42, 0x00, 0x42, 0x00, 0x41, ...sleb(0), 0x41, ...sleb(100),
    0x10, 0, 0x1a,
    // fd_read(mem[100], 128, 1, 108); drop
    0x41, ...sleb(100), 0x28, 0x02, 0x00,
    0x41, ...sleb(128), 0x41, ...sleb(1), 0x41, ...sleb(108),
    0x10, 1, 0x1a,
    // update iov.len at mem[132] = mem[108] (nread)
    0x41, ...sleb(132),
    0x41, ...sleb(108), 0x28, 0x02, 0x00,
    0x36, 0x02, 0x00,
    // path_open(3, 0, 32, 14, 9, 0n, 0n, 0, 104); drop
    0x41, ...sleb(3), 0x41, ...sleb(0), 0x41, ...sleb(32), 0x41, ...sleb(outPath.length),
    0x41, ...sleb(9), 0x42, 0x00, 0x42, 0x00, 0x41, ...sleb(0), 0x41, ...sleb(104),
    0x10, 0, 0x1a,
    // fd_write(mem[104], 128, 1, 112); drop
    0x41, ...sleb(104), 0x28, 0x02, 0x00,
    0x41, ...sleb(128), 0x41, ...sleb(1), 0x41, ...sleb(112),
    0x10, 2, 0x1a,
    // proc_exit(0)
    0x41, ...sleb(0), 0x10, 3,
    0x0b,
  ]
  const code = [1, ...uleb(codeBody.length), ...codeBody]

  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, types),
    ...section(2, imports),
    ...section(3, funcs),
    ...section(5, mem),
    ...section(7, exportsSec),
    ...section(10, code),
    ...section(11, data),
  ])
}

/** Tiny WASI binary that attempts to call `random_get` (must trap deterministically). */
function buildWasiRandomTrapModule(): Uint8Array {
  const types = [2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0]
  const imports = [1, ...strBytes('wasi_snapshot_preview1'), ...strBytes('random_get'), 0x00, 0]
  const funcs = [1, 1]
  const mem = [1, 0x00, 1]
  const exportsSec = [2, ...strBytes('memory'), 0x02, 0, ...strBytes('_start'), 0x00, 1]
  const body = [0, 0x41, 0x00, 0x41, 0x08, 0x10, 0, 0x1a, 0x0b]
  const code = [1, ...uleb(body.length), ...body]
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...section(1, types),
    ...section(2, imports),
    ...section(3, funcs),
    ...section(5, mem),
    ...section(7, exportsSec),
    ...section(10, code),
  ])
}

describe('Deterministic WASI-over-CAS Builder Runner (wasi-cas-v1)', () => {
  it('executes a pure WASI module reading /inputs/<name>/... and writing /out/... into a chronolog-tree/v1', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const sandbox = new QuickJsSandbox()
    try {
      const wasmHash = await cas.put(buildWasiCopyModule(), [], 'public')
      const srcTree = await putTreeDag(cas, { 'hello.txt': 'hello from deterministic wasi-cas!' }, 'public')
      const drv = await putDerivationNode(cas, {
        format: 'chronolog-drv/v1',
        profile: 'wasi-cas-v1',
        builder: casRef(wasmHash),
        inputs: { src: srcTree.ref },
        args: { optimize: true },
        limits: { maxMemoryBytes: 8 * 1024 * 1024, maxFuel: 100_000 },
      }, 'public')

      const res = await evaluateDerivation({
        drvRefOrHash: drv.ref,
        cas,
        sandbox,
        wasiRunners: { '*': createWasiCasRunner() },
      })
      expect(res.fromCache).toBe(false)
      const outNode = await cas.get(res.outputHash, 'public')
      expect(outNode).not.toBeNull()
      const outTree = decodeTreeNode(outNode!.bytes)
      const copiedRef = outTree.entries['copied.txt']
      expect(copiedRef).toBeDefined()
      const copiedBytes = await readBlobDag(cas, parseCasRef(copiedRef!), 'public')
      expect(new TextDecoder().decode(copiedBytes!)).toBe('hello from deterministic wasi-cas!')
    } finally {
      sandbox.dispose()
    }
  })

  it('deterministically traps non-deterministic WASI random_get syscalls', async () => {
    const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
    const sandbox = new QuickJsSandbox()
    try {
      const wasmHash = await cas.put(buildWasiRandomTrapModule(), [], 'public')
      const drv = await putDerivationNode(cas, {
        format: 'chronolog-drv/v1',
        profile: 'wasi-cas-v1',
        builder: casRef(wasmHash),
        inputs: {},
        args: {},
        limits: { maxMemoryBytes: 8 * 1024 * 1024, maxFuel: 100_000 },
      }, 'public')

      await expect(evaluateDerivation({
        drvRefOrHash: drv.ref,
        cas,
        sandbox,
        wasiRunners: { '*': createWasiCasRunner() },
      })).rejects.toThrow(/WASI_NONDETERMINISTIC_RANDOM/u)
    } finally {
      sandbox.dispose()
    }
  })
})

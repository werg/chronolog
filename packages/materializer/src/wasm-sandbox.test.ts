import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import { ContentAddressedStore, MemoryBytesStore } from '@chronolog/records'
import {
  FuelMeter,
  instrumentWasmModule,
  WasmModuleRejectedError,
  WasmSandbox,
  type WasmCallHostContext,
} from './wasm-sandbox.js'

const uleb = (n: number): number[] => {
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
const sec = (id: number, body: readonly number[]): number[] => [id, ...uleb(body.length), ...body]
const str = (s: string): number[] => [...uleb(utf8(s).length), ...utf8(s)]
const vec = (items: readonly (readonly number[])[]): number[] => [...uleb(items.length), ...items.flat()]

interface Fn { readonly params: readonly number[]; readonly results: readonly number[]; readonly locals?: readonly number[]; readonly body: readonly number[]; readonly export?: string }

/** Tiny assembler: one type per function, optional memory (min/max pages), raw extra sections. */
function wasm(fns: readonly Fn[], options: { readonly memory?: readonly number[]; readonly imports?: readonly number[]; readonly extra?: readonly number[] } = {}): Uint8Array {
  const types = sec(1, vec(fns.map(f => [0x60, ...vec(f.params.map(p => [p])), ...vec(f.results.map(r => [r]))])))
  const funcs = sec(3, vec(fns.map((_, i) => uleb(i))))
  const exportsList: number[][] = fns.flatMap((f, i) => (f.export === undefined ? [] : [[...str(f.export), 0x00, ...uleb(i)]]))
  if (options.memory !== undefined) exportsList.push([...str('memory'), 0x02, 0x00])
  const code = sec(10, vec(fns.map(f => {
    const body = [...vec((f.locals ?? []).map(t => [0x01, t])), ...f.body, 0x0b]
    return [...uleb(body.length), ...body]
  })))
  return new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...types, ...(options.imports ?? []), ...funcs,
    ...(options.memory === undefined ? [] : sec(5, [0x01, ...options.memory])),
    ...sec(7, vec(exportsList)), ...(options.extra ?? []), ...code,
  ])
}

const I32 = 0x7f
const I64 = 0x7e
const F64 = 0x7c

async function setup(bytes: Uint8Array, maxFuel = 1_000, maxMemoryBytes = 1 << 20): Promise<{ sandbox: WasmSandbox; hash: string; host: () => WasmCallHostContext }> {
  const cas = new ContentAddressedStore({ store: new MemoryBytesStore() })
  const hash = await cas.put(bytes, [], 'public')
  const sandbox = new WasmSandbox()
  const host = (): WasmCallHostContext => ({
    cas,
    readPartition: 'any',
    writePartition: 'private',
    readOnly: false,
    maxMemoryBytes,
    fuel: new FuelMeter(maxFuel),
    onMissingCas: (h) => { throw new Error(`missing ${h}`) },
  })
  return { sandbox, hash, host }
}

describe('WasmSandbox deterministic metering', () => {
  it('traps `loop br 0` with fuel exhaustion instead of hanging', async () => {
    const spin = wasm([{ params: [], results: [I32], export: 'spin', body: [0x03, 0x40, 0x0c, 0x00, 0x0b, 0x41, 0x00] }])
    const { sandbox, hash, host } = await setup(spin)
    const h = host()
    expect(() => sandbox.invokeNumeric(hash, 'spin', [], h)).toThrow(/FUEL_EXHAUSTED/)
    expect(h.fuel.exhausted).toBe(true)
  })

  it('charges an exact, replica-independent fuel amount per bounded loop', async () => {
    // count(n): i = 0; loop { i++; br_if (i < n) }; return i
    const count = wasm([{
      params: [I32], results: [I32], locals: [I32], export: 'count',
      body: [0x03, 0x40, 0x20, 0x01, 0x41, 0x01, 0x6a, 0x22, 0x01, 0x20, 0x00, 0x48, 0x0d, 0x00, 0x0b, 0x20, 0x01],
    }])
    const { sandbox, hash, host } = await setup(count, 10_000)
    const runs = [0, 1, 2].map(() => {
      const h = host()
      expect(sandbox.invokeNumeric(hash, 'count', [100_000], h)).toBe(100_000)
      return h.fuel.used
    })
    expect(runs[0]).toBeGreaterThan(50)
    expect(new Set(runs).size).toBe(1)
    const { sandbox: fresh, hash: h2, host: host2 } = await setup(count, runs[0]! - 1)
    expect(() => fresh.invokeNumeric(h2, 'count', [100_000], host2())).toThrow(/FUEL_EXHAUSTED/)
  })

  it('charges bulk memory operations by length', async () => {
    // fill(len): memory.fill(0, 7, len) repeatedly from a loop of 64 iterations
    const fill = wasm([{
      params: [I32], results: [I32], locals: [I32], export: 'fill',
      body: [
        0x03, 0x40,
        0x41, 0x00, 0x41, 0x07, 0x20, 0x00, 0xfc, 0x0b, 0x00,
        0x20, 0x01, 0x41, 0x01, 0x6a, 0x22, 0x01, 0x41, 0xc0, 0x00, 0x48, 0x0d, 0x00,
        0x0b, 0x20, 0x01,
      ],
    }], { memory: [0x01, 0x10, 0x10] })
    const { sandbox, hash, host } = await setup(fill, 50)
    const small = host()
    expect(sandbox.invokeNumeric(hash, 'fill', [16], small)).toBe(64)
    const big = host()
    expect(() => sandbox.invokeNumeric(hash, 'fill', [1 << 20], big)).toThrow(/FUEL_EXHAUSTED/)
    expect(small.fuel.used).toBeLessThan(10)
  })

  it('canonicalizes NaN payloads of float arithmetic', async () => {
    // i64.reinterpret_f64(f64.add(f64.reinterpret_i64(0x7FF4000000000001 (sNaN payload)), 1.0))
    const snan = [0x42, ...[0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xfa, 0xff, 0x00]]
    const nan = wasm([{
      params: [], results: [I64], export: 'nan',
      body: [...snan, 0xbf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f, 0xa0, 0xbd],
    }])
    expect(instrumentWasmModule(nan).bytes.length).toBeGreaterThan(nan.length)
    const { sandbox, hash, host } = await setup(nan)
    const bits = sandbox.invokeNumeric(hash, 'nan', [], host())
    expect(BigInt(bits)).toBe(0x7ff8000000000000n)
  })

  it('rejects non-deterministic or unmeterable modules', () => {
    const reject = (bytes: Uint8Array): string => {
      try { instrumentWasmModule(bytes) } catch (err) { if (err instanceof WasmModuleRejectedError) return err.reason; throw err }
      return 'accepted'
    }
    const noop: Fn = { params: [], results: [], export: 'f', body: [] }
    expect(reject(wasm([noop], { memory: [0x00, 0x01] }))).toBe('memory_max_required')
    expect(reject(wasm([noop], { memory: [0x03, 0x01, 0x01] }))).toBe('shared_memory')
    expect(reject(wasm([{ ...noop, body: [0xfd, 0x0c, ...new Array(16).fill(0), 0x1a] }]))).toBe('simd')
    expect(reject(wasm([{ ...noop, body: [0xfe, 0x03, 0x00] }]))).toBe('threads')
    expect(reject(wasm([noop], { extra: sec(8, [0x00]) }))).toBe('start_function')
    const fuelImport = sec(2, vec([[...str('chronolog'), ...str('fuel_consume'), 0x00, 0x00]]))
    expect(reject(wasm([noop], { imports: fuelImport }))).toBe('import_forbidden:chronolog.fuel_consume')
    expect(reject(wasm([{ ...noop, export: '__chronolog_fuel' }]))).toBe('reserved_export')
    expect(reject(wasm([{ params: [F64], results: [F64], export: 'sq', body: [0x20, 0x00, 0x9f] }]))).toBe('accepted')
  })

  it('refuses a call whose declared memory maximum exceeds the genesis limit', async () => {
    const mod = wasm([{ params: [], results: [I32], export: 'one', body: [0x41, 0x01] }], { memory: [0x01, 0x01, 0x20] })
    const { sandbox, hash, host } = await setup(mod, 1_000, 1 << 20)
    expect(() => sandbox.invokeNumeric(hash, 'one', [], host())).toThrow(/WASM_MEMORY_LIMIT_EXCEEDED/)
    const roomy = await setup(mod, 1_000, 4 << 20)
    expect(roomy.sandbox.invokeNumeric(roomy.hash, 'one', [], roomy.host())).toBe(1)
  })
})

import { bytesToHex, decodeUtf8, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { normalizeJsonValue, type JsonValue } from '@chronolog/protocol'
import {
  readBlobDagSync,
  type CasPartition,
  type ContentAddressedStore,
} from '@chronolog/records'

export const WASM_BUILTIN_ID = 'wasm@1'

interface CompiledWasmEntry {
  readonly module: WebAssembly.Module
  readonly byteLength: number
}

export interface WasmCallHostContext {
  readonly cas: ContentAddressedStore
  readonly readPartition: CasPartition | 'any'
  readonly writePartition: CasPartition
  readonly readOnly: boolean
  readonly maxMemoryBytes: number
  readonly maxFuel: number
  readonly onMissingCas: (hash: string) => never
}

export interface WasmReducerInvocationInput {
  readonly wasmHash: string
  readonly method: 'reduce' | 'query' | 'describe' | 'onConflict'
  readonly state: JsonValue
  readonly payload: JsonValue
  readonly tx?: {
    readonly opId: string
    readonly author: string
    readonly authorTimestampMs: number
    readonly operationId: string
  }
  readonly conflict?: {
    readonly code: string
    readonly detail?: string
    readonly checkIndex?: number
  }
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly config?: JsonValue
  readonly host: WasmCallHostContext
}

export type WasmReducerInvocationResult =
  | { readonly ok: true; readonly value: JsonValue }
  | { readonly ok: false; readonly code: string; readonly detail?: string }

const ALLOWED_IMPORT_MODULES = new Set(['chronolog'])
const ALLOWED_CHRONOLOG_IMPORTS = new Set(['sha256', 'cas_put', 'cas_get', 'fuel_consume'])

/**
 * Pure deterministic WebAssembly execution engine for Chronolog reducers and libraries.
 * - Compiles each cas:sha256-<hash> WASM binary ONCE and caches the WebAssembly.Module in memory.
 * - Strictly rejects any non-'chronolog' host imports (zero WASI, clock, network, or host FS).
 * - Instantiates fresh linear memory per invocation (~10-50us) with memory & fuel enforcement.
 */
export class WasmSandbox {
  readonly #moduleCache = new Map<string, CompiledWasmEntry>()
  readonly #maxCachedModules: number

  constructor(options: { readonly maxCachedModules?: number } = {}) {
    this.#maxCachedModules = options.maxCachedModules ?? 128
  }

  get cachedModuleCount(): number {
    return this.#moduleCache.size
  }

  clearCache(): void {
    this.#moduleCache.clear()
  }

  #compileOrGet(wasmHash: string, host: WasmCallHostContext): CompiledWasmEntry {
    const existing = this.#moduleCache.get(wasmHash)
    if (existing !== undefined) {
      this.#moduleCache.delete(wasmHash)
      this.#moduleCache.set(wasmHash, existing)
      return existing
    }
    const bytes = readBlobDagSync(host.cas, wasmHash, host.readPartition, host.onMissingCas)
    const copy = new Uint8Array(bytes.byteLength)
    copy.set(bytes)
    const mod = new WebAssembly.Module(copy)
    // Strictly validate host imports: only deterministic 'chronolog' bindings are permitted.
    for (const imp of WebAssembly.Module.imports(mod)) {
      if (!ALLOWED_IMPORT_MODULES.has(imp.module) || !ALLOWED_CHRONOLOG_IMPORTS.has(imp.name)) {
        throw new Error(`WASM_IMPORT_FORBIDDEN:${imp.module}.${imp.name}`)
      }
    }
    const entry: CompiledWasmEntry = { module: mod, byteLength: bytes.byteLength }
    this.#moduleCache.set(wasmHash, entry)
    while (this.#moduleCache.size > this.#maxCachedModules) {
      const oldest = this.#moduleCache.keys().next().value
      if (oldest === undefined) break
      this.#moduleCache.delete(oldest)
    }
    return entry
  }

  #instantiate(wasmHash: string, host: WasmCallHostContext): {
    readonly instance: WebAssembly.Instance
    readonly fuelExhausted: () => boolean
  } {
    const compiled = this.#compileOrGet(wasmHash, host)
    let fuelUsed = 0
    let exhausted = false
    let mem: WebAssembly.Memory | null = null

    const getMemory = (): Uint8Array => {
      if (mem === null) throw new Error('WASM_MEMORY_MISSING')
      if (mem.buffer.byteLength > host.maxMemoryBytes) {
        throw new Error('WASM_MEMORY_LIMIT_EXCEEDED')
      }
      return new Uint8Array(mem.buffer)
    }

    const imports: WebAssembly.Imports = {
      chronolog: {
        fuel_consume(amount: number): void {
          fuelUsed += Math.max(1, amount | 0)
          if (fuelUsed > host.maxFuel) {
            exhausted = true
            throw new Error('WASM_FUEL_EXHAUSTED')
          }
        },
        sha256(inPtr: number, inLen: number, outPtr: number): number {
          const view = getMemory()
          const slice = view.subarray(inPtr >>> 0, (inPtr >>> 0) + (inLen >>> 0))
          const digest = sha256Sync(slice)
          view.set(digest, outPtr >>> 0)
          return digest.byteLength
        },
        cas_put(inPtr: number, inLen: number, outHashPtr: number): number {
          if (host.readOnly) throw new Error('CAS_READ_ONLY')
          const view = getMemory()
          const slice = view.slice(inPtr >>> 0, (inPtr >>> 0) + (inLen >>> 0))
          const hashHex = host.cas.putSync(slice, [], host.writePartition)
          const hashBytes = hexToBytes(hashHex)
          view.set(hashBytes, outHashPtr >>> 0)
          return hashBytes.byteLength
        },
        cas_get(hashPtr: number, outPtr: number, maxLen: number): number {
          const view = getMemory()
          const hashBytes = view.subarray(hashPtr >>> 0, (hashPtr >>> 0) + 32)
          const hashHex = bytesToHex(hashBytes)
          const node = host.cas.getSync(hashHex, host.readPartition)
          if (node === null) host.onMissingCas(hashHex)
          const len = node.bytes.byteLength
          if (len > (maxLen >>> 0)) return -len
          view.set(node.bytes, outPtr >>> 0)
          return len
        },
      },
    }

    const instance = new WebAssembly.Instance(compiled.module, imports)
    const exportedMem = instance.exports.memory
    if (exportedMem instanceof WebAssembly.Memory) {
      mem = exportedMem
      if (mem.buffer.byteLength > host.maxMemoryBytes) {
        throw new Error('WASM_MEMORY_LIMIT_EXCEEDED')
      }
    }
    return { instance, fuelExhausted: () => exhausted }
  }

  /** Invoke a numeric export on a cached pure WASM module (for JS reducers using chronolog:wasm). */
  invokeNumeric(
    wasmHash: string,
    exportName: string,
    args: readonly number[],
    host: WasmCallHostContext,
  ): number {
    const { instance, fuelExhausted } = this.#instantiate(wasmHash, host)
    const fn = instance.exports[exportName]
    if (typeof fn !== 'function') throw new Error(`WASM_EXPORT_NOT_FOUND:${exportName}`)
    try {
      const out = (fn as (...a: number[]) => unknown)(...args)
      if (typeof out === 'bigint') return Number(out)
      if (typeof out === 'number') {
        if (!Number.isFinite(out)) throw new Error('WASM_NON_FINITE_RESULT')
        return Object.is(out, -0) ? 0 : out
      }
      return 0
    } catch (err) {
      if (fuelExhausted()) throw new Error('WASM_FUEL_EXHAUSTED', { cause: err })
      throw err
    }
  }

  /** Invoke a JSON-ABI export (alloc + ptr/len -> packed i64 or i32 + result_len) on a pure WASM module. */
  invokeJson(
    wasmHash: string,
    exportName: string,
    input: JsonValue,
    host: WasmCallHostContext,
  ): JsonValue {
    const { instance, fuelExhausted } = this.#instantiate(wasmHash, host)
    const mem = instance.exports.memory
    const alloc = instance.exports.alloc
    const fn = instance.exports[exportName]
    if (!(mem instanceof WebAssembly.Memory)) throw new Error('WASM_MEMORY_MISSING')
    if (typeof alloc !== 'function') throw new Error('WASM_ALLOC_MISSING')
    if (typeof fn !== 'function') throw new Error(`WASM_EXPORT_NOT_FOUND:${exportName}`)

    const inputBytes = utf8(JSON.stringify(input))
    const inPtr = Number((alloc as (n: number) => number)(inputBytes.byteLength)) >>> 0
    if (mem.buffer.byteLength > host.maxMemoryBytes) throw new Error('WASM_MEMORY_LIMIT_EXCEEDED')
    new Uint8Array(mem.buffer, inPtr, inputBytes.byteLength).set(inputBytes)

    let rawResult: unknown
    try {
      rawResult = (fn as (ptr: number, len: number) => unknown)(inPtr, inputBytes.byteLength)
    } catch (err) {
      if (fuelExhausted()) throw new Error('WASM_FUEL_EXHAUSTED', { cause: err })
      throw err
    }
    if (mem.buffer.byteLength > host.maxMemoryBytes) throw new Error('WASM_MEMORY_LIMIT_EXCEEDED')

    let outPtr: number
    let outLen: number
    if (typeof rawResult === 'bigint') {
      outPtr = Number((rawResult >> 32n) & 0xffff_ffffn) >>> 0
      outLen = Number(rawResult & 0xffff_ffffn) >>> 0
    } else if (typeof rawResult === 'number') {
      const resultLenFn = instance.exports.result_len
      if (typeof resultLenFn !== 'function') throw new Error('WASM_RESULT_LEN_MISSING')
      outPtr = rawResult >>> 0
      outLen = Number((resultLenFn as () => number)()) >>> 0
    } else {
      throw new Error('WASM_INVALID_RETURN_ABI')
    }

    if (outPtr + outLen > mem.buffer.byteLength) throw new Error('WASM_OUT_OF_BOUNDS_RESULT')
    const outText = decodeUtf8(new Uint8Array(mem.buffer, outPtr, outLen))
    return normalizeJsonValue(JSON.parse(outText) as unknown)
  }

  /** Execute a standalone pure WASM topic reducer (chronolog-wasm/v1 ABI). */
  invokeReducer(input: WasmReducerInvocationInput): WasmReducerInvocationResult {
    const { instance, fuelExhausted } = this.#instantiate(input.wasmHash, input.host)
    const fn = instance.exports[input.method]
    if (typeof fn !== 'function') {
      return { ok: false, code: `vm:missing_method:${input.method}` }
    }
    const envelope: JsonValue = {
      state: input.state,
      payload: input.payload,
      tx: input.tx === undefined ? null : { ...input.tx, payload: input.payload },
      conflict: input.conflict ?? null,
      topics: input.topics,
      config: input.config ?? null,
    }
    try {
      const val = this.invokeJson(input.wasmHash, input.method, envelope, input.host)
      return { ok: true, value: val }
    } catch (err) {
      if (fuelExhausted() || (err instanceof Error && err.message === 'WASM_FUEL_EXHAUSTED')) {
        return { ok: false, code: 'vm:fuel_exhausted' }
      }
      if (err instanceof Error && err.message === 'WASM_MEMORY_LIMIT_EXCEEDED') {
        return { ok: false, code: 'vm:limit' }
      }
      if (err !== null && typeof err === 'object' && 'code' in err && (err as { code?: unknown }).code === 'MISSING_DEPENDENCY') {
        throw err
      }
      return { ok: false, code: 'reducer:throw', detail: err instanceof Error ? err.message : String(err) }
    }
  }
}

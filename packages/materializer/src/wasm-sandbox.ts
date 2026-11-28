import { bytesToHex, decodeUtf8, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { normalizeJsonValue, type JsonValue } from '@chronolog/protocol'
import {
  readBlobDagSync,
  type CasPartition,
  type ContentAddressedStore,
} from '@chronolog/records'

export const WASM_BUILTIN_ID = 'wasm@1'

/** Thrown by `FuelMeter.charge` once the per-call deterministic budget is spent. */
export class FuelExhaustedError extends Error {
  readonly code = 'FUEL_EXHAUSTED' as const
  constructor() {
    super('FUEL_EXHAUSTED')
    this.name = 'FuelExhaustedError'
  }
}

/**
 * One deterministic fuel budget for a whole invocation (genesis `limits.maxFuel`), shared by
 * nested `ctx.query()` calls. Every metered resource charges it: QuickJS interrupt ticks, metered
 * WASM instructions, SQLite VM steps and page reads, and host bridges (hashing, signature checks,
 * CAS reads/writes, topic transfer). Once exhausted it stays exhausted, so a reducer that catches
 * the thrown error cannot continue: the invocation still ends as `vm:fuel_exhausted`.
 */
export class FuelMeter {
  #remaining: number
  #exhausted = false
  constructor(readonly limit: number) {
    if (!Number.isSafeInteger(limit) || limit <= 0) throw new Error('FUEL_LIMIT_INVALID')
    this.#remaining = limit
  }
  get remaining(): number { return this.#remaining }
  get used(): number { return this.limit - this.#remaining }
  get exhausted(): boolean { return this.#exhausted }
  /** Debit `units`; throws `FuelExhaustedError` (and latches exhaustion) when over budget. */
  charge(units: number): void {
    if (this.#exhausted) throw new FuelExhaustedError()
    if (units <= 0) return
    if (units > this.#remaining) {
      this.#remaining = 0
      this.#exhausted = true
      throw new FuelExhaustedError()
    }
    this.#remaining -= units
  }
}

/** Fuel units per host bridge call (on top of its byte-proportional cost). */
export const HOST_CALL_FUEL = 1
/** Bytes processed by a host bridge (hashing, CAS, JSON transfer) per fuel unit. */
export const HOST_BYTES_PER_FUEL = 32 * 1024
/** Metered WASM instructions per fuel unit (one QuickJS interrupt tick is ~10k bytecodes). */
export const WASM_INSTRUCTIONS_PER_FUEL = 10_000
/** log2 of the bytes moved by `memory.copy` / `memory.fill` / `memory.init` per metered instruction. */
const WASM_BULK_BYTES_SHIFT = 6

/** Deterministic fuel cost of one host bridge call that processes `bytes` bytes. */
export function hostBytesFuel(bytes: number): number {
  return HOST_CALL_FUEL + Math.floor(Math.max(0, bytes) / HOST_BYTES_PER_FUEL)
}

interface CompiledWasmEntry {
  readonly module: WebAssembly.Module
  readonly byteLength: number
  /** Declared linear-memory maximum in bytes (0 when the module defines no memory). */
  readonly maxMemoryBytes: number
}

export interface WasmCallHostContext {
  readonly cas: ContentAddressedStore
  readonly readPartition: CasPartition | 'any'
  readonly writePartition: CasPartition
  readonly readOnly: boolean
  readonly maxMemoryBytes: number
  /** The invocation's shared fuel budget; metered WASM instructions and host imports charge it. */
  readonly fuel: FuelMeter
  readonly onMissingCas: (hash: string) => never
}

export interface WasmReducerInvocationInput {
  readonly wasmHash: string
  readonly method: 'reduce' | 'query' | 'describe' | 'onConflict' | 'admit' | 'authorize' | 'verify'
  /** Lowercase-hex log id (envelope `logId`). */
  readonly logId: string
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

const ALLOWED_IMPORT_MODULE = 'chronolog'
const ALLOWED_CHRONOLOG_IMPORTS = new Set(['sha256', 'cas_put', 'cas_get'])
/** Export name of the injected fuel counter global (reserved; user modules may not export it). */
export const WASM_FUEL_GLOBAL_EXPORT = '__chronolog_fuel'

/** A module the deterministic WASM profile refuses (malformed, non-MVP feature, unmeterable construct). */
export class WasmModuleRejectedError extends Error {
  readonly code = 'WASM_MODULE_REJECTED' as const
  constructor(readonly reason: string) {
    super(`WASM_MODULE_REJECTED:${reason}`)
    this.name = 'WasmModuleRejectedError'
  }
}

// ---------------------------------------------------------------------------------------------
// Deterministic metering rewriter
//
// Every WASM module is rewritten before compilation (the CAS hash still names the original bytes;
// the rewrite is a pure function of them, so every replica runs identical code):
//
// - Fuel: a mutable i64 global (exported as `__chronolog_fuel`) holds the remaining instruction
//   budget. A charge sequence that subtracts a constant and traps with `unreachable` when the
//   counter goes negative is inserted at every function entry, every loop header, after every
//   `else` and after every non-final `end`. Each charge covers the straight-line instructions up
//   to the next charge point in code order; branch targets are always charge points, so every
//   executed instruction is paid for (conditional arms are over-charged, deterministically).
//   `memory.copy`/`memory.fill`/`memory.init` additionally charge their dynamic length. A module
//   cannot opt out of metering (`loop br 0` traps as `vm:fuel_exhausted`).
// - Memory: at most one memory, which must declare a maximum; a call is refused (`vm:limit`) when
//   that maximum exceeds genesis `maxMemoryBytes`, so `memory.grow` failures are deterministic.
// - Floats: every arithmetic op that may produce a NaN with a platform-dependent payload
//   (add/sub/mul/div/sqrt/min/max/ceil/floor/trunc/nearest/demote/promote) is followed by a
//   select that replaces any NaN with the canonical quiet NaN, making results bit-identical.
// - Features: MVP + sign-extension + non-trapping float-to-int + bulk memory (memory and data
//   segments only) + reference-type `select t`/`ref.*`/`table.get|set`. SIMD (incl. relaxed),
//   threads/atomics, shared or 64-bit memory, multi-memory, exceptions, tail calls, GC, table bulk
//   ops and start functions are rejected. Imports are limited to `chronolog.{sha256,cas_put,cas_get}`.
//
// Known limit: the engine's native call-stack depth is not metered, so pathological recursion may
// trap at different depths on different engines; consensus modules must avoid deep recursion.
// ---------------------------------------------------------------------------------------------

class WasmReader {
  pos = 0
  constructor(readonly bytes: Uint8Array) {}
  get done(): boolean { return this.pos >= this.bytes.byteLength }
  peek(): number | undefined { return this.bytes[this.pos] }
  byte(): number {
    if (this.pos >= this.bytes.byteLength) throw new WasmModuleRejectedError('unexpected_end')
    return this.bytes[this.pos++]!
  }
  u32(): number {
    let result = 0
    for (let i = 0; i < 5; i++) {
      const b = this.byte()
      result += (b & 0x7f) * 2 ** (7 * i)
      if ((b & 0x80) === 0) {
        if (result > 0xffff_ffff) throw new WasmModuleRejectedError('leb_overflow')
        return result
      }
    }
    throw new WasmModuleRejectedError('leb_too_long')
  }
  /** Skip a signed LEB128 of at most `maxBytes` bytes. */
  skipSleb(maxBytes: number): void {
    for (let i = 0; i < maxBytes; i++) {
      if ((this.byte() & 0x80) === 0) return
    }
    throw new WasmModuleRejectedError('leb_too_long')
  }
  /** Non-negative signed-33 block type index. */
  s33(): number {
    let result = 0
    for (let i = 0; i < 5; i++) {
      const b = this.byte()
      result += (b & 0x7f) * 2 ** (7 * i)
      if ((b & 0x80) === 0) {
        if ((b & 0x40) !== 0) throw new WasmModuleRejectedError('blocktype_negative')
        return result
      }
    }
    throw new WasmModuleRejectedError('leb_too_long')
  }
  skip(n: number): void {
    if (this.pos + n > this.bytes.byteLength) throw new WasmModuleRejectedError('unexpected_end')
    this.pos += n
  }
  name(): string {
    const len = this.u32()
    const start = this.pos
    this.skip(len)
    return decodeUtf8(this.bytes.subarray(start, start + len))
  }
}

function encodeU32(n: number): number[] {
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

function encodeS64(n: bigint): number[] {
  const out: number[] = []
  let v = n
  for (;;) {
    const b = Number(v & 0x7fn)
    v >>= 7n
    if ((v === 0n && (b & 0x40) === 0) || (v === -1n && (b & 0x40) !== 0)) {
      out.push(b)
      return out
    }
    out.push(b | 0x80)
  }
}

const NUM_VALTYPES = new Set([0x7f, 0x7e, 0x7d, 0x7c])
const REF_VALTYPES = new Set([0x70, 0x6f])

function readValType(r: WasmReader): number {
  const t = r.byte()
  if (!NUM_VALTYPES.has(t) && !REF_VALTYPES.has(t)) throw new WasmModuleRejectedError(t === 0x7b ? 'simd' : `valtype_0x${t.toString(16)}`)
  return t
}

function readLimits(r: WasmReader, kind: 'memory' | 'table'): { readonly min: number; readonly max: number | null } {
  const flags = r.byte()
  if (flags > 1) {
    throw new WasmModuleRejectedError(kind === 'table' ? 'table_limits' : (flags & 0x02) !== 0 ? 'shared_memory' : 'memory64')
  }
  const min = r.u32()
  const max = flags === 1 ? r.u32() : null
  return { min, max }
}

/** Skip a constant expression (global/data/elem initializer) up to and including its `end`. */
function skipConstExpr(r: WasmReader): void {
  for (;;) {
    const op = r.byte()
    if (op === 0x0b) return
    if (op === 0x41) r.skipSleb(5)
    else if (op === 0x42) r.skipSleb(10)
    else if (op === 0x43) r.skip(4)
    else if (op === 0x44) r.skip(8)
    else if (op === 0x23 || op === 0xd2) r.u32()
    else if (op === 0xd0) r.byte()
    else throw new WasmModuleRejectedError(`const_expr_0x${op.toString(16)}`)
  }
}

/** f32/f64 ops whose NaN results may carry a platform-dependent payload. */
const FLOAT32_NAN_OPS = new Set([0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0xb6])
const FLOAT64_NAN_OPS = new Set([0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xbb])

/** Stack-neutral sequence: fuel -= cost; if (fuel < 0) unreachable. */
function chargeSequence(fuelGlobal: number, cost: number): number[] {
  if (cost <= 0) return []
  const g = encodeU32(fuelGlobal)
  return [
    0x23, ...g, 0x42, ...encodeS64(BigInt(cost)), 0x7d, 0x24, ...g,
    0x23, ...g, 0x42, 0x00, 0x53, 0x04, 0x40, 0x00, 0x0b,
  ]
}

/** Stack-neutral dynamic charge for bulk memory ops (the i32 length is on top of the stack). */
function bulkChargeSequence(fuelGlobal: number, scratchI32: number): number[] {
  const g = encodeU32(fuelGlobal)
  const t = encodeU32(scratchI32)
  return [
    0x22, ...t,
    0x23, ...g, 0x20, ...t, 0xad, 0x42, WASM_BULK_BYTES_SHIFT, 0x88, 0x7d, 0x24, ...g,
    0x23, ...g, 0x42, 0x00, 0x53, 0x04, 0x40, 0x00, 0x0b,
  ]
}

/** v -> (v == v) ? v : canonical NaN. */
function canonicalizeF32(scratch: number): number[] {
  const s = encodeU32(scratch)
  return [0x22, ...s, 0x43, 0x00, 0x00, 0xc0, 0x7f, 0x20, ...s, 0x20, ...s, 0x5b, 0x1b]
}

function canonicalizeF64(scratch: number): number[] {
  const s = encodeU32(scratch)
  return [0x22, ...s, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x7f, 0x20, ...s, 0x20, ...s, 0x61, 0x1b]
}

/** Skip the immediates of opcode `op` (already consumed). Returns the 0xFC sub-opcode, else -1. */
function skipImmediates(r: WasmReader, op: number): number {
  if (op === 0x02 || op === 0x03 || op === 0x04) {
    const b = r.peek()
    if (b === 0x40 || (b !== undefined && (NUM_VALTYPES.has(b) || REF_VALTYPES.has(b)))) r.pos++
    else if (b === 0x7b) throw new WasmModuleRejectedError('simd')
    else r.s33()
    return -1
  }
  if (op === 0x0c || op === 0x0d || op === 0x10) { r.u32(); return -1 }
  if (op === 0x0e) {
    const n = r.u32()
    for (let i = 0; i <= n; i++) r.u32()
    return -1
  }
  if (op === 0x11) { r.u32(); r.u32(); return -1 }
  if (op === 0x1c) {
    const n = r.u32()
    for (let i = 0; i < n; i++) readValType(r)
    return -1
  }
  if (op >= 0x20 && op <= 0x26) { r.u32(); return -1 }
  if (op >= 0x28 && op <= 0x3e) {
    const align = r.u32()
    if ((align & 0x40) !== 0) throw new WasmModuleRejectedError('multi_memory')
    r.u32()
    return -1
  }
  if (op === 0x3f || op === 0x40) {
    if (r.byte() !== 0x00) throw new WasmModuleRejectedError('multi_memory')
    return -1
  }
  if (op === 0x41) { r.skipSleb(5); return -1 }
  if (op === 0x42) { r.skipSleb(10); return -1 }
  if (op === 0x43) { r.skip(4); return -1 }
  if (op === 0x44) { r.skip(8); return -1 }
  if (op >= 0x45 && op <= 0xc4) return -1
  if (op === 0xd0) {
    if (!REF_VALTYPES.has(r.byte())) throw new WasmModuleRejectedError('ref_null_type')
    return -1
  }
  if (op === 0xd1) return -1
  if (op === 0xd2) { r.u32(); return -1 }
  if (op === 0xfc) {
    const sub = r.u32()
    if (sub <= 7) return sub
    if (sub === 8) {
      r.u32()
      if (r.byte() !== 0x00) throw new WasmModuleRejectedError('multi_memory')
      return sub
    }
    if (sub === 9) { r.u32(); return sub }
    if (sub === 10) {
      if (r.byte() !== 0x00 || r.byte() !== 0x00) throw new WasmModuleRejectedError('multi_memory')
      return sub
    }
    if (sub === 11) {
      if (r.byte() !== 0x00) throw new WasmModuleRejectedError('multi_memory')
      return sub
    }
    throw new WasmModuleRejectedError(`table_bulk_0xfc_${sub}`)
  }
  if (op === 0x00 || op === 0x01 || op === 0x05 || op === 0x0b || op === 0x0f || op === 0x1a || op === 0x1b) return -1
  const feature = op === 0xfd ? 'simd'
    : op === 0xfe ? 'threads'
      : op === 0xfb ? 'gc'
        : op === 0x12 || op === 0x13 ? 'tail_call'
          : (op >= 0x06 && op <= 0x0a) || op === 0x18 || op === 0x19 || op === 0x1f ? 'exceptions'
            : `opcode_0x${op.toString(16)}`
  throw new WasmModuleRejectedError(feature)
}

function instrumentFunctionBody(body: Uint8Array, typeParamCount: number, fuelGlobal: number): number[] {
  const r = new WasmReader(body)
  const localGroups = r.u32()
  const locals: number[] = []
  let localCount = typeParamCount
  for (let i = 0; i < localGroups; i++) {
    const n = r.u32()
    const t = readValType(r)
    localCount += n
    if (localCount > 50_000) throw new WasmModuleRejectedError('too_many_locals')
    locals.push(...encodeU32(n), t)
  }
  // Three scratch locals appended after all existing ones: i32 (bulk length), f32, f64 (NaN checks).
  const scratchI32 = localCount
  const scratchF32 = localCount + 1
  const scratchF64 = localCount + 2
  const out: number[] = [...encodeU32(localGroups + 3), ...locals, 0x01, 0x7f, 0x01, 0x7d, 0x01, 0x7c]

  let segment: number[] = []
  let cost = 0
  const closeSegment = (): void => {
    for (const b of chargeSequence(fuelGlobal, cost)) out.push(b)
    for (const b of segment) out.push(b)
    segment = []
    cost = 0
  }
  let depth = 1
  let finished = false
  while (!r.done) {
    if (finished) throw new WasmModuleRejectedError('code_after_function_end')
    const start = r.pos
    const op = r.byte()
    const sub = skipImmediates(r, op)
    cost++
    if (op === 0xfc && (sub === 8 || sub === 10 || sub === 11)) {
      for (const b of bulkChargeSequence(fuelGlobal, scratchI32)) segment.push(b)
    }
    for (let i = start; i < r.pos; i++) segment.push(body[i]!)
    if (FLOAT32_NAN_OPS.has(op)) segment.push(...canonicalizeF32(scratchF32))
    else if (FLOAT64_NAN_OPS.has(op)) segment.push(...canonicalizeF64(scratchF64))
    if (op === 0x02 || op === 0x04) depth++
    else if (op === 0x03) { depth++; closeSegment() }
    else if (op === 0x05) closeSegment()
    else if (op === 0x0b) {
      depth--
      if (depth === 0) finished = true
      else closeSegment()
    }
  }
  if (!finished) throw new WasmModuleRejectedError('function_body_unterminated')
  closeSegment()
  return out
}

export interface InstrumentedWasm {
  readonly bytes: Uint8Array<ArrayBuffer>
  /** Declared memory maximum in bytes (0 without a memory). */
  readonly maxMemoryBytes: number
}

/**
 * Validate a WASM binary against the deterministic profile and inject mandatory fuel metering and
 * NaN canonicalization (see the profile description above). Pure function of `bytes`; throws
 * `WasmModuleRejectedError` for anything outside the profile.
 */
export function instrumentWasmModule(bytes: Uint8Array): InstrumentedWasm {
  if (bytes.byteLength < 8 || bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    throw new WasmModuleRejectedError('bad_magic')
  }
  if (bytes[4] !== 0x01 || bytes[5] !== 0x00 || bytes[6] !== 0x00 || bytes[7] !== 0x00) throw new WasmModuleRejectedError('bad_version')
  const sections: { readonly id: number; readonly body: Uint8Array }[] = []
  const top = new WasmReader(bytes)
  top.pos = 8
  while (!top.done) {
    const id = top.byte()
    const size = top.u32()
    const start = top.pos
    top.skip(size)
    sections.push({ id, body: bytes.subarray(start, start + size) })
  }

  const typeParamCounts: number[] = []
  let importedFuncs = 0
  const funcTypes: number[] = []
  let definedGlobals = 0
  let memoryMaxBytes = 0
  let memories = 0
  const exportNames = new Set<string>()
  let codeBodies: Uint8Array[] | null = null

  for (const { id, body } of sections) {
    const s = new WasmReader(body)
    if (id === 0) continue
    if (id === 1) {
      const n = s.u32()
      for (let i = 0; i < n; i++) {
        if (s.byte() !== 0x60) throw new WasmModuleRejectedError('non_func_type')
        const params = s.u32()
        for (let j = 0; j < params; j++) readValType(s)
        const results = s.u32()
        for (let j = 0; j < results; j++) readValType(s)
        typeParamCounts.push(params)
      }
    } else if (id === 2) {
      const n = s.u32()
      for (let i = 0; i < n; i++) {
        const mod = s.name()
        const field = s.name()
        const kind = s.byte()
        if (mod !== ALLOWED_IMPORT_MODULE || kind !== 0x00 || !ALLOWED_CHRONOLOG_IMPORTS.has(field)) {
          throw new WasmModuleRejectedError(`import_forbidden:${mod}.${field}`)
        }
        funcTypes.push(s.u32())
        importedFuncs++
      }
    } else if (id === 3) {
      const n = s.u32()
      for (let i = 0; i < n; i++) funcTypes.push(s.u32())
    } else if (id === 4) {
      const n = s.u32()
      for (let i = 0; i < n; i++) {
        if (!REF_VALTYPES.has(s.byte())) throw new WasmModuleRejectedError('table_type')
        readLimits(s, 'table')
      }
    } else if (id === 5) {
      const n = s.u32()
      memories += n
      if (memories > 1) throw new WasmModuleRejectedError('multi_memory')
      for (let i = 0; i < n; i++) {
        const lim = readLimits(s, 'memory')
        if (lim.max === null) throw new WasmModuleRejectedError('memory_max_required')
        memoryMaxBytes = lim.max * 65_536
      }
    } else if (id === 6) {
      const n = s.u32()
      for (let i = 0; i < n; i++) {
        readValType(s)
        s.byte()
        skipConstExpr(s)
      }
      definedGlobals = n
    } else if (id === 7) {
      const n = s.u32()
      for (let i = 0; i < n; i++) {
        exportNames.add(s.name())
        s.byte()
        s.u32()
      }
    } else if (id === 8) {
      throw new WasmModuleRejectedError('start_function')
    } else if (id === 10) {
      const n = s.u32()
      codeBodies = []
      for (let i = 0; i < n; i++) {
        const size = s.u32()
        const start = s.pos
        s.skip(size)
        codeBodies.push(body.subarray(start, start + size))
      }
    } else if (id === 13) {
      throw new WasmModuleRejectedError('exceptions')
    } else if (id !== 9 && id !== 11 && id !== 12) {
      throw new WasmModuleRejectedError(`section_${id}`)
    }
  }
  if (exportNames.has(WASM_FUEL_GLOBAL_EXPORT)) throw new WasmModuleRejectedError('reserved_export')
  if ((codeBodies?.length ?? 0) !== funcTypes.length - importedFuncs) throw new WasmModuleRejectedError('function_code_mismatch')

  // Only function imports are allowed, so the new global's index is the defined-global count.
  const fuelGlobal = definedGlobals
  const newGlobalEntry = [0x7e, 0x01, 0x42, 0x00, 0x0b]
  const exportName = utf8(WASM_FUEL_GLOBAL_EXPORT)
  const newExportEntry = [...encodeU32(exportName.byteLength), ...exportName, 0x03, ...encodeU32(fuelGlobal)]

  const out: number[] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
  const emit = (id: number, content: readonly number[] | Uint8Array): void => {
    out.push(id, ...encodeU32(content.length))
    for (const b of content) out.push(b)
  }
  const appendEntry = (body: Uint8Array, entry: readonly number[]): number[] => {
    const s = new WasmReader(body)
    const n = s.u32()
    return [...encodeU32(n + 1), ...body.subarray(s.pos), ...entry]
  }
  // Canonical section order (data count 12 sits between element 9 and code 10).
  const rank = (id: number): number => (id === 12 ? 9.5 : id)
  let globalDone = false
  let exportDone = false
  const emitMissingBefore = (id: number): void => {
    if (!globalDone && rank(id) > 6) { emit(6, [0x01, ...newGlobalEntry]); globalDone = true }
    if (!exportDone && rank(id) > 7) { emit(7, [0x01, ...newExportEntry]); exportDone = true }
  }
  for (const { id, body } of sections) {
    if (id === 0) continue // custom sections (names, producers) carry no semantics; drop them
    emitMissingBefore(id)
    if (id === 6) { emit(6, appendEntry(body, newGlobalEntry)); globalDone = true; continue }
    if (id === 7) { emit(7, appendEntry(body, newExportEntry)); exportDone = true; continue }
    if (id === 10 && codeBodies !== null) {
      const content: number[] = [...encodeU32(codeBodies.length)]
      codeBodies.forEach((fnBody, i) => {
        const params = typeParamCounts[funcTypes[importedFuncs + i]!]
        if (params === undefined) throw new WasmModuleRejectedError('type_index')
        const instrumented = instrumentFunctionBody(fnBody, params, fuelGlobal)
        content.push(...encodeU32(instrumented.length))
        for (const b of instrumented) content.push(b)
      })
      emit(10, content)
      continue
    }
    emit(id, body)
  }
  emitMissingBefore(11)
  return { bytes: Uint8Array.from(out), maxMemoryBytes: memoryMaxBytes }
}

/**
 * Pure deterministic WebAssembly execution engine for Chronolog reducers and libraries.
 * - Validates, meters and NaN-canonicalizes each cas:sha256-<hash> binary ONCE and caches the
 *   compiled WebAssembly.Module in memory.
 * - Strictly rejects any non-'chronolog' host imports (zero WASI, clock, network, or host FS).
 * - Instantiates fresh linear memory per invocation with memory & mandatory fuel enforcement.
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
    const instrumented = instrumentWasmModule(bytes)
    let mod: WebAssembly.Module
    try {
      mod = new WebAssembly.Module(instrumented.bytes)
    } catch (err) {
      throw new WasmModuleRejectedError(`invalid:${err instanceof Error ? err.message : String(err)}`)
    }
    const entry: CompiledWasmEntry = { module: mod, byteLength: bytes.byteLength, maxMemoryBytes: instrumented.maxMemoryBytes }
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
    /** Run one export call with the shared fuel meter loaded into the instance's fuel global. */
    readonly metered: <T>(fn: () => T) => T
  } {
    const compiled = this.#compileOrGet(wasmHash, host)
    if (compiled.maxMemoryBytes > host.maxMemoryBytes) throw new Error('WASM_MEMORY_LIMIT_EXCEEDED')
    let mem: WebAssembly.Memory | null = null
    let fuelGlobal: WebAssembly.Global | null = null

    const getMemory = (): Uint8Array => {
      if (mem === null) throw new Error('WASM_MEMORY_MISSING')
      return new Uint8Array(mem.buffer)
    }
    /** Host imports debit the in-instance counter directly (it is settled into the meter on exit). */
    const chargeHost = (bytes: number): void => {
      if (fuelGlobal === null) throw new Error('WASM_FUEL_GLOBAL_MISSING')
      const next = (fuelGlobal.value as bigint) - BigInt(hostBytesFuel(bytes) * WASM_INSTRUCTIONS_PER_FUEL)
      fuelGlobal.value = next
      if (next < 0n) throw new FuelExhaustedError()
    }

    const imports: WebAssembly.Imports = {
      chronolog: {
        sha256(inPtr: number, inLen: number, outPtr: number): number {
          chargeHost(inLen >>> 0)
          const view = getMemory()
          const slice = view.subarray(inPtr >>> 0, (inPtr >>> 0) + (inLen >>> 0))
          const digest = sha256Sync(slice)
          view.set(digest, outPtr >>> 0)
          return digest.byteLength
        },
        cas_put(inPtr: number, inLen: number, outHashPtr: number): number {
          if (host.readOnly) throw new Error('CAS_READ_ONLY')
          chargeHost(inLen >>> 0)
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
          chargeHost(len)
          if (len > (maxLen >>> 0)) return -len
          view.set(node.bytes, outPtr >>> 0)
          return len
        },
      },
    }

    const instance = new WebAssembly.Instance(compiled.module, imports)
    const exportedMem = instance.exports.memory
    if (exportedMem instanceof WebAssembly.Memory) mem = exportedMem
    const g = instance.exports[WASM_FUEL_GLOBAL_EXPORT]
    if (!(g instanceof WebAssembly.Global)) throw new Error('WASM_FUEL_GLOBAL_MISSING')
    fuelGlobal = g
    const perFuel = BigInt(WASM_INSTRUCTIONS_PER_FUEL)
    const settle = (budget: bigint): void => {
      const left = g.value as bigint
      if (left < 0n) {
        try { host.fuel.charge(host.fuel.remaining + 1) } catch { /* latched exhausted */ }
        throw new FuelExhaustedError()
      }
      host.fuel.charge(Number((budget - left + perFuel - 1n) / perFuel))
    }
    const metered = <T>(fn: () => T): T => {
      if (host.fuel.exhausted) throw new FuelExhaustedError()
      const budget = BigInt(host.fuel.remaining) * perFuel
      g.value = budget
      let result: T
      try {
        result = fn()
      } catch (err) {
        settle(budget)
        throw err
      }
      settle(budget)
      return result
    }
    return { instance, metered }
  }

  /** Invoke a numeric export on a cached pure WASM module (for JS reducers using chronolog:wasm). */
  invokeNumeric(
    wasmHash: string,
    exportName: string,
    args: readonly number[],
    host: WasmCallHostContext,
  ): number {
    const { instance, metered } = this.#instantiate(wasmHash, host)
    const fn = instance.exports[exportName]
    if (typeof fn !== 'function') throw new Error(`WASM_EXPORT_NOT_FOUND:${exportName}`)
    const out = metered(() => (fn as (...a: number[]) => unknown)(...args))
    if (typeof out === 'bigint') return Number(out)
    if (typeof out === 'number') {
      if (!Number.isFinite(out)) throw new Error('WASM_NON_FINITE_RESULT')
      return Object.is(out, -0) ? 0 : out
    }
    return 0
  }

  /** Invoke a JSON-ABI export (alloc + ptr/len -> packed i64 or i32 + result_len) on a pure WASM module. */
  #invokeJsonOnInstance(
    instance: WebAssembly.Instance,
    exportName: string,
    input: JsonValue,
    metered: <T>(fn: () => T) => T,
  ): JsonValue {
    const mem = instance.exports.memory
    const alloc = instance.exports.alloc
    const fn = instance.exports[exportName]
    if (!(mem instanceof WebAssembly.Memory)) throw new Error('WASM_MEMORY_MISSING')
    if (typeof alloc !== 'function') throw new Error('WASM_ALLOC_MISSING')
    if (typeof fn !== 'function') throw new Error(`WASM_EXPORT_NOT_FOUND:${exportName}`)

    const inputBytes = utf8(JSON.stringify(input))
    const inPtr = Number(metered(() => (alloc as (n: number) => number)(inputBytes.byteLength))) >>> 0
    if (inPtr + inputBytes.byteLength > mem.buffer.byteLength) throw new Error('WASM_OUT_OF_BOUNDS_INPUT')
    new Uint8Array(mem.buffer, inPtr, inputBytes.byteLength).set(inputBytes)

    const rawResult = metered(() => (fn as (ptr: number, len: number) => unknown)(inPtr, inputBytes.byteLength))

    let outPtr: number
    let outLen: number
    if (typeof rawResult === 'bigint') {
      outPtr = Number((rawResult >> 32n) & 0xffff_ffffn) >>> 0
      outLen = Number(rawResult & 0xffff_ffffn) >>> 0
    } else if (typeof rawResult === 'number') {
      const resultLenFn = instance.exports.result_len
      if (typeof resultLenFn !== 'function') throw new Error('WASM_RESULT_LEN_MISSING')
      outPtr = rawResult >>> 0
      outLen = Number(metered(() => (resultLenFn as () => number)())) >>> 0
    } else {
      throw new Error('WASM_INVALID_RETURN_ABI')
    }

    if (outPtr + outLen > mem.buffer.byteLength) throw new Error('WASM_OUT_OF_BOUNDS_RESULT')
    const outText = decodeUtf8(new Uint8Array(mem.buffer, outPtr, outLen))
    return normalizeJsonValue(JSON.parse(outText) as unknown)
  }

  invokeJson(
    wasmHash: string,
    exportName: string,
    input: JsonValue,
    host: WasmCallHostContext,
  ): JsonValue {
    const { instance, metered } = this.#instantiate(wasmHash, host)
    return this.#invokeJsonOnInstance(instance, exportName, input, metered)
  }

  /** Execute a standalone pure WASM topic reducer (chronolog-wasm/v1 ABI). */
  invokeReducer(input: WasmReducerInvocationInput): WasmReducerInvocationResult {
    try {
      const { instance, metered } = this.#instantiate(input.wasmHash, input.host)
      if (typeof instance.exports[input.method] !== 'function') {
        return { ok: false, code: `vm:missing_method:${input.method}` }
      }
      const envelope: JsonValue = {
        state: input.state,
        payload: input.payload,
        tx: input.tx === undefined ? null : { ...input.tx, payload: input.payload },
        conflict: input.conflict ?? null,
        topics: input.topics,
        config: input.config ?? null,
        logId: input.logId,
      }
      return { ok: true, value: this.#invokeJsonOnInstance(instance, input.method, envelope, metered) }
    } catch (err) {
      if (err !== null && typeof err === 'object' && 'code' in err && (err as { code?: unknown }).code === 'MISSING_DEPENDENCY') {
        throw err
      }
      if (err instanceof FuelExhaustedError || input.host.fuel.exhausted) return { ok: false, code: 'vm:fuel_exhausted' }
      if (err instanceof WasmModuleRejectedError) return { ok: false, code: 'vm:module_rejected', detail: err.reason }
      if (err instanceof Error && err.message === 'WASM_MEMORY_LIMIT_EXCEEDED') return { ok: false, code: 'vm:limit' }
      return { ok: false, code: 'reducer:crash', detail: err instanceof Error ? err.message : String(err) }
    }
  }
}

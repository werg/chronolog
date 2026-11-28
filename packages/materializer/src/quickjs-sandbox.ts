import {
  newQuickJSWASMModuleFromVariant,
  newVariant,
  type QuickJSHandle,
  type QuickJSRuntime,
  type QuickJSSyncVariant,
  type QuickJSWASMModule,
} from 'quickjs-emscripten-core'
import baseVariant from '@jitl/quickjs-ng-wasmfile-release-sync'
import { bytesToHex, decodeUtf8, hexToBytes, perfCount, sha256Sync, utf8 } from '@chronolog/canonical'
import { verifyEd25519Sync } from '@chronolog/crypto'
import {
  assertValidReducersConfig,
  canonicalEventPayload,
  isControlTopic,
  normalizeJsonValue,
  type JsonValue,
} from '@chronolog/protocol'
import {
  casRef,
  parseCasRef,
  readBlobDagSync,
  resolvePackageRelativePath,
  tryDecodePackageNode,
  tryParseCasRef,
  type CasPartition,
  type ChronologBuiltinName,
  type ChronologPackageNode,
  type ContentAddressedStore,
} from '@chronolog/records'
import { WASM_BUILTIN_ID, WasmSandbox } from './wasm-sandbox.js'

export const QUICKJS_RUNTIME_ID = 'quickjs-ng@0.32.0'
export const CRYPTO_BUILTIN_ID = 'crypto@1'
export const CAS_BUILTIN_ID = 'cas@1'
export const DEFAULT_MAX_FUEL = 200_000
export { WASM_BUILTIN_ID }

/** Uncatchable host-level signal that a required CAS chunk/module is missing locally. */
export class MissingDependencyError extends Error {
  readonly code = 'MISSING_DEPENDENCY' as const
  constructor(readonly hash: string, readonly kind: 'cas' | 'module' | 'sqlite' = 'cas') {
    super(`MISSING_DEPENDENCY:${kind}/${hash}`)
    this.name = 'MissingDependencyError'
  }
}

export class OperationalTimeoutError extends Error {
  readonly code = 'OPERATIONAL_TIMEOUT' as const
  constructor(message = 'REDUCER_WATCHDOG_TIMEOUT') {
    super(message)
    this.name = 'OperationalTimeoutError'
  }
}

export interface SqliteDdlAllowlist {
  readonly createTable?: boolean
  readonly alterTable?: readonly string[]
  readonly dropTable?: readonly string[]
  readonly indexOn?: readonly string[]
  readonly createView?: boolean
  readonly dropView?: readonly string[]
}

export interface SqliteExecOptions {
  readonly mode?: 'admin' | 'user' | 'readonly'
  readonly ddl?: SqliteDdlAllowlist
}

export interface SqliteExecResult {
  readonly changes: number
  readonly lastInsertRowid: number
  readonly createdTables: readonly string[]
  readonly droppedTables: readonly string[]
  readonly createdViews?: readonly string[]
  readonly droppedViews?: readonly string[]
}

export interface SqliteQueryResult {
  readonly columns: readonly string[]
  readonly rows: readonly (readonly JsonValue[])[]
}

export interface SqliteDbHandle {
  exec(sql: string, params?: readonly JsonValue[], options?: SqliteExecOptions): SqliteExecResult
  query(sql: string, params?: readonly JsonValue[]): SqliteQueryResult
  validateExpr(table: string, sqlOp: 'INSERT' | 'UPDATE' | 'DELETE', expr: string): void
  commit(): string
  close(): void
}

export interface SqliteBuiltinDriver {
  readonly builtinId: string
  openDb(options: {
    readonly dbRoot: string | null
    readonly cas: ContentAddressedStore
    readonly partition: CasPartition
    readonly actor: string
    readonly opId: string
    readonly opTimeMs: bigint
    readonly readOnly: boolean
    readonly onMissingCas: (hash: string) => never
  }): SqliteDbHandle
}

export interface QuickJsSandboxOptions {
  /** Optional static pre-compiled WebAssembly.Module (required on Cloudflare Workers). */
  readonly wasmModule?: WebAssembly.Module
  readonly sqliteDriver?: SqliteBuiltinDriver
  readonly watchdogMs?: number
}

export interface AssumptionFailureInfo {
  readonly code: string
  readonly detail?: string
  readonly checkIndex?: number
}

export interface ReducerInvocationInput {
  readonly imports: Readonly<Record<string, string>>
  readonly builtins: Readonly<Record<string, string>>
  readonly topicBindings?: Readonly<Record<string, { readonly module: string; readonly export?: string; readonly config?: JsonValue }>>
  readonly moduleSpecifier: string
  readonly exportName: string
  readonly method: 'reduce' | 'query' | 'describe' | 'onConflict' | 'derive'
  readonly state: JsonValue
  readonly payload: JsonValue
  readonly tx?: {
    readonly opId: string
    readonly author: string
    readonly authorTimestampMs: number
    readonly operationId: string
  }
  readonly conflict?: AssumptionFailureInfo
  /** Lazy outcome lookup for ops visible to this invocation (never serialized wholesale into the VM). */
  readonly opOutcome?: (opId: string) => 'accepted' | 'rejected' | null
  readonly opOutcomes?: Readonly<Record<string, 'accepted' | 'rejected'>>
  readonly topicLastOpIds?: Readonly<Record<string, string>>
  /** Visible topic states; read lazily by `ctx.topic()` / `ctx.query()` through host calls. */
  readonly topics: Readonly<Record<string, JsonValue>>
  /** Optional precomputed content hash of a visible topic state (memoization key for nested queries). */
  readonly topicHash?: (topic: string) => string | undefined
  readonly config?: JsonValue
  readonly cas: ContentAddressedStore
  readonly casPartition: CasPartition
  readonly readOnly: boolean
  readonly maxMemoryBytes: number
  readonly maxFuel?: number
}

export type ReducerInvocationResult =
  | { readonly ok: true; readonly value: JsonValue }
  | { readonly ok: false; readonly code: string; readonly detail?: string }

const CRYPTO_MODULE_SHIM = `
export function sha256(input) { return globalThis.__chronologHost.sha256(input); }
export function verifyEd25519(pubKeyHex, message, sigHex) { return globalThis.__chronologHost.verifyEd25519(pubKeyHex, message, sigHex); }
export function canonicalJson(value) { return globalThis.__chronologHost.canonicalJson(value); }
`

const CAS_MODULE_SHIM = `
export function put(bytes, links = []) { return globalThis.__chronologHost.casPut(bytes, links); }
export function get(hash) { return globalThis.__chronologHost.casGet(hash); }
`

const WASM_MODULE_SHIM = `
export function invoke(wasmHashOrRef, exportName, args = []) {
  return JSON.parse(globalThis.__chronologHost.wasmInvoke(String(wasmHashOrRef), String(exportName), JSON.stringify(args ?? [])));
}
export function invokeJson(wasmHashOrRef, exportName, input = null) {
  return JSON.parse(globalThis.__chronologHost.wasmInvokeJson(String(wasmHashOrRef), String(exportName), JSON.stringify(input === undefined ? null : input)));
}
`

const SQLITE_MODULE_SHIM = `
export function openDb(dbRoot = null) {
  const handleId = globalThis.__chronologHost.sqlOpen(dbRoot);
  return {
    exec(sql, params = [], options = {}) {
      return JSON.parse(globalThis.__chronologHost.sqlExec(handleId, String(sql), JSON.stringify(params ?? []), JSON.stringify(options ?? {})));
    },
    query(sql, params = []) {
      return JSON.parse(globalThis.__chronologHost.sqlQuery(handleId, String(sql), JSON.stringify(params ?? [])));
    },
    validateExpr(table, sqlOp, expr) {
      globalThis.__chronologHost.sqlValidateExpr(handleId, String(table), String(sqlOp), String(expr));
    },
    commit() {
      return globalThis.__chronologHost.sqlCommit(handleId);
    },
    close() {
      globalThis.__chronologHost.sqlClose(handleId);
    },
  };
}
`

/**
 * Determinism prelude, evaluated first in every fresh context (before any module body). Its
 * completion value hands the host the intrinsics and two tiny helpers it needs, so the per-call
 * `ctx` object is assembled from host functions without compiling a JS stub per invocation:
 * `[JSON, JSON.parse, JSON.stringify, String, Object.is, makeCtx, finish]`.
 */
const DETERMINISM_PRELUDE = `
Object.defineProperty(globalThis, 'Date', { value: undefined, writable: false, configurable: false });
Object.defineProperty(Math, 'random', { value: () => { throw new Error('NONDETERMINISTIC_MATH_RANDOM'); }, writable: false, configurable: false });
for (const k of ['Intl', 'performance', 'WeakRef', 'FinalizationRegistry']) {
  if (typeof globalThis[k] !== 'undefined') {
    Object.defineProperty(globalThis, k, { value: undefined, writable: false, configurable: false });
  }
}
[JSON, JSON.parse, JSON.stringify, String, Object.is,
  (topic, query, mount, mountQuery, opOutcome, topicLastOpId, config) => Object.freeze({ topic, query, mount, mountQuery, opOutcome, topicLastOpId, config }),
  (out) => JSON.stringify({ __ok: true, value: out })];
`

/** Carries a VM exception out of a host-side coercion so a host `ctx` method can rethrow it unchanged. */
class VmThrow extends Error {
  constructor(readonly error: QuickJSHandle) { super('VM_EXCEPTION') }
}

/** Per-invocation entry module name (also what a reducer resolves `__chronolog_entry__` to). */
const ENTRY_MODULE_NAME = '__chronolog_entry__'

/** Entry module: imports the target export and re-exports it as `default` for the host to read. */
function entryModuleSource(moduleSpecifier: string, exportName: string): string {
  return exportName === 'default'
    ? `import __target from ${JSON.stringify(moduleSpecifier)};\nexport default __target;`
    : `import { ${exportName} as __target } from ${JSON.stringify(moduleSpecifier)};\nexport default __target;`
}

/** `ctx.mount(name)` body of the former in-VM stub; compiled lazily on first use only. */
const MOUNT_HELPER_SOURCE = `(m, name) => m && typeof m === 'object' && m.mounts && Object.prototype.hasOwnProperty.call(m.mounts, String(name)) ? m.mounts[String(name)] : null`

type HostBuiltin = 'chronolog:crypto' | 'chronolog:cas' | 'chronolog:wasm' | 'chronolog:sqlite'
/** `globalThis.__chronologHost` methods installed when the corresponding builtin shim is loaded. */
const HOST_BUILTIN_FUNCTIONS: Readonly<Record<HostBuiltin, readonly string[]>> = {
  'chronolog:crypto': ['sha256', 'verifyEd25519', 'canonicalJson'],
  'chronolog:cas': ['casPut', 'casGet'],
  'chronolog:wasm': ['wasmInvoke', 'wasmInvokeJson'],
  'chronolog:sqlite': ['sqlOpen', 'sqlExec', 'sqlQuery', 'sqlValidateExpr', 'sqlCommit', 'sqlClose'],
}

/** The `tx` argument as the reducer sees it (`payload` included), or null. */
function txJson(input: ReducerInvocationInput): JsonValue {
  return input.tx === undefined ? null : { ...input.tx, payload: input.payload }
}

/**
 * Note: `@jitl/quickjs-ng-wasmfile-release-sync@0.32.0` omits `BigInt` whenever custom `intrinsics`
 * flags are passed to `runtime.newContext(...)` (because `QTS_NewContext` switches to `JS_NewContextRaw`
 * without `JS_AddIntrinsicBigInt`). We therefore use `runtime.newContext()` so deterministic `BigInt`
 * remains available to reducers, and lock out `Date`, `performance`, `Intl`, `WeakRef`, and
 * `FinalizationRegistry` in `DETERMINISM_PRELUDE`.
 */

let defaultQuickJsPromise: Promise<QuickJSWASMModule> | null = null
/**
 * One QuickJS WASM instance per compiled module (e.g. a Cloudflare Worker's static import), shared by
 * every sandbox. Each invocation still gets a fresh context, so sharing the instance cannot leak state;
 * it removes a per-kernel instantiation and its 16 MiB initial heap.
 */
const sharedQuickJs = new WeakMap<WebAssembly.Module, Promise<QuickJSWASMModule>>()

export async function loadQuickJsModule(wasmModule?: WebAssembly.Module): Promise<QuickJSWASMModule> {
  const syncBase = baseVariant as unknown as QuickJSSyncVariant
  if (wasmModule !== undefined) {
    let shared = sharedQuickJs.get(wasmModule)
    if (shared === undefined) {
      shared = newQuickJSWASMModuleFromVariant(newVariant(syncBase, { wasmModule }))
      sharedQuickJs.set(wasmModule, shared)
      shared.catch(() => sharedQuickJs.delete(wasmModule))
    }
    return shared
  }
  if (defaultQuickJsPromise === null) {
    defaultQuickJsPromise = newQuickJSWASMModuleFromVariant(syncBase).catch(err => {
      defaultQuickJsPromise = null
      throw err
    })
  }
  return defaultQuickJsPromise
}

/** Split a bare specifier (e.g. '@scope/pkg/sub' or 'pkg/sub') into package name + export subpath. */
function splitBareSpecifier(spec: string): { readonly pkgName: string; readonly subpath: string } {
  if (spec.startsWith('@')) {
    const parts = spec.split('/')
    if (parts.length >= 2) {
      const pkgName = `${parts[0]!}/${parts[1]!}`
      const rest = parts.slice(2).join('/')
      return { pkgName, subpath: rest.length === 0 ? '.' : `./${rest}` }
    }
  }
  const slash = spec.indexOf('/')
  if (slash < 0) return { pkgName: spec, subpath: '.' }
  return { pkgName: spec.slice(0, slash), subpath: `./${spec.slice(slash + 1)}` }
}

type DecodedCasModule =
  | { readonly kind: 'package'; readonly pkg: ChronologPackageNode }
  | { readonly kind: 'source'; readonly text: string }

export class QuickJsSandbox {
  readonly #wasmPromise: Promise<QuickJSWASMModule>
  readonly #sqliteDriver: SqliteBuiltinDriver | undefined
  readonly #watchdogMs: number
  readonly #runtimePool: (QuickJSRuntime | undefined)[] = []
  readonly #nestedQueryCache = new Map<string, string>()
  /** Content-addressed immutable cache: casHash -> parsed chronolog-pkg/v1 manifest or decoded UTF-8 JS source. */
  readonly #moduleCache = new Map<string, DecodedCasModule>()
  readonly #wasmSandbox = new WasmSandbox()

  constructor(options: QuickJsSandboxOptions = {}) {
    this.#wasmPromise = loadQuickJsModule(options.wasmModule)
    this.#sqliteDriver = options.sqliteDriver
    this.#watchdogMs = options.watchdogMs ?? 2_000
  }

  get sqliteBuiltinId(): string | null {
    return this.#sqliteDriver?.builtinId ?? null
  }

  get wasmSandbox(): WasmSandbox {
    return this.#wasmSandbox
  }

  #disposed = false

  get disposed(): boolean { return this.#disposed }

  /** Release pooled runtimes and caches. Idempotent; later invocations throw SANDBOX_DISPOSED. */
  dispose(): void {
    this.#disposed = true
    for (let i = 0; i < this.#runtimePool.length; i++) {
      try { this.#runtimePool[i]?.dispose() } catch { /* ignore */ }
      this.#runtimePool[i] = undefined
    }
    this.#nestedQueryCache.clear()
    this.#moduleCache.clear()
    this.#wasmSandbox.clearCache()
  }

  /**
   * Inspect a module CAS node (demand-paging if needed) to check whether it is a pure-WASM package.
   */
  #inspectCasModuleSync(
    hash: string,
    cas: ContentAddressedStore,
    readPartition: CasPartition | 'any',
    onMissing: (h: string) => never,
  ): DecodedCasModule {
    const cached = this.#moduleCache.get(hash)
    if (cached !== undefined) {
      // Still verify partition visibility on public-only reads!
      if (readPartition === 'public' && !cas.hasSync(hash, 'public')) {
        onMissing(hash)
      }
      return cached
    }
    const node = cas.getSync(hash, readPartition)
    if (node === null) onMissing(hash)
    const pkg = tryDecodePackageNode(node.bytes)
    let entry: DecodedCasModule
    if (pkg !== null) {
      entry = { kind: 'package', pkg }
    } else {
      const fullBytes = node.links.length === 0
        ? node.bytes
        : readBlobDagSync(cas, hash, readPartition, onMissing)
      entry = { kind: 'source', text: decodeUtf8(fullBytes) }
    }
    this.#moduleCache.set(hash, entry)
    if (this.#moduleCache.size > 1024) {
      const oldest = this.#moduleCache.keys().next().value
      if (oldest !== undefined) this.#moduleCache.delete(oldest)
    }
    return entry
  }

  /**
   * Execute one deterministic reduce/query/describe/onConflict/derive call.
   * Automatically dispatches runtime === 'wasm-pure' packages to WasmSandbox and
   * JS/hybrid packages to a fresh isolated QuickJSContext with 2-arg scoped resolution.
   */
  async invoke(input: ReducerInvocationInput): Promise<ReducerInvocationResult> {
    if (this.#disposed) throw new Error('SANDBOX_DISPOSED')
    const readPartition: CasPartition | 'any' = input.casPartition === 'public' ? 'public' : 'any'
    const maxFuel = input.maxFuel ?? DEFAULT_MAX_FUEL

    // Demand-page loop for both pure-WASM and QuickJS invocations
    for (let faults = 0; faults < 256; faults++) {
      try {
        perfCount(`vm.${input.method}`)
        // Check if target module is a standalone pure-WASM package (chronolog-pkg/v1 with runtime: 'wasm-pure')
        const targetRef = tryParseCasRef(input.moduleSpecifier) !== null
          ? input.moduleSpecifier
          : input.imports[input.moduleSpecifier]
        const targetHash = targetRef !== undefined ? tryParseCasRef(targetRef) : null
        if (targetHash !== null && input.method !== 'derive') {
          const onMissing = (h: string): never => { throw new MissingDependencyError(h, 'module') }
          const inspected = this.#inspectCasModuleSync(targetHash, input.cas, readPartition, onMissing)
          if (inspected.kind === 'package' && inspected.pkg.runtime === 'wasm-pure' && inspected.pkg.wasm !== undefined) {
            const wasmFileRef = inspected.pkg.files[inspected.pkg.wasm.entry]
            if (wasmFileRef === undefined) return { ok: false, code: 'vm:module_load_error', detail: 'WASM_ENTRY_MISSING' }
            const wasmHash = parseCasRef(wasmFileRef)
            return this.#wasmSandbox.invokeReducer({
              wasmHash,
              method: input.method,
              state: input.state,
              payload: input.payload,
              ...(input.tx === undefined ? {} : { tx: input.tx }),
              ...(input.conflict === undefined ? {} : { conflict: input.conflict }),
              topics: input.topics,
              ...(input.config === undefined ? {} : { config: input.config }),
              host: {
                cas: input.cas,
                readPartition,
                writePartition: input.casPartition,
                readOnly: input.readOnly,
                maxMemoryBytes: input.maxMemoryBytes,
                maxFuel,
                onMissingCas: (h) => { throw new MissingDependencyError(h, 'cas') },
              },
            })
          }
        }
        const qjs = await this.#wasmPromise
        return this.#invokeSync(qjs, input, 0)
      } catch (err) {
        if (err instanceof MissingDependencyError && await input.cas.ensureLoaded(err.hash, readPartition)) {
          continue
        }
        throw err
      }
    }
    const qjs = await this.#wasmPromise
    return this.#invokeSync(qjs, input, 0)
  }

  #acquireRuntime(qjs: QuickJSWASMModule, depth: number): QuickJSRuntime {
    const existing = this.#runtimePool[depth]
    if (existing !== undefined) {
      this.#runtimePool[depth] = undefined
      return existing
    }
    return qjs.newRuntime()
  }

  #releaseRuntime(runtime: QuickJSRuntime, depth: number, healthy: boolean): void {
    if (healthy && this.#runtimePool[depth] === undefined) {
      this.#runtimePool[depth] = runtime
      return
    }
    try { runtime.dispose() } catch { /* ignore */ }
  }

  #invokeSync(qjs: QuickJSWASMModule, input: ReducerInvocationInput, depth: number): ReducerInvocationResult {
    const runtime = this.#acquireRuntime(qjs, depth)
    const openDbs = new Map<number, SqliteDbHandle>()
    let nextDbId = 1
    let missingDep: MissingDependencyError | null = null
    const moduleLoadState: { error: Error | null } = { error: null }
    let fuelExhausted = false
    let timedOut = false
    let healthy = true
    const maxFuel = input.maxFuel ?? DEFAULT_MAX_FUEL
    let fuelTicks = 0
    const deadline = Date.now() + this.#watchdogMs

    const readPartition: CasPartition | 'any' = input.casPartition === 'public' ? 'public' : 'any'
    const writePartition: CasPartition = input.casPartition

    const tripMissing = (hash: string, kind: 'cas' | 'module' | 'sqlite'): never => {
      const err = new MissingDependencyError(hash, kind)
      missingDep ??= err
      throw err
    }

    const resolveCasTargetToCanonical = (ref: string, subpath: string): string | { error: Error } => {
      const hash = tryParseCasRef(ref)
      if (hash === null) return { error: new Error(`MODULE_REF_INVALID:${ref}`) }
      try {
        const inspected = this.#inspectCasModuleSync(hash, input.cas, readPartition, h => tripMissing(h, 'module'))
        if (inspected.kind === 'package') {
          const exported = inspected.pkg.exports[subpath]
          if (exported !== undefined) return `pkg:${hash}/${exported}`
          // Allow direct file path fallback when subpath starts with './'
          const direct = subpath.startsWith('./') ? subpath.slice(2) : subpath
          if (Object.hasOwn(inspected.pkg.files, direct)) return `pkg:${hash}/${direct}`
          return { error: new Error(`PACKAGE_EXPORT_NOT_FOUND:${casRef(hash)}:${subpath}`) }
        }
        if (subpath !== '.') return { error: new Error(`LEAF_MODULE_NO_SUBPATH:${ref}:${subpath}`) }
        return `cas:${hash}`
      } catch (err) {
        if (err instanceof MissingDependencyError) return { error: err }
        return { error: err instanceof Error ? err : new Error(String(err)) }
      }
    }

    // Assigned once the context exists; the module loader only runs inside that context's evals.
    let installHost: (builtin: HostBuiltin) => void = () => { throw new Error('HOST_NOT_READY') }

    try {
      runtime.setMemoryLimit(input.maxMemoryBytes)
      runtime.setMaxStackSize(512 * 1024)
      // Deterministic fuel metering for consensus replay; wall-clock watchdog only for local read-only calls.
      runtime.setInterruptHandler(() => {
        if (missingDep !== null) return true
        if (++fuelTicks > maxFuel) {
          fuelExhausted = true
          return true
        }
        if (input.readOnly && Date.now() > deadline) {
          timedOut = true
          return true
        }
        return false
      })

      // Scoped 2-argument Module Normalizer + Hash-Pinned Package/Module Loader
      runtime.setModuleLoader(
        (moduleName: string) => {
          if (moduleName === 'chronolog:crypto') {
            if (!Object.hasOwn(input.builtins, 'chronolog:crypto')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:crypto') }
            installHost('chronolog:crypto')
            return CRYPTO_MODULE_SHIM
          }
          if (moduleName === 'chronolog:cas') {
            if (!Object.hasOwn(input.builtins, 'chronolog:cas')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:cas') }
            installHost('chronolog:cas')
            return CAS_MODULE_SHIM
          }
          if (moduleName === 'chronolog:wasm') {
            if (!Object.hasOwn(input.builtins, 'chronolog:wasm')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:wasm') }
            installHost('chronolog:wasm')
            return WASM_MODULE_SHIM
          }
          if (moduleName === 'chronolog:sqlite') {
            if (!Object.hasOwn(input.builtins, 'chronolog:sqlite') || this.#sqliteDriver === undefined) {
              return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:sqlite') }
            }
            installHost('chronolog:sqlite')
            return SQLITE_MODULE_SHIM
          }
          if (moduleName === ENTRY_MODULE_NAME) return entryModuleSource(input.moduleSpecifier, input.exportName)
          if (moduleName.startsWith('pkg:')) {
            const rest = moduleName.slice(4)
            const slash = rest.indexOf('/')
            if (slash !== 64) return { error: new Error(`PACKAGE_MODULE_ID_INVALID:${moduleName}`) }
            const pkgHash = rest.slice(0, 64)
            const filePath = rest.slice(65)
            try {
              const inspected = this.#inspectCasModuleSync(pkgHash, input.cas, readPartition, h => tripMissing(h, 'module'))
              if (inspected.kind !== 'package') return { error: new Error(`PACKAGE_EXPECTED:${pkgHash}`) }
              const fileRef = inspected.pkg.files[filePath]
              if (fileRef === undefined) return { error: new Error(`PACKAGE_FILE_NOT_FOUND:${pkgHash}/${filePath}`) }
              const fileHash = parseCasRef(fileRef)
              const fileEntry = this.#inspectCasModuleSync(fileHash, input.cas, readPartition, h => tripMissing(h, 'module'))
              if (fileEntry.kind !== 'source') return { error: new Error(`PACKAGE_FILE_NOT_SOURCE:${filePath}`) }
              return fileEntry.text
            } catch (err) {
              if (err instanceof MissingDependencyError) return { error: err }
              return { error: err instanceof Error ? err : new Error(String(err)) }
            }
          }
          if (moduleName.startsWith('cas:')) {
            const hash = moduleName.slice(4)
            try {
              const entry = this.#inspectCasModuleSync(hash, input.cas, readPartition, h => tripMissing(h, 'module'))
              if (entry.kind !== 'source') return { error: new Error(`MODULE_NOT_SOURCE:${moduleName}`) }
              return entry.text
            } catch (err) {
              if (err instanceof MissingDependencyError) return { error: err }
              return { error: err instanceof Error ? err : new Error(String(err)) }
            }
          }
          return { error: new Error(`MODULE_NOT_FOUND:${moduleName}`) }
        },
        (baseModuleName: string, requestedName: string) => {
          if (requestedName === ENTRY_MODULE_NAME) return ENTRY_MODULE_NAME

          // 1. Builtin capability check + per-package capability attenuation
          if (requestedName.startsWith('chronolog:')) {
            if (!Object.hasOwn(input.builtins, requestedName)) {
              const err = new Error(`BUILTIN_NOT_ENABLED:${requestedName}`)
              moduleLoadState.error ??= err
              return { error: err }
            }
            if (baseModuleName.startsWith('pkg:')) {
              const pkgHash = baseModuleName.slice(4, 68)
              try {
                const inspected = this.#inspectCasModuleSync(pkgHash, input.cas, readPartition, h => tripMissing(h, 'module'))
                if (inspected.kind === 'package') {
                  if (!inspected.pkg.builtins.includes(requestedName as ChronologBuiltinName)) {
                    const err = new Error(`BUILTIN_CAPABILITY_DENIED:${requestedName}`)
                    moduleLoadState.error ??= err
                    return { error: err }
                  }
                }
              } catch (err) {
                if (err instanceof MissingDependencyError) return { error: err }
                const wrapped = err instanceof Error ? err : new Error(String(err))
                moduleLoadState.error ??= wrapped
                return { error: wrapped }
              }
            }
            return requestedName
          }

          // 2. Direct hash-addressed import (cas:sha256-<64-hex>)
          if (requestedName.startsWith('cas:sha256-')) {
            return resolveCasTargetToCanonical(requestedName, '.')
          }

          // 3. Relative imports (./ or ../) strictly inside a chronolog-pkg/v1 package
          if (requestedName.startsWith('./') || requestedName.startsWith('../')) {
            if (!baseModuleName.startsWith('pkg:')) {
              return { error: new Error(`RELATIVE_IMPORT_OUTSIDE_PACKAGE:${requestedName}`) }
            }
            const rest = baseModuleName.slice(4)
            const pkgHash = rest.slice(0, 64)
            const currentFile = rest.slice(65)
            try {
              const inspected = this.#inspectCasModuleSync(pkgHash, input.cas, readPartition, h => tripMissing(h, 'module'))
              if (inspected.kind !== 'package') return { error: new Error(`PACKAGE_EXPECTED:${pkgHash}`) }
              const resolved = resolvePackageRelativePath(currentFile, requestedName)
              for (const candidate of [resolved, `${resolved}.js`, `${resolved}.mjs`, `${resolved}/index.js`]) {
                if (Object.hasOwn(inspected.pkg.files, candidate)) {
                  return `pkg:${pkgHash}/${candidate}`
                }
              }
              return { error: new Error(`PACKAGE_FILE_NOT_FOUND:${pkgHash}/${resolved}`) }
            } catch (err) {
              if (err instanceof MissingDependencyError) return { error: err }
              return { error: err instanceof Error ? err : new Error(String(err)) }
            }
          }

          // 4. Scoped package dependency resolution (eliminates diamond conflicts!)
          if (baseModuleName.startsWith('pkg:')) {
            const pkgHash = baseModuleName.slice(4, 68)
            try {
              const inspected = this.#inspectCasModuleSync(pkgHash, input.cas, readPartition, h => tripMissing(h, 'module'))
              if (inspected.kind === 'package') {
                const exactDep = inspected.pkg.dependencies[requestedName]
                if (exactDep !== undefined) {
                  return resolveCasTargetToCanonical(exactDep, '.')
                }
                const { pkgName, subpath } = splitBareSpecifier(requestedName)
                const scopedDep = inspected.pkg.dependencies[pkgName]
                if (scopedDep !== undefined) {
                  return resolveCasTargetToCanonical(scopedDep, subpath)
                }
              }
            } catch (err) {
              if (err instanceof MissingDependencyError) return { error: err }
              return { error: err instanceof Error ? err : new Error(String(err)) }
            }
          }

          // 5. Top-level $reducers.imports resolution (exact match or package + subpath)
          const directRef = input.imports[requestedName]
          if (directRef !== undefined) {
            return resolveCasTargetToCanonical(directRef, '.')
          }
          const { pkgName, subpath } = splitBareSpecifier(requestedName)
          const pkgRef = input.imports[pkgName]
          if (pkgRef !== undefined) {
            return resolveCasTargetToCanonical(pkgRef, subpath)
          }
          return { error: new Error(`MODULE_NOT_FOUND:${requestedName}`) }
        },
      )
      perfCount('vm.newContext')
      const ctx = runtime.newContext()
      const owned: QuickJSHandle[] = []
      const own = (h: QuickJSHandle): QuickJSHandle => { owned.push(h); return h }
      try {
        const preludeRes = ctx.evalCode(DETERMINISM_PRELUDE, '__prelude__.js')
        if (preludeRes.error) { preludeRes.error.dispose(); return { ok: false, code: 'vm:prelude_failed' } }
        const preludeOut = own(preludeRes.value)
        const intrinsic = (i: number): QuickJSHandle => own(ctx.getProp(preludeOut, i))

        // Builtin host bridges: registered here, installed on `__chronologHost` only when the builtin's
        // shim module is loaded (all loading happens before any module body runs).
        type HostFn = (...args: QuickJSHandle[]) => QuickJSHandle | void
        const hostImpls = new Map<string, HostFn>()
        const bindFn = (name: string, fn: HostFn): void => { hostImpls.set(name, fn) }
        const hostObj = own(ctx.newObject())
        ctx.setProp(ctx.global, '__chronologHost', hostObj)
        const installed = new Set<HostBuiltin>()
        installHost = (builtin) => {
          if (installed.has(builtin)) return
          installed.add(builtin)
          for (const name of HOST_BUILTIN_FUNCTIONS[builtin]) {
            const fn = hostImpls.get(name)
            if (fn === undefined) continue
            const handle = ctx.newFunction(name, (...args) => {
              if (missingDep !== null) throw missingDep
              return fn(...args)
            })
            ctx.setProp(hostObj, name, handle)
            handle.dispose()
          }
        }

        const queryTopic = (topicName: string, inputJson: string): string => {
          if (depth >= 4) throw new Error('TOPIC_QUERY_DEPTH_EXCEEDED')
          if (readPartition === 'public' && !isControlTopic(topicName)) {
            return 'null'
          }
          const rawQueryInput = JSON.parse(inputJson) as unknown
          const topicState: JsonValue = Object.hasOwn(input.topics, topicName) ? input.topics[topicName]! : null
          const binding = input.topicBindings?.[topicName]
          if (binding === undefined) {
            return JSON.stringify(topicState)
          }
          const nestedPartition: CasPartition = (readPartition === 'public' || isControlTopic(topicName)) ? 'public' : input.casPartition
          const modRef = input.imports[binding.module] ?? binding.module
          const canMemoize = isControlTopic(topicName) && modRef.startsWith('cas:sha256-') && Object.keys(input.imports).length <= 32
          let memoKey: string | null = null
          if (canMemoize) {
            const stateKey = input.topicHash?.(topicName) ?? bytesToHex(sha256Sync(utf8(JSON.stringify(topicState))))
            const inputKey = JSON.stringify(rawQueryInput)
            const configKey = binding.config === undefined ? '' : JSON.stringify(binding.config)
            memoKey = `${nestedPartition}\0${modRef}\0${binding.export ?? 'default'}\0${stateKey}\0${configKey}\0${inputKey}`
            const hit = this.#nestedQueryCache.get(memoKey)
            if (hit !== undefined) {
              this.#nestedQueryCache.delete(memoKey)
              this.#nestedQueryCache.set(memoKey, hit)
              return hit
            }
          }
          let nestedRes: ReducerInvocationResult
          try {
            nestedRes = this.#invokeSync(qjs, {
              imports: input.imports,
              builtins: input.builtins,
              ...(input.topicBindings === undefined ? {} : { topicBindings: input.topicBindings }),
              moduleSpecifier: binding.module,
              exportName: binding.export ?? 'default',
              method: 'query',
              state: topicState,
              payload: normalizeJsonValue(rawQueryInput),
              topics: input.topics,
              ...(input.topicHash === undefined ? {} : { topicHash: input.topicHash }),
              ...(binding.config === undefined ? {} : { config: binding.config }),
              cas: input.cas,
              casPartition: nestedPartition,
              readOnly: true,
              maxMemoryBytes: input.maxMemoryBytes,
              maxFuel,
            }, depth + 1)
          } catch (err) {
            if (err instanceof MissingDependencyError) {
              missingDep ??= err
              throw err
            }
            throw err
          }
          if (!nestedRes.ok) {
            if (nestedRes.code === 'vm:missing_method:query') {
              return JSON.stringify(topicState)
            }
            throw new Error(`TOPIC_QUERY_FAILED:${nestedRes.code}:${nestedRes.detail ?? ''}`)
          }
          const serialized = JSON.stringify(nestedRes.value)
          if (memoKey !== null) {
            this.#nestedQueryCache.set(memoKey, serialized)
            if (this.#nestedQueryCache.size > 512) {
              const oldest = this.#nestedQueryCache.keys().next().value
              if (oldest !== undefined) this.#nestedQueryCache.delete(oldest)
            }
          }
          return serialized
        }

        // Verified cross-log sub-state query against a pinned snapshot inside $mounts!
        const queryMount = (mountName: string, topicName: string, inputJson: string): string => {
          if (depth >= 4) throw new Error('TOPIC_QUERY_DEPTH_EXCEEDED')
          const rawQueryInput = JSON.parse(inputJson) as unknown
          const mountsTopic = input.topics.$mounts
          if (mountsTopic === null || typeof mountsTopic !== 'object' || Array.isArray(mountsTopic)) {
            return 'null'
          }
          const mountsMap = (mountsTopic as Readonly<Record<string, JsonValue>>).mounts
          if (mountsMap === null || typeof mountsMap !== 'object' || Array.isArray(mountsMap)) {
            return 'null'
          }
          const mountRec = (mountsMap as Readonly<Record<string, JsonValue>>)[mountName]
          if (mountRec === null || typeof mountRec !== 'object' || Array.isArray(mountRec)) {
            return 'null'
          }
          const mountedTopics = (mountRec as Readonly<Record<string, JsonValue>>).topics
          if (mountedTopics === null || typeof mountedTopics !== 'object' || Array.isArray(mountedTopics)) {
            return 'null'
          }
          const mt = mountedTopics as Readonly<Record<string, JsonValue>>
          const targetState: JsonValue = Object.hasOwn(mt, topicName) ? mt[topicName]! : null
          const mountedReducersRaw = mt.$reducers
          if (mountedReducersRaw === undefined) {
            return JSON.stringify(targetState)
          }
          const mountedReducers = assertValidReducersConfig(mountedReducersRaw)
          const binding = mountedReducers.topics[topicName]
          if (binding === undefined) {
            return JSON.stringify(targetState)
          }
          let nestedRes: ReducerInvocationResult
          try {
            nestedRes = this.#invokeSync(qjs, {
              imports: mountedReducers.imports,
              builtins: mountedReducers.runtime.builtins,
              topicBindings: mountedReducers.topics,
              moduleSpecifier: binding.module,
              exportName: binding.export ?? 'default',
              method: 'query',
              state: targetState,
              payload: normalizeJsonValue(rawQueryInput),
              topics: mt,
              ...(binding.config === undefined ? {} : { config: binding.config }),
              cas: input.cas,
              casPartition: 'public',
              readOnly: true,
              maxMemoryBytes: input.maxMemoryBytes,
              maxFuel,
            }, depth + 1)
          } catch (err) {
            if (err instanceof MissingDependencyError) {
              missingDep ??= err
              throw err
            }
            throw err
          }
          if (!nestedRes.ok) {
            if (nestedRes.code === 'vm:missing_method:query') {
              return JSON.stringify(targetState)
            }
            throw new Error(`MOUNT_QUERY_FAILED:${nestedRes.code}:${nestedRes.detail ?? ''}`)
          }
          return JSON.stringify(nestedRes.value)
        }

        bindFn('sha256', (dataHandle) => {
          const raw = ctx.dump(dataHandle) as unknown
          const bytes = typeof raw === 'string' ? utf8(raw) : raw instanceof Uint8Array ? raw : utf8(JSON.stringify(raw))
          return ctx.newString(bytesToHex(sha256Sync(bytes)))
        })

        bindFn('verifyEd25519', (pubH, msgH, sigH) => {
          const pubHex = ctx.getString(pubH)
          const msgRaw = ctx.dump(msgH) as unknown
          const sigHex = ctx.getString(sigH)
          if (!/^[0-9a-f]{64}$/u.test(pubHex) || !/^[0-9a-f]{128}$/u.test(sigHex)) return ctx.false
          const msgBytes = typeof msgRaw === 'string' ? utf8(msgRaw) : msgRaw instanceof Uint8Array ? msgRaw : utf8(JSON.stringify(msgRaw))
          return verifyEd25519Sync(hexToBytes(pubHex), msgBytes, hexToBytes(sigHex)) ? ctx.true : ctx.false
        })

        bindFn('canonicalJson', (valH) => {
          const val = normalizeJsonValue(ctx.dump(valH))
          return ctx.newString(canonicalEventPayload(val))
        })

        bindFn('casPut', (bytesH, linksH) => {
          if (input.readOnly) throw new Error('CAS_READ_ONLY')
          const raw = ctx.dump(bytesH) as unknown
          const bytes = typeof raw === 'string' ? utf8(raw) : raw instanceof Uint8Array ? raw : Array.isArray(raw) ? Uint8Array.from(raw as number[]) : (() => { throw new Error('CAS_PUT_BYTES_INVALID') })()
          const rawLinks = linksH === undefined ? [] : (ctx.dump(linksH) as unknown)
          if (!Array.isArray(rawLinks) || !rawLinks.every(l => typeof l === 'string')) throw new Error('CAS_PUT_LINKS_INVALID')
          const hash = input.cas.putSync(bytes, rawLinks, writePartition)
          return ctx.newString(hash)
        })

        bindFn('casGet', (hashH) => {
          const rawHash = ctx.getString(hashH)
          const hash = tryParseCasRef(rawHash) ?? rawHash
          if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('CAS_HASH_INVALID')
          const node = input.cas.getSync(hash, readPartition)
          if (node === null) {
            tripMissing(hash, 'cas')
            return ctx.undefined
          }
          return ctx.newString(JSON.stringify({ bytesHex: bytesToHex(node.bytes), links: node.links }))
        })

        bindFn('wasmInvoke', (refH, exportH, argsJsonH) => {
          const rawRef = ctx.getString(refH)
          const hash = tryParseCasRef(rawRef) ?? rawRef
          if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('WASM_HASH_INVALID')
          const exportName = ctx.getString(exportH)
          const args = JSON.parse(ctx.getString(argsJsonH)) as number[]
          if (!Array.isArray(args) || !args.every(n => typeof n === 'number' && Number.isFinite(n))) {
            throw new Error('WASM_ARGS_INVALID')
          }
          const result = this.#wasmSandbox.invokeNumeric(hash, exportName, args, {
            cas: input.cas,
            readPartition,
            writePartition,
            readOnly: input.readOnly,
            maxMemoryBytes: input.maxMemoryBytes,
            maxFuel,
            onMissingCas: (h) => tripMissing(h, 'cas'),
          })
          return ctx.newString(JSON.stringify(result))
        })

        bindFn('wasmInvokeJson', (refH, exportH, inputJsonH) => {
          const rawRef = ctx.getString(refH)
          const hash = tryParseCasRef(rawRef) ?? rawRef
          if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('WASM_HASH_INVALID')
          const exportName = ctx.getString(exportH)
          const parsedInput = normalizeJsonValue(JSON.parse(ctx.getString(inputJsonH)) as unknown)
          const result = this.#wasmSandbox.invokeJson(hash, exportName, parsedInput, {
            cas: input.cas,
            readPartition,
            writePartition,
            readOnly: input.readOnly,
            maxMemoryBytes: input.maxMemoryBytes,
            maxFuel,
            onMissingCas: (h) => tripMissing(h, 'cas'),
          })
          return ctx.newString(JSON.stringify(result))
        })

        if (this.#sqliteDriver !== undefined) {
          const driver = this.#sqliteDriver
          bindFn('sqlOpen', (rootH) => {
            const rawRoot = ctx.dump(rootH) as unknown
            const dbRoot = typeof rawRoot === 'string' ? rawRoot : null
            const db = driver.openDb({
              dbRoot,
              cas: input.cas,
              partition: input.casPartition,
              actor: input.tx?.author ?? '0'.repeat(64),
              opId: input.tx?.opId ?? '0'.repeat(64),
              opTimeMs: BigInt(input.tx?.authorTimestampMs ?? 0),
              readOnly: input.readOnly,
              onMissingCas: (hash) => tripMissing(hash, 'sqlite'),
            })
            const id = nextDbId++
            openDbs.set(id, db)
            return ctx.newNumber(id)
          })
          bindFn('sqlExec', (idH, sqlH, paramsH, optsH) => {
            const db = openDbs.get(ctx.getNumber(idH))
            if (db === undefined) throw new Error('SQLITE_HANDLE_CLOSED')
            const sql = ctx.getString(sqlH)
            const params = JSON.parse(ctx.getString(paramsH)) as JsonValue[]
            const opts = JSON.parse(ctx.getString(optsH)) as SqliteExecOptions
            const res = db.exec(sql, params, opts)
            return ctx.newString(JSON.stringify(res))
          })
          bindFn('sqlQuery', (idH, sqlH, paramsH) => {
            const db = openDbs.get(ctx.getNumber(idH))
            if (db === undefined) throw new Error('SQLITE_HANDLE_CLOSED')
            const sql = ctx.getString(sqlH)
            const params = JSON.parse(ctx.getString(paramsH)) as JsonValue[]
            const res = db.query(sql, params)
            return ctx.newString(JSON.stringify(res))
          })
          bindFn('sqlValidateExpr', (idH, tableH, opH, exprH) => {
            const db = openDbs.get(ctx.getNumber(idH))
            if (db === undefined) throw new Error('SQLITE_HANDLE_CLOSED')
            db.validateExpr(ctx.getString(tableH), ctx.getString(opH) as 'INSERT' | 'UPDATE' | 'DELETE', ctx.getString(exprH))
          })
          bindFn('sqlCommit', (idH) => {
            const db = openDbs.get(ctx.getNumber(idH))
            if (db === undefined) throw new Error('SQLITE_HANDLE_CLOSED')
            return ctx.newString(db.commit())
          })
          bindFn('sqlClose', (idH) => {
            const id = ctx.getNumber(idH)
            const db = openDbs.get(id)
            if (db !== undefined) { db.close(); openDbs.delete(id) }
          })
        }

        // Intrinsics captured after the prelude and before any reducer module body runs.
        const jsonH = intrinsic(0)
        const jsonParseH = intrinsic(1)
        const jsonStringifyH = intrinsic(2)
        const stringH = intrinsic(3)
        const objectIsH = intrinsic(4)
        const makeCtxH = intrinsic(5)
        const finishH = intrinsic(6)
        /** `JSON.parse(text)` in the VM; the result (or the VM exception) is owned by the caller. */
        const vmParse = (text: string) => {
          const textH = ctx.newString(text)
          try { return ctx.callFunction(jsonParseH, jsonH, textH) } finally { textH.dispose() }
        }
        /** `String(value)` in the VM, read back as a host string (rethrows the VM exception unchanged). */
        const vmString = (valueH: QuickJSHandle | undefined): string => {
          const res = ctx.callFunction(stringH, ctx.undefined, valueH ?? ctx.undefined)
          if (res.error) throw new VmThrow(res.error)
          try { return ctx.getString(res.value) } finally { res.value.dispose() }
        }
        /** `JSON.stringify(value === undefined ? null : value)` in the VM; `'undefined'` when it yields undefined. */
        const vmStringifyInput = (valueH: QuickJSHandle | undefined): string => {
          const res = valueH === undefined || ctx.typeof(valueH) === 'undefined'
            ? ctx.callFunction(jsonStringifyH, jsonH, ctx.null)
            : ctx.callFunction(jsonStringifyH, jsonH, valueH)
          if (res.error) throw new VmThrow(res.error)
          try { return ctx.getString(res.value) } finally { res.value.dispose() }
        }
        /** Host-implemented `ctx` method: VM exceptions from coercions propagate as-is. */
        const ctxMethod = (name: string, fn: (...args: QuickJSHandle[]) => QuickJSHandle | { error: QuickJSHandle } | { value: QuickJSHandle }) => {
          const handle = ctx.newFunction(name, (...args) => {
            if (missingDep !== null) throw missingDep
            try {
              return fn(...args)
            } catch (err) {
              if (err instanceof VmThrow) return { error: err.error }
              throw err
            }
          })
          ctxMembers.push(own(handle))
        }
        const topicCache = new Map<string, QuickJSHandle>()
        const readTopicCached = (key: string): QuickJSHandle => {
          let cached = topicCache.get(key)
          if (cached === undefined) {
            const res = vmParse(JSON.stringify(Object.hasOwn(input.topics, key) ? input.topics[key]! : null))
            if (res.error) throw new VmThrow(res.error)
            cached = own(res.value)
            topicCache.set(key, cached)
          }
          return cached
        }
        let mountHelperH: QuickJSHandle | null = null

        // ctx: same members, order, freezing and coercions as the former in-VM stub, built from host
        // functions so nothing has to be compiled per invocation.
        const ctxMembers: QuickJSHandle[] = []
        ctxMethod('topic', (nameH) => readTopicCached(vmString(nameH)).dup())
        ctxMethod('query', (nameH, inputH) => {
          const name = vmString(nameH)
          return vmParse(queryTopic(name, vmStringifyInput(inputH)))
        })
        ctxMethod('mount', (nameH) => {
          const mountsH = readTopicCached('$mounts')
          if (mountHelperH === null) {
            // Rarely used: compiled only on first call, with the exact former semantics.
            const res = ctx.evalCode(MOUNT_HELPER_SOURCE, '__chronolog_mount__.js')
            if (res.error) return { error: res.error }
            mountHelperH = own(res.value)
          }
          return ctx.callFunction(mountHelperH, ctx.undefined, mountsH, nameH ?? ctx.undefined)
        })
        ctxMethod('mountQuery', (nameH, topicH, inputH) => {
          const name = vmString(nameH)
          const topic = vmString(topicH)
          return vmParse(queryMount(name, topic, vmStringifyInput(inputH)))
        })
        ctxMethod('opOutcome', (opIdH) => {
          const key = vmString(opIdH)
          const outcome = input.opOutcome !== undefined
            ? input.opOutcome(key)
            : input.opOutcomes !== undefined && Object.hasOwn(input.opOutcomes, key) ? input.opOutcomes[key]! : null
          return outcome === null ? ctx.null : ctx.newString(outcome)
        })
        ctxMethod('topicLastOpId', (nameH) => {
          const key = vmString(nameH)
          const ids = input.topicLastOpIds
          return ids !== undefined && Object.hasOwn(ids, key) ? ctx.newString(ids[key]!) : ctx.null
        })
        const configRes = vmParse(JSON.stringify(input.config ?? null))
        if (configRes.error) { configRes.error.dispose(); return { ok: false, code: 'vm:prelude_failed' } }
        ctxMembers.push(own(configRes.value))
        const ctxRes = ctx.callFunction(makeCtxH, ctx.undefined, ...ctxMembers)
        if (ctxRes.error) { ctxRes.error.dispose(); return { ok: false, code: 'vm:prelude_failed' } }
        const ctxObj = own(ctxRes.value)

        // Load entry module (triggers 2-arg scoped normalizer + Import Map loading)
        const loadRes = ctx.evalCode(
          entryModuleSource(input.moduleSpecifier, input.exportName),
          ENTRY_MODULE_NAME,
          { type: 'module' },
        )
        if (loadRes.error) {
          const dumped = ctx.dump(loadRes.error) as unknown
          loadRes.error.dispose()
          if (missingDep !== null) throw missingDep as Error
          if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
          if (timedOut) throw new OperationalTimeoutError()
          return { ok: false, code: 'vm:module_load_error', detail: moduleLoadState.error !== null ? moduleLoadState.error.message : formatJsError(dumped) }
        }
        own(loadRes.value)
        if (missingDep !== null) throw missingDep as Error
        if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
        if (timedOut) throw new OperationalTimeoutError()

        // Run: `const fn = target && target[method]; fn(...args)`; output is
        // `JSON.stringify({ __ok: true, value: out })`, exactly as before.
        const runResult = ((): { kind: 'missing' } | { kind: 'error'; error: QuickJSHandle } | { kind: 'ok'; json: string } => {
          const target = own(ctx.getProp(loadRes.value, 'default'))
          const targetType = ctx.typeof(target)
          if (targetType !== 'object' && targetType !== 'function' && !(ctx.dump(target) as unknown)) return { kind: 'missing' }
          if (targetType === 'object') {
            // `null` is the only falsy object; the WASM build exposes no equality, so ask `Object.is`.
            const isNull = ctx.callFunction(objectIsH, ctx.undefined, target, ctx.null)
            if (isNull.error) return { kind: 'error', error: isNull.error }
            const nullTarget = ctx.dump(isNull.value) === true
            isNull.value.dispose()
            if (nullTarget) return { kind: 'missing' }
          }
          const fnRes = ctx.getProp(target, input.method)
          own(fnRes)
          if (ctx.typeof(fnRes) !== 'function') return { kind: 'missing' }
          const argsJson = input.method === 'reduce' ? [input.state, txJson(input)]
            : input.method === 'onConflict' ? [input.state, txJson(input), input.conflict ?? null]
              : input.method === 'query' ? [input.state, input.payload]
                : input.method === 'derive' ? [input.payload]
                  : [input.state]
          const argsRes = vmParse(JSON.stringify(argsJson))
          if (argsRes.error) return { kind: 'error', error: argsRes.error }
          const argsArr = own(argsRes.value)
          const args = argsJson.map((_, i) => own(ctx.getProp(argsArr, i)))
          // ctx is the third argument for reduce/onConflict/query, second for derive/describe.
          const ctxIndex = input.method === 'derive' || input.method === 'describe' ? 1 : 2
          args.splice(ctxIndex, 0, ctxObj)
          const callRes = ctx.callFunction(fnRes, ctx.undefined, ...args)
          if (callRes.error) return { kind: 'error', error: callRes.error }
          const out = own(callRes.value)
          const strRes = ctx.callFunction(finishH, ctx.undefined, out)
          if (strRes.error) return { kind: 'error', error: strRes.error }
          const json = ctx.getString(strRes.value)
          strRes.value.dispose()
          return { kind: 'ok', json }
        })()
        if (runResult.kind === 'error') {
          const dumped = ctx.dump(runResult.error) as unknown
          runResult.error.dispose()
          if (missingDep !== null) throw missingDep as Error
          if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
          if (timedOut) throw new OperationalTimeoutError()
          const detail = formatJsError(dumped)
          const code = /out of memory|memory limit/i.test(detail) ? 'vm:limit' : 'reducer:throw'
          return { ok: false, code, detail }
        }
        if (missingDep !== null) throw missingDep as Error
        if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
        if (timedOut) throw new OperationalTimeoutError()
        if (runResult.kind === 'missing') {
          return { ok: false, code: `vm:missing_method:${input.method}` }
        }

        const parsed = JSON.parse(runResult.json) as { __ok?: boolean; value?: unknown }
        try {
          const normalized = normalizeJsonValue(parsed.value)
          return { ok: true, value: normalized }
        } catch (err) {
          return { ok: false, code: 'vm:invalid_output', detail: err instanceof Error ? err.message : String(err) }
        }
      } finally {
        for (const db of openDbs.values()) { try { db.close() } catch { /* ignore */ } }
        openDbs.clear()
        for (let i = owned.length - 1; i >= 0; i--) { const h = owned[i]!; if (h.alive) h.dispose() }
        try { ctx.dispose() } catch { healthy = false }
      }
    } catch (err) {
      healthy = false
      throw err
    } finally {
      if (timedOut || fuelExhausted || missingDep !== null) healthy = false
      this.#releaseRuntime(runtime, depth, healthy)
    }
  }
}

function formatJsError(dumped: unknown): string {
  if (typeof dumped === 'string') return dumped
  if (dumped !== null && typeof dumped === 'object' && 'message' in dumped) {
    return String((dumped as { readonly message: unknown }).message)
  }
  try { return JSON.stringify(dumped) } catch { return String(dumped) }
}

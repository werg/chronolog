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

const DETERMINISM_PRELUDE = `
Object.defineProperty(globalThis, 'Date', { value: undefined, writable: false, configurable: false });
Object.defineProperty(Math, 'random', { value: () => { throw new Error('NONDETERMINISTIC_MATH_RANDOM'); }, writable: false, configurable: false });
if (typeof Intl !== 'undefined') {
  Object.defineProperty(globalThis, 'Intl', { value: undefined, writable: false, configurable: false });
}
`

let defaultQuickJsPromise: Promise<QuickJSWASMModule> | null = null

export async function loadQuickJsModule(wasmModule?: WebAssembly.Module): Promise<QuickJSWASMModule> {
  const syncBase = baseVariant as unknown as QuickJSSyncVariant
  if (wasmModule !== undefined) {
    const variant = newVariant(syncBase, { wasmModule })
    return newQuickJSWASMModuleFromVariant(variant)
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

  dispose(): void {
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
            return CRYPTO_MODULE_SHIM
          }
          if (moduleName === 'chronolog:cas') {
            if (!Object.hasOwn(input.builtins, 'chronolog:cas')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:cas') }
            return CAS_MODULE_SHIM
          }
          if (moduleName === 'chronolog:wasm') {
            if (!Object.hasOwn(input.builtins, 'chronolog:wasm')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:wasm') }
            return WASM_MODULE_SHIM
          }
          if (moduleName === 'chronolog:sqlite') {
            if (!Object.hasOwn(input.builtins, 'chronolog:sqlite') || this.#sqliteDriver === undefined) {
              return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:sqlite') }
            }
            return SQLITE_MODULE_SHIM
          }
          if (moduleName === '__chronolog_entry__') {
            const exp = input.exportName === 'default'
              ? `import __target from ${JSON.stringify(input.moduleSpecifier)};`
              : `import { ${input.exportName} as __target } from ${JSON.stringify(input.moduleSpecifier)};`
            const callExpr = input.method === 'reduce'
              ? 'fn(env.state, env.tx, ctx)'
              : input.method === 'onConflict'
                ? 'fn(env.state, env.tx, ctx, env.conflict)'
                : input.method === 'query'
                  ? 'fn(env.state, env.payload, ctx)'
                  : input.method === 'derive'
                    ? 'fn(env.payload, ctx)'
                    : 'fn(env.state, ctx)'
            return `${exp}\nglobalThis.__chronologRun = () => { const env = JSON.parse(globalThis.__chronologEnvJson); const topicCache = new Map(); const readTopicCached = (name) => { const key = String(name); if (!topicCache.has(key)) topicCache.set(key, JSON.parse(globalThis.__chronologHost.readTopic(key))); return topicCache.get(key); }; const ctx = Object.freeze({ topic(name) { return readTopicCached(name); }, query(name, input = null) { return JSON.parse(globalThis.__chronologHost.queryTopic(String(name), JSON.stringify(input === undefined ? null : input))); }, mount(name) { const m = readTopicCached('$mounts'); return m && typeof m === 'object' && m.mounts && Object.prototype.hasOwnProperty.call(m.mounts, String(name)) ? m.mounts[String(name)] : null; }, mountQuery(name, topic, input = null) { return JSON.parse(globalThis.__chronologHost.queryMount(String(name), String(topic), JSON.stringify(input === undefined ? null : input))); }, opOutcome(opId) { return JSON.parse(globalThis.__chronologHost.opOutcome(String(opId))); }, topicLastOpId(name) { const key = String(name); return env.topicLastOpIds && Object.prototype.hasOwnProperty.call(env.topicLastOpIds, key) ? env.topicLastOpIds[key] : null; }, config: env.config ?? null }); const fn = __target && __target[${JSON.stringify(input.method)}]; if (typeof fn !== 'function') { return JSON.stringify({ __missingMethod: true }); } const out = ${callExpr}; return JSON.stringify({ __ok: true, value: out }); };`
          }
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
          if (requestedName === '__chronolog_entry__') return '__chronolog_entry__'

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
      try {
        const preludeRes = ctx.evalCode(DETERMINISM_PRELUDE, '__prelude__.js')
        if (preludeRes.error) { preludeRes.error.dispose(); return { ok: false, code: 'vm:prelude_failed' } }
        preludeRes.value.dispose()

        // Install host bridges
        const hostObj = ctx.newObject()
        const bindFn = (name: string, fn: (...args: QuickJSHandle[]) => QuickJSHandle | void): void => {
          const handle = ctx.newFunction(name, (...args) => {
            if (missingDep !== null) throw missingDep
            return fn(...args)
          })
          ctx.setProp(hostObj, name, handle)
          handle.dispose()
        }

        bindFn('readTopic', (topicH) => {
          const topicName = ctx.getString(topicH)
          return ctx.newString(JSON.stringify(Object.hasOwn(input.topics, topicName) ? input.topics[topicName]! : null))
        })

        bindFn('opOutcome', (opIdH) => {
          const key = ctx.getString(opIdH)
          if (input.opOutcome !== undefined) {
            return ctx.newString(JSON.stringify(input.opOutcome(key)))
          }
          const val = input.opOutcomes !== undefined && Object.hasOwn(input.opOutcomes, key) ? input.opOutcomes[key]! : null
          return ctx.newString(JSON.stringify(val))
        })

        bindFn('queryTopic', (topicH, inputJsonH) => {
          if (depth >= 4) throw new Error('TOPIC_QUERY_DEPTH_EXCEEDED')
          const topicName = ctx.getString(topicH)
          if (readPartition === 'public' && !isControlTopic(topicName)) {
            return ctx.newString('null')
          }
          const rawQueryInput = JSON.parse(ctx.getString(inputJsonH)) as unknown
          const topicState: JsonValue = Object.hasOwn(input.topics, topicName) ? input.topics[topicName]! : null
          const binding = input.topicBindings?.[topicName]
          if (binding === undefined) {
            return ctx.newString(JSON.stringify(topicState))
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
              return ctx.newString(hit)
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
              return ctx.newString(JSON.stringify(topicState))
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
          return ctx.newString(serialized)
        })

        // Verified cross-log sub-state query against a pinned snapshot inside $mounts!
        bindFn('queryMount', (mountNameH, topicH, inputJsonH) => {
          if (depth >= 4) throw new Error('TOPIC_QUERY_DEPTH_EXCEEDED')
          const mountName = ctx.getString(mountNameH)
          const topicName = ctx.getString(topicH)
          const rawQueryInput = JSON.parse(ctx.getString(inputJsonH)) as unknown
          const mountsTopic = input.topics.$mounts
          if (mountsTopic === null || typeof mountsTopic !== 'object' || Array.isArray(mountsTopic)) {
            return ctx.newString('null')
          }
          const mountsMap = (mountsTopic as Readonly<Record<string, JsonValue>>).mounts
          if (mountsMap === null || typeof mountsMap !== 'object' || Array.isArray(mountsMap)) {
            return ctx.newString('null')
          }
          const mountRec = (mountsMap as Readonly<Record<string, JsonValue>>)[mountName]
          if (mountRec === null || typeof mountRec !== 'object' || Array.isArray(mountRec)) {
            return ctx.newString('null')
          }
          const mountedTopics = (mountRec as Readonly<Record<string, JsonValue>>).topics
          if (mountedTopics === null || typeof mountedTopics !== 'object' || Array.isArray(mountedTopics)) {
            return ctx.newString('null')
          }
          const mt = mountedTopics as Readonly<Record<string, JsonValue>>
          const targetState: JsonValue = Object.hasOwn(mt, topicName) ? mt[topicName]! : null
          const mountedReducersRaw = mt.$reducers
          if (mountedReducersRaw === undefined) {
            return ctx.newString(JSON.stringify(targetState))
          }
          const mountedReducers = assertValidReducersConfig(mountedReducersRaw)
          const binding = mountedReducers.topics[topicName]
          if (binding === undefined) {
            return ctx.newString(JSON.stringify(targetState))
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
              return ctx.newString(JSON.stringify(targetState))
            }
            throw new Error(`MOUNT_QUERY_FAILED:${nestedRes.code}:${nestedRes.detail ?? ''}`)
          }
          return ctx.newString(JSON.stringify(nestedRes.value))
        })

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

        ctx.setProp(ctx.global, '__chronologHost', hostObj)
        hostObj.dispose()

        const envJson = JSON.stringify({
          state: input.state,
          payload: input.payload,
          tx: input.tx === undefined ? null : { ...input.tx, payload: input.payload },
          conflict: input.conflict ?? null,
          topicLastOpIds: input.topicLastOpIds ?? {},
          config: input.config ?? null,
        })
        const envHandle = ctx.newString(envJson)
        ctx.setProp(ctx.global, '__chronologEnvJson', envHandle)
        envHandle.dispose()

        // Load entry module (triggers 2-arg scoped normalizer + Import Map loading)
        const loadRes = ctx.evalCode(
          `import '__chronolog_entry__';`,
          '__bootstrap__.mjs',
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
        loadRes.value.dispose()
        if (missingDep !== null) throw missingDep as Error
        if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
        if (timedOut) throw new OperationalTimeoutError()

        const runRes = ctx.evalCode('globalThis.__chronologRun()', '__run__.js')
        if (runRes.error) {
          const dumped = ctx.dump(runRes.error) as unknown
          runRes.error.dispose()
          if (missingDep !== null) throw missingDep as Error
          if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
          if (timedOut) throw new OperationalTimeoutError()
          const detail = formatJsError(dumped)
          const code = /out of memory|memory limit/i.test(detail) ? 'vm:limit' : 'reducer:throw'
          return { ok: false, code, detail }
        }
        const rawOut = ctx.getString(runRes.value)
        runRes.value.dispose()
        if (missingDep !== null) throw missingDep as Error
        if (fuelExhausted) return { ok: false, code: 'vm:fuel_exhausted' }
        if (timedOut) throw new OperationalTimeoutError()

        const parsed = JSON.parse(rawOut) as { __missingMethod?: boolean; __ok?: boolean; value?: unknown }
        if (parsed.__missingMethod) {
          return { ok: false, code: `vm:missing_method:${input.method}` }
        }
        try {
          const normalized = normalizeJsonValue(parsed.value)
          return { ok: true, value: normalized }
        } catch (err) {
          return { ok: false, code: 'vm:invalid_output', detail: err instanceof Error ? err.message : String(err) }
        }
      } finally {
        for (const db of openDbs.values()) { try { db.close() } catch { /* ignore */ } }
        openDbs.clear()
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

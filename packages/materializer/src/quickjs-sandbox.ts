import {
  newQuickJSWASMModuleFromVariant,
  newVariant,
  type QuickJSHandle,
  type QuickJSRuntime,
  type QuickJSSyncVariant,
  type QuickJSWASMModule,
} from 'quickjs-emscripten-core'
import baseVariant from '@jitl/quickjs-ng-wasmfile-release-sync'
import { bytesToHex, decodeUtf8, hexToBytes, sha256Sync, utf8 } from '@chronolog/canonical'
import { verifyEd25519Sync } from '@chronolog/crypto'
import { canonicalEventPayload, isControlTopic, normalizeJsonValue, type JsonValue } from '@chronolog/protocol'
import type { CasPartition, ContentAddressedStore } from '@chronolog/records'

export const QUICKJS_RUNTIME_ID = 'quickjs-ng@0.32.0'
export const CRYPTO_BUILTIN_ID = 'crypto@1'
export const CAS_BUILTIN_ID = 'cas@1'

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
  readonly method: 'reduce' | 'query' | 'describe' | 'onConflict'
  readonly state: JsonValue
  readonly payload: JsonValue
  readonly tx?: {
    readonly opId: string
    readonly author: string
    readonly authorTimestampMs: number
    readonly operationId: string
  }
  readonly conflict?: AssumptionFailureInfo
  readonly opOutcomes?: Readonly<Record<string, 'accepted' | 'rejected'>>
  readonly topicLastOpIds?: Readonly<Record<string, string>>
  readonly topics: Readonly<Record<string, JsonValue>>
  readonly config?: JsonValue
  readonly cas: ContentAddressedStore
  readonly casPartition: CasPartition
  readonly readOnly: boolean
  readonly maxMemoryBytes: number
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

export class QuickJsSandbox {
  readonly #wasmPromise: Promise<QuickJSWASMModule>
  readonly #sqliteDriver: SqliteBuiltinDriver | undefined
  readonly #watchdogMs: number
  readonly #runtimePool: (QuickJSRuntime | undefined)[] = []
  readonly #nestedQueryCache = new Map<string, string>()

  constructor(options: QuickJsSandboxOptions = {}) {
    this.#wasmPromise = loadQuickJsModule(options.wasmModule)
    this.#sqliteDriver = options.sqliteDriver
    this.#watchdogMs = options.watchdogMs ?? 2_000
  }

  get sqliteBuiltinId(): string | null {
    return this.#sqliteDriver?.builtinId ?? null
  }

  dispose(): void {
    for (let i = 0; i < this.#runtimePool.length; i++) {
      try { this.#runtimePool[i]?.dispose() } catch { /* ignore */ }
      this.#runtimePool[i] = undefined
    }
    this.#nestedQueryCache.clear()
  }

  /**
   * Execute one deterministic reduce/query/describe call in a fresh isolated QuickJSContext.
   * Demand-pages locally stored CAS nodes that were evicted from the RAM LRU cache.
   */
  async invoke(input: ReducerInvocationInput): Promise<ReducerInvocationResult> {
    const qjs = await this.#wasmPromise
    const readPartition: CasPartition | 'any' = input.casPartition === 'public' ? 'public' : 'any'
    for (let faults = 0; faults < 256; faults++) {
      try {
        return this.#invokeSync(qjs, input, 0)
      } catch (err) {
        if (err instanceof MissingDependencyError && await input.cas.ensureLoaded(err.hash, readPartition)) {
          continue
        }
        throw err
      }
    }
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
    let timedOut = false
    let healthy = true
    const deadline = Date.now() + this.#watchdogMs

    const readPartition: CasPartition | 'any' = input.casPartition === 'public' ? 'public' : 'any'
    const writePartition: CasPartition = input.casPartition

    const tripMissing = (hash: string, kind: 'cas' | 'module' | 'sqlite'): never => {
      const err = new MissingDependencyError(hash, kind)
      missingDep ??= err
      throw err
    }

    try {
      runtime.setMemoryLimit(input.maxMemoryBytes)
      runtime.setMaxStackSize(512 * 1024)
      // Uncatchable interrupt: trips immediately if any host call records a MissingDependency or watchdog expires.
      runtime.setInterruptHandler(() => {
        if (missingDep !== null) return true
        if (Date.now() > deadline) { timedOut = true; return true }
        return false
      })

      // Strict Hash-Pinned Import Map module loader
      runtime.setModuleLoader((moduleName: string) => {
        if (moduleName === 'chronolog:crypto') {
          if (!Object.hasOwn(input.builtins, 'chronolog:crypto')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:crypto') }
          return CRYPTO_MODULE_SHIM
        }
        if (moduleName === 'chronolog:cas') {
          if (!Object.hasOwn(input.builtins, 'chronolog:cas')) return { error: new Error('BUILTIN_NOT_ENABLED:chronolog:cas') }
          return CAS_MODULE_SHIM
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
                : 'fn(env.state, ctx)'
          return `${exp}\nglobalThis.__chronologRun = () => { const env = JSON.parse(globalThis.__chronologEnvJson); const ctx = Object.freeze({ topic(name) { return Object.prototype.hasOwnProperty.call(env.topics, name) ? env.topics[name] : null; }, query(name, input = null) { return JSON.parse(globalThis.__chronologHost.queryTopic(String(name), JSON.stringify(input === undefined ? null : input))); }, opOutcome(opId) { const key = String(opId); return env.opOutcomes && Object.prototype.hasOwnProperty.call(env.opOutcomes, key) ? env.opOutcomes[key] : null; }, topicLastOpId(name) { const key = String(name); return env.topicLastOpIds && Object.prototype.hasOwnProperty.call(env.topicLastOpIds, key) ? env.topicLastOpIds[key] : null; }, config: env.config ?? null }); const fn = __target && __target[${JSON.stringify(input.method)}]; if (typeof fn !== 'function') { return JSON.stringify({ __missingMethod: true }); } const out = ${callExpr}; return JSON.stringify({ __ok: true, value: out }); };`
        }
        const ref = input.imports[moduleName]
        if (ref === undefined) return { error: new Error(`MODULE_NOT_FOUND:${moduleName}`) }
        const match = /^cas:sha256-([0-9a-f]{64})$/u.exec(ref)
        if (match === null) return { error: new Error(`MODULE_REF_INVALID:${moduleName}`) }
        const hash = match[1]!
        const node = input.cas.getSync(hash, readPartition)
        if (node === null) {
          missingDep ??= new MissingDependencyError(hash, 'module')
          return { error: missingDep }
        }
        return decodeUtf8(node.bytes)
      })

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
          const modRef = input.imports[binding.module] ?? ''
          // Pure deterministic query memoization for control topics (e.g. $permissions) when module & topic state are unchanged.
          const canMemoize = isControlTopic(topicName) && modRef.startsWith('cas:sha256-') && Object.keys(input.imports).length <= 32
          let memoKey: string | null = null
          if (canMemoize) {
            const stateKey = bytesToHex(sha256Sync(utf8(JSON.stringify(topicState))))
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
              ...(binding.config === undefined ? {} : { config: binding.config }),
              cas: input.cas,
              casPartition: nestedPartition,
              readOnly: true,
              maxMemoryBytes: input.maxMemoryBytes,
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
          const hash = ctx.getString(hashH)
          if (!/^[0-9a-f]{64}$/u.test(hash)) throw new Error('CAS_HASH_INVALID')
          const node = input.cas.getSync(hash, readPartition)
          if (node === null) {
            tripMissing(hash, 'cas')
            return ctx.undefined
          }
          return ctx.newString(JSON.stringify({ bytesHex: bytesToHex(node.bytes), links: node.links }))
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
          opOutcomes: input.opOutcomes ?? {},
          topicLastOpIds: input.topicLastOpIds ?? {},
          topics: input.topics,
          config: input.config ?? null,
        })
        const envHandle = ctx.newString(envJson)
        ctx.setProp(ctx.global, '__chronologEnvJson', envHandle)
        envHandle.dispose()

        // Load entry module (triggers Import Map loading)
        const loadRes = ctx.evalCode(
          `import '__chronolog_entry__';`,
          '__bootstrap__.mjs',
          { type: 'module' },
        )
        if (loadRes.error) {
          const dumped = ctx.dump(loadRes.error) as unknown
          loadRes.error.dispose()
          if (missingDep !== null) throw missingDep as Error
          if (timedOut) throw new OperationalTimeoutError()
          return { ok: false, code: 'vm:module_load_error', detail: formatJsError(dumped) }
        }
        loadRes.value.dispose()
        if (missingDep !== null) throw missingDep as Error
        if (timedOut) throw new OperationalTimeoutError()

        const runRes = ctx.evalCode('globalThis.__chronologRun()', '__run__.js')
        if (runRes.error) {
          const dumped = ctx.dump(runRes.error) as unknown
          runRes.error.dispose()
          if (missingDep !== null) throw missingDep as Error
          if (timedOut) throw new OperationalTimeoutError()
          const detail = formatJsError(dumped)
          const code = /out of memory|memory limit/i.test(detail) ? 'vm:limit' : 'reducer:throw'
          return { ok: false, code, detail }
        }
        const rawOut = ctx.getString(runRes.value)
        runRes.value.dispose()
        if (missingDep !== null) throw missingDep as Error
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
      if (timedOut || missingDep !== null) healthy = false
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

import { existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync, closeSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import type { ExecutionLimits } from '@chronolog/protocol'
import type { SqlEngine } from './types.js'
import { createBrowserSqlEngine, verifyWasmBuild, type ChronologWasmModule, type WasmBuildManifest } from './wasm-engine.js'

export interface NodeWasmFsApi {
  readonly analyzePath?: (path: string) => { readonly exists: boolean }
  readonly mkdir?: (path: string) => void
  readonly readFile: (path: string) => Uint8Array
  readonly writeFile: (path: string, data: Uint8Array) => void
  readonly unlink?: (path: string) => void
  readonly mount?: (type: unknown, opts: { readonly root: string }, mountpoint: string) => void
  readonly filesystems?: { readonly NODEFS?: unknown }
}

export interface NodeChronologWasmModule extends ChronologWasmModule {
  readonly FS?: NodeWasmFsApi
}

export interface LoadedNodeWasmEngine {
  readonly module: NodeChronologWasmModule
  readonly manifest: WasmBuildManifest
  readonly directory: string
  readonly wasmBytes: number
}

export interface NodeWasmMemoryBudget {
  /** Maximum SQLite page cache in KiB (default: 16384 = 16 MiB to stay well under 512 MB RSS). */
  readonly cacheSizeKiB?: number
  /** Maximum temporary store memory in KiB (default: 8192 = 8 MiB). */
  readonly maxTempStoreKiB?: number
}

function unavailable(reason: string, cause?: unknown): Error {
  return Object.assign(new Error(`SQL_ENGINE_UNAVAILABLE: ${reason}`, cause === undefined ? undefined : { cause }), {
    code: 'SQL_ENGINE_UNAVAILABLE',
    viableRoutes: ['install-prebuilt-wasm-sql', 'install-prebuilt-native-sql', 'use-remote-participant'],
  })
}

/**
 * Atomic, fsyncSync-backed host file persistence helper bridging synchronous WASM VFS writes
 * to crash-safe Node filesystem commits without partial writes or un-synced sidecars.
 */
export function writeFileAtomicSync(targetPath: string, bytes: Uint8Array): void {
  const dir = dirname(targetPath)
  mkdirSync(dir, { recursive: true })
  const tempPath = `${targetPath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
  const fd = openSync(tempPath, 'wx', 0o600)
  try {
    writeFileSync(fd, bytes)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  try {
    renameSync(tempPath, targetPath)
  } catch (error) {
    try { unlinkSync(tempPath) } catch { /* ignore cleanup */ }
    throw error
  }
  try {
    const dirFd = openSync(dir, 'r')
    try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
  } catch {
    // Directory fsync is unsupported on some platforms (e.g. Windows); file fsync + atomic rename still holds.
  }
}

/**
 * Load and cryptographically verify Chronolog's prebuilt WASM SQL artifacts from a local directory.
 * Never compiles native code or silently downgrades to events on missing/corrupt assets.
 */
export async function loadNodeWasmEngine(directory: string): Promise<LoadedNodeWasmEngine> {
  const resolved = resolve(directory)
  const manifestPath = join(resolved, 'manifest.json')
  const wasmPath = join(resolved, 'sqlite3.wasm')
  const loaderPath = join(resolved, 'sqlite3.mjs')
  for (const [label, path] of [['manifest.json', manifestPath], ['sqlite3.wasm', wasmPath], ['sqlite3.mjs', loaderPath]] as const) {
    if (!existsSync(path)) throw unavailable(`Missing verified WASM SQL artifact ${label} in ${resolved}.`)
  }
  let manifest: WasmBuildManifest
  let bytes: Uint8Array
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as WasmBuildManifest
    bytes = new Uint8Array(readFileSync(wasmPath))
    verifyWasmBuild(bytes, manifest)
  } catch (error) {
    throw unavailable('WASM SQL artifact verification failed.', error)
  }
  let compiled: WebAssembly.Module
  let initialize: (options: unknown) => Promise<NodeChronologWasmModule>
  try {
    const copy = new Uint8Array(bytes.byteLength)
    copy.set(bytes)
    compiled = await WebAssembly.compile(copy)
    const imported = await import(/* @vite-ignore */ pathToFileURL(loaderPath).href) as {
      default?: (this: void, options: unknown) => Promise<NodeChronologWasmModule>
    }
    if (typeof imported.default !== 'function') throw new Error('WASM_LOADER_INVALID')
    initialize = imported.default
  } catch (error) {
    throw unavailable('Failed to compile or import WASM SQL module.', error)
  }
  const module = await initialize({
    instantiateWasm(imports: WebAssembly.Imports, done: (instance: WebAssembly.Instance, mod: WebAssembly.Module) => void) {
      const instance = new WebAssembly.Instance(compiled, imports)
      done(instance, compiled)
      return instance.exports
    },
    printErr() { /* Diagnostics are surfaced via structured errors. */ },
  })
  return Object.freeze({ module, manifest, directory: resolved, wasmBytes: bytes.byteLength })
}

/**
 * Production Node WASM SQL engine with synchronous fsyncSync-backed persistence.
 * Uses Emscripten NODEFS when mounted or mirrors the virtual file atomically to disk on flush/close,
 * applying bounded page cache limits so peak RSS stays within constrained sandbox budgets (< 512 MB).
 */
export function createNodeWasmSqlEngine(options: {
  readonly module: NodeChronologWasmModule
  readonly manifest: WasmBuildManifest
  readonly vfs?: string
  readonly limits?: Partial<ExecutionLimits>
  readonly memoryBudget?: NodeWasmMemoryBudget
}): SqlEngine {
  const cacheSizeKiB = options.memoryBudget?.cacheSizeKiB ?? 16_384
  if (!Number.isSafeInteger(cacheSizeKiB) || cacheSizeKiB < 256 || cacheSizeKiB > 131_072) {
    throw unavailable('Invalid WASM SQL memory budget cacheSizeKiB (must be 256..131072).')
  }
  const base = createBrowserSqlEngine({
    module: options.module,
    manifest: options.manifest,
    vfs: options.vfs ?? 'unix-none',
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
  const fs = options.module.FS
  return Object.freeze({
    executionManifest: base.executionManifest,
    openDatabase(openOptions: Parameters<SqlEngine['openDatabase']>[0]) {
      if (typeof openOptions.path !== 'string' || openOptions.path.length === 0 || openOptions.path === ':memory:') {
        throw new Error('MATERIALIZER_PERSISTENT_PATH_REQUIRED')
      }
      const hostPath = resolve(openOptions.path)
      const virtualPath = `/chronolog-node-${Buffer.from(hostPath).toString('hex').slice(0, 48)}.sqlite`
      mkdirSync(dirname(hostPath), { recursive: true })
      if (fs !== undefined && existsSync(hostPath)) {
        fs.writeFile(virtualPath, new Uint8Array(readFileSync(hostPath)))
      }
      const opened = base.openDatabase({ ...openOptions, path: fs !== undefined ? virtualPath : openOptions.path })
      try {
        opened.database.exec(`PRAGMA cache_size = -${cacheSizeKiB}`)
      } catch {
        // Authorizer or read-only configuration may disallow PRAGMA; keep engine operational.
      }
      const originalClose = opened.database.close.bind(opened.database)
      const syncToHost = (): void => {
        if (fs === undefined) return
        try {
          if (fs.analyzePath?.(virtualPath).exists === false) return
          const snapshot = fs.readFile(virtualPath)
          writeFileAtomicSync(hostPath, snapshot)
        } catch (error) {
          throw unavailable(`Failed to flush WASM SQL database to ${hostPath}.`, error)
        }
      }
      const proxiedDatabase = new Proxy(opened.database, {
        get(target, prop, receiver) {
          if (prop === 'close') {
            return () => {
              try {
                originalClose()
              } finally {
                syncToHost()
              }
            }
          }
          const value: unknown = Reflect.get(target, prop, receiver)
          return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value
        },
      })
      return { ...opened, database: proxiedDatabase }
    },
  })
}

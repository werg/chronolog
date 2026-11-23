import { nodeVfsFileIdentity, nodeVfsFullPath } from './node-vfs-path.js'
import { tryLock, unlock } from 'fs-native-extensions'
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createHash, randomBytes } from 'node:crypto'
import type { ExecutionLimits } from '@chronolog/protocol'
import type { SqlEngine } from './types.js'
import { createBrowserSqlEngine, verifyWasmBuild, type ChronologWasmModule, type WasmBuildManifest } from './wasm-engine.js'

interface SqliteStruct {
  readonly pointer: number
  $iVersion: number
  $szOsFile?: number
  $mxPathname?: number
  $zName?: number
  $pMethods?: number
  installMethods(methods: Record<string, (...args: never[]) => unknown>, checkArgc?: boolean): void
  registerVfs?(asDefault: boolean): void
  addOnDispose?(...items: unknown[]): void
  dispose(): void
}

interface SqliteStructCtor {
  new (pointer?: number): SqliteStruct
  readonly structInfo: { readonly sizeof: number }
}

export interface NodeChronologWasmModule extends ChronologWasmModule {
  readonly capi: ChronologWasmModule['capi'] & {
    readonly sqlite3_vfs?: SqliteStructCtor
    readonly sqlite3_io_methods?: SqliteStructCtor
    readonly sqlite3_file?: SqliteStructCtor
    readonly sqlite3_vfs_find?: (name: string) => number
    readonly SQLITE_OK?: number
    readonly SQLITE_IOERR?: number
    readonly SQLITE_IOERR_READ?: number
    readonly SQLITE_IOERR_SHORT_READ?: number
    readonly SQLITE_IOERR_WRITE?: number
    readonly SQLITE_IOERR_FSYNC?: number
    readonly SQLITE_IOERR_TRUNCATE?: number
    readonly SQLITE_IOERR_FSTAT?: number
    readonly SQLITE_IOERR_DELETE?: number
    readonly SQLITE_CANTOPEN?: number
    readonly SQLITE_NOTFOUND?: number
    readonly SQLITE_OPEN_READONLY?: number
    readonly SQLITE_OPEN_READWRITE?: number
    readonly SQLITE_OPEN_CREATE?: number
    readonly SQLITE_OPEN_DELETEONCLOSE?: number
    readonly SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN?: number
  }
  readonly wasm: ChronologWasmModule['wasm'] & {
    readonly allocCString?: (value: string) => number
    readonly cstrToJs?: (pointer: number) => string
    readonly poke?: (pointer: number, value: number | bigint, type?: string) => void
    readonly poke32?: (pointer: number, value: number) => void
    readonly poke64?: (pointer: number, value: bigint) => void
    readonly pokePtr?: (pointer: number, value: number) => void
    readonly peek8?: (pointer: number) => number
    readonly jstrlen?: (value: string) => number
  }
  readonly vfs?: {
    installVfs(options: {
      readonly io?: { readonly struct: SqliteStruct; readonly methods: Record<string, (...args: never[]) => unknown> }
      readonly vfs?: { readonly struct: SqliteStruct; readonly methods: Record<string, (...args: never[]) => unknown>; readonly asDefault?: boolean }
    }): unknown
  }
}

export interface LoadedNodeWasmEngine {
  readonly module: NodeChronologWasmModule
  readonly manifest: WasmBuildManifest
  readonly directory: string
  readonly wasmBytes: number
}

export interface NodeWasmMemoryBudget {
  /** SQLite cache target per connection in KiB; not a total WASM/process RSS bound. */
  readonly cacheSizeKiB?: number
}

const NODE_FS_VFS_NAME = 'chronolog-node-fs'
const installedVfsModules = new WeakMap<NodeChronologWasmModule, Set<string>>()

function unavailable(reason: string, cause?: unknown): Error {
  return Object.assign(new Error(`SQL_ENGINE_UNAVAILABLE: ${reason}`, cause === undefined ? undefined : { cause }), {
    code: 'SQL_ENGINE_UNAVAILABLE',
    viableRoutes: ['install-prebuilt-wasm-sql', 'install-prebuilt-native-sql', 'use-remote-participant'],
  })
}

function syncDirectoryBestEffort(dir: string): void {
  try {
    const dirFd = openSync(dir, 'r')
    try { fsyncSync(dirFd) } finally { closeSync(dirFd) }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (!['EINVAL', 'ENOTSUP', 'ENOSYS'].includes(code ?? '') && !(process.platform === 'win32' && ['EACCES', 'EPERM', 'EISDIR'].includes(code ?? ''))) throw error
  }
}

/**
 * Atomic, fsyncSync-backed host file persistence helper for crash-safe Node filesystem commits.
 */
export function writeFileAtomicSync(targetPath: string, bytes: Uint8Array): void {
  const dir = dirname(targetPath)
  mkdirSync(dir, { recursive: true })
  const tempPath = `${targetPath}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
  let fd: number | undefined, renamed = false
  try {
    fd = openSync(tempPath, 'wx', 0o600)
    writeFileSync(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined
    renameSync(tempPath, targetPath); renamed = true
    syncDirectoryBestEffort(dir)
  } finally {
    if (fd !== undefined) { try { closeSync(fd) } catch { /* Preserve the primary failure. */ } }
    if (!renamed) { try { unlinkSync(tempPath) } catch { /* Preserve the primary failure. */ } }
  }
}

function fileOffset(value: number | bigint): number {
  const offset = Number(value)
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('SQLITE_FILE_OFFSET_INVALID')
  return offset
}

interface OpenNodeFile {
  readonly fd: number
  readonly path: string
  readonly deleteOnClose: boolean
  readonly owner?: FileOwner
  lock: number
}

interface FileOwner { readonly key: string; readonly lease: number; readonly users: Set<OpenNodeFile> }

function vfsDiagnostic(operation: string, stage: string, raw: string | undefined, error?: unknown): void {
  if (process.env.CHRONOLOG_NODE_VFS_DIAGNOSTICS !== '1') return
  const failure = error as { code?: unknown; errcode?: unknown } | undefined
  try {
    process.stderr.write('chronolog-node-vfs ' + JSON.stringify({ operation, stage,
      pathHash: raw === undefined ? null : createHash('sha256').update(raw).digest('hex').slice(0, 16),
      length: raw?.length, colon: raw?.indexOf(':'), backslash: raw?.includes('\\'), slash: raw?.includes('/'),
      lockFile: raw?.endsWith('-lock'), code: typeof failure?.code === 'string' && /^[A-Z0-9_]{1,64}$/u.test(failure.code) ? failure.code : null,
      errno: typeof failure?.errcode === 'number' ? failure.errcode : null,
    }) + '\n')
  } catch { /* Diagnostics cannot change VFS behavior. */ }
}

/**
 * Install a synchronous, fsyncSync-backed Node.js filesystem VFS (`chronolog-node-fs`) into the
 * compiled DoltLite SQLite WASM module. All reads/writes go directly to real host files with zero
 * in-memory double-buffering and full DoltLite chunk-store compatibility across Linux/macOS/Windows.
 */
export function installNodeFsVfs(module: NodeChronologWasmModule, vfsName = NODE_FS_VFS_NAME): string {
  if (installedVfsModules.get(module)?.has(vfsName)) return vfsName
  const { capi, wasm, vfs } = module
  if (!vfs?.installVfs || !capi.sqlite3_vfs || !capi.sqlite3_io_methods || !capi.sqlite3_file ||
      !wasm.allocCString || !wasm.cstrToJs || !wasm.poke32 || !wasm.poke64 || !wasm.pokePtr || !wasm.poke) {
    throw unavailable('WASM module does not expose sqlite3.vfs.installVfs APIs required for Node host persistence.')
  }
  if (capi.sqlite3_vfs_find?.(vfsName)) {
    throw unavailable('The requested VFS name is already owned by another implementation.')
  }

  const SQLITE_OK = capi.SQLITE_OK ?? 0
  const SQLITE_IOERR = capi.SQLITE_IOERR ?? 10
  const SQLITE_IOERR_READ = capi.SQLITE_IOERR_READ ?? 266
  const SQLITE_IOERR_SHORT_READ = capi.SQLITE_IOERR_SHORT_READ ?? 522
  const SQLITE_IOERR_WRITE = capi.SQLITE_IOERR_WRITE ?? 778
  const SQLITE_IOERR_FSYNC = capi.SQLITE_IOERR_FSYNC ?? 1034
  const SQLITE_IOERR_TRUNCATE = capi.SQLITE_IOERR_TRUNCATE ?? 1546
  const SQLITE_IOERR_FSTAT = capi.SQLITE_IOERR_FSTAT ?? 1802
  const SQLITE_IOERR_DELETE = capi.SQLITE_IOERR_DELETE ?? 2570
  const SQLITE_CANTOPEN = capi.SQLITE_CANTOPEN ?? 14
  const SQLITE_NOTFOUND = capi.SQLITE_NOTFOUND ?? 12
  const SQLITE_OPEN_READONLY = capi.SQLITE_OPEN_READONLY ?? 0x00000001
  const SQLITE_OPEN_CREATE = capi.SQLITE_OPEN_CREATE ?? 0x00000004
  const SQLITE_OPEN_DELETEONCLOSE = capi.SQLITE_OPEN_DELETEONCLOSE ?? 0x00000008
  const SQLITE_OPEN_MAIN_DB = 0x00000100
  const SQLITE_BUSY = 5

  const openFiles = new Map<number, OpenNodeFile>()
  const owners = new Map<string, FileOwner>()
  function owner(path: string, fd: number) {
    const key = nodeVfsFileIdentity(path, fstatSync(fd, { bigint: true }))
    let group = owners.get(key)
    if (group !== undefined) return group
    // A lock on the database inode survives path aliases and needs no sidecar.
    // Reserve a byte far beyond SQLite's addressable pages so Windows mandatory
    // byte-range locks do not interfere with database reads/writes.
    if (existsSync(path + '.chronolog-owner.sqlite')) throw new Error('SQLITE_LEGACY_OWNER_MIGRATION_REQUIRED: stop older runtimes and remove their obsolete owner sidecar before opening this database')
    const lease = openSync(path, 'r+')
    try {
      if (nodeVfsFileIdentity(path, fstatSync(lease, { bigint: true })) !== key) throw new Error('SQLITE_BUSY: file identity changed during owner acquisition')
      if (!tryLock(lease, 2 ** 52, 1)) throw new Error('SQLITE_BUSY: database already owned')
    } catch (error) { closeSync(lease); throw error }
    group = { key, lease, users: new Set() }; owners.set(key, group)
    return group
  }
  function release(entry: OpenNodeFile) {
    if (entry.owner === undefined) return
    entry.owner.users.delete(entry)
    if (entry.owner.users.size === 0) { unlock(entry.owner.lease, 2 ** 52, 1); closeSync(entry.owner.lease); owners.delete(entry.owner.key) }
  }
  const vfsStruct = new capi.sqlite3_vfs()
  const ioStruct = new capi.sqlite3_io_methods()
  ioStruct.$iVersion = 1
  vfsStruct.$iVersion = 2
  vfsStruct.$szOsFile = capi.sqlite3_file.structInfo.sizeof
  vfsStruct.$mxPathname = 4096
  vfsStruct.$zName = wasm.allocCString(vfsName)
  vfsStruct.addOnDispose?.('$zName', vfsStruct.$zName, ioStruct)

  const ioMethods: Record<string, (...args: never[]) => unknown> = {
    xClose(pFile: number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_OK
      openFiles.delete(pFile)
      try {
        closeSync(entry.fd)
        release(entry)
        if (entry.deleteOnClose) {
          try { unlinkSync(entry.path) } catch { /* ignore */ }
        }
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR
      }
    },
    xRead(pFile: number, pDest: number, n: number, offset64: bigint | number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_IOERR_READ
      try {
        const heap = wasm.heap8u()
        const start = Number(pDest)
        const target = heap.subarray(start, start + n)
        let total = 0
        let pos = fileOffset(offset64)
        while (total < n) {
          const got = readSync(entry.fd, target, total, n - total, pos)
          if (got === 0) break
          total += got
          pos += got
        }
        if (total < n) {
          heap.fill(0, start + total, start + n)
          return SQLITE_IOERR_SHORT_READ
        }
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR_READ
      }
    },
    xWrite(pFile: number, pSrc: number, n: number, offset64: bigint | number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_IOERR_WRITE
      try {
        const heap = wasm.heap8u()
        const start = Number(pSrc)
        const slice = heap.subarray(start, start + n)
        let written = 0
        let pos = fileOffset(offset64)
        while (written < n) {
          const put = writeSync(entry.fd, slice, written, n - written, pos)
          if (put <= 0) return SQLITE_IOERR_WRITE
          written += put
          pos += put
        }
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR_WRITE
      }
    },
    xTruncate(pFile: number, size64: bigint | number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_IOERR_TRUNCATE
      try {
        ftruncateSync(entry.fd, fileOffset(size64))
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR_TRUNCATE
      }
    },
    xSync(pFile: number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_IOERR_FSYNC
      try {
        fsyncSync(entry.fd)
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR_FSYNC
      }
    },
    xFileSize(pFile: number, pOutSize: number) {
      const entry = openFiles.get(pFile)
      if (!entry) return SQLITE_IOERR_FSTAT
      try {
        const stats = fstatSync(entry.fd, { bigint: true })
        wasm.poke64!(pOutSize, stats.size)
        return SQLITE_OK
      } catch {
        return SQLITE_IOERR_FSTAT
      }
    },
    xLock(pFile: number, level: number) {
      const entry = openFiles.get(pFile)
      if (entry === undefined || level < 1 || level > 4) return SQLITE_IOERR
      if (level <= entry.lock) return SQLITE_OK
      const others = [...(entry.owner?.users ?? [])].filter(other => other !== entry)
      if (level === 1 && others.some(other => other.lock >= 3) || level >= 2 && others.some(other => other.lock >= 2)) return SQLITE_BUSY
      if (level === 4 && others.some(other => other.lock > 0)) { entry.lock = 3; return SQLITE_BUSY }
      entry.lock = level; return SQLITE_OK
    },
    xUnlock(pFile: number, level: number) {
      const entry = openFiles.get(pFile)
      if (entry === undefined || level < 0 || level > entry.lock) return SQLITE_IOERR
      entry.lock = level; return SQLITE_OK
    },
    xCheckReservedLock(pFile: number, pOut: number) {
      const entry = openFiles.get(pFile)
      if (entry === undefined) return SQLITE_IOERR
      wasm.poke32!(pOut, [...(entry.owner?.users ?? [entry])].some(other => other.lock >= 2) ? 1 : 0)
      return SQLITE_OK
    },
    xFileControl() { return SQLITE_NOTFOUND },
    xSectorSize() { return 4096 },
    xDeviceCharacteristics() { return 0 },
  }

  const encoder = new TextEncoder()
  const vfsMethods: Record<string, (...args: never[]) => unknown> = {
    xOpen(_pVfs: number, zName: number, pFile: number, flags: number, pOutFlags: number) {
      let fd: number | undefined, entry: OpenNodeFile | undefined, raw: string | undefined
      let stage = 'name'
      try {
        const hasName = zName !== 0 && (wasm.peek8?.(zName) ?? 1) !== 0
        raw = hasName ? wasm.cstrToJs!(zName) : undefined
        const requestedPath = raw !== undefined ? resolve(raw)
          : join(tmpdir(), `chronolog-wasm-tmp-${process.pid}-${randomBytes(8).toString('hex')}.db`)
        const readOnly = (flags & SQLITE_OPEN_READONLY) !== 0, create = (flags & SQLITE_OPEN_CREATE) !== 0
        stage = 'directory'
        if (!readOnly) mkdirSync(dirname(requestedPath), { recursive: true })
        let openFlags = readOnly ? fsConstants.O_RDONLY : fsConstants.O_RDWR
        if (!readOnly && create) openFlags |= fsConstants.O_CREAT
        stage = 'open'
        fd = openSync(requestedPath, openFlags, 0o600)
        stage = 'realpath'
        const filePath = realpathSync(requestedPath)
        stage = 'owner'
        const group = (flags & SQLITE_OPEN_MAIN_DB) !== 0 ? owner(filePath, fd) : undefined
        entry = { fd, path: filePath, deleteOnClose: !hasName || (flags & SQLITE_OPEN_DELETEONCLOSE) !== 0,
          lock: 0, ...(group === undefined ? {} : { owner: group }) }
        group?.users.add(entry); openFiles.set(pFile, entry)
        wasm.pokePtr!(pFile, ioStruct.pointer)
        if (pOutFlags) wasm.poke32!(pOutFlags, flags)
        return SQLITE_OK
      } catch (error) {
        vfsDiagnostic('xOpen', stage, raw, error)
        if (fd !== undefined) { try { closeSync(fd) } catch { /* Preserve CANTOPEN. */ } }
        if (entry !== undefined) { openFiles.delete(pFile); release(entry) }
        wasm.pokePtr!(pFile, 0)
        return SQLITE_CANTOPEN
      }
    },
    xDelete(_pVfs: number, zName: number, syncDir: number) {
      try {
        const filePath = resolve(wasm.cstrToJs!(zName))
        if (existsSync(filePath)) {
          if (owners.has(nodeVfsFileIdentity(realpathSync(filePath), statSync(filePath, { bigint: true })))) return SQLITE_IOERR_DELETE
          unlinkSync(filePath)
        }
        if (syncDir) syncDirectoryBestEffort(dirname(filePath))
        return SQLITE_OK
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code
        return code === 'ENOENT' ? SQLITE_OK : SQLITE_IOERR_DELETE
      }
    },
    xAccess(_pVfs: number, zName: number, _flags: number, pResOut: number) {
      try {
        const filePath = resolve(wasm.cstrToJs!(zName))
        wasm.poke32!(pResOut, existsSync(filePath) ? 1 : 0)
      } catch {
        wasm.poke32!(pResOut, 0)
      }
      return SQLITE_OK
    },
    xFullPathname(_pVfs: number, zName: number, nOut: number, pOut: number) {
      let raw: string | undefined
      try {
        raw = wasm.cstrToJs!(zName)
        const full = nodeVfsFullPath(raw)
        vfsDiagnostic('xFullPathname', 'input', raw)
        vfsDiagnostic('xFullPathname', 'output', full)
        const encoded = encoder.encode(full)
        if (encoded.byteLength + 1 > nOut) return SQLITE_CANTOPEN
        const heap = wasm.heap8u(), start = Number(pOut)
        heap.set(encoded, start); heap[start + encoded.byteLength] = 0
        return SQLITE_OK
      } catch (error) { vfsDiagnostic('xFullPathname', 'resolve', raw, error); return SQLITE_CANTOPEN }
    },
    xRandomness(_pVfs: number, nByte: number, zOut: number) {
      const bytes = randomBytes(nByte)
      wasm.heap8u().set(bytes, Number(zOut))
      return nByte
    },
    xSleep(_pVfs: number, microseconds: number) {
      const ms = Math.max(0, Math.ceil(microseconds / 1000))
      if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
      return microseconds
    },
    xCurrentTime(_pVfs: number, pOut: number) {
      wasm.poke!(pOut, 2440587.5 + Date.now() / 86_400_000, 'double')
      return SQLITE_OK
    },
    xCurrentTimeInt64(_pVfs: number, pOut: number) {
      wasm.poke64!(pOut, BigInt(Math.round(2440587.5 * 86_400_000)) + BigInt(Date.now()))
      return SQLITE_OK
    },
  }

  vfs.installVfs({
    io: { struct: ioStruct, methods: ioMethods },
    vfs: { struct: vfsStruct, methods: vfsMethods, asDefault: false },
  })
  const names = installedVfsModules.get(module) ?? new Set<string>()
  names.add(vfsName); installedVfsModules.set(module, names)
  return vfsName
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
    if (typeof manifest.loaderSha256 !== 'string' || createHash('sha256').update(readFileSync(loaderPath)).digest('hex') !== manifest.loaderSha256) throw new Error('WASM_LOADER_BUILD_MISMATCH')
  } catch (error) {
    throw unavailable('WASM SQL artifact verification failed.', error)
  }
  let compiled: WebAssembly.Module
  let initialize: (options: unknown) => Promise<NodeChronologWasmModule>
  try {
    const copy = new Uint8Array(bytes.byteLength)
    copy.set(bytes)
    compiled = await WebAssembly.compile(copy)
    const imported = await import(/* @vite-ignore */ pathToFileURL(loaderPath).href + '?sha256=' + manifest.loaderSha256) as {
      default?: (this: void, options: unknown) => Promise<NodeChronologWasmModule>
    }
    if (typeof imported.default !== 'function') throw new Error('WASM_LOADER_INVALID')
    initialize = imported.default
  } catch (error) {
    throw unavailable('Failed to compile or import WASM SQL module.', error)
  }
  let module: NodeChronologWasmModule
  try { module = await initialize({
    instantiateWasm(imports: WebAssembly.Imports, done: (instance: WebAssembly.Instance, mod: WebAssembly.Module) => void) {
      const instance = new WebAssembly.Instance(compiled, imports)
      done(instance, compiled)
      return instance.exports
    },
    printErr() { /* Diagnostics are surfaced via structured errors. */ },
  })
  } catch (error) { throw unavailable('Failed to initialize WASM SQL module.', error) }
  return Object.freeze({ module, manifest, directory: resolved, wasmBytes: bytes.byteLength })
}

/**
 * Production Node WASM SQL engine backed by synchronous `node:fs` (`chronolog-node-fs` VFS)
 * with `fsyncSync` durability and bounded SQLite page cache for constrained sandbox RSS budgets.
 */
export function createNodeWasmSqlEngine(options: {
  readonly module: NodeChronologWasmModule
  readonly manifest: WasmBuildManifest
  readonly vfs?: string
  readonly limits?: Partial<ExecutionLimits>
  readonly memoryBudget?: NodeWasmMemoryBudget
}): SqlEngine {
  if (Object.keys(options.memoryBudget ?? {}).some(key => key !== 'cacheSizeKiB')) throw unavailable('Unsupported WASM SQL memory budget option.')
  const cacheSizeKiB = options.memoryBudget?.cacheSizeKiB ?? 16_384
  if (!Number.isSafeInteger(cacheSizeKiB) || cacheSizeKiB < 256 || cacheSizeKiB > 131_072) {
    throw unavailable('Invalid WASM SQL memory budget cacheSizeKiB (must be 256..131072).')
  }
  const vfsName = options.vfs ?? installNodeFsVfs(options.module)
  const base = createBrowserSqlEngine({
    module: options.module,
    manifest: options.manifest,
    vfs: vfsName,
    ...(options.limits === undefined ? {} : { limits: options.limits }),
  })
  return Object.freeze({
    executionManifest: base.executionManifest,
    openDatabase(openOptions: Parameters<SqlEngine['openDatabase']>[0]) {
      if (typeof openOptions.path !== 'string' || openOptions.path.length === 0 || openOptions.path === ':memory:') {
        throw new Error('MATERIALIZER_PERSISTENT_PATH_REQUIRED')
      }
      const hostPath = resolve(openOptions.path)
      const existingPath = existsSync(hostPath) ? realpathSync(hostPath) : hostPath
      if (existsSync(existingPath + '.chronolog-owner.sqlite')) throw unavailable('Legacy WASM owner sidecar found. Stop older runtimes before removing the obsolete owner SQLite file and its WAL/SHM companions.')
      mkdirSync(dirname(hostPath), { recursive: true })
      const opened = base.openDatabase({ ...openOptions, path: nodeVfsFullPath(hostPath) })
      try {
        opened.database.exec(`PRAGMA cache_size = -${cacheSizeKiB}`)
        opened.database.exec('PRAGMA temp_store = FILE')
      } catch (error) {
        opened.database.close()
        throw unavailable('Could not enforce the requested SQLite cache/temp policy.', error)
      }
      return opened
    },
  })
}

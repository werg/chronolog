import { utf8 } from '@chronolog/canonical'
import { canonicalJson, type JsonValue } from '@chronolog/protocol'
import {
  casRef,
  decodePackageNode,
  decodeTreeNode,
  normalizePosixPath,
  parseCasRef,
  putBlobDag,
  putTreeDag,
  readBlobDag,
  type CasPartition,
  type ChronologDerivationNode,
  type ContentAddressedStore,
} from '@chronolog/records'
import type { WasiDerivationRunner } from './derivation.js'

const ERRNO_SUCCESS = 0
const ERRNO_BADF = 8
const ERRNO_INVAL = 28
const ERRNO_NOENT = 44
const ERRNO_NOSYS = 52
const ERRNO_ROFS = 69

const FILETYPE_DIRECTORY = 3
const FILETYPE_REGULAR_FILE = 4

class WasiExit extends Error {
  readonly code: number
  constructor(code: number) {
    super(`WASI_EXIT:${code}`)
    this.code = code
  }
}

interface VirtualFd {
  readonly kind: 'stdio' | 'preopen' | 'file'
  readonly path: string
  readonly writable: boolean
  offset: number
  data: Uint8Array
}

function concatChunks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.byteLength + b.byteLength)
  out.set(a, 0)
  out.set(b, a.byteLength)
  return out
}

/**
 * Reference pure, deterministic `wasi-cas-v1` runner (`wasi_snapshot_preview1` over CAS VFS).
 *
 * Works identically in Node.js, Browsers, and Cloudflare Workers (zero `node:wasi` required):
 * - Mounts every named `drv.inputs` (`chronolog-tree/v1` or `chronolog-blob/v1`) read-only at `/inputs/<name>/...`
 * - Provides a deterministic writable `/out/` directory; on clean `proc_exit(0)`, packs `/out/...`
 *   into a canonical `chronolog-tree/v1` CAS node (or single `chronolog-blob/v1` if only `/out/output` exists).
 * - Strips ALL ambient non-determinism: `clock_time_get` returns 0, `random_get` traps,
 *   `environ_get` exposes ONLY canonical `CHRONOLOG_ARGS=<canonicalJson(drv.args)>`, zero host fs/network.
 */
export function createWasiCasRunner(): WasiDerivationRunner {
  const compiledCache = new Map<string, WebAssembly.Module>()

  return async (
    drv: ChronologDerivationNode,
    cas: ContentAddressedStore,
    partition: CasPartition,
  ): Promise<string> => {
    const builderHash = parseCasRef(drv.builder)
    const builderNode = await cas.get(builderHash, partition)
    if (builderNode === null) throw new Error(`WASI_BUILDER_MISSING:${drv.builder}`)

    // Builder can be a raw .wasm blob OR a chronolog-pkg/v1 with `wasm.entry`
    let wasmHash = builderHash
    let wasmBytes: Uint8Array | null
    try {
      const pkg = decodePackageNode(builderNode.bytes)
      const entryPath = pkg.wasm?.entry ?? pkg.exports['.']
      if (entryPath === undefined || pkg.files[entryPath] === undefined) {
        throw new Error(`WASI_BUILDER_ENTRY_MISSING:${drv.builder}`)
      }
      wasmHash = parseCasRef(pkg.files[entryPath])
      wasmBytes = await readBlobDag(cas, wasmHash, partition)
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('WASI_BUILDER_')) throw err
      wasmBytes = await readBlobDag(cas, builderHash, partition)
    }
    if (wasmBytes === null) throw new Error(`WASI_BUILDER_BYTES_MISSING:${wasmHash}`)

    // 1. Hydrate read-only virtual filesystem from drv.inputs
    const roFiles = new Map<string, Uint8Array>()
    for (const [inputName, ref] of Object.entries(drv.inputs).sort(([a], [b]) => a.localeCompare(b))) {
      const inputHash = parseCasRef(ref)
      const node = await cas.get(inputHash, partition)
      if (node === null) throw new Error(`WASI_INPUT_MISSING:${inputName}:${ref}`)
      let loadedTree = false
      try {
        const tree = decodeTreeNode(node.bytes)
        for (const [relPath, fileRef] of Object.entries(tree.entries)) {
          const fBytes = await readBlobDag(cas, parseCasRef(fileRef), partition)
          if (fBytes === null) throw new Error(`WASI_INPUT_FILE_MISSING:${relPath}`)
          roFiles.set(`inputs/${normalizePosixPath(inputName)}/${normalizePosixPath(relPath)}`, fBytes)
        }
        loadedTree = true
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('WASI_INPUT_')) throw err
      }
      if (!loadedTree) {
        const fBytes = await readBlobDag(cas, inputHash, partition)
        if (fBytes === null) throw new Error(`WASI_INPUT_BYTES_MISSING:${inputName}`)
        roFiles.set(`inputs/${normalizePosixPath(inputName)}`, fBytes)
      }
    }

    const outFiles = new Map<string, Uint8Array>()
    const fds = new Map<number, VirtualFd>([
      [0, { kind: 'stdio', path: '/dev/stdin', writable: false, offset: 0, data: new Uint8Array(0) }],
      [1, { kind: 'stdio', path: '/dev/stdout', writable: true, offset: 0, data: new Uint8Array(0) }],
      [2, { kind: 'stdio', path: '/dev/stderr', writable: true, offset: 0, data: new Uint8Array(0) }],
      [3, { kind: 'preopen', path: '/', writable: true, offset: 0, data: new Uint8Array(0) }],
    ])
    let nextFd = 4
    const memBox: { current: WebAssembly.Memory | null } = { current: null }

    const argsList = [utf8('chronolog-wasi-builder\0')]
    const envList = [utf8(`CHRONOLOG_ARGS=${canonicalJson(drv.args as JsonValue)}\0`)]

    const memView = (): DataView => new DataView(memBox.current!.buffer)
    const memU8 = (): Uint8Array => new Uint8Array(memBox.current!.buffer)

    const resolvePath = (dirPath: string, rawRel: string): string | null => {
      const cleaned = rawRel.replace(/^\/+/u, '')
      const base = dirPath === '/' ? '' : dirPath.replace(/^\/+|\/+$/gu, '')
      const joined = base.length > 0 ? `${base}/${cleaned}` : cleaned
      try { return normalizePosixPath(joined) } catch { return null }
    }

    const wasiImports = {
      args_sizes_get(argcPtr: number, argvBufSizePtr: number): number {
        const dv = memView()
        dv.setUint32(argcPtr, argsList.length, true)
        dv.setUint32(argvBufSizePtr, argsList.reduce((s, a) => s + a.byteLength, 0), true)
        return ERRNO_SUCCESS
      },
      args_get(argvPtr: number, argvBufPtr: number): number {
        const dv = memView(); const u8 = memU8()
        let bufOff = argvBufPtr
        for (let i = 0; i < argsList.length; i++) {
          dv.setUint32(argvPtr + i * 4, bufOff, true)
          u8.set(argsList[i]!, bufOff)
          bufOff += argsList[i]!.byteLength
        }
        return ERRNO_SUCCESS
      },
      environ_sizes_get(countPtr: number, bufSizePtr: number): number {
        const dv = memView()
        dv.setUint32(countPtr, envList.length, true)
        dv.setUint32(bufSizePtr, envList.reduce((s, e) => s + e.byteLength, 0), true)
        return ERRNO_SUCCESS
      },
      environ_get(envPtr: number, envBufPtr: number): number {
        const dv = memView(); const u8 = memU8()
        let bufOff = envBufPtr
        for (let i = 0; i < envList.length; i++) {
          dv.setUint32(envPtr + i * 4, bufOff, true)
          u8.set(envList[i]!, bufOff)
          bufOff += envList[i]!.byteLength
        }
        return ERRNO_SUCCESS
      },
      clock_time_get(_id: number, _precision: bigint, timePtr: number): number {
        memView().setBigUint64(timePtr, 0n, true)
        return ERRNO_SUCCESS
      },
      clock_res_get(_id: number, resPtr: number): number {
        memView().setBigUint64(resPtr, 1_000_000n, true)
        return ERRNO_SUCCESS
      },
      random_get(): number {
        throw new Error('WASI_NONDETERMINISTIC_RANDOM')
      },
      proc_exit(code: number): never {
        throw new WasiExit(code)
      },
      fd_prestat_get(fd: number, bufPtr: number): number {
        const entry = fds.get(fd)
        if (entry === undefined || entry.kind !== 'preopen') return ERRNO_BADF
        const dv = memView()
        dv.setUint8(bufPtr, 0) // preopentype::dir
        dv.setUint32(bufPtr + 4, utf8(entry.path).byteLength, true)
        return ERRNO_SUCCESS
      },
      fd_prestat_dir_name(fd: number, pathPtr: number, pathLen: number): number {
        const entry = fds.get(fd)
        if (entry === undefined || entry.kind !== 'preopen') return ERRNO_BADF
        const bytes = utf8(entry.path)
        if (bytes.byteLength > pathLen) return ERRNO_INVAL
        memU8().set(bytes, pathPtr)
        return ERRNO_SUCCESS
      },
      path_open(
        dirFd: number,
        _dirFlags: number,
        pathPtr: number,
        pathLen: number,
        oflags: number,
        _rightsBase: bigint,
        _rightsInheriting: bigint,
        _fdFlags: number,
        outFdPtr: number,
      ): number {
        const dir = fds.get(dirFd)
        if (dir === undefined || dir.kind !== 'preopen') return ERRNO_BADF
        const rawPath = new TextDecoder().decode(memU8().subarray(pathPtr, pathPtr + pathLen))
        const norm = resolvePath(dir.path, rawPath)
        if (norm === null) return ERRNO_INVAL
        const wantsCreate = (oflags & 1) !== 0
        const wantsTrunc = (oflags & 8) !== 0

        if (norm.startsWith('out/')) {
          const outKey = norm.slice('out/'.length)
          if (outKey.length === 0) return ERRNO_INVAL
          const existing = outFiles.get(outKey)
          if (existing === undefined && !wantsCreate) return ERRNO_NOENT
          const initial = wantsTrunc || existing === undefined ? new Uint8Array(0) : existing.slice()
          outFiles.set(outKey, initial)
          const fd = nextFd++
          fds.set(fd, { kind: 'file', path: norm, writable: true, offset: 0, data: initial })
          memView().setUint32(outFdPtr, fd, true)
          return ERRNO_SUCCESS
        }

        if (wantsCreate || wantsTrunc) return ERRNO_ROFS
        const data = roFiles.get(norm)
        if (data === undefined) return ERRNO_NOENT
        const fd = nextFd++
        fds.set(fd, { kind: 'file', path: norm, writable: false, offset: 0, data })
        memView().setUint32(outFdPtr, fd, true)
        return ERRNO_SUCCESS
      },
      fd_read(fd: number, iovsPtr: number, iovsLen: number, nreadPtr: number): number {
        const entry = fds.get(fd)
        if (entry === undefined || entry.kind === 'preopen') return ERRNO_BADF
        const dv = memView(); const u8 = memU8()
        let total = 0
        for (let i = 0; i < iovsLen; i++) {
          const ptr = dv.getUint32(iovsPtr + i * 8, true)
          const len = dv.getUint32(iovsPtr + i * 8 + 4, true)
          const avail = Math.max(0, entry.data.byteLength - entry.offset)
          const toRead = Math.min(len, avail)
          if (toRead > 0) {
            u8.set(entry.data.subarray(entry.offset, entry.offset + toRead), ptr)
            entry.offset += toRead
            total += toRead
          }
        }
        dv.setUint32(nreadPtr, total, true)
        return ERRNO_SUCCESS
      },
      fd_write(fd: number, iovsPtr: number, iovsLen: number, nwrittenPtr: number): number {
        const entry = fds.get(fd)
        if (entry === undefined || entry.kind === 'preopen') return ERRNO_BADF
        if (!entry.writable) return ERRNO_ROFS
        const dv = memView(); const u8 = memU8()
        let total = 0
        for (let i = 0; i < iovsLen; i++) {
          const ptr = dv.getUint32(iovsPtr + i * 8, true)
          const len = dv.getUint32(iovsPtr + i * 8 + 4, true)
          const slice = u8.slice(ptr, ptr + len)
          entry.data = concatChunks(entry.data, slice)
          entry.offset = entry.data.byteLength
          total += len
        }
        if (entry.kind === 'file' && entry.path.startsWith('out/')) {
          outFiles.set(entry.path.slice('out/'.length), entry.data)
        }
        dv.setUint32(nwrittenPtr, total, true)
        return ERRNO_SUCCESS
      },
      fd_fdstat_get(fd: number, statPtr: number): number {
        const entry = fds.get(fd)
        if (entry === undefined) return ERRNO_BADF
        const dv = memView()
        dv.setUint8(statPtr, entry.kind === 'preopen' ? FILETYPE_DIRECTORY : FILETYPE_REGULAR_FILE)
        dv.setUint16(statPtr + 2, 0, true)
        dv.setBigUint64(statPtr + 8, 0xffffffffffffffffn, true)
        dv.setBigUint64(statPtr + 16, 0xffffffffffffffffn, true)
        return ERRNO_SUCCESS
      },
      fd_close(fd: number): number {
        if (fd <= 3 || !fds.has(fd)) return ERRNO_BADF
        fds.delete(fd)
        return ERRNO_SUCCESS
      },
      fd_seek(): number { return ERRNO_NOSYS },
      path_create_directory(): number { return ERRNO_SUCCESS },
      path_filestat_get(): number { return ERRNO_NOSYS },
    }

    let mod = compiledCache.get(wasmHash)
    if (mod === undefined) {
      mod = await WebAssembly.compile(wasmBytes.slice())
      // Reject any host imports outside `wasi_snapshot_preview1`
      for (const imp of WebAssembly.Module.imports(mod)) {
        if (imp.module !== 'wasi_snapshot_preview1') {
          throw new Error(`WASI_DISALLOWED_HOST_IMPORT:${imp.module}.${imp.name}`)
        }
      }
      compiledCache.set(wasmHash, mod)
    }

    const instance = await WebAssembly.instantiate(mod, { wasi_snapshot_preview1: wasiImports })
    const exp = instance.exports
    if (!(exp.memory instanceof WebAssembly.Memory)) throw new Error('WASI_MEMORY_EXPORT_REQUIRED')
    if (typeof exp._start !== 'function') throw new Error('WASI_START_EXPORT_REQUIRED')
    memBox.current = exp.memory

    try {
      ;(exp._start as () => void)()
    } catch (err) {
      if (err instanceof WasiExit) {
        if (err.code !== 0) throw new Error(`WASI_NONZERO_EXIT:${err.code}`, { cause: err })
      } else {
        throw err
      }
    }

    // Check output files
    if (outFiles.size === 0) throw new Error('WASI_NO_OUTPUT_PRODUCED')
    if (outFiles.size === 1 && outFiles.has('output')) {
      const stored = await putBlobDag(cas, outFiles.get('output')!, partition)
      return casRef(stored.hash)
    }
    const filesRecord: Record<string, Uint8Array> = {}
    for (const [k, v] of [...outFiles.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      filesRecord[k] = v
    }
    const tree = await putTreeDag(cas, filesRecord, partition)
    return tree.ref
  }
}

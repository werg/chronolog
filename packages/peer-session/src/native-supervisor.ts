import { chmodSync, lstatSync, mkdirSync, rmSync } from 'node:fs'
import { createServer, connect, type Server, type Socket } from 'node:net'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

/** Create a private directory (0700 on POSIX). */
export function ensurePrivateDirectory(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  try { chmodSync(dir, 0o700) } catch { /* Windows */ }
}

/**
 * The single owner fence: an OS-level exclusive SQLite lock held for as long as the handle is open.
 * The kernel releases it when the process dies, so there is no stale-lock recovery, no PID reuse
 * hazard, and no read-then-delete race.
 */
export interface ExclusiveSqliteFence {
  readonly path: string
  /** True until `close()`; proof that this process still holds the fence. */
  readonly held: boolean
  close(): void
}

function isSqliteBusy(err: unknown): boolean {
  const { errcode, message } = err as { errcode?: unknown; message?: unknown }
  if (typeof errcode === 'number') return (errcode & 0xff) === 5 || (errcode & 0xff) === 6
  return typeof message === 'string' && /database (?:table )?is (?:locked|busy)/iu.test(message)
}

/**
 * Acquire an OS-level exclusive SQLite fence (`PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE`)
 * using Node's built-in `node:sqlite` (`DatabaseSync`) so two processes can never own the same
 * state directory (and so never sign concurrently or race on its IPC socket).
 * Throws `OWNER_BUSY` when another process holds it; any other failure is rethrown unchanged.
 */
export function openExclusiveSqliteFence(dbPath: string): ExclusiveSqliteFence {
  ensurePrivateDirectory(dirname(dbPath))
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath)
    db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS owner_fence(id INTEGER PRIMARY KEY);')
  } catch (err) {
    try { db?.close() } catch { /* ignore */ }
    if (!isSqliteBusy(err)) throw err
    throw Object.assign(new Error(`Exclusive SQLite fence busy: ${dbPath}`), { code: 'OWNER_BUSY', cause: err })
  }
  const handle = db
  let closed = false
  return {
    path: dbPath,
    get held() { return !closed },
    close() {
      if (closed) return
      closed = true
      try { handle.exec('ROLLBACK') } catch { /* ignore */ }
      try { handle.close() } catch { /* ignore */ }
    },
  }
}

export interface NativeIpcConnection {
  send(frame: Uint8Array): void
  onFrame(listener: (frame: Uint8Array) => void): () => void
  onClose(listener: () => void): () => void
  close(): void
}

function wrapLengthPrefixedSocket(socket: Socket, maxFrameBytes = 16 * 1024 * 1024): NativeIpcConnection {
  const frameListeners = new Set<(frame: Uint8Array) => void>()
  const closeListeners = new Set<() => void>()
  let buf: Buffer<ArrayBufferLike> = Buffer.alloc(0)

  socket.on('data', (chunk: Buffer) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk])
    while (buf.length >= 4) {
      const len = buf.readUInt32BE(0)
      if (len > maxFrameBytes) {
        socket.destroy(new Error('IPC_FRAME_TOO_LARGE'))
        return
      }
      if (buf.length < 4 + len) break
      const frame = new Uint8Array(buf.subarray(4, 4 + len))
      buf = buf.subarray(4 + len)
      for (const fn of frameListeners) fn(frame)
    }
  })
  const emitClose = (): void => {
    for (const fn of closeListeners) fn()
    closeListeners.clear()
  }
  socket.on('close', emitClose)
  socket.on('error', () => { socket.destroy() })

  return {
    send(frame: Uint8Array) {
      if (frame.byteLength > maxFrameBytes) throw new Error('IPC_FRAME_TOO_LARGE')
      const header = Buffer.allocUnsafe(4)
      header.writeUInt32BE(frame.byteLength, 0)
      socket.write(Buffer.concat([header, Buffer.from(frame.buffer, frame.byteOffset, frame.byteLength)]))
    },
    onFrame(listener) {
      frameListeners.add(listener)
      return () => frameListeners.delete(listener)
    },
    onClose(listener) {
      closeListeners.add(listener)
      return () => closeListeners.delete(listener)
    },
    close() { socket.destroy() },
  }
}

/**
 * Start a length-prefixed local IPC server over a Unix domain socket or Windows named pipe.
 * Requires the caller's held `ExclusiveSqliteFence`: only the fence holder may replace a stale
 * socket file, and only a leftover socket (never a regular file) is unlinked.
 */
export async function startNativeIpcServer(options: {
  readonly socketPath: string
  /** The held owner fence; a socket is only created (and any stale one unlinked) while it is held. */
  readonly fence: ExclusiveSqliteFence
  readonly maxFrameBytes?: number
  readonly onConnection: (conn: NativeIpcConnection) => void
}): Promise<{ readonly socketPath: string; close(): Promise<void> }> {
  if (!options.fence.held) throw Object.assign(new Error('startNativeIpcServer requires a held owner fence'), { code: 'OWNER_FENCE_NOT_HELD' })
  const isPipe = options.socketPath.startsWith('\\\\.\\pipe\\')
  if (!isPipe) {
    ensurePrivateDirectory(dirname(options.socketPath))
    let stale: ReturnType<typeof lstatSync> | undefined
    try { stale = lstatSync(options.socketPath) } catch (err) { if ((err as { code?: string }).code !== 'ENOENT') throw err }
    if (stale !== undefined) {
      if (!stale.isSocket()) throw Object.assign(new Error(`Refusing to replace non-socket file at ${options.socketPath}`), { code: 'EEXIST' })
      rmSync(options.socketPath, { force: true })
    }
  }
  const server: Server = createServer(socket => {
    options.onConnection(wrapLengthPrefixedSocket(socket, options.maxFrameBytes))
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(options.socketPath, () => {
      server.off('error', reject)
      if (!isPipe) {
        try { chmodSync(options.socketPath, 0o600) } catch { /* ignore */ }
      }
      resolve()
    })
  })
  return {
    socketPath: options.socketPath,
    async close() {
      await new Promise<void>(resolve => server.close(() => resolve()))
      if (!isPipe) rmSync(options.socketPath, { force: true })
    },
  }
}

/** Connect to a local length-prefixed IPC server. */
export async function connectNativeIpc(socketPath: string, maxFrameBytes?: number): Promise<NativeIpcConnection> {
  const socket = await new Promise<Socket>((resolve, reject) => {
    const s = connect(socketPath, () => { s.off('error', reject); resolve(s) })
    s.once('error', reject)
  })
  return wrapLengthPrefixedSocket(socket, maxFrameBytes)
}

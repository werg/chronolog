import { chmodSync, mkdirSync, openSync, closeSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { createServer, connect, type Server, type Socket } from 'node:net'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

/** Create a private directory (0700 on POSIX). */
export function ensurePrivateDirectory(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  try { chmodSync(dir, 0o700) } catch { /* Windows */ }
}

function isPidAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return (err as { code?: string }).code === 'EPERM'
  }
}

export interface AtomicLockHandle {
  readonly path: string
  release(): void
}

/**
 * Acquire an exclusive atomic lockfile inside `dir` (with stale dead-PID recovery).
 * Throws `OWNER_BUSY` if another live process holds the lock.
 */
export function acquireAtomicLock(dir: string, filename = 'owner.lock'): AtomicLockHandle {
  ensurePrivateDirectory(dir)
  const lockPath = join(dir, filename)
  const payload = JSON.stringify({ pid: process.pid, startedAt: Date.now() }) + '\n'

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(lockPath, 'wx', 0o600)
      try { writeFileSync(fd, payload) } finally { closeSync(fd) }
      let released = false
      return {
        path: lockPath,
        release() {
          if (released) return
          released = true
          try { unlinkSync(lockPath) } catch { /* ignore */ }
        },
      }
    } catch (err) {
      if ((err as { code?: string }).code !== 'EEXIST') throw err
      try {
        const existing = JSON.parse(readFileSync(lockPath, 'utf8')) as { pid?: number }
        if (typeof existing.pid === 'number' && isPidAlive(existing.pid)) {
          throw Object.assign(new Error(`Owner lock held by active PID ${existing.pid}`), { code: 'OWNER_BUSY' })
        }
        rmSync(lockPath, { force: true })
      } catch (readErr) {
        if ((readErr as { code?: string }).code === 'OWNER_BUSY') throw readErr
        rmSync(lockPath, { force: true })
      }
    }
  }
  throw Object.assign(new Error('Failed to acquire atomic owner lock'), { code: 'OWNER_BUSY' })
}

export interface ExclusiveSqliteFence {
  readonly path: string
  close(): void
}

/**
 * Acquire an OS-level exclusive SQLite fence (`PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE`)
 * using Node's built-in `node:sqlite` (`DatabaseSync`) so two processes can never sign concurrently.
 */
export function openExclusiveSqliteFence(dbPath: string): ExclusiveSqliteFence {
  ensurePrivateDirectory(dirname(dbPath))
  let db: DatabaseSync | undefined
  try {
    db = new DatabaseSync(dbPath)
    db.exec('PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS owner_fence(id INTEGER PRIMARY KEY);')
    let closed = false
    return {
      path: dbPath,
      close() {
        if (closed) return
        closed = true
        try { db?.exec('ROLLBACK') } catch { /* ignore */ }
        try { db?.close() } catch { /* ignore */ }
      },
    }
  } catch (err) {
    try { db?.close() } catch { /* ignore */ }
    throw Object.assign(new Error(`Exclusive SQLite fence busy: ${dbPath}`), { code: 'OWNER_BUSY', cause: err })
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

/** Start a length-prefixed local IPC server over a Unix domain socket or Windows named pipe. */
export async function startNativeIpcServer(options: {
  readonly socketPath: string
  readonly maxFrameBytes?: number
  readonly onConnection: (conn: NativeIpcConnection) => void
}): Promise<{ readonly socketPath: string; close(): Promise<void> }> {
  const isPipe = options.socketPath.startsWith('\\\\.\\pipe\\')
  if (!isPipe) {
    ensurePrivateDirectory(dirname(options.socketPath))
    rmSync(options.socketPath, { force: true })
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

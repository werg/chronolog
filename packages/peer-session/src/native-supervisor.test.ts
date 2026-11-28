import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/canonical'
import { connectNativeIpc, openExclusiveSqliteFence, startNativeIpcServer, type ExclusiveSqliteFence } from './native-supervisor.js'

let dir: string
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'chronolog-native-sup-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

/** Hold the fence from a separate OS process, like a second agent on the same state directory. */
async function holdFenceInChild(dbPath: string): Promise<{ kill(): Promise<void> }> {
  const child = spawn(process.execPath, ['-e', `
    const { DatabaseSync } = require('node:sqlite')
    const db = new DatabaseSync(process.argv[1])
    db.exec('PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; CREATE TABLE IF NOT EXISTS owner_fence(id INTEGER PRIMARY KEY);')
    process.stdout.write('held\\n')
    setInterval(() => {}, 1000)
  `, dbPath], { stdio: ['ignore', 'pipe', 'inherit'] })
  await new Promise<void>((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', code => reject(new Error(`fence child exited early: ${String(code)}`)))
    child.stdout.once('data', () => { child.removeAllListeners('exit'); resolve() })
  })
  return {
    kill: () => new Promise<void>(resolve => { child.once('exit', () => resolve()); child.kill('SIGKILL') }),
  }
}

/** A crashed owner (SIGKILL) cannot unlink its socket, so the file is left behind. */
async function leaveStaleSocketBehind(socketPath: string): Promise<void> {
  const child = spawn(process.execPath, ['-e', `
    require('node:net').createServer().listen(process.argv[1], () => process.stdout.write('listening\\n'))
  `, socketPath], { stdio: ['ignore', 'pipe', 'inherit'] })
  await new Promise<void>((resolve, reject) => {
    child.once('error', reject)
    child.stdout.once('data', () => resolve())
  })
  await new Promise<void>(resolve => { child.once('exit', () => resolve()); child.kill('SIGKILL') })
}

describe('native supervisor owner fence', () => {
  it('is exclusive in-process and released on close', () => {
    const path = join(dir, 'owner.sqlite')
    const first = openExclusiveSqliteFence(path)
    expect(first.held).toBe(true)
    expect(() => openExclusiveSqliteFence(path)).toThrow(expect.objectContaining({ code: 'OWNER_BUSY' }))
    first.close()
    expect(first.held).toBe(false)
    first.close()
    openExclusiveSqliteFence(path).close()
  })

  it('does not mislabel non-contention failures as OWNER_BUSY', () => {
    writeFileSync(join(dir, 'owner.sqlite'), 'this is not a sqlite database, not even close'.repeat(8))
    let caught: unknown
    try { openExclusiveSqliteFence(join(dir, 'owner.sqlite')) } catch (err) { caught = err }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as { code?: string }).code).not.toBe('OWNER_BUSY')
  })

  it('refuses a second process while a live owner holds it and recovers after the owner is killed', async () => {
    const path = join(dir, 'owner.sqlite')
    const child = await holdFenceInChild(path)
    try {
      expect(() => openExclusiveSqliteFence(path)).toThrow(expect.objectContaining({ code: 'OWNER_BUSY' }))
    } finally {
      await child.kill()
    }
    // The kernel dropped the dead owner's lock; no stale-lock cleanup logic is involved.
    openExclusiveSqliteFence(path).close()
  })
})

describe('native supervisor IPC', () => {
  it('serves length-prefixed frames and removes its socket on close', async () => {
    const fence = openExclusiveSqliteFence(join(dir, 'owner.sqlite'))
    const socketPath = join(dir, 'ipc.sock')
    const srv = await startNativeIpcServer({
      socketPath,
      fence,
      onConnection: conn => conn.onFrame(frame => conn.send(utf8(`echo:${new TextDecoder().decode(frame)}`))),
    })
    try {
      const client = await connectNativeIpc(socketPath)
      const reply = await new Promise<string>(resolve => {
        client.onFrame(frame => resolve(new TextDecoder().decode(frame)))
        client.send(utf8('ping'))
      })
      expect(reply).toBe('echo:ping')
      client.close()
    } finally {
      await srv.close()
      fence.close()
    }
    expect(existsSync(socketPath)).toBe(false)
  })

  it('refuses to create or unlink a socket without a held fence', async () => {
    const socketPath = join(dir, 'ipc.sock')
    const live = createServer()
    await new Promise<void>(resolve => live.listen(socketPath, resolve))
    try {
      const fence: ExclusiveSqliteFence = openExclusiveSqliteFence(join(dir, 'owner.sqlite'))
      fence.close()
      await expect(startNativeIpcServer({ socketPath, fence, onConnection: () => {} }))
        .rejects.toMatchObject({ code: 'OWNER_FENCE_NOT_HELD' })
      // The live owner's socket was not unlinked by the fenceless attempt.
      const client = await connectNativeIpc(socketPath)
      client.close()
    } finally {
      await new Promise<void>(resolve => live.close(() => resolve()))
    }
  })

  it('replaces only a leftover socket, never a regular file', async () => {
    const fence = openExclusiveSqliteFence(join(dir, 'owner.sqlite'))
    try {
      const filePath = join(dir, 'not-a-socket')
      writeFileSync(filePath, 'precious')
      await expect(startNativeIpcServer({ socketPath: filePath, fence, onConnection: () => {} }))
        .rejects.toMatchObject({ code: 'EEXIST' })
      expect(existsSync(filePath)).toBe(true)

      // A crashed owner leaves a socket file behind; the fence holder reclaims it.
      const stalePath = join(dir, 'stale.sock')
      await leaveStaleSocketBehind(stalePath)
      expect(existsSync(stalePath)).toBe(true)
      const srv = await startNativeIpcServer({ socketPath: stalePath, fence, onConnection: () => {} })
      const client = await connectNativeIpc(stalePath)
      client.close()
      await srv.close()
    } finally {
      fence.close()
    }
  })
})

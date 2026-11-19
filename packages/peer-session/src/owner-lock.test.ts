import { describe, expect, it } from 'vitest'
import { acquireApplicationOwnerLock, type ApplicationOwnerLockManager } from './owner-lock.js'

function manager(): ApplicationOwnerLockManager {
  const held = new Set<string>()
  return { async request(name, options, callback) {
    expect(options).toEqual({ mode: 'exclusive', ifAvailable: true })
    if (held.has(name)) return callback(null)
    held.add(name)
    try { await callback({ name }) } finally { held.delete(name) }
  } }
}

describe('protocol-first profile owner fencing', () => {
  it('fences same-profile owners before storage and releases only on explicit close', async () => {
    const locks = manager(), one = await acquireApplicationOwnerLock('profile-a', { locks })
    await expect(acquireApplicationOwnerLock('profile-a', { locks })).rejects.toThrow('OWNER_BUSY')
    const independent = await acquireApplicationOwnerLock('profile-b', { locks })
    expect(one.signal.aborted).toBe(false)
    await one.close(); expect(one.signal.aborted).toBe(true)
    const replacement = await acquireApplicationOwnerLock('profile-a', { locks })
    await one.close(); await expect(acquireApplicationOwnerLock('profile-a', { locks })).rejects.toThrow('OWNER_BUSY')
    await independent.close(); await replacement.close()
  })
  it('cancels acquisition without permitting implicit takeover or silently releasing a live owner', async () => {
    const locks = manager(), cancelled = new AbortController(); cancelled.abort(new Error('cancel'))
    await expect(acquireApplicationOwnerLock('profile-a', { locks, signal: cancelled.signal })).rejects.toThrow('cancel')
    const caller = new AbortController(), owner = await acquireApplicationOwnerLock('profile-a', { locks, signal: caller.signal })
    caller.abort(new Error('caller ended'))
    expect(owner.signal.aborted).toBe(false)
    await expect(acquireApplicationOwnerLock('profile-a', { locks })).rejects.toThrow('OWNER_BUSY')
    await owner.close()
  })
  it('reports unsupported primitives and invalid profile selection explicitly', async () => {
    await expect(acquireApplicationOwnerLock('../other')).rejects.toThrow('APPLICATION_OWNER_PROFILE_INVALID')
    await expect(acquireApplicationOwnerLock('profile', { locks: {} as ApplicationOwnerLockManager })).rejects.toThrow('APPLICATION_OWNER_LOCK_UNAVAILABLE')
  })
  it('queues a follower behind the real exclusive lease and cancels queued takeover', async () => {
    let releaseFirst!: () => void, acquireQueued!: () => void
    let count = 0
    const locks: ApplicationOwnerLockManager = { async request(_name, options, callback) {
      if (++count === 1) {
        try { await callback({}) } finally { releaseFirst?.() }
      } else {
        expect(options.ifAvailable).toBeUndefined()
        await new Promise<void>((resolve, reject) => {
          releaseFirst = resolve; acquireQueued = resolve
          options.signal?.addEventListener('abort', () => reject(options.signal?.reason), { once: true })
        })
        await callback({})
      }
    } }
    const first = await acquireApplicationOwnerLock('profile', { locks })
    let acquired = false
    const waiting = acquireApplicationOwnerLock('profile', { locks, wait: true }).then(value => { acquired = true; return value })
    await Promise.resolve(); expect(acquired).toBe(false)
    await first.close(); const second = await waiting; expect(acquired).toBe(true); await second.close()
    const cancellation = new AbortController()
    const cancelled = acquireApplicationOwnerLock('profile', { locks, wait: true, signal: cancellation.signal })
    cancellation.abort(new Error('tab closed')); await expect(cancelled).rejects.toThrow('tab closed')
    acquireQueued() // A late callback cannot grant a cancelled acquisition.
  })

})

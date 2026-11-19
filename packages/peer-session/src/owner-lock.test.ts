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
})

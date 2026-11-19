/** A protocol-owner lease is distinct from the lazy durable-data storage lock. */
export interface ApplicationOwnerLock {
  readonly profileId: string
  readonly signal: AbortSignal
  close(): Promise<void>
}
export interface ApplicationOwnerLockManager {
  request(name: string, options: { readonly mode: 'exclusive'; readonly ifAvailable?: true; readonly signal?: AbortSignal }, callback: (lock: object | null) => Promise<void>): Promise<void>
}

/**
 * Never steals a suspended owner's lease. Acquire before opening profile identity,
 * then release only after the owner's session closes. No OPFS/SQL import or access.
 * Caller cancellation affects acquisition, not an already acquired owner lifetime.
 */
export function acquireApplicationOwnerLock(profileId: string, options: {
  readonly locks?: ApplicationOwnerLockManager
  /** Queue a fenced takeover until the previous owner actually releases its lease. */
  readonly wait?: boolean
  readonly signal?: AbortSignal
} = {}): Promise<ApplicationOwnerLock> {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(profileId)) return Promise.reject(new Error('APPLICATION_OWNER_PROFILE_INVALID'))
  if (options.signal?.aborted) return Promise.reject(options.signal.reason)
  const locks = (options.locks ?? (typeof navigator === 'undefined' ? undefined : navigator.locks)) as ApplicationOwnerLockManager | undefined
  if (locks === undefined || typeof locks.request !== 'function') return Promise.reject(new Error('APPLICATION_OWNER_LOCK_UNAVAILABLE'))
  return new Promise((resolve, reject) => {
    let settled = false
    const abort = (): void => { if (!settled) { settled = true; reject(options.signal?.reason) } }
    options.signal?.addEventListener('abort', abort, { once: true })
    const clean = (): void => options.signal?.removeEventListener('abort', abort)
    let completed: Promise<void>
    try {
      completed = locks.request('chronolog-owner:' + profileId, { mode: 'exclusive', ...(options.wait === true
        ? options.signal === undefined ? {} : { signal: options.signal } : { ifAvailable: true as const }) }, async lock => {
        if (settled) return
        settled = true; clean()
        if (lock === null) { reject(Object.assign(new Error('OWNER_BUSY'), { code: 'OWNER_BUSY' })); return }
        const lifetime = new AbortController()
        let release!: () => void, closing: Promise<void> | undefined
        const held = new Promise<void>(done => { release = done })
        resolve(Object.freeze({ profileId, signal: lifetime.signal, close(): Promise<void> {
          if (closing !== undefined) return closing
          lifetime.abort(new Error('OWNER_UNREACHABLE')); release()
          closing = completed.then(() => undefined)
          return closing
        } }))
        await held
      })
      void completed.catch(error => { if (!settled) { settled = true; clean(); reject(error) } })
    } catch (error) { settled = true; clean(); reject(error) }
  })
}

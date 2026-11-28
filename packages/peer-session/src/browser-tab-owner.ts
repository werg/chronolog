import { connectApplicationOwner } from './browser.js'
import { SessionError } from './view-store.js'
import type { WorkerApplicationSession } from './worker-application.js'

export const TAB_OWNER_PROTOCOL = 'chronolog/tab-owner/v1'

/**
 * Request persistent browser storage so IndexedDB/OPFS device keys and journals
 * are kept out of best-effort eviction. Never throws; returns null if unsupported.
 */
export function requestPersistentStorage(): Promise<boolean | null> {
  const nav = (globalThis as { navigator?: { storage?: { persist?: () => Promise<boolean>; persisted?: () => Promise<boolean> } } }).navigator
  const storage = nav?.storage
  if (typeof storage?.persist !== 'function') return Promise.resolve(null)
  return (async () => {
    try {
      if (typeof storage.persisted === 'function' && await storage.persisted()) return true
      return await storage.persist!()
    } catch {
      return false
    }
  })()
}

export interface NetworkLeaderOptions {
  readonly tabId?: string
  readonly namespace?: string
  readonly signal?: AbortSignal
  readonly hiddenGraceMs?: number
  readonly pingTimeoutMs?: number
  readonly onRole: (active: boolean) => void
}

/**
 * Non-blocking, stealable networking leader election across concurrent tabs/PWAs of the same
 * profile using Web Locks (`navigator.locks`) + `BroadcastChannel` liveness probing.
 *
 * Never blocks local IndexedDB reads or writes — follower tabs stay interactive via shared
 * storage + BroadcastChannel `syncFromStore()`, while at most one live tab maintains host
 * discovery/relay sockets. Frozen or hidden holders are cleanly stolen by visible tabs.
 */
export function coordinateNetworkLeader(profileId: string, options: NetworkLeaderOptions): () => void {
  const ns = options.namespace ?? 'chronolog'
  const tabId = options.tabId ?? (typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Math.random()))
  const hiddenGraceMs = options.hiddenGraceMs ?? 10_000
  const pingTimeoutMs = options.pingTimeoutMs ?? 500
  const nav = (globalThis as { navigator?: { locks?: { request?: (name: string, opts: Record<string, unknown>, cb: (lock: unknown) => Promise<void>) => Promise<void> } } }).navigator
  const locks = nav?.locks
  const doc = (globalThis as { document?: { visibilityState?: string; addEventListener?: (t: string, fn: () => void) => void; removeEventListener?: (t: string, fn: () => void) => void } }).document
  if (typeof locks?.request !== 'function') {
    options.onRole(true)
    return () => {}
  }

  const lockName = `${ns}:net:${profileId}`
  const channel = typeof globalThis.BroadcastChannel === 'function' ? new BroadcastChannel(`${ns}:net:${profileId}`) : null
  let stopped = false
  let holding = false
  let releaseHeld: (() => void) | null = null
  let hiddenTimer: ReturnType<typeof setTimeout> | undefined
  let trying = false

  const isVisible = (): boolean => doc === undefined || doc.visibilityState !== 'hidden'
  const setHolding = (next: boolean): void => {
    if (holding === next) return
    holding = next
    try { options.onRole(next) } catch { /* caller callback error */ }
  }
  const dropLeadership = (): void => {
    if (hiddenTimer !== undefined) { clearTimeout(hiddenTimer); hiddenTimer = undefined }
    if (releaseHeld === null) return
    const rel = releaseHeld
    releaseHeld = null
    setHolding(false)
    rel()
    try { channel?.postMessage({ type: 'net-released', from: tabId }) } catch { /* ignore */ }
  }

  const pingHolder = (): Promise<{ readonly visible: boolean } | null> => new Promise(resolve => {
    if (channel === null) { resolve(null); return }
    const id = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Math.random())
    const timer = setTimeout(() => {
      channel.removeEventListener('message', onPong)
      resolve(null)
    }, pingTimeoutMs)
    const onPong = (event: MessageEvent): void => {
      const data = event.data as { type?: string; id?: string; visible?: boolean } | null
      if (data?.type !== 'net-pong' || data.id !== id) return
      clearTimeout(timer)
      channel.removeEventListener('message', onPong)
      resolve({ visible: Boolean(data.visible) })
    }
    channel.addEventListener('message', onPong)
    try {
      channel.postMessage({ type: 'net-ping', id, from: tabId })
    } catch {
      clearTimeout(timer)
      channel.removeEventListener('message', onPong)
      resolve(null)
    }
  })

  const holdLock = (lockOpts: Record<string, unknown>): Promise<boolean> => new Promise(resolve => {
    let resolved = false
    const finish = (acquired: boolean): void => {
      if (!resolved) { resolved = true; resolve(acquired) }
    }
    void locks.request!(lockName, lockOpts, lock => {
      if (!lock || stopped || options.signal?.aborted) {
        finish(false)
        return Promise.resolve()
      }
      return new Promise<void>(release => {
        releaseHeld = release
        setHolding(true)
        finish(true)
      })
    }).catch(() => {
      if (releaseHeld !== null) { releaseHeld = null; setHolding(false) }
      finish(false)
    })
  })

  const tryAcquire = async (): Promise<void> => {
    if (stopped || options.signal?.aborted || holding || trying) return
    trying = true
    try {
      if (await holdLock({ ifAvailable: true })) return
      if (!isVisible() || stopped || options.signal?.aborted) return
      const holder = await pingHolder()
      if (stopped || options.signal?.aborted || holding) return
      if (holder === null || !holder.visible) {
        await holdLock({ steal: true })
      }
    } finally {
      trying = false
    }
  }

  const onChannel = (event: MessageEvent): void => {
    const data = event.data as { type?: string; id?: string; from?: string } | null
    if (stopped || data === null || data.from === tabId) return
    if (data.type === 'net-ping' && holding) {
      try { channel?.postMessage({ type: 'net-pong', id: data.id, from: tabId, visible: isVisible() }) } catch { /* ignore */ }
    } else if (data.type === 'net-released' && !holding && isVisible()) {
      void tryAcquire()
    }
  }
  channel?.addEventListener('message', onChannel)

  const onVisibility = (): void => {
    if (stopped) return
    if (isVisible()) {
      if (hiddenTimer !== undefined) { clearTimeout(hiddenTimer); hiddenTimer = undefined }
      if (!holding) void tryAcquire()
    } else if (holding) {
      if (hiddenTimer !== undefined) clearTimeout(hiddenTimer)
      hiddenTimer = setTimeout(() => { hiddenTimer = undefined; if (!isVisible()) dropLeadership() }, hiddenGraceMs)
    }
  }
  const onFreeze = (): void => dropLeadership()
  const onFocus = (): void => { if (!stopped && !holding && isVisible()) void tryAcquire() }

  doc?.addEventListener?.('visibilitychange', onVisibility)
  doc?.addEventListener?.('freeze', onFreeze)
  doc?.addEventListener?.('resume', onFocus)
  globalThis.addEventListener?.('focus', onFocus)
  globalThis.addEventListener?.('pagehide', onFreeze)

  void tryAcquire()

  const stop = (): void => {
    if (stopped) return
    stopped = true
    if (hiddenTimer !== undefined) { clearTimeout(hiddenTimer); hiddenTimer = undefined }
    doc?.removeEventListener?.('visibilitychange', onVisibility)
    doc?.removeEventListener?.('freeze', onFreeze)
    doc?.removeEventListener?.('resume', onFocus)
    globalThis.removeEventListener?.('focus', onFocus)
    globalThis.removeEventListener?.('pagehide', onFreeze)
    channel?.removeEventListener('message', onChannel)
    dropLeadership()
    channel?.close()
  }
  options.signal?.addEventListener('abort', stop, { once: true })
  return stop
}

/**
 * Tab-side services bound to the owner Worker (for example an in-tab WebRTC host the Worker
 * relays to, or a listener for Worker diagnostics). `closeNow` runs synchronously first on
 * every close (and on `pagehide`), before anything is awaited; `close` is awaited afterwards.
 */
export interface TabWorkerServicesHandle {
  closeNow?(): void
  close?(): void | Promise<void>
}

export interface ConnectTabWorkerOwnerOptions<S extends TabWorkerServicesHandle | undefined = undefined> {
  readonly profileId: string
  readonly workerUrl: string | URL
  readonly applicationId: string
  readonly configuration?: unknown
  readonly context?: Readonly<Record<string, unknown>>
  readonly protocol?: string
  readonly namespace?: string
  /** Dedicated Worker name (default `chronolog-owner:<profileId>`). */
  readonly workerName?: string
  /** Stable id of this tab for network leader election. */
  readonly tabId?: string
  readonly timeoutMs?: number
  /** Aborting closes the attachment at any point, including after it opened. */
  readonly signal?: AbortSignal
  /** Ask for persistent storage (default true). */
  readonly persistStorage?: boolean
  /**
   * `'retire'` (default): a non-persisted `pagehide` closes services synchronously, posts
   * `retire` to the Worker before the page goes away, then releases. `'ignore'`: the host does it.
   */
  readonly pagehide?: 'retire' | 'ignore'
  /** Start tab-side services for the Worker right after it is spawned, before `boot`. */
  readonly onWorker?: (worker: Worker, ctx: { readonly signal: AbortSignal }) => S
}

export interface TabWorkerAttachment<S extends TabWorkerServicesHandle | undefined = undefined> {
  readonly session: WorkerApplicationSession
  readonly worker: Worker
  readonly ownerInstanceId: string
  /** What `onWorker` returned. */
  readonly services: S
  /** `requestPersistentStorage()` result (null when unsupported or not requested). */
  readonly storagePersisted: Promise<boolean | null>
  /** Ask the Worker to resync from the shared store and run its `onWake` hook. */
  wake(): void
  close(): Promise<void>
}

const randomId = (): string => typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Math.random())

function validateWorkerUrl(options: { readonly profileId: string; readonly workerUrl: string | URL }): URL {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(options.profileId)) {
    throw new SessionError('INVALID_PROFILE', 'Invalid browser owner profileId')
  }
  if (typeof globalThis.Worker !== 'function') {
    throw new SessionError('OWNER_CAPABILITY_UNAVAILABLE', 'Dedicated Workers are required for browser session ownership')
  }
  const url = new URL(String(options.workerUrl), globalThis.location?.href)
  if (globalThis.location?.origin && url.origin !== globalThis.location.origin) {
    throw new SessionError('OWNER_ORIGIN_MISMATCH', 'Session worker URL must share origin with page')
  }
  return url
}

function waitForWorker<T>(worker: Worker, protocol: string, predicate: (data: Record<string, unknown>) => boolean, options: { readonly signal?: AbortSignal; readonly timeoutMs: number }): Promise<T> {
  return new Promise((resolve, reject) => {
    const finish = (err: unknown, val?: T): void => {
      clearTimeout(timer)
      worker.removeEventListener('message', onMsg)
      worker.removeEventListener('error', onErr)
      options.signal?.removeEventListener('abort', onAbort)
      if (err !== null && err !== undefined) reject(err instanceof Error ? err : new Error(typeof err === 'string' ? err : 'WORKER_ERROR'))
      else resolve(val as T)
    }
    const onMsg = (ev: MessageEvent): void => {
      const data = ev.data as Record<string, unknown> | null
      if (data?.protocol !== protocol) return
      if (data.type === 'failure') {
        const code = typeof data.code === 'string' ? data.code : 'OWNER_UNREACHABLE'
        const message = typeof data.message === 'string' ? data.message : 'Worker failed'
        finish(new SessionError(code, message))
      } else if (predicate(data)) {
        finish(null, data as unknown as T)
      }
    }
    const onErr = (ev: ErrorEvent): void => finish(new SessionError('WORKER_LOAD_FAILED', ev.message || 'Worker failed to load'))
    const onAbort = (): void => finish(options.signal?.reason ?? new Error('ABORTED'))
    const timer = setTimeout(() => finish(new SessionError('BOOT_TIMEOUT', 'Session worker timed out')), options.timeoutMs)
    worker.addEventListener('message', onMsg)
    worker.addEventListener('error', onErr)
    options.signal?.addEventListener('abort', onAbort, { once: true })
    if (options.signal?.aborted) onAbort()
  })
}

/**
 * Lock-free 1:1 dedicated Worker tab owner:
 * - Spawns a dedicated Worker backed by multi-tab IndexedDB/OPFS + BroadcastChannel sync.
 * - Transfers a direct MessageChannel port to `createApplicationOwner` inside the Worker.
 * - Coordinates a non-blocking stealable network leader lock across sibling tabs.
 * - Starts optional tab-side `onWorker` services and retires the Worker on page unload.
 */
export async function connectTabWorkerOwner<S extends TabWorkerServicesHandle | undefined = undefined>(options: ConnectTabWorkerOwnerOptions<S>): Promise<TabWorkerAttachment<S>> {
  const url = validateWorkerUrl(options)
  const protocol = options.protocol ?? TAB_OWNER_PROTOCOL
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new SessionError('OWNER_CONFIGURATION_INVALID', 'Opening timeout must be finite and positive')
  options.signal?.throwIfAborted()
  const storagePersisted = options.persistStorage === false ? Promise.resolve(null) : requestPersistentStorage()

  const lifetime = new AbortController()
  const worker = new Worker(url, { type: 'module', name: options.workerName ?? `chronolog-owner:${options.profileId}` })
  const channel = new MessageChannel()
  let services: S | undefined, session: WorkerApplicationSession | undefined, stopLeader: (() => void) | undefined
  let releasing: Promise<void> | undefined

  const postRetire = (): string | null => {
    const id = randomId()
    try { worker.postMessage({ protocol, type: 'retire', id, profileId: options.profileId }); return id } catch { return null }
  }
  const release = (reason: unknown, unloading = false): Promise<void> => {
    if (releasing !== undefined) return releasing
    try { services?.closeNow?.() } catch { /* best effort */ }
    try { stopLeader?.() } catch { /* ignore */ }
    globalThis.removeEventListener?.('pagehide', onPageHide)
    options.signal?.removeEventListener('abort', onExternalAbort)
    lifetime.abort(reason)
    // On unload the page may be gone before any await resumes: retire synchronously.
    const retireId = unloading ? postRetire() : null
    releasing = (async () => {
      if (!unloading) { try { await session?.detach() } catch { /* ignore */ } }
      try { await services?.close?.() } catch { /* ignore */ }
      try { channel.port1.close() } catch { /* ignore */ }
      try {
        const id = retireId ?? postRetire()
        if (id !== null) await waitForWorker(worker, protocol, d => d.type === 'retired' && d.id === id, { timeoutMs: 2000 })
      } catch { /* terminate regardless */ }
      worker.terminate()
    })()
    return releasing
  }
  const onPageHide = (event: Event): void => {
    if ((event as Event & { persisted?: boolean }).persisted === true) return
    void release(new Error('PAGE_UNLOAD'), true)
  }
  const onExternalAbort = (): void => { void release(options.signal?.reason ?? new Error('ABORTED')) }

  try {
    options.signal?.addEventListener('abort', onExternalAbort, { once: true })
    services = options.onWorker?.(worker, { signal: lifetime.signal })
    const bootId = randomId()
    const readyPromise = waitForWorker<{ readonly ownerInstanceId: string }>(worker, protocol, d => d.type === 'ready' && d.id === bootId, { signal: lifetime.signal, timeoutMs })
    worker.postMessage(
      { protocol, type: 'boot', id: bootId, profileId: options.profileId, ...(options.configuration === undefined ? {} : { configuration: options.configuration }) },
      [channel.port2],
    )
    const ready = await readyPromise
    channel.port1.start()
    session = await attachWithin(channel.port1, options, lifetime.signal, timeoutMs)
    lifetime.signal.throwIfAborted()
    stopLeader = coordinateNetworkLeader(options.profileId, {
      ...(options.namespace === undefined ? {} : { namespace: options.namespace }),
      ...(options.tabId === undefined ? {} : { tabId: options.tabId }),
      signal: lifetime.signal,
      onRole: active => {
        try { worker.postMessage({ protocol, type: 'network-role', active }) } catch { /* ignore */ }
      },
    })
    if (options.pagehide !== 'ignore') globalThis.addEventListener?.('pagehide', onPageHide)
    const attached = session
    return Object.freeze({
      session: attached,
      worker,
      ownerInstanceId: ready.ownerInstanceId,
      services: services as S,
      storagePersisted,
      wake() { try { worker.postMessage({ protocol, type: 'wake' }) } catch { /* ignore */ } },
      close: () => release(new Error('TAB_DETACHED')),
    })
  } catch (err) {
    await release(err)
    throw err
  }
}

async function attachWithin(port: MessagePort, options: ConnectTabWorkerOwnerOptions<TabWorkerServicesHandle | undefined>, signal: AbortSignal, timeoutMs: number): Promise<WorkerApplicationSession> {
  signal.throwIfAborted()
  let cancelled = false, timer: ReturnType<typeof setTimeout> | undefined, onAbort: (() => void) | undefined
  const opening = connectApplicationOwner(port, {
    applicationId: options.applicationId,
    ...(options.context === undefined ? {} : { context: options.context }),
  })
  void opening.then(late => { if (cancelled) void late.detach().catch(() => {}) }, () => {})
  try {
    return await Promise.race([
      opening,
      new Promise<never>((_, reject) => {
        onAbort = () => { cancelled = true; reject(signal.reason) }
        signal.addEventListener('abort', onAbort, { once: true })
        timer = setTimeout(() => { cancelled = true; reject(new SessionError('CONNECT_TIMEOUT', 'Timed out attaching to the session worker')) }, timeoutMs)
      }),
    ])
  } finally {
    clearTimeout(timer)
    if (onAbort !== undefined) signal.removeEventListener('abort', onAbort)
  }
}

/**
 * Deliberate enrollment: spawn a short-lived owner Worker that answers `identity` through its
 * `createIdentity` configuration, without opening a session, and return the device public key.
 */
export async function createTabWorkerIdentity(options: {
  readonly profileId: string
  readonly workerUrl: string | URL
  readonly configuration?: unknown
  readonly protocol?: string
  readonly timeoutMs?: number
  readonly signal?: AbortSignal
  readonly persistStorage?: boolean
}): Promise<string> {
  const url = validateWorkerUrl(options)
  const protocol = options.protocol ?? TAB_OWNER_PROTOCOL
  const worker = new Worker(url, { type: 'module' })
  const id = randomId()
  try {
    const reply = waitForWorker<{ readonly publicKey: string }>(worker, protocol, d => d.type === 'identity' && d.id === id, {
      timeoutMs: options.timeoutMs ?? 30_000,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    worker.postMessage({ protocol, type: 'identity', id, profileId: options.profileId, ...(options.configuration === undefined ? {} : { configuration: options.configuration }) })
    const { publicKey } = await reply
    if (options.persistStorage !== false) void requestPersistentStorage()
    return publicKey
  } finally {
    worker.terminate()
  }
}

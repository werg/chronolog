import { createApplicationOwner } from './session-owner.js'
import type { ApplicationOwnerOptions, ApplicationSessionOwner } from './owner-types.js'
import type { ApplicationSession, FactsDelta } from './session.js'
import { FACTS_SOURCE_STORE } from './session-types.js'
import { TAB_OWNER_PROTOCOL } from './browser-tab-owner.js'

export interface TabWorkerOwnedSession {
  readonly session: ApplicationSession
  readonly extensions?: ApplicationOwnerOptions['extensions']
  setNetworkActive?(active: boolean): void
  /** Called after the Worker wakes (network change, tab resume, `wake()`), after a store sync was started. */
  onWake?(): void | Promise<void>
  close?(): void | Promise<void>
}

export interface TabWorkerScope {
  postMessage(message: unknown): void
  addEventListener(type: 'message', listener: (event: Event) => void): void
  removeEventListener(type: 'message', listener: (event: Event) => void): void
}

/** Context passed to `openSession`: owner basics plus whatever `services` contributed. */
export type TabWorkerOpenContext<C extends object = object> = C & { readonly signal: AbortSignal; readonly initialNetworkActive: boolean }

/**
 * Worker-scope services started before the session opens (for example a WebRTC opener that
 * relays to an in-tab RTC host). `context` is merged into the `openSession` context;
 * `close` runs when the owner closes.
 */
export type TabWorkerServices<C extends object> = (ctx: {
  readonly scope: TabWorkerScope
  readonly signal: AbortSignal
  /** Resync from the shared store and run `onWake` (call on network changes). */
  readonly wake: () => void
}) => { readonly context: C; close?(): void }

export interface TabWorkerConfiguration<C extends object = object> {
  readonly profileId: string
  readonly openSession: (ctx: TabWorkerOpenContext<C>) => Promise<TabWorkerOwnedSession>
  /** Answers a tab's `createTabWorkerIdentity` request with the device public key. */
  readonly createIdentity?: (ctx: { readonly signal: AbortSignal }) => Promise<string>
  readonly ownerOptions?: ApplicationOwnerOptions
}

export interface ServeTabWorkerOwnerOptions<C extends object = object> extends Partial<TabWorkerConfiguration<C>> {
  readonly scope?: TabWorkerScope
  readonly protocol?: string
  readonly namespace?: string
  readonly services?: TabWorkerServices<C>
  /** Lazily resolve the configuration from the tab's `boot`/`identity` message. */
  readonly load?: (ctx: { readonly signal: AbortSignal; readonly configuration: unknown }) => Promise<TabWorkerConfiguration<C>>
}

export interface TabWorkerOwnerHandle {
  readonly owner: ApplicationSessionOwner | undefined
  /** Resync from the shared store and run `onWake`. */
  wake(): void
  close(): Promise<void>
}

const errorCode = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code
  if (typeof code === 'string' && code.length > 0) return code
  return error instanceof Error ? error.message : String(error)
}

/**
 * Serve one dedicated Worker owned by a browser tab over lock-free multi-tab IndexedDB/OPFS.
 * - Attaches transferred `MessagePort` directly to `createApplicationOwner`.
 * - Broadcasts `facts-updated` across sibling tabs on `BroadcastChannel` for every fact
 *   delta not ingested from the shared store, and calls `session.syncFromStore()` on receipt.
 * - Forwards stealable `network-role` messages to `owned.setNetworkActive`.
 * - Answers `identity` requests through `createIdentity` without opening a session.
 */
export function serveTabWorkerOwner<C extends object = object>(options: ServeTabWorkerOwnerOptions<C>): TabWorkerOwnerHandle {
  const scope = options.scope ?? globalThis
  const protocol = options.protocol ?? TAB_OWNER_PROTOCOL
  const ns = options.namespace ?? 'chronolog'
  const lifetime = new AbortController()
  const workerId = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Math.random())

  let configuration: TabWorkerConfiguration<C> | undefined
  let owner: ApplicationSessionOwner | undefined
  let owned: TabWorkerOwnedSession | undefined
  let opening: Promise<ApplicationSessionOwner> | undefined
  let appPort: MessagePort | undefined
  let syncChannel: BroadcastChannel | undefined
  let stopFacts: () => void = () => {}
  let closing: Promise<void> | undefined
  let closed = false
  let latestNetworkActive: boolean | null = null
  // Store syncs coalesce: at most one running and one queued, so bursts of sibling notices
  // never pile up, and a notice that arrives mid-sync still gets a full pass afterwards.
  let syncRunning = false, syncQueued = false
  let broadcastQueued = false

  const post = (value: unknown): void => {
    try { scope.postMessage(value) } catch { /* tab closed */ }
  }

  const syncFromStore = (): void => {
    if (closed || owned === undefined) return
    if (syncRunning) { syncQueued = true; return }
    syncRunning = true
    void owned.session.syncFromStore().catch(() => false).finally(() => {
      syncRunning = false
      if (syncQueued) { syncQueued = false; syncFromStore() }
    })
  }

  const wake = (): void => {
    if (closed || owned === undefined) return
    syncFromStore()
    try { void Promise.resolve(owned.onWake?.()).catch(() => {}) } catch { /* ignore */ }
  }

  const services = options.services?.({ scope, signal: lifetime.signal, wake })

  // Origin, not timing, decides: a delta made only of facts this Worker pulled from the shared
  // store is already visible to siblings; anything else (local writes, network deliveries,
  // untagged deltas) is announced, even while a store sync is running.
  const broadcast = (delta: FactsDelta): void => {
    if (closed) return
    if (delta.items.length > 0 && delta.items.every(item => item.source === FACTS_SOURCE_STORE)) return
    if (broadcastQueued) return
    broadcastQueued = true
    queueMicrotask(() => {
      broadcastQueued = false
      if (closed) return
      try { syncChannel?.postMessage({ type: 'facts-updated', sender: workerId }) } catch { /* ignore */ }
    })
  }

  let configPromise: Promise<TabWorkerConfiguration<C>> | undefined
  const resolveConfig = (supplied: unknown): Promise<TabWorkerConfiguration<C>> => {
    if (configPromise !== undefined) return configPromise
    configPromise = (async () => {
      const loaded: Partial<TabWorkerConfiguration<C>> = options.load !== undefined
        ? await options.load({ signal: lifetime.signal, configuration: supplied })
        : options
      if (loaded.profileId === undefined || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(loaded.profileId) || typeof loaded.openSession !== 'function') {
        throw new Error('OWNER_CONFIGURATION_INVALID')
      }
      return configuration = loaded as TabWorkerConfiguration<C>
    })()
    void configPromise.catch(() => {})
    return configPromise
  }
  if (options.load === undefined) void resolveConfig(undefined)

  const ensureOpen = (supplied: unknown, transferredPort: MessagePort | null): Promise<ApplicationSessionOwner> => {
    if (opening !== undefined) return opening
    opening = (async () => {
      const config = await resolveConfig(supplied)
      lifetime.signal.throwIfAborted()
      try {
        owned = await config.openSession({
          ...(services?.context ?? {} as C),
          signal: lifetime.signal,
          initialNetworkActive: latestNetworkActive !== false,
        })
        lifetime.signal.throwIfAborted()
        const ownerOptions = config.ownerOptions ?? {}
        owner = createApplicationOwner(owned.session, owned.extensions !== undefined ? { ...ownerOptions, extensions: owned.extensions } : ownerOptions)
        if (transferredPort !== null) {
          appPort = transferredPort
          appPort.start()
          owner.attach(appPort)
        }
        if (typeof globalThis.BroadcastChannel === 'function') {
          syncChannel = new BroadcastChannel(`${ns}:sync:${config.profileId}`)
          syncChannel.addEventListener('message', (event: MessageEvent) => {
            const data = event.data as { sender?: string; type?: string } | null
            if (closed || data === null || data.sender === workerId || data.type !== 'facts-updated') return
            syncFromStore()
          })
          stopFacts = owned.session.onFacts(broadcast)
        }
        if (latestNetworkActive !== null) {
          try { owned.setNetworkActive?.(latestNetworkActive) } catch { /* ignore */ }
        }
        owned.session.signal.addEventListener('abort', () => { void close().catch(() => {}) }, { once: true })
        if (owned.session.signal.aborted) void close().catch(() => {})
        return owner
      } catch (err) {
        try { await owned?.session.close() } finally { await owned?.close?.() }
        throw err
      }
    })().catch(err => { opening = undefined; owned = undefined; owner = undefined; throw err })
    return opening
  }

  const fail = (id: unknown, err: unknown): void =>
    post({ protocol, type: 'failure', id, code: errorCode(err), message: err instanceof Error ? err.message : String(err) })

  const handleControl = async (data: Record<string, unknown>, ports: readonly MessagePort[]): Promise<void> => {
    if (data.type === 'identity') {
      try {
        const config = await resolveConfig(data.configuration)
        if (data.profileId !== config.profileId) throw new Error('INVALID_PROFILE')
        if (config.createIdentity === undefined) throw new Error('OWNER_IDENTITY_UNAVAILABLE')
        const publicKey = await config.createIdentity({ signal: lifetime.signal })
        post({ protocol, type: 'identity', id: data.id, publicKey })
      } catch (err) { fail(data.id, err) }
      return
    }
    if (data.type === 'boot') {
      try {
        const config = await resolveConfig(data.configuration)
        if (data.profileId !== config.profileId) throw new Error('INVALID_PROFILE')
        const activeOwner = await ensureOpen(data.configuration, ports[0] ?? null)
        post({ protocol, type: 'ready', id: data.id, profileId: config.profileId, ownerInstanceId: activeOwner.ownerInstanceId })
      } catch (err) { fail(data.id, err) }
      return
    }
    if (data.type === 'network-role') {
      latestNetworkActive = Boolean(data.active)
      try { owned?.setNetworkActive?.(latestNetworkActive) } catch { /* ignore */ }
      return
    }
    if (data.type === 'wake') { wake(); return }
    if (data.type === 'retire') {
      try { await close() }
      finally { post({ protocol, type: 'retired', id: data.id, profileId: configuration?.profileId }) }
    }
  }

  const onMessage = (event: Event): void => {
    const me = event as MessageEvent
    const data = me.data as Record<string, unknown> | null
    if (closed || data === null || data.protocol !== protocol) return
    void handleControl(data, me.ports ?? [])
  }
  scope.addEventListener('message', onMessage)

  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    closed = true
    lifetime.abort(new Error('OWNER_CLOSED'))
    scope.removeEventListener('message', onMessage)
    closing = (async () => {
      try { stopFacts() } catch { /* ignore */ }
      try { syncChannel?.close() } catch { /* ignore */ }
      try { appPort?.close() } catch { /* ignore */ }
      try { services?.close?.() } catch { /* ignore */ }
      try { await owner?.close() } catch { /* ignore */ }
      try { await owned?.close?.() } catch { /* ignore */ }
      try { await owned?.session.close() } catch { /* ignore */ }
      owner = undefined; owned = undefined; syncChannel = undefined; appPort = undefined
    })()
    return closing
  }

  return Object.freeze({
    get owner() { return owner },
    wake,
    close,
  })
}

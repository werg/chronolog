import { createApplicationOwner } from './session-owner.js'
import type { ApplicationOwnerOptions, ApplicationSessionOwner } from './owner-types.js'
import type { ApplicationSession } from './session.js'
import { TAB_OWNER_PROTOCOL } from './browser-tab-owner.js'

export interface TabWorkerOwnedSession {
  readonly session: ApplicationSession
  readonly extensions?: ApplicationOwnerOptions['extensions']
  setNetworkActive?(active: boolean): void
  onWake?(): void | Promise<void>
  close?(): void | Promise<void>
}

export interface ServeTabWorkerOwnerOptions {
  readonly scope?: {
    postMessage(message: unknown): void
    addEventListener(type: 'message', listener: (event: Event) => void): void
    removeEventListener(type: 'message', listener: (event: Event) => void): void
  }
  readonly profileId?: string
  readonly protocol?: string
  readonly namespace?: string
  readonly openSession?: (ctx: { readonly signal: AbortSignal; readonly initialNetworkActive: boolean }) => Promise<TabWorkerOwnedSession>
  readonly ownerOptions?: ApplicationOwnerOptions
  readonly load?: (ctx: { readonly signal: AbortSignal; readonly configuration: unknown }) => Promise<{
    readonly profileId: string
    readonly openSession: (ctx: { readonly signal: AbortSignal; readonly initialNetworkActive: boolean }) => Promise<TabWorkerOwnedSession>
    readonly ownerOptions?: ApplicationOwnerOptions
  }>
}

/**
 * Serve one dedicated Worker owned by a browser tab over lock-free multi-tab IndexedDB/OPFS.
 * - Attaches transferred `MessagePort` directly to `createApplicationOwner`.
 * - Broadcasts `facts-updated` across sibling tabs on `BroadcastChannel` and calls `session.syncFromStore()`.
 * - Forwards stealable `network-role` messages to `owned.setNetworkActive`.
 */
export function serveTabWorkerOwner(options: ServeTabWorkerOwnerOptions): {
  readonly owner: ApplicationSessionOwner | undefined
  close(): Promise<void>
} {
  const scope = options.scope ?? globalThis
  const protocol = options.protocol ?? TAB_OWNER_PROTOCOL
  const ns = options.namespace ?? 'chronolog'
  const lifetime = new AbortController()
  const workerId = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Math.random())

  let profileId = options.profileId
  let openSession = options.openSession
  let ownerOptions: ApplicationOwnerOptions = options.ownerOptions ?? {}
  let owner: ApplicationSessionOwner | undefined
  let owned: TabWorkerOwnedSession | undefined
  let opening: Promise<ApplicationSessionOwner> | undefined
  let appPort: MessagePort | undefined
  let syncChannel: BroadcastChannel | undefined
  let stopFacts: () => void = () => {}
  let closing: Promise<void> | undefined
  let closed = false
  let syncingFromStore = false
  let latestNetworkActive: boolean | null = null

  const post = (value: unknown): void => {
    try { scope.postMessage(value) } catch { /* tab closed */ }
  }

  let configPromise: Promise<void> | undefined
  const resolveConfig = (configuration: unknown): Promise<void> => {
    if (configPromise !== undefined) return configPromise
    configPromise = Promise.resolve()
      .then(async () => {
        if (options.load !== undefined) {
          const loaded = await options.load({ signal: lifetime.signal, configuration })
          profileId = loaded.profileId
          openSession = loaded.openSession
          ownerOptions = loaded.ownerOptions ?? {}
        }
        if (profileId === undefined || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(profileId) || openSession === undefined) {
          throw new Error('OWNER_CONFIGURATION_INVALID')
        }
      })
    void configPromise.catch(() => {})
    return configPromise
  }
  if (options.load === undefined) void resolveConfig(undefined)

  const ensureOpen = (configuration: unknown, transferredPort: MessagePort | null): Promise<ApplicationSessionOwner> => {
    if (opening !== undefined) return opening
    opening = (async () => {
      await resolveConfig(configuration)
      lifetime.signal.throwIfAborted()
      try {
        owned = await openSession!({
          signal: lifetime.signal,
          initialNetworkActive: latestNetworkActive !== false,
        })
        lifetime.signal.throwIfAborted()
        owner = createApplicationOwner(
          owned.session,
          owned.extensions !== undefined ? { ...ownerOptions, extensions: owned.extensions } : ownerOptions,
        )
        if (transferredPort !== null) {
          appPort = transferredPort
          appPort.start()
          owner.attach(appPort)
        }
        if (typeof globalThis.BroadcastChannel === 'function' && profileId !== undefined) {
          syncChannel = new BroadcastChannel(`${ns}:sync:${profileId}`)
          syncChannel.addEventListener('message', (event: MessageEvent) => {
            const data = event.data as { sender?: string; type?: string } | null
            if (closed || data === null || data.sender === workerId || data.type !== 'facts-updated') return
            syncingFromStore = true
            void owned?.session.syncFromStore().catch(() => {}).finally(() => { syncingFromStore = false })
          })
          stopFacts = owned.session.onFacts(() => {
            if (closed || syncingFromStore) return
            try { syncChannel?.postMessage({ type: 'facts-updated', sender: workerId }) } catch { /* ignore */ }
          })
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

  const handleControl = async (data: Record<string, unknown>, ports: readonly MessagePort[]): Promise<void> => {
    if (data.type === 'boot') {
      try {
        await resolveConfig(data.configuration)
        if (data.profileId !== profileId) throw new Error('INVALID_PROFILE')
        const activeOwner = await ensureOpen(data.configuration, ports[0] ?? null)
        post({ protocol, type: 'ready', id: data.id, profileId, ownerInstanceId: activeOwner.ownerInstanceId })
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        post({ protocol, type: 'failure', id: data.id, code: msg, message: msg })
      }
      return
    }
    if (data.type === 'network-role') {
      latestNetworkActive = Boolean(data.active)
      try { owned?.setNetworkActive?.(latestNetworkActive) } catch { /* ignore */ }
      return
    }
    if (data.type === 'retire') {
      try { await close() }
      finally { post({ protocol, type: 'retired', id: data.id, profileId }) }
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
      try { await owner?.close() } catch { /* ignore */ }
      try { await owned?.close?.() } catch { /* ignore */ }
      try { await owned?.session.close() } catch { /* ignore */ }
      owner = undefined; owned = undefined; syncChannel = undefined; appPort = undefined
    })()
    return closing
  }

  return Object.freeze({
    get owner() { return owner },
    close,
  })
}

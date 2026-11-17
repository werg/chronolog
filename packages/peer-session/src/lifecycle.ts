import { createHttpWebRtcSignaling, supervisePeerSession, type PeerDescription, type PeerSessionRetry,
  type PeerSignaling, type RtcPeerConnection, type WebRtcOptions } from '@chronolog/transport-webrtc'
import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationPeerAvailability, ApplicationSession, SessionStatus } from './session.js'
import type { ApplicationPeerConnection } from './network.js'
import { connectApplicationWebRtc } from './webrtc.js'
import { connectWorkerApplicationWebRtc, type ApplicationWorkerEndpoint } from './worker-transport.js'
import type { WorkerApplicationSession } from './worker-application.js'

export type ApplicationPeerRoute = { readonly kind: 'https'; readonly url: string }
  | { readonly kind: 'rendezvous'; readonly channel: string }
  | { readonly kind: 'invitation'; readonly peerId: string }
export interface ApplicationPeerAdvertisement extends Omit<ApplicationPeerAvailability, 'profiles'> {
  readonly profiles: readonly string[]
  readonly routes: readonly ApplicationPeerRoute[]
}
export interface ApplicationPeerLease {
  readonly advertisement: ApplicationPeerAdvertisement
  readonly expiresAt: number
  readonly refreshAfter: number
}
interface InvitationListener {
  readonly ready: Promise<unknown>
  readonly invitations: AsyncIterable<{ readonly channel: string; readonly requesterPeerId: string }>
  readonly closed: Promise<unknown>
  close(): void | Promise<void>
}
interface Rendezvous extends PeerSignaling { readonly ready: Promise<{ readonly role: 'offerer' | 'answerer' }> }

/** Structural match for Tendriller's bounded discovery/control ports; no application command proxy. */
export interface ApplicationPeerHost extends ApplicationControlHost {
  discover(): Promise<{ readonly applicationId: string; readonly peers: readonly ApplicationPeerLease[] }>
  advertise(value: ApplicationPeerAdvertisement, options?: { readonly ttlMs?: number }): Promise<ApplicationPeerLease>
  withdraw(peerId: string): Promise<void>
  listenInvitations(peerId: string, options?: { readonly signal?: AbortSignal }): InvitationListener
  invite(peerId: string, value: { readonly channel: string; readonly requesterPeerId: string }): Promise<unknown>
  rendezvous(channel: string, peerId: string, options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number }): Rendezvous
}
export interface ApplicationNetworkOptions {
  readonly host: ApplicationPeerHost
  readonly configuration?: RTCConfiguration
  readonly createPeerConnection?: (configuration: RTCConfiguration) => RtcPeerConnection
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
  readonly retry?: PeerSessionRetry
  /** Availability renewal is coarse and independent of command volume. Defaults to ten minutes. */
  readonly advertisementTtlMs?: number
  readonly routes?: readonly ApplicationPeerRoute[]
  readonly recovery?: false | { readonly graceMs?: number; readonly cooldownMs?: number }
}
export interface ApplicationNetworkStatus {
  readonly phase: 'joining' | 'connected' | 'waiting' | 'closed'
  readonly invitationListener: 'connecting' | 'listening' | 'stopped'
  readonly activePeers: number
  readonly discoveryRequests: number
  readonly availabilityUpdates: number
  readonly takeoverRequests: number
  readonly lastError: string | null
}
export interface ApplicationNetwork {
  /** Current application readiness; a selected coordinator can be ready without another peer. */
  readonly ready: Promise<void>
  readonly signal: AbortSignal
  readonly status: ApplicationNetworkStatus
  onStatus(listener: (status: ApplicationNetworkStatus) => void): () => void
  /** Explicit restart after a bounded reconnect budget was exhausted. */
  reconnect(): Promise<void>
  close(): Promise<void>
}

const DEFAULT_RETRY: PeerSessionRetry = { initialDelayMs: 500, maxDelayMs: 5_000, maxAttempts: 8, jitter: 0.2, resetAfterMs: 30_000 }

/**
 * The supported native/in-thread lifecycle: invitations, coarse advertisements,
 * bounded reconnect, peer catch-up and permitted takeover. Healthy command paths
 * never consult the host; availability failures cannot stop an existing link.
 */
export function maintainApplicationWebRtc(session: ApplicationSession, options: ApplicationNetworkOptions): ApplicationNetwork {
  return maintain({ session, connect: rtc => connectApplicationWebRtc(session, rtc),
    takeover: transitionId => session.recovery.takeover(options.host, { transitionId }) }, options)
}

/** The page owns ICE; the Worker owns identity, commands, history, key enrollment and recovery. */
export function maintainWorkerApplicationWebRtc(session: WorkerApplicationSession, worker: ApplicationWorkerEndpoint,
  options: ApplicationNetworkOptions): ApplicationNetwork {
  return maintain({ session, connect: rtc => connectWorkerApplicationWebRtc(worker, rtc),
    takeover: transitionId => session.recovery.takeover({ transitionId }) }, options)
}

interface NetworkOwner {
  readonly session: Pick<ApplicationSession, 'applicationId' | 'deviceId' | 'storageId' | 'signal' | 'status' | 'onStatus' | 'adopt' | 'availability'>
  connect(options: WebRtcOptions & { readonly expectedPeerId: string }): Promise<ApplicationPeerConnection>
  takeover(transitionId: string): Promise<unknown>
}

function maintain(owner: NetworkOwner, options: ApplicationNetworkOptions): ApplicationNetwork {
  const { session } = owner
  const { host } = options, retry = options.retry ?? DEFAULT_RETRY, timeoutMs = options.timeoutMs ?? 30_000
  const ttlMs = options.advertisementTtlMs ?? 600_000, graceMs = options.recovery === false ? Infinity : options.recovery?.graceMs ?? 3_000
  const cooldownMs = options.recovery === false ? Infinity : options.recovery?.cooldownMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000 || !Number.isSafeInteger(ttlMs) || ttlMs < 30_000 || ttlMs > 600_000 ||
      graceMs !== Infinity && (!Number.isSafeInteger(graceMs) || graceMs < 250 || graceMs > 60_000) ||
      cooldownMs !== Infinity && (!Number.isSafeInteger(cooldownMs) || cooldownMs < graceMs || cooldownMs > 3_600_000) ||
      options.routes !== undefined && options.routes.length > 3) throw new Error('APPLICATION_NETWORK_OPTIONS_INVALID')
  const lifetime = new AbortController(), inputSignal = options.signal === undefined ? session.signal : AbortSignal.any([session.signal, options.signal])
  const peers = new Map<string, ApplicationPeerConnection>(), pending = new Set<string>(), observers = new Set<(state: ApplicationNetworkStatus) => void>()
  const incoming = new Set<Promise<void>>()
  let closed = false, phase: ApplicationNetworkStatus['phase'] = 'joining', invitationState: ApplicationNetworkStatus['invitationListener'] = 'connecting'
  let discoveryRequests = 0, availabilityUpdates = 0, takeoverRequests = 0, lastError: string | null = null
  let joinTask: Promise<void> | undefined, closing: Promise<void> | undefined, missedSince = Date.now(), lastTakeover = -Infinity
  let wasReady = session.status.phase === 'ready'
  let generation = session.status.generation
  let resolveReady!: () => void, rejectReady!: (reason: unknown) => void
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject }); void ready.catch(() => undefined)
  const status = (): ApplicationNetworkStatus => ({ phase, invitationListener: invitationState, activePeers: peers.size,
    discoveryRequests, availabilityUpdates, takeoverRequests, lastError })
  const publish = (): void => { const current = status(); for (const observer of observers) { try { observer(current) } catch { /* Isolate observers. */ } } }
  const failure = (error: unknown): void => { lastError = error instanceof Error ? error.message : 'APPLICATION_NETWORK_FAILED'; publish() }
  const open = (): void => { lifetime.signal.throwIfAborted() }
  const isReady = (): boolean => session.status.phase === 'ready'
  const call = <T>(promise: Promise<T>): Promise<T> => interrupted(promise, AbortSignal.any([lifetime.signal, AbortSignal.timeout(timeoutMs)]))
  const rtcOptions = (signal: AbortSignal): Pick<WebRtcOptions, 'configuration' | 'createPeerConnection' | 'timeoutMs' | 'signal'> => ({
    signal, timeoutMs, ...(options.configuration === undefined ? {} : { configuration: options.configuration }),
    ...(options.createPeerConnection === undefined ? {} : { createPeerConnection: options.createPeerConnection }),
  })
  const add = (link: ApplicationPeerConnection): void => {
    open()
    const previous = peers.get(link.peerId)
    if (previous !== undefined && previous !== link) { void link.close(); return }
    peers.set(link.peerId, link)
    const removed = (): void => {
      if (peers.get(link.peerId) === link) peers.delete(link.peerId)
      publish()
      if (!closed && !isReady()) void join().catch(failure)
    }
    link.signal.addEventListener('abort', removed, { once: true })
    if (link.signal.aborted) removed()
    else publish()
  }
  const negotiated = async (expectedPeerId: string, signaling: Rendezvous, signal: AbortSignal): Promise<ApplicationPeerConnection> => {
    try {
      const role = (await interrupted(signaling.ready, signal)).role
      const link = await owner.connect({ ...rtcOptions(signal), role, signaling, expectedPeerId })
      if (signal.aborted || closed) { await link.close(); signal.throwIfAborted(); open() }
      return link
    } catch (error) { await signaling.close(); throw error }
  }
  const accept = async (invitation: { readonly channel: string; readonly requesterPeerId: string }, signal: AbortSignal): Promise<void> => {
    if (pending.size >= 4 || peers.size >= 4 || peers.has(invitation.requesterPeerId) || pending.has(invitation.requesterPeerId)) return
    if (!/^[0-9a-f]{64}$/u.test(invitation.requesterPeerId) || invitation.requesterPeerId === session.deviceId) return
    pending.add(invitation.requesterPeerId)
    signal.throwIfAborted()
    const signaling = host.rendezvous(invitation.channel, session.deviceId, { signal: lifetime.signal, timeoutMs })
    try { add(await negotiated(invitation.requesterPeerId, signaling, lifetime.signal)) }
    finally { pending.delete(invitation.requesterPeerId) }
  }

  const openAvailability = () => supervisePeerSession({ readiness: 'transport', signal: lifetime.signal, retry,
    onState(state) { invitationState = state.phase === 'connected' ? 'listening' : state.phase === 'stopped' ? 'stopped' : 'connecting'; publish() },
    connect: async signal => {
      const listener = host.listenInvitations(session.deviceId, { signal }), controller = new AbortController()
      let refreshTimer: ReturnType<typeof setTimeout> | undefined, stopped = false
      const stop = async (): Promise<void> => {
        if (stopped) return
        stopped = true; clearTimeout(refreshTimer); signal.removeEventListener('abort', abort)
        controller.abort(new Error('APPLICATION_INVITATION_LISTENER_CLOSED')); await listener.close()
      }
      const abort = (): void => { void stop() }
      signal.addEventListener('abort', abort, { once: true })
      void listener.closed.then(() => { void stop() }, () => { void stop() })
      const refresh = async (): Promise<void> => {
        signal.throwIfAborted(); open()
        const metadata = await session.availability()
        signal.throwIfAborted(); availabilityUpdates++; publish()
        const lease = await call(host.advertise({ ...metadata,
          routes: [{ kind: 'invitation', peerId: session.deviceId }, ...(options.routes ?? [])] }, { ttlMs }))
        signal.throwIfAborted()
        const delay = Math.max(15_000, Math.min(ttlMs, lease.refreshAfter - Date.now()))
        refreshTimer = setTimeout(() => { void refresh().catch(error => { failure(error); void stop() }) }, delay)
      }
      try {
        await interrupted(listener.ready, signal); await refresh()
        void (async () => {
          try { for await (const invitation of listener.invitations) {
            signal.throwIfAborted()
            const task = accept(invitation, signal).catch(failure)
            incoming.add(task); void task.finally(() => { incoming.delete(task) })
          } }
          catch (error) { if (!signal.aborted) failure(error) }
          finally { await stop() }
        })().catch(() => undefined)
        return { signal: controller.signal, close: stop }
      } catch (error) { await stop(); throw error }
    },
  })
  let availability = openAvailability()
  void availability.completion.catch(failure)

  const connect = async (advertisement: ApplicationPeerAdvertisement): Promise<void> => {
    const peerId = advertisement.peerId
    if (peers.has(peerId) || pending.has(peerId) || peers.size + pending.size >= 4) return
    pending.add(peerId)
    try {
      for (const route of advertisement.routes) {
        open()
        const signal = lifetime.signal
        try {
          let link: ApplicationPeerConnection
          if (route.kind === 'https') {
            const signaling = createHttpWebRtcSignaling({ url: route.url, signal, timeoutMs })
            link = await owner.connect({ ...rtcOptions(signal), role: 'offerer', signaling, expectedPeerId: peerId })
          } else {
            if (route.kind === 'invitation' && route.peerId !== peerId) throw new Error('APPLICATION_PEER_ROUTE_MISMATCH')
            const channel = route.kind === 'rendezvous' ? route.channel : `join-${crypto.randomUUID()}`
            const signaling = host.rendezvous(channel, session.deviceId, { signal, timeoutMs })
            try {
              if (route.kind === 'invitation') await call(host.invite(peerId, { channel, requesterPeerId: session.deviceId }))
              link = await negotiated(peerId, signaling, signal)
            } catch (error) { await signaling.close(); throw error }
          }
          add(link); return
        } catch (error) { failure(error) }
      }
    } finally { pending.delete(peerId) }
  }
  const join = (): Promise<void> => {
    open()
    if (joinTask !== undefined) return joinTask
    const task = (async () => {
      phase = 'joining'; publish()
      for (let attempt = 0; attempt < retry.maxAttempts; attempt++) {
        open()
        try {
          const bundle = await call(host.application()); open()
          try { await session.adopt(bundle) }
          catch (error) { if (!(error instanceof Error) || error.message !== 'PEER_RECOVERY_PREFIX_INCOMPLETE') throw error }
          open()
          discoveryRequests++; publish()
          const directory = await call(host.discover()); open()
          if (directory.applicationId !== session.applicationId || !Array.isArray(directory.peers) || directory.peers.length > 64) throw new Error('APPLICATION_PEER_DIRECTORY_INVALID')
          const selected = session.status.coordinator
          const candidates = (directory.peers as readonly ApplicationPeerLease[]).filter(lease => lease.expiresAt > Date.now() && lease.advertisement.peerId !== session.deviceId &&
            lease.advertisement.profiles.includes('peer-generation-v1') && /^[0-9a-f]{64}$/u.test(lease.advertisement.peerId))
          candidates.sort((a, b) => Number(b.advertisement.peerId === selected) - Number(a.advertisement.peerId === selected) ||
            Number(b.advertisement.recovery?.generation === generation) - Number(a.advertisement.recovery?.generation === generation) ||
            (b.advertisement.recovery?.sequence ?? 0) - (a.advertisement.recovery?.sequence ?? 0) || a.advertisement.peerId.localeCompare(b.advertisement.peerId))
          for (const candidate of candidates.slice(0, 4)) { await connect(candidate.advertisement); if (isReady()) break }
          if (isReady()) { phase = 'connected'; lastError = null; resolveReady(); publish(); return }
          const now = Date.now()
          if (options.recovery !== false && now - missedSince >= graceMs && now - lastTakeover >= cooldownMs && session.status.phase === 'waiting') {
            lastTakeover = now; takeoverRequests++; publish()
            await call(owner.takeover(`takeover-${session.deviceId.slice(0, 16)}-${session.status.generation}`))
            if (isReady()) { phase = 'connected'; resolveReady(); publish(); return }
          }
        } catch (error) {
          if (lifetime.signal.aborted) throw lifetime.signal.reason
          failure(error)
          if (isReady()) { phase = 'connected'; resolveReady(); publish(); return }
        }
        if (attempt + 1 < retry.maxAttempts) {
          const base = Math.min(retry.maxDelayMs, retry.initialDelayMs * 2 ** attempt), jitter = retry.jitter ?? 0.2
          await pause(Math.max(1, Math.round(base * (1 + jitter * (Math.random() * 2 - 1)))), lifetime.signal)
        }
      }
      phase = 'waiting'; publish()
      const error = new Error(lastError ?? 'APPLICATION_NETWORK_RECONNECT_EXHAUSTED')
      rejectReady(error); throw error
    })()
    joinTask = task
    void task.then(() => { if (joinTask === task) joinTask = undefined }, () => { if (joinTask === task) joinTask = undefined })
    return task
  }
  const changed = (state: SessionStatus): void => {
    if (state.generation !== generation) { generation = state.generation; missedSince = Date.now() }
    if (state.phase === 'ready') { phase = 'connected'; missedSince = Date.now(); resolveReady(); publish() }
    else if (!closed) {
      if (wasReady) missedSince = Date.now()
      phase = 'waiting'; publish(); void Promise.resolve().then(join).catch(failure)
    }
    wasReady = state.phase === 'ready'
  }
  const stopStatus = session.onStatus(changed)
  const close = (): Promise<void> => {
    if (closing !== undefined) return closing
    const active = [...peers.values()], accepting = [...incoming], joining = joinTask
    closing = Promise.resolve().then(async () => {
      await Promise.allSettled([availability.close(), ...active.map(link => link.close()), ...accepting, joining])
    })
    closed = true; phase = 'closed'; lifetime.abort(new Error('APPLICATION_NETWORK_CLOSED')); rejectReady(lifetime.signal.reason)
    inputSignal.removeEventListener('abort', abort); stopStatus(); publish(); observers.clear()
    void host.withdraw(session.deviceId).catch(() => undefined)
    return closing
  }
  const abort = (): void => { void close() }
  inputSignal.addEventListener('abort', abort, { once: true })
  if (inputSignal.aborted) abort()
  else void join().catch(failure)
  return { ready, signal: lifetime.signal, get status() { return status() },
    onStatus(listener) { observers.add(listener); try { listener(status()) } catch { /* Isolate observers. */ } return () => { observers.delete(listener) } },
    async reconnect() {
      open()
      if (availability.state.phase === 'stopped') { availability = openAvailability(); void availability.completion.catch(failure) }
      await join()
    }, close }
}

function interrupted<T>(value: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void value.catch(() => undefined); return Promise.reject(signal.reason) }
  return new Promise((resolve, reject) => {
    const abort = (): void => { reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
    void value.then(resolve, reject).finally(() => { signal.removeEventListener('abort', abort) })
  })
}
function pause(milliseconds: number, signal: AbortSignal): Promise<void> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = (): void => { clearTimeout(timer); reject(signal.reason) }
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve() }, milliseconds)
    signal.addEventListener('abort', abort, { once: true })
  })
}
// Keep the host signaling contract structural across native and browser SDK artifacts.
export type { PeerDescription }

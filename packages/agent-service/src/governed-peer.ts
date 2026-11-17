import { createCapabilitySignals, isCapabilityActive, type CapabilitySnapshot } from '@chronolog/capabilities'
import { bytesToHex, equalBytes, type Ed25519KeyPair } from '@chronolog/protocol'
import type { FeedLink } from '@chronolog/records'
import type { SignalLimits, SignalRoute, Signals } from '@chronolog/signals'
import { SignalBackpressureError } from '@chronolog/signals'

import type { FramedPeerConnection } from './framing.js'
import { openAuthenticatedPeerLink, type PeerAuthorization } from './peer-link.js'

export interface GovernedPeerSession {
  readonly peer: PeerAuthorization
  readonly signal: AbortSignal
  readonly completion: Promise<void>
  close(): Promise<void>
}
export interface GovernedPeerService {
  readonly signals: Signals
  connectPeer(options: GovernedPeerConnectionOptions): Promise<GovernedPeerSession>
  close(): Promise<void>
}
export interface GovernedPeerConnectionOptions { readonly connection: FramedPeerConnection; readonly peerIdentity?: Uint8Array }

/**
 * One replica's live routes. Membership authorizes the current connection and
 * publisher; it neither advances nor depends on application finality.
 */
export async function createGovernedPeerService(options: {
  readonly identity: Ed25519KeyPair
  readonly groupId: Uint8Array
  readonly activeMembership: () => CapabilitySnapshot
  readonly local: FeedLink
  readonly attach: (link: FeedLink) => () => void
  readonly signalLimits?: SignalLimits
}): Promise<GovernedPeerService> {
  if (!(options.groupId instanceof Uint8Array) || options.groupId.length !== 32) throw new Error('PEER_GROUP_INVALID')
  const groupId = options.groupId.slice(), identity = { ...options.identity, publicKeyBytes: options.identity.publicKeyBytes.slice() }
  const lifetime = new AbortController(), openings = new Map<FramedPeerConnection, number>()
  const sessions = new Map<string, GovernedPeerSession>()
  const accepted = new Map<string, number>()
  let nextOpening = 0
  const pruneAttempts = (): void => {
    const oldest = Math.min(...openings.values())
    for (const [feed, attempt] of accepted) if (!sessions.has(feed) && attempt < oldest) accepted.delete(feed)
  }
  const current = (): CapabilitySnapshot => {
    const snapshot = options.activeMembership()
    if (!equalBytes(snapshot.groupId, groupId)) throw new Error('PEER_GROUP_MISMATCH')
    return snapshot
  }
  const signals = createCapabilitySignals({ ...options.signalLimits, groupId, identity, current, relay: true })
  return {
    signals,
    async connectPeer(input) {
      if (lifetime.signal.aborted) { await input.connection.close(); throw new Error('PEER_SERVICE_CLOSED') }
      if (openings.has(input.connection)) throw new Error('PEER_CONNECTION_ALREADY_OPEN')
      if (openings.size >= 64 || nextOpening >= Number.MAX_SAFE_INTEGER) {
        await input.connection.close(); throw new Error('PEER_OPENING_QUOTA_EXCEEDED')
      }
      const peerIdentity = input.peerIdentity?.slice()
      if (peerIdentity !== undefined && peerIdentity.length !== 32) { await input.connection.close(); throw new Error('PEER_IDENTITY_INVALID') }
      const { connection } = input
      const attempt = ++nextOpening
      openings.set(connection, attempt)
      let resolveRoute!: (route: SignalRoute | undefined) => void, rejectRoute!: (error: unknown) => void
      const routeReady = new Promise<SignalRoute | undefined>((resolve, reject) => { resolveRoute = resolve; rejectRoute = reject })
      void routeReady.catch(() => undefined)
      let raw: Awaited<ReturnType<typeof openAuthenticatedPeerLink>> | undefined
      let route: SignalRoute | undefined, detach: (() => void) | undefined
      try {
        const snapshot = current()
        const reader = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
          capability.grant.transportAuthor === options.local.identity && isCapabilityActive(capability, snapshot.revision) &&
          equalBytes(capability.grant.signingPublicKey, identity.publicKeyBytes))
        if (reader === undefined) throw new Error('PEER_LOCAL_READER_GRANT_REQUIRED')
        raw = await openAuthenticatedPeerLink({ connection, local: options.local, identity, groupId, grantId: reader.id,
          authorizePeer: peer => {
            if (lifetime.signal.aborted || (peerIdentity !== undefined && !equalBytes(peerIdentity, peer.authorId))) return false
            const active = current(), capability = active.capabilities.get(bytesToHex(peer.grantId))
            return capability !== undefined && capability.grant.role === 'reader' && isCapabilityActive(capability, active.revision) &&
              capability.grant.transportAuthor === peer.feedId && equalBytes(capability.grant.signingPublicKey, peer.authorId)
          },
          receiveSignal: async frame => { await (await routeReady)?.receive(frame) },
        })
        if (lifetime.signal.aborted) throw new Error('PEER_SERVICE_CLOSED')
        if ((accepted.get(raw.peer.feedId) ?? 0) > attempt) throw new Error('PEER_CONNECTION_SUPERSEDED')
        if (!accepted.has(raw.peer.feedId) && accepted.size >= 1024) throw new Error('PEER_SESSION_QUOTA_EXCEEDED')
        const authenticated = raw, controller = new AbortController()
        let closed = false
        const dispose = (): void => {
          if (closed) return
          closed = true; controller.abort(); route?.close(); detach?.()
          if (sessions.get(authenticated.peer.feedId) === session) sessions.delete(authenticated.peer.feedId)
          pruneAttempts()
        }
        const close = async (): Promise<void> => { dispose(); await authenticated.close() }
        if (connection.live !== undefined) route = signals.attachRoute({ close, async send(frame, { signal }) {
          signal.throwIfAborted()
          try {
            const active = current(), localReader = active.capabilities.get(bytesToHex(reader.id))
            if (localReader === undefined || !isCapabilityActive(localReader, active.revision)) throw new Error('PEER_LOCAL_READER_GRANT_REQUIRED')
            return await authenticated.sendSignal(frame, { signal })
          } catch (error) {
            if (!signal.aborted && !SignalBackpressureError.is(error)) void close().catch(() => undefined)
            throw error
          }
        } })
        detach = options.attach(authenticated.link)
        const completion = authenticated.completion.finally(dispose)
        void completion.catch(() => undefined)
        const session: GovernedPeerSession = { peer: authenticated.peer, signal: controller.signal, completion, close }
        const previous = sessions.get(authenticated.peer.feedId)
        accepted.set(authenticated.peer.feedId, attempt)
        sessions.set(authenticated.peer.feedId, session)
        if (previous !== undefined) void previous.close().catch(() => undefined)
        resolveRoute(route)
        return session
      } catch (error) {
        rejectRoute(error); route?.close(); detach?.()
        try { if (raw === undefined) await connection.close(); else await raw.close() } catch { /* Preserve the opening failure. */ }
        throw error
      } finally { openings.delete(connection); pruneAttempts() }
    },
    async close() {
      if (lifetime.signal.aborted) return
      lifetime.abort(); signals.close()
      await Promise.allSettled([...openings.keys()].map(connection => connection.close()).concat([...sessions.values()].map(session => session.close())))
      sessions.clear(); openings.clear(); accepted.clear()
    },
  }
}

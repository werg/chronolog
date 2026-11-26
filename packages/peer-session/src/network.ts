import type { ApplicationSession, SessionCasNode, SessionFacts } from './session.js'
import type { FramedPeerConnection } from '@chronolog/records'
import type {
  InBandSignalingHandle, InBandSignalingOptions, PeerMediaController,
  PeerStreamsController, RtcSignalMessage, WebRtcSession,
} from '@chronolog/transport-webrtc'
import { bytesToHex, sha256Sync } from '@chronolog/canonical'
import { decodeOperationCore, decodeSignedOperation, encryptedEnvelopeDigest, operationIdDigest } from '@chronolog/protocol'
import { check, signRecord, verifyRecord, type Signed } from '@chronolog/authority'
import { createNetworkContent, type ContentWireMessage } from './network-content.js'
import { ApplicationSecureChannel, type ApplicationChannelHello } from './secure-channel.js'
import type { SignalRoute, SignalReceiveDiagnostics } from '@chronolog/signals'
import { APPLICATION_NETWORK_LIMITS, ApplicationMessageWire } from './network-wire.js'
import { PeerFactKnowledge } from './network-facts.js'

export interface PeerLinkTransportCapabilities {
  readonly session?: WebRtcSession
  attachInBandSignaling?(options: InBandSignalingOptions & { readonly peerId: string }): InBandSignalingHandle
}

export interface ApplicationPeerConnectOptions {
  readonly connection: FramedPeerConnection & PeerLinkTransportCapabilities
  readonly peerIdentity?: string
  readonly signal?: AbortSignal
  readonly handshakeTimeoutMs?: number
}

export interface ApplicationPeerLiveDiagnostics {
  readonly sentLiveBytes: number
  readonly receivedLiveBytes: number
  readonly signalRejections: SignalReceiveDiagnostics
}

export interface ApplicationPeerLinkStats extends Partial<ApplicationPeerLiveDiagnostics> {
  readonly sentBytes: number
  readonly receivedBytes: number
}

export interface ApplicationPeerLink {
  readonly peerIdentity: string
  readonly transportKind: 'direct' | 'relay'
  readonly media: PeerMediaController
  readonly streams: PeerStreamsController
  readonly signal: AbortSignal
  readonly completion: Promise<void>
  readonly stats: ApplicationPeerLinkStats
  synchronize(): Promise<void>
  close(): Promise<void>
}

export interface ApplicationPeerDiagnostics extends Partial<ApplicationPeerLiveDiagnostics> {
  readonly connectionId: string
  readonly peerId: string
  readonly kind: 'unknown'
  readonly sentReliableBytes: number
  readonly receivedReliableBytes: number
}

const tracked = new WeakMap<ApplicationSession, Map<string, () => ApplicationPeerDiagnostics>>()
const activeLinks = new WeakMap<ApplicationSession, Map<string, ApplicationPeerLink>>()
const linkListeners = new WeakMap<ApplicationSession, Set<(event: { readonly type: 'connected' | 'disconnected'; readonly link: ApplicationPeerLink }) => void>>()

export function applicationPeerDiagnostics(session: ApplicationSession): readonly ApplicationPeerDiagnostics[] {
  return [...(tracked.get(session)?.values() ?? [])].map(snapshot => snapshot())
}

export function applicationPeerLinks(session: ApplicationSession): readonly ApplicationPeerLink[] {
  return [...(activeLinks.get(session)?.values() ?? [])]
}

export function onApplicationPeerLink(
  session: ApplicationSession,
  listener: (event: { readonly type: 'connected' | 'disconnected'; readonly link: ApplicationPeerLink }) => void,
): () => void {
  let set = linkListeners.get(session)
  if (!set) linkListeners.set(session, set = new Set())
  set.add(listener)
  for (const link of applicationPeerLinks(session)) {
    try { listener({ type: 'connected', link }) } catch { /* Isolate observer errors. */ }
  }
  return () => { set.delete(listener) }
}

const unavailableMedia: PeerMediaController = Object.freeze({
  available: false,
  unavailableReason: 'relay',
  addTrack() { throw new Error('WEBRTC_MEDIA_UNAVAILABLE') },
  removeTrack() { throw new Error('WEBRTC_MEDIA_UNAVAILABLE') },
  addTransceiver() { throw new Error('WEBRTC_MEDIA_UNAVAILABLE') },
  getTransceivers() { return [] },
  onTrack() { return () => {} },
  async restartIce() { throw new Error('WEBRTC_MEDIA_UNAVAILABLE') },
})

const unavailableStreams: PeerStreamsController = Object.freeze({
  available: false,
  unavailableReason: 'relay',
  open() { throw new Error('WEBRTC_STREAMS_UNAVAILABLE') },
  onStream() { return () => {} },
})

interface Hello {
  readonly applicationId: string
  readonly nonce: string
  readonly publicOps: readonly Uint8Array[]
  readonly casNodes: readonly SessionCasNode[]
  readonly channel: ApplicationChannelHello
}
interface Proof {
  readonly applicationId: string
  readonly localNonce: string
  readonly peerNonce: string
  readonly encapsulatedKey: string
}
type Message =
  | { readonly kind: 'hello'; readonly value: Signed<Hello> }
  | { readonly kind: 'proof'; readonly value: Signed<Proof> }
  | { readonly kind: 'facts'; readonly requestId: string; readonly facts: SessionFacts }
  | { readonly kind: 'ack'; readonly requestId: string }
  | { readonly kind: 'content'; readonly message: ContentWireMessage }
  | { readonly kind: 'rtc'; readonly message: RtcSignalMessage }

/** Physical feed counters only protect framing. Every operation authenticates its own immutable authored order. */
export async function connectApplicationPeer(session: ApplicationSession, options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
  check(session.status.connectedPeers < APPLICATION_NETWORK_LIMITS.peers, 'SESSION_PEER_LIMIT')
  const lifetime = new AbortController()
  const signal = AbortSignal.any([lifetime.signal, session.signal, options.connection.signal, ...(options.signal === undefined ? [] : [options.signal])])
  const secure = new ApplicationSecureChannel(options.connection, signal)
  const wire = new ApplicationMessageWire(secure.connection, signal, options.handshakeTimeoutMs ?? 30_000)
  const iterator = wire.messages()[Symbol.asyncIterator]()
  const localNonce = crypto.randomUUID(), connectionId = crypto.randomUUID()
  const timeout = setTimeout(() => lifetime.abort(new Error('PEER_HANDSHAKE_TIMEOUT')), options.handshakeTimeoutMs ?? 30_000)

  let authenticated = false
  let stopping: Promise<void> | undefined
  let stopFacts: (() => void) | undefined
  let signalRoute: SignalRoute | undefined
  let contentLink: ReturnType<typeof createNetworkContent> | undefined
  let inBandRtc: InBandSignalingHandle | undefined
  let createdLink: ApplicationPeerLink | undefined
  let sentLiveBytes = 0, receivedLiveBytes = 0
  const liveDiagnostics = (): Partial<ApplicationPeerLiveDiagnostics> =>
    signalRoute === undefined ? {} : { sentLiveBytes, receivedLiveBytes, signalRejections: signalRoute.diagnostics }
  const pending = new Map<string, { resolve(): void; reject(error: unknown): void; timer: ReturnType<typeof setTimeout> }>()

  const close = (): Promise<void> => stopping ??= (async () => {
    lifetime.abort(new Error('PEER_CLOSED'))
    stopFacts?.(); signalRoute?.close(); contentLink?.close(); inBandRtc?.close(); secure.clear()
    for (const value of pending.values()) { clearTimeout(value.timer); value.reject(signal.reason) }
    pending.clear()
    if (authenticated) {
      authenticated = false
      tracked.get(session)?.delete(connectionId)
      if (createdLink) {
        const links = activeLinks.get(session)
        if (links?.get(connectionId) === createdLink) links.delete(connectionId)
        for (const listener of linkListeners.get(session) ?? []) {
          try { listener({ type: 'disconnected', link: createdLink }) } catch { /* Isolate observer errors. */ }
        }
      }
      session.setConnectedPeers(tracked.get(session)?.size ?? 0)
    }
    await options.connection.close()
    void iterator.return?.()
  })()

  signal.addEventListener('abort', () => { void close().catch(() => undefined) }, { once: true })

  try {
    const publicControl = await session.exportPublicControlFacts()
    await wire.send({
      kind: 'hello',
      value: await signRecord('peer-hello', {
        applicationId: session.applicationId,
        nonce: localNonce,
        publicOps: publicControl.publicOps,
        casNodes: publicControl.casNodes,
        channel: await secure.hello(),
      }, session.device.identity),
    } satisfies Message)

    const next = await iterator.next(); check(!next.done, 'PEER_HELLO_MISSING')
    const hello = next.value as Message; check(hello.kind === 'hello', 'PEER_HELLO_INVALID')
    await verifyRecord('peer-hello', hello.value)
    check(
      hello.value.payload.applicationId === session.applicationId &&
      typeof hello.value.payload.nonce === 'string' &&
      hello.value.payload.nonce.length <= 128 &&
      (options.peerIdentity === undefined || options.peerIdentity === hello.value.signer),
      'PEER_SCOPE_MISMATCH',
    )

    // Merge peer's public control facts so membership updates (admissions/revocations) apply before gating
    await session.mergeFacts({
      publicOps: hello.value.payload.publicOps,
      encryptedEnvelopes: [],
      casNodes: hello.value.payload.casNodes.filter(n => n.partition === 'public'),
      retentions: [],
      checkpoints: [],
    })
    check(session.isMember(hello.value.signer), 'PEER_MEMBER_REQUIRED')

    const localContext = { applicationId: session.applicationId, identity: session.device.identity.publicKey, nonce: localNonce }
    const peerContext = { applicationId: session.applicationId, identity: hello.value.signer, nonce: hello.value.payload.nonce }
    const encapsulatedKey = await secure.prepare(hello.value.payload.channel.receiverKey, localContext, peerContext)
    await wire.send({
      kind: 'proof',
      value: await signRecord('peer-proof', {
        applicationId: session.applicationId,
        localNonce,
        peerNonce: hello.value.payload.nonce,
        encapsulatedKey,
      }, session.device.identity),
    } satisfies Message)
    secure.enableSending()

    const proofNext = await iterator.next(); check(!proofNext.done, 'PEER_PROOF_MISSING')
    const proof = proofNext.value as Message; check(proof.kind === 'proof', 'PEER_PROOF_INVALID')
    await verifyRecord('peer-proof', proof.value, hello.value.signer)
    check(
      proof.value.payload.applicationId === session.applicationId &&
      proof.value.payload.localNonce === hello.value.payload.nonce &&
      proof.value.payload.peerNonce === localNonce,
      'PEER_PROOF_CONTEXT_INVALID',
    )
    await secure.accept(proof.value.payload.encapsulatedKey, peerContext, localContext)
    clearTimeout(timeout)

    const peerId = hello.value.signer
    const connections = tracked.get(session) ?? new Map<string, () => ApplicationPeerDiagnostics>()
    check(connections.size < APPLICATION_NETWORK_LIMITS.peers, 'SESSION_PEER_LIMIT')
    tracked.set(session, connections); authenticated = true
    connections.set(connectionId, () => ({
      connectionId,
      peerId,
      kind: 'unknown',
      sentReliableBytes: wire.stats.sentBytes,
      receivedReliableBytes: wire.stats.receivedBytes,
      ...liveDiagnostics(),
    }))
    session.setConnectedPeers(connections.size)

    const authorizeReader = (): void => {
      check(session.isReader(peerId) && session.isReader(session.device.identity.publicKey), 'RTC_FORBIDDEN')
    }
    const sendRtc = (rtcMessage: RtcSignalMessage): Promise<void> =>
      wire.send({ kind: 'rtc', message: rtcMessage } satisfies Message, authorizeReader)
    const polite = session.device.identity.publicKey < peerId
    const rtcSession = options.connection.session
    if (rtcSession !== undefined) {
      inBandRtc = rtcSession.attachInBandSignaling({ polite, send: sendRtc })
    } else if (typeof options.connection.attachInBandSignaling === 'function') {
      inBandRtc = options.connection.attachInBandSignaling({ peerId, polite, send: sendRtc })
    }
    const transportKind: 'direct' | 'relay' = rtcSession !== undefined || typeof options.connection.attachInBandSignaling === 'function' ? 'direct' : 'relay'

    if (secure.connection.live !== undefined && session.isReader(peerId)) {
      const live = secure.connection.live
      signalRoute = session.signals.attachRoute({
        async trySend(frame: Uint8Array, input: { readonly signal: AbortSignal }) {
          const accepted = await live.trySend(frame, input)
          if (accepted) sentLiveBytes = Math.min(Number.MAX_SAFE_INTEGER, sentLiveBytes + frame.length)
          return accepted
        },
      })
      void (async () => {
        try {
          for await (const frame of live.frames(signal)) {
            if (!session.isReader(peerId)) break
            receivedLiveBytes = Math.min(Number.MAX_SAFE_INTEGER, receivedLiveBytes + frame.length)
            await signalRoute?.receive(frame)
          }
        } catch { /* Independent live lane is disposable. */ }
      })()
    }

    contentLink = createNetworkContent({
      content: session.content,
      peerId,
      signal,
      authorize: () => session.isReader(peerId) && session.isReader(session.device.identity.publicKey),
      send: message => wire.send(
        { kind: 'content', message } satisfies Message,
        () => check(session.isReader(peerId) && session.isReader(session.device.identity.publicKey), 'CONTENT_FORBIDDEN'),
      ),
    })

    const knowledge = new PeerFactKnowledge()

    const retainIncoming = async (facts: SessionFacts): Promise<void> => {
      for (const raw of facts.publicOps) {
        try {
          const signed = decodeSignedOperation(raw)
          const core = decodeOperationCore(signed.coreBytes)
          const proposalId = bytesToHex(operationIdDigest(signed.coreBytes))
          await session.retain(proposalId, {
            author: bytesToHex(core.author),
            envelopeDigest: bytesToHex(sha256Sync(raw)),
          })
        } catch { /* ignore invalid */ }
      }
      for (const raw of facts.encryptedEnvelopes) {
        try {
          const envDigest = bytesToHex(encryptedEnvelopeDigest(raw))
          const inspected = session.inspectOperation(envDigest)
          if (inspected.stored) {
            await session.retain(inspected.proposalId, { author: inspected.author, envelopeDigest: envDigest })
          }
        } catch { /* ignore */ }
      }
    }

    let sendTail: Promise<void> = Promise.resolve()
    const sendFacts = (requestId = ''): Promise<void> => {
      const task = sendTail.then(async () => {
        signal.throwIfAborted()
        const allFacts = await session.exportFacts({ includePrivateCas: session.isReader(peerId) })
        const facts = await knowledge.missing(allFacts)
        const count = facts.publicOps.length + facts.encryptedEnvelopes.length + facts.casNodes.length + facts.retentions.length + facts.checkpoints.length
        if (requestId === '' && count === 0) return
        await wire.send({ kind: 'facts', requestId, facts } satisfies Message)
        await knowledge.remember(facts)
      })
      sendTail = task.catch(() => undefined)
      return task
    }

    let flushing: Promise<void> | undefined, dirty = false
    const publish = (): Promise<void> => {
      dirty = true
      return flushing ??= (async () => {
        try { while (dirty && !signal.aborted) { dirty = false; await sendFacts() } }
        finally { flushing = undefined }
      })()
    }
    stopFacts = session.onFacts(() => { void publish().catch(() => close()) })

    void (async () => {
      try {
        while (!signal.aborted) {
          const incoming = await iterator.next(); if (incoming.done) break
          const message = incoming.value as Message
          check(session.isMember(peerId), 'PEER_REVOKED')
          if (message.kind === 'facts') {
            check(typeof message.requestId === 'string' && message.requestId.length <= 128, 'PEER_REQUEST_INVALID')
            await session.mergeFacts(message.facts)
            await knowledge.remember(message.facts)
            await retainIncoming(message.facts)
            if (message.requestId !== '') await wire.send({ kind: 'ack', requestId: message.requestId } satisfies Message)
          } else if (message.kind === 'content') {
            await contentLink.handle(message.message)
          } else if (message.kind === 'rtc') {
            if (inBandRtc !== undefined && session.isReader(peerId)) {
              void inBandRtc.receive(message.message).catch(() => undefined)
            }
          } else if (message.kind === 'ack') {
            const waiter = pending.get(message.requestId)
            if (waiter !== undefined) { pending.delete(message.requestId); clearTimeout(waiter.timer); waiter.resolve() }
          } else {
            throw new Error('PEER_MESSAGE_INVALID')
          }
        }
      } catch (error) { lifetime.abort(error) }
      finally { await close() }
    })()

    await publish()
    const completion = signal.aborted ? Promise.resolve() : new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }))
    const link: ApplicationPeerLink = {
      peerIdentity: peerId,
      transportKind,
      media: rtcSession?.media ?? unavailableMedia,
      streams: rtcSession?.streams ?? unavailableStreams,
      signal,
      completion,
      get stats() { return { ...wire.stats, ...liveDiagnostics() } },
      close,
      synchronize() {
        check(!signal.aborted && pending.size < 4, 'PEER_REQUEST_LIMIT')
        const requestId = crypto.randomUUID()
        return new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => { pending.delete(requestId); reject(new Error('PEER_SYNC_TIMEOUT')); void close() }, 30_000)
          pending.set(requestId, { resolve, reject, timer })
          void sendFacts(requestId).catch(error => { clearTimeout(timer); pending.delete(requestId); reject(error); void close() })
        })
      },
    }
    createdLink = link
    let sessionLinks = activeLinks.get(session)
    if (!sessionLinks) { sessionLinks = new Map<string, ApplicationPeerLink>(); activeLinks.set(session, sessionLinks) }
    sessionLinks.set(connectionId, link)
    for (const listener of linkListeners.get(session) ?? []) {
      try { listener({ type: 'connected', link }) } catch { /* Isolate observer errors. */ }
    }
    return link
  } catch (error) {
    await close()
    throw error
  } finally {
    clearTimeout(timeout)
  }
}

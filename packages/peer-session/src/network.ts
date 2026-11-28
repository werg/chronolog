import type { ApplicationSession, FactScope, FactsDelta, SessionCasNode } from './session.js'
import type { FramedPeerConnection } from '@chronolog/records'
import type {
  InBandSignalingHandle, InBandSignalingOptions, PeerMediaController,
  PeerStreamsController, RtcSignalMessage, WebRtcSession,
} from '@chronolog/transport-webrtc'
import { bytesToHex } from '@chronolog/canonical'
import { decodeEncryptedEnvelope, decodeSignedOperation, operationIdDigest } from '@chronolog/protocol'
import { check, signRecord, verifyRecord, type Signed } from '@chronolog/authority'
import type { FinalityCheckpoint } from '@chronolog/authority'
import type { RetentionEvidence } from './operation.js'
import { reconcileRanges, type ReconcileRange } from './reconcile.js'
import { createNetworkContent, type ContentWireMessage } from './network-content.js'
import { ApplicationSecureChannel, type ApplicationChannelHello } from './secure-channel.js'
import type { SignalRoute, SignalReceiveDiagnostics } from '@chronolog/signals'
import { APPLICATION_NETWORK_LIMITS, ApplicationMessageWire, interruptible as interruptibleWait } from './network-wire.js'

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

/** Sync v3 hello: identity, freshness and key share only — facts move by reconciliation. */
interface Hello {
  readonly applicationId: string
  readonly nonce: string
  readonly channel: ApplicationChannelHello
}
interface Proof {
  readonly applicationId: string
  readonly localNonce: string
  readonly peerNonce: string
  readonly encapsulatedKey: string
}
interface WireFacts {
  readonly publicOps: readonly Uint8Array[]
  readonly encryptedEnvelopes: readonly Uint8Array[]
  readonly checkpoints: readonly FinalityCheckpoint[]
}
type Message =
  | { readonly kind: 'hello'; readonly value: Signed<Hello> }
  | { readonly kind: 'proof'; readonly value: Signed<Proof> }
  /** Reconciliation step of round `round` (owned by the side that started it). */
  | { readonly kind: 'recon'; readonly round: string; readonly scope: FactScope; readonly owner: boolean; readonly ranges: readonly ReconcileRange[] }
  /** Owner finished round `round`; the peer acks once everything sent before it is merged. */
  | { readonly kind: 'recon-end'; readonly round: string; readonly scope: FactScope }
  /** Initial reconciliation done (sent by the initiator). */
  | { readonly kind: 'ready' }
  | { readonly kind: 'want'; readonly requestId: string; readonly scope: FactScope; readonly ids: readonly string[] }
  /** Facts batch; a non-empty requestId answers a `want` (sent once, on the final batch). */
  | { readonly kind: 'facts'; readonly requestId: string; readonly facts: WireFacts }
  | { readonly kind: 'cas-want'; readonly requestId: string; readonly hashes: readonly string[]; readonly subgraph?: boolean }
  | { readonly kind: 'cas'; readonly requestId: string; readonly nodes: readonly SessionCasNode[] }
  /** Batched, signed retention receipt for facts this peer received from us. */
  | { readonly kind: 'receipt'; readonly evidence: RetentionEvidence }
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

  const close = (): Promise<void> => stopping ??= (async () => {
    lifetime.abort(new Error('PEER_CLOSED'))
    stopFacts?.(); signalRoute?.close(); contentLink?.close(); inBandRtc?.close(); secure.clear()
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
    await wire.send({
      kind: 'hello',
      value: await signRecord('peer-hello', {
        applicationId: session.applicationId,
        nonce: localNonce,
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

    // Membership is gated after the public reconciliation round (so in-flight admissions apply first);
    // until then only public facts flow on this link.

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

    const self = session.device.identity.publicKey
    const initiator = self < peerId
    // Ordered outbox: the receive loop never awaits transmission, so two peers bulk-pushing to each
    // other cannot deadlock on full transport buffers. Wire order == post order.
    let outTail: Promise<void> = Promise.resolve()
    const post = (message: Message): Promise<void> => {
      const task = outTail.then(() => wire.send(message))
      outTail = task.catch(() => undefined)
      task.catch(() => { void close() })
      return task
    }
    let memberVerified = false
    let markMember!: () => void
    const memberReady = new Promise<void>(resolve => { markMember = resolve })
    const privateAllowed = (): boolean => memberVerified && session.isReader(peerId) && session.isReader(self)
    const verifyMember = (): void => {
      if (memberVerified) return
      check(session.isMember(peerId), 'PEER_MEMBER_REQUIRED')
      memberVerified = true
      markMember()
    }

    // ---- outgoing facts (batched, size-bounded) ----
    const FACT_BATCH_BYTES = 512 * 1024
    const sendFactBatches = async (facts: WireFacts, requestId = ''): Promise<void> => {
      const batches: { publicOps: Uint8Array[]; encryptedEnvelopes: Uint8Array[]; checkpoints: FinalityCheckpoint[] }[] = []
      let current = { publicOps: [] as Uint8Array[], encryptedEnvelopes: [] as Uint8Array[], checkpoints: [] as FinalityCheckpoint[] }, size = 0
      const roll = (bytes: number): void => {
        if (size + bytes > FACT_BATCH_BYTES && size > 0) { batches.push(current); current = { publicOps: [], encryptedEnvelopes: [], checkpoints: [] }; size = 0 }
        size += bytes
      }
      for (const raw of facts.publicOps) { roll(raw.length); current.publicOps.push(raw) }
      for (const raw of facts.encryptedEnvelopes) { if (!privateAllowed()) break; roll(raw.length); current.encryptedEnvelopes.push(raw) }
      for (const cp of facts.checkpoints) { roll(4096); current.checkpoints.push(cp) }
      batches.push(current)
      let sent: Promise<void> = Promise.resolve()
      for (let i = 0; i < batches.length; i++) {
        const batch = batches[i]!, last = i === batches.length - 1
        if (!last && batch.publicOps.length + batch.encryptedEnvelopes.length + batch.checkpoints.length === 0) continue
        if (last && requestId === '' && batch.publicOps.length + batch.encryptedEnvelopes.length + batch.checkpoints.length === 0) continue
        sent = post({ kind: 'facts', requestId: last ? requestId : '', facts: batch })
      }
      await sent
    }
    const pushIds = (scope: FactScope, ids: readonly string[]): Promise<void> => {
      if (ids.length === 0 || (scope === 'private' && !privateAllowed())) return Promise.resolve()
      return sendFactBatches(session.exportFactsById(scope, ids))
    }

    // ---- live push of new facts (never echo facts back to the link that delivered them) ----
    const livePending: { scope: FactScope; id: string }[] = []
    let liveFlush: Promise<void> | undefined
    const flushLive = (): Promise<void> => liveFlush ??= (async () => {
      try {
        while (livePending.length > 0 && !signal.aborted) {
          const items = livePending.splice(0)
          await pushIds('public', items.filter(item => item.scope === 'public').map(item => item.id))
          await pushIds('private', items.filter(item => item.scope === 'private').map(item => item.id))
        }
      } finally { liveFlush = undefined }
    })()
    stopFacts = session.onFacts((delta: FactsDelta) => {
      for (const item of delta.items) {
        if (item.source === connectionId) continue
        if (item.scope === 'private' && !privateAllowed()) continue
        livePending.push({ scope: item.scope, id: item.id })
      }
      if (livePending.length > 0) void flushLive().catch(() => close())
    })

    // ---- retention receipts (one signature per debounced batch) ----
    let receiptItems: { proposalId: string }[] = []
    let receiptTimer: ReturnType<typeof setTimeout> | undefined
    const flushReceipts = async (): Promise<void> => {
      receiptTimer = undefined
      const items = receiptItems; receiptItems = []
      if (items.length === 0 || signal.aborted) return
      const evidence = await session.retainMany(items)
      const own = evidence.find(ev => ev.signer === self)
      if (own !== undefined) void post({ kind: 'receipt', evidence: own })
    }
    const queueReceipts = (facts: WireFacts): void => {
      for (const raw of facts.publicOps) {
        try { receiptItems.push({ proposalId: bytesToHex(operationIdDigest(decodeSignedOperation(raw).coreBytes)) }) } catch { /* rejected by merge */ }
      }
      for (const raw of facts.encryptedEnvelopes) {
        try { receiptItems.push({ proposalId: bytesToHex(decodeEncryptedEnvelope(raw).opId) }) } catch { /* ignore */ }
      }
      if (receiptItems.length > 0 && receiptTimer === undefined) {
        receiptTimer = setTimeout(() => { void flushReceipts().catch(() => undefined) }, 25)
      }
    }

    // ---- on-demand CAS pull (modules, packages, reducer-read nodes, SQLite pages); derived CAS is never pushed ----
    const casRequests = new Map<string, { resolve(): void; reject(error: unknown): void }>()
    const requestedCas = new Set<string>()
    const pullMissingCas = async (): Promise<void> => {
      for (let attempt = 0; attempt < 8 && !signal.aborted; attempt++) {
        const missing = session.missingCasDependencies().filter(hash => !requestedCas.has(hash))
        if (missing.length === 0) return
        for (const hash of missing) requestedCas.add(hash)
        const requestId = crypto.randomUUID()
        const done = new Promise<void>((resolve, reject) => casRequests.set(requestId, { resolve, reject }))
        void post({ kind: 'cas-want', requestId, hashes: missing.slice(0, 1024), subgraph: true })
        await done
      }
    }

    // ---- reconciliation rounds ----
    interface Round { readonly scope: FactScope; outstanding: number; readonly wants: Set<string>; ended: boolean; resolve(): void; reject(error: unknown): void }
    const rounds = new Map<string, Round>()
    const wantRequests = new Map<string, string>() // want requestId -> round id
    const maybeFinishRound = async (id: string): Promise<void> => {
      const round = rounds.get(id)
      if (round === undefined || round.ended || round.outstanding > 0 || round.wants.size > 0) return
      round.ended = true
      await pullMissingCas()
      void post({ kind: 'recon-end', round: id, scope: round.scope })
    }
    const applyStep = async (roundId: string, scope: FactScope, ranges: readonly ReconcileRange[], owner: boolean): Promise<void> => {
      const allowed = scope === 'public' || privateAllowed()
      const local = allowed ? session.factIds(scope) : undefined
      const step = local === undefined ? { reply: ranges.filter(r => !('ids' in r)).map(r => ({ prefix: r.prefix, ids: [] })), push: [], want: [] } : reconcileRanges(local, ranges)
      if (allowed) void pushIds(scope, step.push)
      if (allowed && step.want.length > 0) {
        const requestId = crypto.randomUUID()
        if (owner) { wantRequests.set(requestId, roundId); for (const want of step.want) rounds.get(roundId)?.wants.add(want) }
        void post({ kind: 'want', requestId, scope, ids: step.want })
      }
      if (owner) {
        // Our round: continue while summaries need answers; id lists still get one (empty) reply.
        const round = rounds.get(roundId)
        if (round === undefined) return
        if (step.reply.length > 0) {
          round.outstanding++
          void post({ kind: 'recon', round: roundId, scope, owner: true, ranges: step.reply })
        }
        await maybeFinishRound(roundId)
      } else {
        // Peer's round: always answer so the owner can count outstanding exchanges.
        void post({ kind: 'recon', round: roundId, scope, owner: false, ranges: step.reply })
      }
    }
    const runRound = (scope: FactScope): Promise<void> => {
      check(!signal.aborted && rounds.size < 8, 'PEER_REQUEST_LIMIT')
      const id = crypto.randomUUID()
      return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => { rounds.delete(id); reject(new Error('PEER_SYNC_TIMEOUT')); void close() }, 60_000)
        rounds.set(id, {
          scope, outstanding: 1, wants: new Set(), ended: false,
          resolve: () => { clearTimeout(timer); rounds.delete(id); resolve() },
          reject: (error) => { clearTimeout(timer); rounds.delete(id); reject(error) },
        })
        const local = scope === 'private' && !privateAllowed() ? undefined : session.factIds(scope)
        const root: ReconcileRange = local === undefined ? { prefix: '', count: 0, fp: new Uint8Array(16) } : local.summary('')
        void wire.send({ kind: 'recon', round: id, scope, owner: false, ranges: [root] })
          .catch(error => { rounds.get(id)?.reject(error) })
      })
    }

    let markReady!: () => void
    const initialSync = new Promise<void>(resolve => { markReady = resolve })
    void initialSync.catch(() => undefined)
    const runInitialSync = async (): Promise<void> => {
      await runRound('public')
      verifyMember()
      await runRound('private')
      void post({ kind: 'ready' })
      markReady()
    }
    let contentTail: Promise<void> = Promise.resolve()
    void (async () => {
      try {
        while (!signal.aborted) {
          const incoming = await iterator.next(); if (incoming.done) break
          const message = incoming.value as Message
          if (memberVerified) check(session.isMember(peerId), 'PEER_REVOKED')
          switch (message.kind) {
            case 'recon': {
              check(typeof message.round === 'string' && message.round.length <= 64 && Array.isArray(message.ranges) && message.ranges.length <= 4096, 'PEER_REQUEST_INVALID')
              check(message.scope === 'public' || message.scope === 'private', 'PEER_REQUEST_INVALID')
              const round = rounds.get(message.round)
              // A message flagged owner:false addressed to one of OUR rounds is the peer's reply.
              if (round !== undefined && !message.owner) {
                round.outstanding--
                await applyStep(message.round, message.scope, message.ranges, true)
              } else {
                await applyStep(message.round, message.scope, message.ranges, false)
              }
              break
            }
            case 'recon-end': {
              if (message.scope === 'public') verifyMember()
              void post({ kind: 'ack', requestId: message.round })
              break
            }
            case 'ready': markReady(); break
            case 'want': {
              check(Array.isArray(message.ids) && message.ids.length <= 100_000, 'PEER_REQUEST_INVALID')
              const allowed = message.scope === 'public' || privateAllowed()
              void sendFactBatches(allowed ? session.exportFactsById(message.scope, message.ids) : { publicOps: [], encryptedEnvelopes: [], checkpoints: [] }, message.requestId)
              break
            }
            case 'facts': {
              check(typeof message.requestId === 'string' && message.requestId.length <= 128, 'PEER_REQUEST_INVALID')
              const facts = message.facts
              const encryptedEnvelopes = privateAllowed() ? facts.encryptedEnvelopes : []
              await session.mergeFacts({ publicOps: facts.publicOps, encryptedEnvelopes, casNodes: [], retentions: [], checkpoints: facts.checkpoints }, { source: connectionId })
              queueReceipts({ publicOps: facts.publicOps, encryptedEnvelopes, checkpoints: [] })
              if (message.requestId !== '') {
                const roundId = wantRequests.get(message.requestId)
                wantRequests.delete(message.requestId)
                const round = roundId === undefined ? undefined : rounds.get(roundId)
                if (round !== undefined) { round.wants.clear(); await maybeFinishRound(roundId!) }
              }
              if (session.missingCasDependencies().length > 0) void pullMissingCas().catch(() => undefined)
              break
            }
            case 'cas-want': {
              check(Array.isArray(message.hashes) && message.hashes.length <= 1024, 'PEER_REQUEST_INVALID')
              const nodes = await session.exportCasNodes(
                message.hashes.filter((h: unknown): h is string => typeof h === 'string' && /^[0-9a-f]{64}$/u.test(h)),
                privateAllowed(),
                { subgraph: message.subgraph !== false },
              )
              void post({ kind: 'cas', requestId: message.requestId, nodes })
              break
            }
            case 'cas': {
              const nodes = message.nodes.filter(node => node.partition === 'public' || privateAllowed())
              if (nodes.length > 0) await session.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: nodes, retentions: [], checkpoints: [] }, { source: connectionId })
              const waiter = casRequests.get(message.requestId)
              casRequests.delete(message.requestId); waiter?.resolve()
              break
            }
            case 'receipt': {
              await session.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: [], retentions: [message.evidence], checkpoints: [] }, { source: connectionId })
              break
            }
            case 'content': {
              const content = message.message
              if (memberVerified) await contentLink.handle(content)
              else contentTail = contentTail.then(() => memberReady).then(() => contentLink!.handle(content)).catch(() => undefined)
              break
            }
            case 'rtc':
              if (memberVerified && inBandRtc !== undefined && session.isReader(peerId)) {
                void inBandRtc.receive(message.message).catch(() => undefined)
              }
              break
            case 'ack': {
              const round = rounds.get(message.requestId)
              if (round !== undefined) round.resolve()
              break
            }
            default: throw new Error('PEER_MESSAGE_INVALID')
          }
        }
      } catch (error) { lifetime.abort(error) }
      finally {
        for (const round of rounds.values()) round.reject(signal.reason ?? new Error('PEER_CLOSED'))
        for (const waiter of casRequests.values()) waiter.reject(signal.reason ?? new Error('PEER_CLOSED'))
        if (receiptTimer !== undefined) clearTimeout(receiptTimer)
        await close()
      }
    })()

    if (initiator) void runInitialSync().catch(error => { lifetime.abort(error) })
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
      async synchronize() {
        check(!signal.aborted, 'PEER_REQUEST_LIMIT')
        await interruptibleWait(initialSync, signal)
        await runRound('public')
        await runRound('private')
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

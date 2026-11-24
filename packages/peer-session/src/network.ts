import {
  encodePeerValue, peerDigest, verifyAuthorityBundle, validateHistoryPoint,
  createParticipantRequest, createParticipantResponse, validateParticipantRequest, validateParticipantResponse, PEER_PARTICIPANT_POLICY,
  type AuthorityBundle, type SignedControlRevision, type SignedGeneration, type HistoryPoint, type PeerAuthority, type ParticipantRequest, type ParticipantInterest,
} from '@chronolog/peer-generation/control'
import type { OrderedCommand, PeerRevision, SignedAttempt, SignedRetainedCoverage } from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes, signDomain, verifyDomain, DOMAINS } from '@chronolog/protocol'
import { MAX_SIGNAL_BYTES, type SignalChannel, type SignalRoute, type SignalReceiveDiagnostics } from '@chronolog/signals'
import type { ContentManifest, ContentReference, ContentRetention } from './content.js'
import type { ApplicationKeyRequest, ApplicationKeyShare } from './keys.js'
import type { ApplicationDataPort, ApplicationParticipant } from './participant-types.js'
import { ApplicationSecureChannel, APPLICATION_CHANNEL_SUITE, type ApplicationChannelHello } from './secure-channel.js'
import {
  APPLICATION_NETWORK_LIMITS as LIMITS, ApplicationMessageWire, createFramedPeerConnectionPair,
  interruptible, networkError, record, requireNetwork, timeout,
  type FramedPeerConnection, type PeerLiveLane,
} from './network-wire.js'

export { APPLICATION_NETWORK_LIMITS, createFramedPeerConnectionPair } from './network-wire.js'
export type { FramedPeerConnection, PeerLiveLane } from './network-wire.js'
export interface ApplicationPeerLink {
  readonly peerId: string
  /** Availability of the remote data facet; independent of authenticated live/control traffic. */
  readonly data: 'idle' | 'active' | 'unavailable'
  readonly signal: AbortSignal
  readonly completion: Promise<void>
  /** Local application framing bytes; excludes channel encryption and transport/billing overhead. */
  readonly stats: { readonly sentBytes: number; readonly receivedBytes: number; readonly sentLiveBytes: number; readonly receivedLiveBytes: number; readonly sentRequests: number; readonly receivedRequests: number; readonly signalRejections?: SignalReceiveDiagnostics }
  synchronize(): Promise<void>
  /** Stop routing new work and retain authenticated RPC traffic until the bounded drain deadline. */
  retire(): Promise<void>
  close(): Promise<void>
}
/** Internal owner port: every attachment has already proved the remote key. */
export interface ApplicationPeerPort {
  readonly participant: ApplicationParticipant
  readonly signals: SignalChannel
  readonly signal: AbortSignal
  attach(peerId: string, submit: (attempt: SignedAttempt) => Promise<void>, link: { close(): Promise<void>; retire?(): Promise<void> }): () => void
  resume(): Promise<void>
  /** A complete head received through this authenticated coordinator link. */
  observeHead?(peerId: string, revision: PeerRevision, requestedAt: number): void
}
export interface ApplicationPeerConnectOptions {
  readonly connection: FramedPeerConnection
  /** Full bundles for compatibility with older endpoints; suffix exchange is the default. */
  readonly authorityExchange?: 'suffix' | 'bundle'
  readonly peerIdentity?: string
  readonly signal?: AbortSignal
  readonly handshakeTimeoutMs?: number
  readonly requestTimeoutMs?: number
  readonly transferTimeoutMs?: number
  /** Replacement drain budget, measured once from retirement (default 5 seconds). */
  readonly drainTimeoutMs?: number
}
interface Hello { readonly application: string; readonly profile: 'peer-generation-v1'; readonly descriptor: string; readonly author: string; readonly nonce: string; readonly authority: AuthorityBundle | AuthoritySummary; readonly channel: ApplicationChannelHello }
interface AuthoritySummary {
  readonly format: 'authority-summary-v1'
  readonly controls: number
  readonly generations: number
  readonly generation: string | null
  readonly controlDigest: string
}
interface AuthoritySuffix {
  readonly base: AuthoritySummary | null
  readonly controls: readonly SignedControlRevision[]
  readonly generations: readonly SignedGeneration[]
}
async function authoritySummary(authority: PeerAuthority): Promise<AuthoritySummary> {
  return { format: 'authority-summary-v1', controls: authority.controlCount, generations: authority.generationCount,
    generation: authority.current?.id ?? null, controlDigest: await peerDigest(authority.control) }
}
function validateSummary(input: unknown): AuthoritySummary {
  const summary = record(input, ['format', 'controls', 'generations', 'generation', 'controlDigest'])
  requireNetwork(summary.format === 'authority-summary-v1' && Number.isSafeInteger(summary.controls) && (summary.controls as number) > 0 &&
    (summary.controls as number) <= 4096 && Number.isSafeInteger(summary.generations) && (summary.generations as number) >= 0 && (summary.generations as number) <= 4096 &&
    (summary.generations === 0 ? summary.generation === null : hexadecimal(summary.generation)) && hexadecimal(summary.controlDigest), 'APPLICATION_NETWORK_AUTHORITY_INVALID')
  return summary as unknown as AuthoritySummary
}
async function authoritySuffix(authority: PeerAuthority, base: AuthoritySummary): Promise<AuthoritySuffix> {
  const matches = base.generations <= authority.generationCount && base.controls <= authority.controlCount &&
    (authority.generationAt(base.generations - 1)?.id ?? null) === base.generation &&
    await peerDigest(authority.controlAt(base.controls - 1)) === base.controlDigest
  return { base: matches ? base : null, ...authority.suffix(matches ? base.controls : 0, matches ? base.generations : 0) }
}
async function applyAuthoritySuffix(authority: PeerAuthority, input: unknown): Promise<PeerAuthority> {
  const suffix = record(input, ['base', 'controls', 'generations']) as unknown as AuthoritySuffix
  requireNetwork(Array.isArray(suffix.controls) && suffix.controls.length <= 4096 && Array.isArray(suffix.generations) && suffix.generations.length <= 4096, 'APPLICATION_NETWORK_AUTHORITY_INVALID')
  if (suffix.base === null) return verifyAuthorityBundle({ descriptor: authority.signedDescriptor, controls: suffix.controls, generations: suffix.generations })
  requireNetwork(same(validateSummary(suffix.base), await authoritySummary(authority)), 'APPLICATION_NETWORK_AUTHORITY_INVALID')
  return authority.extend(suffix.controls, suffix.generations)
}
interface RemoteState { readonly authority: PeerAuthority; readonly data: boolean; readonly point: HistoryPoint | null; readonly revision: PeerRevision | null }
type Method = 'state' | 'openData' | 'range' | 'submit' | 'coverage' | 'keyShare' | 'contentManifest' | 'contentChunk' | 'contentRetained' | 'contentObserveRetention'
const methods: readonly Method[] = ['state', 'openData', 'range', 'submit', 'coverage', 'keyShare', 'contentManifest', 'contentChunk', 'contentRetained', 'contentObserveRetention']
const interests: Readonly<Record<Method, ParticipantInterest>> = {
  state: { facet: 'control', action: 'state' }, keyShare: { facet: 'control', action: 'keyShare' },
  openData: { facet: 'database', action: 'open' }, range: { facet: 'database', action: 'range' }, submit: { facet: 'database', action: 'submit' }, coverage: { facet: 'database', action: 'coverage' },
  contentManifest: { facet: 'content', action: 'manifest' }, contentChunk: { facet: 'content', action: 'chunk' },
  contentRetained: { facet: 'content', action: 'retained' }, contentObserveRetention: { facet: 'content', action: 'observeRetention' },
}
interface Pending { readonly method: Method; readonly request: ParticipantRequest; resolve(value: unknown): void; reject(error: unknown): void; cancel(): void }
interface Owner { next: number; readonly openings: Map<NetworkPeer, number>; readonly accepted: Map<string, number>; readonly peers: Map<string, NetworkPeer>; readonly retiring: Map<string, NetworkPeer> }
const owners = new WeakMap<ApplicationPeerPort, Owner>()
const hexadecimal = (value: unknown, length = 64): value is string => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/u.test(value)
const same = (a: unknown, b: unknown): boolean => bytesToHex(encodePeerValue(a)) === bytesToHex(encodePeerValue(b))
class PeerDataUnavailableError extends Error {
  constructor() { super('APPLICATION_DATA_UNAVAILABLE') }
}
/** A data-resource failure must not retire an otherwise authenticated participant. */
export function isPeerDataUnavailable(error: unknown): error is PeerDataUnavailableError {
  return error instanceof PeerDataUnavailableError
}
function retryablePull(error: unknown): boolean {
  return error instanceof Error && ['APPLICATION_NETWORK_STATE_CHANGED', 'PEER_AUTHORITY_REGRESSION', 'PEER_CURSOR_RECOVERY_REQUIRED',
    'PEER_VIEW_RECOVERY_REQUIRED', 'APPLICATION_KEY_REQUEST_EXPIRED'].includes(error.message)
}
/** Retirement fences pending data work without retiring its authenticated connection. */
async function useData<T>(data: ApplicationDataPort, run: () => Promise<T>): Promise<T> {
  try {
    requireNetwork(!data.replica.closed, 'APPLICATION_DATA_UNAVAILABLE')
    const value = await run()
    requireNetwork(!data.replica.closed, 'APPLICATION_DATA_UNAVAILABLE')
    return value
  } catch (error) {
    if (data.replica.closed) throw new PeerDataUnavailableError()
    throw error
  }
}
function availablePoint(replica: ApplicationDataPort['replica'] | undefined): HistoryPoint | null {
  if (replica === undefined) return null
  try { return replica.retainedPoint }
  catch (error) {
    // Authority invalidation publishes before all new-generation heads are loaded.
    // No prefix is advertised until the replica can actually describe one.
    if (error instanceof Error && error.message === 'PEER_RECOVERY_PREFIX_INCOMPLETE') return null
    throw error
  }
}
function grant(participant: Pick<ApplicationParticipant, 'grant'>, key: string, role: 'reader' | 'writer' | 'relay'): boolean {
  return participant.grant(key)?.[role] === true
}
function requireSubmitter(participant: ApplicationParticipant, carrier: string, input: unknown): void {
  const author = (input as SignedAttempt | null)?.payload?.header?.author
  requireNetwork(typeof author === 'string' && grant(participant, author, 'writer') &&
    (author === carrier || grant(participant, carrier, 'relay')), 'PEER_AUTHOR_FORBIDDEN')
}
function deadline(value: number | undefined, fallback: number): number {
  const selected = value ?? fallback
  requireNetwork(Number.isSafeInteger(selected) && selected > 0 && selected <= 120_000, 'APPLICATION_NETWORK_TIMEOUT_INVALID')
  return selected
}
function position(authority: PeerAuthority, point: HistoryPoint): readonly [number, number] {
  validateHistoryPoint(point)
  const index = authority.selectedSegments().findIndex(value => value.generation.id === point.generation)
  requireNetwork(index >= 0 && authority.contains(point), 'APPLICATION_NETWORK_CURSOR_INVALID')
  return [index, point.sequence]
}
function atOrAfter(authority: PeerAuthority, left: HistoryPoint, right: HistoryPoint): boolean {
  const a = position(authority, left), b = position(authority, right)
  return a[0] > b[0] || a[0] === b[0] && a[1] >= b[1]
}
function newest(left: PeerAuthority, right: PeerAuthority): PeerAuthority {
  requireNetwork(same(left.signedDescriptor, right.signedDescriptor), 'APPLICATION_NETWORK_SCOPE_MISMATCH')
  const [old, current] = left.generationCount <= right.generationCount ? [left, right] : [right, left]
  requireNetwork(current.controlCount >= old.controlCount && (old.current?.id ?? null) === (current.generationAt(old.generationCount - 1)?.id ?? null) &&
    same(old.control, current.controlAt(old.controlCount - 1)), 'PEER_CONTROL_EQUIVOCATION')
  return left.generationCount === right.generationCount ? left : current
}
/** Largest remotely retained point that remains selected by the latest authority. */
function transferTarget(remote: PeerAuthority, latest: PeerAuthority, point: HistoryPoint | null): HistoryPoint | null {
  if (point === null) return null
  const remoteSegments = remote.selectedSegments(), available = position(remote, point)[0]
  let target: HistoryPoint | null = null
  for (const selected of latest.selectedSegments()) {
    const index = remoteSegments.findIndex(value => value.generation.id === selected.generation.id)
    if (index < 0 || index > available) continue
    const retained = index === available ? point : remoteSegments[index]!.cutoff!
    const candidate = selected.cutoff !== null && selected.cutoff.sequence <= retained.sequence ? selected.cutoff : retained
    // A generation's zero root authenticates its inherited base; it is not a
    // command to fetch. The captured revision still verifies this root below.
    if (candidate.sequence > 0) target = candidate
  }
  return target
}

class NetworkPeer implements ApplicationPeerLink {
  readonly #port: ApplicationPeerPort
  readonly #input: ApplicationPeerConnectOptions
  readonly #owner: Owner
  readonly #attempt: number
  readonly #controller = new AbortController()
  readonly #wire: ApplicationMessageWire
  readonly #channel: ApplicationSecureChannel
  #proofSent: Promise<void> | undefined
  readonly #pending = new Map<number, Pending>()
  readonly #requestMs: number
  readonly #handshakeMs: number
  readonly #drainMs: number
  #retiring = false
  #drainTimer: ReturnType<typeof setTimeout> | undefined
  readonly #ready: Promise<void>
  readonly completion: Promise<void>
  #readyResolve!: () => void
  #readyReject!: (error: unknown) => void
  #completeResolve!: () => void
  #completeReject!: (error: unknown) => void
  #knownAuthority: PeerAuthority | undefined
  #localSummary: AuthoritySummary | undefined
  #localAuthority: PeerAuthority | undefined
  #authorityRequested = false
  #authorityAnswered = false
  #local: Hello | undefined
  #remote: Hello | undefined
  #authenticated = false
  #confirmed = false
  #nextRequest = 0
  #lastRemoteRequest = 0
  #sentLiveBytes = 0
  #receivedLiveBytes = 0
  #sentRequests = 0
  #receivedRequests = 0
  #incoming = 0
  #route: SignalRoute | undefined
  #detach: (() => void) | undefined
  #detachContent: (() => void) | undefined
  #detachKeys: (() => void) | undefined
  #data: ApplicationDataPort | undefined
  #disposeLive: (() => void) | undefined
  #unsubscribe: (() => void) | undefined
  #disposeListeners: (() => void)[] = []
  #closeTask: Promise<void> | undefined
  #sync: Promise<void> | undefined
  #nextSync: Promise<void> | undefined
  #syncAgain = false
  #hintPending = false
  #lastHint = ''
  #stateRetries = 0
  #remoteData: boolean | undefined
  #remoteDataFailure: Error | undefined
  #remoteOpening: Promise<void> | undefined

  constructor(port: ApplicationPeerPort, input: ApplicationPeerConnectOptions, owner: Owner, attempt: number) {
    this.#port = port; this.#input = input; this.#owner = owner; this.#attempt = attempt
    this.#requestMs = deadline(input.requestTimeoutMs, 120_000); this.#handshakeMs = deadline(input.handshakeTimeoutMs, 10_000)
    this.#drainMs = deadline(input.drainTimeoutMs, 5000)
    this.#channel = new ApplicationSecureChannel(input.connection, this.signal)
    this.#wire = new ApplicationMessageWire(this.#channel.connection, this.signal, deadline(input.transferTimeoutMs, 30_000), () => {
      if (this.#authenticated) this.#reader()
    })
    this.#ready = new Promise((resolve, reject) => { this.#readyResolve = resolve; this.#readyReject = reject })
    this.completion = new Promise((resolve, reject) => { this.#completeResolve = resolve; this.#completeReject = reject })
    void this.#ready.catch(() => undefined); void this.completion.catch(() => undefined)
    for (const signal of [port.signal, input.signal, input.connection.signal]) {
      if (signal === undefined) continue
      const abort = (): void => this.#fail(signal.reason ?? networkError('APPLICATION_NETWORK_CLOSED'))
      signal.addEventListener('abort', abort, { once: true }); this.#disposeListeners.push(() => signal.removeEventListener('abort', abort))
      if (signal.aborted) abort()
    }
  }
  get peerId(): string { return this.#remote?.author ?? '' }
  get data(): ApplicationPeerLink['data'] { return this.#remoteData === true ? 'active' : this.#remoteDataFailure === undefined ? 'idle' : 'unavailable' }
  get signal(): AbortSignal { return this.#controller.signal }
  get stats(): ApplicationPeerLink['stats'] {
    return { ...this.#wire.stats, sentLiveBytes: this.#sentLiveBytes, receivedLiveBytes: this.#receivedLiveBytes,
      sentRequests: this.#sentRequests, receivedRequests: this.#receivedRequests,
      ...(this.#route === undefined ? {} : { signalRejections: this.#route.diagnostics }) }
  }
  #reader(): void {
    this.signal.throwIfAborted()
    requireNetwork(this.#remote !== undefined && grant(this.#port.participant, this.peerId, 'reader') &&
      grant(this.#port.participant, this.#port.participant.device.publicKey, 'reader'), 'APPLICATION_PEER_NOT_AUTHORIZED')
  }
  async open(): Promise<void> {
    const participant = this.#port.participant
    requireNetwork(this.#input.peerIdentity === undefined || hexadecimal(this.#input.peerIdentity), 'APPLICATION_PEER_IDENTITY_INVALID')
    requireNetwork(grant(participant, participant.device.publicKey, 'reader'), 'APPLICATION_PEER_NOT_AUTHORIZED')
    this.#localAuthority = await verifyAuthorityBundle(participant.authority)
    this.#knownAuthority = this.#localAuthority
    this.#localSummary = await authoritySummary(this.#localAuthority)
    requireNetwork(this.#input.authorityExchange === undefined || ['suffix', 'bundle'].includes(this.#input.authorityExchange), 'APPLICATION_NETWORK_AUTHORITY_INVALID')
    this.#local = { application: participant.descriptor.applicationId, profile: 'peer-generation-v1',
      descriptor: await peerDigest(participant.authority.descriptor), author: participant.device.publicKey,
      nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(32))), authority: this.#input.authorityExchange === 'bundle' ? this.#localAuthority.bundle : this.#localSummary, channel: await this.#channel.hello() }
    const handshake = timeout(this.#handshakeMs, 'APPLICATION_PEER_HANDSHAKE_TIMEOUT')
    void this.#read().catch(error => this.#fail(error))
    try {
      await interruptible(this.#wire.send({ kind: 'hello', value: this.#local }), AbortSignal.any([this.signal, handshake.signal]))
      await interruptible(this.#ready, AbortSignal.any([this.signal, handshake.signal]))
      this.#reader()
      requireNetwork((this.#owner.accepted.get(this.peerId) ?? 0) <= this.#attempt, 'APPLICATION_PEER_SUPERSEDED')
      requireNetwork(this.#owner.peers.size < LIMITS.peers || this.#owner.peers.has(this.peerId), 'APPLICATION_PEER_LIMIT')
      const previous = this.#owner.peers.get(this.peerId)
      this.#owner.accepted.set(this.peerId, this.#attempt); this.#owner.peers.set(this.peerId, this)
      if (previous !== undefined) void previous.retire().catch(() => undefined)
      this.#detach = this.#port.attach(this.peerId, async attempt => {
        this.#reader()
        requireSubmitter(participant, participant.device.publicKey, attempt)
        await this.#request('submit', attempt)
        this.#reader(); await this.synchronize()
      }, this)
      this.#unsubscribe = participant.subscribe(() => this.#changed())
      this.#changed()
    } catch (error) { this.#fail(error); throw error }
    finally { handshake.cancel() }
  }
  #prepareLive(): void {
    if (this.#channel.connection.live !== undefined) {
      const lane = this.#channel.connection.live
      this.#route = this.#port.signals.attachRoute({ close: reason => this.#dispose(reason), trySend: async (frame, { signal }) => {
        signal.throwIfAborted(); this.#reader()
        if (this.#retiring || this.#owner.peers.get(this.peerId) !== this) return false
        const accepted = await lane.trySend(frame, { signal: AbortSignal.any([signal, this.signal]) })
        if (accepted) this.#sentLiveBytes += frame.length
        this.#reader(); return accepted
      } })
      const route = this.#route
      let closed = false
      const dispose = (): void => {
        if (closed) return
        closed = true; route.close(); lane.signal.removeEventListener('abort', dispose)
        void lane.close().catch(() => undefined)
      }
      this.#disposeLive = dispose
      lane.signal.addEventListener('abort', dispose, { once: true })
      if (lane.signal.aborted) dispose()
      void this.#readLive(lane, route).catch(error => this.#fail(error)).finally(dispose)
    }
  }
  #attachData(): boolean {
    const data = this.#port.participant.data
    if (this.#retiring || data === undefined || data === this.#data) return false
    this.#data = data
    this.#detachContent = data.content.attachSource(this.peerId, {
      manifest: async reference => await this.#request('contentManifest', reference) as ContentManifest | null,
      chunk: async (reference, index) => {
        const bytes = await this.#request('contentChunk', { reference, index })
        this.#reader()
        if (bytes === null) return null
        requireNetwork(typeof bytes === 'string' && bytes.length <= 2 * (65_536 + 16) && /^(?:[0-9a-f]{2})+$/u.test(bytes),
          'APPLICATION_CONTENT_CHUNK_INVALID')
        return hexToBytes(bytes)
      },
      retained: async reference => {
        const receipt = await this.#request('contentRetained', reference) as ContentRetention
        requireNetwork(receipt?.payload?.peer === this.peerId, 'CONTENT_RETENTION_INVALID')
        return receipt
      },
      observeRetention: async receipt => { await this.#request('contentObserveRetention', receipt) },
    })
    this.#detachKeys = data.keys.attachSource(this.peerId, async request => {
      const share = await this.#request('keyShare', request) as ApplicationKeyShare
      this.#reader()
      requireNetwork(share?.payload?.issuer === this.peerId, 'APPLICATION_KEY_SHARE_INVALID')
      return share
    })
    return true
  }
  async #currentAuthority(): Promise<PeerAuthority> {
    if (this.#knownAuthority?.current?.id !== this.#port.participant.generation.id) this.#knownAuthority = await verifyAuthorityBundle(this.#port.participant.authority)
    return this.#knownAuthority
  }
  async #proveHello(remote: PeerAuthority): Promise<void> {
    const current = await this.#currentAuthority()
    this.signal.throwIfAborted()
    const latest = newest(current, remote)
    if (latest !== current) await this.#port.participant.adoptAuthority(latest.bundle)
    this.#knownAuthority = latest
    this.signal.throwIfAborted(); this.#reader()
    const encapsulatedKey = await this.#channel.prepare(this.#remote!.channel.receiverKey, this.#local!, this.#remote!)
    this.#reader()
    const signature = await signDomain(DOMAINS.peerConnection, encodePeerValue({ sender: this.#local, receiver: this.#remote, encapsulatedKey }), this.#port.participant.device.privateKey)
    this.#reader()
    this.#proofSent = this.#wire.send({ kind: 'proof', signature: bytesToHex(signature), encapsulatedKey }, () => this.#reader())
      .then(() => { this.#channel.enableSending() })
    void this.#proofSent.catch(error => this.#fail(error))
  }
  async #read(): Promise<void> {
    for await (const value of this.#wire.messages()) {
      this.signal.throwIfAborted()
      requireNetwork(value !== null && typeof value === 'object' && 'kind' in value, 'APPLICATION_NETWORK_MESSAGE_INVALID')
      const kind = value.kind
      if (kind === 'hello') {
        const message = record(value, ['kind', 'value']), input = record(message.value, ['application', 'profile', 'descriptor', 'author', 'nonce', 'authority', 'channel'])
        const channel = record(input.channel, ['suite', 'receiverKey'])
        const local = this.#local
        requireNetwork(local !== undefined, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
        requireNetwork(this.#remote === undefined && channel.suite === APPLICATION_CHANNEL_SUITE && hexadecimal(channel.receiverKey) &&
          input.application === local.application && input.profile === local.profile &&
          input.descriptor === local.descriptor && hexadecimal(input.author) && hexadecimal(input.nonce) &&
          input.author !== local.author && (this.#input.peerIdentity === undefined || input.author === this.#input.peerIdentity), 'APPLICATION_NETWORK_SCOPE_MISMATCH')
        this.#remote = input as unknown as Hello
        const offered = input.authority
        if (offered !== null && typeof offered === 'object' && 'format' in offered) {
          const summary = validateSummary(offered)
          if (same(summary, this.#localSummary)) await this.#proveHello(this.#localAuthority!)
          else {
            this.#authorityRequested = true
            void this.#wire.send({ kind: 'authority-request', base: this.#localSummary }).catch(error => this.#fail(error))
          }
        } else await this.#proveHello(await verifyAuthorityBundle(offered as AuthorityBundle, this.#localAuthority!.signedDescriptor))
      } else if (kind === 'authority-request') {
        const message = record(value, ['kind', 'base'])
        requireNetwork(!this.#authenticated && this.#remote !== undefined && !this.#authorityAnswered, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
        this.#authorityAnswered = true
        const suffix = await authoritySuffix(this.#localAuthority!, validateSummary(message.base))
        void this.#wire.send({ kind: 'authority-response', suffix }).catch(error => this.#fail(error))
      } else if (kind === 'authority-response') {
        const message = record(value, ['kind', 'suffix'])
        requireNetwork(!this.#authenticated && this.#authorityRequested && this.#proofSent === undefined, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
        this.#authorityRequested = false
        const authority = await applyAuthoritySuffix(this.#localAuthority!, message.suffix)
        requireNetwork(same(await authoritySummary(authority), this.#remote!.authority), 'APPLICATION_NETWORK_AUTHORITY_INVALID')
        await this.#proveHello(authority)
      } else if (kind === 'proof') {
        const message = record(value, ['kind', 'signature', 'encapsulatedKey'])
        requireNetwork(!this.#authenticated && this.#remote !== undefined && this.#proofSent !== undefined &&
          hexadecimal(message.signature, 128) && hexadecimal(message.encapsulatedKey), 'APPLICATION_PEER_PROOF_INVALID')
        requireNetwork(await verifyDomain(DOMAINS.peerConnection, encodePeerValue({ sender: this.#remote, receiver: this.#local, encapsulatedKey: message.encapsulatedKey }),
          hexToBytes(message.signature), hexToBytes(this.peerId)), 'APPLICATION_PEER_PROOF_INVALID')
        this.#reader()
        await this.#channel.accept(message.encapsulatedKey, this.#remote, this.#local)
        await interruptible(this.#proofSent, this.signal)
        this.#reader(); this.#authenticated = true
        this.#prepareLive()
        // Reserve candidate routing before reciprocal confirmation. A failed
        // proof or local route quota must preserve both working endpoints.
        // Keep reading while the write is backpressured by the remote reader.
        void this.#wire.send({ kind: 'ready' }).catch(error => this.#fail(error))
      } else {
        requireNetwork(this.#authenticated, 'APPLICATION_PEER_AUTHENTICATION_REQUIRED'); this.#reader()
        if (kind === 'ready') {
          record(value, ['kind'])
          requireNetwork(!this.#confirmed, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
          this.#confirmed = true; this.#readyResolve()
          continue
        }
        requireNetwork(this.#confirmed, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
        if (kind === 'request') {
          const message = record(value, ['kind', 'message'])
          const request = this.#incomingMessage(message.message), id = Number(request.requestId)
          const method = methods.find(method => interests[method].facet === request.facet && interests[method].action === request.action)
          requireNetwork(Number.isSafeInteger(id) && String(id) === request.requestId && id > this.#lastRemoteRequest &&
            method !== undefined && this.#incoming < LIMITS.incomingRequests,
          'APPLICATION_NETWORK_REQUEST_INVALID')
          this.#lastRemoteRequest = id; this.#incoming++; this.#receivedRequests++
          void this.#respond(request, method).catch(error => this.#fail(error)).finally(() => { this.#incoming-- })
        } else if (kind === 'response') {
          const message = record(value, ['kind', 'ok', 'message']), response = this.#incomingMessage(message.message)
          const id = Number(response.requestId)
          requireNetwork(Number.isSafeInteger(id) && String(id) === response.requestId && typeof message.ok === 'boolean', 'APPLICATION_NETWORK_RESPONSE_INVALID')
          const pending = this.#pending.get(id)
          requireNetwork(pending !== undefined, 'APPLICATION_NETWORK_RESPONSE_INVALID')
          const payload = validateParticipantResponse(response, pending.request, PEER_PARTICIPANT_POLICY).payload
          // Keep the waiter registered until the whole reply is valid. Closing
          // a malformed response must still reject this request with the link.
          let failure: Error | undefined
          if (!message.ok) {
            requireNetwork(typeof payload === 'string' && /^[A-Z0-9_]{1,128}$/u.test(payload), 'APPLICATION_NETWORK_RESPONSE_INVALID')
            failure = pending.method !== 'state' && payload === 'APPLICATION_DATA_UNAVAILABLE'
              ? new PeerDataUnavailableError() : networkError(payload)
            if (isPeerDataUnavailable(failure)) { this.#remoteData = false; this.#remoteDataFailure = failure }
          }
          this.#pending.delete(id); pending.cancel()
          if (failure === undefined) pending.resolve(payload)
          else pending.reject(failure)
        } else if (kind === 'hint') {
          const message = this.#incomingMessage(record(value, ['kind', 'message']).message)
          requireNetwork(message.facet === 'ephemeral' && message.action === 'hint' && message.payload === null, 'APPLICATION_NETWORK_MESSAGE_INVALID')
          this.#kick()
        }
        else throw networkError('APPLICATION_NETWORK_MESSAGE_INVALID')
      }
    }
    throw networkError('APPLICATION_NETWORK_ENDED')
  }
  #incomingMessage(value: unknown): ParticipantRequest {
    const message = validateParticipantRequest(value, PEER_PARTICIPANT_POLICY)
    requireNetwork(message.applicationId === this.#port.participant.descriptor.applicationId, 'APPLICATION_NETWORK_SCOPE_MISMATCH')
    return message
  }
  async #readLive(lane: PeerLiveLane, route: SignalRoute): Promise<void> {
    try {
      for await (const frame of lane.frames(AbortSignal.any([this.signal, lane.signal]))) {
        this.#reader(); requireNetwork(frame instanceof Uint8Array && frame.length <= MAX_SIGNAL_BYTES, 'APPLICATION_NETWORK_LIVE_LIMIT')
        this.#receivedLiveBytes += frame.length
        if (!this.#retiring && this.#owner.peers.get(this.peerId) === this) await route.receive(frame)
        this.#reader()
      }
    } catch (error) { if (!this.signal.aborted && !lane.signal.aborted) throw error }
  }
  #request(method: Method, value: unknown): Promise<unknown> {
    this.#reader()
    if (this.#retiring) {
      const current = this.#owner.peers.get(this.peerId)
      requireNetwork(current !== undefined && current !== this, 'APPLICATION_PEER_RETIRED')
      return current.#request(method, value)
    }
    if (method !== 'state' && method !== 'openData' && !this.#remoteData)
      return this.#openRemoteData().then(() => this.#request(method, value))
    requireNetwork(this.#pending.size < LIMITS.pendingRequests && this.#nextRequest < Number.MAX_SAFE_INTEGER, 'APPLICATION_NETWORK_BACKPRESSURE')
    const id = ++this.#nextRequest
    const request = createParticipantRequest({ applicationId: this.#port.participant.descriptor.applicationId,
      requestId: String(id), ...interests[method], payload: value }, PEER_PARTICIPANT_POLICY)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(networkError('APPLICATION_NETWORK_REQUEST_TIMEOUT')), this.#requestMs)
      this.#pending.set(id, { method, request, resolve, reject, cancel: () => clearTimeout(timer) })
      void Promise.resolve().then(() => this.#wire.send({ kind: 'request', message: request }, () => {
        if (method === 'submit') requireSubmitter(this.#port.participant, this.#port.participant.device.publicKey, value)
        if (method === 'keyShare') requireNetwork((value as ApplicationKeyRequest).payload.recipient === this.#port.participant.device.publicKey,
          'APPLICATION_KEY_REQUEST_INVALID')
      })).then(() => { this.#sentRequests++ }).catch(error => {
        const pending = this.#pending.get(id)
        this.#pending.delete(id); pending?.cancel(); pending?.reject(error)
        if (!(error instanceof Error && ['APPLICATION_NETWORK_BACKPRESSURE', 'PEER_AUTHOR_FORBIDDEN'].includes(error.message))) this.#fail(error)
      })
    })
  }
  #openRemoteData(): Promise<void> {
    if (this.#remoteData === true) return Promise.resolve()
    if (this.#remoteDataFailure !== undefined) return Promise.reject(this.#remoteDataFailure)
    requireNetwork(this.#port.participant.data !== undefined, 'APPLICATION_DATA_NOT_ACTIVE')
    if (this.#remoteOpening !== undefined) return this.#remoteOpening
    const work = (async () => {
      await this.#readState()
      if (this.#remoteData === true) return
      // Actual data use may request the selected coordinator's service. A
      // background replica never opts an unrelated cold follower into storage.
      requireNetwork(this.peerId === this.#port.participant.generation.payload.coordinator, 'APPLICATION_DATA_NOT_ACTIVE')
      const value = await this.#request('openData', null)
      requireNetwork(value === null, 'APPLICATION_NETWORK_RESPONSE_INVALID')
      this.#reader(); this.#remoteData = true
    })().finally(() => { if (this.#remoteOpening === work) this.#remoteOpening = undefined })
    this.#remoteOpening = work; return work
  }
  async #readState(): Promise<RemoteState> {
    const base = await this.#currentAuthority()
    const response = record(await this.#request('state', this.#input.authorityExchange === 'bundle' ? null : await authoritySummary(base)), ['authority', 'data', 'point', 'revision'])
    const offered = response.authority
    const remote = offered !== null && typeof offered === 'object' && 'base' in offered
      ? await applyAuthoritySuffix(base, offered) : await verifyAuthorityBundle(offered as AuthorityBundle, base.signedDescriptor)
    requireNetwork(typeof response.data === 'boolean' && (response.data || response.point === null && response.revision === null), 'APPLICATION_NETWORK_STATE_INVALID')
    this.#remoteData = response.data
    if (response.data) this.#remoteDataFailure = undefined
    return { ...response, authority: remote } as unknown as RemoteState
  }
  async #respond(request: ParticipantRequest, method: Method): Promise<void> {
    try {
      this.#reader()
      const participant = this.#port.participant, input = request.payload
      let value: unknown
      if (method === 'state') {
        const authority = await this.#currentAuthority()
        const offered = input === null ? authority.bundle : await authoritySuffix(authority, validateSummary(input))
        const replica = participant.data?.replica, revision = replica?.ready === true ? replica.revision : null
        value = { authority: offered, data: replica !== undefined, point: revision?.point ?? availablePoint(replica), revision }
      } else value = await this.#serveData(method, input)
      this.#reader(); await this.#wire.send({ kind: 'response', ok: true, message: createParticipantResponse(request, value, PEER_PARTICIPANT_POLICY) })
    } catch (error) {
      this.#reader()
      const code = error instanceof Error && /^[A-Z0-9_]{1,128}$/u.test(error.message) ? error.message : 'APPLICATION_NETWORK_REQUEST_REJECTED'
      await this.#wire.send({ kind: 'response', ok: false, message: createParticipantResponse(request, code, PEER_PARTICIPANT_POLICY) })
    }
  }
  async #serveData(method: Exclude<Method, 'state'>, input: unknown): Promise<unknown> {
    const participant = this.#port.participant
    if (method === 'openData') {
      requireNetwork(input === null, 'APPLICATION_NETWORK_MESSAGE_INVALID')
      requireNetwork(participant.isCoordinator, 'PEER_NOT_COORDINATOR')
    }
    if (method === 'submit') {
      requireSubmitter(participant, this.peerId, input)
      requireNetwork(participant.isCoordinator, 'PEER_NOT_COORDINATOR')
    }
    // Only an explicit activation or a writer's submission requests coordinator
    // storage. Key exchange, range reads and coverage use an already active facet.
    const activate = method === 'openData' || method === 'submit'
    requireNetwork(activate || participant.data !== undefined, 'APPLICATION_DATA_NOT_ACTIVE')
    let data = participant.data
    if (activate) {
      try { data = await participant.openData() }
      catch {
        this.#reader()
        throw networkError('APPLICATION_DATA_UNAVAILABLE')
      }
    }
    requireNetwork(data !== undefined, 'APPLICATION_DATA_NOT_ACTIVE')
    this.#reader(); this.#attachData()
    if (method === 'openData') return null
    return useData(data, async () => {
      const replica = data.replica
      let value: unknown = null
      if (method === 'range') {
        const request = record(input, ['generation', 'after', 'through', 'at'])
        requireNetwork(request.generation === replica.generation.id, 'APPLICATION_NETWORK_STATE_CHANGED')
        if (request.after !== null) validateHistoryPoint(request.after as HistoryPoint)
        validateHistoryPoint(request.through as HistoryPoint)
        const authority = await verifyAuthorityBundle(replica.authority)
        const commands = await replica.exportCommands({ ...(request.after === null ? {} : { after: request.after as HistoryPoint }),
          ...(request.at === null ? {} : { at: request.at as PeerRevision }),
          limit: LIMITS.rangeCommands, maxBytes: LIMITS.rangeBytes })
        this.#reader(); requireNetwork(request.generation === replica.generation.id, 'APPLICATION_NETWORK_STATE_CHANGED')
        value = commands.filter(command => atOrAfter(authority, request.through as HistoryPoint,
          { generation: command.receipt.payload.generation, sequence: command.receipt.payload.sequence, root: command.receipt.root }))
      } else if (method === 'submit') {
        const attempt = input as SignedAttempt
        requireSubmitter(participant, this.peerId, attempt)
        await replica.order(attempt); this.#reader(); requireSubmitter(participant, this.peerId, attempt)
      } else if (method === 'coverage') {
        const request = record(input, ['generation', 'point'])
        validateHistoryPoint(request.point as HistoryPoint)
        // Coverage is evidence for the exact prefix the requester already owns,
        // never an unsolicited claim about a possibly advancing remote head.
        if (request.generation === replica.generation.id) {
          try { value = await replica.retainedCoverage(request.point as HistoryPoint) }
          catch (error) {
            // Enrollment can still be acquiring a rotated key on this same
            // link. Incomplete coverage is absence of evidence, not a broken peer.
            if (!(error instanceof Error && ['PEER_RECOVERY_PREFIX_INCOMPLETE', 'PEER_EPOCH_KEY_UNAVAILABLE'].includes(error.message))) throw error
          }
        }
      } else if (method === 'keyShare') {
        const request = input as ApplicationKeyRequest
        requireNetwork(request?.payload?.recipient === this.peerId, 'APPLICATION_KEY_REQUEST_INVALID')
        value = await data.keys.offer(request)
      } else if (method === 'contentManifest') value = await data.content.serveManifest(this.peerId, input as ContentReference)
      else if (method === 'contentChunk') {
        const request = record(input, ['reference', 'index'])
        requireNetwork(Number.isSafeInteger(request.index), 'APPLICATION_CONTENT_CHUNK_INVALID')
        const bytes = await data.content.serveChunk(this.peerId, request.reference as ContentReference, request.index as number)
        value = bytes === null ? null : bytesToHex(bytes)
      } else if (method === 'contentRetained') value = await data.content.retained(input as ContentReference)
      else {
        const receipt = input as ContentRetention
        requireNetwork(receipt?.payload?.peer === this.peerId, 'CONTENT_RETENTION_INVALID')
        await data.content.observeRetention(receipt)
      }
      return value
    })
  }
  synchronize(): Promise<void> {
    this.#reader()
    if (this.#retiring) {
      const current = this.#owner.peers.get(this.peerId)
      requireNetwork(current !== undefined && current !== this, 'APPLICATION_PEER_RETIRED')
      return current.synchronize()
    }
    if (this.#sync === undefined) return this.#startPull()
    if (this.#nextSync !== undefined) return this.#nextSync
    // An explicit barrier must observe a head advertised after this call. Joining
    // an older background pull could report success before a newly ordered body.
    const next = this.#sync.then(() => {
      this.#nextSync = undefined; this.#reader(); return this.#startPull()
    }).finally(() => { if (this.#nextSync === next) this.#nextSync = undefined })
    this.#nextSync = next; return next
  }
  #startPull(): Promise<void> {
    const task = this.#pull().catch((error: unknown) => {
      // Validation retirement belongs to the pull, not its observer. Explicit
      // synchronize() must fence the same invalid peer as a background hint.
      if (!isPeerDataUnavailable(error) && !retryablePull(error)) this.#fail(error)
      throw error
    }).finally(() => {
      if (this.#sync === task) this.#sync = undefined
      if (this.#syncAgain && this.#nextSync === undefined && !this.signal.aborted && !this.#retiring) { this.#syncAgain = false; this.#kick() }
      if (!this.signal.aborted && !this.#retiring && this.#port.participant.data?.replica.ready === true) void this.#port.resume().catch(() => undefined)
    })
    this.#sync = task; return task
  }
  async #pull(opened = false): Promise<void> {
    const requestedAt = Date.now(), participant = this.#port.participant
    const response = await this.#readState()
    const remote = response.authority
    const local = await this.#currentAuthority()
    this.#reader()
    const latest = newest(local, remote)
    if (latest !== local) await participant.adoptAuthority(latest.bundle)
    this.#knownAuthority = latest
    this.#reader()
    const target = transferTarget(remote, latest, response.point)
    const at = response.revision !== null && remote.current?.id === latest.current?.id ? response.revision : null
    if (at !== null) {
      validateHistoryPoint(at.point)
      requireNetwork(at.applicationId === participant.descriptor.applicationId && at.historyId === participant.descriptor.historyId &&
        at.generation === remote.current?.id && at.point.generation === at.generation &&
        at.controlRevision === remote.current.payload.controlRevision && (at.point.sequence === 0 || same(at.point, target)),
      'APPLICATION_NETWORK_STATE_INVALID')
    }
    // A cold connection exchanges authority and live signals only. An active
    // remote announcement never opts this participant into durable storage.
    const data = participant.data
    if (data === undefined) return
    if (!response.data && this.peerId !== participant.generation.payload.coordinator) return
    if (!response.data) {
      requireNetwork(!opened, 'APPLICATION_NETWORK_STATE_CHANGED')
      await this.#openRemoteData(); return this.#pull(true)
    }
    await useData(data, async () => {
      const replica = data.replica
      await data.keys.ensure()
      this.#reader()
      let after = availablePoint(replica)
      if (after !== null && !remote.contains(after)) after = null
      const peer = this
      async function* pages(): AsyncGenerator<readonly OrderedCommand[]> {
        const retained = availablePoint(replica)
        if (target === null || retained !== null && atOrAfter(latest, retained, target)) return
        for (;;) {
          const input = await peer.#request('range', { generation: remote.current!.id, after, through: target, at })
          requireNetwork(Array.isArray(input) && input.length > 0 && input.length <= LIMITS.rangeCommands && encodePeerValue(input).length <= LIMITS.rangeBytes,
            'APPLICATION_NETWORK_RANGE_INVALID')
          const commands = input as readonly OrderedCommand[]
          let point = after
          // Reject an overrun or non-progressing page before any durable write.
          // The replica then verifies every original signature and chain link.
          for (const command of commands) {
            const receipt = command?.receipt
            requireNetwork(receipt?.payload !== undefined, 'APPLICATION_NETWORK_RANGE_INVALID')
            const next = { generation: receipt.payload.generation, sequence: receipt.payload.sequence, root: receipt.root }
            requireNetwork((point === null || !atOrAfter(latest, point, next)) && atOrAfter(latest, target, next) &&
              (!atOrAfter(latest, next, target) || same(next, target)),
              'APPLICATION_NETWORK_RANGE_INVALID')
            point = next
          }
          yield commands
          peer.#reader()
          after = point
          if (same(point, target)) break
        }
      }
      if (at !== null) await replica.synchronize(latest.bundle, pages(), { at })
      else {
        for await (const commands of pages()) await replica.receiveHistory(latest.bundle, commands)
        // Installing a key can make an already retained selected prefix usable.
        if (!replica.ready) await replica.receiveHistory(latest.bundle, [])
      }
      this.#reader()
      if (replica.ready) {
        const generation = replica.generation.id, point = at?.point ?? target ?? replica.revision.point
        const remoteCoverage = await this.#request('coverage', { generation, point })
        if (remoteCoverage !== null) {
          const coverage = remoteCoverage as SignedRetainedCoverage
          requireNetwork(coverage.payload?.peer === this.peerId && coverage.payload.generation === generation &&
            same(coverage.payload.point, point), 'PEER_COVERAGE_INVALID')
          if (replica.ready && replica.generation.id === generation) await replica.observeCoverage(coverage)
        }
        this.#reader()
      }
      if (at !== null && replica.generation.id === at.generation && this.peerId === replica.generation.payload.coordinator) {
        this.#reader()
        this.#port.observeHead?.(this.peerId, structuredClone(at), requestedAt)
      }
    })
  }
  #kick(): void {
    if (this.signal.aborted || this.#retiring) return
    if (this.#sync !== undefined) { this.#syncAgain = true; return }
    void this.#startPull().then(() => { this.#stateRetries = 0 }).catch(error => {
      if (isPeerDataUnavailable(error)) return
      if (retryablePull(error) && this.#stateRetries++ < 2) this.#kick()
      else this.#fail(error)
    })
  }
  #changed(): void {
    try {
      this.#reader()
      if (this.#retiring) return
      const activated = this.#attachData(), participant = this.#port.participant, replica = participant.data?.replica
      const key = `${participant.generation.id}/${participant.authority.controls.at(-1)!.payload.revision}/${replica === undefined ? 'inactive' : 'active'}/${availablePoint(replica)?.root ?? ''}/${replica?.ready ?? false}`
      if (key !== this.#lastHint) { this.#lastHint = key; this.#sendHint() }
      if (activated) this.#kick()
    } catch (error) { this.#fail(error) }
  }
  #sendHint(): void {
    if (this.#hintPending || this.signal.aborted || this.#retiring) return
    this.#hintPending = true
    const advertised = this.#lastHint
    const message = createParticipantRequest({ applicationId: this.#port.participant.descriptor.applicationId,
      requestId: 'hint', facet: 'ephemeral', action: 'hint', payload: null }, PEER_PARTICIPANT_POLICY)
    void Promise.resolve().then(() => { if (!this.#retiring) return this.#wire.send({ kind: 'hint', message }) }).catch(error => this.#fail(error)).finally(() => {
      this.#hintPending = false
      // A response may have captured an older head while this write completed.
      if (this.#lastHint !== advertised) this.#sendHint()
    })
  }
  #fail(error: unknown): void { void this.#dispose(error) }
  #dispose(error?: unknown): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    let closed!: () => void
    this.#closeTask = new Promise(resolve => { closed = resolve })
    const reason = error ?? networkError('APPLICATION_NETWORK_CLOSED')
    if (this.#drainTimer !== undefined) clearTimeout(this.#drainTimer)
    this.#drainTimer = undefined
    if (this.#owner.retiring.get(this.peerId) === this) this.#owner.retiring.delete(this.peerId)
    this.#controller.abort(reason); this.#channel.clear(); this.#readyReject(reason)
    for (const pending of this.#pending.values()) { pending.cancel(); pending.reject(reason) }
    this.#pending.clear(); this.#detach?.(); this.#detachContent?.(); this.#detachKeys?.(); this.#unsubscribe?.(); this.#route?.close(); this.#disposeLive?.()
    for (const dispose of this.#disposeListeners) dispose()
    this.#disposeListeners = []
    if (this.#owner.peers.get(this.peerId) === this) this.#owner.peers.delete(this.peerId)
    if (error === undefined) this.#completeResolve(); else this.#completeReject(error)
    // The lifetime and attachments are fenced synchronously. A broken transport
    // cannot prevent the application owner from shutting down.
    const deadline = timeout(1000, 'APPLICATION_NETWORK_CLOSE_TIMEOUT')
    void interruptible(Promise.resolve().then(() => this.#input.connection.close()), deadline.signal)
      .catch(() => undefined).finally(() => { deadline.cancel(); closed() })
    return this.#closeTask
  }
  retire(): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    if (this.#retiring) return this.completion
    this.#reader(); this.#retiring = true; this.#syncAgain = false
    // One draining connection per identity and at most LIMITS.peers overall.
    // Churn may evict an earlier drain, but can never grow an unbounded tail.
    const previous = this.#owner.retiring.get(this.peerId)
    if (previous !== undefined && previous !== this) void previous.close()
    if (this.#owner.retiring.size >= LIMITS.peers) void this.#owner.retiring.values().next().value?.close()
    this.#owner.retiring.set(this.peerId, this)
    if (this.#owner.peers.get(this.peerId) === this) this.#owner.peers.delete(this.peerId)
    // Detach before publishing the replacement's sources/live route. The
    // authority subscription stays until close so revocation still fences RPCs.
    this.#detach?.(); this.#detach = undefined
    this.#detachContent?.(); this.#detachContent = undefined
    this.#detachKeys?.(); this.#detachKeys = undefined
    this.#route?.close()
    // Keep the physical live lane until final close: transports may share its
    // lifetime with reliable RPC. Retired receive loops discard live frames.
    // Even a locally idle link may have a remote request or reply in transit.
    // A single absolute deadline covers that race without heartbeats or polling.
    this.#drainTimer = setTimeout(() => { void this.#dispose() }, this.#drainMs)
    return this.completion
  }
  close(): Promise<void> { return this.#dispose() }
}

export function connectedApplicationPeers(port: ApplicationPeerPort): readonly ApplicationPeerLink[] {
  return [...owners.get(port)?.peers.values() ?? []]
}

export async function connectApplicationPeer(port: ApplicationPeerPort, input: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
  let owner = owners.get(port)
  if (owner === undefined) { owner = { next: 0, openings: new Map(), accepted: new Map(), peers: new Map(), retiring: new Map() }; owners.set(port, owner) }
  requireNetwork(owner.openings.size < LIMITS.peers && owner.next < Number.MAX_SAFE_INTEGER, 'APPLICATION_PEER_LIMIT')
  const attempt = ++owner.next, peer = new NetworkPeer(port, input, owner, attempt)
  owner.openings.set(peer, attempt)
  try { await peer.open(); return peer }
  catch (error) { await peer.close(); throw error }
  finally {
    owner.openings.delete(peer)
    const oldest = Math.min(...owner.openings.values())
    for (const [key, accepted] of owner.accepted) if (!owner.peers.has(key) && accepted < oldest) owner.accepted.delete(key)
  }
}
export async function connectApplicationPeerPair(left: ApplicationPeerPort, right: ApplicationPeerPort): Promise<{
  synchronize(): Promise<void>; close(): Promise<void>
}> {
  requireNetwork(left !== right, 'APPLICATION_PEER_SELF')
  const [a, b] = createFramedPeerConnectionPair()
  const links = await Promise.allSettled([
    connectApplicationPeer(left, { connection: a, peerIdentity: right.participant.device.publicKey }),
    connectApplicationPeer(right, { connection: b, peerIdentity: left.participant.device.publicKey }),
  ])
  if (links[0].status !== 'fulfilled' || links[1].status !== 'fulfilled') {
    await Promise.all([a.close(), b.close()]); throw (links.find(value => value.status === 'rejected') as PromiseRejectedResult).reason
  }
  const first = links[0].value, second = links[1].value
  const close = async (): Promise<void> => { const x = first.close(), y = second.close(); await Promise.all([x, y]) }
  try {
    await Promise.all([first.synchronize(), second.synchronize()])
    return { synchronize: async () => { await Promise.all([first.synchronize(), second.synchronize()]) }, close }
  } catch (error) { await close(); throw error }
}

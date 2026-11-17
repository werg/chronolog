import {
  encodePeerValue, peerDigest, verifyAuthorityBundle, validateHistoryPoint,
  type AuthorityBundle, type HistoryPoint, type OrderedCommand, type PeerAuthority, type PeerReplica,
  type PeerRevision, type SignedAttempt, type SignedRetainedCoverage,
} from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes, signDomain, verifyDomain, DOMAINS } from '@chronolog/protocol'
import { MAX_SIGNAL_BYTES, type SignalChannel, type SignalRoute } from '@chronolog/signals'
import type { ApplicationContent, ContentManifest, ContentReference, ContentRetention } from './content.js'
import type { ApplicationKeyring, ApplicationKeyRequest, ApplicationKeyShare } from './keys.js'
import {
  APPLICATION_NETWORK_LIMITS as LIMITS, ApplicationMessageWire, createFramedPeerConnectionPair,
  interruptible, networkError, record, requireNetwork, timeout,
  type FramedPeerConnection, type PeerLiveLane,
} from './network-wire.js'

export { APPLICATION_NETWORK_LIMITS, createFramedPeerConnectionPair } from './network-wire.js'
export type { FramedPeerConnection, PeerLiveLane } from './network-wire.js'
export interface ApplicationPeerLink {
  readonly peerId: string
  readonly signal: AbortSignal
  readonly completion: Promise<void>
  readonly stats: { readonly sentBytes: number; readonly receivedBytes: number; readonly sentRequests: number; readonly receivedRequests: number }
  synchronize(): Promise<void>
  close(): Promise<void>
}
/** Internal owner port: every attachment has already proved the remote key. */
export interface ApplicationPeerPort {
  readonly replica: PeerReplica
  readonly signals: SignalChannel
  readonly content: ApplicationContent
  readonly keys: ApplicationKeyring
  readonly signal: AbortSignal
  attach(peerId: string, submit: (attempt: SignedAttempt) => Promise<void>, link: { close(): Promise<void> }): () => void
  resume(): Promise<void>
}
export interface ApplicationPeerConnectOptions {
  readonly connection: FramedPeerConnection
  readonly peerIdentity?: string
  readonly signal?: AbortSignal
  readonly handshakeTimeoutMs?: number
  readonly requestTimeoutMs?: number
  readonly transferTimeoutMs?: number
}
interface Hello { readonly application: string; readonly profile: 'peer-generation-v1'; readonly descriptor: string; readonly author: string; readonly nonce: string; readonly authority: AuthorityBundle }
interface RemoteState { readonly authority: AuthorityBundle; readonly point: HistoryPoint | null; readonly revision: PeerRevision | null }
type Method = 'state' | 'range' | 'submit' | 'coverage' | 'keyShare' | 'contentManifest' | 'contentChunk' | 'contentRetained' | 'contentObserveRetention'
const methods: readonly Method[] = ['state', 'range', 'submit', 'coverage', 'keyShare', 'contentManifest', 'contentChunk', 'contentRetained', 'contentObserveRetention']
interface Pending { resolve(value: unknown): void; reject(error: unknown): void; cancel(): void }
interface Owner { next: number; readonly openings: Map<NetworkPeer, number>; readonly accepted: Map<string, number>; readonly peers: Map<string, NetworkPeer> }
const owners = new WeakMap<ApplicationPeerPort, Owner>()
const hexadecimal = (value: unknown, length = 64): value is string => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/u.test(value)
const same = (a: unknown, b: unknown): boolean => bytesToHex(encodePeerValue(a)) === bytesToHex(encodePeerValue(b))
function grant(replica: PeerReplica, key: string, role: 'reader' | 'writer'): boolean {
  return replica.grant(key)?.[role] === true
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
  const a = left.bundle, b = right.bundle
  requireNetwork(same(a.descriptor, b.descriptor), 'APPLICATION_NETWORK_SCOPE_MISMATCH')
  const [old, current] = a.generations.length <= b.generations.length ? [a, b] : [b, a]
  requireNetwork(current.controls.length >= old.controls.length && old.controls.every((value, index) => same(value, current.controls[index])) &&
    old.generations.every((value, index) => same(value, current.generations[index])), 'PEER_CONTROL_EQUIVOCATION')
  return current === b ? right : left
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
  readonly #pending = new Map<number, Pending>()
  readonly #requestMs: number
  readonly #handshakeMs: number
  readonly #ready: Promise<void>
  readonly completion: Promise<void>
  #readyResolve!: () => void
  #readyReject!: (error: unknown) => void
  #completeResolve!: () => void
  #completeReject!: (error: unknown) => void
  #local: Hello | undefined
  #remote: Hello | undefined
  #authenticated = false
  #nextRequest = 0
  #lastRemoteRequest = 0
  #sentRequests = 0
  #receivedRequests = 0
  #incoming = 0
  #route: SignalRoute | undefined
  #detach: (() => void) | undefined
  #detachContent: (() => void) | undefined
  #detachKeys: (() => void) | undefined
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

  constructor(port: ApplicationPeerPort, input: ApplicationPeerConnectOptions, owner: Owner, attempt: number) {
    this.#port = port; this.#input = input; this.#owner = owner; this.#attempt = attempt
    this.#requestMs = deadline(input.requestTimeoutMs, 120_000); this.#handshakeMs = deadline(input.handshakeTimeoutMs, 10_000)
    this.#wire = new ApplicationMessageWire(input.connection, this.signal, deadline(input.transferTimeoutMs, 30_000), () => {
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
  get signal(): AbortSignal { return this.#controller.signal }
  get stats(): ApplicationPeerLink['stats'] {
    return { ...this.#wire.stats, sentRequests: this.#sentRequests, receivedRequests: this.#receivedRequests }
  }
  #reader(): void {
    this.signal.throwIfAborted()
    requireNetwork(this.#remote !== undefined && grant(this.#port.replica, this.peerId, 'reader') &&
      grant(this.#port.replica, this.#port.replica.device.publicKey, 'reader'), 'APPLICATION_PEER_NOT_AUTHORIZED')
  }
  async open(): Promise<void> {
    const replica = this.#port.replica
    requireNetwork(this.#input.peerIdentity === undefined || hexadecimal(this.#input.peerIdentity), 'APPLICATION_PEER_IDENTITY_INVALID')
    requireNetwork(grant(replica, replica.device.publicKey, 'reader'), 'APPLICATION_PEER_NOT_AUTHORIZED')
    this.#local = { application: replica.descriptor.applicationId, profile: 'peer-generation-v1',
      descriptor: await peerDigest(replica.authority.descriptor), author: replica.device.publicKey,
      nonce: bytesToHex(crypto.getRandomValues(new Uint8Array(32))), authority: replica.authority }
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
      if (previous !== undefined) void previous.close()
      this.#detach = this.#port.attach(this.peerId, async attempt => {
        this.#reader()
        requireNetwork(attempt.payload.header.author === replica.device.publicKey && grant(replica, replica.device.publicKey, 'writer'), 'PEER_AUTHOR_FORBIDDEN')
        await this.#request('submit', attempt)
        this.#reader(); await this.synchronize()
      }, this)
      this.#detachContent = this.#port.content.attachSource(this.peerId, {
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
      this.#detachKeys = this.#port.keys.attachSource(this.peerId, async request => {
        const share = await this.#request('keyShare', request) as ApplicationKeyShare
        this.#reader()
        requireNetwork(share?.payload?.issuer === this.peerId, 'APPLICATION_KEY_SHARE_INVALID')
        return share
      })
      if (this.#input.connection.live !== undefined) {
        const lane = this.#input.connection.live
        this.#route = this.#port.signals.attachRoute({ close: () => this.close(), trySend: async (frame, { signal }) => {
          signal.throwIfAborted(); this.#reader()
          const accepted = await lane.trySend(frame, { signal: AbortSignal.any([signal, this.signal]) })
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
      this.#unsubscribe = replica.subscribe(() => this.#changed())
      this.#changed()
    } catch (error) { this.#fail(error); throw error }
    finally { handshake.cancel() }
  }
  async #read(): Promise<void> {
    for await (const value of this.#wire.messages()) {
      this.signal.throwIfAborted()
      requireNetwork(value !== null && typeof value === 'object' && 'kind' in value, 'APPLICATION_NETWORK_MESSAGE_INVALID')
      const kind = value.kind
      if (kind === 'hello') {
        const message = record(value, ['kind', 'value']), input = record(message.value, ['application', 'profile', 'descriptor', 'author', 'nonce', 'authority'])
        const local = this.#local
        requireNetwork(local !== undefined, 'APPLICATION_NETWORK_HANDSHAKE_ORDER')
        requireNetwork(this.#remote === undefined && input.application === local.application && input.profile === local.profile &&
          input.descriptor === local.descriptor && hexadecimal(input.author) && hexadecimal(input.nonce) &&
          input.author !== local.author && (this.#input.peerIdentity === undefined || input.author === this.#input.peerIdentity), 'APPLICATION_NETWORK_SCOPE_MISMATCH')
        // Public authority evidence is authenticated independently of its relay.
        // Learn a new reader grant before requiring that reader's fresh proof.
        const remote = await verifyAuthorityBundle(input.authority as AuthorityBundle, this.#port.replica.authority.descriptor)
        this.signal.throwIfAborted()
        const current = await verifyAuthorityBundle(this.#port.replica.authority)
        this.signal.throwIfAborted()
        const latest = newest(current, remote)
        if (!same(latest.bundle, current.bundle)) await this.#port.replica.receiveHistory(latest.bundle, [])
        this.signal.throwIfAborted()
        this.#remote = input as unknown as Hello
        this.#reader()
        const signature = await signDomain(DOMAINS.peerConnection, encodePeerValue({ sender: this.#local, receiver: this.#remote }), this.#port.replica.device.privateKey)
        this.#reader()
        // Continue reading while the other endpoint applies stream backpressure.
        // Both peers may be waiting to send their proof at this exact boundary.
        void this.#wire.send({ kind: 'proof', signature: bytesToHex(signature) }, () => this.#reader()).catch(error => this.#fail(error))
      } else if (kind === 'proof') {
        const message = record(value, ['kind', 'signature'])
        requireNetwork(!this.#authenticated && this.#remote !== undefined && hexadecimal(message.signature, 128), 'APPLICATION_PEER_PROOF_INVALID')
        requireNetwork(await verifyDomain(DOMAINS.peerConnection, encodePeerValue({ sender: this.#remote, receiver: this.#local }),
          hexToBytes(message.signature), hexToBytes(this.peerId)), 'APPLICATION_PEER_PROOF_INVALID')
        this.#reader(); this.#authenticated = true; this.#readyResolve()
      } else {
        requireNetwork(this.#authenticated, 'APPLICATION_PEER_AUTHENTICATION_REQUIRED'); this.#reader()
        if (kind === 'request') {
          const message = record(value, ['kind', 'id', 'method', 'value'])
          requireNetwork(Number.isSafeInteger(message.id) && (message.id as number) > this.#lastRemoteRequest &&
            methods.includes(message.method as Method) && this.#incoming < LIMITS.incomingRequests,
          'APPLICATION_NETWORK_REQUEST_INVALID')
          this.#lastRemoteRequest = message.id as number; this.#incoming++; this.#receivedRequests++
          void this.#respond(message.id as number, message.method as Method, message.value).catch(error => this.#fail(error)).finally(() => { this.#incoming-- })
        } else if (kind === 'response') {
          const message = record(value, ['kind', 'id', 'ok', 'value'])
          requireNetwork(Number.isSafeInteger(message.id) && typeof message.ok === 'boolean', 'APPLICATION_NETWORK_RESPONSE_INVALID')
          const pending = this.#pending.get(message.id as number)
          requireNetwork(pending !== undefined, 'APPLICATION_NETWORK_RESPONSE_INVALID')
          this.#pending.delete(message.id as number); pending.cancel()
          if (message.ok) pending.resolve(message.value)
          else { requireNetwork(typeof message.value === 'string' && /^[A-Z0-9_]{1,128}$/u.test(message.value), 'APPLICATION_NETWORK_RESPONSE_INVALID'); pending.reject(networkError(message.value)) }
        } else if (kind === 'hint') { record(value, ['kind']); this.#kick() }
        else throw networkError('APPLICATION_NETWORK_MESSAGE_INVALID')
      }
    }
    throw networkError('APPLICATION_NETWORK_ENDED')
  }
  async #readLive(lane: PeerLiveLane, route: SignalRoute): Promise<void> {
    try {
      for await (const frame of lane.frames(AbortSignal.any([this.signal, lane.signal]))) {
        this.#reader(); requireNetwork(frame instanceof Uint8Array && frame.length <= MAX_SIGNAL_BYTES, 'APPLICATION_NETWORK_LIVE_LIMIT')
        await route.receive(frame); this.#reader()
      }
    } catch (error) { if (!this.signal.aborted && !lane.signal.aborted) throw error }
  }
  #request(method: Method, value: unknown): Promise<unknown> {
    this.#reader()
    requireNetwork(this.#pending.size < LIMITS.pendingRequests && this.#nextRequest < Number.MAX_SAFE_INTEGER, 'APPLICATION_NETWORK_BACKPRESSURE')
    const id = ++this.#nextRequest
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#fail(networkError('APPLICATION_NETWORK_REQUEST_TIMEOUT')), this.#requestMs)
      this.#pending.set(id, { resolve, reject, cancel: () => clearTimeout(timer) })
      void Promise.resolve().then(() => this.#wire.send({ kind: 'request', id, method, value }, () => {
        if (method === 'submit') requireNetwork(grant(this.#port.replica, this.#port.replica.device.publicKey, 'writer'), 'PEER_AUTHOR_FORBIDDEN')
        if (method === 'keyShare') requireNetwork((value as ApplicationKeyRequest).payload.recipient === this.#port.replica.device.publicKey,
          'APPLICATION_KEY_REQUEST_INVALID')
      })).then(() => { this.#sentRequests++ }).catch(error => {
        const pending = this.#pending.get(id)
        this.#pending.delete(id); pending?.cancel(); pending?.reject(error)
        if (!(error instanceof Error && ['APPLICATION_NETWORK_BACKPRESSURE', 'PEER_AUTHOR_FORBIDDEN'].includes(error.message))) this.#fail(error)
      })
    })
  }
  async #respond(id: number, method: Method, input: unknown): Promise<void> {
    try {
      this.#reader(); const replica = this.#port.replica
      let value: unknown = null
      if (method === 'state') {
        requireNetwork(input === null, 'APPLICATION_NETWORK_MESSAGE_INVALID')
        const revision = replica.ready ? replica.revision : null
        value = { authority: replica.authority, point: revision?.point ?? replica.retainedPoint, revision }
      }
      else if (method === 'range') {
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
        requireNetwork(attempt?.payload?.header?.author === this.peerId && grant(replica, this.peerId, 'writer'), 'PEER_AUTHOR_FORBIDDEN')
        await replica.order(attempt); this.#reader(); requireNetwork(grant(replica, this.peerId, 'writer'), 'PEER_AUTHOR_FORBIDDEN')
      } else if (method === 'coverage') {
        const request = record(input, ['generation', 'point'])
        validateHistoryPoint(request.point as HistoryPoint)
        // Coverage is evidence for the exact prefix the requester already owns,
        // never an unsolicited claim about a possibly advancing remote head.
        if (request.generation === replica.generation.id) {
          try { value = await replica.retainedCoverage(request.point as HistoryPoint) }
          catch (error) {
            if (!(error instanceof Error && error.message === 'PEER_RECOVERY_PREFIX_INCOMPLETE')) throw error
          }
        }
      } else if (method === 'keyShare') {
        const request = input as ApplicationKeyRequest
        requireNetwork(request?.payload?.recipient === this.peerId, 'APPLICATION_KEY_REQUEST_INVALID')
        value = await this.#port.keys.offer(request)
      } else if (method === 'contentManifest') value = await this.#port.content.serveManifest(this.peerId, input as ContentReference)
      else if (method === 'contentChunk') {
        const request = record(input, ['reference', 'index'])
        requireNetwork(Number.isSafeInteger(request.index), 'APPLICATION_CONTENT_CHUNK_INVALID')
        const bytes = await this.#port.content.serveChunk(this.peerId, request.reference as ContentReference, request.index as number)
        value = bytes === null ? null : bytesToHex(bytes)
      } else if (method === 'contentRetained') value = await this.#port.content.retained(input as ContentReference)
      else {
        const receipt = input as ContentRetention
        requireNetwork(receipt?.payload?.peer === this.peerId, 'CONTENT_RETENTION_INVALID')
        await this.#port.content.observeRetention(receipt)
      }
      this.#reader(); await this.#wire.send({ kind: 'response', id, ok: true, value })
    } catch (error) {
      this.#reader()
      const code = error instanceof Error && /^[A-Z0-9_]{1,128}$/u.test(error.message) ? error.message : 'APPLICATION_NETWORK_REQUEST_REJECTED'
      await this.#wire.send({ kind: 'response', id, ok: false, value: code })
    }
  }
  synchronize(): Promise<void> {
    this.#reader()
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
    const task = this.#pull().finally(() => {
      if (this.#sync === task) this.#sync = undefined
      if (this.#syncAgain && this.#nextSync === undefined && !this.signal.aborted) { this.#syncAgain = false; this.#kick() }
      if (!this.signal.aborted && this.#port.replica.ready) void this.#port.resume().catch(() => undefined)
    })
    this.#sync = task; return task
  }
  async #pull(): Promise<void> {
    const response = record(await this.#request('state', null), ['authority', 'point', 'revision']) as unknown as RemoteState
    const replica = this.#port.replica
    const remote = await verifyAuthorityBundle(response.authority, replica.authority.descriptor)
    const local = await verifyAuthorityBundle(replica.authority)
    this.#reader()
    const latest = newest(local, remote), target = transferTarget(remote, latest, response.point)
    if (!same(latest.bundle, local.bundle)) await replica.receiveHistory(latest.bundle, [])
    this.#reader()
    await this.#port.keys.ensure()
    this.#reader()
    let after = replica.retainedPoint
    if (after !== null && !remote.contains(after)) after = null
    const at = response.revision !== null && remote.current?.id === latest.current?.id ? response.revision : null
    if (at !== null) {
      validateHistoryPoint(at.point)
      requireNetwork(at.applicationId === replica.descriptor.applicationId && at.historyId === replica.descriptor.historyId &&
        at.generation === remote.current?.id && at.point.generation === at.generation &&
        at.controlRevision === remote.current.payload.controlRevision && (at.point.sequence === 0 || same(at.point, target)),
      'APPLICATION_NETWORK_STATE_INVALID')
    }
    const peer = this
    async function* pages(): AsyncGenerator<readonly OrderedCommand[]> {
      if (target === null || replica.retainedPoint !== null && atOrAfter(latest, replica.retainedPoint, target)) return
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
  }
  #kick(): void {
    if (this.signal.aborted) return
    if (this.#sync !== undefined) { this.#syncAgain = true; return }
    void this.#startPull().then(() => { this.#stateRetries = 0 }).catch(error => {
      if (error instanceof Error && ['APPLICATION_NETWORK_STATE_CHANGED', 'PEER_AUTHORITY_REGRESSION', 'PEER_CURSOR_RECOVERY_REQUIRED',
        'PEER_VIEW_RECOVERY_REQUIRED', 'APPLICATION_KEY_REQUEST_EXPIRED'].includes(error.message) &&
          this.#stateRetries++ < 2) this.#kick()
      else this.#fail(error)
    })
  }
  #changed(): void {
    try {
      this.#reader()
      const replica = this.#port.replica, key = `${replica.generation.id}/${replica.retainedPoint?.root ?? ''}/${replica.ready}`
      if (key === this.#lastHint) return
      this.#lastHint = key
      this.#sendHint()
    } catch (error) { this.#fail(error) }
  }
  #sendHint(): void {
    if (this.#hintPending || this.signal.aborted) return
    this.#hintPending = true
    const advertised = this.#lastHint
    void Promise.resolve().then(() => this.#wire.send({ kind: 'hint' })).catch(error => this.#fail(error)).finally(() => {
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
    this.#controller.abort(reason); this.#readyReject(reason)
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
  close(): Promise<void> { return this.#dispose() }
}

export async function connectApplicationPeer(port: ApplicationPeerPort, input: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
  let owner = owners.get(port)
  if (owner === undefined) { owner = { next: 0, openings: new Map(), accepted: new Map(), peers: new Map() }; owners.set(port, owner) }
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
    connectApplicationPeer(left, { connection: a, peerIdentity: right.replica.device.publicKey }),
    connectApplicationPeer(right, { connection: b, peerIdentity: left.replica.device.publicKey }),
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

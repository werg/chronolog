import {
  createParticipantRequest, decodePeerValue, encodePeerValue, peerDigest, validateHistoryPoint, verifyAuthorityBundle,
  type HistoryPoint, type PeerReplica, type PeerRevision,
} from '@chronolog/peer-generation'
import type { BytesStore, FramedPeerConnection } from '@chronolog/records'
import type { ApplicationPeerConnectOptions, ApplicationPeerLink } from './network.js'
import type { ApplicationRecovery, ApplicationRecoveryExpectation } from './recovery.js'
import { awaitOwnedTask } from './lifetime.js'
import type {
  ApplicationParticipation, ApplicationParticipationOptions, ApplicationParticipationStatus,
  ApplicationPeerHint, ApplicationPeerInvitation, ApplicationRecoveryProposal,
} from './participation-types.js'

interface Owner {
  readonly replica: PeerReplica
  readonly recovery: ApplicationRecovery
  readonly store: BytesStore
  readonly signal: AbortSignal
  connect(options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink>
  links(): readonly ApplicationPeerLink[]
  resume(): Promise<void>
}
interface Observation { readonly generation: string; readonly point: HistoryPoint; readonly observedAt: number }
interface Joining { readonly controller: AbortController; readonly incoming: boolean; readonly finished: Promise<void> }
const identity = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value)
const samePoint = (left: HistoryPoint, right: HistoryPoint): boolean => left.generation === right.generation && left.sequence === right.sequence && left.root === right.root
const message = (error: unknown): string => error instanceof Error ? error.message : 'APPLICATION_PARTICIPATION_FAILED'
function bound(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  const selected = value ?? fallback
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) throw new Error('APPLICATION_PARTICIPATION_OPTIONS_INVALID')
  return selected
}

/** One session owner for discovery, connection attempts and verified recovery policy. */
export class OwnedApplicationParticipation implements ApplicationParticipation {
  readonly #owner: Owner
  readonly #options: ApplicationParticipationOptions
  readonly #lifetime = new AbortController()
  readonly signal: AbortSignal
  readonly #maxPeers: number
  readonly #initialRetry: number
  readonly #maximumRetry: number
  readonly #advertiseMs: number
  readonly #graceMs: number
  readonly #freshnessMs: number
  readonly #timeoutMs: number
  readonly #observationKey: string
  readonly #listeners = new Set<(status: ApplicationParticipationStatus) => void>()
  readonly #calls = new Map<string, Promise<unknown>>()
  readonly #joining = new Map<string, Joining>()
  readonly #physicalOpenings = new Set<symbol>()
  readonly #ownedLinks = new Set<ApplicationPeerLink>()
  readonly #watchedLinks = new Map<ApplicationPeerLink, () => void>()
  readonly #task: Promise<void>
  readonly #invitations: Promise<void>
  readonly #unsubscribe: () => void
  #status: ApplicationParticipationStatus = { phase: 'connecting', connectedPeers: [], recovery: null, error: null }
  #observation: Observation | null = null
  #pendingObservation: Observation | null = null
  #persistence: Promise<void> | undefined
  #proposal: ApplicationRecoveryProposal | null = null
  #approved: string | null = null
  #wakePending = false
  #wakeWait: (() => void) | undefined
  #nextScan = 0
  #nextAdvertisement = 0
  #missingSince: number | null = null
  #retry = 0
  #initial = true
  #generation: string
  #error: string | null = null
  #closed: Promise<void> | undefined

  constructor(owner: Owner, input: ApplicationParticipationOptions) {
    this.#owner = owner
    // Capture delivery functions once. A caller cannot replace them mid-attempt.
    const application = input.control.application.bind(input.control), selectGeneration = input.control.selectGeneration.bind(input.control)
    this.#options = {
      control: { application: options => this.#delivery('control:read', () => application(options)),
        selectGeneration: (request, options) => this.#delivery('control:select', () => selectGeneration(request, options)) },
      discovery: { read: input.discovery.read.bind(input.discovery), advertise: input.discovery.advertise.bind(input.discovery),
        withdraw: input.discovery.withdraw.bind(input.discovery), invitations: input.discovery.invitations.bind(input.discovery) },
      transport: { open: input.transport.open.bind(input.transport) },
    }
    this.#maxPeers = bound(input.connections?.maxPeers, 4, 1, 8)
    this.#initialRetry = bound(input.connections?.retryInitialMs, 1000, 1, 60_000)
    this.#maximumRetry = bound(input.connections?.retryMaxMs, 30_000, this.#initialRetry, 600_000)
    this.#advertiseMs = bound(input.connections?.advertiseMs, 60_000, 15_000, 300_000)
    this.#timeoutMs = bound(input.connections?.timeoutMs, 15_000, 1, 120_000)
    this.#graceMs = bound(input.recovery?.graceMs, 3000, 1, 600_000)
    this.#freshnessMs = bound(input.recovery?.freshnessMs, 300_000, 1, 86_400_000)
    this.#generation = owner.replica.generation.id
    this.#observationKey = `peer-session/coordinator-observation/${owner.replica.descriptor.applicationId}`
    this.signal = AbortSignal.any([owner.signal, this.#lifetime.signal])
    this.#unsubscribe = owner.replica.subscribe(() => this.#wake())
    this.#invitations = Promise.resolve().then(() => this.#listen()).catch(error => { if (!this.signal.aborted) this.#error = message(error) })
    this.#task = Promise.resolve().then(() => this.#run()).catch(error => {
      if (!this.signal.aborted) { this.#error = message(error); this.#publish('unavailable') }
    })
  }
  get status(): ApplicationParticipationStatus { return structuredClone(this.#status) }
  onStatus(listener: (status: ApplicationParticipationStatus) => void): () => void {
    this.#listeners.add(listener)
    try { listener(this.status) } catch { /* Observation never owns progress. */ }
    return () => { this.#listeners.delete(listener) }
  }
  async approveRecovery(proposalId: string): Promise<void> {
    this.signal.throwIfAborted()
    const proposal = this.#proposal, replica = this.#owner.replica
    if (proposal === null || proposal.id !== proposalId) throw new Error('APPLICATION_RECOVERY_APPROVAL_STALE')
    const base = await replica.recoveryPoint().catch(error => { throw new Error('APPLICATION_RECOVERY_APPROVAL_STALE', { cause: error }) })
    const generation = replica.generation
    const id = await peerDigest({ generation: generation.id, control: generation.payload.controlRevision, coordinator: proposal.coordinator, point: base.point })
    this.signal.throwIfAborted()
    if (this.#proposal?.id !== proposalId || !samePoint(proposal.point, base.point) || id !== proposalId ||
        replica.generation.id !== generation.id) throw new Error('APPLICATION_RECOVERY_APPROVAL_STALE')
    this.#approved = proposalId; this.#nextScan = 0; this.#wake()
  }

  /** Called only after this exact coordinator's authenticated head has been fully verified locally. */
  observeHead(peerId: string, revision: PeerRevision, requestedAt: number): void {
    const replica = this.#owner.replica
    if (this.signal.aborted || peerId !== replica.generation.payload.coordinator || revision.generation !== replica.generation.id ||
        !Number.isSafeInteger(requestedAt) || requestedAt > Date.now() || requestedAt < 0) return
    if (this.#observation?.generation === revision.generation && this.#observation.observedAt > requestedAt) return
    this.#observation = { generation: revision.generation, point: structuredClone(revision.point), observedAt: requestedAt }
    this.#pendingObservation = this.#observation
    if (this.#persistence !== undefined) return
    const task = (async () => {
      while (this.#pendingObservation !== null) {
        const value = this.#pendingObservation; this.#pendingObservation = null
        await this.#owner.store.put(this.#observationKey, encodePeerValue(value))
      }
    })().catch(error => { this.#observation = null; this.#pendingObservation = null; this.#error = message(error); this.#wake() })
      .finally(() => { if (this.#persistence === task) this.#persistence = undefined })
    this.#persistence = task
  }

  async #run(): Promise<void> {
    const bytes = await this.#owner.store.get(this.#observationKey)
    this.signal.throwIfAborted()
    if (bytes !== null) {
      const value = decodePeerValue<Observation>(bytes)
      validateHistoryPoint(value.point)
      if (identity(value.generation) && Number.isSafeInteger(value.observedAt) && value.observedAt >= 0 && value.point.generation === value.generation &&
          (this.#observation === null || value.observedAt > this.#observation.observedAt)) this.#observation = value
    }
    while (!this.signal.aborted) {
      this.#watchLinks()
      const replica = this.#owner.replica, now = Date.now()
      this.#observeGeneration()
      if (this.#healthy()) { this.#missingSince = null; this.#proposal = null; this.#approved = null; this.#retry = 0 }
      else this.#missingSince ??= now
      if (now >= this.#nextAdvertisement) {
        this.#nextAdvertisement = now + this.#advertiseMs
        try {
          await this.#call('advertise', signal => this.#options.discovery.advertise({ identity: replica.device.publicKey,
            storageId: replica.storageId, generation: replica.generation.id, point: replica.ready ? replica.revision.point : null },
          { ttlMs: 2 * this.#advertiseMs, signal }))
        } catch (error) { this.#error = message(error) }
      }
      if (Date.now() >= this.#nextScan) {
        try { await this.#scan(); this.#error = null }
        catch (error) { this.#error = message(error) }
        this.signal.throwIfAborted()
        this.#nextScan = Date.now() + (this.#healthy() ? this.#advertiseMs : this.#backoff(this.#retry++))
      }
      this.#publish()
      await this.#wait(Math.max(1, Math.min(this.#nextScan, this.#nextAdvertisement) - Date.now()))
    }
  }

  async #scan(): Promise<void> {
    const replica = this.#owner.replica
    let authorityError: Error | undefined
    if (this.#initial || !this.#healthy()) {
      try {
        const bundle = await this.#call('authority', signal => this.#options.control.application({ signal }))
        this.signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, replica.authority.descriptor)
        this.signal.throwIfAborted()
        await replica.receiveHistory(bundle, [])
        this.#initial = false
      } catch (error) { authorityError = new Error(message(error), { cause: error }) }
    }
    let directoryError: Error | undefined
    if (!this.#healthy() || this.#links().length < this.#maxPeers) {
      try {
        const hints = this.#hints(await this.#call('directory', signal => this.#options.discovery.read({ signal })))
        const coordinator = replica.generation.payload.coordinator
        hints.sort((left, right) => Number(right.identity === coordinator) - Number(left.identity === coordinator) ||
          Number(replica.grant(right.identity)?.reader === true) - Number(replica.grant(left.identity)?.reader === true) || left.identity.localeCompare(right.identity))
        await Promise.allSettled(hints.slice(0, this.#maxPeers).map(peer => this.#connect({ peer })))
      } catch (error) { directoryError = new Error(message(error), { cause: error }) }
    }
    this.signal.throwIfAborted()
    const links = this.#links(), synchronized = await Promise.allSettled(links.map(link => this.#call(`sync:${link.peerId}`, () => link.synchronize())))
    for (const [index, result] of synchronized.entries()) {
      if (result.status === 'rejected') void links[index]!.close().catch(() => undefined)
    }
    const available = new Set(links.filter((link, index) => synchronized[index]?.status === 'fulfilled' && !link.signal.aborted).map(link => link.peerId))
    this.signal.throwIfAborted()
    // Authority can advance during this scan. Retire an older choice before
    // creating its replacement, rather than clearing the new proposal next turn.
    this.#observeGeneration()
    const pending = [...await this.#call('journal', () => this.#owner.recovery.inspect())].reverse().find(entry => entry.selected === null && !entry.superseded)
    if (pending !== undefined) {
      if (pending.request.payload.reason !== 'takeover' && pending.request.payload.reason !== 'handover') throw new Error('APPLICATION_TRANSITION_JOURNAL_INVALID')
      await this.#select(pending.request.payload.coordinator, pending.request.payload.transitionId, pending.request.payload.reason)
      return
    }
    if (this.#healthy() || this.#missingSince === null || Date.now() - this.#missingSince < this.#graceMs) {
      if (directoryError !== undefined) throw directoryError
      if (authorityError !== undefined) throw authorityError
      return
    }
    if (authorityError !== undefined) throw authorityError
    if (replica.grant(replica.device.publicKey)?.recovery !== true) throw new Error('PEER_RECOVERY_FORBIDDEN')
    const base = await replica.recoveryPoint()
    this.signal.throwIfAborted()
    const expected: ApplicationRecoveryExpectation = { generation: replica.generation.id, controlRevision: replica.generation.payload.controlRevision, point: base.point }
    const retained = replica.ready ? replica.shared(base.point) : []
    const candidates = new Set<string>()
    if (replica.grant(replica.device.publicKey)?.coordinator === true) candidates.add(replica.device.publicKey)
    for (const link of this.#links()) {
      if (available.has(link.peerId) && replica.grant(link.peerId)?.coordinator === true && retained.some(receipt => receipt.payload.peer === link.peerId && samePoint(receipt.payload.point, base.point))) candidates.add(link.peerId)
    }
    const selected = [...candidates].sort()[0]
    if (selected === undefined) throw new Error('APPLICATION_NO_COMPLETE_COORDINATOR')
    const observation = this.#observation, now = Date.now()
    let observedAt: number | null = null
    if (observation !== null && observation.generation === replica.generation.id && observation.observedAt <= now) {
      try { await replica.prefixProof(observation.point); observedAt = observation.observedAt } catch { /* Unknown evidence cannot establish freshness. */ }
    }
    this.signal.throwIfAborted()
    const ageMs = observedAt === null ? null : now - observedAt
    const id = await peerDigest({ generation: expected.generation, control: expected.controlRevision, coordinator: selected, point: base.point })
    if (ageMs === null || ageMs > this.#freshnessMs) {
      this.#proposal = { id, coordinator: selected, point: base.point, reason: ageMs === null ? 'freshness-unknown' : 'older-than-budget', observedAt, ageMs }
      if (this.#approved !== id) return
    } else this.#proposal = null
    await this.#select(selected, undefined, 'takeover', expected)
  }

  async #select(coordinator: string, transitionId?: string, reason: 'takeover' | 'handover' = 'takeover', expected?: ApplicationRecoveryExpectation): Promise<void> {
    this.#publish('recovering')
    await this.#call('selection', signal => this.#owner.recovery[reason](this.#options.control, {
      coordinator, signal, ...(transitionId === undefined ? {} : { transitionId }),
      ...(expected === undefined ? {} : { expected }),
    }))
    this.signal.throwIfAborted()
    await this.#call('resume', () => this.#owner.resume())
    this.#proposal = null; this.#approved = null; this.#nextAdvertisement = 0
  }

  #hints(input: unknown): ApplicationPeerHint[] {
    const payload = createParticipantRequest({ applicationId: this.#owner.replica.descriptor.applicationId,
      requestId: 'directory', facet: 'discovery', action: 'read', payload: input }).payload
    if (!Array.isArray(payload) || payload.length > 64 || encodePeerValue(payload).length > 64 * 1024) throw new Error('APPLICATION_DIRECTORY_INVALID')
    const valid = (payload as unknown[]).map(value => {
      if (value === null || typeof value !== 'object' || Object.keys(value).length !== 2 || !('identity' in value) || !identity(value.identity) || !Object.hasOwn(value, 'route')) throw new Error('APPLICATION_DIRECTORY_INVALID')
      return value as ApplicationPeerHint
    }).filter(value => value.identity !== this.#owner.replica.device.publicKey)
    return [...new Map(valid.map(value => [value.identity, value])).values()]
  }

  async #listen(): Promise<void> {
    let failures = 0
    while (!this.signal.aborted) {
      let iterator: AsyncIterator<ApplicationPeerInvitation> | undefined
      try {
        iterator = this.#options.discovery.invitations({ signal: this.signal })[Symbol.asyncIterator]()
        while (!this.signal.aborted) {
          const next = await awaitOwnedTask(this.signal, () => iterator!.next())
          if (next.done) break
          const value = createParticipantRequest({ applicationId: this.#owner.replica.descriptor.applicationId,
            requestId: 'invitation', facet: 'ephemeral', action: 'invite', payload: next.value }).payload as ApplicationPeerInvitation
          if (value === null || typeof value !== 'object' || Object.keys(value).length !== 2 || !Object.hasOwn(value, 'token')) throw new Error('APPLICATION_INVITATION_INVALID')
          const peer = this.#hints([value.peer])[0]
          if (peer !== undefined) void this.#connect({ peer, invitation: value.token }).catch(error => { this.#error = message(error); this.#wake() })
          failures = 0
        }
      } catch (error) { if (!this.signal.aborted) this.#error = message(error) }
      finally { try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* Delivery cleanup cannot own application lifetime. */ } }
      if (!this.signal.aborted) await delay(this.#backoff(failures++), this.signal)
    }
  }

  async #connect(input: { readonly peer: ApplicationPeerHint; readonly invitation?: unknown }): Promise<void> {
    this.signal.throwIfAborted()
    const peer = this.#hints([input.peer])[0]
    if (peer === undefined || this.#links().some(link => link.peerId === peer.identity)) return
    const previous = this.#joining.get(peer.identity), incoming = input.invitation !== undefined
    if (previous !== undefined) {
      if (!incoming || previous.incoming || this.#owner.replica.device.publicKey < peer.identity) return
      previous.controller.abort(new Error('APPLICATION_CONNECTION_SUPERSEDED'))
      await awaitOwnedTask(this.signal, () => previous.finished)
    }
    if (this.#links().length + this.#physicalOpenings.size >= this.#maxPeers) return
    const token = Symbol(), controller = new AbortController()
    const signal = AbortSignal.any([this.signal, controller.signal])
    let finished!: () => void, settled = false, link: ApplicationPeerLink | undefined, connection: FramedPeerConnection | undefined
    const joining: Joining = { controller, incoming, finished: new Promise(resolve => { finished = resolve }) }
    this.#joining.set(peer.identity, joining); this.#physicalOpenings.add(token)
    const timer = setTimeout(() => controller.abort(new Error('APPLICATION_CONNECTION_TIMEOUT')), this.#timeoutMs)
    const opening = Promise.resolve().then(() => {
      signal.throwIfAborted()
      return this.#options.transport.open({ peer, ...(incoming ? { invitation: structuredClone(input.invitation) } : {}) }, { signal })
    })
    void opening.then(value => { if (signal.aborted) return value.close() }, () => undefined).catch(() => undefined)
    void opening.finally(() => { settled = true; if (signal.aborted) this.#physicalOpenings.delete(token) }).catch(() => undefined)
    try {
      connection = await awaitOwnedTask(signal, () => opening)
      signal.throwIfAborted()
      link = await this.#owner.connect({ connection, peerIdentity: peer.identity, signal,
        handshakeTimeoutMs: this.#timeoutMs, requestTimeoutMs: this.#timeoutMs, transferTimeoutMs: this.#timeoutMs })
      await awaitOwnedTask(signal, () => link!.synchronize())
      signal.throwIfAborted(); this.#ownedLinks.add(link); this.#watchLinks()
      this.#nextScan = 0; this.#wake()
    } catch (error) {
      controller.abort(error)
      if (link !== undefined) await link.close()
      else if (connection !== undefined) void connection.close().catch(() => undefined)
      throw error
    } finally {
      clearTimeout(timer)
      if (settled) this.#physicalOpenings.delete(token)
      if (this.#joining.get(peer.identity) === joining) this.#joining.delete(peer.identity)
      finished()
    }
  }

  #links(): readonly ApplicationPeerLink[] { return this.#owner.links().filter(link => !link.signal.aborted) }
  #observeGeneration(): void {
    const generation = this.#owner.replica.generation.id
    if (this.#generation === generation) return
    this.#generation = generation; this.#proposal = null; this.#approved = null
    this.#nextScan = 0; this.#nextAdvertisement = 0
  }
  #healthy(): boolean {
    const replica = this.#owner.replica
    return replica.ready && (replica.isCoordinator || this.#links().some(link => link.peerId === replica.generation.payload.coordinator))
  }
  #watchLinks(): void {
    for (const link of this.#links()) {
      if (this.#watchedLinks.has(link)) continue
      const ended = (): void => {
        this.#watchedLinks.delete(link); this.#ownedLinks.delete(link)
        this.#nextScan = Math.min(this.#nextScan, Date.now() + this.#initialRetry); this.#wake()
      }
      this.#watchedLinks.set(link, ended); link.signal.addEventListener('abort', ended, { once: true })
      if (link.signal.aborted) ended()
    }
  }
  #backoff(attempt: number): number { return Math.max(1, Math.round(Math.min(this.#maximumRetry, this.#initialRetry * 2 ** Math.min(attempt, 20)) * (0.75 + Math.random() * 0.25))) }
  #publish(phase?: ApplicationParticipationStatus['phase']): void {
    const replica = this.#owner.replica
    const next: ApplicationParticipationStatus = {
      phase: phase ?? (this.signal.aborted ? 'closed' : this.#proposal !== null && this.#approved !== this.#proposal.id ? 'approval-required'
        : !replica.ready ? 'recovering' : replica.isCoordinator ? 'coordinating' : this.#healthy() ? 'following' : this.#error !== null ? 'unavailable' : 'connecting'),
      connectedPeers: this.#links().map(link => link.peerId).sort(), recovery: structuredClone(this.#proposal), error: this.#error,
    }
    if (JSON.stringify(next) === JSON.stringify(this.#status)) return
    this.#status = next
    for (const listener of [...this.#listeners]) { try { listener(this.status) } catch { /* Observation never owns progress. */ } }
  }
  #wake(): void { this.#wakePending = true; this.#wakeWait?.() }
  #wait(ms: number): Promise<void> {
    if (this.#wakePending) { this.#wakePending = false; return Promise.resolve() }
    return new Promise(resolve => {
      const finish = (): void => { clearTimeout(timer); this.signal.removeEventListener('abort', finish); this.#wakeWait = undefined; this.#wakePending = false; resolve() }
      const timer = setTimeout(finish, ms)
      this.#wakeWait = finish; this.signal.addEventListener('abort', finish, { once: true })
      if (this.signal.aborted) finish()
    })
  }
  async #call<T>(key: string, call: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.signal.throwIfAborted()
    if (this.#calls.has(key)) throw new Error('APPLICATION_PARTICIPATION_BUSY')
    const timeout = new AbortController(), timer = setTimeout(() => timeout.abort(new Error('APPLICATION_PARTICIPATION_TIMEOUT')), this.#timeoutMs)
    const signal = AbortSignal.any([this.signal, timeout.signal])
    const work = this.#delivery(key, () => { signal.throwIfAborted(); return call(signal) })
    try { return await awaitOwnedTask(signal, () => work) } finally { clearTimeout(timer) }
  }
  #delivery<T>(key: string, call: () => Promise<T>): Promise<T> {
    this.signal.throwIfAborted()
    if (this.#calls.has(key)) throw new Error('APPLICATION_PARTICIPATION_BUSY')
    const work = Promise.resolve().then(() => { this.signal.throwIfAborted(); return call() })
    this.#calls.set(key, work)
    void work.finally(() => { if (this.#calls.get(key) === work) this.#calls.delete(key) }).catch(() => undefined)
    return work
  }
  close(): Promise<void> {
    if (this.#closed !== undefined) return this.#closed
    let resolve!: () => void, reject!: (error: unknown) => void
    this.#closed = new Promise<void>((done, fail) => { resolve = done; reject = fail })
    const links = [...this.#ownedLinks]
    this.#lifetime.abort(new Error('APPLICATION_PARTICIPATION_CLOSED')); this.#unsubscribe(); this.#wake()
    for (const joining of this.#joining.values()) joining.controller.abort(this.signal.reason)
    for (const [link, dispose] of this.#watchedLinks) link.signal.removeEventListener('abort', dispose)
    this.#watchedLinks.clear(); this.#publish('closed'); this.#listeners.clear()
    void (async () => {
      await Promise.allSettled([this.#task, this.#invitations, ...links.map(link => link.close())])
      await this.#persistence
      const cleanup = AbortSignal.timeout(Math.min(this.#timeoutMs, 1000))
      await awaitOwnedTask(cleanup, () => this.#options.discovery.withdraw({ signal: cleanup })).catch(() => undefined)
    })().then(resolve, reject)
    return this.#closed
  }
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    const finish = (): void => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve() }
    const timer = setTimeout(finish, ms)
    signal.addEventListener('abort', finish, { once: true }); if (signal.aborted) finish()
  })
}

import {
  createParticipantRequest, decodePeerValue, encodePeerValue, peerDigest, validateHistoryPoint, verifyAuthorityBundle,
  type HistoryPoint,
} from '@chronolog/peer-generation/control'
import type { PeerRevision } from '@chronolog/peer-generation'
import type { BytesStore, FramedPeerConnection } from '@chronolog/records'
import { isPeerDataUnavailable, type ApplicationPeerConnectOptions, type ApplicationPeerLink } from './network.js'
import type { ApplicationRecoveryExpectation } from './recovery.js'
import type { ApplicationParticipant } from './participant-types.js'
import { awaitOwnedTask } from './lifetime.js'
import type {
  ApplicationParticipation, ApplicationParticipationOptions, ApplicationParticipationStatus,
  ApplicationPeerHint, ApplicationPeerInvitation, ApplicationRecoveryProposal, ApplicationPeerAdvertisement, ApplicationDiscoveryNotification,
  ApplicationTransportDescription, ApplicationConnectionDiagnostic,
} from './participation-types.js'

interface Owner {
  readonly participant: ApplicationParticipant
  readonly store: BytesStore
  readonly signal: AbortSignal
  connect(options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink>
  links(): readonly ApplicationPeerLink[]
  resume(): Promise<void>
}
interface Observation { readonly generation: string; readonly point: HistoryPoint; readonly observedAt: number }
interface Joining { readonly controller: AbortController; readonly incoming: boolean; readonly replacement: boolean; readonly finished: Promise<void> }
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
  readonly #discoveryFence = new AbortController()
  readonly signal: AbortSignal
  readonly #maxPeers: number
  readonly #initialRetry: number
  readonly #maximumRetry: number
  readonly #graceMs: number
  readonly #freshnessMs: number
  readonly #upgradeCooldownMs: number
  readonly #timeoutMs: number
  readonly #observationKey: string
  readonly #listeners = new Set<(status: ApplicationParticipationStatus) => void>()
  readonly #calls = new Map<string, Promise<unknown>>()
  readonly #joining = new Map<string, Joining>()
  readonly #physicalOpenings = new Set<symbol>()
  readonly #ownedLinks = new Set<ApplicationPeerLink>()
  readonly #transports = new WeakMap<ApplicationPeerLink, ApplicationTransportDescription>()
  readonly #lastUpgrade = new Map<string, number>()
  #upgradeTask: Promise<void> | undefined
  readonly #connectionIds = new WeakMap<ApplicationPeerLink, number>()
  #nextConnectionId = 0
  #connectionRevision = 0
  #connectionKey = '[]' 
  readonly #watchedLinks = new Map<ApplicationPeerLink, () => void>()
  readonly #task: Promise<void>
  readonly #invitations: Promise<void>
  readonly #notifications: Promise<void>
  readonly #unsubscribe: () => void
  #status: ApplicationParticipationStatus = { connectionRevision: 0, phase: 'connecting', connectedPeers: [], recovery: null, error: null }
  #observation: Observation | null = null
  #pendingObservation: Observation | null = null
  #persistence: Promise<void> | undefined
  #proposal: ApplicationRecoveryProposal | null = null
  #approved: string | null = null
  #wakePending = false
  #wakeWait: (() => void) | undefined
  #nextScan = Infinity
  #nextAdvertisement = Infinity
  #discoveryReady = false
  #hasDiscoveryReady = false
  #discoveryTerminal = false
  #discoveryError: string | null = null
  #advertiseRetry = 0
  #advertisementError: string | null = null
  #stateKey: string
  #missingSince: number | null = null
  #retry = 0
  #initial = true
  #generation: string
  #error: string | null = null
  #closed: Promise<void> | undefined
  #dataActive: boolean

  constructor(owner: Owner, input: ApplicationParticipationOptions) {
    this.#owner = owner
    // Capture delivery functions once. A caller cannot replace them mid-attempt.
    const application = input.control.application.bind(input.control), selectGeneration = input.control.selectGeneration.bind(input.control)
    this.#options = {
      control: { application: options => this.#delivery('control:read', () => application(options)),
        selectGeneration: (request, options) => this.#delivery('control:select', () => selectGeneration(request, options)) },
      discovery: { read: input.discovery.read.bind(input.discovery), advertise: input.discovery.advertise.bind(input.discovery),
        notifications: input.discovery.notifications.bind(input.discovery),
        withdraw: input.discovery.withdraw.bind(input.discovery), invitations: input.discovery.invitations.bind(input.discovery) },
      transport: { open: input.transport.open.bind(input.transport),
        ...(input.transport.upgrade === undefined ? {} : { upgrade: input.transport.upgrade.bind(input.transport) }),
        ...(input.transport.describe === undefined ? {} : { describe: input.transport.describe.bind(input.transport) }) },
    }
    this.#maxPeers = bound(input.connections?.maxPeers, 4, 1, 8)
    this.#initialRetry = bound(input.connections?.retryInitialMs, 1000, 1, 60_000)
    this.#maximumRetry = bound(input.connections?.retryMaxMs, 30_000, this.#initialRetry, 600_000)
    this.#timeoutMs = bound(input.connections?.timeoutMs, 15_000, 1, 120_000)
    this.#upgradeCooldownMs = bound(input.connections?.upgradeCooldownMs, 30_000, 1_000, 600_000)
    this.#graceMs = bound(input.recovery?.graceMs, 3000, 1, 600_000)
    this.#freshnessMs = bound(input.recovery?.freshnessMs, 300_000, 1, 86_400_000)
    this.#generation = owner.participant.generation.id
    this.#dataActive = owner.participant.data !== undefined
    this.#observationKey = `peer-session/coordinator-observation/${owner.participant.descriptor.applicationId}`
    this.signal = AbortSignal.any([owner.signal, this.#lifetime.signal])
    this.#stateKey = this.#snapshotKey()
    this.#unsubscribe = owner.participant.subscribe(() => {
      const key = this.#snapshotKey()
      if (key === this.#stateKey) return
      this.#stateKey = key
      this.#nextScan = 0; this.#nextAdvertisement = 0
      if (!this.#dataActive && owner.participant.data !== undefined) {
        this.#dataActive = true; this.#missingSince = null; this.#nextScan = 0; this.#nextAdvertisement = 0
      }
      this.#wake()
    })
    this.#notifications = Promise.resolve().then(() => this.#watchDiscovery()).catch(error => {
      if (!this.signal.aborted) { this.#discoveryError = message(error); this.#publish('unavailable') }
    })
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
  diagnostics(): Promise<readonly ApplicationConnectionDiagnostic[]> {
    return Promise.resolve(this.#links().map(link => { const stats = link.stats; return { peerId: link.peerId,
      ...(this.#transports.get(link) ?? { kind: 'unknown' as const }), ...stats,
      sentReliableBytes: stats.sentBytes, receivedReliableBytes: stats.receivedBytes,
      sentBytes: stats.sentBytes + stats.sentLiveBytes, receivedBytes: stats.receivedBytes + stats.receivedLiveBytes,
    } }).sort((left, right) => left.peerId.localeCompare(right.peerId)))
  }
  reconsiderConnections(): Promise<void> {
    if (this.signal.aborted || this.#discoveryTerminal || this.#options.transport.upgrade === undefined) return Promise.resolve()
    if (this.#upgradeTask !== undefined) return this.#upgradeTask
    const candidates = this.#links().filter(link => this.#transports.get(link)?.kind === 'relay')
    const now = Date.now(), current = new Set(this.#links().map(link => link.peerId))
    for (const peerId of this.#lastUpgrade.keys()) if (!current.has(peerId)) this.#lastUpgrade.delete(peerId)
    const work = candidates.filter(link => now - (this.#lastUpgrade.get(link.peerId) ?? -Infinity) >= this.#upgradeCooldownMs)
    if (work.length === 0) return Promise.resolve()
    const task = Promise.allSettled(work.map(link => this.#connect({ peer: { identity: link.peerId, route: null }, upgrade: true })))
      .then(() => undefined).finally(() => { if (this.#upgradeTask === task) this.#upgradeTask = undefined })
    this.#upgradeTask = task
    return task
  }
  async approveRecovery(proposalId: string): Promise<void> {
    this.signal.throwIfAborted()
    const proposal = this.#proposal, replica = this.#owner.participant.data?.replica
    if (replica === undefined || proposal === null || proposal.id !== proposalId) throw new Error('APPLICATION_RECOVERY_APPROVAL_STALE')
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
    const replica = this.#owner.participant.data?.replica
    if (replica === undefined || this.signal.aborted || peerId !== replica.generation.payload.coordinator || revision.generation !== replica.generation.id ||
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
      if (this.#discoveryTerminal) { this.#publish('unavailable'); await this.#wait(Infinity); continue }
      this.#watchLinks()
      const participant = this.#owner.participant, replica = participant.data?.replica, now = Date.now()
      this.#observeGeneration()
      if (replica === undefined || this.#healthy()) { this.#missingSince = null; this.#proposal = null; this.#approved = null }
      else this.#missingSince ??= now
      // No hosted work may race ahead of the subscription's initial ready.
      if (!this.#discoveryReady && (!this.#hasDiscoveryReady || this.#healthy())) { this.#publish(); await this.#wait(Infinity); continue }
      if (this.#discoveryReady && now >= this.#nextAdvertisement) {
        this.#nextAdvertisement = Infinity
        try {
          await this.#call('advertise', signal => this.#options.discovery.advertise(this.#advertisement(), { signal }))
          this.#advertiseRetry = 0; this.#advertisementError = null
        } catch (error) {
          this.#advertisementError = message(error)
          this.#nextAdvertisement = Math.min(this.#nextAdvertisement, Date.now() + this.#backoff(this.#advertiseRetry++))
        }
      }
      if (!this.#discoveryTerminal && Date.now() >= this.#nextScan) {
        // Clear before awaiting: a notification or real state change during the scan must survive it.
        this.#nextScan = Infinity
        let failed = false
        try { await this.#scan(); this.#error = null }
        catch (error) { failed = true; this.#error = message(error) }
        this.signal.throwIfAborted()
        if (failed || !this.#healthy()) this.#nextScan = Math.min(this.#nextScan, Date.now() + this.#backoff(this.#retry++))
        else this.#retry = 0
      }
      this.#publish()
      await this.#wait(Math.max(1, Math.min(this.#nextScan, this.#discoveryReady ? this.#nextAdvertisement : Infinity) - Date.now()))
    }
  }

  #advertisement(): ApplicationPeerAdvertisement {
    const participant = this.#owner.participant, replica = participant.data?.replica
    return { identity: participant.device.publicKey, storageId: participant.storageId, generation: participant.generation.id,
      data: replica !== undefined, point: replica?.ready === true ? replica.revision.point : null }
  }
  #snapshotKey(): string {
    const participant = this.#owner.participant, replica = participant.data?.replica, control = participant.authority.controls.at(-1)
    // Replication owns changing history heads. Only presence/authority/data lifecycle changes invalidate discovery.
    return JSON.stringify([participant.generation.id, control?.payload.revision, control?.signature, replica !== undefined, replica?.closed === true,
      this.#links().map(link => `${link.peerId}:${link.data}`).sort()])
  }

  async #watchDiscovery(): Promise<void> {
    let failures = 0
    while (!this.signal.aborted) {
      let iterator: AsyncIterator<ApplicationDiscoveryNotification> | undefined
      let ready = false
      try {
        iterator = this.#options.discovery.notifications({ signal: this.signal })[Symbol.asyncIterator]()
        while (!this.signal.aborted) {
          const next = await awaitOwnedTask(this.signal, () => iterator!.next())
          if (next.done) throw new Error('APPLICATION_DISCOVERY_NOTIFICATIONS_ENDED')
          const value: unknown = next.value
          if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).join() !== 'type' || !('type' in value) ||
              value.type !== 'ready' && value.type !== 'changed' || !ready && value.type !== 'ready') throw new Error('APPLICATION_DISCOVERY_NOTIFICATION_INVALID')
          if (value.type === 'ready') {
            ready = true; this.#discoveryReady = true; this.#hasDiscoveryReady = true; this.#discoveryError = null; failures = 0
            this.#nextAdvertisement = 0
            void this.reconsiderConnections()
          }
          this.#nextScan = 0; this.#wake()
        }
      } catch (error) {
        if (!this.signal.aborted) {
          this.#discoveryReady = false; this.#discoveryError = message(error)
          if (error !== null && typeof error === 'object' && 'retryable' in error && error.retryable === false) {
            this.#discoveryTerminal = true; this.#nextScan = Infinity; this.#nextAdvertisement = Infinity
            this.#proposal = null; this.#approved = null
            this.#discoveryFence.abort(error)
            for (const [peerId, joining] of this.#joining) {
              if (!joining.replacement && !this.#links().some(link => link.peerId === peerId && link.data === 'active')) joining.controller.abort(error)
            }
            this.#wake(); break
          }
          this.#wake()
        }
      } finally {
        try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* Cleanup cannot own lifetime. */ }
      }
      if (!this.signal.aborted) await delay(this.#backoff(failures++), this.signal)
    }
  }

  async #scan(): Promise<void> {
    const participant = this.#owner.participant
    let authorityError: Error | undefined
    if (this.#initial || !this.#healthy()) {
      try {
        const bundle = await this.#call('authority', signal => this.#options.control.application({ signal }))
        this.signal.throwIfAborted()
        await verifyAuthorityBundle(bundle, participant.authority.descriptor)
        this.signal.throwIfAborted()
        await participant.adoptAuthority(bundle)
        this.#initial = false
      } catch (error) { authorityError = new Error(message(error), { cause: error }) }
    }
    let directoryError: Error | undefined
    if (!this.#healthy() || this.#links().length < this.#maxPeers) {
      try {
        const hints = this.#hints(await this.#call('directory', signal => this.#options.discovery.read({ signal })))
        const coordinator = participant.generation.payload.coordinator
        hints.sort((left, right) => Number(right.identity === coordinator) - Number(left.identity === coordinator) ||
          Number(participant.grant(right.identity)?.reader === true) - Number(participant.grant(left.identity)?.reader === true) || left.identity.localeCompare(right.identity))
        await Promise.allSettled(hints.slice(0, this.#maxPeers).map(peer => this.#connect({ peer })))
      } catch (error) { directoryError = new Error(message(error), { cause: error }) }
    }
    this.signal.throwIfAborted()
    const links = this.#links(), synchronized = await Promise.allSettled(links.map(link => this.#call(`sync:${link.peerId}`, () => link.synchronize())))
    for (const [index, result] of synchronized.entries()) {
      if (result.status === 'rejected' && !isPeerDataUnavailable(result.reason) && !this.signal.aborted && !this.#discoveryTerminal) void links[index]!.close().catch(() => undefined)
    }
    const available = new Set(links.filter((link, index) => synchronized[index]?.status === 'fulfilled' && link.data === 'active' && !link.signal.aborted).map(link => link.peerId))
    this.signal.throwIfAborted()
    // Authority can advance during this scan. Retire an older choice before
    // creating its replacement, rather than clearing the new proposal next turn.
    this.#observeGeneration()
    const data = participant.data
    if (data === undefined) {
      if (directoryError !== undefined) throw directoryError
      if (authorityError !== undefined) throw authorityError
      return
    }
    const replica = data.replica
    const pending = [...await this.#call('journal', () => data.recovery.inspect())].reverse().find(entry => entry.selected === null && !entry.superseded)
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
    // An invitation or its superseding attempt can arrive after discovery. Do
    // not declare loss while that coordinator's bounded opening still owns work.
    if (this.#healthy() || this.#joining.has(replica.generation.payload.coordinator)) return
    if (ageMs === null || ageMs > this.#freshnessMs) {
      this.#proposal = { id, coordinator: selected, point: base.point, reason: ageMs === null ? 'freshness-unknown' : 'older-than-budget', observedAt, ageMs }
      if (this.#approved !== id) return
    } else this.#proposal = null
    await this.#select(selected, undefined, 'takeover', expected)
  }

  async #select(coordinator: string, transitionId?: string, reason: 'takeover' | 'handover' = 'takeover', expected?: ApplicationRecoveryExpectation): Promise<void> {
    const data = this.#owner.participant.data
    if (data === undefined) throw new Error('APPLICATION_DATA_NOT_ACTIVE')
    this.#publish('recovering')
    await this.#call('selection', signal => data.recovery[reason](this.#options.control, {
      coordinator, signal, ...(transitionId === undefined ? {} : { transitionId }),
      ...(expected === undefined ? {} : { expected }),
    }))
    this.signal.throwIfAborted()
    await this.#call('resume', () => this.#owner.resume())
    this.#proposal = null; this.#approved = null; this.#nextAdvertisement = 0
  }

  #hints(input: unknown): ApplicationPeerHint[] {
    const payload = createParticipantRequest({ applicationId: this.#owner.participant.descriptor.applicationId,
      requestId: 'directory', facet: 'discovery', action: 'read', payload: input }).payload
    if (!Array.isArray(payload) || payload.length > 64 || encodePeerValue(payload).length > 64 * 1024) throw new Error('APPLICATION_DIRECTORY_INVALID')
    const valid = (payload as unknown[]).map(value => {
      if (value === null || typeof value !== 'object' || Object.keys(value).length !== 2 || !('identity' in value) || !identity(value.identity) || !Object.hasOwn(value, 'route')) throw new Error('APPLICATION_DIRECTORY_INVALID')
      return value as ApplicationPeerHint
    }).filter(value => value.identity !== this.#owner.participant.device.publicKey)
    return [...new Map(valid.map(value => [value.identity, value])).values()]
  }

  async #listen(): Promise<void> {
    const signal = AbortSignal.any([this.signal, this.#discoveryFence.signal])
    let failures = 0
    while (!signal.aborted) {
      let iterator: AsyncIterator<ApplicationPeerInvitation> | undefined
      try {
        iterator = this.#options.discovery.invitations({ signal })[Symbol.asyncIterator]()
        while (!signal.aborted) {
          const next = await awaitOwnedTask(signal, () => iterator!.next())
          if (next.done) break
          const value = createParticipantRequest({ applicationId: this.#owner.participant.descriptor.applicationId,
            requestId: 'invitation', facet: 'ephemeral', action: 'invite', payload: next.value }).payload as ApplicationPeerInvitation
          if (value === null || typeof value !== 'object' || (Object.keys(value).length !== 2 && !(Object.keys(value).length === 3 && value.upgrade === true)) || !Object.hasOwn(value, 'token')) throw new Error('APPLICATION_INVITATION_INVALID')
          const peer = this.#hints([value.peer])[0]
          if (peer !== undefined) void this.#connect({ peer, invitation: value.token, ...(value.upgrade ? { upgrade: true } : {}) }).catch(error => { if (!value.upgrade) { this.#error = message(error); this.#wake() } })
          failures = 0
        }
      } catch (error) { if (!signal.aborted) this.#error = message(error) }
      finally { try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* Delivery cleanup cannot own application lifetime. */ } }
      if (!signal.aborted) await delay(this.#backoff(failures++), signal)
    }
  }

  async #connect(input: { readonly peer: ApplicationPeerHint; readonly invitation?: unknown; readonly upgrade?: true }): Promise<void> {
    this.signal.throwIfAborted(); this.#discoveryFence.signal.throwIfAborted()
    const peer = this.#hints([input.peer])[0]
    if (peer === undefined) return
    const current = this.#links().find(link => link.peerId === peer.identity)
    const incoming = input.invitation !== undefined
    // An ordinary invitation may be the same device restarting while its old
    // physical route still looks alive. Only the network handshake can prove
    // replacement authority; keep that route until reciprocal readiness.
    const canConnect = (): boolean => {
      const latest = this.#links().find(link => link.peerId === peer.identity)
      // A newer authenticated winner owns this identity after any await.
      if (latest !== undefined && latest !== current) return false
      return input.upgrade
        ? latest !== undefined && this.#transports.get(latest)?.kind === 'relay' && this.#options.transport.upgrade !== undefined
        : incoming || latest === undefined
    }
    if (!canConnect()) return
    let superseded = false
    // Supersession awaits release of the old attempt. Re-read ownership after
    // every await: multiple invitations must never overwrite one another's slot.
    while (true) {
      const previous = this.#joining.get(peer.identity)
      if (previous === undefined) {
        if (input.upgrade && !superseded) {
          const last = this.#lastUpgrade.get(peer.identity)
          if (last !== undefined && Date.now() - last < this.#upgradeCooldownMs) return
        }
        break
      }
      if (!incoming) { await awaitOwnedTask(this.signal, () => previous.finished); return }
      if (previous.incoming || this.#owner.participant.device.publicKey < peer.identity) return
      superseded = true
      previous.controller.abort(new Error('APPLICATION_CONNECTION_SUPERSEDED'))
      await awaitOwnedTask(this.signal, () => previous.finished)
      this.signal.throwIfAborted(); this.#discoveryFence.signal.throwIfAborted()
      if (!canConnect()) return
    }
    if (!canConnect()) return
    const logicalPeers = new Set([...this.#links().map(link => link.peerId), ...this.#joining.keys()])
    if (this.#physicalOpenings.size >= this.#maxPeers || !logicalPeers.has(peer.identity) && logicalPeers.size >= this.#maxPeers) return
    // maxPeers bounds logical peers and concurrent physical candidates separately.
    // A candidate replacing an existing link cannot consume a second logical slot.
    if (input.upgrade) this.#lastUpgrade.set(peer.identity, Date.now())
    const token = Symbol(), controller = new AbortController()
    const signal = AbortSignal.any([this.signal, controller.signal])
    // Hosted discovery may fence an opening, never an authenticated replacement.
    // The network owner promotes synchronously before its connect promise resumes.
    const fenceCandidate = (): void => {
      if (!this.#links().some(value => value.peerId === peer.identity && value !== current)) controller.abort(this.#discoveryFence.signal.reason)
    }
    if (current !== undefined) {
      this.#discoveryFence.signal.addEventListener('abort', fenceCandidate, { once: true })
      if (this.#discoveryFence.signal.aborted) fenceCandidate()
    }
    let finished!: () => void, settled = false, link: ApplicationPeerLink | undefined, connection: FramedPeerConnection | undefined
    const joining: Joining = { controller, incoming, replacement: current !== undefined, finished: new Promise(resolve => { finished = resolve }) }
    this.#joining.set(peer.identity, joining); this.#physicalOpenings.add(token)
    const timer = setTimeout(() => controller.abort(new Error('APPLICATION_CONNECTION_TIMEOUT')), this.#timeoutMs)
    const opening = Promise.resolve().then(() => {
      signal.throwIfAborted()
      const value = { peer, ...(incoming ? { invitation: structuredClone(input.invitation) } : {}) }
      return input.upgrade ? this.#options.transport.upgrade!(value, { signal }) : this.#options.transport.open(value, { signal })
    })
    void opening.then(value => { if (signal.aborted) return value.close() }, () => undefined).catch(() => undefined)
    void opening.finally(() => { settled = true; if (signal.aborted) this.#physicalOpenings.delete(token) }).catch(() => undefined)
    try {
      connection = await awaitOwnedTask(signal, () => opening)
      signal.throwIfAborted()
      if (!canConnect()) {
        await connection.close(); return
      }
      const description = this.#options.transport.describe?.(connection) ?? { kind: 'unknown' as const }
      if (!['direct', 'relay', 'unknown'].includes(description.kind) || description.reason !== undefined && !['direct_failed', 'direct_timeout'].includes(description.reason) ||
          input.upgrade && description.kind !== 'direct') throw new Error('APPLICATION_TRANSPORT_DESCRIPTION_INVALID')
      link = await this.#owner.connect({ connection, peerIdentity: peer.identity, signal,
        handshakeTimeoutMs: this.#timeoutMs, requestTimeoutMs: this.#timeoutMs, transferTimeoutMs: this.#timeoutMs })
      this.#discoveryFence.signal.removeEventListener('abort', fenceCandidate)
      this.#transports.set(link, { kind: description.kind, ...(description.reason === undefined ? {} : { reason: description.reason }) })
      try { await awaitOwnedTask(signal, () => link!.synchronize()) }
      catch (error) { if (!isPeerDataUnavailable(error)) throw error }
      signal.throwIfAborted(); this.#ownedLinks.add(link); this.#watchLinks()
      this.#nextScan = 0; this.#wake()
    } catch (error) {
      controller.abort(error)
      if (link !== undefined) await link.close()
      else if (connection !== undefined) void connection.close().catch(() => undefined)
      throw error
    } finally {
      clearTimeout(timer)
      this.#discoveryFence.signal.removeEventListener('abort', fenceCandidate)
      if (settled) this.#physicalOpenings.delete(token)
      if (this.#joining.get(peer.identity) === joining) this.#joining.delete(peer.identity)
      finished()
    }
  }

  #links(): readonly ApplicationPeerLink[] { return this.#owner.links().filter(link => !link.signal.aborted) }
  #observeGeneration(): void {
    const generation = this.#owner.participant.generation.id
    if (this.#generation === generation) return
    this.#generation = generation; this.#proposal = null; this.#approved = null
    this.#nextScan = 0; this.#nextAdvertisement = 0
  }
  #healthy(): boolean {
    const replica = this.#owner.participant.data?.replica
    if (replica === undefined) return this.#links().length > 0
    return replica.ready && (replica.isCoordinator || this.#links().some(link => link.peerId === replica.generation.payload.coordinator && link.data === 'active'))
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
    const replica = this.#owner.participant.data?.replica
    const error = this.#discoveryError ?? this.#error ?? this.#advertisementError ?? (replica !== undefined && this.#links().some(link => link.peerId === replica.generation.payload.coordinator && link.data === 'unavailable')
      ? 'APPLICATION_DATA_UNAVAILABLE' : null)
    const links = this.#links()
    const key = JSON.stringify(links.map(link => {
      let id = this.#connectionIds.get(link)
      if (id === undefined) { id = ++this.#nextConnectionId; this.#connectionIds.set(link, id) }
      return [link.peerId, id, this.#transports.get(link) ?? null] as const
    }).sort((left, right) => String(left[0]).localeCompare(String(right[0]))))
    if (key !== this.#connectionKey) { this.#connectionKey = key; this.#connectionRevision++ }
    const next: ApplicationParticipationStatus = {
      connectionRevision: this.#connectionRevision,
      phase: this.signal.aborted ? 'closed' : this.#discoveryTerminal ? 'unavailable' : !this.#hasDiscoveryReady ? error === null ? 'connecting' : 'unavailable' : phase ?? (this.#proposal !== null && this.#approved !== this.#proposal.id ? 'approval-required'
        : replica === undefined ? error !== null ? 'unavailable' : this.#links().length > 0 ? 'connected' : 'connecting'
          : !replica.ready ? 'recovering' : replica.isCoordinator ? 'coordinating' : this.#healthy() ? 'following' : error !== null ? 'unavailable' : 'connecting'),
      connectedPeers: this.#links().map(link => link.peerId).sort(), recovery: structuredClone(this.#proposal), error,
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
      const timer = Number.isFinite(ms) ? setTimeout(finish, ms) : undefined
      this.#wakeWait = finish; this.signal.addEventListener('abort', finish, { once: true })
      if (this.signal.aborted) finish()
    })
  }
  async #call<T>(key: string, call: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.signal.throwIfAborted(); this.#discoveryFence.signal.throwIfAborted()
    if (this.#calls.has(key)) throw new Error('APPLICATION_PARTICIPATION_BUSY')
    const timeout = new AbortController(), timer = setTimeout(() => timeout.abort(new Error('APPLICATION_PARTICIPATION_TIMEOUT')), this.#timeoutMs)
    const signal = AbortSignal.any([this.signal, this.#discoveryFence.signal, timeout.signal])
    const work = this.#delivery(key, () => { signal.throwIfAborted(); return call(signal) })
    try { return await awaitOwnedTask(signal, () => work) } finally { clearTimeout(timer) }
  }
  #delivery<T>(key: string, call: () => Promise<T>): Promise<T> {
    this.signal.throwIfAborted(); this.#discoveryFence.signal.throwIfAborted()
    if (this.#calls.has(key)) throw new Error('APPLICATION_PARTICIPATION_BUSY')
    const work = Promise.resolve().then(() => { this.signal.throwIfAborted(); this.#discoveryFence.signal.throwIfAborted(); return call() })
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
      await Promise.allSettled([this.#task, this.#notifications, this.#invitations, this.#upgradeTask, ...links.map(link => link.close())])
      await this.#persistence
      if (this.#discoveryTerminal) return
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

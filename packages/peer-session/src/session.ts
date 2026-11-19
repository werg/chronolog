import {
  PEER_GENERATION_CAPABILITIES, assertAuthorityExtension, verifyAuthorityBundle,
  type AuthorityBundle, type PeerAuthority, type PeerGrant, type PeerIdentity,
} from '@chronolog/peer-generation/control'
import type { PeerRevision, AppliedResult, OperationState, RecoveryNotice, SignedAttempt, SignedRetainedCoverage, PrefixProof } from '@chronolog/peer-generation'
import { bytesToHex, hexToBytes, type ChangeProgram, type EventPayload } from '@chronolog/protocol'
import { SignalChannel, type Signals } from '@chronolog/signals'
import { describeApplication, type ApplicationCommand, type ApplicationDefinition, type ApplicationQuery } from './definition.js'
import type { OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationData } from './application-data.js'
import type { ApplicationParticipant } from './participant-types.js'
import type { ApplicationContent } from './content.js'
import type { ApplicationKeyring } from './keys.js'
import type { ApplicationRecovery } from './recovery.js'
import { APPLICATION_PROJECTION_LIMITS, type ApplicationProjectionDefinition, type ApplicationProjectionHandle } from './projection-types.js'
import { ApplicationControlParticipant, type ControlParticipantOptions } from './control-participant.js'
import { OwnedApplicationParticipation } from './participation.js'
import type { ApplicationParticipation, ApplicationParticipationOptions } from './participation-types.js'
import { connectApplicationPeer, connectApplicationPeerPair, connectedApplicationPeers,
  type ApplicationPeerConnectOptions, type ApplicationPeerLink, type ApplicationPeerPort } from './network.js'
import type { ApplicationChange, ApplicationReadView, CommandOptions, SessionStatus } from './session-types.js'
import type { ApplicationOperation, ApplicationSubmission } from './operation.js'
import { awaitOwnedTask } from './lifetime.js'
import { deferredStream } from './deferred-stream.js'
import { retainApplicationAuthority } from './session-authority.js'

export * from './session-types.js'
export * from './errors.js'
export { ApplicationOperation, type ApplicationSubmission } from './operation.js'

type CommandArguments<T> = T extends ApplicationCommand<infer I> ? I : never
type QueryArguments<T> = T extends ApplicationQuery<infer I, unknown, never> ? I : never
type QueryResult<T> = T extends ApplicationQuery<never, infer R, never> ? Awaited<R> : never
interface PeerEndpoint { submit(attempt: SignedAttempt): Promise<void>; readonly link: { close(): Promise<void> } }
const internals = new WeakMap<ApplicationSession, ApplicationPeerPort>()
export type ApplicationContentAccess = Pick<ApplicationContent, 'stage' | 'resume' | 'read' | 'retain' | 'retained' | 'retention' | 'observeRetention'>
export type ApplicationRecoveryAccess = Pick<ApplicationRecovery, 'inspect' | 'takeover' | 'handover'>
export type ApplicationKeyAccess = Pick<ApplicationKeyring, 'install' | 'ensure' | 'request' | 'offer' | 'validate'> & {
  missing(requiredEpochs?: readonly number[]): Promise<readonly number[]>
}

/** One protocol owner, with a single durable facet loaded by actual data demand. */
export class ApplicationSession<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly capabilities: typeof PEER_GENERATION_CAPABILITIES & { readonly sql: boolean }
  readonly signals: Signals
  readonly content: ApplicationContentAccess
  readonly recovery: ApplicationRecoveryAccess
  readonly keys: ApplicationKeyAccess
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
    inspect(operationId: string, options?: { readonly author?: string }): Promise<{ readonly state: OperationState; readonly attempt: SignedAttempt } | null>
    wait(operationId: string, options?: { readonly author?: string; readonly signal?: AbortSignal }): Promise<AppliedResult>
  }
  readonly #options: OpenPeerApplicationOptions<D>
  readonly #closing: () => Promise<void>
  readonly #lifetime = new AbortController()
  readonly #participant: ApplicationParticipant
  readonly #peers = new Map<string, PeerEndpoint>()
  readonly #links = new Set<{ close(): Promise<void> }>()
  readonly #projections = new Map<string, ApplicationProjectionHandle>()
  readonly #listeners = new Set<() => void>()
  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #recoveryListeners = new Set<(notice: RecoveryNotice) => void>()
  #authority: PeerAuthority
  #authorityTail: Promise<unknown> = Promise.resolve()
  #data: ApplicationData<D> | undefined
  #dataTask: Promise<ApplicationData<D>> | undefined
  #initialDataTask: Promise<ApplicationData<D>> | undefined
  #database: SessionStatus['database'] = 'idle'
  #dataDisposers: Array<() => void> = []
  #lastStatus = ''
  #closed = false
  #closeTask: Promise<void> | undefined
  #control: ApplicationControlParticipant | undefined
  #participation: OwnedApplicationParticipation | undefined

  constructor(options: OpenPeerApplicationOptions<D>, authority: PeerAuthority, closing: () => Promise<void>) {
    this.#options = options; this.#authority = authority; this.#closing = closing
    this.capabilities = Object.freeze({ ...PEER_GENERATION_CAPABILITIES,
      sql: options.definition.schema !== undefined || authority.descriptor.schemaDigest !== null })
    const session = this
    this.#participant = {
      device: options.device.identity, storageId: options.device.storageId,
      get descriptor() { return session.#authority.descriptor },
      get authority() { return session.#authority.bundle },
      get generation() {
        const generation = session.#authority.current
        if (generation === null) throw new Error('PEER_NO_SELECTED_GENERATION')
        return generation
      },
      get isCoordinator() { return this.generation.payload.coordinator === this.device.publicKey },
      grant(publicKey) { return session.#authority.grant(publicKey) },
      adoptAuthority: async input => { await this.#adoptAuthority(input) },
      subscribe: listener => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener) } },
      get data() { return session.#data?.replica.closed === false ? session.#data : undefined }, openData: () => this.#openData(),
    }
    const signals = new SignalChannel({ ...options.signals?.limits, scope: this.applicationId,
      relay: options.signals?.delivery === 'application', localEcho: options.signals?.localEcho === true,
      identity: { publicKeyBytes: hexToBytes(this.deviceId), privateKey: options.device.identity.privateKey },
      authorize: ({ scope, authorId }) => scope === this.applicationId && this.#participant.grant(bytesToHex(authorId))?.reader === true })
    this.signals = signals
    internals.set(this, { participant: this.#participant, signals, signal: this.signal,
      attach: (peerId, submit, link) => this.#attachPeer(peerId, submit, link), resume: () => this.resume(),
      observeHead: (peerId, revision, requestedAt) => this.#participation?.observeHead(peerId, revision, requestedAt) })
    this.content = Object.freeze({
      stage: async input => (await this.#requireData()).content.stage(input),
      resume: async id => (await this.#requireData()).content.resume(id),
      read(reference, input = {}) { return deferredStream(async signal =>
        (await session.#dataFor(signal)).content.read(reference, { ...input, signal }), {
        signal: input.signal === undefined ? session.signal : AbortSignal.any([session.signal, input.signal]),
        concurrentNextError: 'APPLICATION_CONTENT_CONCURRENT_NEXT', abort: 'throw' }) },
      retain: async (reference, input = {}) => (await this.#dataFor(input.signal)).content.retain(reference, input),
      retained: async reference => (await this.#requireData()).content.retained(reference),
      retention: async reference => (await this.#requireData()).content.retention(reference),
      observeRetention: async receipt => (await this.#requireData()).content.observeRetention(receipt),
    })
    this.keys = Object.freeze({
      missing: async required => (await this.#requireData()).keys.missing(required),
      install: async input => (await this.#requireData()).keys.install(input),
      ensure: async required => (await this.#requireData()).keys.ensure(required),
      request: async required => (await this.#requireData()).keys.request(required),
      offer: async request => (await this.#requireData()).keys.offer(request),
      validate: async () => (await this.#requireData()).keys.validate(),
    })
    this.recovery = Object.freeze({
      inspect: async () => (await this.#requireData()).recovery.inspect(),
      takeover: async (host, input = {}) => (await this.#dataFor(input.signal)).recovery.takeover(host, input),
      handover: async (host, input) => (await this.#dataFor(input.signal)).recovery.handover(host, input),
    })
    this.operations = Object.freeze({
      get: async (id, input = {}) => (await this.#requireData()).operations.get(id, input),
      inspect: async (id, input = {}) => (await this.#requireData()).operations.inspect(id, input),
      wait: (id, input = {}) => this.waitFor(id, input),
    })
  }

  get signal(): AbortSignal { return this.#lifetime.signal }
  get revision(): PeerRevision | null { return this.#data?.replica.ready ? this.#data.replica.revision : null }
  get deviceId(): string { return this.#options.device.identity.publicKey }
  get applicationId(): string { return this.#participant.descriptor.applicationId }
  get historyId(): string { return this.#participant.descriptor.historyId }
  get storageId(): string { return this.#options.device.storageId }
  get participation(): ApplicationParticipation | undefined { return this.#participation }
  get status(): SessionStatus {
    const coordinator = this.#participant.generation.payload.coordinator, data = this.#participant.data
    return { phase: this.#closed ? 'closed' : data !== undefined && data.keys.missing().length > 0 ? 'awaiting-keys'
      : data !== undefined && !data.replica.ready ? 'recovering' : this.#participant.isCoordinator || this.#peers.has(coordinator) ? 'ready' : 'waiting',
      database: this.#database, role: this.#participant.isCoordinator ? 'coordinator' : 'follower',
      generation: this.#participant.generation.id, coordinator, connectedPeers: this.#peers.size }
  }
  describe() { return { ...describeApplication(this.#options.definition), capabilities: this.capabilities } }
  /** Public signed authority already verified by this owner; no data activation or host request. */
  async authority(): Promise<AuthorityBundle> {
    this.#assertOpen()
    return structuredClone(this.#participant.authority)
  }
  onStatus(listener: (status: SessionStatus) => void): () => void {
    this.#statusListeners.add(listener)
    try { listener(this.status) } catch { /* Observers cannot change ownership. */ }
    return () => { this.#statusListeners.delete(listener) }
  }
  #changed(): void {
    for (const listener of this.#listeners) { try { listener() } catch { /* Observers cannot change ownership. */ } }
    const status = this.status, encoded = JSON.stringify(status)
    if (encoded === this.#lastStatus) return
    this.#lastStatus = encoded
    for (const listener of this.#statusListeners) { try { listener(status) } catch { /* Observers cannot change ownership. */ } }
  }
  #serializeAuthority<T>(run: () => Promise<T>): Promise<T> {
    const result = this.#authorityTail.then(run); this.#authorityTail = result.catch(() => undefined); return result
  }
  #adoptAuthority(input: AuthorityBundle): Promise<RecoveryNotice | null> {
    const captured = structuredClone(input)
    return this.#serializeAuthority(async () => {
      this.#assertOpen()
      const next = await verifyAuthorityBundle(captured, this.#participant.authority.descriptor)
      assertAuthorityExtension(await verifyAuthorityBundle(this.#participant.authority), next)
      const retained = await retainApplicationAuthority(this.#options.device, next.bundle)
      this.#assertOpen(); this.#authority = retained
      const data = this.#participant.data
      let recovery: RecoveryNotice | null = null
      if (data !== undefined) {
        try { recovery = (await data.replica.receiveHistory(retained.bundle, [])).recovery }
        catch (error) { if (!data.replica.closed) throw error }
      }
      this.#changed(); return recovery
    })
  }
  #openData(): Promise<ApplicationData<D>> {
    this.#assertDataAvailable()
    if (this.#dataTask !== undefined) return this.#dataTask
    this.#database = 'opening'
    const task = (async () => {
      let data: ApplicationData<D> | undefined
      try {
        const { openApplicationData } = await import('./application-data.js')
        this.#assertOpen()
        data = await openApplicationData({ ...this.#options, authority: this.#participant.authority, session: this,
          adoptAuthority: async input => { await this.#adoptAuthority(input) },
          submit: async attempt => { await this.#peers.get(this.#participant.generation.payload.coordinator)?.submit(attempt) } })
        const opened = data
        await this.#serializeAuthority(async () => {
          this.#assertOpen()
          const retained = await retainApplicationAuthority(this.#options.device, opened.replica.authority)
          await opened.replica.receiveHistory(retained.bundle, []); this.#assertOpen()
          this.#authority = retained; this.#data = opened
          this.#dataDisposers = [opened.replica.subscribe(() => {
            if (opened.replica.closed && !this.#closed) {
              this.#database = 'failed'
              for (const dispose of this.#dataDisposers.splice(0)) dispose()
              void opened.close(new Error('APPLICATION_DATA_UNAVAILABLE')).catch(() => undefined)
            }
            this.#changed()
          }), opened.keys.subscribe(() => this.#changed()),
            opened.replica.onRecovery(notice => { for (const listener of this.#recoveryListeners) {
              try { listener(notice) } catch { /* Observers cannot undo durable recovery. */ }
            } })]
          this.#database = 'ready'; this.#changed()
        })
        void opened.resume().catch(() => undefined)
        return opened
      } catch (error) {
        await data?.close().catch(() => undefined)
        if (!this.#closed) { this.#database = 'failed'; this.#changed() }
        throw error
      }
    })()
    this.#dataTask = task; this.#changed()
    void task.catch(() => undefined)
    return task
  }
  /** Existing links join the first public data demand once; inbound activation remains local-only. */
  #requireData(): Promise<ApplicationData<D>> {
    this.#assertDataAvailable()
    this.#initialDataTask ??= Promise.resolve().then(async () => {
      const data = await this.#openData()
      await Promise.allSettled(connectedApplicationPeers(internals.get(this)!).map(link => link.synchronize()))
      this.#assertDataAvailable(); return data
    })
    return this.#initialDataTask
  }
  #dataFor(signal?: AbortSignal): Promise<ApplicationData<D>> {
    return awaitOwnedTask(signal === undefined ? this.signal : AbortSignal.any([this.signal, signal]), () => this.#requireData())
  }

  async command<Name extends keyof D['commands'] & string>(name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions): Promise<ApplicationOperation> {
    return (await this.#requireData()).command(name, input, options)
  }
  /** The owning host has authenticated and approved the use of this signing identity. */
  async submitProgramAs(program: ChangeProgram, author: PeerIdentity, options: CommandOptions): Promise<ApplicationSubmission> {
    const capturedProgram = structuredClone(program), identity = { ...author }, request = structuredClone(options)
    return (await this.#requireData()).submitProgramAs(capturedProgram, identity, request)
  }
  async reapply<Name extends keyof D['commands'] & string>(id: string, name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions & { readonly originalAuthor?: string }): Promise<ApplicationOperation> {
    return (await this.#requireData()).reapply(id, name, input, options)
  }
  async query<Name extends keyof D['queries'] & string>(name: Name, input: QueryArguments<D['queries'][Name]>): Promise<{ readonly revision: PeerRevision; readonly value: QueryResult<D['queries'][Name]> }> {
    return (await this.#requireData()).query(name, input)
  }
  memberGrant(publicKey: string): PeerGrant | null {
    this.#assertOpen()
    return this.#participant.grant(publicKey)
  }
  async operationByAttempt(attemptId: string, author: string): Promise<OperationState | null> {
    return (await this.#requireData()).replica.operationByAttempt(attemptId, author)
  }
  async readView(): Promise<ApplicationReadView> { return (await this.#requireData()).readView() }
  onRecovery(listener: (notice: RecoveryNotice) => void): () => void {
    this.#assertOpen(); this.#recoveryListeners.add(listener); return () => { this.#recoveryListeners.delete(listener) }
  }
  async inspectRecovery(): Promise<readonly RecoveryNotice[]> { return (await this.#requireData()).inspectRecovery() }
  async recoveryPoint(): Promise<PrefixProof> { return (await this.#requireData()).recoveryPoint() }
  async adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null> {
    const data = await this.#requireData(), notice = await this.#adoptAuthority(authority)
    this.#assertDataAvailable()
    return await data.adopt(this.#participant.authority) ?? notice
  }
  changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    return deferredStream(async signal => (await this.#dataFor(signal)).changes({ signal }), {
      signal: options.signal === undefined ? this.signal : AbortSignal.any([this.signal, options.signal]),
      concurrentNextError: 'APPLICATION_CHANGE_CONCURRENT_NEXT', abort: 'done' })
  }
  project<State extends EventPayload>(definition: ApplicationProjectionDefinition<State>): ApplicationProjectionHandle<State> {
    this.#assertOpen()
    if (this.#projections.has(definition.id)) throw new Error('APPLICATION_PROJECTION_IN_USE')
    if (this.#projections.size >= APPLICATION_PROJECTION_LIMITS.active) throw new Error('APPLICATION_PROJECTION_LIMIT')
    const captured = { ...definition, initial: structuredClone(definition.initial),
      ...(definition.topics === undefined ? {} : { topics: [...definition.topics] }) }
    const lifetime = new AbortController(), signal = AbortSignal.any([this.signal, lifetime.signal])
    let closed = false, actual: ApplicationProjectionHandle<State> | undefined
    const acquire = async (input?: AbortSignal): Promise<ApplicationProjectionHandle<State>> => {
      if (closed) throw new Error('APPLICATION_PROJECTION_CLOSED')
      const data = await this.#dataFor(input === undefined ? signal : AbortSignal.any([signal, input]))
      if (closed) throw new Error('APPLICATION_PROJECTION_CLOSED')
      actual ??= data.project(captured); return actual
    }
    const handle: ApplicationProjectionHandle<State> = Object.freeze({ id: captured.id,
      read: async (options: { readonly signal?: AbortSignal } = {}) => (await acquire(options.signal)).read(options),
      changes(options: { readonly signal?: AbortSignal } = {}) { return deferredStream(async owned =>
        (await acquire(owned)).changes({ signal: owned }), {
        signal: options.signal === undefined ? signal : AbortSignal.any([signal, options.signal]),
        concurrentNextError: 'APPLICATION_PROJECTION_CONCURRENT_NEXT', abort: 'done' }) },
      close: async () => { if (closed) return; closed = true; lifetime.abort(new Error('APPLICATION_PROJECTION_CLOSED'))
        this.#projections.delete(captured.id); await actual?.close() },
    })
    this.#projections.set(captured.id, handle); return handle
  }
  projection<State extends EventPayload = EventPayload>(id: string): ApplicationProjectionHandle<State> {
    this.#assertOpen(); const handle = this.#projections.get(id)
    if (handle === undefined) throw new Error('APPLICATION_PROJECTION_NOT_FOUND')
    return handle as ApplicationProjectionHandle<State>
  }
  connectPeer(options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
    this.#assertOpen(); return connectApplicationPeer(internals.get(this)!, options)
  }
  participate(options: ApplicationParticipationOptions): ApplicationParticipation {
    this.#assertOpen()
    if (this.#participation !== undefined) throw new Error('APPLICATION_PARTICIPATION_ALREADY_STARTED')
    const participation = new OwnedApplicationParticipation({ participant: this.#participant,
      store: this.#options.device.store, signal: this.signal, connect: input => this.connectPeer(input),
      links: () => connectedApplicationPeers(internals.get(this)!), resume: () => this.resume() }, options)
    this.#participation = participation; this.#links.add(participation); return participation
  }
  connectControlParticipant(options: ControlParticipantOptions): ApplicationControlParticipant {
    this.#assertOpen()
    if (this.#control !== undefined && this.#links.has(this.#control)) throw new Error('APPLICATION_CONTROL_ALREADY_ATTACHED')
    const participant = new ApplicationControlParticipant(this.#participant, this.#options.device.store, this.signal, options)
    this.#control = participant; this.#links.add(participant)
    participant.signal.addEventListener('abort', () => {
      const released = (): void => { this.#links.delete(participant) }
      void participant.close().then(released, released)
    }, { once: true })
    return participant
  }
  async retry(id: string, author?: string): Promise<void> { return (await this.#requireData()).retry(id, author) }
  async resume(): Promise<void> {
    this.#assertOpen()
    if (this.#participant.data !== undefined) await this.#data?.resume()
  }
  async waitFor(id: string, options: { readonly author?: string; readonly signal?: AbortSignal } = {}): Promise<AppliedResult> {
    return (await this.#dataFor(options.signal)).waitFor(id, options)
  }
  async waitForCoverage(applied: AppliedResult, options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> {
    return (await this.#dataFor(options.signal)).waitForCoverage(applied, options)
  }
  #attachPeer(peerId: string, submit: (attempt: SignedAttempt) => Promise<void>, link: { close(): Promise<void> }): () => void {
    this.#assertOpen()
    if (this.#participant.grant(peerId)?.reader !== true) throw new Error('APPLICATION_PEER_NOT_AUTHORIZED')
    if (this.#peers.size >= 8 && !this.#peers.has(peerId)) throw new Error('APPLICATION_PEER_LIMIT')
    const previous = this.#peers.get(peerId), endpoint = { submit, link }
    this.#peers.set(peerId, endpoint); this.#links.add(link)
    if (previous !== undefined && previous.link !== link) {
      try { void Promise.resolve(previous.link.close()).catch(() => undefined) } catch { /* The previous endpoint is replaced. */ }
    }
    this.#changed()
    return () => { if (this.#peers.get(peerId) === endpoint) this.#peers.delete(peerId); this.#links.delete(link); this.#changed() }
  }
  close(): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    this.#closeTask = Promise.resolve().then(async () => {
      await Promise.allSettled([...this.#links, ...this.#projections.values()].map(value => Promise.resolve().then(() => value.close())))
      await this.#dataTask?.catch(() => undefined)
      for (const dispose of this.#dataDisposers.splice(0)) dispose()
      await this.#authorityTail
      try { await this.#data?.close() } finally { await this.#closing() }
    })
    this.#closed = true; this.#database = 'closed'; this.#lifetime.abort(new Error('APPLICATION_SESSION_CLOSED'))
    internals.get(this)!.signals.close(); this.#changed()
    this.#listeners.clear(); this.#statusListeners.clear(); this.#recoveryListeners.clear()
    return this.#closeTask
  }
  #assertOpen(): void { if (this.#closed) throw new Error('APPLICATION_SESSION_CLOSED') }
  #assertDataAvailable(): void {
    this.#assertOpen()
    if (this.#data?.replica.closed === true) throw new Error('APPLICATION_DATA_UNAVAILABLE')
  }
}

/** In-process transport uses the same participant and durable-facet protocol. */
export async function connectApplications(left: ApplicationSession, right: ApplicationSession): Promise<{ synchronize(): Promise<void>; close(): Promise<void> }> {
  if (left === right) throw new Error('APPLICATION_PEER_SELF')
  return connectApplicationPeerPair(internals.get(left)!, internals.get(right)!)
}

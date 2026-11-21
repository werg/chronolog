import { APPLICATION_OWNER_PROTOCOL, type ApplicationOwnerHandshake, type ApplicationEndpointBinding, type ApplicationEndpointState } from './owner-types.js'
import type { AuthorityBundle, AppliedResult, OperationState, PeerRevision, PrefixProof, RecoveryNotice, SignedAttempt, SignedRetainedCoverage } from '@chronolog/peer-generation'
import { PEER_GENERATION_CAPABILITIES, validateApplicationDescription } from '@chronolog/peer-generation/metadata'
import type { EphemeralSignal, Signals } from '@chronolog/signals'
import type { EventPayload } from '@chronolog/protocol'
import type { ApplicationCommand, ApplicationDefinition, ApplicationQuery } from './definition.js'
import type { ContentReference, ContentRetention, ContentUpload } from './content.js'
import type { ApplicationRecoveryExpectation, ApplicationTransition } from './recovery.js'
import type { ApplicationChange, ApplicationEventBatch, ApplicationEventOptions, CommandOptions, QueryParameter, QueryRows, SessionStatus } from './session-types.js'
import type { ApplicationParticipation, ApplicationParticipationStatus, ApplicationConnectionDiagnostic } from './participation-types.js'
import type { ApplicationProjectionHandle, ApplicationProjectionSnapshot } from './projection-types.js'
import { AbandonedOperationError, RecoveredViewError } from './errors.js'
import { awaitOwnedTask } from './lifetime.js'
import { PROTOCOL, MAX_REQUESTS, MAX_RELEASES, MAX_STREAMS, releasesResource, bounded,
  type Endpoint, type Description, type Metadata, type Snapshot, type WireError, type Request, type Response } from './worker-application-protocol.js'

type CommandArguments<T> = T extends ApplicationCommand<infer I> ? I : never
type QueryArguments<T> = T extends ApplicationQuery<infer I, unknown, never> ? I : never
type QueryResult<T> = T extends ApplicationQuery<never, infer R, never> ? Awaited<R> : never
interface Pending { readonly bounded?: { readonly startedAt: number; readonly deadline: number }; readonly release: boolean; resolve(value: unknown): void; reject(reason: unknown): void }

/** Captured SQL/events stay in the Worker until explicitly released. */
export interface WorkerApplicationReadView {
  readonly revision: PeerRevision
  query(sql: string, parameters?: readonly QueryParameter[]): Promise<QueryRows>
  readEvents(options?: ApplicationEventOptions): Promise<ApplicationEventBatch>
  release(): Promise<void>
}

/** A saved operation remains in the owning Worker when its page stops waiting. */
export interface WorkerApplicationOperation {
  readonly operationId: string
  get(): Promise<OperationState | null>
  applied(options?: { readonly signal?: AbortSignal }): Promise<AppliedResult>
  retry(): Promise<void>
  shared(options?: { readonly signal?: AbortSignal }): Promise<readonly SignedRetainedCoverage[]>
}

/** Page-facing facade; the Worker owns signing keys, durable work and projections. */
export class WorkerApplicationSession<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly applicationId: string
  readonly historyId: string
  readonly deviceId: string
  readonly storageId: string
  readonly endpoint: ApplicationEndpointBinding | undefined
  readonly capabilities: Description['capabilities']
  readonly participation: ApplicationParticipation | undefined
  readonly operations = {
    get: (id: string, options: { readonly author?: string } = {}): Promise<OperationState | null> => this.#call('operation.get', [id, options]),
    inspect: (id: string, options: { readonly author?: string } = {}): Promise<{ readonly state: OperationState; readonly attempt: SignedAttempt } | null> => this.#call('operation.inspect', [id, options]),
    wait: (id: string, options: { readonly author?: string; readonly signal?: AbortSignal } = {}): Promise<AppliedResult> => {
      const { signal, ...scope } = options
      return this.#call('operation.wait', [id, scope], signal, true)
    },
  }
  readonly recovery = {
    inspect: (): Promise<readonly ApplicationTransition[]> => this.#call('recovery.inspect', []),
    takeover: (options: { readonly coordinator?: string; readonly transitionId?: string; readonly expected?: ApplicationRecoveryExpectation; readonly signal?: AbortSignal } = {}): Promise<RecoveryNotice | null> => {
      const { signal, ...request } = options
      return this.#call('recovery.takeover', [request], signal, true)
    },
    handover: (options: { readonly coordinator: string; readonly transitionId?: string; readonly signal?: AbortSignal }): Promise<RecoveryNotice | null> => {
      const { signal, ...request } = options
      return this.#call('recovery.handover', [request], signal, true)
    },
  }
  readonly signals: Signals = {
    send: (topic, payload, options = {}) => this.#call('signals.send', [topic, payload, { ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }), ...(options.stream === undefined ? {} : { stream: options.stream }) }], options.signal),
    subscribe: (options = {}) => this.#stream<EphemeralSignal>('signals', [{ ...(options.topics === undefined ? {} : { topics: options.topics }),
      ...(options.mode === undefined ? {} : { mode: options.mode }), ...(options.streams === undefined ? {} : { streams: options.streams }) }], options.signal),
  }
  readonly content = {
    stage: async (options: { readonly bytes: number; readonly mediaType?: string }): Promise<ContentUpload> => this.#upload(await this.#call('content.stage', [options])),
    resume: async (id: string): Promise<ContentUpload> => this.#upload(await this.#call('content.resume', [id])),
    read: (reference: ContentReference, options: { readonly offset?: number; readonly length?: number; readonly signal?: AbortSignal } = {}): AsyncIterable<Uint8Array> =>
      this.#stream('content', [reference, { ...(options.offset === undefined ? {} : { offset: options.offset }), ...(options.length === undefined ? {} : { length: options.length }) }], options.signal),
    retain: (reference: ContentReference, options: { readonly signal?: AbortSignal } = {}): Promise<ContentRetention> => this.#call('content.retain', [reference], options.signal),
    retained: (reference: ContentReference): Promise<ContentRetention> => this.#call('content.retained', [reference]),
    retention: (reference: ContentReference): Promise<readonly ContentRetention[]> => this.#call('content.retention', [reference]),
  }
  readonly #port: MessagePort
  readonly #description: Description
  readonly #timeoutMs: number
  readonly #lifetime = new AbortController()
  readonly #pending = new Map<number, Pending>()
  readonly #streams = new Set<AbortController>()
  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #recoveryListeners = new Set<(notice: RecoveryNotice) => void>()
  readonly #participationListeners = new Set<(status: ApplicationParticipationStatus) => void>()
  readonly #participationLifetime = new AbortController()
  #snapshot: Snapshot
  #nextId = 0
  #closing: Promise<void> | undefined
  #stopExternal: (() => void) | undefined

  /** Construct through connectApplicationWorker so readiness is authenticated to the owned port. */
  constructor(port: MessagePort, metadata: Metadata, timeoutMs: number, signal?: AbortSignal) {
    this.#port = port; this.#timeoutMs = timeoutMs; this.#snapshot = metadata
    this.applicationId = metadata.applicationId; this.historyId = metadata.historyId; this.deviceId = metadata.deviceId; this.storageId = metadata.storageId
    this.endpoint = metadata.endpoint === undefined ? undefined : Object.freeze({ ...metadata.endpoint,
      context: Object.freeze({ ...metadata.endpoint.context }), capabilities: Object.freeze([...metadata.endpoint.capabilities]),
      ...(metadata.endpoint.identity === undefined ? {} : { identity: Object.freeze({ ...metadata.endpoint.identity }) }) })
    Object.defineProperty(this.signals, 'delivery', { value: metadata.signalDelivery ?? 'neighbors', enumerable: true })
    this.capabilities = Object.freeze({ ...metadata.description.capabilities })
    this.#description = { ...metadata.description, capabilities: this.capabilities }
    if (metadata.participation !== null) {
      const owner = this
      this.participation = {
        get status() { return structuredClone(owner.#snapshot.participation!) },
        signal: this.#participationLifetime.signal,
        onStatus(listener) {
          owner.#participationListeners.add(listener)
          try { listener(structuredClone(owner.#snapshot.participation!)) } catch { /* Observation does not own participation. */ }
          return () => { owner.#participationListeners.delete(listener) }
        },
        diagnostics: async () => {
          const value: unknown = await this.#call('participation.diagnostics', [])
          validateConnectionDiagnostics(value); return value
        },
        reconsiderConnections: () => this.#call('participation.reconsider', []),
        approveRecovery: id => this.#call('participation.approve', [id]),
        close: () => this.#call('participation.close', []),
      }
      if (metadata.participation.phase === 'closed') this.#participationLifetime.abort(new Error('APPLICATION_PARTICIPATION_CLOSED'))
    }
    port.addEventListener('message', this.#receive); port.addEventListener('messageerror', this.#messageError); port.start()
    if (signal !== undefined) {
      const abort = (): void => { void this.close().catch(() => undefined) }
      signal.addEventListener('abort', abort, { once: true }); this.#stopExternal = () => signal.removeEventListener('abort', abort)
      if (signal.aborted) abort()
    }
    // Every response carries the current coherent snapshot; an older coalesced
    // callback value must not replace that newer observed status.
    if (this.endpoint === undefined || this.endpoint.capabilities.includes('diagnostics')) {
    void this.#observe('status', () => {}).catch(error => this.#fail(error))
    void this.#observe('recovery', notice => {
      for (const listener of this.#recoveryListeners) { try { listener(notice as RecoveryNotice) } catch { /* Observers cannot change application progress. */ } }
    }).catch(error => this.#fail(error))
    if (this.participation !== undefined) void this.#observe('participation', () => {}).catch(error => this.#fail(error))
    }
  }
  /** Oldest finite facade call, in this realm's performance.now() clock.
   * Passive stream/operation waits never count. This is a caller deadline,
   * not evidence that the owner received or began executing the request.
   */
  get boundedRequest(): { readonly startedAt: number; readonly deadline: number } | null {
    let oldest: Pending['bounded']
    for (const request of this.#pending.values()) {
      if (request.bounded !== undefined && (oldest === undefined || request.bounded.startedAt < oldest.startedAt)) oldest = request.bounded
    }
    return oldest === undefined ? null : { ...oldest }
  }
  get signal(): AbortSignal { return this.#lifetime.signal }
  get status(): SessionStatus { return { ...this.#snapshot.status } }
  get revision(): PeerRevision | null { return structuredClone(this.#snapshot.revision) }
  describe(): Description { return structuredClone(this.#description) }
  authority(): Promise<AuthorityBundle> { return this.#call('authority', []) }
  onStatus(listener: (status: SessionStatus) => void): () => void {
    this.#statusListeners.add(listener)
    try { listener(this.status) } catch { /* Observation does not own the session. */ }
    return () => { this.#statusListeners.delete(listener) }
  }
  onRecovery(listener: (notice: RecoveryNotice) => void): () => void {
    this.signal.throwIfAborted(); this.#recoveryListeners.add(listener)
    return () => { this.#recoveryListeners.delete(listener) }
  }
  async command<Name extends keyof D['commands'] & string>(name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions): Promise<WorkerApplicationOperation> {
    return this.#operation(await this.#call('command', [name, input, options]))
  }
  async reapply<Name extends keyof D['commands'] & string>(id: string, name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions & { readonly originalAuthor?: string }): Promise<WorkerApplicationOperation> {
    return this.#operation(await this.#call('reapply', [id, name, input, options]))
  }
  query<Name extends keyof D['queries'] & string>(name: Name, input: QueryArguments<D['queries'][Name]>): Promise<{ readonly revision: PeerRevision; readonly value: QueryResult<D['queries'][Name]> }> {
    return this.#call('query', [name, input])
  }
  retry(id: string): Promise<void> { return this.#call('retry', [id]) }
  resume(): Promise<void> { return this.#call('resume', []) }
  inspectRecovery(): Promise<readonly RecoveryNotice[]> { return this.#call('inspectRecovery', []) }
  recoveryPoint(): Promise<PrefixProof> { return this.#call('recoveryPoint', []) }
  adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null> { return this.#call('adopt', [authority]) }
  changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> { return this.#stream('changes', [], options.signal) }
  projection<State extends EventPayload = EventPayload>(id: string): ApplicationProjectionHandle<State> {
    const captured = this.#call<number>('projection.open', [id]), lifetime = new AbortController()
    // An unused facade may outlive a failed remote lookup without an unhandled rejection.
    void captured.catch(() => undefined)
    let closing: Promise<void> | undefined
    const signal = (external?: AbortSignal): AbortSignal => AbortSignal.any([this.signal, lifetime.signal,
      ...(external === undefined ? [] : [external])])
    return Object.freeze({ id,
      read: async (options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationProjectionSnapshot<State>> => {
        const owned = signal(options.signal), token = await awaitOwnedTask(owned, () => captured)
        return this.#call('projection.read', [token], owned)
      },
      changes: (options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationProjectionSnapshot<State>> =>
        this.#stream('projection', async () => [await captured], signal(options.signal)),
      close: (): Promise<void> => {
        if (closing !== undefined) return closing
        closing = captured.then(token => this.signal.aborted ? undefined : this.#call<void>('projection.close', [token]))
          .catch(error => { closing = undefined; if (!this.signal.aborted) throw error })
        lifetime.abort(new Error('APPLICATION_PROJECTION_CLOSED'))
        return closing
      },
    })
  }
  async readView(): Promise<WorkerApplicationReadView> {
    const captured = await this.#call<{ id: number; revision: PeerRevision }>('view.open', [])
    let released = false
    const held = (): void => { if (released) throw new Error('APPLICATION_VIEW_RELEASED') }
    return { revision: captured.revision,
      query: (sql, parameters = []) => { held(); return this.#call('view.query', [captured.id, sql, parameters]) },
      readEvents: (options = {}) => { held(); return this.#call('view.events', [captured.id, options]) },
      release: async () => { if (released) return; released = true; await this.#call('view.release', [captured.id]) },
    }
  }
  /** Detach cancels this endpoint's observation only; the owner's journal survives. */
  detach(): Promise<void> { return this.close() }
  suspend(): Promise<void> { return this.#call('endpoint.suspend', []) }
  resumeAttachment(): Promise<ApplicationEndpointBinding | null> { return this.#call('endpoint.resume', []) }
  endpoints(): Promise<readonly (ApplicationEndpointBinding & { readonly state: ApplicationEndpointState })[]> { return this.#call('endpoints.list', []) }
  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing
    this.#closing = (async () => {
      try { if (!this.signal.aborted) await this.#call('close', []) }
      catch (error) { if (!this.signal.aborted) throw error }
      finally { this.#fail(new Error('APPLICATION_SESSION_CLOSED')) }
    })()
    return this.#closing
  }
  #call<T>(method: string, args: readonly unknown[], signal?: AbortSignal, passive = false): Promise<T> {
    if (this.signal.aborted) return Promise.reject(this.signal.reason)
    if (signal?.aborted) return Promise.reject(signal.reason)
    const release = releasesResource(method)
    if (method !== 'close' && [...this.#pending.values()].filter(call => call.release === release).length >= (release ? MAX_RELEASES : MAX_REQUESTS)) return Promise.reject(new Error('APPLICATION_WORKER_REQUEST_LIMIT'))
    const id = ++this.#nextId
    if (!Number.isSafeInteger(id)) return Promise.reject(new Error('APPLICATION_WORKER_REQUEST_ID_EXHAUSTED'))
    const request: Request = { id, method, args }
    try { bounded(request) } catch (error) { return Promise.reject(error) }
    return new Promise<T>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined
      const clean = (): void => { signal?.removeEventListener('abort', abort); if (timer !== undefined) clearTimeout(timer) }
      const abort = (): void => {
        clean(); this.#pending.delete(id); this.#cancel(id); reject(signal?.reason ?? new Error('APPLICATION_WORKER_TIMEOUT'))
      }
      const startedAt = performance.now()
      this.#pending.set(id, { ...(passive ? {} : { bounded: { startedAt, deadline: startedAt + this.#timeoutMs } }), release, resolve: value => { clean(); resolve(value as T) }, reject: error => { clean(); reject(error) } })
      signal?.addEventListener('abort', abort, { once: true })
      if (!passive) timer = setTimeout(abort, this.#timeoutMs)
      try { this.#port.postMessage(request) } catch (error) { this.#pending.delete(id); clean(); reject(error) }
    })
  }
  #stream<T>(name: string, args: readonly unknown[] | (() => Promise<readonly unknown[]>), signal?: AbortSignal): AsyncIterable<T> {
    const client = this
    return { [Symbol.asyncIterator]() {
      if (name !== 'content' && (client.signal.aborted || signal?.aborted)) {
        const ended = async (): Promise<IteratorResult<T>> => ({ done: true, value: undefined })
        return { next: ended, return: ended }
      }
      if (client.#streams.size >= MAX_STREAMS) throw new Error('APPLICATION_WORKER_STREAM_LIMIT')
      const controller = new AbortController(); client.#streams.add(controller)
      const lifetime = AbortSignal.any([client.signal, controller.signal, ...(signal === undefined ? [] : [signal])])
      let opened: Promise<number> | undefined, id: number | undefined, done = false, pulling = false
      const finish = (): void => {
        if (done) return
        done = true; controller.abort(new Error('APPLICATION_WORKER_STREAM_CLOSED')); client.#streams.delete(controller)
        if (id !== undefined) client.#cancel(id)
        else void opened?.then(value => client.#cancel(value), () => undefined)
      }
      lifetime.addEventListener('abort', finish, { once: true })
      return {
        async next(): Promise<IteratorResult<T>> {
          if (done) return { done: true, value: undefined }
          if (pulling) throw new Error('APPLICATION_WORKER_STREAM_BUSY')
          pulling = true
          try {
            opened ??= typeof args === 'function'
              ? awaitOwnedTask(lifetime, args).then(values => client.#call<number>('stream.open', [name, ...values], lifetime))
              : client.#call<number>('stream.open', [name, ...args], lifetime)
            id = await opened
            const result = await client.#call<IteratorResult<T>>('stream.next', [id], lifetime, true)
            if (result.done) finish()
            return result
          } catch (error) {
            const cancelled = lifetime.aborted; finish()
            // Observation closes normally; interrupted byte reads must still
            // report failure instead of appearing to be complete content.
            if (cancelled && name !== 'content') return { done: true, value: undefined }
            throw error
          }
          finally { pulling = false }
        },
        async return(): Promise<IteratorResult<T>> { finish(); lifetime.removeEventListener('abort', finish); return { done: true, value: undefined } },
      }
    } }
  }
  #operation(id: string): WorkerApplicationOperation {
    return Object.freeze({ operationId: id, get: () => this.operations.get(id),
      applied: (options: { readonly signal?: AbortSignal } = {}) => this.operations.wait(id, options),
      retry: () => this.retry(id), shared: (options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> => this.#call('operation.shared', [id], options.signal, true) })
  }
  #upload(id: string): ContentUpload {
    return { id, write: (index, bytes) => this.#call('content.write', [id, index, bytes]),
      progress: () => this.#call('content.progress', [id]), commit: () => this.#call('content.commit', [id]) }
  }
  async #observe(name: string, listener: (value: unknown) => void): Promise<void> {
    try { for await (const value of this.#stream(name, [], this.signal)) listener(value) }
    catch (error) { if (!this.signal.aborted) throw error }
  }
  #cancel(id: number): void { try { this.#port.postMessage({ cancel: id }) } catch { /* Cancellation never replaces durable work. */ } }
  readonly #receive = (event: MessageEvent): void => {
    try {
      bounded(event.data)
      const response = event.data as Response & { ended?: WireError }
      if (response.ended !== undefined) { this.#fail(fromError(response.ended), false); return }
      if (!Number.isSafeInteger(response.id)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      const pending = this.#pending.get(response.id)
      if (pending === undefined) return // A cancelled waiter can have an already posted result.
      // Validate and publish the response snapshot while this waiter is still
      // owned. A malformed reply must reject it immediately when the port ends.
      this.#update(response.snapshot); this.#pending.delete(response.id)
      if (response.error === undefined) pending.resolve(response.value)
      else pending.reject(fromError(response.error))
    } catch (error) { this.#fail(error) }
  }
  readonly #messageError = (): void => { this.#fail(new Error('APPLICATION_WORKER_MESSAGE_INVALID')) }
  #update(value: Snapshot): void {
    validateStatus(value.status); validateParticipation(value.participation)
    if ((value.participation === null) !== (this.participation === undefined)) throw new Error('APPLICATION_WORKER_PARTICIPATION_CHANGED')
    const changed = JSON.stringify(value.status) !== JSON.stringify(this.#snapshot.status)
    const participationChanged = JSON.stringify(value.participation) !== JSON.stringify(this.#snapshot.participation)
    this.#snapshot = value
    if (changed) for (const listener of this.#statusListeners) { try { listener(this.status) } catch { /* Observation cannot change state. */ } }
    if (value.participation?.phase === 'closed') this.#participationLifetime.abort(new Error('APPLICATION_PARTICIPATION_CLOSED'))
    if (participationChanged) for (const listener of this.#participationListeners) {
      try { listener(structuredClone(value.participation!)) } catch { /* Observation cannot choose recovery. */ }
    }
  }
  #fail(reason: unknown, notifyOwner = true): void {
    if (this.signal.aborted) return
    if (notifyOwner) {
      try { this.#port.postMessage({ id: ++this.#nextId, method: 'close', args: [] } satisfies Request) }
      catch { /* A failed port cannot acknowledge cleanup; the Worker lifetime still fences all work. */ }
    }
    this.#lifetime.abort(reason); this.#stopExternal?.()
    this.#participationLifetime.abort(reason)
    this.#snapshot = { ...this.#snapshot, status: { ...this.#snapshot.status, phase: 'closed', database: 'closed' },
      participation: this.#snapshot.participation === null ? null : { ...this.#snapshot.participation, phase: 'closed' } }
    for (const listener of this.#statusListeners) { try { listener(this.status) } catch { /* Observe closure independently. */ } }
    this.#statusListeners.clear(); this.#recoveryListeners.clear()
    for (const listener of this.#participationListeners) {
      try { listener(structuredClone(this.#snapshot.participation!)) } catch { /* Observe closure independently. */ }
    }
    this.#participationListeners.clear()
    for (const pending of this.#pending.values()) pending.reject(reason)
    this.#pending.clear()
    for (const controller of this.#streams) controller.abort(reason)
    this.#streams.clear()
    this.#port.removeEventListener('message', this.#receive); this.#port.removeEventListener('messageerror', this.#messageError); this.#port.close()
  }
}

/** Connect to a ready Worker without exposing or transferring its signing keys. */
export function connectApplicationWorker<D extends ApplicationDefinition = ApplicationDefinition>(endpoint: Endpoint, options: {
  readonly signal?: AbortSignal; readonly timeoutMs?: number
} = {}): Promise<WorkerApplicationSession<D>> {
  return connect<D>(endpoint, options, PROTOCOL)
}
/** Attach to an existing owner without opening a signer store or creating a session. */
export function connectApplicationOwner<D extends ApplicationDefinition = ApplicationDefinition>(endpoint: Endpoint,
  options: ApplicationOwnerHandshake & { readonly signal?: AbortSignal; readonly timeoutMs?: number }): Promise<WorkerApplicationSession<D>> {
  const { signal, timeoutMs, ...handshake } = options
  return connect<D>(endpoint, { ...(signal === undefined ? {} : { signal }), ...(timeoutMs === undefined ? {} : { timeoutMs }) }, APPLICATION_OWNER_PROTOCOL, handshake)
}
function connect<D extends ApplicationDefinition>(endpoint: Endpoint, options: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
  protocol: Metadata['protocol'], handshake?: ApplicationOwnerHandshake): Promise<WorkerApplicationSession<D>> {
  const timeoutMs = options.timeoutMs ?? 30_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) return Promise.reject(new Error('APPLICATION_WORKER_TIMEOUT_INVALID'))
  if (options.signal?.aborted) return Promise.reject(options.signal.reason)
  const channel = new MessageChannel(), port = channel.port1
  return new Promise((resolve, reject) => {
    const clean = (): void => { clearTimeout(timer); options.signal?.removeEventListener('abort', abort); port.removeEventListener('message', ready) }
    const fail = (reason: unknown): void => {
      clean()
      try { port.postMessage({ id: 1, method: 'close', args: [] } satisfies Request) } catch { /* The handoff may not have reached the Worker. */ }
      port.close(); channel.port2.close(); reject(reason)
    }
    const abort = (): void => { fail(options.signal?.reason) }
    const ready = (event: MessageEvent): void => {
      try {
        bounded(event.data)
        const value = event.data as { ready?: Metadata; ended?: WireError }
        if (value.ended !== undefined) { fail(fromError(value.ended)); return }
        const metadata = value.ready
        if (metadata === undefined || metadata.protocol !== protocol || !/^[0-9a-f]{64}$/u.test(metadata.applicationId) || !/^[0-9a-f]{64}$/u.test(metadata.deviceId) ||
            typeof metadata.storageId !== 'string' || typeof metadata.historyId !== 'string') {
          throw new Error('APPLICATION_WORKER_METADATA_INVALID')
        }
        const { capabilities, ...description } = metadata.description
        if (capabilities === null || typeof capabilities !== 'object' || typeof capabilities.sql !== 'boolean' ||
            Object.keys(capabilities).length !== Object.keys(PEER_GENERATION_CAPABILITIES).length + 1 ||
            Object.entries(PEER_GENERATION_CAPABILITIES).some(([key, expected]) => capabilities[key as keyof typeof PEER_GENERATION_CAPABILITIES] !== expected)) {
          throw new Error('APPLICATION_WORKER_METADATA_INVALID')
        }
        validateApplicationDescription(description)
        if (handshake !== undefined && (metadata.applicationId !== handshake.applicationId || description.id !== handshake.definitionId || description.version !== handshake.definitionVersion || !validEndpoint(metadata.endpoint))) throw new Error('CONTRACT_INCOMPATIBLE')
        validateStatus(metadata.status); validateParticipation(metadata.participation)
        clean(); resolve(new WorkerApplicationSession<D>(port, metadata, timeoutMs, options.signal))
      } catch (error) { fail(error) }
    }
    const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_READY_TIMEOUT')), timeoutMs)
    options.signal?.addEventListener('abort', abort, { once: true }); port.addEventListener('message', ready); port.start()
    try { endpoint.postMessage({ protocol, port: channel.port2, ...(handshake === undefined ? {} : { handshake }) }, [channel.port2]) }
    catch (error) { fail(error) }
  })
}

function validateParticipation(value: unknown): asserts value is ApplicationParticipationStatus | null {
  if (value === null) return
  if (value === undefined || typeof value !== 'object') throw new Error('APPLICATION_WORKER_METADATA_INVALID')
  const status = value as ApplicationParticipationStatus
  if (!['connecting', 'connected', 'following', 'coordinating', 'recovering', 'approval-required', 'unavailable', 'closed'].includes(status.phase) ||
      !Array.isArray(status.connectedPeers) || status.connectedPeers.length > 8 ||
      status.connectedPeers.some(peer => typeof peer !== 'string' || !/^[0-9a-f]{64}$/u.test(peer)) ||
      status.error !== null && typeof status.error !== 'string' || status.recovery === undefined ||
      status.recovery !== null && (typeof status.recovery !== 'object' || typeof status.recovery.id !== 'string' ||
        !['freshness-unknown', 'older-than-budget'].includes(status.recovery.reason) ||
        status.recovery.observedAt !== null && (!Number.isSafeInteger(status.recovery.observedAt) || status.recovery.observedAt < 0) ||
        status.recovery.ageMs !== null && (!Number.isSafeInteger(status.recovery.ageMs) || status.recovery.ageMs < 0))) {
    throw new Error('APPLICATION_WORKER_METADATA_INVALID')
  }
}
function fromError(error: WireError): Error {
  if (error.name === 'AbandonedOperationError' && error.operation && (error.operation.status === 'abandoned' || error.operation.status === 'needsReapply')) return new AbandonedOperationError(error.operation)
  if (error.name === 'RecoveredViewError' && error.revision) return new RecoveredViewError(error.revision)
  return Object.assign(new Error(error.message), { name: error.name, ...(error.code === undefined ? {} : { code: error.code }) })
}

function validateStatus(value: unknown): asserts value is SessionStatus {
  if (value === null || typeof value !== 'object') throw new Error('APPLICATION_WORKER_METADATA_INVALID')
  const status = value as SessionStatus
  if (!['ready', 'waiting', 'recovering', 'awaiting-keys', 'closed'].includes(status.phase) ||
      !['idle', 'opening', 'ready', 'failed', 'closed'].includes(status.database) ||
      !['coordinator', 'follower'].includes(status.role) || typeof status.generation !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(status.generation) || typeof status.coordinator !== 'string' ||
      !/^[0-9a-f]{64}$/u.test(status.coordinator) || !Number.isSafeInteger(status.connectedPeers) ||
      status.connectedPeers < 0 || status.connectedPeers > 8) throw new Error('APPLICATION_WORKER_METADATA_INVALID')
}

function validEndpoint(value: ApplicationEndpointBinding | undefined): value is ApplicationEndpointBinding {
  return value !== undefined && ['ownerInstanceId', 'endpointId', 'endpointIncarnation'].every(key =>
    typeof value[key as keyof ApplicationEndpointBinding] === 'string' && /^[A-Za-z0-9-]{1,128}$/u.test(value[key as keyof ApplicationEndpointBinding] as string)) &&
    value.evidence === 'owner-bound' && ['caller-asserted', 'owner-validated'].includes(value.contextEvidence) &&
    value.context !== null && typeof value.context === 'object' && Array.isArray(value.capabilities) &&
    value.capabilities.length <= 8 && value.capabilities.every((item: unknown) => typeof item === 'string' && ['commands', 'queries', 'events', 'content', 'signals', 'operations', 'diagnostics', 'ownerAdmin'].includes(item))
}

function validateConnectionDiagnostics(value: unknown): asserts value is readonly ApplicationConnectionDiagnostic[] {
  if (!Array.isArray(value) || value.length > 8) throw new Error('APPLICATION_WORKER_METADATA_INVALID')
  const peers = new Set<string>()
  for (const item of value as unknown[]) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) throw new Error('APPLICATION_WORKER_METADATA_INVALID')
    const record = item as Record<string, unknown>
    const counts = ['sentBytes', 'receivedBytes', 'sentReliableBytes', 'receivedReliableBytes', 'sentLiveBytes', 'receivedLiveBytes', 'sentRequests', 'receivedRequests']
    if (Object.keys(record).some(key => !['peerId', 'kind', 'reason', ...counts].includes(key)) ||
        typeof record.peerId !== 'string' || !/^[0-9a-f]{64}$/u.test(record.peerId) || peers.has(record.peerId) ||
        !['direct', 'relay', 'unknown'].includes(record.kind as string) ||
        record.reason !== undefined && !['direct_failed', 'direct_timeout'].includes(record.reason as string) ||
        counts.some(key => !Number.isSafeInteger(record[key]) || (record[key] as number) < 0) ||
        record.sentBytes !== (record.sentReliableBytes as number) + (record.sentLiveBytes as number) ||
        record.receivedBytes !== (record.receivedReliableBytes as number) + (record.receivedLiveBytes as number)) throw new Error('APPLICATION_WORKER_METADATA_INVALID')
    peers.add(record.peerId)
  }
}

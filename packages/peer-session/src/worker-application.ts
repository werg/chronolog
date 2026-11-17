import type { AuthorityBundle, AppliedResult, OperationState, PeerRevision, PrefixProof, RecoveryNotice, SignedAttempt, SignedRetainedCoverage } from '@chronolog/peer-generation'
import type { EphemeralSignal, SignalPayload, SignalSendOptions, Signals, SignalSubscribeOptions } from '@chronolog/signals'

import type { ApplicationCommand, ApplicationDefinition, ApplicationQuery } from './definition.js'
import type { ContentReference, ContentRetention, ContentUpload } from './content.js'
import type { ApplicationControlHost, ApplicationTransition } from './recovery.js'
import {
  AbandonedOperationError, RecoveredViewError, type ApplicationChange, type ApplicationEventBatch,
  type ApplicationEventOptions, type ApplicationReadView, type ApplicationSession, type CommandOptions,
  type QueryParameter, type QueryRows, type SessionStatus,
} from './session.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'

const PROTOCOL = 'chronolog/peer-session/worker-application/v1'
const MAX_REQUESTS = 64, MAX_STREAMS = 16, MAX_BYTES = 1_048_576
type Endpoint = ApplicationWorkerEndpoint & { start?(): void }
type Description = ReturnType<ApplicationSession['describe']>
type CommandArguments<T> = T extends ApplicationCommand<infer I> ? I : never
type QueryArguments<T> = T extends ApplicationQuery<infer I, unknown, never> ? I : never
type QueryResult<T> = T extends ApplicationQuery<never, infer R, never> ? Awaited<R> : never
interface Snapshot { readonly status: SessionStatus; readonly revision: PeerRevision | null }
interface Metadata extends Snapshot {
  readonly applicationId: string; readonly historyId: string; readonly deviceId: string; readonly storageId: string
  readonly description: Description
}
interface WireError { readonly name: string; readonly message: string; readonly code?: string; readonly operation?: OperationState; readonly revision?: PeerRevision }
interface Request { readonly id: number; readonly method: string; readonly args: readonly unknown[] }
interface Response { readonly id: number; readonly value?: unknown; readonly error?: WireError; readonly snapshot: Snapshot }
interface Stream { readonly iterator: AsyncIterator<unknown>; readonly controller: AbortController; busy: boolean }
interface Pending { resolve(value: unknown): void; reject(reason: unknown): void }

/** Captured SQL/events stay in the Worker until explicitly released. */
export interface WorkerApplicationReadView {
  readonly revision: PeerRevision
  query(sql: string, parameters?: readonly QueryParameter[]): Promise<QueryRows>
  readEvents(options?: ApplicationEventOptions): Promise<ApplicationEventBatch>
  release(): Promise<void>
}

/**
 * Serve one page facade beside the owned application. A dedicated port isolates
 * application RPC from RTC handoff and application-owned UI messages. The same
 * pull/cancel pattern as the maintained browser RPC keeps streams bounded.
 */
export function serveApplicationWorker(session: ApplicationSession, endpoint: Endpoint, options: {
  readonly host?: ApplicationControlHost
} = {}): { close(): Promise<void> } {
  let port: MessagePort | undefined, closed = false, lastId = 0, nextView = 0
  let closing: Promise<void> | undefined
  const calls = new Map<number, AbortController>(), streams = new Map<number, Stream>(), views = new Map<number, ApplicationReadView>()
  const send = (value: unknown): void => { bounded(value); port?.postMessage(value) }
  const respond = (id: number, value: unknown): void => { send({ id, value, snapshot: snapshot(session) } satisfies Response) }
  const cancelStream = async (id: number): Promise<void> => {
    const stream = streams.get(id)
    if (stream === undefined) return
    streams.delete(id); stream.controller.abort(new Error('APPLICATION_WORKER_CANCELLED'))
    await stream.iterator.return?.().catch(() => undefined)
  }
  const stop = (reason: unknown): Promise<void> => {
    if (closing !== undefined) return closing
    closed = true
    endpoint.removeEventListener('message', connect)
    session.signal.removeEventListener('abort', aborted)
    for (const controller of calls.values()) controller.abort(reason)
    for (const view of views.values()) view.release()
    views.clear()
    port?.removeEventListener('message', receive); port?.removeEventListener('messageerror', messageError)
    closing = Promise.allSettled([...streams.keys()].map(cancelStream)).then(async () => {
      try { await session.close() }
      finally {
        // A page can reopen the device immediately after close resolves: send
        // the terminal observation only after the owning store released its lock.
        try { send({ ended: errorValue(reason) }) } catch { /* An unavailable page cannot keep the Worker alive. */ }
        port?.close()
      }
    })
    return closing
  }
  const aborted = (): void => { void stop(session.signal.reason).catch(() => undefined) }
  const messageError = (): void => { void stop(new Error('APPLICATION_WORKER_MESSAGE_INVALID')).catch(() => undefined) }
  const controlHost = (): ApplicationControlHost => {
    if (options.host === undefined) throw new Error('APPLICATION_CONTROL_HOST_UNAVAILABLE')
    return options.host
  }
  const view = (id: unknown): ApplicationReadView => {
    const result = typeof id === 'number' ? views.get(id) : undefined
    if (result === undefined) throw new Error('APPLICATION_VIEW_RELEASED')
    return result
  }
  const invoke = async (method: string, args: readonly unknown[], signal: AbortSignal): Promise<unknown> => {
    switch (method) {
      case 'command': return (await session.command(args[0] as string, args[1] as never, args[2] as CommandOptions)).operationId
      case 'reapply': return (await session.reapply(args[0] as string, args[1] as string, args[2] as never, args[3] as CommandOptions)).operationId
      case 'query': return session.query(args[0] as string, args[1] as never)
      case 'operation.get': return session.operations.get(args[0] as string, args[1] as { author?: string })
      case 'operation.inspect': return session.operations.inspect(args[0] as string, args[1] as { author?: string })
      case 'operation.wait': return session.operations.wait(args[0] as string, { signal })
      case 'operation.shared': return session.waitForCoverage(await session.operations.wait(args[0] as string, { signal }), { signal })
      case 'retry': return session.retry(args[0] as string)
      case 'resume': return session.resume()
      case 'inspectRecovery': return session.inspectRecovery()
      case 'recoveryPoint': return session.recoveryPoint()
      case 'adopt': return session.adopt(args[0] as AuthorityBundle)
      case 'recovery.inspect': return session.recovery.inspect()
      case 'recovery.takeover': return session.recovery.takeover(controlHost(), args[0] as { transitionId?: string })
      case 'recovery.handover': return session.recovery.handover(controlHost(), args[0] as { coordinator: string; transitionId?: string })
      case 'signals.send': return session.signals.send(args[0] as string, args[1] as SignalPayload, { ...args[2] as SignalSendOptions, signal })
      case 'view.open': {
        const captured = await session.readView()
        if (signal.aborted) { captured.release(); signal.throwIfAborted() }
        const id = ++nextView; views.set(id, captured)
        return { id, revision: captured.revision }
      }
      case 'view.query': return view(args[0]).query(args[1] as string, args[2] as readonly QueryParameter[])
      case 'view.events': return view(args[0]).readEvents(args[1] as ApplicationEventOptions)
      case 'view.release': { const captured = views.get(args[0] as number); views.delete(args[0] as number); captured?.release(); return null }
      case 'content.stage': return (await session.content.stage(args[0] as { bytes: number; mediaType?: string })).id
      case 'content.resume': return (await session.content.resume(args[0] as string)).id
      case 'content.write': return (await session.content.resume(args[0] as string)).write(args[1] as number, args[2] as Uint8Array)
      case 'content.progress': return (await session.content.resume(args[0] as string)).progress()
      case 'content.commit': return (await session.content.resume(args[0] as string)).commit()
      case 'content.retain': return session.content.retain(args[0] as ContentReference, { signal })
      case 'content.retained': return session.content.retained(args[0] as ContentReference)
      case 'content.retention': return session.content.retention(args[0] as ContentReference)
      case 'close': await stop(new Error('APPLICATION_SESSION_CLOSED')); return null
      default: throw new Error('APPLICATION_WORKER_METHOD_UNKNOWN')
    }
  }
  const openStream = (name: unknown, args: readonly unknown[], signal: AbortSignal): AsyncIterator<unknown> => {
    switch (name) {
      case 'changes': return session.changes({ signal })[Symbol.asyncIterator]()
      case 'signals': return session.signals.subscribe({ ...args[0] as SignalSubscribeOptions, signal })[Symbol.asyncIterator]()
      case 'status': return observe<SessionStatus>(listener => session.onStatus(listener), signal)
      case 'recovery': return observe<RecoveryNotice>(listener => session.onRecovery(listener), signal)
      case 'content': return session.content.read(args[0] as ContentReference, { ...args[1] as { offset?: number; length?: number }, signal })[Symbol.asyncIterator]()
      default: throw new Error('APPLICATION_WORKER_STREAM_UNKNOWN')
    }
  }
  const handle = async (request: Request): Promise<void> => {
    if (closed) throw new Error('APPLICATION_SESSION_CLOSED')
    if (calls.size >= MAX_REQUESTS) throw new Error('APPLICATION_WORKER_REQUEST_LIMIT')
    const controller = new AbortController(); calls.set(request.id, controller)
    try {
      let result: unknown
      if (request.method === 'stream.open') {
        if (streams.size >= MAX_STREAMS) throw new Error('APPLICATION_WORKER_STREAM_LIMIT')
        const iterator = openStream(request.args[0], request.args.slice(1), controller.signal)
        streams.set(request.id, { iterator, controller, busy: false }); result = request.id
      } else if (request.method === 'stream.next') {
        const stream = streams.get(request.args[0] as number)
        if (stream === undefined) throw new Error('APPLICATION_WORKER_STREAM_CLOSED')
        if (stream.busy) throw new Error('APPLICATION_WORKER_STREAM_BUSY')
        stream.busy = true
        try { result = await stream.iterator.next() }
        finally { stream.busy = false }
        if ((result as IteratorResult<unknown>).done) await cancelStream(request.args[0] as number)
      } else result = await invoke(request.method, request.args, controller.signal)
      if (!closed && !controller.signal.aborted) respond(request.id, result)
    } finally { calls.delete(request.id) }
  }
  const receive = (event: MessageEvent): void => {
    const input = event.data as Partial<Request> & { cancel?: unknown }
    try {
      bounded(input)
      if (input?.cancel !== undefined) {
        if (!Number.isSafeInteger(input.cancel)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
        calls.get(input.cancel as number)?.abort(new Error('APPLICATION_WORKER_CANCELLED'))
        void cancelStream(input.cancel as number)
        return
      }
      if (!input || !Number.isSafeInteger(input.id) || input.id! <= lastId || typeof input.method !== 'string' || !Array.isArray(input.args)) {
        throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      }
      lastId = input.id!
      void handle(input as Request).catch((error: unknown) => {
        if (!closed) {
          try { send({ id: input.id!, error: errorValue(error), snapshot: snapshot(session) } satisfies Response) }
          catch { void stop(error).catch(() => undefined) }
        }
      })
    } catch (error) { void stop(error).catch(() => undefined) }
  }
  const connect = (event: MessageEvent): void => {
    const input = event.data as { protocol?: unknown; port?: MessagePort } | null
    if (input?.protocol !== PROTOCOL || !input.port || typeof input.port.postMessage !== 'function') return
    if (closed || port !== undefined) {
      input.port.postMessage({ ended: errorValue(new Error(closed ? 'APPLICATION_SESSION_CLOSED' : 'APPLICATION_WORKER_CLIENT_IN_USE')) })
      input.port.close(); return
    }
    port = input.port
    port.addEventListener('message', receive); port.addEventListener('messageerror', messageError); port.start()
    try { send({ ready: { ...snapshot(session), applicationId: session.applicationId, historyId: session.historyId,
      deviceId: session.deviceId, storageId: session.storageId, description: session.describe() } satisfies Metadata }) }
    catch (error) { void stop(error).catch(() => undefined) }
  }
  endpoint.addEventListener('message', connect); endpoint.start?.()
  session.signal.addEventListener('abort', aborted, { once: true })
  if (session.signal.aborted) aborted()
  return { close: () => stop(new Error('APPLICATION_SESSION_CLOSED')) }
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
  readonly capabilities: Description['capabilities']
  readonly operations = {
    get: (id: string, options: { readonly author?: string } = {}): Promise<OperationState | null> => this.#call('operation.get', [id, options]),
    inspect: (id: string, options: { readonly author?: string } = {}): Promise<{ readonly state: OperationState; readonly attempt: SignedAttempt } | null> => this.#call('operation.inspect', [id, options]),
    wait: (id: string, options: { readonly signal?: AbortSignal } = {}): Promise<AppliedResult> => this.#call('operation.wait', [id], options.signal),
  }
  readonly recovery = {
    inspect: (): Promise<readonly ApplicationTransition[]> => this.#call('recovery.inspect', []),
    takeover: (options: { readonly transitionId?: string } = {}): Promise<RecoveryNotice | null> => this.#call('recovery.takeover', [options]),
    handover: (options: { readonly coordinator: string; readonly transitionId?: string }): Promise<RecoveryNotice | null> => this.#call('recovery.handover', [options]),
  }
  readonly signals: Signals = {
    send: (topic, payload, options = {}) => this.#call('signals.send', [topic, payload, options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }], options.signal),
    subscribe: (options = {}) => this.#stream<EphemeralSignal>('signals', [{ ...(options.topics === undefined ? {} : { topics: options.topics }),
      ...(options.mode === undefined ? {} : { mode: options.mode }) }], options.signal),
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
  #snapshot: Snapshot
  #nextId = 0
  #closing: Promise<void> | undefined
  #stopExternal: (() => void) | undefined

  /** Construct through connectApplicationWorker so readiness is authenticated to the owned port. */
  constructor(port: MessagePort, metadata: Metadata, timeoutMs: number, signal?: AbortSignal) {
    this.#port = port; this.#timeoutMs = timeoutMs; this.#snapshot = metadata; this.#description = metadata.description
    this.applicationId = metadata.applicationId; this.historyId = metadata.historyId; this.deviceId = metadata.deviceId; this.storageId = metadata.storageId
    this.capabilities = metadata.description.capabilities
    port.addEventListener('message', this.#receive); port.addEventListener('messageerror', this.#messageError); port.start()
    if (signal !== undefined) {
      const abort = (): void => { void this.close().catch(() => undefined) }
      signal.addEventListener('abort', abort, { once: true }); this.#stopExternal = () => signal.removeEventListener('abort', abort)
      if (signal.aborted) abort()
    }
    // Every response carries the current coherent snapshot; an older coalesced
    // callback value must not replace that newer observed status.
    void this.#observe('status', () => {}).catch(error => this.#fail(error))
    void this.#observe('recovery', notice => {
      for (const listener of this.#recoveryListeners) { try { listener(notice as RecoveryNotice) } catch { /* Observers cannot change application progress. */ } }
    }).catch(error => this.#fail(error))
  }
  get signal(): AbortSignal { return this.#lifetime.signal }
  get status(): SessionStatus { return { ...this.#snapshot.status } }
  get revision(): PeerRevision {
    if (this.#snapshot.revision === null) throw new Error('PEER_RECOVERING')
    return structuredClone(this.#snapshot.revision)
  }
  describe(): Description { return structuredClone(this.#description) }
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
    if (this.#pending.size >= MAX_REQUESTS) return Promise.reject(new Error('APPLICATION_WORKER_REQUEST_LIMIT'))
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
      this.#pending.set(id, { resolve: value => { clean(); resolve(value as T) }, reject: error => { clean(); reject(error) } })
      signal?.addEventListener('abort', abort, { once: true })
      if (!passive) timer = setTimeout(abort, this.#timeoutMs)
      try { this.#port.postMessage(request) } catch (error) { this.#pending.delete(id); clean(); reject(error) }
    })
  }
  #stream<T>(name: string, args: readonly unknown[], signal?: AbortSignal): AsyncIterable<T> {
    const client = this
    return { [Symbol.asyncIterator]() {
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
            opened ??= client.#call<number>('stream.open', [name, ...args], lifetime)
            id = await opened
            const result = await client.#call<IteratorResult<T>>('stream.next', [id], lifetime, true)
            if (result.done) finish()
            return result
          } catch (error) { finish(); throw error }
          finally { pulling = false }
        },
        async return(): Promise<IteratorResult<T>> { finish(); lifetime.removeEventListener('abort', finish); return { done: true, value: undefined } },
      }
    } }
  }
  #operation(id: string): WorkerApplicationOperation {
    return Object.freeze({ operationId: id, get: () => this.operations.get(id),
      applied: (options: { readonly signal?: AbortSignal } = {}) => this.operations.wait(id, options),
      retry: () => this.retry(id), shared: (options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> => this.#call('operation.shared', [id], options.signal) })
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
      if (response.ended !== undefined) { this.#fail(fromError(response.ended)); return }
      if (!Number.isSafeInteger(response.id)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      const pending = this.#pending.get(response.id)
      if (pending === undefined) return // A cancelled waiter can have an already posted result.
      this.#pending.delete(response.id); this.#update(response.snapshot)
      if (response.error === undefined) pending.resolve(response.value)
      else pending.reject(fromError(response.error))
    } catch (error) { this.#fail(error) }
  }
  readonly #messageError = (): void => { this.#fail(new Error('APPLICATION_WORKER_MESSAGE_INVALID')) }
  #update(value: Snapshot): void {
    const changed = JSON.stringify(value.status) !== JSON.stringify(this.#snapshot.status)
    this.#snapshot = value
    if (changed) for (const listener of this.#statusListeners) { try { listener(this.status) } catch { /* Observation cannot change state. */ } }
  }
  #fail(reason: unknown): void {
    if (this.signal.aborted) return
    this.#lifetime.abort(reason); this.#stopExternal?.()
    this.#snapshot = { ...this.#snapshot, status: { ...this.#snapshot.status, phase: 'closed' } }
    for (const listener of this.#statusListeners) { try { listener(this.status) } catch { /* Observe closure independently. */ } }
    this.#statusListeners.clear(); this.#recoveryListeners.clear()
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
        if (metadata === undefined || !/^[0-9a-f]{64}$/u.test(metadata.applicationId) || !/^[0-9a-f]{64}$/u.test(metadata.deviceId) ||
            typeof metadata.storageId !== 'string' || typeof metadata.historyId !== 'string' || metadata.description.profile !== 'peer-generation-v1') {
          throw new Error('APPLICATION_WORKER_METADATA_INVALID')
        }
        clean(); resolve(new WorkerApplicationSession<D>(port, metadata, timeoutMs, options.signal))
      } catch (error) { fail(error) }
    }
    const timer = setTimeout(() => fail(new Error('APPLICATION_WORKER_READY_TIMEOUT')), timeoutMs)
    options.signal?.addEventListener('abort', abort, { once: true }); port.addEventListener('message', ready); port.start()
    try { endpoint.postMessage({ protocol: PROTOCOL, port: channel.port2 }, [channel.port2]) }
    catch (error) { fail(error) }
  })
}

function snapshot(session: ApplicationSession): Snapshot {
  let revision: PeerRevision | null = null
  try { revision = session.revision } catch (error) { if (!(error instanceof Error) || error.message !== 'PEER_RECOVERING') throw error }
  return { status: session.status, revision }
}
function errorValue(error: unknown): WireError {
  if (!(error instanceof Error)) return { name: 'Error', message: String(error) }
  return { name: error.name, message: error.message,
    ...('code' in error && typeof error.code === 'string' ? { code: error.code } : {}),
    ...(error instanceof AbandonedOperationError ? { operation: error.operation } : {}),
    ...(error instanceof RecoveredViewError ? { revision: error.revision } : {}) }
}
function fromError(error: WireError): Error {
  if (error.name === 'AbandonedOperationError' && error.operation && (error.operation.status === 'abandoned' || error.operation.status === 'needsReapply')) return new AbandonedOperationError(error.operation)
  if (error.name === 'RecoveredViewError' && error.revision) return new RecoveredViewError(error.revision)
  return Object.assign(new Error(error.message), { name: error.name, ...(error.code === undefined ? {} : { code: error.code }) })
}
/** One coalesced callback value, independent of how long a page stops pulling. */
function observe<T>(subscribe: (listener: (value: T) => void) => () => void, signal: AbortSignal): AsyncIterator<T> {
  let pending: T | undefined, hasValue = false, closed = false, wake: (() => void) | undefined
  const unsubscribe = subscribe(value => { pending = value; hasValue = true; wake?.(); wake = undefined })
  const close = (): void => { if (closed) return; closed = true; unsubscribe(); signal.removeEventListener('abort', close); wake?.(); wake = undefined }
  signal.addEventListener('abort', close, { once: true }); if (signal.aborted) close()
  return {
    async next() {
      while (!hasValue && !closed) await new Promise<void>(resolve => { wake = resolve })
      signal.throwIfAborted()
      if (closed) return { done: true, value: undefined }
      const value = pending!; pending = undefined; hasValue = false
      return { done: false, value }
    },
    async return() { close(); return { done: true, value: undefined } },
  }
}
/** Structured-clone payload budget, including binary values and SQL integers. */
function bounded(value: unknown): void {
  const seen = new Set<object>(); let bytes = 0, nodes = 0
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 65_536 || depth > 32 || bytes > MAX_BYTES) throw new Error('APPLICATION_WORKER_MESSAGE_LIMIT')
    if (typeof item === 'string') bytes += new TextEncoder().encode(item).length
    else if (typeof item === 'bigint') bytes += item.toString().length
    else if (item === null || item === undefined || typeof item === 'number' || typeof item === 'boolean') bytes += 8
    else if (item instanceof Uint8Array) bytes += item.byteLength
    else if (typeof item === 'object') {
      if (seen.has(item)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      seen.add(item)
      for (const [key, child] of Object.entries(item)) { bytes += new TextEncoder().encode(key).length; visit(child, depth + 1) }
      seen.delete(item)
    } else throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    if (bytes > MAX_BYTES) throw new Error('APPLICATION_WORKER_MESSAGE_LIMIT')
  }
  visit(value, 0)
}

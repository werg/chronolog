import type { BytesStore } from '@chronolog/records'
import { createPeerReplica, type PeerReplica, type PeerRevision, type AppliedResult, type OperationState, type AuthorityBundle,
  type RecoveryNotice, type SignedAttempt, type SignedRetainedCoverage, type PrefixProof, type CapturedPeerView,
  type HistoryCompactionOptions, type HistoryCompactionResult } from '@chronolog/peer-generation'
import type { PeerIdentity } from '@chronolog/peer-generation/control'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime, type MaterializedLocalSqlValue } from '@chronolog/materializer'
import { bytesToHex, decodeTransactionCore, isEmitStep, type ChangeProgram, type EventPayload } from '@chronolog/protocol'
import type { ApplicationCommand, ApplicationDefinition, ApplicationQuery } from './definition.js'
import type { ApplicationDevice, ApplicationStorage } from './device.js'
import type { ApplicationSession } from './session.js'
import type { OpenPeerApplicationOptions } from './runtime.js'
import type { ApplicationDataPort } from './participant-types.js'
import { APPLICATION_EVENT_CURSOR_LIMIT, type ApplicationChange, type ApplicationEvent, type ApplicationEventBatch,
  type ApplicationEventOptions, type ApplicationReadView, type CommandOptions, type QueryParameter } from './session-types.js'
import { AbandonedOperationError, RecoveredViewError } from './errors.js'
import { ApplicationOperation, type ApplicationSubmission } from './operation.js'
import { ApplicationRecovery } from './recovery.js'
import { ApplicationContent } from './content.js'
import { ApplicationKeyring } from './keys.js'
import { ApplicationProjection, APPLICATION_PROJECTION_LIMITS, type ApplicationProjectionDefinition, type ApplicationProjectionHandle } from './projection.js'

type CommandArguments<T> = T extends ApplicationCommand<infer I> ? I : never
type QueryArguments<T> = T extends ApplicationQuery<infer I, unknown, never> ? I : never
type QueryResult<T> = T extends ApplicationQuery<never, infer R, never> ? Awaited<R> : never

/** The one durable journal, materializer and local-view implementation. */
export class ApplicationData<D extends ApplicationDefinition = ApplicationDefinition> implements ApplicationDataPort {
  readonly #replica: PeerReplica
  readonly #store: BytesStore
  readonly #storage: ApplicationStorage
  readonly #definition: D
  readonly #session: ApplicationSession<D>
  readonly #submit: (attempt: SignedAttempt) => Promise<void>
  readonly #lifetime = new AbortController()
  readonly signal: AbortSignal
  readonly content: ApplicationContent
  readonly keys: ApplicationKeyring
  readonly recovery: ApplicationRecovery
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
    inspect(operationId: string, options?: { readonly author?: string }): Promise<{ readonly state: OperationState; readonly attempt: SignedAttempt } | null>
    wait(operationId: string, options?: { readonly author?: string; readonly signal?: AbortSignal }): Promise<AppliedResult>
  }
  readonly #inflight = new Map<string, Promise<void>>()
  readonly #links = new Set<{ close(): Promise<void> }>()
  readonly #projections = new Map<string, ApplicationProjectionHandle>()
  readonly #views = new Set<ApplicationReadView>()
  #openingViews = 0
  #closed = false
  #closeTask: Promise<void> | undefined

  constructor(options: { readonly replica: PeerReplica; readonly definition: D; readonly storage: ApplicationStorage;
    readonly content: ApplicationContent; readonly keys: ApplicationKeyring; readonly session: ApplicationSession<D>;
    readonly submit: (attempt: SignedAttempt) => Promise<void>; readonly adoptAuthority: (authority: AuthorityBundle) => Promise<void> }) {
    this.#replica = options.replica; this.#storage = options.storage; this.#store = options.storage.store; this.#definition = options.definition
    this.#session = options.session; this.#submit = options.submit; this.content = options.content; this.keys = options.keys
    this.signal = AbortSignal.any([options.session.signal, this.#lifetime.signal])
    this.recovery = new ApplicationRecovery({ replica: options.replica, store: this.#store, signal: this.signal, adoptAuthority: options.adoptAuthority })
    const replica = this.#replica
    this.operations = Object.freeze({ get: (operationId: string, options: { readonly author?: string } = {}) => replica.operation(operationId, options.author),
      inspect: async (operationId: string, options: { readonly author?: string } = {}) => {
        const state = await replica.operation(operationId, options.author), attempt = await replica.attempt(operationId, options.author)
        return state === null || attempt === null ? null : { state, attempt }
      },
      wait: (operationId: string, waitOptions: { readonly author?: string; readonly signal?: AbortSignal } = {}) => this.waitFor(operationId, waitOptions) })
  }
  get replica(): PeerReplica { return this.#replica }
  get applicationId(): string { return this.#replica.descriptor.applicationId }
  get historyId(): string { return this.#replica.descriptor.historyId }

  async command<Name extends keyof D['commands'] & string>(name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions): Promise<ApplicationOperation> {
    this.#assertOpen()
    const command = this.#definition.commands[name]
    if (command === undefined) throw new Error('APPLICATION_COMMAND_UNKNOWN')
    await this.#replica.prepare({ operationId: options.operationId, program: command.prepare(input as never),
      command: name, commandVersion: this.#definition.version, ...(options.basedOn === undefined ? {} : { basedOn: options.basedOn }) })
    // Preparation is the only local journal write. Disconnection never creates another queue.
    void this.retry(options.operationId).catch(() => undefined)
    return new ApplicationOperation(this.#session, options.operationId)
  }

  async submitProgramAs(program: ChangeProgram, author: PeerIdentity, options: CommandOptions): Promise<ApplicationSubmission> {
    this.#assertOpen()
    const { id: attemptId, payload: { header } } = await this.#replica.prepareAs({ operationId: options.operationId, program,
      ...(options.basedOn === undefined ? {} : { basedOn: options.basedOn }) }, author)
    void this.retry(header.operationId, header.author).catch(() => undefined)
    return Object.assign(new ApplicationOperation(this.#session, header.operationId, header.author), { attemptId })
  }

  async reapply<Name extends keyof D['commands'] & string>(operationId: string, name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions & { readonly originalAuthor?: string }): Promise<ApplicationOperation> {
    this.#assertOpen()
    const original = await this.#replica.operation(operationId, options.originalAuthor)
    if (original === null || original.status !== 'abandoned' && original.status !== 'needsReapply') throw new Error('APPLICATION_REAPPLY_REQUIRES_ABANDONED_ATTEMPT')
    if (options.operationId === operationId) throw new Error('APPLICATION_REAPPLY_REQUIRES_NEW_ID')
    const command = this.#definition.commands[name]
    if (command === undefined) throw new Error('APPLICATION_COMMAND_UNKNOWN')
    await this.#replica.prepare({ operationId: options.operationId, program: command.prepare(input as never),
      command: name, commandVersion: this.#definition.version, reapplyOf: original.attemptId,
      ...(options.basedOn === undefined ? {} : { basedOn: options.basedOn }) })
    void this.retry(options.operationId).catch(() => undefined)
    return new ApplicationOperation(this.#session, options.operationId)
  }

  async query<Name extends keyof D['queries'] & string>(name: Name, input: QueryArguments<D['queries'][Name]>): Promise<{ readonly revision: PeerRevision; readonly value: QueryResult<D['queries'][Name]> }> {
    const query = this.#definition.queries[name]
    if (query === undefined) throw new Error('APPLICATION_QUERY_UNKNOWN')
    const view = await this.readView()
    try { return { revision: view.revision, value: await query.read(view as never, input as never) as QueryResult<D['queries'][Name]> } }
    finally { view.release() }
  }

  async readView(): Promise<ApplicationReadView> {
    this.#assertOpen()
    if (this.#views.size + this.#openingViews >= 8) throw new Error('APPLICATION_VIEW_LIMIT')
    this.#openingViews++
    let captured: CapturedPeerView
    try { captured = await this.#replica.capture() } finally { this.#openingViews-- }
    if (this.#closed || this.#views.size >= 8) { captured.release(); throw new Error(this.#closed ? 'APPLICATION_SESSION_CLOSED' : 'APPLICATION_VIEW_LIMIT') }
    let released = false
    const views = this.#views
    const held = (): void => { if (released) throw new Error('APPLICATION_VIEW_RELEASED') }
    const view: ApplicationReadView = Object.freeze({ revision: captured.revision,
      query(sql: string, parameters: readonly QueryParameter[] = []) {
        held()
        const result = captured.read.query(sql, parameters.map(encodeParameter))
        return { columns: result.columns, rows: result.rows.map(row => row.map(decodeParameter)) }
      },
      readEvents(options: ApplicationEventOptions = {}) { held(); return readEvents(captured, options) },
      release() { if (released) return; released = true; views.delete(view); captured.release() },
    })
    views.add(view)
    return view
  }

  onRecovery(listener: (notice: RecoveryNotice) => void): () => void { this.#assertOpen(); return this.#replica.onRecovery(listener) }
  inspectRecovery(): readonly RecoveryNotice[] { return this.#replica.inspectRecovery() }
  recoveryPoint(): Promise<PrefixProof> { this.#assertOpen(); return this.#replica.recoveryPoint() }
  async adopt(authority: AuthorityBundle): Promise<RecoveryNotice | null> {
    this.#assertOpen()
    const notice = await this.#replica.adopt(authority)
    void this.resume().catch(() => undefined)
    return notice
  }

  /** Compact older history records and abandoned generations, optionally retaining a summary command first. */
  async compact(options: HistoryCompactionOptions & {
    readonly summarize?: (events: readonly ApplicationEvent[]) => ChangeProgram | null | Promise<ChangeProgram | null>
    readonly operationId?: string
    readonly signal?: AbortSignal
  } = {}): Promise<HistoryCompactionResult> {
    this.#assertOpen()
    const keepTail = options.keepTail ?? 0
    let extraTail = 0
    if (options.summarize !== undefined) {
      if (typeof options.operationId !== 'string' || options.operationId.length === 0) throw new Error('APPLICATION_COMPACT_OPERATION_ID_REQUIRED')
      const view = await this.readView()
      const allEvents: ApplicationEvent[] = []
      try {
        let cursor: string | undefined
        for (;;) {
          const batch = view.readEvents({ limit: 1024, ...(cursor === undefined ? {} : { cursor }) })
          allEvents.push(...batch.events)
          if (!batch.hasMore) break
          cursor = batch.cursor
        }
      } finally { view.release() }
      const summaryProgram = await options.summarize(allEvents)
      if (summaryProgram !== null) {
        const submission = await this.submitProgramAs(summaryProgram, this.#replica.device, { operationId: options.operationId })
        const applied = await submission.applied({ ...(options.signal === undefined ? {} : { signal: options.signal }) })
        if (applied.outcome !== 'accepted') throw new Error(`APPLICATION_COMPACT_SUMMARY_REJECTED:${applied.rejectionCode ?? 'unknown'}`)
        extraTail = 1
      }
    }
    return this.#replica.compact({
      keepTail: keepTail + extraTail,
      ...(options.pruneAbandoned === undefined ? {} : { pruneAbandoned: options.pruneAbandoned }),
    })
  }

  changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    return coalescedChanges(this.#replica, this.signal, options.signal)
  }

  /** Register a pure reducer in the owning Worker or native session. */
  project<State extends EventPayload>(definition: ApplicationProjectionDefinition<State>): ApplicationProjection<State> {
    this.#assertOpen()
    if (this.#projections.has(definition.id)) throw new Error('APPLICATION_PROJECTION_IN_USE')
    if (this.#projections.size >= APPLICATION_PROJECTION_LIMITS.active) throw new Error('APPLICATION_PROJECTION_LIMIT')
    const projection = new ApplicationProjection({ source: this, store: this.#store, definition,
      release: () => { this.#projections.delete(projection.id); this.#links.delete(projection) } })
    this.#projections.set(projection.id, projection); this.#links.add(projection)
    return projection
  }

  /** Read a registered projection without moving reducer callbacks across a transport. */
  projection<State extends EventPayload = EventPayload>(id: string): ApplicationProjectionHandle<State> {
    this.#assertOpen()
    const projection = this.#projections.get(id)
    if (projection === undefined) throw new Error('APPLICATION_PROJECTION_NOT_FOUND')
    return projection as ApplicationProjectionHandle<State>
  }

  async retry(operationId: string, author = this.#replica.device.publicKey): Promise<void> {
    this.#assertOpen()
    const key = JSON.stringify([author, operationId])
    const existing = this.#inflight.get(key)
    if (existing !== undefined) return existing
    const task = (async () => {
      const state = await this.#replica.operation(operationId, author)
      if (state === null) throw new Error('APPLICATION_OPERATION_NOT_FOUND')
      if (state.status === 'applied') return
      if (state.status === 'abandoned' || state.status === 'needsReapply') throw new AbandonedOperationError(state)
      const attempt = await this.#replica.attempt(operationId, author)
      if (attempt === null) throw new Error('APPLICATION_ATTEMPT_MISSING')
      if (this.#replica.isCoordinator) await this.#replica.order(attempt)
      else await this.#submit(attempt)
    })()
    this.#inflight.set(key, task)
    try { await task } finally { this.#inflight.delete(key) }
  }

  async resume(): Promise<void> {
    this.#assertOpen()
    if (!this.#replica.ready) return
    for (const { payload: { header } } of await this.#replica.pendingAttempts()) await this.retry(header.operationId, header.author)
  }

  async waitFor(operationId: string, options: { readonly author?: string; readonly signal?: AbortSignal } = {}): Promise<AppliedResult> {
    return waitFor(this.#replica, this.signal, options.signal, async () => {
      if (!this.#replica.ready) return undefined
      const current = await this.#replica.operation(operationId, options.author)
      if (current?.status === 'applied') return current
      if (current?.status === 'abandoned' || current?.status === 'needsReapply') throw new AbandonedOperationError(current)
      if (current === null) throw new Error('APPLICATION_OPERATION_NOT_FOUND')
      return undefined
    })
  }

  async waitForCoverage(applied: AppliedResult, options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> {
    return waitFor(this.#replica, this.signal, options.signal, async () => {
      if (!this.#replica.ready) return undefined
      const current = await this.#replica.operation(applied.operationId, applied.author)
      if (current?.status === 'abandoned' || current?.status === 'needsReapply') throw new AbandonedOperationError(current)
      const root = this.#replica.receiptRoot(applied.attemptId)
      if (root === null) return undefined
      const coverage = this.#replica.shared({ generation: applied.generation, sequence: applied.sequence, root })
      return coverage.length === 0 ? undefined : coverage
    })
  }

  close(reason: Error = new Error('APPLICATION_SESSION_CLOSED')): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    this.#closed = true; this.#lifetime.abort(reason)
    for (const view of [...this.#views]) view.release()
    this.content.close()
    this.#closeTask = (async () => {
      await Promise.allSettled([...this.#links].map(link => Promise.resolve().then(() => link.close())))
      await Promise.allSettled([this.recovery.close(), this.keys.close(), ...this.#inflight.values()])
      try { await this.#replica.close() } finally { await this.#storage.close() }
    })()
    return this.#closeTask
  }
  #assertOpen(): void { this.signal.throwIfAborted(); if (this.#closed) throw new Error('APPLICATION_SESSION_CLOSED') }
}

/** Called exactly once, on the participant's first durable operation. */
export async function openApplicationData<const D extends ApplicationDefinition>(options: OpenPeerApplicationOptions<D> & {
  readonly session: ApplicationSession<D>; readonly authority: AuthorityBundle; readonly submit: (attempt: SignedAttempt) => Promise<void>;
  readonly adoptAuthority: (authority: AuthorityBundle) => Promise<void>
}): Promise<ApplicationData<D>> {
  const signal = options.session.signal
  let storage: ApplicationStorage | undefined, materializer: ChronologMaterializationRuntime | undefined, replica: PeerReplica | undefined, keys: ApplicationKeyring | undefined
  try {
    signal.throwIfAborted()
    storage = await options.device.openStorage(); signal.throwIfAborted()
    const store = storage.store
    const device: ApplicationDevice = { ...options.device, store }
    keys = await ApplicationKeyring.open({ device, authority: options.authority,
      ...(options.epochKeys === undefined ? {} : { epochKeys: options.epochKeys }) }); signal.throwIfAborted()
    materializer = options.createMaterializer === undefined ? await createEventMaterializationRuntime({ store,
      namespace: options.authority.descriptor.payload.historyId,
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }) : await options.createMaterializer({ signal })
    signal.throwIfAborted()
    const requiresSql = options.definition.schema !== undefined || options.authority.descriptor.payload.schemaDigest !== null
    if (materializer.queries.capabilities.sql !== requiresSql) {
      throw new Error(requiresSql ? 'APPLICATION_SCHEMA_REQUIRES_SQL' : 'APPLICATION_SQL_REQUIRES_SCHEMA')
    }
    replica = await createPeerReplica({ authority: options.authority, device: device.identity, store,
      storageId: device.storageId, epochKeys: keys.epochKeys, materializer,
      ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) })
    signal.throwIfAborted(); keys.bind(replica); await keys.validate(); signal.throwIfAborted()
    const keyring = keys
    const content = new ApplicationContent({ replica, store, storageId: device.storageId,
      epochKeys: keyring.epochKeys, acquireKey: epoch => keyring.ensure([epoch]) })
    return new ApplicationData({ replica, storage, definition: options.definition, content, keys, session: options.session, submit: options.submit, adoptAuthority: options.adoptAuthority })
  } catch (error) {
    await Promise.allSettled([Promise.resolve().then(() => keys?.close()),
      Promise.resolve().then(() => replica === undefined ? materializer?.close() : replica.close())])
    try { await storage?.close() } catch { /* Preserve the initialization failure after attempting every owned release. */ }
    throw error
  }
}

function encodeParameter(value: QueryParameter): MaterializedLocalSqlValue {
  if (value === null) return { kind: 'null' }
  if (typeof value === 'string') return { kind: 'text', value }
  if (typeof value === 'bigint') return { kind: 'integer', value: String(value) }
  if (value instanceof Uint8Array) return { kind: 'blob', value: value.slice() }
  if (typeof value === 'number' && Number.isFinite(value)) return Number.isSafeInteger(value) ? { kind: 'integer', value: String(value) } : { kind: 'real', value }
  throw new Error('APPLICATION_SQL_PARAMETER_INVALID')
}
function decodeParameter(value: MaterializedLocalSqlValue): QueryParameter {
  switch (value.kind) {
    case 'null': return null
    case 'integer': { const exact = BigInt(value.value); return exact >= BigInt(Number.MIN_SAFE_INTEGER) && exact <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(exact) : exact }
    case 'real': case 'text': return value.value
    case 'blob': return value.value.slice()
  }
}
function readEvents(captured: CapturedPeerView, options: ApplicationEventOptions): ApplicationEventBatch {
  const limit = options.limit ?? 128, topics = options.topics === undefined ? null : [...new Set(options.topics)].sort()
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024 || topics !== null && (topics.length > 128 || topics.some(topic => typeof topic !== 'string' || topic.length > 128))) throw new Error('APPLICATION_EVENT_OPTIONS_INVALID')
  let index = 0
  if (options.cursor !== undefined) {
    try {
      if (options.cursor.length > APPLICATION_EVENT_CURSOR_LIMIT) throw new Error()
      const cursor = JSON.parse(options.cursor) as { historyId: string; generation: string; index: number; anchor: string | null; topics: readonly string[] | null }
      if (cursor.historyId !== captured.revision.historyId || cursor.generation !== captured.revision.generation) throw new RecoveredViewError(captured.revision)
      if (!Number.isSafeInteger(cursor.index) || cursor.index < 0 || cursor.index > captured.read.orderLength || JSON.stringify(cursor.topics) !== JSON.stringify(topics) ||
          cursor.anchor !== (cursor.index === 0 ? null : bytesToHex(captured.read.transactionAt(cursor.index - 1)!.txId))) throw new Error()
      index = cursor.index
    } catch (error) { if (error instanceof RecoveredViewError) throw error; throw new Error('APPLICATION_EVENT_CURSOR_INVALID', { cause: error }) }
  }
  const events: ApplicationEvent[] = []
  const end = Math.min(captured.read.orderLength, index + limit)
  while (index < end) {
    const transaction = captured.read.transactionAt(index++)!
    if (transaction.outcome !== 'accepted') continue
    const core = decodeTransactionCore(transaction.canonicalCandidate)
    let ordinal = 0
    for (const step of core.program.steps) {
      if (!isEmitStep(step)) continue
      const eventOrdinal = ordinal++
      if (topics !== null && !topics.includes(step.topic)) continue
      events.push({ id: `${bytesToHex(transaction.txId)}:${eventOrdinal}`, attemptId: bytesToHex(transaction.txId),
        operationId: core.operationId, author: bytesToHex(core.authorId), authorTimestampMs: String(core.authorTimestampMs), topic: step.topic, payload: structuredClone(step.payload) })
    }
  }
  return { revision: captured.revision, events, hasMore: index < captured.read.orderLength,
    cursor: JSON.stringify({ historyId: captured.revision.historyId, generation: captured.revision.generation, index,
      anchor: index === 0 ? null : bytesToHex(captured.read.transactionAt(index - 1)!.txId), topics }) }
}

function waitFor<T>(replica: PeerReplica, lifetime: AbortSignal, signal: AbortSignal | undefined, check: () => Promise<T | undefined>): Promise<T> {
  const abort = signal === undefined ? lifetime : AbortSignal.any([lifetime, signal])
  abort.throwIfAborted()
  return new Promise((resolve, reject) => {
    let done = false, running = false, again = false, unsubscribe = () => {}
    const finish = (value: T | undefined, error?: unknown): void => {
      if (done) return
      done = true; unsubscribe(); abort.removeEventListener('abort', stop)
      if (error !== undefined) reject(error); else resolve(value!)
    }
    const stop = (): void => finish(undefined, abort.reason)
    const inspect = (): void => {
      if (done) return
      if (running) { again = true; return }
      running = true
      void (async () => {
        try {
          do { again = false; const value = await check(); if (value !== undefined) { finish(value); return } } while (again && !done)
        } catch (error) { finish(undefined, error) }
        finally { running = false }
      })()
    }
    abort.addEventListener('abort', stop, { once: true }); unsubscribe = replica.subscribe(inspect); inspect()
    if (done) unsubscribe()
  })
}
function coalescedChanges(replica: PeerReplica, lifetime: AbortSignal, signal?: AbortSignal): AsyncIterable<ApplicationChange> {
  return { [Symbol.asyncIterator]() {
    const abort = signal === undefined ? lifetime : AbortSignal.any([lifetime, signal])
    let closed = false, pending: ApplicationChange | undefined, waiting: ((value: IteratorResult<ApplicationChange>) => void) | undefined
    let latestRecovery: RecoveryNotice | null = null
    let lastRevision: string | undefined
    const close = (): IteratorResult<ApplicationChange> => {
      if (!closed) { closed = true; unsubscribe(); recovery(); abort.removeEventListener('abort', close); waiting?.({ done: true, value: undefined }); waiting = undefined; pending = undefined }
      return { done: true, value: undefined }
    }
    const publish = (): void => {
      if (closed || !replica.ready) return
      const revision = replica.revision
      const identity = `${revision.generation}/${revision.point.root}/${revision.materializationRevision}`
      if (latestRecovery === null && identity === lastRevision) return
      lastRevision = identity
      const value: ApplicationChange = { kind: latestRecovery === null ? 'applied' : 'recovery', revision, recovery: latestRecovery }
      latestRecovery = null
      if (waiting !== undefined) { const resolve = waiting; waiting = undefined; resolve({ done: false, value }) }
      else pending = value.kind === 'applied' && pending?.kind === 'recovery' ? { ...value, kind: 'recovery', recovery: pending.recovery } : value
    }
    const unsubscribe = replica.subscribe(publish), recovery = replica.onRecovery(notice => { latestRecovery = notice; publish() })
    abort.addEventListener('abort', close, { once: true })
    if (abort.aborted) close(); else publish()
    return {
      next(): Promise<IteratorResult<ApplicationChange>> {
        if (closed) return Promise.resolve({ done: true, value: undefined })
        if (pending !== undefined) { const value = pending; pending = undefined; return Promise.resolve({ done: false, value }) }
        if (waiting !== undefined) return Promise.reject(new Error('APPLICATION_CHANGES_CONCURRENT_NEXT'))
        return new Promise(resolve => { waiting = resolve })
      },
      async return() { return close() },
    }
  } }
}

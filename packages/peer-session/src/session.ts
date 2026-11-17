import type { BytesStore } from '@chronolog/records'
import {
  PEER_GENERATION_CAPABILITIES, type PeerReplica, type PeerRevision, type AppliedResult,
  type OperationState, type AuthorityBundle, type RecoveryNotice, type SignedAttempt,
  type SignedRetainedCoverage, type PrefixProof, type CapturedPeerView, } from '@chronolog/peer-generation'
import {
  bytesToHex, hexToBytes, decodeTransactionCore, isEmitStep,
  type EventPayload,
} from '@chronolog/protocol'
import { SignalChannel, type Signals } from '@chronolog/signals'
import type { MaterializedLocalSqlValue } from '@chronolog/materializer'

import { applicationDefinitionDigest, describeApplication, type ApplicationCommand, type ApplicationDefinition, type ApplicationQuery } from './definition.js'
import { ApplicationRecovery } from './recovery.js'
import type { ApplicationContent } from './content.js'
import type { ApplicationKeyring } from './keys.js'
import { ApplicationControlParticipant, type ControlParticipantOptions } from './control-participant.js'
import { OwnedApplicationParticipation } from './participation.js'
import type { ApplicationParticipation, ApplicationParticipationOptions } from './participation-types.js'
import {
  connectApplicationPeer, connectApplicationPeerPair, connectedApplicationPeers,
  type ApplicationPeerConnectOptions, type ApplicationPeerLink, type ApplicationPeerPort,
} from './network.js'

export type QueryParameter = null | string | number | bigint | Uint8Array
export interface QueryRows {
  readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]
  readonly rows: readonly (readonly QueryParameter[])[]
}
export interface ApplicationEvent {
  readonly id: string
  readonly attemptId: string
  readonly operationId: string
  readonly author: string
  readonly authorTimestampMs: string
  readonly topic: string
  readonly payload: EventPayload
}
export interface ApplicationEventBatch {
  readonly revision: PeerRevision
  readonly events: readonly ApplicationEvent[]
  readonly cursor: string
  readonly hasMore: boolean
}
export interface ApplicationEventOptions { readonly cursor?: string; readonly topics?: readonly string[]; readonly limit?: number }
export interface ApplicationReadView {
  readonly revision: PeerRevision
  query(sql: string, parameters?: readonly QueryParameter[]): QueryRows
  readEvents(options?: ApplicationEventOptions): ApplicationEventBatch
  release(): void
}
export interface CommandOptions { readonly operationId: string; readonly basedOn?: PeerRevision }
export interface ApplicationChange { readonly kind: 'applied' | 'recovery'; readonly revision: PeerRevision; readonly recovery: RecoveryNotice | null }
export interface SessionStatus {
  readonly phase: 'ready' | 'waiting' | 'recovering' | 'awaiting-keys' | 'closed'
  readonly role: 'coordinator' | 'follower'
  readonly generation: string
  readonly coordinator: string
  readonly connectedPeers: number
}

export class AbandonedOperationError extends Error {
  constructor(readonly operation: Extract<OperationState, { status: 'abandoned' | 'needsReapply' }>) {
    super('APPLICATION_OPERATION_ABANDONED'); this.name = 'AbandonedOperationError'
  }
}
export class RecoveredViewError extends Error {
  constructor(readonly revision: PeerRevision) { super('APPLICATION_VIEW_RECOVERED'); this.name = 'RecoveredViewError' }
}

/** A saved immutable attempt. Cancelling a waiter never cancels its command. */
export class ApplicationOperation {
  constructor(readonly session: ApplicationSession, readonly operationId: string) {}
  get(): Promise<OperationState | null> { return this.session.operations.get(this.operationId) }
  applied(options: { readonly signal?: AbortSignal } = {}): Promise<AppliedResult> {
    return this.session.waitFor(this.operationId, options)
  }
  retry(): Promise<void> { return this.session.retry(this.operationId) }
  async shared(options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> {
    const applied = await this.applied(options)
    return this.session.waitForCoverage(applied, options)
  }
}

type CommandArguments<T> = T extends ApplicationCommand<infer I> ? I : never
type QueryArguments<T> = T extends ApplicationQuery<infer I, unknown, never> ? I : never
type QueryResult<T> = T extends ApplicationQuery<never, infer R, never> ? Awaited<R> : never
interface PeerEndpoint { submit(attempt: SignedAttempt): Promise<void>; readonly link: { close(): Promise<void> } }
interface SessionInternals { readonly port: ApplicationPeerPort }
const internals = new WeakMap<ApplicationSession, SessionInternals>()

/** The application-facing owner: one peer journal, coherent views and explicit recovery. */
export class ApplicationSession<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly capabilities: typeof PEER_GENERATION_CAPABILITIES & PeerReplica['queryCapabilities']
  readonly signals: Signals
  readonly recovery: ApplicationRecovery
  readonly content: ApplicationContent
  readonly keys: ApplicationKeyring
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
    inspect(operationId: string, options?: { readonly author?: string }): Promise<{ readonly state: OperationState; readonly attempt: SignedAttempt } | null>
    wait(operationId: string, options?: { readonly signal?: AbortSignal }): Promise<AppliedResult>
  }
  readonly #replica: PeerReplica
  readonly #store: BytesStore
  readonly #definition: D
  readonly #peers = new Map<string, PeerEndpoint>()
  readonly #lifetime = new AbortController()
  readonly #closing: (() => void | Promise<void>) | undefined
  readonly #inflight = new Map<string, Promise<void>>()
  readonly #links = new Set<{ close(): Promise<void> }>()
  readonly #views = new Set<ApplicationReadView>()
  readonly #statusListeners = new Set<(status: SessionStatus) => void>()
  readonly #stopStatus: () => void
  readonly #stopKeys: () => void
  #lastStatus = ''
  #closed = false
  #closeTask: Promise<void> | undefined
  #control: ApplicationControlParticipant | undefined
  #participation: OwnedApplicationParticipation | undefined

  constructor(options: { readonly replica: PeerReplica; readonly definition: D; readonly store: BytesStore; readonly content: ApplicationContent; readonly keys: ApplicationKeyring; readonly close?: () => void | Promise<void> }) {
    this.#replica = options.replica; this.#store = options.store; this.#definition = options.definition; this.#closing = options.close
    const replica = this.#replica
    this.capabilities = Object.freeze({ ...PEER_GENERATION_CAPABILITIES, ...replica.queryCapabilities })
    const signals = new SignalChannel({ scope: replica.descriptor.applicationId,
      identity: { publicKeyBytes: hexToBytes(replica.device.publicKey), privateKey: replica.device.privateKey },
      authorize: ({ scope, authorId }) => scope === replica.descriptor.applicationId && currentReader(replica, bytesToHex(authorId)),
    })
    this.signals = signals
    this.recovery = new ApplicationRecovery({ replica, store: options.store, signal: this.#lifetime.signal })
    this.content = options.content
    this.keys = options.keys
    const port: ApplicationPeerPort = { replica, signals, content: options.content, keys: options.keys, signal: this.#lifetime.signal,
      attach: (peerId, submit, link) => this.#attachPeer(peerId, submit, link),
      resume: () => this.resume(),
      observeHead: (peerId, revision, observedAt) => this.#participation?.observeHead(peerId, revision, observedAt),
    }
    internals.set(this, { port })
    this.#stopStatus = replica.subscribe(() => this.#publishStatus())
    this.#stopKeys = options.keys.subscribe(() => this.#publishStatus())
    this.operations = Object.freeze({ get: (operationId: string, options: { readonly author?: string } = {}) => replica.operation(operationId, options.author),
      inspect: async (operationId: string, options: { readonly author?: string } = {}) => {
        const state = await replica.operation(operationId, options.author), attempt = await replica.attempt(operationId, options.author)
        return state === null || attempt === null ? null : { state, attempt }
      },
      wait: (operationId: string, waitOptions: { readonly signal?: AbortSignal } = {}) => this.waitFor(operationId, waitOptions) })
  }

  get signal(): AbortSignal { return this.#lifetime.signal }
  get revision(): PeerRevision { return this.#replica.revision }
  get deviceId(): string { return this.#replica.device.publicKey }
  get applicationId(): string { return this.#replica.descriptor.applicationId }
  get participation(): ApplicationParticipation | undefined { return this.#participation }
  get historyId(): string { return this.#replica.descriptor.historyId }
  get storageId(): string { return this.#replica.storageId }
  get status(): SessionStatus {
    const coordinator = this.#replica.generation.payload.coordinator
    return { phase: this.#closed ? 'closed' : this.keys.missing().length > 0 ? 'awaiting-keys' : !this.#replica.ready ? 'recovering' : this.#replica.isCoordinator || this.#peers.has(coordinator) ? 'ready' : 'waiting',
      role: this.#replica.isCoordinator ? 'coordinator' : 'follower', generation: this.#replica.generation.id,
      coordinator, connectedPeers: this.#peers.size }
  }
  describe() { return { ...describeApplication(this.#definition), capabilities: this.capabilities } }
  onStatus(listener: (status: SessionStatus) => void): () => void {
    this.#statusListeners.add(listener)
    try { listener(this.status) } catch { /* Observation never changes peer lifetime. */ }
    return () => { this.#statusListeners.delete(listener) }
  }
  #publishStatus(): void {
    const status = this.status, key = JSON.stringify(status)
    if (key === this.#lastStatus) return
    this.#lastStatus = key
    for (const listener of this.#statusListeners) { try { listener(status) } catch { /* Observation never changes peer lifetime. */ } }
  }

  async command<Name extends keyof D['commands'] & string>(name: Name, input: CommandArguments<D['commands'][Name]>, options: CommandOptions): Promise<ApplicationOperation> {
    this.#assertOpen()
    const command = this.#definition.commands[name]
    if (command === undefined) throw new Error('APPLICATION_COMMAND_UNKNOWN')
    await this.#replica.prepare({ operationId: options.operationId, program: command.prepare(input as never),
      command: name, commandVersion: this.#definition.version, ...(options.basedOn === undefined ? {} : { basedOn: options.basedOn }) })
    // Preparation is the only local journal write. Disconnection never creates another queue.
    void this.retry(options.operationId).catch(() => undefined)
    return new ApplicationOperation(this, options.operationId)
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
    return new ApplicationOperation(this, options.operationId)
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
    if (this.#views.size >= 8) throw new Error('APPLICATION_VIEW_LIMIT')
    const captured = await this.#replica.capture()
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

  changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationChange> {
    return coalescedChanges(this.#replica, this.#lifetime.signal, options.signal)
  }

  connectPeer(options: ApplicationPeerConnectOptions): Promise<ApplicationPeerLink> {
    this.#assertOpen()
    return connectApplicationPeer(internals.get(this)!.port, options)
  }

  /** Own discovery, reconnection and conservative recovery for this session lifetime. */
  participate(options: ApplicationParticipationOptions): ApplicationParticipation {
    this.#assertOpen()
    if (this.#participation !== undefined) throw new Error('APPLICATION_PARTICIPATION_ALREADY_STARTED')
    const participation = new OwnedApplicationParticipation({ replica: this.#replica, recovery: this.recovery,
      store: this.#store, signal: this.signal, connect: input => this.connectPeer(input),
      links: () => connectedApplicationPeers(internals.get(this)!.port),
      resume: () => this.resume(),
    }, options)
    this.#participation = participation
    this.#links.add(participation)
    return participation
  }

  connectControlParticipant(options: ControlParticipantOptions): ApplicationControlParticipant {
    this.#assertOpen()
    if (this.#control !== undefined && !this.#control.signal.aborted) throw new Error('APPLICATION_CONTROL_ALREADY_ATTACHED')
    const participant = new ApplicationControlParticipant(this.#replica, this.#store, this.#lifetime.signal, options)
    this.#control = participant
    this.#links.add(participant)
    participant.signal.addEventListener('abort', () => { this.#links.delete(participant) }, { once: true })
    return participant
  }

  async retry(operationId: string): Promise<void> {
    this.#assertOpen()
    const existing = this.#inflight.get(operationId)
    if (existing !== undefined) return existing
    const task = (async () => {
      const state = await this.#replica.operation(operationId)
      if (state === null) throw new Error('APPLICATION_OPERATION_NOT_FOUND')
      if (state.status === 'applied') return
      if (state.status === 'abandoned' || state.status === 'needsReapply') throw new AbandonedOperationError(state)
      const attempt = await this.#replica.attempt(operationId)
      if (attempt === null) throw new Error('APPLICATION_ATTEMPT_MISSING')
      if (this.#replica.isCoordinator) await this.#replica.order(attempt)
      else {
        const endpoint = this.#peers.get(this.#replica.generation.payload.coordinator)
        if (endpoint === undefined) return
        await endpoint.submit(attempt)
      }
    })()
    this.#inflight.set(operationId, task)
    try { await task } finally { this.#inflight.delete(operationId) }
  }

  async resume(): Promise<void> {
    this.#assertOpen()
    if (!this.#replica.ready) return
    for (const attempt of await this.#replica.pendingAttempts()) await this.retry(attempt.payload.header.operationId)
  }

  async waitFor(operationId: string, options: { readonly signal?: AbortSignal } = {}): Promise<AppliedResult> {
    return waitFor(this.#replica, this.#lifetime.signal, options.signal, async () => {
      if (!this.#replica.ready) return undefined
      const current = await this.#replica.operation(operationId)
      if (current?.status === 'applied') return current
      if (current?.status === 'abandoned' || current?.status === 'needsReapply') throw new AbandonedOperationError(current)
      if (current === null) throw new Error('APPLICATION_OPERATION_NOT_FOUND')
      return undefined
    })
  }

  async waitForCoverage(applied: AppliedResult, options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> {
    return waitFor(this.#replica, this.#lifetime.signal, options.signal, async () => {
      if (!this.#replica.ready) return undefined
      const current = await this.#replica.operation(applied.operationId)
      if (current?.status === 'abandoned' || current?.status === 'needsReapply') throw new AbandonedOperationError(current)
      const commands = await this.#replica.exportCommands()
      const command = commands.find(value => value.attempt.id === applied.attemptId)
      if (command === undefined) return undefined
      const coverage = this.#replica.shared({ generation: applied.generation, sequence: applied.sequence, root: command.receipt.root })
      return coverage.length === 0 ? undefined : coverage
    })
  }

  /** Runtime-owned attachment. Discovery hints never invoke this without peer authentication. */
  #attachPeer(peerId: string, submit: (attempt: SignedAttempt) => Promise<void>, link: { close(): Promise<void> }): () => void {
    this.#assertOpen()
    if (!currentReader(this.#replica, peerId)) throw new Error('APPLICATION_PEER_NOT_AUTHORIZED')
    if (this.#peers.size >= 8 && !this.#peers.has(peerId)) throw new Error('APPLICATION_PEER_LIMIT')
    const previous = this.#peers.get(peerId), endpoint = { submit, link }
    this.#peers.set(peerId, endpoint); this.#links.add(link)
    if (previous !== undefined && previous.link !== link) {
      try { void Promise.resolve(previous.link.close()).catch(() => undefined) } catch { /* The previous endpoint is already replaced. */ }
    }
    this.#publishStatus()
    return () => { if (this.#peers.get(peerId) === endpoint) this.#peers.delete(peerId); this.#links.delete(link); this.#publishStatus() }
  }

  close(): Promise<void> {
    if (this.#closeTask !== undefined) return this.#closeTask
    let resolve!: () => void, reject!: (error: unknown) => void
    this.#closeTask = new Promise<void>((done, fail) => { resolve = done; reject = fail })
    const owned = [...this.#links]
    this.#closed = true; this.#lifetime.abort(new Error('APPLICATION_SESSION_CLOSED'))
    this.#publishStatus(); this.#statusListeners.clear(); this.#stopStatus(); this.#stopKeys()
    for (const view of [...this.#views]) view.release()
    internals.get(this)!.port.signals.close()
    this.content.close()
    const links = owned.map(link => Promise.resolve().then(() => link.close()))
    const recovery = this.recovery.close()
    const keys = this.keys.close()
    void (async () => {
      await Promise.allSettled([...links, recovery, keys])
      await Promise.allSettled(this.#inflight.values())
      try { await this.#replica.close() } finally { await this.#closing?.() }
    })().then(resolve, reject)
    return this.#closeTask
  }
  #assertOpen(): void { if (this.#closed) throw new Error('APPLICATION_SESSION_CLOSED') }
}

export async function openApplication<const D extends ApplicationDefinition>(options: {
  readonly replica: PeerReplica; readonly definition: D; readonly store: BytesStore; readonly content: ApplicationContent; readonly keys: ApplicationKeyring; readonly close?: () => void | Promise<void>
}): Promise<ApplicationSession<D>> {
  if (await applicationDefinitionDigest(options.definition) !== options.replica.descriptor.definitionDigest) throw new Error('APPLICATION_DEFINITION_MISMATCH')
  const session = new ApplicationSession(options)
  try { await session.resume(); return session }
  catch (error) { await session.close(); throw error }
}

/** In-process transport for embedded peers and reproducible independent-store qualification. */
export async function connectApplications(left: ApplicationSession, right: ApplicationSession): Promise<{ synchronize(): Promise<void>; close(): Promise<void> }> {
  if (left === right) throw new Error('APPLICATION_PEER_SELF')
  return connectApplicationPeerPair(internals.get(left)!.port, internals.get(right)!.port)
}

function currentReader(replica: PeerReplica, publicKey: string): boolean {
  return replica.grant(publicKey)?.reader === true
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
      if (options.cursor.length > 8192) throw new Error()
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

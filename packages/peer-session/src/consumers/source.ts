import type { AppliedResult, OperationState, PeerRevision, PeerStore } from '@chronolog/peer-generation'
import { assertCanonicalCbor, assertEventTopic, canonicalEventPayload, encodeCanonicalCbor, type EventPayload } from '@chronolog/protocol'

import type { ApplicationChange, ApplicationEvent, ApplicationEventBatch, ApplicationEventOptions, QueryParameter, QueryRows } from '../session.js'
import { ownSessionResource } from '../internals.js'

/** A captured, verified application view, also implemented by the Worker facade. */
export interface ApplicationConsumerView {
  readonly revision: PeerRevision
  readEvents(options?: ApplicationEventOptions): ApplicationEventBatch | Promise<ApplicationEventBatch>
  query(sql: string, parameters?: readonly QueryParameter[]): QueryRows | Promise<QueryRows>
  release(): void | Promise<void>
}

/** Consumers use the session's verified views and operation journal, never another command outbox. */
export interface ApplicationConsumerSession {
  readonly applicationId: string
  readonly historyId: string
  readonly revision: PeerRevision
  readonly signal: AbortSignal
  readView(): Promise<ApplicationConsumerView>
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationChange>
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
  }
}

/** Returned by an ordinary domain command on the owned native or Worker session. */
export interface ApplicationConsumerOperation {
  readonly operationId: string
  get(): Promise<OperationState | null>
  applied(options?: { readonly signal?: AbortSignal }): Promise<AppliedResult>
  retry(): Promise<void>
}

export interface ApplicationConsumerOptions {
  readonly id: string
  /** Changing reducer, provider, authorization or publication semantics requires a new version. */
  readonly version: string
  readonly session: ApplicationConsumerSession
  readonly store: PeerStore
  readonly maxStateBytes?: number
}

const owners = new WeakMap<PeerStore, Set<string>>()

/** One exclusive consumer owner and one atomic durable record. Reload after every ambiguous write. */
export class ConsumerJournal {
  readonly signal: AbortSignal
  readonly #abort = new AbortController()
  readonly #options: ApplicationConsumerOptions
  readonly #key: string
  readonly #binding: string
  readonly #maximum: number
  readonly #stop: () => void
  readonly #release: () => void
  #active: Promise<unknown> | undefined
  #closed: Promise<void> | undefined

  constructor(kind: string, options: ApplicationConsumerOptions, configuration: unknown) {
    for (const value of [options.id, options.version, options.session.applicationId, options.session.historyId]) consumerId(value)
    options.session.signal.throwIfAborted()
    this.#options = options
    this.#maximum = bounded(options.maxStateBytes ?? 8 * 1024 * 1024, 1024, 64 * 1024 * 1024)
    this.#key = `peer-session/consumers/${options.session.applicationId}/${encodeURIComponent(options.session.historyId)}/${kind}/${encodeURIComponent(options.id)}`
    this.#binding = JSON.stringify([kind, options.id, options.version, options.session.applicationId, options.session.historyId, configuration])
    const held = owners.get(options.store) ?? new Set<string>()
    if (held.has(this.#key)) throw new Error('APPLICATION_CONSUMER_IN_USE')
    held.add(this.#key); owners.set(options.store, held)
    this.signal = AbortSignal.any([this.#abort.signal, options.session.signal])
    const close = (): void => { void this.close() }
    options.session.signal.addEventListener('abort', close, { once: true })
    this.#stop = () => options.session.signal.removeEventListener('abort', close)
    try { this.#release = ownSessionResource(options.session, this) }
    catch (error) { this.#stop(); held.delete(this.#key); throw error }
  }

  async read(): Promise<unknown> {
    this.signal.throwIfAborted()
    const bytes = await this.#options.store.get(this.#key)
    if (bytes === null) return null
    if (bytes.length > this.#maximum) throw new Error('APPLICATION_CONSUMER_STATE_LIMIT')
    const value = assertCanonicalCbor(bytes)
    if (!Array.isArray(value) || value.length !== 3 || value[0] !== 1n || typeof value[1] !== 'string' || typeof value[2] !== 'string') {
      throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    }
    if (value[1] !== this.#binding) throw new Error('APPLICATION_CONSUMER_BINDING_MISMATCH')
    return JSON.parse(value[2]) as unknown
  }

  async write(value: unknown): Promise<void> {
    this.signal.throwIfAborted()
    const bytes = encodeCanonicalCbor([1n, this.#binding, JSON.stringify(value)])
    if (bytes.length > this.#maximum) throw new Error('APPLICATION_CONSUMER_STATE_LIMIT')
    await this.#options.store.put(this.#key, bytes)
  }

  reserve(value: unknown, additionalBytes: number): void {
    const bytes = encodeCanonicalCbor([1n, this.#binding, JSON.stringify(value)])
    if (bytes.length + additionalBytes > this.#maximum) throw new Error('APPLICATION_CONSUMER_STATE_LIMIT')
  }

  run<T>(operation: () => Promise<T>): Promise<T> {
    this.signal.throwIfAborted()
    if (this.#active !== undefined) return Promise.reject(new Error('APPLICATION_CONSUMER_BUSY'))
    const active = Promise.resolve().then(operation)
    this.#active = active
    return active.finally(() => { if (this.#active === active) this.#active = undefined })
  }

  close(): Promise<void> {
    this.#closed ??= (async () => {
      this.#abort.abort(new Error('APPLICATION_CONSUMER_CLOSED')); this.#stop()
      try { await this.#active } catch { /* The caller owns a failed or cancelled turn. */ }
      owners.get(this.#options.store)?.delete(this.#key)
      this.#release()
    })()
    return this.#closed
  }
}

export function consumerId(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || [...value].some(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)) {
    throw new Error('APPLICATION_CONSUMER_ID_INVALID')
  }
}
export function bounded(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error('APPLICATION_CONSUMER_BOUND_INVALID')
  return value
}
export function topics(input?: readonly string[]): readonly string[] | null {
  if (input === undefined) return null
  bounded(input.length, 1, 64); input.forEach(assertEventTopic)
  return [...new Set(input)].sort()
}
export function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
  return value as Record<string, unknown>
}
export function clonePayload<T extends EventPayload>(value: T): T { return JSON.parse(canonicalEventPayload(value)) as T }
export function revision(value: unknown): PeerRevision {
  const r = record(value), point = record(r.point)
  for (const field of ['applicationId', 'generation']) if (typeof r[field] !== 'string' || !/^[0-9a-f]{64}$/u.test(r[field])) throw new Error('APPLICATION_CONSUMER_REVISION_INVALID')
  if (typeof r.historyId !== 'string' || typeof r.materializationRevision !== 'string' || !/^[0-9]+$/u.test(r.materializationRevision) ||
      !Number.isSafeInteger(r.controlRevision) || (r.controlRevision as number) < 0 || point.generation !== r.generation ||
      typeof point.root !== 'string' || !/^[0-9a-f]{64}$/u.test(point.root) || !Number.isSafeInteger(point.sequence) || (point.sequence as number) < 0) {
    throw new Error('APPLICATION_CONSUMER_REVISION_INVALID')
  }
  consumerId(r.historyId)
  return structuredClone(value) as PeerRevision
}
export function sameSelection(a: PeerRevision, b: PeerRevision): boolean {
  return a.applicationId === b.applicationId && a.historyId === b.historyId && a.generation === b.generation && a.controlRevision === b.controlRevision
}
export function assertCurrent(session: ApplicationConsumerSession, view: ApplicationConsumerView): void {
  if (!sameSelection(session.revision, view.revision)) throw new Error('APPLICATION_CONSUMER_VIEW_CHANGED')
}
export function event(value: unknown): ApplicationEvent {
  const e = record(value)
  for (const field of ['attemptId', 'author']) if (typeof e[field] !== 'string' || !/^[0-9a-f]{64}$/u.test(e[field])) throw new Error('APPLICATION_CONSUMER_EVENT_INVALID')
  if (typeof e.id !== 'string' || !new RegExp(`^${String(e.attemptId)}:(?:[0-9]|[1-5][0-9]|6[0-3])$`, 'u').test(e.id) ||
      typeof e.operationId !== 'string' || typeof e.authorTimestampMs !== 'string' || !/^[0-9]+$/u.test(e.authorTimestampMs) || typeof e.topic !== 'string') {
    throw new Error('APPLICATION_CONSUMER_EVENT_INVALID')
  }
  consumerId(e.operationId); assertEventTopic(e.topic)
  return { id: e.id, attemptId: e.attemptId as string, operationId: e.operationId, author: e.author as string,
    authorTimestampMs: e.authorTimestampMs, topic: e.topic, payload: clonePayload(e.payload as EventPayload) }
}
export async function readBatch(view: ApplicationConsumerView, options: ApplicationEventOptions): Promise<ApplicationEventBatch> {
  const batch = await view.readEvents(options)
  if (JSON.stringify(revision(batch.revision)) !== JSON.stringify(view.revision) || typeof batch.cursor !== 'string' || batch.cursor.length === 0 ||
      batch.cursor.length > 8192 || typeof batch.hasMore !== 'boolean' || !Array.isArray(batch.events) || batch.events.length > (options.limit ?? 32) * 64) {
    throw new Error('APPLICATION_CONSUMER_BATCH_INVALID')
  }
  if (batch.cursor === options.cursor && (batch.hasMore || batch.events.length !== 0)) throw new Error('APPLICATION_CONSUMER_NO_PROGRESS')
  const events = batch.events.map(event)
  if (new Set(events.map(e => e.id)).size !== events.length || options.topics !== undefined && events.some(e => !options.topics!.includes(e.topic)) ||
      new TextEncoder().encode(JSON.stringify(events)).length > 1024 * 1024) throw new Error('APPLICATION_CONSUMER_BATCH_LIMIT')
  return { ...batch, events }
}
export async function selected(session: ApplicationConsumerSession, intent: ApplicationEvent): Promise<boolean> {
  const state = await session.operations.get(intent.operationId, { author: intent.author })
  return state?.status === 'applied' && state.outcome === 'accepted' && state.attemptId === intent.attemptId
}

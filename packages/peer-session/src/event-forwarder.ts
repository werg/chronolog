import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import { awaitOwnedTask } from './lifetime.js'
import type { ApplicationChange, ApplicationEvent, ApplicationEventBatch, ApplicationEventOptions, ApplicationReadView, MaterializedRevision, SessionStatus } from './session-types.js'
import type { OperationInspection } from './operation.js'
export interface ForwarderReadView {
  readonly applicationId: string
  readonly revision: MaterializedRevision
  query(sql: string, parameters?: Parameters<ApplicationReadView['query']>[1]): ReturnType<ApplicationReadView['query']> | Promise<ReturnType<ApplicationReadView['query']>>
  readEvents(options?: ApplicationEventOptions): ApplicationEventBatch | Promise<ApplicationEventBatch>
  release(): void | Promise<void>
}
export interface EventForwarderSession {
  readonly applicationId: string
  readonly signal: AbortSignal
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationChange>
  onStatus(listener: (status: SessionStatus) => void): () => void
  readView(options?: { readonly view?: 'local' | 'final' }): Promise<ForwarderReadView>
  readonly operations: { get(id: string): { inspect(): OperationInspection | Promise<OperationInspection> } | null | Promise<{ inspect(): OperationInspection | Promise<OperationInspection> } | null> }
}
/** A private durable exporter checkpoint, not an application ordering cursor or a UI draft store. */
export interface EventForwarderCheckpoint { load(): string | undefined | Promise<string | undefined>; save(state: string): void | Promise<void> }
export type EventDeliveryObservation = Pick<OperationInspection, 'stored' | 'materialized' | 'retained' | 'finalized' | 'excluded'>
export interface EventProjection { readonly name: string; readonly payload: unknown }
export type EventDeliveryProjection<Projected extends EventProjection> = Projected & { readonly observation: EventDeliveryObservation; readonly change: 'upsert' | 'retract' }
export interface EventForwarderOptions<Projected extends EventProjection> {
  readonly session: EventForwarderSession
  readonly topics?: readonly string[]
  readonly limit?: number
  readonly view?: 'local' | 'final'
  /** Change this local exporter label when projection meaning changes. It never freezes database schema. */
  readonly scope?: string
  readonly maxEvents?: number
  readonly maxBytes?: number
  readonly checkpoint: EventForwarderCheckpoint
  readonly project: (event: ApplicationEvent, batch: ApplicationEventBatch, context: { readonly view: ForwarderReadView; readonly observation: EventDeliveryObservation }) => Projected | null | undefined | Promise<Projected | null | undefined>
  readonly deliver: (projected: EventDeliveryProjection<Projected>, event: ApplicationEvent, batch: ApplicationEventBatch, signal: AbortSignal) => void | Promise<void>
  readonly signal?: AbortSignal
}
interface Entry<Projected> { readonly event: ApplicationEvent; readonly projected: Projected; readonly observation: EventDeliveryObservation; readonly revision: MaterializedRevision; readonly present: boolean; readonly acknowledged: boolean }
interface Checkpoint<Projected> { readonly format: 'authored-event-outbox-v1'; readonly scope: string; readonly entries: Readonly<Record<string, Entry<Projected>>> }
function check(condition: unknown, code: string): asserts condition { if (!condition) throw Object.assign(new Error(code), { code }) }
/**
 * Reconciles effective snapshots by stable event ID. Late SQL outcome changes retract prior provisional
 * exports; facts can update without a new application revision. The pending ledger is durable BEFORE
 * external delivery, so lost replies retry the same identity. Delivery must be idempotent; this helper
 * does not promise exactly-once external effects or turn finality into a retention promise.
 */
export async function forwardSessionEvents<Projected extends EventProjection>(options: EventForwarderOptions<Projected>): Promise<void> {
  const { session, checkpoint, project, deliver } = options, limit = options.limit ?? 32, maxEvents = options.maxEvents ?? 10_000, maxBytes = options.maxBytes ?? 8 * 1024 * 1024, viewType = options.view ?? 'local'
  check(Number.isSafeInteger(limit) && limit >= 1 && limit <= 256 && Number.isSafeInteger(maxEvents) && maxEvents >= 1 && maxEvents <= 100_000 && Number.isSafeInteger(maxBytes) && maxBytes >= 1024 && maxBytes <= 32 * 1024 * 1024, 'EVENT_FORWARDER_LIMIT_INVALID')
  const topics = options.topics === undefined ? undefined : [...new Set(options.topics)].sort()
  check(topics === undefined || topics.length <= 128 && topics.every(topic => typeof topic === 'string' && topic.length > 0 && topic.length <= 128), 'EVENT_FORWARDER_TOPICS_INVALID')
  const scope = JSON.stringify([session.applicationId, options.scope ?? 'default', viewType, topics ?? null]), owner = new AbortController(), signal = AbortSignal.any([owner.signal, session.signal, ...(options.signal === undefined ? [] : [options.signal])])
  const serialize = (value: unknown): string => canonicalJson(value as EventPayload, { maxBytes, maxNodes: 1_000_000, maxDepth: 48 })
  let entries = new Map<string, Entry<Projected>>(), dirty = true, ended = false, wake: (() => void) | undefined
  const invalidate = (): void => { dirty = true; wake?.() }
  let stopStatus: (() => void) | undefined, iterator: AsyncIterator<ApplicationChange> | undefined
  const save = async (): Promise<void> => { check(entries.size <= maxEvents * 2, 'EVENT_FORWARDER_ENTRY_LIMIT'); const state: Checkpoint<Projected> = { format: 'authored-event-outbox-v1', scope, entries: Object.fromEntries([...entries].sort(([a], [b]) => a.localeCompare(b))) }; await awaitOwnedTask(signal, () => checkpoint.save(serialize(state))) }
  const observation = async (event: ApplicationEvent, revision: MaterializedRevision, present: boolean): Promise<EventDeliveryObservation> => {
    const operation = await session.operations.get(event.proposalId)
    check(operation !== null, 'EVENT_FORWARDER_OPERATION_MISSING')
    const inspected = await operation.inspect()
    check(inspected.applicationId === session.applicationId && inspected.author === event.author, 'EVENT_FORWARDER_OPERATION_SCOPE_INVALID')
    return { stored: inspected.stored, materialized: present ? { proposalId: event.proposalId, revision, outcome: 'accepted', rejectionCode: null, failingStatementIndex: null } : inspected.materialized, retained: structuredClone(inspected.retained), finalized: present && inspected.finalized, excluded: inspected.excluded }
  }
  try {
    const raw = await awaitOwnedTask(signal, () => checkpoint.load())
    if (raw !== undefined) {
      check(typeof raw === 'string' && new TextEncoder().encode(raw).length <= maxBytes, 'EVENT_FORWARDER_CHECKPOINT_LIMIT')
      let parsed: Checkpoint<Projected>
      try { parsed = JSON.parse(raw) as Checkpoint<Projected> } catch { throw Object.assign(new Error('EVENT_FORWARDER_CHECKPOINT_INVALID'), { code: 'EVENT_FORWARDER_CHECKPOINT_INVALID' }) }
      check(parsed.format === 'authored-event-outbox-v1' && parsed.scope === scope && parsed.entries !== null && typeof parsed.entries === 'object' && !Array.isArray(parsed.entries), 'EVENT_FORWARDER_CHECKPOINT_SCOPE_INVALID')
      entries = new Map(Object.entries(parsed.entries)); check(entries.size <= maxEvents * 2, 'EVENT_FORWARDER_ENTRY_LIMIT'); serialize(parsed)
      for (const [id, entry] of entries) check(entry.event?.id === id && typeof entry.event.proposalId === 'string' && entry.projected !== null && typeof entry.projected === 'object' && typeof entry.present === 'boolean' && typeof entry.acknowledged === 'boolean', 'EVENT_FORWARDER_CHECKPOINT_INVALID')
    }
    stopStatus = session.onStatus(invalidate)
    iterator = session.changes({ signal })[Symbol.asyncIterator]()
    const changes = iterator
    void (async () => { for (;;) { const next = await awaitOwnedTask(signal, () => changes.next()); if (next.done === true) { ended = true; wake?.(); return }; invalidate() } })().catch(error => owner.abort(error))
    for (;;) {
      if (!dirty) { if (ended) return; const waiting = new Promise<void>(resolve => { wake = resolve }); await awaitOwnedTask(signal, () => waiting) }
      signal.throwIfAborted(); if (!dirty) continue; dirty = false
      const desired = new Map<string, Entry<Projected>>(), opening = session.readView({ view: viewType })
      let view: ForwarderReadView
      try { view = await awaitOwnedTask(signal, () => opening) }
      catch (error) { void opening.then(late => late.release()).catch(() => undefined); throw error }
      let batch: ApplicationEventBatch = { revision: view.revision, events: [], cursor: '', hasMore: false }
      try {
        check(view.applicationId === session.applicationId && view.revision.view === viewType, 'EVENT_FORWARDER_READ_SCOPE_INVALID')
        let cursor: string | undefined, count = 0
        for (;;) {
          batch = await awaitOwnedTask(signal, () => view.readEvents({ ...(cursor === undefined ? {} : { cursor }), ...(topics === undefined ? {} : { topics }), limit }))
          check(batch.revision.digest === view.revision.digest && batch.revision.view === viewType, 'EVENT_FORWARDER_READ_INCOHERENT')
          for (const event of batch.events) {
            check(++count <= maxEvents && !desired.has(event.id), 'EVENT_FORWARDER_ENTRY_LIMIT')
            const facts = await awaitOwnedTask(signal, () => observation(event, view.revision, true)), projected = await awaitOwnedTask(signal, () => project(structuredClone(event), batch, { view, observation: structuredClone(facts) }))
            if (projected !== null && projected !== undefined) { check(typeof projected.name === 'string' && projected.name.length > 0 && projected.name.length <= 128, 'EVENT_FORWARDER_PROJECTION_INVALID'); serialize(projected); desired.set(event.id, { event: structuredClone(event), projected: structuredClone(projected), observation: facts, revision: view.revision, present: true, acknowledged: false }) }
          }
          if (!batch.hasMore) break
          check(batch.cursor !== cursor, 'EVENT_FORWARDER_CURSOR_STALLED'); cursor = batch.cursor
        }
      } finally { await view.release() }
      // A newer input arrived while deriving. No stale export has started, so simply rederive.
      if (dirty) continue
      for (const [id, prior] of [...entries]) {
        if (dirty) break
        if (desired.has(id)) continue
        const facts = await awaitOwnedTask(signal, () => observation(prior.event, batch.revision, false)), entry: Entry<Projected> = { ...prior, observation: facts, revision: batch.revision, present: false, acknowledged: false }
        entries.set(id, entry); await save()
        await awaitOwnedTask(signal, () => deliver({ ...structuredClone(entry.projected), observation: structuredClone(facts), change: 'retract' }, structuredClone(entry.event), batch, signal))
        entries.delete(id); await save()
      }
      for (const [id, desiredEntry] of desired) {
        if (dirty) break
        const prior = entries.get(id), comparison = (entry: Entry<Projected>): string => serialize({ event: entry.event, projected: entry.projected, observation: entry.observation, revision: entry.revision, present: entry.present })
        if (prior?.acknowledged === true && prior.present && comparison(prior) === comparison(desiredEntry)) continue
        entries.set(id, desiredEntry); await save()
        await awaitOwnedTask(signal, () => deliver({ ...structuredClone(desiredEntry.projected), observation: structuredClone(desiredEntry.observation), change: 'upsert' }, structuredClone(desiredEntry.event), batch, signal))
        entries.set(id, { ...desiredEntry, acknowledged: true }); await save()
      }
    }
  } finally {
    stopStatus?.(); owner.abort(new Error('EVENT_FORWARDER_CLOSED'))
    try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) } catch { /* Preserve the original read/delivery failure. */ }
  }
}

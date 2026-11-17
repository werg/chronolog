import { peerDigest, type AppliedResult, type PeerRevision } from '@chronolog/peer-generation'
import { assertEventTopic, canonicalEventPayload, type EventPayload } from '@chronolog/protocol'
import { ChangeSignal } from '@chronolog/records'

import type { ApplicationEvent } from '../session.js'
import { ConsumerJournal, assertCurrent, bounded, clonePayload, consumerId, event, readBatch, record, revision, sameSelection,
  type ApplicationConsumerOperation, type ApplicationConsumerOptions, type ApplicationConsumerView } from './source.js'

export interface ApplicationTimerOccurrence {
  readonly occurrenceId: string
  readonly timerId: string
  /** Caller-allocated schedule version, distinct from the peer protocol generation. */
  readonly generation: string
  readonly configuration: ApplicationEvent
  readonly scheduledAtMs: number
  readonly observedAtMs: number
  readonly payload: EventPayload
}
export interface ApplicationTimerSchedule {
  readonly timerId: string
  readonly generation: string
  readonly configuration: ApplicationEvent
  readonly nextDueAtMs: number
  readonly intervalMs: number | null
  readonly payload: EventPayload
  readonly active: boolean
}
export interface ApplicationTimerPublication {
  readonly operationId: string
  readonly reapplyOf: string | null
  readonly basedOn: PeerRevision
  readonly status: 'prepared' | 'submitted' | 'applied' | 'cancelled' | 'rejected' | 'abandoned'
  /** A former accepted/rejected observation remains inspectable after abandonment. */
  readonly result: AppliedResult | null
}
export interface ApplicationTimerEntry {
  readonly occurrence: ApplicationTimerOccurrence
  readonly publications: readonly ApplicationTimerPublication[]
}
export interface ApplicationTimerCheckpoint {
  readonly revision: PeerRevision | null
  readonly cursor: string | null
  readonly schedules: readonly ApplicationTimerSchedule[]
  readonly occurrences: readonly ApplicationTimerEntry[]
}
export interface ApplicationTimerOptions extends ApplicationConsumerOptions {
  readonly configurationTopic: string
  readonly authorize: (input: { readonly configuration: ApplicationEvent; readonly view: ApplicationConsumerView; readonly signal: AbortSignal }) => boolean | Promise<boolean>
  /**
   * Return an ordinary session command/reapply handle. Its deterministic program
   * must guard the active configuration and due time if cancellation can race it.
   * createApplicationTimerPrograms supplies those guards for SQL applications.
   */
  readonly publish: (occurrence: ApplicationTimerOccurrence, options: {
    readonly operationId: string; readonly basedOn: PeerRevision; readonly reapplyOf: string | null; readonly signal: AbortSignal
  }) => Promise<ApplicationConsumerOperation>
  readonly now?: () => number
  readonly maxTimers?: number
  readonly maxEntries?: number
  readonly maxOccurrencesPerTick?: number
  readonly pollMs?: number
  readonly timeoutMs?: number
}
export interface ApplicationTimerTurn {
  readonly emitted: number
  readonly cancelled: number
  readonly reset: boolean
  readonly hasMore: boolean
  readonly awaitingReconciliation: boolean
  readonly nextDueAtMs: number | null
}
export class ApplicationTimerRejectedError extends Error {
  constructor(readonly occurrenceId: string, readonly result: AppliedResult) {
    super(`APPLICATION_TIMER_REJECTED: ${result.rejectionCode ?? 'unknown'}`); this.name = 'ApplicationTimerRejectedError'
  }
}
const calls = new WeakMap<ApplicationTimerOptions['store'], Map<string, Promise<unknown>>>()

/** Rebuildable schedule state and a retained journal of ordinary application attempts. */
export class ApplicationTimerScheduler {
  readonly #options: ApplicationTimerOptions
  readonly #journal: ConsumerJournal
  readonly #maxTimers: number
  readonly #maxEntries: number
  readonly #maxPerTick: number
  readonly #pollMs: number
  readonly #timeout: number
  readonly #callKey: string
  #running = false

  private constructor(options: ApplicationTimerOptions) {
    this.#options = options
    if (typeof options.authorize !== 'function' || typeof options.publish !== 'function') throw new Error('APPLICATION_TIMER_POLICY_REQUIRED')
    assertEventTopic(options.configurationTopic)
    this.#maxTimers = bounded(options.maxTimers ?? 4096, 1, 16_384)
    this.#maxEntries = bounded(options.maxEntries ?? 4096, 1, 16_384)
    this.#maxPerTick = bounded(options.maxOccurrencesPerTick ?? 32, 1, 128)
    this.#pollMs = bounded(options.pollMs ?? 1000, 1, 60_000)
    this.#timeout = bounded(options.timeoutMs ?? 30_000, 1, 300_000)
    this.#callKey = JSON.stringify([options.session.applicationId, options.session.historyId, options.id])
    this.#journal = new ConsumerJournal('timers', options, options.configurationTopic)
  }
  static async open(options: ApplicationTimerOptions): Promise<ApplicationTimerScheduler> {
    const scheduler = new ApplicationTimerScheduler(options)
    try { await scheduler.inspect(); return scheduler } catch (error) { await scheduler.close(); throw error }
  }
  inspect(): Promise<ApplicationTimerCheckpoint> { return this.#journal.run(async () => structuredClone(await this.#load())) }
  tick(nowMs = this.#options.now?.() ?? Date.now(), options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationTimerTurn> {
    if (this.#running) return Promise.reject(new Error('APPLICATION_CONSUMER_BUSY'))
    return this.#journal.run(() => this.#tick(nowMs, this.#signal(options.signal)))
  }
  retry(occurrenceId: string, options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationTimerEntry> {
    return this.#journal.run(async () => {
      const state = await this.#load(), entry = this.#find(state, occurrenceId)
      return (await this.#send(state, entry, this.#signal(options.signal))).entry
    })
  }
  reapply(occurrenceId: string, options: { readonly operationId: string; readonly signal?: AbortSignal }): Promise<ApplicationTimerEntry> {
    return this.#journal.run(async () => {
      consumerId(options.operationId)
      let state = await this.#load(), entry = await this.#refresh(this.#find(state, occurrenceId))
      const previous = entry.publications.at(-1)!
      if (previous.status !== 'abandoned' || entry.publications.length >= 16 || entry.publications.some(p => p.operationId === options.operationId)) {
        throw new Error('APPLICATION_TIMER_REAPPLY_REQUIRED')
      }
      entry = { ...entry, publications: [...entry.publications, { operationId: options.operationId, reapplyOf: previous.operationId,
        basedOn: structuredClone(this.#options.session.revision), status: 'prepared', result: null }] }
      state = this.#replace(state, entry); await this.#journal.write(state)
      return (await this.#send(state, entry, this.#signal(options.signal))).entry
    })
  }
  async run(options: { readonly signal?: AbortSignal } = {}): Promise<void> {
    if (this.#running) throw new Error('APPLICATION_CONSUMER_BUSY')
    this.#running = true
    const stop = new AbortController(), signal = AbortSignal.any([this.#signal(options.signal), stop.signal]), wake = new ChangeSignal()
    let failure: unknown
    const watching = (async () => {
      try { for await (const _change of this.#options.session.changes({ signal })) wake.notify() }
      catch (error) { if (!signal.aborted) failure = error }
      finally { if (!signal.aborted && failure === undefined) failure = new Error('APPLICATION_CONSUMER_SOURCE_CLOSED'); wake.close() }
    })()
    try {
      while (!signal.aborted) {
        const version = wake.version
        let turn: ApplicationTimerTurn
        try { turn = await this.#journal.run(() => this.#tick(this.#options.now?.() ?? Date.now(), signal)) }
        catch (error) {
          if (error instanceof Error && error.message === 'APPLICATION_CONSUMER_VIEW_CHANGED') continue
          if (error instanceof Error && ['APPLICATION_TIMER_INTERRUPTED', 'APPLICATION_TIMER_CALLBACK_BUSY'].includes(error.message)) {
            turn = { emitted: 0, cancelled: 0, reset: false, hasMore: false, awaitingReconciliation: true, nextDueAtMs: null }
          } else throw error
        }
        if (turn.hasMore) continue
        if (failure !== undefined) throw failure instanceof Error ? failure : new Error('APPLICATION_CONSUMER_SOURCE_FAILED', { cause: failure })
        const delay = turn.nextDueAtMs === null ? this.#pollMs : Math.max(1, Math.min(this.#pollMs, turn.nextDueAtMs - (this.#options.now?.() ?? Date.now())))
        const timer = setTimeout(() => wake.notify(), delay)
        try { await wake.wait(version, signal) } finally { clearTimeout(timer) }
      }
    } catch (error) { if (!signal.aborted) throw error }
    finally { stop.abort(); await watching; this.#running = false }
  }
  close(): Promise<void> { return this.#journal.close() }

  async #tick(nowMs: number, signal: AbortSignal): Promise<ApplicationTimerTurn> {
    timerTime(nowMs); signal.throwIfAborted()
    const before = await this.#load()
    const view = await this.#options.session.readView()
    let state: ApplicationTimerCheckpoint
    try { state = await this.#scan(before, view, signal); assertCurrent(this.#options.session, view) }
    finally { await view.release() }
    const reset = before.revision !== null && !sameSelection(before.revision, state.revision!)
    for (const entry of state.occurrences) state = this.#replace(state, await this.#refresh(entry))
    state = this.#advance(state)
    if (JSON.stringify(before) !== JSON.stringify(state)) await this.#journal.write(state)
    let emitted = 0, cancelled = 0
    const considered = new Set<string>()
    for (let i = 0; i < this.#maxPerTick; i++) {
      signal.throwIfAborted()
      const due = state.schedules.filter(s => s.active && s.nextDueAtMs <= nowMs && !considered.has(s.configuration.id))
        .sort((a, b) => a.nextDueAtMs - b.nextDueAtMs || a.timerId.localeCompare(b.timerId))[0]
      if (due === undefined) break
      const occurrenceId = `occurrence_${await peerDigest(['chronolog/application-timer/v1', this.#options.session.applicationId,
        this.#options.session.historyId, this.#options.id, this.#options.version, due.configuration.id, due.nextDueAtMs])}`
      let entry = state.occurrences.find(e => e.occurrence.occurrenceId === occurrenceId)
      if (entry === undefined) {
        if (state.occurrences.length >= this.#maxEntries) throw new Error('APPLICATION_TIMER_JOURNAL_LIMIT')
        entry = { occurrence: { occurrenceId, timerId: due.timerId, generation: due.generation, configuration: structuredClone(due.configuration),
          scheduledAtMs: due.nextDueAtMs, observedAtMs: nowMs, payload: clonePayload(due.payload) }, publications: [{ operationId: `timer:${occurrenceId}`,
          reapplyOf: null, basedOn: structuredClone(state.revision!), status: 'prepared', result: null }] }
        state = this.#replace(state, entry); await this.#journal.write(state)
      }
      const previous = entry.publications.at(-1)!.status
      if (previous === 'abandoned' || previous === 'rejected') { considered.add(due.configuration.id); continue }
      const sent = await this.#send(state, entry, signal); state = sent.state; entry = sent.entry
      const status = entry.publications.at(-1)!.status
      if (status === 'applied' && previous !== 'applied') emitted++
      if (status === 'cancelled' && previous !== 'cancelled') cancelled++
      state = this.#advance(state)
      if (status !== 'applied') considered.add(due.configuration.id)
      await this.#journal.write(state)
    }
    const blocked = new Set(state.occurrences.filter(e => ['abandoned', 'rejected', 'prepared', 'submitted'].includes(e.publications.at(-1)!.status)).map(e => e.occurrence.configuration.id))
    const available = state.schedules.filter(s => s.active && !blocked.has(s.configuration.id))
    return { emitted, cancelled, reset, hasMore: available.some(s => s.nextDueAtMs <= nowMs), awaitingReconciliation: blocked.size > 0,
      nextDueAtMs: available.reduce<number | null>((at, s) => at === null ? s.nextDueAtMs : Math.min(at, s.nextDueAtMs), null) }
  }
  async #scan(state: ApplicationTimerCheckpoint, view: ApplicationConsumerView, signal: AbortSignal): Promise<ApplicationTimerCheckpoint> {
    const reset = state.revision !== null && !sameSelection(state.revision, view.revision)
    const schedules = new Map((reset ? [] : state.schedules).map(s => [s.timerId, s]))
    let cursor = reset ? undefined : state.cursor ?? undefined
    for (;;) {
      signal.throwIfAborted()
      const batch = await readBatch(view, { topics: [this.#options.configurationTopic], limit: 64, ...(cursor === undefined ? {} : { cursor }) })
      for (const configuration of batch.events) applyTimerConfiguration(schedules, configuration)
      if (schedules.size > this.#maxTimers) throw new Error('APPLICATION_TIMER_SCHEDULE_LIMIT')
      cursor = batch.cursor
      if (!batch.hasMore) break
    }
    return { ...state, revision: structuredClone(view.revision), cursor, schedules: [...schedules.values()].sort((a, b) => a.timerId.localeCompare(b.timerId)) }
  }
  async #send(input: ApplicationTimerCheckpoint, original: ApplicationTimerEntry, signal: AbortSignal): Promise<{ state: ApplicationTimerCheckpoint; entry: ApplicationTimerEntry }> {
    signal.throwIfAborted()
    let state = input, entry = await this.#refresh(original), publication = entry.publications.at(-1)!
    if (publication.status === 'abandoned' || publication.status === 'applied' || publication.status === 'cancelled' || publication.status === 'rejected') {
      state = this.#replace(state, entry); await this.#journal.write(state); return { state, entry }
    }
    const existing = await this.#options.session.operations.get(publication.operationId)
    if (existing === null) {
      const view = await this.#options.session.readView()
      let allowed = false
      try {
        state = await this.#scan(state, view, signal)
        const schedule = state.schedules.find(s => s.timerId === entry.occurrence.timerId)
        const active = schedule?.active === true && schedule.configuration.id === entry.occurrence.configuration.id &&
          schedule.generation === entry.occurrence.generation && schedule.nextDueAtMs === entry.occurrence.scheduledAtMs &&
          canonicalEventPayload(schedule.payload) === canonicalEventPayload(entry.occurrence.payload)
        if (active) allowed = await this.#call(signal, async child => this.#options.authorize({ configuration: structuredClone(entry.occurrence.configuration), view, signal: child }))
        signal.throwIfAborted(); assertCurrent(this.#options.session, view)
      } finally { await view.release() }
      if (!allowed) {
        entry = this.#publication(entry, { ...publication, status: 'cancelled' }); state = this.#replace(state, entry)
        await this.#journal.write(state); return { state, entry }
      }
    }
    publication = { ...publication, status: 'submitted' }
    entry = this.#publication(entry, publication); state = this.#replace(state, entry)
    this.#journal.reserve(state, 2048)
    await this.#journal.write(state)
    const handle = await this.#call(signal, child => this.#options.publish(structuredClone(entry.occurrence), {
      operationId: publication.operationId, basedOn: structuredClone(publication.basedOn), reapplyOf: publication.reapplyOf, signal: child,
    }))
    if (handle.operationId !== publication.operationId) throw new Error('APPLICATION_TIMER_PUBLICATION_MISMATCH')
    try { await this.#call(signal, child => handle.applied({ signal: child })) }
    catch (error) {
      const updated = await this.#refresh(entry)
      state = this.#replace(state, updated); await this.#journal.write(state)
      if (updated.publications.at(-1)!.status !== 'abandoned') throw error
      entry = updated
    }
    entry = await this.#refresh(entry); state = this.#replace(state, entry)
    if (entry.publications.at(-1)!.status === 'cancelled' && entry.publications.at(-1)!.result !== null) {
      // The guard can also lose to another scheduler firing this due slot.
      // Observe that committed configuration event before retiring a schedule.
      const current = await this.#options.session.readView()
      try { state = await this.#scan(state, current, signal); assertCurrent(this.#options.session, current) }
      finally { await current.release() }
    }
    await this.#journal.write(state)
    if (entry.publications.at(-1)!.status === 'rejected') throw new ApplicationTimerRejectedError(entry.occurrence.occurrenceId, entry.publications.at(-1)!.result!)
    return { state, entry }
  }
  async #refresh(entry: ApplicationTimerEntry): Promise<ApplicationTimerEntry> {
    const publication = entry.publications.at(-1)!, current = await this.#options.session.operations.get(publication.operationId)
    if (current === null) {
      if (publication.result !== null || publication.status === 'abandoned') throw new Error('APPLICATION_TIMER_OPERATION_MISSING')
      return entry
    }
    if (current.status === 'applied') return this.#publication(entry, { ...publication, result: current,
      status: current.outcome === 'accepted' ? 'applied' : current.rejectionCode === 'assert:timer_inactive_configuration' ? 'cancelled' : 'rejected' })
    return this.#publication(entry, { ...publication, status: current.status === 'saved' ? 'submitted' : 'abandoned' })
  }
  #advance(state: ApplicationTimerCheckpoint): ApplicationTimerCheckpoint {
    const schedules = new Map(state.schedules.map(s => [s.timerId, s]))
    for (const entry of state.occurrences) {
      const { occurrence } = entry, status = entry.publications.at(-1)!.status, schedule = schedules.get(occurrence.timerId)
      if (schedule === undefined || !schedule.active || schedule.configuration.id !== occurrence.configuration.id || schedule.nextDueAtMs !== occurrence.scheduledAtMs) continue
      if (status === 'applied') schedules.set(schedule.timerId, advance(schedule))
      else if (status === 'cancelled') schedules.set(schedule.timerId, { ...schedule, active: false })
    }
    return { ...state, schedules: [...schedules.values()] }
  }
  async #call<T>(signal: AbortSignal, operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    signal.throwIfAborted()
    const held = calls.get(this.#options.store) ?? new Map<string, Promise<unknown>>(); calls.set(this.#options.store, held)
    if (held.has(this.#callKey)) throw new Error('APPLICATION_TIMER_CALLBACK_BUSY')
    const deadline = new AbortController(), abort = AbortSignal.any([signal, deadline.signal])
    let stop = () => {}
    const interrupted = new Promise<never>((_resolve, reject) => {
      stop = () => reject(new Error('APPLICATION_TIMER_INTERRUPTED', { cause: abort.reason })); abort.addEventListener('abort', stop, { once: true })
    })
    const timer = setTimeout(() => deadline.abort(new Error('APPLICATION_TIMER_TIMEOUT')), this.#timeout)
    const task = Promise.resolve().then(() => { abort.throwIfAborted(); return operation(abort) }); held.set(this.#callKey, task)
    void task.finally(() => { if (held.get(this.#callKey) === task) held.delete(this.#callKey) }).catch(() => undefined)
    try { return await Promise.race([task, interrupted]) } finally { clearTimeout(timer); abort.removeEventListener('abort', stop) }
  }
  #signal(signal?: AbortSignal): AbortSignal { return signal === undefined ? this.#journal.signal : AbortSignal.any([this.#journal.signal, signal]) }
  #publication(entry: ApplicationTimerEntry, publication: ApplicationTimerPublication): ApplicationTimerEntry {
    return { ...entry, publications: [...entry.publications.slice(0, -1), publication] }
  }
  #replace(state: ApplicationTimerCheckpoint, entry: ApplicationTimerEntry): ApplicationTimerCheckpoint {
    return { ...state, occurrences: state.occurrences.some(e => e.occurrence.occurrenceId === entry.occurrence.occurrenceId)
      ? state.occurrences.map(e => e.occurrence.occurrenceId === entry.occurrence.occurrenceId ? entry : e) : [...state.occurrences, entry] }
  }
  #find(state: ApplicationTimerCheckpoint, occurrenceId: string): ApplicationTimerEntry {
    const entry = state.occurrences.find(e => e.occurrence.occurrenceId === occurrenceId)
    if (entry === undefined) throw new Error('APPLICATION_TIMER_OCCURRENCE_NOT_FOUND')
    return entry
  }
  async #load(): Promise<ApplicationTimerCheckpoint> {
    const value = await this.#journal.read()
    if (value === null) return { revision: null, cursor: null, schedules: [], occurrences: [] }
    const state = record(value)
    if ((state.cursor !== null && (typeof state.cursor !== 'string' || state.cursor.length > 8192)) || !Array.isArray(state.schedules) ||
        state.schedules.length > this.#maxTimers || !Array.isArray(state.occurrences) || state.occurrences.length > this.#maxEntries) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    const schedules = state.schedules.map(value => {
      const row = record(value), configuration = event(row.configuration)
      const schedule = scheduleFrom(configuration)
      if (typeof row.nextDueAtMs !== 'number' || typeof row.active !== 'boolean' || row.timerId !== schedule.timerId || row.generation !== schedule.generation ||
          row.intervalMs !== schedule.intervalMs || canonicalEventPayload(row.payload as EventPayload) !== canonicalEventPayload(schedule.payload)) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
      timerTime(row.nextDueAtMs); return { ...schedule, nextDueAtMs: row.nextDueAtMs, active: row.active }
    })
    const occurrences = state.occurrences.map(value => {
      const row = record(value), occurrence = validateApplicationTimerOccurrence(row.occurrence)
      if (!Array.isArray(row.publications) || row.publications.length === 0 || row.publications.length > 16) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
      const publications = row.publications.map(value => {
        const p = record(value)
        if (typeof p.operationId !== 'string' || (p.reapplyOf !== null && typeof p.reapplyOf !== 'string') ||
            !['prepared', 'submitted', 'applied', 'cancelled', 'rejected', 'abandoned'].includes(String(p.status))) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
        consumerId(p.operationId)
        const result = p.result === null ? null : record(p.result)
        if (result !== null && (result.status !== 'applied' || result.operationId !== p.operationId || !['accepted', 'rejected'].includes(String(result.outcome)))) {
          throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
        }
        return { operationId: p.operationId, reapplyOf: p.reapplyOf, basedOn: revision(p.basedOn), status: p.status,
          result: structuredClone(result) } as ApplicationTimerPublication
      })
      return { occurrence, publications }
    })
    if (new Set(schedules.map(s => s.timerId)).size !== schedules.length || new Set(occurrences.map(e => e.occurrence.occurrenceId)).size !== occurrences.length) throw new Error('APPLICATION_CONSUMER_CHECKPOINT_INVALID')
    return { revision: state.revision === null ? null : revision(state.revision), cursor: state.cursor, schedules, occurrences }
  }
}

export function timerTime(value: number): void { bounded(value, 0, Number.MAX_SAFE_INTEGER) }
export function validateApplicationTimerOccurrence(value: unknown): ApplicationTimerOccurrence {
  const occurrence = record(value)
  for (const field of ['occurrenceId', 'timerId', 'generation']) { if (typeof occurrence[field] !== 'string') throw new Error('APPLICATION_TIMER_OCCURRENCE_INVALID'); consumerId(occurrence[field]) }
  if (typeof occurrence.scheduledAtMs !== 'number' || typeof occurrence.observedAtMs !== 'number' || occurrence.observedAtMs < occurrence.scheduledAtMs) throw new Error('APPLICATION_TIMER_OCCURRENCE_INVALID')
  timerTime(occurrence.scheduledAtMs); timerTime(occurrence.observedAtMs)
  const configuration = event(occurrence.configuration), schedule = scheduleFrom(configuration)
  if (occurrence.timerId !== schedule.timerId || occurrence.generation !== schedule.generation || occurrence.scheduledAtMs < schedule.nextDueAtMs ||
      schedule.intervalMs === null && occurrence.scheduledAtMs !== schedule.nextDueAtMs || schedule.intervalMs !== null &&
      (occurrence.scheduledAtMs - schedule.nextDueAtMs) % schedule.intervalMs !== 0 || canonicalEventPayload(occurrence.payload as EventPayload) !== canonicalEventPayload(schedule.payload)) {
    throw new Error('APPLICATION_TIMER_OCCURRENCE_INVALID')
  }
  return { occurrenceId: occurrence.occurrenceId as string, timerId: schedule.timerId, generation: schedule.generation,
    configuration, scheduledAtMs: occurrence.scheduledAtMs, observedAtMs: occurrence.observedAtMs, payload: clonePayload(schedule.payload) }
}
function scheduleFrom(configuration: ApplicationEvent): ApplicationTimerSchedule {
  const value = record(configuration.payload)
  if (value.type !== 'timer.scheduled' || value.version !== 1 || typeof value.timerId !== 'string' || typeof value.generation !== 'string' ||
      typeof value.dueAtMs !== 'number') throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID')
  consumerId(value.timerId); consumerId(value.generation); timerTime(value.dueAtMs)
  const interval = value.intervalMs ?? null
  if (interval !== null) { if (typeof interval !== 'number') throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID'); bounded(interval, 1, Number.MAX_SAFE_INTEGER) }
  return { timerId: value.timerId, generation: value.generation, configuration, nextDueAtMs: value.dueAtMs,
    intervalMs: interval, payload: clonePayload((value.payload ?? null) as EventPayload), active: true }
}
function advance(schedule: ApplicationTimerSchedule): ApplicationTimerSchedule {
  if (schedule.intervalMs === null) return { ...schedule, active: false }
  const nextDueAtMs = schedule.nextDueAtMs + schedule.intervalMs; timerTime(nextDueAtMs)
  return { ...schedule, nextDueAtMs }
}
function applyTimerConfiguration(schedules: Map<string, ApplicationTimerSchedule>, configuration: ApplicationEvent): void {
  const value = record(configuration.payload)
  if (value.type === 'timer.scheduled') { const schedule = scheduleFrom(configuration); schedules.set(schedule.timerId, schedule); return }
  if (value.version !== 1 || typeof value.timerId !== 'string' || typeof value.generation !== 'string') throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID')
  consumerId(value.timerId); consumerId(value.generation)
  const schedule = schedules.get(value.timerId)
  if (value.type === 'timer.cancelled') {
    if (schedule?.generation === value.generation) schedules.set(schedule.timerId, { ...schedule, active: false })
  } else if (value.type === 'timer.fired') {
    if (typeof value.configurationEventId !== 'string' || typeof value.scheduledAtMs !== 'number') throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID')
    if (schedule?.active === true && schedule.generation === value.generation && schedule.configuration.id === value.configurationEventId && schedule.nextDueAtMs === value.scheduledAtMs) {
      schedules.set(schedule.timerId, advance(schedule))
    }
  } else throw new Error('APPLICATION_TIMER_CONFIGURATION_INVALID')
}

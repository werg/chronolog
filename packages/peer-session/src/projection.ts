import type { BytesStore } from '@chronolog/records'
import { decodePeerValue, encodePeerValue, samePeerValue, validatePeerRevision, type PeerRevision } from '@chronolog/peer-generation'
import { assertEventTopic, canonicalJson, type EventPayload } from '@chronolog/protocol'
import { APPLICATION_EVENT_CURSOR_LIMIT, RecoveredViewError, type ApplicationChange, type ApplicationEvent, type ApplicationReadView } from './session.js'
import { awaitOwnedTask } from './lifetime.js'

export const APPLICATION_PROJECTION_LIMITS = Object.freeze({ active: 8, pending: 8, stateBytes: 524_288, checkpointBytes: 2_097_152 })

/** A local derived view. Reducers may replay after recovery and must have no external effects. */
export interface ApplicationProjectionDefinition<State extends EventPayload> {
  readonly id: string
  readonly version: string
  readonly topics?: readonly string[]
  readonly initial: State
  readonly reduce: (state: State, event: ApplicationEvent) => State
}
export interface ApplicationProjectionReset {
  readonly reason: 'recovery' | 'definition'
  readonly previousRevision: PeerRevision
}
export interface ApplicationProjectionSnapshot<State extends EventPayload = EventPayload> {
  readonly revision: PeerRevision
  readonly state: State
  readonly reset: ApplicationProjectionReset | null
}
export interface ApplicationProjectionHandle<State extends EventPayload = EventPayload> {
  readonly id: string
  read(options?: { readonly signal?: AbortSignal }): Promise<ApplicationProjectionSnapshot<State>>
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationProjectionSnapshot<State>>
  close(): Promise<void>
}
interface ProjectionSource {
  readonly applicationId: string
  readonly historyId: string
  readonly signal: AbortSignal
  readView(): Promise<ApplicationReadView>
  changes(options: { readonly signal: AbortSignal }): AsyncIterable<ApplicationChange>
}
interface Checkpoint {
  readonly applicationId: string
  readonly historyId: string
  readonly id: string
  readonly version: string
  readonly topics: readonly string[] | null
  readonly revision: PeerRevision
  readonly cursor: string
  readonly state: string
}
function stateBytes(value: EventPayload): string {
  // Leave room for the snapshot envelope in the same bounded Worker transport.
  return canonicalJson(value, { maxBytes: APPLICATION_PROJECTION_LIMITS.stateBytes, maxNodes: 32_768, maxDepth: 24 })
}
function identifier(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(value)) throw new Error('APPLICATION_PROJECTION_ID_INVALID')
}
function topics(value: readonly string[] | undefined): readonly string[] | null {
  if (value === undefined) return null
  if (!Array.isArray(value) || value.length > 128) throw new Error('APPLICATION_PROJECTION_TOPICS_INVALID')
  const names: string[] = []
  for (const topic of value) {
    if (typeof topic !== 'string') throw new Error('APPLICATION_PROJECTION_TOPICS_INVALID')
    assertEventTopic(topic); names.push(topic)
  }
  return [...new Set(names)].sort()
}

/** One session-owned checkpoint atomically binds reducer state to a verified event cursor. */
export class ApplicationProjection<State extends EventPayload> implements ApplicationProjectionHandle<State> {
  readonly id: string
  readonly #version: string
  readonly #topics: readonly string[] | null
  readonly #initial: string
  readonly #reduce: ApplicationProjectionDefinition<State>['reduce']
  readonly #source: ProjectionSource
  readonly #store: BytesStore
  readonly #key: string
  readonly #lifetime = new AbortController()
  readonly #signal: AbortSignal
  readonly #release: () => void
  #tail: Promise<unknown> = Promise.resolve()
  #closing: Promise<void> | undefined
  #pending = 0
  #loaded = false
  #checkpoint: Checkpoint | null = null
  #fault: unknown

  constructor(options: { readonly source: ProjectionSource; readonly store: BytesStore;
    readonly definition: ApplicationProjectionDefinition<State>; readonly release: () => void }) {
    const definition = options.definition
    identifier(definition.id); identifier(definition.version)
    if (typeof definition.reduce !== 'function') throw new Error('APPLICATION_PROJECTION_REDUCER_INVALID')
    this.id = definition.id; this.#version = definition.version; this.#topics = topics(definition.topics)
    this.#initial = stateBytes(definition.initial); this.#reduce = definition.reduce
    this.#source = options.source; this.#store = options.store; this.#release = options.release
    this.#signal = AbortSignal.any([options.source.signal, this.#lifetime.signal])
    this.#key = `peer-session/projection/${options.source.applicationId}/${this.id}`
  }

  read(options: { readonly signal?: AbortSignal } = {}): Promise<ApplicationProjectionSnapshot<State>> {
    const signal = options.signal === undefined ? this.#signal : AbortSignal.any([this.#signal, options.signal])
    return awaitOwnedTask(signal, () => {
      if (this.#pending >= APPLICATION_PROJECTION_LIMITS.pending) throw new Error('APPLICATION_PROJECTION_BUSY')
      this.#pending++
      const result = this.#tail.then(() => this.#read())
      this.#tail = result.catch(() => undefined).finally(() => { this.#pending-- })
      return result
    })
  }

  async #read(): Promise<ApplicationProjectionSnapshot<State>> {
    this.#signal.throwIfAborted()
    if (this.#fault !== undefined) throw new Error('APPLICATION_PROJECTION_REOPEN_REQUIRED', { cause: this.#fault })
    if (!this.#loaded) {
      const bytes = await this.#store.get(this.#key)
      this.#signal.throwIfAborted()
      if (bytes !== null) {
        if (bytes.length > APPLICATION_PROJECTION_LIMITS.checkpointBytes) throw new Error('APPLICATION_PROJECTION_CHECKPOINT_INVALID')
        const checkpoint = decodePeerValue<Checkpoint>(bytes)
        const fields = ['applicationId', 'historyId', 'id', 'version', 'topics', 'revision', 'cursor', 'state']
        if (checkpoint === null || typeof checkpoint !== 'object' || Object.keys(checkpoint).length !== fields.length ||
          fields.some(key => !Object.hasOwn(checkpoint, key))) throw new Error('APPLICATION_PROJECTION_CHECKPOINT_INVALID')
        validatePeerRevision(checkpoint.revision); identifier(checkpoint.version)
        if (checkpoint.applicationId !== this.#source.applicationId || checkpoint.historyId !== this.#source.historyId || checkpoint.id !== this.id ||
          checkpoint.revision.applicationId !== checkpoint.applicationId || checkpoint.revision.historyId !== checkpoint.historyId ||
          typeof checkpoint.cursor !== 'string' || checkpoint.cursor.length > APPLICATION_EVENT_CURSOR_LIMIT || typeof checkpoint.state !== 'string' ||
          stateBytes(JSON.parse(checkpoint.state) as EventPayload) !== checkpoint.state ||
          checkpoint.topics !== null && !samePeerValue(topics(checkpoint.topics), checkpoint.topics)) {
          throw new Error('APPLICATION_PROJECTION_CHECKPOINT_INVALID')
        }
        this.#checkpoint = checkpoint
      }
      this.#loaded = true
    }
    const previous = this.#checkpoint, view = await this.#source.readView()
    let reset: ApplicationProjectionReset | null = null, next: Checkpoint
    try {
      this.#signal.throwIfAborted()
      const compatible = previous !== null && previous.version === this.#version && samePeerValue(previous.topics, this.#topics)
      if (previous !== null && !compatible) reset = { reason: 'definition', previousRevision: previous.revision }
      else if (previous !== null && previous.revision.generation !== view.revision.generation) {
        reset = { reason: 'recovery', previousRevision: previous.revision }
      }
      if (compatible && reset === null && samePeerValue(previous.revision, view.revision)) {
        return { revision: structuredClone(previous.revision), state: JSON.parse(previous.state) as State, reset: null }
      }
      let cursor = compatible && reset === null ? previous.cursor : undefined
      let state = JSON.parse(compatible && reset === null ? previous.state : this.#initial) as State
      let encoded = stateBytes(state)
      while (true) {
        this.#signal.throwIfAborted()
        let batch
        try { batch = view.readEvents({ ...(cursor === undefined ? {} : { cursor }), ...(this.#topics === null ? {} : { topics: this.#topics }), limit: 128 }) }
        catch (error) {
          if (!(error instanceof RecoveredViewError) || previous === null || cursor === undefined) throw error
          reset = { reason: 'recovery', previousRevision: previous.revision }
          cursor = undefined; state = JSON.parse(this.#initial) as State; continue
        }
        for (const event of batch.events) state = this.#reduce(state, event)
        encoded = stateBytes(state); cursor = batch.cursor
        if (!batch.hasMore) break
      }
      next = { applicationId: this.#source.applicationId, historyId: this.#source.historyId, id: this.id, version: this.#version,
        topics: this.#topics, revision: view.revision, cursor, state: encoded }
    } finally { view.release() }
    const bytes = encodePeerValue(next)
    if (bytes.length > APPLICATION_PROJECTION_LIMITS.checkpointBytes) throw new Error('APPLICATION_PROJECTION_CHECKPOINT_INVALID')
    this.#signal.throwIfAborted()
    try { await this.#store.put(this.#key, bytes) }
    catch (error) {
      // The write may have committed before its acknowledgment was lost. Only
      // reopening can establish which coherent checkpoint is durable.
      this.#fault = error ?? new Error('APPLICATION_PROJECTION_WRITE_FAILED'); throw error
    }
    this.#checkpoint = next
    this.#signal.throwIfAborted()
    return { revision: structuredClone(next.revision), state: JSON.parse(next.state) as State, reset: structuredClone(reset) }
  }

  changes(options: { readonly signal?: AbortSignal } = {}): AsyncIterable<ApplicationProjectionSnapshot<State>> {
    const projection = this
    return { [Symbol.asyncIterator]() {
      const controller = new AbortController(), signal = AbortSignal.any([projection.#signal, controller.signal,
        ...(options.signal === undefined ? [] : [options.signal])])
      const iterator = projection.#source.changes({ signal })[Symbol.asyncIterator]()
      let closed = false, pulling = false, previous: PeerRevision | undefined
      const finish = (): void => {
        if (closed) return
        closed = true; signal.removeEventListener('abort', finish)
        controller.abort(new Error('APPLICATION_PROJECTION_STREAM_CLOSED'))
        void iterator.return?.().catch(() => undefined)
      }
      signal.addEventListener('abort', finish, { once: true })
      if (signal.aborted) finish()
      return {
        async next(): Promise<IteratorResult<ApplicationProjectionSnapshot<State>>> {
          if (closed) return { done: true, value: undefined }
          if (pulling) throw new Error('APPLICATION_PROJECTION_CONCURRENT_NEXT')
          pulling = true
          try {
            const next = await awaitOwnedTask(signal, () => iterator.next())
            if (next.done) { finish(); return { done: true, value: undefined } }
            const value = await projection.read({ signal })
            const reset = value.reset ?? (previous !== undefined && previous.generation !== value.revision.generation
              ? { reason: 'recovery' as const, previousRevision: previous } : null)
            previous = structuredClone(value.revision)
            return { done: false, value: { ...value, reset } }
          } catch (error) {
            const cancelled = signal.aborted; finish()
            if (cancelled) return { done: true, value: undefined }
            throw error
          } finally { pulling = false }
        },
        async return() { finish(); return { done: true, value: undefined } },
      }
    } }
  }

  close(): Promise<void> {
    this.#lifetime.abort(new Error('APPLICATION_PROJECTION_CLOSED'))
    this.#closing ??= this.#tail.then(() => { this.#release() })
    return this.#closing
  }
}

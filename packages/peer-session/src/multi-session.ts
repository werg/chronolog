import { forwardSessionEvents, type EventForwarderOptions, type EventForwarderSession, type EventProjection } from './event-forwarder.js'
import type { ApplicationChange } from './session-types.js'

/** The part of an application session that merged change feeds and forwarders read. */
export interface MergeableSession {
  readonly applicationId: string
  readonly signal?: AbortSignal
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationChange>
}
export interface MergedSessionChange extends ApplicationChange {
  readonly applicationId: string
}
/** Sessions as a fixed collection, or a registry that yields sessions as they open. */
export type SessionSource<Session> = Iterable<Session> | AsyncIterable<Session>
export interface MergedSessionChanges extends AsyncIterable<MergedSessionChange> {
  /** Start following a session; adding the same session twice is a no-op. */
  add(session: MergeableSession): void
  /** Stop following a session. A session whose own change feed ends is removed automatically. */
  remove(session: MergeableSession): void
  readonly size: number
  /** End the merged stream and every per-session subscription. */
  close(): void
}

/**
 * One invalidation stream over many sessions in a process. Each session keeps at most
 * one undelivered change: its own feed is not read again until the consumer takes the
 * previous one, so the per-session coalescing of `changes()` bounds memory.
 * A session feed that fails is removed and reported to `onError`; without `onError`
 * the merged stream fails with that error.
 */
export function mergeSessionChanges(source: SessionSource<MergeableSession> = [], options: {
  readonly signal?: AbortSignal
  readonly onError?: (error: unknown, session: MergeableSession) => void
} = {}): MergedSessionChanges {
  const owner = new AbortController()
  const lifetime = options.signal === undefined ? owner.signal : AbortSignal.any([owner.signal, options.signal])
  const members = new Map<MergeableSession, AbortController>()
  const ready: { readonly session: MergeableSession; readonly change: MergedSessionChange; readonly taken: () => void }[] = []
  let failure: { readonly error: unknown } | undefined
  let wake: () => void = () => undefined
  let iterating = false
  const notify = (): void => { const resolve = wake; wake = () => undefined; resolve() }
  lifetime.addEventListener('abort', () => { for (const member of members.values()) member.abort(); members.clear(); notify() }, { once: true })

  async function follow(session: MergeableSession, member: AbortController): Promise<void> {
    const signal = AbortSignal.any([member.signal, ...(session.signal === undefined ? [] : [session.signal])])
    try {
      for await (const change of session.changes({ signal })) {
        if (signal.aborted) return
        await new Promise<void>(resolve => {
          const taken = (): void => { signal.removeEventListener('abort', taken); resolve() }
          signal.addEventListener('abort', taken, { once: true })
          ready.push({ session, taken, change: Object.freeze({ applicationId: session.applicationId, kind: change.kind, revision: change.revision, revisedOpIds: change.revisedOpIds }) })
          notify()
        })
        if (signal.aborted) return
      }
    } catch (error) {
      if (signal.aborted) return
      if (options.onError !== undefined) options.onError(error, session)
      else { failure ??= { error }; notify() }
    } finally {
      if (members.get(session) === member) members.delete(session)
    }
  }
  function add(session: MergeableSession): void {
    if (lifetime.aborted || members.has(session)) return
    const member = new AbortController()
    members.set(session, member)
    void follow(session, member)
  }
  function remove(session: MergeableSession): void {
    const member = members.get(session)
    if (member === undefined) return
    members.delete(session)
    member.abort()
    for (let index = ready.length - 1; index >= 0; index--) if (ready[index]!.session === session) ready.splice(index, 1)
  }
  if (Symbol.asyncIterator in source) {
    void (async () => {
      try { for await (const session of source) { if (lifetime.aborted) return; add(session) } }
      catch (error) { failure ??= { error }; notify() }
    })()
  } else for (const session of source) add(session)

  return {
    add, remove,
    get size() { return members.size },
    close() { owner.abort() },
    [Symbol.asyncIterator](): AsyncIterator<MergedSessionChange> {
      if (iterating) throw new Error('SESSION_CHANGES_SINGLE_CONSUMER')
      iterating = true
      return {
        async next(): Promise<IteratorResult<MergedSessionChange>> {
          for (;;) {
            if (failure !== undefined) { const { error } = failure; failure = undefined; owner.abort(); throw error }
            if (lifetime.aborted) return { done: true, value: undefined }
            const entry = ready.shift()
            if (entry !== undefined) { entry.taken(); return { done: false, value: entry.change } }
            await new Promise<void>(resolve => { wake = resolve })
          }
        },
        async return(): Promise<IteratorResult<MergedSessionChange>> {
          owner.abort()
          return { done: true, value: undefined }
        },
      }
    },
  }
}

export interface SessionCheckpointScope {
  readonly applicationId: string
  /** Stable storage key `applicationId`. */
  readonly key: string
}
export interface SessionCheckpoints {
  load(scope: SessionCheckpointScope): string | undefined | Promise<string | undefined>
  save(scope: SessionCheckpointScope, state: string): void | Promise<void>
}
export type ForwardableSession = EventForwarderSession & MergeableSession & { readonly signal: AbortSignal }
export interface SessionForwarders {
  add(session: ForwardableSession): void
  remove(session: ForwardableSession): void
  readonly size: number
  /** Stop every forwarder and wait for them to settle; rejects if the session registry failed. */
  close(): Promise<void>
}

export function sessionCheckpointKey(applicationId: string): string { return applicationId }

/**
 * Run `forwardSessionEvents` for each owned application, with its own durable snapshot/outbox
 * checkpoint. A forwarder that stops with an error is removed and reported to `onError`;
 * the other applications continue. Checkpoint adapters must be private to this owner.
 * A forwarder whose session closes simply ends.
 */
export function forwardManySessionEvents<Projected extends EventProjection>(options: Omit<EventForwarderOptions<Projected>, 'session' | 'checkpoint'> & {
  readonly sessions?: SessionSource<ForwardableSession>
  readonly checkpoints: SessionCheckpoints
  readonly onError: (error: unknown, session: ForwardableSession) => void
}): SessionForwarders {
  const { sessions = [], checkpoints, onError, signal, ...forwarder } = options
  const owner = new AbortController()
  const lifetime = signal === undefined ? owner.signal : AbortSignal.any([owner.signal, signal])
  let sourceFailure: { readonly error: unknown } | undefined
  const running = new Map<ForwardableSession, { readonly stop: AbortController; readonly done: Promise<void> }>()
  function add(session: ForwardableSession): void {
    if (lifetime.aborted || running.has(session)) return
    const stop = new AbortController()
    const scope = Object.freeze({ applicationId: session.applicationId, key: sessionCheckpointKey(session.applicationId) })
    const done = forwardSessionEvents({ ...forwarder, session, signal: AbortSignal.any([lifetime, stop.signal]),
      checkpoint: { load: () => checkpoints.load(scope), save: state => checkpoints.save(scope, state) } })
      .catch(error => { if (!stop.signal.aborted && !lifetime.aborted && !session.signal.aborted) onError(error, session) })
      .finally(() => { if (running.get(session)?.stop === stop) running.delete(session) })
    running.set(session, { stop, done })
  }
  function remove(session: ForwardableSession): void {
    const entry = running.get(session)
    if (entry === undefined) return
    running.delete(session)
    entry.stop.abort()
  }
  if (Symbol.asyncIterator in sessions) {
    void (async () => {
      try { for await (const session of sessions) { if (lifetime.aborted) return; add(session) } }
      catch (error) { sourceFailure = { error }; owner.abort(error) }
    })()
  } else for (const session of sessions) add(session)
  return {
    add, remove,
    get size() { return running.size },
    async close() {
      const settled = [...running.values()].map(entry => entry.done)
      owner.abort()
      await Promise.all(settled)
      if (sourceFailure !== undefined) throw sourceFailure.error
    },
  }
}

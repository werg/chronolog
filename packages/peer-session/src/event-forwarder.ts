import { awaitOwnedTask } from './lifetime.js'
import type { ApplicationChange, ApplicationEvent, ApplicationEventBatch, ApplicationEventOptions } from './session-types.js'

export interface EventForwarderSession {
  readonly signal: AbortSignal
  changes(options?: { readonly signal?: AbortSignal }): AsyncIterable<ApplicationChange>
  readView(): Promise<{
    readEvents(options?: ApplicationEventOptions): ApplicationEventBatch | Promise<ApplicationEventBatch>
    release(): void | Promise<void>
  }>
}

export interface EventForwarderCheckpoint {
  load(): string | undefined | Promise<string | undefined>
  save(cursor: string): void | Promise<void>
}

export interface EventForwarderOptions<Projected> {
  readonly session: EventForwarderSession
  readonly topics?: readonly string[]
  readonly limit?: number
  readonly checkpoint: EventForwarderCheckpoint
  readonly project: (event: ApplicationEvent, batch: ApplicationEventBatch) => Projected | null | undefined | Promise<Projected | null | undefined>
  readonly deliver: (projected: Projected, event: ApplicationEvent, batch: ApplicationEventBatch, signal: AbortSignal) => void | Promise<void>
  readonly signal?: AbortSignal
}

/**
 * Durable cursor-based topic forwarder over an owned peer session.
 * Advances its checkpoint only after each projected batch is delivered, and halts
 * on generation recovery when a prior cursor exists so callers review exclusion.
 */
export async function forwardSessionEvents<Projected>(options: EventForwarderOptions<Projected>): Promise<void> {
  const { session, topics, limit = 32, checkpoint, project, deliver, signal } = options
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
    throw Object.assign(new Error('EVENT_FORWARDER_LIMIT_INVALID'), { code: 'EVENT_FORWARDER_LIMIT_INVALID' })
  }
  const owner = new AbortController()
  const lifetime = AbortSignal.any([session.signal, owner.signal, ...(signal === undefined ? [] : [signal])])
  const selectedTopics = topics === undefined ? undefined : [...topics]
  let iterator: AsyncIterator<ApplicationChange> | undefined
  let captured = false, queued = false, ended = false
  let wake: () => void = () => undefined
  try {
    let cursor = await awaitOwnedTask(lifetime, () => checkpoint.load())
    iterator = session.changes({ signal: lifetime })[Symbol.asyncIterator]()
    const changes = iterator
    // Observe recovery while delivery is pending, rather than only after an
    // arbitrarily slow external callback has returned and saved an old cursor.
    void (async () => {
      for (;;) {
        const next = await awaitOwnedTask(lifetime, () => changes.next())
        if (next.done === true) { ended = true; wake(); return }
        if (next.value.kind === 'recovery' && (cursor !== undefined || captured)) {
          throw Object.assign(new Error('EVENT_FORWARDER_REVIEW_RECOVERY'), { code: 'EVENT_FORWARDER_REVIEW_RECOVERY' })
        }
        queued = true; wake()
      }
    })().catch(error => { owner.abort(error) })
    for (;;) {
      if (!queued && !ended) await awaitOwnedTask(lifetime, () => new Promise<void>(resolve => { wake = resolve }))
      lifetime.throwIfAborted()
      if (!queued) return
      queued = false
      for (;;) {
        captured = true
        const batch = await awaitOwnedTask(lifetime, async () => {
          const view = await session.readView()
          let result: ApplicationEventBatch
          try {
            lifetime.throwIfAborted()
            result = await view.readEvents({ ...(cursor === undefined ? {} : { cursor }),
              ...(selectedTopics === undefined ? {} : { topics: selectedTopics }), limit })
          } catch (error) {
            try { await view.release() } catch { /* Preserve the read/cancellation evidence. */ }
            throw error
          }
          await view.release()
          return result
        })
        if (batch.hasMore && batch.cursor === cursor) throw new Error('EVENT_FORWARDER_CURSOR_STALLED')
        for (const event of batch.events) {
          const projected = await awaitOwnedTask(lifetime, () => project(event, batch))
          if (projected !== null && projected !== undefined) {
            await awaitOwnedTask(lifetime, () => deliver(projected, event, batch, lifetime))
          }
        }
        if (batch.cursor !== cursor) {
          await awaitOwnedTask(lifetime, () => checkpoint.save(batch.cursor))
          cursor = batch.cursor
        }
        if (!batch.hasMore) break
      }
    }
  } finally {
    owner.abort(new Error('EVENT_FORWARDER_CLOSED'))
    try { void Promise.resolve(iterator?.return?.()).catch(() => undefined) }
    catch { /* Preserve the original callback/read error. */ }
  }
}

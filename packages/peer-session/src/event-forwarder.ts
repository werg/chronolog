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
  const lifetime = signal === undefined ? session.signal : AbortSignal.any([session.signal, signal])
  let cursor = await checkpoint.load()
  for await (const change of session.changes({ signal: lifetime })) {
    if (change.kind === 'recovery' && cursor !== undefined) {
      throw Object.assign(new Error('EVENT_FORWARDER_REVIEW_RECOVERY'), { code: 'EVENT_FORWARDER_REVIEW_RECOVERY' })
    }
    for (;;) {
      lifetime.throwIfAborted()
      const view = await session.readView()
      let batch: ApplicationEventBatch
      try {
        batch = await view.readEvents({
          ...(cursor === undefined ? {} : { cursor }),
          ...(topics === undefined ? {} : { topics }),
          limit,
        })
      } finally {
        await view.release()
      }
      for (const event of batch.events) {
        lifetime.throwIfAborted()
        const projected = await project(event, batch)
        if (projected !== null && projected !== undefined) {
          await deliver(projected, event, batch, lifetime)
        }
      }
      if (batch.cursor !== cursor) {
        await checkpoint.save(batch.cursor)
        cursor = batch.cursor
      }
      if (!batch.hasMore) break
    }
  }
}

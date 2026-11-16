import type { EventPayload } from './program.js'

export interface EffectiveEvent {
  readonly id: string
  readonly proposalId: string
  readonly eventOrdinal: number
  readonly topic: string
  readonly payload: EventPayload
}
export interface EventTransaction { readonly proposalId: string; readonly events: readonly EffectiveEvent[] }
export interface EventReadOptions {
  readonly cursor?: string
  readonly topics?: readonly string[]
  /** Maximum matching whole proposals, not an event count. */
  readonly limit?: number
}
export interface EventBatch {
  readonly transactions: readonly EventTransaction[]
  readonly scannedThrough: string
  readonly hasMore: boolean
  readonly revision: string
}

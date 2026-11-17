import type { PeerRevision } from '@chronolog/peer-generation'
import type { EventPayload } from '@chronolog/protocol'
import type { ApplicationEvent } from './session-types.js'

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

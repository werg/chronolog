import type { PeerRevision, RecoveryNotice } from '@chronolog/peer-generation'
import type { EventPayload } from '@chronolog/protocol'

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
/** Covers 128 topic filters of 128 UTF-16 units, including worst-case JSON escapes and scope metadata. */
export const APPLICATION_EVENT_CURSOR_LIMIT = 128 * 1024
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
  readonly database: 'idle' | 'opening' | 'ready' | 'failed' | 'closed'
  readonly role: 'coordinator' | 'follower'
  readonly generation: string
  readonly coordinator: string
  readonly connectedPeers: number
}


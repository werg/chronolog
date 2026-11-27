import type { EventPayload, JsonValue, OperationAssumptionsConfig } from '@chronolog/protocol'
import type { SqliteQueryResult } from '@chronolog/materializer'

export interface MaterializedRevision {
  readonly digest: string
  readonly stateRoot: string
  readonly historyDigest: string
  readonly view: 'local' | 'final'
  readonly orderLength: number
}

export type QueryParameter = null | string | number | bigint | Uint8Array

export type QueryRows = SqliteQueryResult

export interface ApplicationEvent {
  readonly id: string
  readonly proposalId: string
  readonly operationId: string
  readonly author: string
  readonly authorTimestampMs: string
  readonly topic: string
  readonly payload: EventPayload
}

export interface ApplicationEventBatch {
  readonly revision: MaterializedRevision
  readonly events: readonly ApplicationEvent[]
  readonly cursor: string
  readonly hasMore: boolean
}

export interface ApplicationEventOptions {
  readonly cursor?: string
  readonly topics?: readonly string[]
  readonly limit?: number
}

export interface ApplicationReadView {
  readonly applicationId: string
  readonly revision: MaterializedRevision
  topic(name: string): JsonValue | null
  query(topic: string, input?: JsonValue): Promise<JsonValue>
  opOutcome?(opId: string): 'accepted' | 'rejected' | null
  topicLastOpId?(topic: string): string | null
  readEvents(options?: ApplicationEventOptions): ApplicationEventBatch
  release(): void
}

export interface CommandOptions {
  readonly operationId?: string
  readonly authorTimestampMs?: bigint
  readonly visibility?: 'public' | 'encrypted'
  /** Explicit signed causal and/or state assumptions evaluated deterministically before applying updates. */
  readonly assumptions?: OperationAssumptionsConfig
  /** Shorthand for op_accepted assumptions (automatically clamps authorTimestampMs past referenced ops). */
  readonly afterOps?: readonly string[]
  /** Shorthand for op_rejected assumptions (deterministic fallback / compensating action). */
  readonly requiresRejected?: readonly string[]
  /** Behavior when an assumption fails: 'reject' (default) or 'record_conflict'. */
  readonly onAssumptionFailed?: 'reject' | 'record_conflict'
}

export interface ApplicationChange {
  readonly kind: 'materialized' | 'finalized' | 'dependency'
  readonly revision: MaterializedRevision
  readonly revisedProposalIds: readonly string[]
  readonly changedTopics?: readonly string[]
  readonly changedTables?: readonly string[]
}

export interface SessionStatus {
  readonly pendingDependencies?: readonly string[]
  readonly canAuthor: boolean
  readonly phase: 'ready' | 'awaiting-keys' | 'closed'
  readonly database: 'idle' | 'opening' | 'ready' | 'failed' | 'closed'
  readonly connectedPeers: number
  readonly connectionRevision?: number
  readonly pendingOperations: number
  readonly materializationError: string | null
}

export interface WaitOptions {
  readonly signal?: AbortSignal
  readonly timeoutMs?: number
}

export const APPLICATION_EVENT_CURSOR_LIMIT = 128 * 1024

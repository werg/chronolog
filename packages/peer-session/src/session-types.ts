import type { EventPayload } from '@chronolog/protocol'
export interface MaterializedRevision { readonly digest: string; readonly view: 'local' | 'final'; readonly executionManifestDigest: string; readonly policyDigest: string }
export type QueryParameter = null | string | number | bigint | Uint8Array
export interface QueryRows { readonly columns: readonly { readonly name: string; readonly declaredType?: string }[]; readonly rows: readonly (readonly QueryParameter[])[] }
export interface ApplicationEvent { readonly id: string; readonly proposalId: string; readonly operationId: string; readonly author: string; readonly authorTimestampMs: string; readonly topic: string; readonly payload: EventPayload }
export interface ApplicationEventBatch { readonly revision: MaterializedRevision; readonly events: readonly ApplicationEvent[]; readonly cursor: string; readonly hasMore: boolean }
export interface ApplicationEventOptions { readonly cursor?: string; readonly topics?: readonly string[]; readonly limit?: number }
export interface ApplicationReadView { readonly applicationId: string; readonly revision: MaterializedRevision; query(sql: string, parameters?: readonly QueryParameter[]): QueryRows; readEvents(options?: ApplicationEventOptions): ApplicationEventBatch; release(): void }
export interface CommandOptions { readonly operationId?: string; readonly authorTimestampMs?: bigint }
export interface ApplicationChange { readonly kind: 'materialized' | 'finalized' | 'dependency'; readonly revision: MaterializedRevision; readonly revisedProposalIds: readonly string[] }
export interface SessionStatus { readonly pendingDependencies?: readonly string[]; readonly canAuthor: boolean; readonly phase: 'ready' | 'awaiting-keys' | 'closed'; readonly database: 'idle' | 'opening' | 'ready' | 'failed' | 'closed'; readonly connectedPeers: number; readonly connectionRevision?: number; readonly pendingOperations: number; readonly materializationError: string | null }
export interface WaitOptions { readonly signal?: AbortSignal; readonly timeoutMs?: number }
export const APPLICATION_EVENT_CURSOR_LIMIT = 128 * 1024

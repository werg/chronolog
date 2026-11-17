import type { OperationState, PeerRevision } from '@chronolog/peer-generation'
import type { ApplicationSession } from './session.js'
import type { SessionStatus } from './session-types.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
import type { ApplicationParticipationStatus } from './participation-types.js'

export const PROTOCOL = 'chronolog/peer-session/worker-application/v1'
export const MAX_REQUESTS = 64, MAX_RELEASES = 16, MAX_STREAMS = 16, MAX_BYTES = 1_048_576
export const releasesResource = (method: string): boolean => method === 'projection.close' || method === 'view.release'
export type Endpoint = ApplicationWorkerEndpoint & { start?(): void }
export type Description = ReturnType<ApplicationSession['describe']>
export interface Snapshot {
  readonly status: SessionStatus
  readonly revision: PeerRevision | null
  readonly participation: ApplicationParticipationStatus | null
}
export interface Metadata extends Snapshot {
  readonly protocol: typeof PROTOCOL
  readonly applicationId: string; readonly historyId: string; readonly deviceId: string; readonly storageId: string
  readonly description: Description
}
export interface WireError { readonly name: string; readonly message: string; readonly code?: string; readonly operation?: OperationState; readonly revision?: PeerRevision }
export interface Request { readonly id: number; readonly method: string; readonly args: readonly unknown[] }
export interface Response { readonly id: number; readonly value?: unknown; readonly error?: WireError; readonly snapshot: Snapshot }

/** Structured-clone payload budget, including binary values and SQL integers. */
export function bounded(value: unknown): void {
  const seen = new Set<object>(); let bytes = 0, nodes = 0
  const visit = (item: unknown, depth: number): void => {
    if (++nodes > 65_536 || depth > 32 || bytes > MAX_BYTES) throw new Error('APPLICATION_WORKER_MESSAGE_LIMIT')
    if (typeof item === 'string') bytes += new TextEncoder().encode(item).length
    else if (typeof item === 'bigint') bytes += item.toString().length
    else if (item === null || item === undefined || typeof item === 'number' || typeof item === 'boolean') bytes += 8
    else if (item instanceof Uint8Array) bytes += item.byteLength
    else if (typeof item === 'object') {
      if (seen.has(item)) throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
      seen.add(item)
      for (const [key, child] of Object.entries(item)) { bytes += new TextEncoder().encode(key).length; visit(child, depth + 1) }
      seen.delete(item)
    } else throw new Error('APPLICATION_WORKER_MESSAGE_INVALID')
    if (bytes > MAX_BYTES) throw new Error('APPLICATION_WORKER_MESSAGE_LIMIT')
  }
  visit(value, 0)
}

import type { OperationAssumptionsConfig, OperationVisibility, TopicUpdate } from '@chronolog/protocol'
import type { Signed } from '@chronolog/authority'
import type { MaterializedRevision, WaitOptions } from './session-types.js'

export interface MaterializedOperation {
  readonly opId: string
  readonly revision: MaterializedRevision
  readonly outcome: 'accepted' | 'rejected'
  readonly rejectionCode: string | null
  readonly rejectionDetail?: string
}

/** One signed receipt covers a batch of retained operations (sync v3). */
export interface RetentionStatement {
  readonly applicationId: string
  readonly peer: string
  readonly storageId: string
  /** Operation ids retained (any envelope version of an op carries the same signed operation). */
  readonly items: readonly string[]
}

export type RetentionEvidence = Signed<RetentionStatement>

export interface OperationInspection {
  readonly applicationId: string
  readonly author: string
  readonly authorTimestampMs: string | null
  readonly opId: string
  readonly operationId: string
  readonly visibility: OperationVisibility
  readonly stored: boolean
  readonly pending: 'dependency' | 'key' | null
  readonly materialized: MaterializedOperation | null
  readonly retained: readonly RetentionEvidence[]
  readonly finalized: boolean
  readonly excluded: boolean
}

export interface OperationOwner {
  inspectOperation(id: string): OperationInspection
  waitOperation(id: string, fact: 'materialized' | 'retained' | 'finalized', options?: WaitOptions): Promise<OperationInspection>
}

export class ApplicationOperation {
  readonly stored = true
  constructor(readonly id: string, readonly operationId: string, private readonly owner: OperationOwner) {}
  inspect(): OperationInspection { return this.owner.inspectOperation(this.id) }
  async materialized(options?: WaitOptions): Promise<MaterializedOperation> { return (await this.owner.waitOperation(this.id, 'materialized', options)).materialized! }
  async retained(options?: WaitOptions): Promise<readonly RetentionEvidence[]> { return (await this.owner.waitOperation(this.id, 'retained', options)).retained }
  async finalized(options?: WaitOptions): Promise<MaterializedOperation> { return (await this.owner.waitOperation(this.id, 'finalized', options)).materialized! }
}

export interface ApplicationSubmission {
  readonly operationId?: string
  readonly authorTimestampMs?: bigint
  readonly visibility?: OperationVisibility
  /** Wait for background materialization before resolving submit (defaults to false for instant local append). */
  readonly awaitMaterialized?: boolean
  readonly updates: readonly TopicUpdate[]
  readonly assumptions?: OperationAssumptionsConfig
}

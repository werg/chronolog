import type { HistoryPoint, OperationState, PeerRevision, TransitionReason } from '@chronolog/peer-generation'

export class AbandonedOperationError extends Error {
  constructor(readonly operation: Extract<OperationState, { status: 'abandoned' | 'needsReapply' }>) {
    super('APPLICATION_OPERATION_ABANDONED'); this.name = 'AbandonedOperationError'
  }
}
/** Selected-transition evidence only; never a claim that an old cursor is safe. */
export interface ApplicationRecoveryEvidence {
  readonly reason: TransitionReason | null
  readonly adopted: HistoryPoint | null
  readonly unknownLoss: boolean
}
export class RecoveredViewError extends Error {
  readonly code = 'APPLICATION_VIEW_RECOVERED' as const
  readonly recovery: ApplicationRecoveryEvidence | null
  constructor(readonly revision: PeerRevision, recovery: ApplicationRecoveryEvidence | null = null) {
    super('APPLICATION_VIEW_RECOVERED'); this.name = 'RecoveredViewError'
    this.recovery = structuredClone(recovery)
  }
}

/** The portable control-port conflict; adapters may preserve an equivalent typed error. */
export class ApplicationControlConflictError extends Error {
  readonly code = 'peer_generation_conflict' as const
  constructor(message = 'The expected application generation is no longer selected.', options?: ErrorOptions) {
    super(message, options)
    this.name = 'ApplicationControlConflictError'
  }
}


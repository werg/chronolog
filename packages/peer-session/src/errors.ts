import type { OperationState, PeerRevision } from '@chronolog/peer-generation'

export class AbandonedOperationError extends Error {
  constructor(readonly operation: Extract<OperationState, { status: 'abandoned' | 'needsReapply' }>) {
    super('APPLICATION_OPERATION_ABANDONED'); this.name = 'AbandonedOperationError'
  }
}
export class RecoveredViewError extends Error {
  constructor(readonly revision: PeerRevision) { super('APPLICATION_VIEW_RECOVERED'); this.name = 'RecoveredViewError' }
}

/** The portable control-port conflict; adapters may preserve an equivalent typed error. */
export class ApplicationControlConflictError extends Error {
  readonly code = 'peer_generation_conflict' as const
  constructor(message = 'The expected application generation is no longer selected.', options?: ErrorOptions) {
    super(message, options)
    this.name = 'ApplicationControlConflictError'
  }
}


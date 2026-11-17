import type { AppliedResult, OperationState, SignedRetainedCoverage } from '@chronolog/peer-generation'
import type { ApplicationSession } from './session.js'

/** A saved immutable attempt. Cancelling a waiter never cancels its command. */
export class ApplicationOperation {
  constructor(readonly session: ApplicationSession, readonly operationId: string) {}
  get(): Promise<OperationState | null> { return this.session.operations.get(this.operationId) }
  applied(options: { readonly signal?: AbortSignal } = {}): Promise<AppliedResult> {
    return this.session.waitFor(this.operationId, options)
  }
  retry(): Promise<void> { return this.session.retry(this.operationId) }
  async shared(options: { readonly signal?: AbortSignal } = {}): Promise<readonly SignedRetainedCoverage[]> {
    const applied = await this.applied(options)
    return this.session.waitForCoverage(applied, options)
  }
}


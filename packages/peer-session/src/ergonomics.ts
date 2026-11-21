import type { AppliedResult, OperationState, PeerRevision } from '@chronolog/peer-generation'

export type OperationLifecycleState = 'recorded' | 'submitted' | 'applied' | 'rejected' | 'unknown'

export interface OperationLifecycleSummary {
  readonly operationId: string
  readonly lifecycle: OperationLifecycleState
  readonly status: OperationState['status'] | 'unknown'
  readonly outcome: 'accepted' | 'rejected' | null
  readonly sequence: number | null
  readonly generation: string | null
  readonly errorCode: string | null
  readonly reason: string | null
  readonly safeToReconcile: boolean
}

export interface BatchCommandEntry {
  readonly operationId: string
  readonly command: string
  readonly input: unknown
  readonly basedOn?: PeerRevision
}

export interface BatchCommandResult {
  readonly operationId: string
  readonly command: string
  readonly lifecycle: OperationLifecycleState
  readonly applied: AppliedResult | null
  readonly state: OperationState | null
  readonly error: { readonly code: string; readonly message: string } | null
}

export interface BatchSubmitOptions {
  readonly wait?: 'applied' | 'recorded'
  readonly signal?: AbortSignal
  readonly stopOnError?: boolean
  /** Optional durable pre-submission persistence hook called before each command transmits. */
  readonly beforeSubmit?: (entry: BatchCommandEntry) => void | Promise<void>
}

export interface ErgonomicSession {
  readonly applicationId: string
  readonly deviceId: string
  readonly historyId?: string
  readonly status?: unknown
  query(name: string, input: unknown): Promise<{ readonly revision: PeerRevision; readonly value: unknown }>
  command(name: string, input: unknown, options: { readonly operationId: string; readonly basedOn?: PeerRevision }): Promise<{
    get(): Promise<OperationState | null>
    applied(options?: { readonly signal?: AbortSignal }): Promise<AppliedResult>
  }>
  readonly operations: {
    get(operationId: string, options?: { readonly author?: string }): Promise<OperationState | null>
    inspect(operationId: string, options?: { readonly author?: string }): Promise<{ readonly state: OperationState; readonly attempt: unknown } | null>
  }
  close?(): Promise<void> | void
}

/**
 * Map Chronolog's exact operation journal state and optional transport error into
 * the canonical five-state lifecycle envelope without conflating recorded/submitted with applied.
 */
export function describeOperationLifecycle(
  operationId: string,
  state: OperationState | null | undefined,
  options: { readonly transmitted?: boolean; readonly error?: unknown } = {},
): OperationLifecycleSummary {
  if (state === null || state === undefined) {
    const err = options.error as { code?: unknown; message?: unknown } | undefined
    return Object.freeze({
      operationId,
      lifecycle: 'unknown',
      status: 'unknown',
      outcome: null,
      sequence: null,
      generation: null,
      errorCode: typeof err?.code === 'string' ? err.code : null,
      reason: typeof err?.message === 'string' ? err.message : 'Operation outcome is not yet observed; inspect again by operationId.',
      safeToReconcile: true,
    })
  }
  if (state.status === 'applied') {
    const rejected = state.outcome === 'rejected'
    return Object.freeze({
      operationId,
      lifecycle: rejected ? 'rejected' : 'applied',
      status: 'applied',
      outcome: state.outcome,
      sequence: state.sequence,
      generation: state.generation,
      errorCode: rejected ? (state.rejectionCode ?? 'COMMAND_REJECTED') : null,
      reason: rejected ? (state.rejectionCode ?? 'Command rejected by application guard.') : null,
      safeToReconcile: false,
    })
  }
  if (state.status === 'saved') {
    return Object.freeze({
      operationId,
      lifecycle: options.transmitted === true ? 'submitted' : 'recorded',
      status: 'saved',
      outcome: null,
      sequence: null,
      generation: null,
      errorCode: null,
      reason: null,
      safeToReconcile: true,
    })
  }
  // abandoned or needsReapply
  return Object.freeze({
    operationId,
    lifecycle: 'rejected',
    status: state.status,
    outcome: 'rejected',
    sequence: null,
    generation: null,
    errorCode: state.status === 'abandoned' ? 'OPERATION_ABANDONED' : 'OPERATION_NEEDS_REAPPLY',
    reason: state.status === 'abandoned'
      ? 'Operation was excluded by a generation recovery; review and deliberately reapply if still needed.'
      : 'Operation requires explicit review and reapplication against current state.',
    safeToReconcile: true,
  })
}

/**
 * Submit an ordered batch of idempotent commands over one session, optionally persisting
 * pre-submission outbox entries and mapping each item to its honest lifecycle state.
 */
export async function submitBatch(
  session: ErgonomicSession,
  entries: readonly BatchCommandEntry[],
  options: BatchSubmitOptions = {},
): Promise<readonly BatchCommandResult[]> {
  if (!Array.isArray(entries) || entries.length > 64) {
    throw Object.assign(new Error('Batch must contain between 0 and 64 commands.'), { code: 'BATCH_LIMIT_EXCEEDED' })
  }
  const items: readonly BatchCommandEntry[] = entries
  const seen = new Set<string>()
  for (const entry of items) {
    if (typeof entry.operationId !== 'string' || entry.operationId.length === 0 || entry.operationId.length > 256) {
      throw Object.assign(new Error('Each batched command requires a stable non-empty operationId.'), { code: 'OPERATION_ID_INVALID' })
    }
    if (seen.has(entry.operationId)) {
      throw Object.assign(new Error(`Duplicate operationId in batch: ${entry.operationId}`), { code: 'BATCH_DUPLICATE_OPERATION_ID' })
    }
    seen.add(entry.operationId)
  }
  const results: BatchCommandResult[] = []
  const waitMode = options.wait ?? 'applied'
  for (const entry of items) {
    options.signal?.throwIfAborted()
    if (options.beforeSubmit !== undefined) await options.beforeSubmit(entry)
    try {
      const handle = await session.command(entry.command, entry.input, {
        operationId: entry.operationId,
        ...(entry.basedOn === undefined ? {} : { basedOn: entry.basedOn }),
      })
      if (waitMode === 'recorded') {
        const state = await handle.get()
        const summary = describeOperationLifecycle(entry.operationId, state, { transmitted: true })
        results.push(Object.freeze({ operationId: entry.operationId, command: entry.command, lifecycle: summary.lifecycle, applied: null, state, error: null }))
        continue
      }
      try {
        const applied = await handle.applied(options.signal === undefined ? undefined : { signal: options.signal })
        const state = await handle.get()
        const summary = describeOperationLifecycle(entry.operationId, state)
        results.push(Object.freeze({ operationId: entry.operationId, command: entry.command, lifecycle: summary.lifecycle, applied, state, error: null }))
        if (options.stopOnError === true && applied.outcome === 'rejected') break
      } catch (waitError) {
        const state = await session.operations.get(entry.operationId).catch(() => null)
        const err = waitError as { code?: unknown; message?: unknown }
        results.push(Object.freeze({
          operationId: entry.operationId,
          command: entry.command,
          lifecycle: state?.status === 'applied' ? (state.outcome === 'rejected' ? 'rejected' : 'applied') : 'unknown',
          applied: null,
          state,
          error: {
            code: typeof err?.code === 'string' ? err.code : 'OPERATION_OUTCOME_UNKNOWN',
            message: typeof err?.message === 'string' ? err.message : 'Operation wait did not complete.',
          },
        }))
        if (options.stopOnError === true) break
      }
    } catch (error) {
      const err = error as { code?: unknown; message?: unknown }
      results.push(Object.freeze({
        operationId: entry.operationId,
        command: entry.command,
        lifecycle: 'rejected',
        applied: null,
        state: null,
        error: {
          code: typeof err?.code === 'string' ? err.code : 'COMMAND_SUBMISSION_FAILED',
          message: typeof err?.message === 'string' ? err.message : String(error),
        },
      }))
      if (options.stopOnError === true) break
    }
  }
  return Object.freeze(results)
}

export interface UnifiedAppClient {
  readonly applicationId: string
  readonly deviceId: string
  readonly historyId: string | null
  submitCommand(entry: BatchCommandEntry, options?: { readonly wait?: 'applied' | 'recorded'; readonly signal?: AbortSignal }): Promise<BatchCommandResult>
  submitBatch(entries: readonly BatchCommandEntry[], options?: BatchSubmitOptions): Promise<readonly BatchCommandResult[]>
  inspectOperation(operationId: string): Promise<OperationLifecycleSummary>
  query(name: string, input?: unknown): Promise<{ readonly revision: PeerRevision; readonly value: unknown }>
  flush(): Promise<void>
  close(): Promise<void>
}

/**
 * Uniform five-step ergonomic client over any Chronolog peer session (native, Worker, or attached).
 */
export function createAppClient(
  session: ErgonomicSession,
  options: {
    readonly beforeSubmit?: (entry: BatchCommandEntry) => void | Promise<void>
    readonly flush?: () => void | Promise<void>
    readonly close?: () => void | Promise<void>
  } = {},
): UnifiedAppClient {
  const client: UnifiedAppClient = {
    applicationId: session.applicationId,
    deviceId: session.deviceId,
    historyId: session.historyId ?? null,
    async submitCommand(entry, callOptions = {}) {
      const [result] = await submitBatch(session, [entry], {
        ...(callOptions.wait === undefined ? {} : { wait: callOptions.wait }),
        ...(callOptions.signal === undefined ? {} : { signal: callOptions.signal }),
        ...(options.beforeSubmit === undefined ? {} : { beforeSubmit: options.beforeSubmit }),
      })
      return result!
    },
    submitBatch(entries, callOptions = {}) {
      return submitBatch(session, entries, {
        ...(options.beforeSubmit === undefined ? {} : { beforeSubmit: options.beforeSubmit }),
        ...callOptions,
      })
    },
    async inspectOperation(operationId) {
      const state = await session.operations.get(operationId)
      return describeOperationLifecycle(operationId, state)
    },
    query(name, input = null) {
      return session.query(name, input)
    },
    async flush() {
      if (options.flush !== undefined) await options.flush()
    },
    async close() {
      if (options.close !== undefined) await options.close()
      else await session.close?.()
    },
  }
  return Object.freeze(client)
}

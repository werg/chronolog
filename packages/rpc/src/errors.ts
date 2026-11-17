import { SignalError } from '@chronolog/signals'
import type { SignalErrorCode } from '@chronolog/signals'

export type RpcErrorCode =
  | 'cancelled'
  | 'deadline_exceeded'
  | 'transport_unavailable'
  | 'unauthenticated'
  | 'permission_denied'
  | 'invalid_argument'
  | 'not_found'
  | 'already_exists'
  | 'resource_exhausted'
  | 'failed_precondition'
  | 'revision_unavailable'
  | 'revision_not_retained'
  | 'result_not_available'
  | 'node_starting'
  | 'node_replaying'
  | 'protocol_rejected'
  | 'internal'

// Live failures remain actionable across RPC, but are never a request to replay
// a message. This exhaustive mapping grows with the standalone public contract.
const SIGNAL_ERROR_CODES: Readonly<Record<SignalErrorCode, RpcErrorCode>> = {
  signal_authorization_required: 'failed_precondition',
  signal_backpressure: 'resource_exhausted',
  signal_bounds_invalid: 'invalid_argument',
  signal_channel_closed: 'transport_unavailable',
  signal_clock_invalid: 'failed_precondition',
  signal_clock_or_sequence_exhausted: 'failed_precondition',
  signal_disconnected: 'transport_unavailable',
  signal_expired: 'deadline_exceeded',
  signal_frame_invalid: 'protocol_rejected',
  signal_frame_too_large: 'invalid_argument',
  signal_identity_invalid: 'invalid_argument',
  signal_mode_invalid: 'invalid_argument',
  signal_options_invalid: 'invalid_argument',
  signal_payload_invalid: 'invalid_argument',
  signal_receive_timeout: 'deadline_exceeded',
  signal_replay_limit: 'resource_exhausted',
  signal_route_backpressure: 'resource_exhausted',
  signal_route_closed: 'transport_unavailable',
  signal_route_invalid: 'invalid_argument',
  signal_route_limit: 'resource_exhausted',
  signal_scope_invalid: 'invalid_argument',
  signal_scope_mismatch: 'permission_denied',
  signal_send_timeout: 'deadline_exceeded',
  signal_signature_invalid: 'unauthenticated',
  signal_subscription_limit: 'resource_exhausted',
  signal_subscription_overflow: 'resource_exhausted',
  signal_topic_filter_invalid: 'invalid_argument',
  signal_topic_invalid: 'invalid_argument',
  signal_ttl_invalid: 'invalid_argument',
  signal_unauthorized: 'permission_denied',
}

const RETRYABLE_CODES = new Set<RpcErrorCode>([
  'deadline_exceeded',
  'transport_unavailable',
  'resource_exhausted',
  'node_starting',
  'node_replaying',
])

export class ChronologRpcError extends Error {
  readonly code: RpcErrorCode
  readonly retryable: boolean
  readonly details?: Readonly<Record<string, string>>

  constructor(
    code: RpcErrorCode,
    message: string,
    options: {
      readonly cause?: unknown
      readonly retryable?: boolean
      readonly details?: Readonly<Record<string, string>>
    } = {},
  ) {
    super(message, { cause: options.cause })
    this.name = 'ChronologRpcError'
    this.code = code
    this.retryable = options.retryable ?? RETRYABLE_CODES.has(code)
    if (options.details !== undefined) this.details = options.details
  }
}

export function isChronologRpcError(error: unknown): error is ChronologRpcError {
  return error instanceof ChronologRpcError
}

export function toChronologRpcError(error: unknown): ChronologRpcError {
  if (isChronologRpcError(error)) return error
  if (error instanceof SignalError) {
    return new ChronologRpcError(SIGNAL_ERROR_CODES[error.code], error.message, {
      cause: error, retryable: false, details: { signalCode: error.code },
    })
  }
  if (error instanceof DOMException && error.name === 'AbortError') {
    return new ChronologRpcError('cancelled', 'RPC call was cancelled', { cause: error })
  }
  return new ChronologRpcError(
    'internal',
    error instanceof Error ? error.message : 'Unknown RPC failure',
    { cause: error },
  )
}

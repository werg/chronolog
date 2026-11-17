/** Default intent lifetime at the caller's send boundary. */
export const DEFAULT_SIGNAL_TTL_MS = 5_000
/** Largest supported configured lifetime; a channel may impose a lower maximum. */
export const MAX_SIGNAL_TTL_MS = 300_000

/** JSON values carried by live messages, independently of a database. */
export type SignalPayload = null | boolean | number | string | readonly SignalPayload[] | { readonly [key: string]: SignalPayload }

export interface EphemeralSignal {
  readonly scope: string
  readonly authorId: string
  readonly sessionId: string
  readonly sequence: number
  readonly topic: string
  readonly payload: SignalPayload
  readonly issuedAtMs: number
  readonly expiresAtMs: number
}
export interface SignalSendOptions { readonly ttlMs?: number; readonly signal?: AbortSignal }
export interface SignalSubscribeOptions {
  readonly topics?: readonly string[]
  /** all preserves admitted messages in bounded FIFO order; latest replaces pending values. */
  readonly mode?: 'all' | 'latest'
  readonly signal?: AbortSignal
}
export interface Signals {
  /** Live dispatch only: no offline outbox, retry, remote receipt or processing acknowledgment. */
  send(topic: string, payload: SignalPayload, options?: SignalSendOptions): Promise<EphemeralSignal>
  subscribe(options?: SignalSubscribeOptions): AsyncIterable<EphemeralSignal>
}
export interface SignalIdentity { readonly publicKeyBytes: Uint8Array; readonly privateKey: CryptoKey }
export interface SignalAuthorization { readonly scope: string; readonly authorId: string; readonly topic: string }
export interface SignalTransport {
  /** Must honor cancellation. Encryption and recipient admission belong to this transport.
   * Throw SignalError('signal_route_backpressure') only if no bytes were accepted. */
  send(frame: Uint8Array, options: { readonly signal: AbortSignal }): Promise<void>
  /** Retire the underlying connection after a failed or noncooperative write. */
  close?(): void | Promise<void>
}
export interface SignalRoute {
  /** Admission belongs to this connection lifetime; closing cancels pending verification. */
  receive(frame: Uint8Array): Promise<EphemeralSignal | null>
  close(): void
}
export interface SignalChannelOptions {
  readonly scope: string
  readonly identity: SignalIdentity
  /** Current policy for original authors, independent of route identity. No implicit trust. */
  readonly authorize: (message: SignalAuthorization) => boolean | Promise<boolean>
  /** Forward verified originals to other attached live routes; false by default. */
  readonly relay?: boolean
  readonly now?: () => number
  readonly maxTtlMs?: number
  readonly maxClockSkewMs?: number
  readonly maxPendingSends?: number
  readonly maxPendingReceives?: number
  readonly maxRoutes?: number
  readonly maxSubscriptions?: number
  readonly maxQueuedSignals?: number
  readonly maxQueuedBytes?: number
  readonly maxReplayEntries?: number
  readonly sendTimeoutMs?: number
  readonly receiveTimeoutMs?: number
  /** Observe failed relays or partial fan-out; invalid receives still reject receive(). */
  readonly onError?: (error: Error) => void
}
export type SignalErrorCode =
  | 'signal_authorization_required'
  | 'signal_backpressure'
  | 'signal_bounds_invalid'
  | 'signal_channel_closed'
  | 'signal_clock_invalid'
  | 'signal_clock_or_sequence_exhausted'
  | 'signal_disconnected'
  | 'signal_expired'
  | 'signal_frame_invalid'
  | 'signal_frame_too_large'
  | 'signal_identity_invalid'
  | 'signal_mode_invalid'
  | 'signal_options_invalid'
  | 'signal_payload_invalid'
  | 'signal_receive_timeout'
  | 'signal_replay_limit'
  | 'signal_route_backpressure'
  | 'signal_route_closed'
  | 'signal_route_invalid'
  | 'signal_route_limit'
  | 'signal_scope_invalid'
  | 'signal_scope_mismatch'
  | 'signal_send_timeout'
  | 'signal_signature_invalid'
  | 'signal_subscription_limit'
  | 'signal_subscription_overflow'
  | 'signal_topic_filter_invalid'
  | 'signal_topic_invalid'
  | 'signal_ttl_invalid'
  | 'signal_unauthorized'

export class SignalError extends Error {
  constructor(readonly code: SignalErrorCode, message: string = code) { super(message); this.name = 'SignalError' }
}

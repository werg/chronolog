import type { HistoryPoint } from '@chronolog/peer-generation'
import type { FramedPeerConnection } from '@chronolog/records'
import type { ApplicationControlHost } from './recovery.js'

/** Untrusted delivery information. The connection must prove this exact identity. */
export interface ApplicationPeerHint {
  readonly identity: string
  readonly route: unknown
}
export interface ApplicationPeerInvitation {
  readonly peer: ApplicationPeerHint
  readonly token: unknown
  /** A bounded direct-only replacement hint; never authority. */
  readonly upgrade?: true
}
export interface ApplicationPeerAdvertisement {
  readonly identity: string
  readonly storageId: string
  readonly generation: string
  /** Durable availability is separate from a live authenticated participant. */
  readonly data: boolean
  readonly point: HistoryPoint | null
}
/** Routing invalidation only, never application state or authority. Each connection starts with ready. */
export interface ApplicationDiscoveryNotification { readonly type: 'ready' | 'changed' }
export interface ApplicationDiscoveryPort {
  /** Start before advertising. ready means the authenticated transport is connected; emit it again after reconnect.
   * Throw an error with retryable === false for terminal revocation, replacement or invalid protocol.
   * Terminal discovery fences hosted participation work without closing the application session.
   */
  notifications(options: { readonly signal: AbortSignal }): AsyncIterable<ApplicationDiscoveryNotification>
  read(options: { readonly signal: AbortSignal }): Promise<readonly ApplicationPeerHint[]>
  advertise(value: ApplicationPeerAdvertisement, options: { readonly signal: AbortSignal }): Promise<void>
  withdraw(options: { readonly signal: AbortSignal }): Promise<void>
  invitations(options: { readonly signal: AbortSignal }): AsyncIterable<ApplicationPeerInvitation>
}
export interface ApplicationTransportDescription {
  readonly kind: 'direct' | 'relay' | 'unknown'
  readonly reason?: 'direct_failed' | 'direct_timeout'
}
export interface ApplicationConnectionDiagnostic extends ApplicationTransportDescription {
  readonly peerId: string
  /** Application framing for this authenticated link, excluding encryption/socket overhead and SDP. */
  readonly sentBytes: number
  readonly receivedBytes: number
  readonly sentReliableBytes: number
  readonly receivedReliableBytes: number
  readonly sentLiveBytes: number
  readonly receivedLiveBytes: number
  readonly sentRequests: number
  readonly receivedRequests: number
}
/** Opens bytes only. Authentication, authority and recovery remain in the session. */
export interface ApplicationTransportPort {
  open(input: { readonly peer: ApplicationPeerHint; readonly invitation?: unknown }, options: { readonly signal: AbortSignal }): Promise<FramedPeerConnection>
  /** Never fall back to another relay when improving a working link. */
  upgrade?(input: { readonly peer: ApplicationPeerHint; readonly invitation?: unknown }, options: { readonly signal: AbortSignal }): Promise<FramedPeerConnection>
  /** Local routing metadata only; a selection is not authentication. */
  describe?(connection: FramedPeerConnection): ApplicationTransportDescription
}
export interface ApplicationParticipationOptions {
  readonly control: ApplicationControlHost
  readonly discovery: ApplicationDiscoveryPort
  readonly transport: ApplicationTransportPort
  readonly recovery?: {
    /** Reconnect grace before a possible selection. Defaults to 3 seconds. */
    readonly graceMs?: number
    /** Local coordinator-observation budget; never an unconditional loss bound. Defaults to 5 minutes. */
    readonly freshnessMs?: number
  }
  readonly connections?: {
    readonly maxPeers?: number
    readonly retryInitialMs?: number
    readonly retryMaxMs?: number
    readonly timeoutMs?: number
    /** Minimum between event-triggered upgrades per peer; no timer is scheduled. Defaults to 30 seconds. */
    readonly upgradeCooldownMs?: number
  }
}
export interface ApplicationRecoveryProposal {
  readonly id: string
  readonly coordinator: string
  readonly point: HistoryPoint
  readonly reason: 'freshness-unknown' | 'older-than-budget'
  readonly observedAt: number | null
  readonly ageMs: number | null
}
export interface ApplicationParticipationStatus {
  /** Local route revision; changes only when authenticated active links change. */
  readonly connectionRevision: number
  readonly phase: 'connecting' | 'connected' | 'following' | 'coordinating' | 'recovering' | 'approval-required' | 'unavailable' | 'closed'
  readonly connectedPeers: readonly string[]
  readonly recovery: ApplicationRecoveryProposal | null
  readonly error: string | null
}
export interface ApplicationParticipation {
  readonly status: ApplicationParticipationStatus
  readonly signal: AbortSignal
  onStatus(listener: (status: ApplicationParticipationStatus) => void): () => void
  /** Local authenticated link snapshot. Does not scan, synchronize or contact a host. */
  diagnostics(): Promise<readonly ApplicationConnectionDiagnostic[]>
  /** Coalesces actual network/provider changes into bounded direct-only attempts. */
  reconsiderConnections(): Promise<void>
  /** Approves only the currently displayed complete prefix; changed authority invalidates it. */
  approveRecovery(proposalId: string): Promise<void>
  close(): Promise<void>
}

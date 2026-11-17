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
}
export interface ApplicationPeerAdvertisement {
  readonly identity: string
  readonly storageId: string
  readonly generation: string
  readonly point: HistoryPoint | null
}
export interface ApplicationDiscoveryPort {
  read(options: { readonly signal: AbortSignal }): Promise<readonly ApplicationPeerHint[]>
  advertise(value: ApplicationPeerAdvertisement, options: { readonly ttlMs: number; readonly signal: AbortSignal }): Promise<void>
  withdraw(options: { readonly signal: AbortSignal }): Promise<void>
  invitations(options: { readonly signal: AbortSignal }): AsyncIterable<ApplicationPeerInvitation>
}
/** Opens bytes only. Authentication, authority and recovery remain in the session. */
export interface ApplicationTransportPort {
  open(input: { readonly peer: ApplicationPeerHint; readonly invitation?: unknown }, options: { readonly signal: AbortSignal }): Promise<FramedPeerConnection>
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
    /** Coarse discoverability lease renewal. Defaults to 60 seconds. */
    readonly advertiseMs?: number
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
  readonly phase: 'connecting' | 'following' | 'coordinating' | 'recovering' | 'approval-required' | 'unavailable' | 'closed'
  readonly connectedPeers: readonly string[]
  readonly recovery: ApplicationRecoveryProposal | null
  readonly error: string | null
}
export interface ApplicationParticipation {
  readonly status: ApplicationParticipationStatus
  readonly signal: AbortSignal
  onStatus(listener: (status: ApplicationParticipationStatus) => void): () => void
  /** Approves only the currently displayed complete prefix; changed authority invalidates it. */
  approveRecovery(proposalId: string): Promise<void>
  close(): Promise<void>
}

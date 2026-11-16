import type { RuntimeApi, RuntimeConfiguration } from '@tendriller/core/contract'
import type { ApplicationBackend } from '@tendriller/core/application'
import type { EventBatch } from '@chronolog/protocol'
import type { ApplicationOperation } from '@tendriller/core/application'
import type { RtcDataChannel, WebRtcSession } from '@chronolog/transport-webrtc'
import type { BrowserEventBootstrap, BrowserEventIdentity } from '../browser/event-contract.js'

export type PilotPeerBootstrap = Omit<BrowserEventBootstrap, 'peerUrl' | 'peerToken' | 'connection'>
export interface PilotBootstrap {
  readonly peer: PilotPeerBootstrap
  readonly teamId: string
  readonly applicationId: string
  readonly hostBase: string
}
export interface PeerIntroductionModule {
  readonly introducePeerWorker: (options: { readonly peers: RuntimeApi['peers']; readonly channel: string; readonly peerId: string;
    readonly configuration: RTCConfiguration; readonly handoff: (channel: RtcDataChannel) => void }) => Promise<WebRtcSession>
}
export interface PilotRouteStats {
  readonly route: 'webrtc'
  readonly authenticatedMs: number
  readonly sentBytes: number
  readonly receivedBytes: number
  readonly queuedBytes: number
}
export interface PilotRegistration { readonly device: string; readonly identity: BrowserEventIdentity }
export interface PilotProgress {
  readonly connected: boolean
  readonly records: number
  readonly processedRecords: number
  readonly finalOrderLength: number
  readonly materializationPending: boolean
  readonly error?: string
  readonly transportError?: string
  readonly ingest?: { readonly phase: string; readonly phaseAgeMs: number; readonly subscriptionRestarts: number; readonly retryRecords: number }
}
export interface PilotDiagnostics {
  readonly identity: string
  readonly connectionErrors: readonly string[]
  holdNextSubmission(): void
  heldSubmission(): { readonly operationId: string; readonly proposalId: string } | null
  releaseSubmission(): void
  disconnect(): Promise<void>
  reconnect(): Promise<void>
  routeStats(): Promise<readonly PilotRouteStats[]>
  progress(): Promise<PilotProgress>
  signalingStats(): readonly WebRtcSession['signaling'][]
  routeState(): Promise<{ readonly records: number; readonly recordDigest: string; readonly capabilityDigest: string; readonly finalOrderLength: number }>
  sync(): Promise<void>
  events(): Promise<EventBatch>
  operation(operationId: string): Promise<ApplicationOperation | null>
  close(): Promise<void>
}
export interface PilotWindow {
  tendril: RuntimeApi
  applicationPilot: PilotDiagnostics
}
export interface PublicKernel {
  startRuntime(configuration: RuntimeConfiguration, options?: { readonly application: ApplicationBackend }): RuntimeApi
}


import type { RuntimeApi, RuntimeConfiguration, RuntimeSocket } from '@tendriller/core/contract'
import type { ApplicationBackend } from '@tendriller/core/application'
import type { EventBatch } from '@chronolog/protocol'
import type { ApplicationOperation } from '@tendriller/core/application'
import type { BrowserEventBootstrap, BrowserEventIdentity } from '../browser/event-contract.js'

export interface PilotBootstrap {
  readonly peer: BrowserEventBootstrap
  readonly teamId: string
  readonly applicationId: string
}
export interface PilotRegistration { readonly device: string; readonly identity: BrowserEventIdentity }
export interface PilotDiagnostics {
  readonly identity: string
  readonly connectionErrors: readonly string[]
  holdNextSubmission(): void
  heldSubmission(): { readonly operationId: string; readonly proposalId: string } | null
  releaseSubmission(): void
  disconnect(): Promise<void>
  reconnect(): Promise<void>
  sync(): Promise<void>
  events(): Promise<EventBatch>
  operation(operationId: string): Promise<ApplicationOperation | null>
  close(): Promise<void>
}
export interface PilotWindow {
  tendril: RuntimeApi
  applicationPilot: PilotDiagnostics
  __TENDRIL_NO_SW__: boolean
  __TENDRIL_TRANSPORT__: (url: string) => RuntimeSocket
}
export interface PublicKernel {
  startRuntime(configuration: RuntimeConfiguration, options: { readonly application: ApplicationBackend }): RuntimeApi
}


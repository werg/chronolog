import type { ApplicationSession } from './session.js'
import type { ApplicationControlHost } from './recovery.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'

/** Versioned independently of application definitions, publications and history generations. */
export const APPLICATION_OWNER_PROTOCOL = 'chronolog/peer-session/owner/v2' as const
export type ApplicationAttachmentCapability = 'commands' | 'queries' | 'events' | 'content' | 'signals' | 'operations' | 'diagnostics' | 'ownerAdmin'
export type ApplicationEndpointState = 'active' | 'suspended' | 'detached' | 'replaced'
export interface ApplicationEndpointContext {
  readonly viewId?: string
  readonly documentPath?: string
  readonly publicationId?: string
  readonly runId?: string
}
export interface ApplicationAttachmentIdentity {
  /** Product-authenticated membership/binding references; never taken from the handshake. */
  readonly principalId?: string
  readonly agentBindingId?: string
  readonly deviceProfileId?: string
}
export interface ApplicationEndpointBinding {
  readonly identity?: ApplicationAttachmentIdentity
  readonly ownerInstanceId: string
  readonly endpointId: string
  readonly endpointIncarnation: string
  readonly context: ApplicationEndpointContext
  /** The tuple is port-bound. Authored document/run claims require separate product validation. */
  readonly evidence: 'owner-bound'
  readonly contextEvidence: 'caller-asserted' | 'owner-validated'
  readonly capabilities: readonly ApplicationAttachmentCapability[]
}
export interface ApplicationOwnerHandshake {
  readonly applicationId: string
  readonly definitionId: string
  readonly definitionVersion: string
  readonly context?: ApplicationEndpointContext
}
export interface ApplicationAttachmentPolicy {
  /** Trusted owner-side policy, never read from the client handshake. */
  readonly identity?: ApplicationAttachmentIdentity
  readonly capabilities?: readonly ApplicationAttachmentCapability[]
  readonly commands?: readonly string[]
  readonly queries?: readonly string[]
  readonly context?: ApplicationEndpointContext
  readonly contextEvidence?: 'caller-asserted' | 'owner-validated'
  /** Includes automatic diagnostics observers. Diagnostics attachments require a spare request slot. */
  readonly maxRequests?: number
  /** Status/recovery and optional participation each occupy one stream; keep a spare for application use. */
  readonly maxStreams?: number
  readonly maxViews?: number
}
export interface ApplicationOwnerOptions {
  readonly host?: ApplicationControlHost
  readonly maxAttachments?: number
  readonly maxRequests?: number
  readonly maxStreams?: number
  readonly maxViews?: number
  readonly lastClient?: 'keep-alive' | 'shutdown'
  /** Local binding authorization; this does not replace enrolled signing grants. */
  readonly authorize?: (handshake: ApplicationOwnerHandshake) => ApplicationAttachmentPolicy
  /** Product composition may validate and inject context before command preparation. */
  readonly prepareCommand?: (endpoint: ApplicationEndpointBinding, name: string, input: unknown) => unknown
}
export interface ApplicationSessionOwner {
  readonly ownerInstanceId: string
  readonly session: ApplicationSession
  /** Accept many bounded clients on a dedicated Worker or SharedWorker connection port. */
  attach(endpoint: ApplicationWorkerEndpoint & { start?(): void }, policy?: ApplicationAttachmentPolicy): () => void
  endpoints(): readonly (ApplicationEndpointBinding & { readonly state: ApplicationEndpointState })[]
  /** Owner shutdown, unlike closing/detaching an individual facade. */
  close(): Promise<void>
}
export const APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES: readonly ApplicationAttachmentCapability[] = Object.freeze([
  'commands', 'queries', 'events', 'content', 'signals', 'operations', 'diagnostics',
])

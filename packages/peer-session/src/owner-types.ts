import type { ApplicationSession } from './session.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
export { APPLICATION_OWNER_PROTOCOL } from './worker-application-protocol.js'
export type ApplicationAttachmentCapability = 'commands' | 'queries' | 'events' | 'content' | 'signals' | 'operations' | 'diagnostics' | 'admission' | 'extensions' | 'replication'
export interface ApplicationEndpointContext { readonly viewId?: string; readonly documentPath?: string; readonly publicationId?: string; readonly runId?: string }
export interface ApplicationAttachmentIdentity { readonly principalId?: string; readonly agentBindingId?: string; readonly deviceProfileId?: string }
export interface ApplicationEndpointBinding { readonly identity?: ApplicationAttachmentIdentity; readonly ownerInstanceId: string; readonly endpointId: string; readonly endpointIncarnation: string; readonly context: ApplicationEndpointContext; readonly evidence: 'owner-bound'; readonly contextEvidence: 'caller-asserted' | 'owner-validated'; readonly capabilities: readonly ApplicationAttachmentCapability[] }
export interface ApplicationAttachmentPolicy { readonly identity?: ApplicationAttachmentIdentity; readonly contextEvidence?: 'caller-asserted' | 'owner-validated'; readonly capabilities?: readonly ApplicationAttachmentCapability[]; readonly commands?: readonly string[]; readonly queries?: readonly string[]; readonly rawSubmit?: boolean; readonly rawSql?: boolean; readonly maxRequests?: number; readonly maxViews?: number; readonly context?: ApplicationEndpointContext }
/**
 * Owner-local named actions and notices composed by the host application (for example
 * device admission). They run beside the session inside the owner; attachments call
 * them only with the `extensions` capability and never receive owner key material.
 */
export interface ApplicationOwnerExtensions { call(name: string, args: readonly unknown[], context: { readonly endpoint: ApplicationEndpointBinding; readonly signal: AbortSignal }): Promise<unknown>; subscribe?(listener: (value: unknown) => void): () => void }
export interface ApplicationOwnerOptions { readonly extensions?: ApplicationOwnerExtensions; readonly maxAttachments?: number; readonly lastClient?: 'keep-alive' | 'shutdown'; readonly inactivityTimeoutMs?: number | null; readonly authorize?: (handshake: { readonly applicationId: string; readonly context?: ApplicationEndpointContext }) => ApplicationAttachmentPolicy; readonly prepareCommand?: (endpoint: ApplicationEndpointBinding, name: string, input: unknown) => unknown }
export interface ApplicationSessionOwner { readonly ownerInstanceId: string; readonly session: ApplicationSession; attach(endpoint: ApplicationWorkerEndpoint & { start?(): void }, policy?: ApplicationAttachmentPolicy): () => void; endpoints(): readonly (ApplicationEndpointBinding & { readonly state: 'active' | 'suspended' })[]; close(): Promise<void> }
export const APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES: readonly ApplicationAttachmentCapability[] = ['commands', 'queries', 'events', 'content', 'signals', 'operations', 'diagnostics', 'admission', 'extensions', 'replication']

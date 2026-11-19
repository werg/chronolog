import type { ApplicationSession } from './session.js'
import { serveApplicationWorker } from './worker-application-server.js'
import { bounded, type Endpoint } from './worker-application-protocol.js'
import { APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES, APPLICATION_OWNER_PROTOCOL,
  type ApplicationAttachmentCapability, type ApplicationAttachmentPolicy, type ApplicationEndpointBinding,
  type ApplicationEndpointContext, type ApplicationEndpointState, type ApplicationOwnerHandshake,
  type ApplicationOwnerOptions, type ApplicationSessionOwner } from './owner-types.js'
export * from './owner-types.js'

const owners = new WeakMap<ApplicationSession, ApplicationSessionOwner>()
const CAPABILITIES = [...APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES, 'ownerAdmin']
const LIMITS = { requests: 512, streams: 256, views: 128 } as const

/** One protocol/session/journal owner, with isolated attachment lifetimes and quotas. */
export function createApplicationOwner(session: ApplicationSession, options: ApplicationOwnerOptions = {}): ApplicationSessionOwner {
  session.signal.throwIfAborted()
  if (owners.has(session)) throw new Error('OWNER_BUSY')
  const ownerInstanceId = crypto.randomUUID(), maxAttachments = limit(options.maxAttachments, 32, 128)
  const bounds = { requests: limit(options.maxRequests, LIMITS.requests, 4096), streams: limit(options.maxStreams, LIMITS.streams, 1024), views: limit(options.maxViews, LIMITS.views, 1024) }
  const used = { requests: 0, streams: 0, views: 0 }
  const attachments = new Map<string, { binding: ApplicationEndpointBinding; state: ApplicationEndpointState; close(): Promise<void> }>()
  const listeners = new Set<() => void>()
  let closing: Promise<void> | undefined, closed = false
  const reserve = (kind: keyof typeof used): (() => void) => {
    if (closed) throw new Error('OWNER_UNREACHABLE')
    if (used[kind] >= bounds[kind]) throw Object.assign(new Error('OWNER_BUSY'), { code: 'OWNER_BUSY' })
    used[kind]++
    let released = false
    return () => { if (!released) { released = true; used[kind]-- } }
  }
  const owner: ApplicationSessionOwner = {
    ownerInstanceId, session,
    attach(endpoint: Endpoint, fixed: ApplicationAttachmentPolicy = {}) {
      if (closed) throw new Error('OWNER_UNREACHABLE')
      validatePolicy(fixed)
      const owned = new Set<string>()
      let detached = false
      const receive = (event: MessageEvent): void => {
        const frame = event.data as { protocol?: unknown; port?: MessagePort; handshake?: unknown } | null
        if (typeof frame?.protocol !== 'string' || !frame.protocol.startsWith('chronolog/peer-session/')) return
        const port = frame.port
        if (port === undefined || typeof port.postMessage !== 'function' || typeof port.close !== 'function') return
        try {
          if (closed || detached) throw new Error('OWNER_UNREACHABLE')
          if (frame.protocol !== APPLICATION_OWNER_PROTOCOL) throw new Error('CONTRACT_INCOMPATIBLE')
          bounded(frame.handshake)
          const handshake = validateHandshake(frame.handshake)
          const description = session.describe()
          if (handshake.applicationId !== session.applicationId || handshake.definitionId !== description.id || handshake.definitionVersion !== description.version) throw new Error('CONTRACT_INCOMPATIBLE')
          if (attachments.size >= maxAttachments) throw new Error('APPLICATION_OWNER_ATTACHMENT_LIMIT')
          const approved = options.authorize?.(structuredClone(handshake)) ?? {}
          validatePolicy(approved)
          const policy = mergePolicy(fixed, approved)
          // The page automatically holds status and recovery observers, plus
          // participation when present. Each uses one stream and a passive
          // stream.next request. Reject incompatible owner-side limits before
          // publishing a ready facade instead of accepting one that immediately
          // closes when its built-in observers hit a quota.
          if ((policy.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES).includes('diagnostics')) {
            const observers = session.participation === undefined ? 2 : 3
            if ((policy.maxStreams ?? 8) <= observers || (policy.maxRequests ?? 16) <= observers ||
                bounds.streams <= observers || bounds.requests <= observers) throw new Error('APPLICATION_ATTACHMENT_OBSERVER_LIMIT')
          }
          const claimedContext = checkedContext(policy.context ?? handshake.context ?? {})
          // A duplicate tab can copy its storage; it cannot acquire another live view's drafts.
          const requestedView = claimedContext.viewId
          const viewId = requestedView !== undefined && ![...attachments.values()].some(value => value.binding.context.viewId === requestedView)
            ? requestedView : crypto.randomUUID()
          const binding: ApplicationEndpointBinding = Object.freeze({ ownerInstanceId, endpointId: crypto.randomUUID(), endpointIncarnation: crypto.randomUUID(),
            context: Object.freeze({ ...claimedContext, viewId }), ...(policy.identity === undefined ? {} : { identity: Object.freeze(structuredClone(policy.identity)) }), evidence: 'owner-bound', contextEvidence: policy.contextEvidence ?? 'caller-asserted',
            capabilities: Object.freeze([...(policy.capabilities ?? APPLICATION_DEFAULT_ATTACHMENT_CAPABILITIES)]) })
          const record = { binding, state: 'active' as ApplicationEndpointState, close: async (): Promise<void> => undefined }
          attachments.set(binding.endpointId, record); owned.add(binding.endpointId)
          const server = serveApplicationWorker(session, endpoint, { ...policy, ...(options.host === undefined ? {} : { host: options.host }),
            capabilities: binding.capabilities, closeSession: false, initialPort: port, binding, reserve,
            maxRequests: limit(policy.maxRequests, 16, 64), maxStreams: limit(policy.maxStreams, 8, 16), maxViews: limit(policy.maxViews, 8, 32),
            ...(options.prepareCommand === undefined ? {} : { prepareCommand: options.prepareCommand }),
            listEndpoints: () => owner.endpoints(), shutdown: () => owner.close(),
            onState(state) { record.state = state },
            onClose() {
              record.state = 'detached'; attachments.delete(binding.endpointId); owned.delete(binding.endpointId)
              if (!closed && attachments.size === 0 && options.lastClient === 'shutdown') void owner.close().catch(() => undefined)
            },
          })
          record.close = () => server.close()
        } catch (error) {
          const code = error instanceof Error ? error.message : 'APPLICATION_OWNER_HANDSHAKE_INVALID'
          try { port.postMessage({ ended: { name: 'Error', message: code, code } }) } finally { port.close() }
        }
      }
      const detach = (): void => {
        if (detached) return
        detached = true; endpoint.removeEventListener('message', receive); listeners.delete(detach)
        for (const id of owned) void attachments.get(id)?.close().catch(() => undefined)
      }
      endpoint.addEventListener('message', receive); endpoint.start?.(); listeners.add(detach)
      return detach
    },
    endpoints: () => [...attachments.values()].map(({ binding, state }) => ({ ...structuredClone(binding), state })),
    close() {
      if (closing !== undefined) return closing
      closed = true; session.signal.removeEventListener('abort', abort)
      const pending = [...attachments.values()].map(value => value.close())
      for (const detach of [...listeners]) detach()
      closing = Promise.allSettled(pending).then(async () => { try { await session.close() } finally { owners.delete(session) } })
      return closing
    },
  }
  const abort = (): void => { void owner.close().catch(() => undefined) }
  session.signal.addEventListener('abort', abort, { once: true }); owners.set(session, owner)
  if (session.signal.aborted) abort()
  return owner
}

function limit(value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) throw new Error('APPLICATION_OWNER_LIMIT_INVALID')
  return result
}
function checkedContext(value: ApplicationEndpointContext): ApplicationEndpointContext {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.entries(value).some(([key, item]) =>
      !['viewId', 'documentPath', 'publicationId', 'runId'].includes(key) || typeof item !== 'string' || item.length === 0 || item.length > (key === 'documentPath' ? 1024 : 128) || [...item].some(character => character.charCodeAt(0) < 32))) throw new Error('APPLICATION_ENDPOINT_CONTEXT_INVALID')
  return structuredClone(value)
}
function validateHandshake(value: unknown): ApplicationOwnerHandshake {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('APPLICATION_OWNER_HANDSHAKE_INVALID')
  const input = value as ApplicationOwnerHandshake
  if (Object.keys(input).some(key => !['applicationId', 'definitionId', 'definitionVersion', 'context'].includes(key)) ||
      !/^[0-9a-f]{64}$/u.test(input.applicationId) || typeof input.definitionId !== 'string' || typeof input.definitionVersion !== 'string' ||
      input.definitionId.length > 128 || input.definitionVersion.length > 128) throw new Error('APPLICATION_OWNER_HANDSHAKE_INVALID')
  if (input.context !== undefined) checkedContext(input.context)
  return input
}
function validatePolicy(policy: ApplicationAttachmentPolicy): void {
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy) ||
      policy.capabilities !== undefined && (!Array.isArray(policy.capabilities) || policy.capabilities.some((value: unknown) => typeof value !== 'string' || !CAPABILITIES.includes(value))) ||
      [policy.commands, policy.queries].some(values => values !== undefined && (!Array.isArray(values) || values.length > 128 || values.some(value => typeof value !== 'string' || value.length > 128))) ||
      policy.contextEvidence !== undefined && !['caller-asserted', 'owner-validated'].includes(policy.contextEvidence)) throw new Error('APPLICATION_ATTACHMENT_POLICY_INVALID')
  if (policy.identity !== undefined && (policy.identity === null || typeof policy.identity !== 'object' || Array.isArray(policy.identity) || Object.entries(policy.identity).some(([key, value]) => !['principalId', 'agentBindingId', 'deviceProfileId'].includes(key) || typeof value !== 'string' || value.length === 0 || value.length > 128))) throw new Error('APPLICATION_ATTACHMENT_IDENTITY_INVALID')
  if (policy.context !== undefined) checkedContext(policy.context)
  limit(policy.maxRequests, 16, 64); limit(policy.maxStreams, 8, 16); limit(policy.maxViews, 8, 32)
}
function mergePolicy(a: ApplicationAttachmentPolicy, b: ApplicationAttachmentPolicy): ApplicationAttachmentPolicy {
  const intersection = <T>(left: readonly T[] | undefined, right: readonly T[] | undefined): readonly T[] | undefined =>
    left === undefined ? right : right === undefined ? left : left.filter(value => right.includes(value))
  const capabilities = intersection<ApplicationAttachmentCapability>(a.capabilities, b.capabilities), commands = intersection(a.commands, b.commands), queries = intersection(a.queries, b.queries)
  return { ...a, ...b, ...(capabilities === undefined ? {} : { capabilities }), ...(commands === undefined ? {} : { commands }), ...(queries === undefined ? {} : { queries }),
    maxRequests: Math.min(a.maxRequests ?? 16, b.maxRequests ?? 16), maxStreams: Math.min(a.maxStreams ?? 8, b.maxStreams ?? 8), maxViews: Math.min(a.maxViews ?? 8, b.maxViews ?? 8) }
}

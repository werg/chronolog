import type { PeerReplica, PeerStore } from '@chronolog/peer-generation'
import type { SignalChannel } from '@chronolog/signals'
import type { ApplicationSession } from './session.js'
import type { ApplicationContent } from './content.js'
import type { ApplicationKeyring } from './keys.js'

export const sessionInternals = new WeakMap<ApplicationSession, { readonly replica: PeerReplica; readonly signals: SignalChannel; readonly store: PeerStore; readonly content: ApplicationContent; readonly keys: ApplicationKeyring }>()

interface ResourceOwner { readonly signal: AbortSignal }
interface SessionResource { close(): void | Promise<void> }
const resources = new WeakMap<ResourceOwner, { closing: boolean; task?: Promise<void>; values: Set<SessionResource> }>()

/** Internal ownership, shared by native sessions and their page-side Worker facades. */
export function ownSessionResource(owner: ResourceOwner, resource: SessionResource): () => void {
  owner.signal.throwIfAborted()
  const state = resources.get(owner) ?? { closing: false, values: new Set<SessionResource>() }
  if (state.closing) throw new Error('APPLICATION_SESSION_CLOSED')
  state.values.add(resource); resources.set(owner, state)
  return () => { state.values.delete(resource) }
}

/** Storage stays open until every registered owner has settled its active work. */
export function closeSessionResources(owner: ResourceOwner): Promise<void> {
  const state = resources.get(owner) ?? { closing: false, values: new Set<SessionResource>() }
  resources.set(owner, state); state.closing = true
  state.task ??= (async () => {
    const results = await Promise.allSettled([...state.values].map(resource => Promise.resolve().then(() => resource.close())))
    state.values.clear()
    const failures = results.flatMap(result => result.status === 'rejected' ? [result.reason as unknown] : [])
    if (failures.length !== 0) throw new AggregateError(failures, 'APPLICATION_RESOURCE_CLOSE_FAILED')
  })()
  return state.task
}

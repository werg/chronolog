import type { BytesStore } from '@chronolog/records'
import type { ChronologMaterializationRuntime } from '@chronolog/materializer'
import type { AuthorityProvider, AuthorityBundle } from '@chronolog/authority'
import { createAuthorityProvider } from '@chronolog/authority'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import type { ApplicationDefinition } from './definition.js'
import { ApplicationSession } from './session.js'
export interface CreateApplicationSessionOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly authority?: AuthorityProvider | AuthorityBundle
  readonly applicationId?: string
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  readonly createMaterializer?: (options: { readonly signal: AbortSignal; readonly rootPrincipal: Uint8Array; readonly store: BytesStore }) => ChronologMaterializationRuntime | Promise<ChronologMaterializationRuntime>
  readonly maxOperations?: number
  readonly maxHistoryBytes?: number
}
/** Opens cached authority/identity first, without host discovery or transport. */
export async function createApplicationSession<const D extends ApplicationDefinition>(options: CreateApplicationSessionOptions<D>): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  try {
    const authority = options.authority !== undefined && 'grant' in options.authority ? options.authority : await createAuthorityProvider({ store: options.device.store, ...(options.authority === undefined ? {} : { bundle: options.authority }), ...(options.applicationId === undefined ? {} : { applicationId: options.applicationId }), ...(options.epochKeys === undefined ? {} : { epochKeys: options.epochKeys }) })
    if (options.epochKeys !== undefined) for (const [epoch, key] of options.epochKeys) await authority.installEpochKey(epoch, key)
    const storage = await options.device.openStorage()
    return await ApplicationSession.open({ ...options, authority, store: storage.store, async release() { release(); await options.device.close() } })
  } catch (error) { release(); await options.device.close(); throw error }
}

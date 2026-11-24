import type { AuthorityBundle } from '@chronolog/peer-generation/control'
import type { SignalLimits } from '@chronolog/signals'
import type { ChronologMaterializationRuntime } from '@chronolog/materializer'
import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { ApplicationSession } from './session.js'
import { retainApplicationAuthority } from './session-authority.js'

export interface OpenPeerApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly authority: AuthorityBundle
  /** Optional explicit bootstrap. Enrolled keys persist when the durable facet opens. */
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  /** Invoked only on durable demand. Import the SQL implementation inside this factory. */
  readonly createMaterializer?: (options: { readonly signal: AbortSignal }) => ChronologMaterializationRuntime | Promise<ChronologMaterializationRuntime>
  /** Explicit live reach. Application mode forwards signed frames with bounded replay protection. */
  readonly signals?: { readonly delivery?: 'neighbors' | 'application'; readonly localEcho?: boolean; readonly limits?: SignalLimits }
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}

/** Start the protocol participant; database code and storage remain unopened. */
export async function openPeerApplication<const D extends ApplicationDefinition>(options: OpenPeerApplicationOptions<D>): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  try {
    const requiresSql = options.definition.schema !== undefined || options.authority.descriptor.payload.schemaDigest !== null
    if (requiresSql && options.createMaterializer === undefined) throw new Error('APPLICATION_SCHEMA_REQUIRES_SQL')
    const authority = await retainApplicationAuthority(options.device, options.authority)
    if (await applicationDefinitionDigest(options.definition) !== authority.currentDefinitionDigest) throw new Error('APPLICATION_DEFINITION_MISMATCH')
    if (authority.current === null) throw new Error('PEER_NO_SELECTED_GENERATION')
    const captured = { ...options, ...(options.epochKeys === undefined ? {} : {
      epochKeys: new Map([...options.epochKeys].map(([epoch, key]) => [epoch, key.slice()])) }) }
    return new ApplicationSession(captured, authority, async () => { release(); await options.device.close() })
  } catch (error) { release(); await options.device.close(); throw error }
}

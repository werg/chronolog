import { createPeerReplica, type AuthorityBundle, type PeerReplicaOptions } from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'

import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { openApplication, type ApplicationSession } from './session.js'
import { ApplicationContent } from './content.js'

export interface OpenPeerApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly authority: AuthorityBundle
  readonly epochKeys: ReadonlyMap<number, Uint8Array>
  /** Called after claiming the device; the session owns the returned runtime. Events need no factory. */
  readonly createMaterializer?: () => ChronologMaterializationRuntime | Promise<ChronologMaterializationRuntime>
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}

export async function openPeerApplication<const D extends ApplicationDefinition>(options: OpenPeerApplicationOptions<D>): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  let materializer: ChronologMaterializationRuntime | undefined
  try {
    if (await applicationDefinitionDigest(options.definition) !== options.authority.descriptor.payload.definitionDigest) throw new Error('APPLICATION_DEFINITION_MISMATCH')
    materializer = options.createMaterializer === undefined ? await createEventMaterializationRuntime({ store: options.device.store,
      namespace: options.authority.descriptor.payload.historyId, historyProfile: 'peer-generation-v1',
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }) : await options.createMaterializer()
    const input: PeerReplicaOptions = { authority: options.authority, device: options.device.identity,
      store: options.device.store, storageId: options.device.storageId, epochKeys: options.epochKeys, materializer,
      ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }
    const replica = await createPeerReplica(input)
    const content = new ApplicationContent({ replica, store: options.device.store, storageId: options.device.storageId, epochKeys: options.epochKeys })
    return await openApplication({ replica, definition: options.definition, store: options.device.store, content,
      close: async () => { release(); await options.device.close() } })
  } catch (error) {
    release(); await materializer?.close(); await options.device.close(); throw error
  }
}

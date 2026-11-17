import { createPeerReplica, type AuthorityBundle, type PeerReplicaOptions } from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'

import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { openApplication, type ApplicationSession } from './session.js'

export interface OpenPeerApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly authority: AuthorityBundle
  readonly epochKeys: ReadonlyMap<number, Uint8Array>
  /** The events path needs no SQL/WASM. SQL runtimes supply the verified engine here. */
  readonly materializer?: ChronologMaterializationRuntime
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}

export async function openPeerApplication<const D extends ApplicationDefinition>(options: OpenPeerApplicationOptions<D>): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  let materializer: ChronologMaterializationRuntime | undefined
  try {
    if (await applicationDefinitionDigest(options.definition) !== options.authority.descriptor.payload.definitionDigest) throw new Error('APPLICATION_DEFINITION_MISMATCH')
    materializer = options.materializer ?? await createEventMaterializationRuntime({ store: options.device.store,
      namespace: options.authority.descriptor.payload.historyId, historyProfile: 'peer-generation-v1',
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) })
    const input: PeerReplicaOptions = { authority: options.authority, device: options.device.identity,
      store: options.device.store, storageId: options.device.storageId, epochKeys: options.epochKeys, materializer,
      ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }
    const replica = await createPeerReplica(input)
    return await openApplication({ replica, definition: options.definition,
      close: async () => { release(); await options.device.close() } })
  } catch (error) {
    release(); await materializer?.close(); await options.device.close(); throw error
  }
}

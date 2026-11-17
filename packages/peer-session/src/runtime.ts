import { createPeerReplica, type AuthorityBundle, type PeerReplica, type PeerReplicaOptions } from '@chronolog/peer-generation'
import { createEventMaterializationRuntime, type ChronologMaterializationRuntime } from '@chronolog/materializer'

import { applicationDefinitionDigest, type ApplicationDefinition } from './definition.js'
import { claimApplicationDevice, type ApplicationDevice } from './device.js'
import { openApplication, type ApplicationSession } from './session.js'
import { ApplicationContent } from './content.js'
import { ApplicationKeyring } from './keys.js'

export interface OpenPeerApplicationOptions<D extends ApplicationDefinition = ApplicationDefinition> {
  readonly device: ApplicationDevice
  readonly definition: D
  readonly authority: AuthorityBundle
  /** Optional explicit bootstrap. Enrolled keys persist; new readers acquire wrapped keys from peers. */
  readonly epochKeys?: ReadonlyMap<number, Uint8Array>
  /** Called after claiming the device; the session owns the returned runtime. Events need no factory. */
  readonly createMaterializer?: () => ChronologMaterializationRuntime | Promise<ChronologMaterializationRuntime>
  readonly maxRecords?: number
  readonly maxHistoryBytes?: number
}

export async function openPeerApplication<const D extends ApplicationDefinition>(options: OpenPeerApplicationOptions<D>): Promise<ApplicationSession<D>> {
  const release = claimApplicationDevice(options.device)
  let materializer: ChronologMaterializationRuntime | undefined
  let replica: PeerReplica | undefined, keys: ApplicationKeyring | undefined
  try {
    if (await applicationDefinitionDigest(options.definition) !== options.authority.descriptor.payload.definitionDigest) throw new Error('APPLICATION_DEFINITION_MISMATCH')
    keys = await ApplicationKeyring.open({ device: options.device, authority: options.authority,
      ...(options.epochKeys === undefined ? {} : { epochKeys: options.epochKeys }) })
    materializer = options.createMaterializer === undefined ? await createEventMaterializationRuntime({ store: options.device.store,
      namespace: options.authority.descriptor.payload.historyId, historyProfile: 'peer-generation-v1',
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }) : await options.createMaterializer()
    const input: PeerReplicaOptions = { authority: options.authority, device: options.device.identity,
      store: options.device.store, storageId: options.device.storageId, epochKeys: keys.epochKeys, materializer,
      ...(options.maxRecords === undefined ? {} : { maxRecords: options.maxRecords }),
      ...(options.maxHistoryBytes === undefined ? {} : { maxHistoryBytes: options.maxHistoryBytes }) }
    replica = await createPeerReplica(input); keys.bind(replica); await keys.validate()
    const keyring = keys
    const content = new ApplicationContent({ replica, store: options.device.store, storageId: options.device.storageId,
      epochKeys: keyring.epochKeys, acquireKey: epoch => keyring.ensure([epoch]) })
    return await openApplication({ replica, definition: options.definition, store: options.device.store, content, keys,
      close: async () => { keys?.close(); release(); await options.device.close() } })
  } catch (error) {
    keys?.close(); release(); if (replica !== undefined) await replica.close(); else await materializer?.close()
    await options.device.close(); throw error
  }
}

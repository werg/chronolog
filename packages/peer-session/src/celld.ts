import { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'

import { openApplicationDevice, type ApplicationDevice } from './device.js'

export { openPeerApplication as openCelldApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { openCelldApplicationControl, type CelldApplicationControl } from './celld-control.js'
export {
  createCelldPeerTransport, frameCelldPeerStream,
  type CelldPeerBinding, type CelldPeerEndpoint, type CelldPeerStream,
} from './celld-peer.js'
export { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'

/** Open one device under its celld object, optionally using a SQLite facet for application data. */
export async function openCelldDevice(options: {
  readonly storage: CelldBytesStorage
  readonly create?: true
  readonly metadataLimits?: CelldBytesStoreOptions
  readonly dataLimits?: CelldBytesStoreOptions
  readonly openDataStorage?: () => CelldBytesStorage
}): Promise<ApplicationDevice> {
  const store = new CelldBytesStore(options.storage, options.metadataLimits)
  const openDataStorage = options.openDataStorage
  try {
    return await openApplicationDevice({
      store,
      ...(options.create === undefined ? {} : { create: options.create }),
      ...(openDataStorage === undefined ? {} : {
        openStorage: () => {
          const data = new CelldBytesStore(openDataStorage(), options.dataLimits)
          return { store: data, close: () => data.close() }
        },
      }),
      close: () => store.close(),
    })
  } catch (error) {
    store.close()
    throw error
  }
}

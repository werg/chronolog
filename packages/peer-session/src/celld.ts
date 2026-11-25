import { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'
import type { SigningIdentity } from '@chronolog/authority'
import { hexToBytes, importEd25519PrivateKey } from '@chronolog/protocol'
import { openApplicationDevice, verifyDeviceSigner, type ApplicationDevice } from './device.js'
export { CelldBytesStore, CelldPrivateBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions, type CelldPrivateBytesStorage } from '@chronolog/records/celld'
export { createApplicationSession } from './index.js'
/** Import a per-class secret against the public key admitted by the host. */
export async function importCelldSigningIdentity(publicKey: string, pkcs8Hex: string | undefined): Promise<SigningIdentity> {
  if (pkcs8Hex === undefined) throw new Error('CELLD_SIGNING_SECRET_MISSING')
  if (pkcs8Hex.length < 2 || pkcs8Hex.length > 512 || !/^(?:[0-9a-f]{2})+$/u.test(pkcs8Hex)) {
    throw new Error('CELLD_SIGNING_SECRET_INVALID')
  }
  const bytes = hexToBytes(pkcs8Hex)
  try {
    const privateKey = await importEd25519PrivateKey(bytes, false)
    const identity = { publicKey, privateKey }
    await verifyDeviceSigner(identity)
    return Object.freeze(identity)
  } catch {
    throw new Error('CELLD_SIGNING_SECRET_INVALID')
  } finally {
    bytes.fill(0)
  }
}

/** Open one device under its celld object, optionally using a SQLite facet for application data. */
export async function openCelldDevice(options: {
  readonly storage: CelldBytesStorage
  readonly create?: true
  readonly managedSigner?: SigningIdentity
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
      ...(options.managedSigner === undefined ? {} : { managedSigner: options.managedSigner }),
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

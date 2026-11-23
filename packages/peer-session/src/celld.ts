import { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'
import type { PeerIdentity } from '@chronolog/peer-generation/control'
import { hexToBytes, importEd25519PrivateKey } from '@chronolog/protocol'

import { openApplicationDevice, verifyDeviceSigner, type ApplicationDevice } from './device.js'

export { openPeerApplication as openCelldApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { openCelldApplicationControl, type CelldApplicationControl } from './celld-control.js'
export {
  createCelldPeerTransport, frameCelldPeerStream,
  type CelldPeerBinding, type CelldPeerEndpoint, type CelldPeerStream,
} from './celld-peer.js'
export {
  acceptCelldApplicationInvitation, signCelldApplicationInvitation,
  type CelldApplicationInvitation, type AcceptedCelldApplicationInvitation,
} from './celld-invitation.js'
export {
  signCelldWorkspacePublication, verifyCelldWorkspacePublication,
  type CelldWorkspacePublication, type SignedCelldWorkspacePublication,
} from './celld-workspace-publication.js'
export { CelldBytesStore, type CelldBytesStorage, type CelldBytesStoreOptions } from '@chronolog/records/celld'

/** Import a per-class secret against the public key admitted by the host. */
export async function importCelldSigningIdentity(publicKey: string, pkcs8Hex: string | undefined): Promise<PeerIdentity> {
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
  readonly managedSigner?: PeerIdentity
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

export {
  celldDoltPublicationPeer, serveCelldDoltPublication, type CelldDoltPublicationGrant,
} from './celld-dolt-carrier.js'

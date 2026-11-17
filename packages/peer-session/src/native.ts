import { NativeBytesStore, type NativeBytesStoreOptions } from '@chronolog/records/native'

import { openApplicationDevice, type ApplicationDevice } from './device.js'
export { openPeerApplication as openNativeApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { NativeBytesStore } from '@chronolog/records/native'

/** The SQLite file is the exclusive signer/history owner; a second process receives a busy error. */
export async function openNativeDevice(options: {
  readonly path: string
  readonly create?: true
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}): Promise<ApplicationDevice> {
  const limits: NativeBytesStoreOptions = {
    ...(options.quotaBytes === undefined ? {} : { quotaBytes: options.quotaBytes }),
    ...(options.maxValueBytes === undefined ? {} : { maxValueBytes: options.maxValueBytes }),
  }
  const store = new NativeBytesStore(options.path, limits)
  try { return await openApplicationDevice({ store, ...(options.create === undefined ? {} : { create: options.create }), close: () => store.close() }) }
  catch (error) { store.close(); throw error }
}

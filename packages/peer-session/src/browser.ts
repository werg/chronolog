import { acquireBrowserStorage } from '@chronolog/records/browser'

import { openApplicationDevice, type ApplicationDevice } from './device.js'
export { openPeerApplication as openBrowserApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { serveApplicationWorker, connectApplicationWorker, WorkerApplicationSession, type WorkerApplicationReadView } from './worker-application.js'

/** Open in the owning Worker. Missing storage capabilities and second-tab ownership fail explicitly. */
export async function openBrowserDevice(options: { readonly name: string; readonly create?: true }): Promise<ApplicationDevice> {
  if (typeof document !== 'undefined') throw new Error('BROWSER_PEER_WORKER_REQUIRED')
  const owner = await acquireBrowserStorage(options.name)
  try { return await openApplicationDevice({ store: owner.bytes, ...(options.create === undefined ? {} : { create: options.create }), close: () => owner.close() }) }
  catch (error) { await owner.close(); throw error }
}

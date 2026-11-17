import { BrowserMetadataStore } from './browser-metadata.js'
import { openApplicationDevice, type ApplicationDevice } from './device.js'

/** Open the protocol identity in its Worker; application files remain unopened. */
export async function openBrowserDevice(options: { readonly name: string; readonly create?: true }): Promise<ApplicationDevice> {
  if (typeof document !== 'undefined') throw new Error('BROWSER_PEER_WORKER_REQUIRED')
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(options.name)) throw new Error('BROWSER_STORAGE_NAME_INVALID')
  const metadata = await BrowserMetadataStore.open(options.name)
  try {
    return await openApplicationDevice({ store: metadata,
      ...(options.create === undefined ? {} : { create: options.create }),
      async openStorage() {
        const { acquireBrowserStorage } = await import('@chronolog/records/browser')
        const owner = await acquireBrowserStorage(options.name)
        return { store: owner.bytes, close: () => owner.close() }
      },
      close: () => { metadata.close() },
    })
  } catch (error) { metadata.close(); throw error }
}

import { BrowserMetadataStore } from './browser-metadata.js'
import { openApplicationDevice, type ApplicationDevice } from './device.js'

/** Open the protocol identity in its Worker; uses multi-tab lock-free IndexedDB storage. */
export async function openBrowserDevice(options: { readonly name: string; readonly create?: true }): Promise<ApplicationDevice> {
  if (typeof document !== 'undefined') throw new Error('BROWSER_PEER_WORKER_REQUIRED')
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(options.name)) throw new Error('BROWSER_STORAGE_NAME_INVALID')
  const metadata = await BrowserMetadataStore.open(options.name)
  try {
    return await openApplicationDevice({
      store: metadata,
      ...(options.create === undefined ? {} : { create: options.create }),
      async openStorage() {
        const { IndexedDbBytesStore } = await import('@chronolog/records/indexeddb-browser')
        const store = await IndexedDbBytesStore.open(options.name, { create: true })
        return {
          store,
          close: () => store.close(),
        }
      },
      close: () => { metadata.close() },
    })
  } catch (error) { metadata.close(); throw error }
}

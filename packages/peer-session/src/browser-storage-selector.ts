import { assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/protocol'
import { acquireBrowserStorageLock, inspectLegacyOpfsDirectory, OpfsBytesStore, probeOpfsWritable } from '@chronolog/records/browser'
import { IndexedDbBytesStore, probeIndexedDbBytesStore } from '@chronolog/records/indexeddb-browser'
import type { ApplicationStorage } from './device.js'
import type { BrowserMetadataStore } from './browser-metadata.js'

const BACKEND_PIN = 'peer-session/storage-backend/v1'
const STORAGE_OPENED = 'peer-session/storage-opened/v1'
type RecordBackend = 'opfs' | 'indexeddb'

function decodePin(bytes: Uint8Array): RecordBackend {
  let value: unknown
  try { value = assertCanonicalCbor(bytes) } catch { throw new Error('BROWSER_STORAGE_BACKEND_PIN_INVALID') }
  if (!Array.isArray(value) || value.length !== 2 || value[0] !== 1n ||
      (value[1] !== 'opfs' && value[1] !== 'indexeddb')) throw new Error('BROWSER_STORAGE_BACKEND_PIN_INVALID')
  return value[1] as RecordBackend
}

/** Select once under the same exclusive lock that owns every subsequent record write. */
export async function openSelectedBrowserStorage(name: string, metadata: BrowserMetadataStore): Promise<ApplicationStorage> {
  // Preserve the legacy unsupported-OPFS error before Web Lock contention for
  // pinned OPFS devices. This is a read-only preflight, not backend selection:
  // the pin is re-read authoritatively after taking the exclusive lock.
  if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) {
    const preflightPin = await metadata.get(BACKEND_PIN)
    if (preflightPin !== null && decodePin(preflightPin) === 'opfs') {
      throw new Error('BROWSER_DURABLE_STORAGE_UNAVAILABLE')
    }
  }
  const lock = await acquireBrowserStorageLock(name)
  try {
    let root: FileSystemDirectoryHandle | undefined
    const opfsRoot = async (): Promise<FileSystemDirectoryHandle> => {
      if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) {
        throw new Error('BROWSER_DURABLE_STORAGE_UNAVAILABLE')
      }
      return root ??= await navigator.storage.getDirectory()
    }
    const opened = await metadata.get(STORAGE_OPENED)
    const oldPin = await metadata.get(BACKEND_PIN)
    let backend: RecordBackend
    if (oldPin !== null) backend = decodePin(oldPin)
    else {
      // An opened old device, or any pre-upgrade app directory including one
      // abandoned before STORAGE_OPENED, must never be redirected to empty IDB.
      let candidate: RecordBackend
      if (opened !== null || await inspectLegacyOpfsDirectory(name, await opfsRoot())) candidate = 'opfs'
      else if (await probeOpfsWritable(await opfsRoot())) candidate = 'opfs'
      else if (await probeIndexedDbBytesStore()) candidate = 'indexeddb'
      else throw new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED')
      const created = await metadata.compareAndSwap(BACKEND_PIN, null, encodeCanonicalCbor([1n, candidate]))
      const persisted = await metadata.get(BACKEND_PIN)
      if (persisted === null) throw new Error('BROWSER_STORAGE_BACKEND_AMBIGUOUS')
      backend = decodePin(persisted)
      if (!created && backend !== candidate) {
        // A competing writer won the metadata CAS; only its immutable choice is safe.
        // The named Web Lock still excludes simultaneous data owners.
      }
    }

    const store = await (async () => {
      if (backend === 'indexeddb') {
        if (typeof indexedDB === 'undefined') throw new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED')
        return IndexedDbBytesStore.open(name)
      }
      // One root acquisition is shared between legacy inspection, capability
      // verification and opening; a protocol-first session requests it once.
      const directoryRoot = await opfsRoot()
      if (!await probeOpfsWritable(directoryRoot)) throw new Error('BROWSER_STORAGE_BACKEND_UNSUPPORTED')
      let directory: FileSystemDirectoryHandle
      try { directory = await directoryRoot.getDirectoryHandle('chronolog-' + name, { create: opened === null }) }
      catch (error) {
        if (opened !== null && error instanceof DOMException && error.name === 'NotFoundError') {
          throw new Error('APPLICATION_DATA_STORAGE_MISSING', { cause: error })
        }
        throw error
      }
      return new OpfsBytesStore(directory)
    })()
    let closing: Promise<void> | undefined
    return { store, close() {
      return closing ??= (async () => {
        try { await store.close() } finally { await lock.close() }
      })()
    } }
  } catch (error) { await lock.close(); throw error }
}

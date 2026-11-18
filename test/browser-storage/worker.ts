import { encodeCanonicalCbor } from '@chronolog/canonical'
import { OpfsBytesStore, acquireBrowserStorage, probeOpfsWritable } from '@chronolog/records/browser'
import { IndexedDbBytesStore, inspectExistingIndexedDbRecords } from '@chronolog/records/indexeddb-browser'
import { openBrowserDevice, probeBrowserCapabilities } from '@chronolog/peer-session/worker'
import { BrowserMetadataStore } from '../../packages/peer-session/src/browser-metadata.js'
import type { BytesStore } from '@chronolog/records'

const endpoint = globalThis as unknown as {
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  postMessage(value: unknown): void
}
const pinKey = 'peer-session/storage-backend/v1'
const openedKey = 'peer-session/storage-opened/v1'
const bindingKey = 'peer-session/storage-binding/v1'
function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error('BROWSER_STORAGE_TEST: ' + message)
}
async function fails(task: Promise<unknown>, code: string): Promise<void> {
  try { await task } catch (error) {
    check(error instanceof Error && error.message.includes(code), 'wrong failure for ' + code + ': ' + String(error))
    return
  }
  throw new Error('BROWSER_STORAGE_TEST: unexpectedly succeeded: ' + code)
}
async function exercise(store: BytesStore): Promise<void> {
  check(await store.get('missing') === null, 'missing key')
  const input = Uint8Array.of(1, 3, 5)
  const written = store.put('data', input)
  input[0] = 200
  await written
  check((await store.get('data'))?.[0] === 1, 'input alias')
  const output = await store.get('data')
  check(output !== null, 'output exists')
  output[0] = 201
  check((await store.get('data'))?.[0] === 1, 'output alias')
  await store.put('empty', new Uint8Array())
  check((await store.get('empty'))?.length === 0, 'empty payload')
  const big = Uint8Array.from({ length: 128 * 1024 + 13 }, (_, index) => index % 251)
  await store.put('large', big)
  check((await store.get('large'))?.[big.length - 1] === big[big.length - 1], 'large payload')
  const first = store.put('ordering', Uint8Array.of(1))
  const second = store.put('ordering', Uint8Array.of(2))
  const third = store.get('ordering')
  await Promise.all([first, second])
  check((await third)?.[0] === 2, 'queued read after both puts')
  await fails(store.put('', Uint8Array.of(1)), 'OPFS_KEY_INVALID')
  await fails(store.get('x'.repeat(4097)), 'OPFS_KEY_INVALID')
}
async function idbConformance(name: string): Promise<void> {
  let store = await IndexedDbBytesStore.open(name)
  await exercise(store)
  const closing = store.close()
  await closing
  await fails(store.put('after-close', Uint8Array.of(1)), 'INDEXEDDB_STORE_CLOSED')
  store = await IndexedDbBytesStore.open(name)
  check((await store.get('ordering'))?.[0] === 2, 'IDB persisted order')
  await store.close()

  // Inject wrong-key envelopes in the real IDB object store, not a fake decoder.
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('chronolog-data:' + name, 1)
    request.onsuccess = () => { resolve(request.result) }
    request.onerror = () => { reject(request.error) }
  })
  await new Promise<void>((resolve, reject) => {
    const tx = database.transaction('values', 'readwrite', { durability: 'strict' })
    tx.objectStore('values').put(encodeCanonicalCbor([1n, 'wrong-key', Uint8Array.of(1), new Uint8Array(32)]), 'ordering')
    tx.oncomplete = () => { resolve() }
    tx.onabort = () => { reject(tx.error) }
  })
  database.close()
  store = await IndexedDbBytesStore.open(name)
  await fails(store.get('ordering'), 'INDEXEDDB_VALUE_CORRUPT')
  await store.close()
}
async function opfsConformance(name: string): Promise<void> {
  if (!await probeOpfsWritable()) return
  const root = await navigator.storage.getDirectory()
  const directory = await root.getDirectoryHandle('test-records-' + name, { create: true })
  let store = new OpfsBytesStore(directory)
  await exercise(store)
  await store.close()
  store = new OpfsBytesStore(directory)
  check((await store.get('ordering'))?.[0] === 2, 'OPFS persisted order')
  await store.close()
  await root.removeEntry('test-records-' + name, { recursive: true })
}

async function run(name: string): Promise<{ id: string; storageId: string; backend: string }> {
  const report = await probeBrowserCapabilities()
  check(report.secureContext && report.dedicatedWorker && report.webLocks, 'worker and locks available')
  check(report.crypto.ed25519 && report.crypto.x25519, 'native crypto available')
  check(report.indexedDb.writable && report.events.supported, 'durable record backend available')
  check(!report.sql.qualified, 'SQL qualification is separate')
  const device = await openBrowserDevice({ name, create: true })
  const metadata = await BrowserMetadataStore.open(name)
  check(await metadata.get(pinKey) === null, 'no pin before first data use')
  check(await metadata.get(openedKey) === null, 'no durable init on identity-only setup')
  const storage = await device.openStorage()
  const rawPin = await metadata.get(pinKey)
  check(rawPin !== null, 'first data use pinned backend')
  const pin = encodeCanonicalCbor([1n, report.events.backend])
  check(rawPin.length === pin.length && rawPin.every((v, i) => v === pin[i]), 'preferred backend')
  await storage.store.put('history/test', Uint8Array.of(7, 8, 9))
  const second = await openBrowserDevice({ name })
  await fails(second.openStorage(), 'BROWSER_STORAGE_IN_USE')
  await second.close()
  await storage.close()
  await device.close()
  metadata.close()

  const reopened = await openBrowserDevice({ name })
  check(reopened.identity.publicKey === device.identity.publicKey && reopened.storageId === device.storageId, 'identity persists')
  const persisted = await reopened.openStorage()
  check((await persisted.store.get('history/test'))?.[2] === 9, 'history persists')
  await reopened.close()

  // An explicit IDB pin exercises the same owning device path in Chromium.
  const fallbackName = name + '-idb'
  const fallback = await openBrowserDevice({ name: fallbackName, create: true })
  const fallbackMeta = await BrowserMetadataStore.open(fallbackName)
  check(await fallbackMeta.compareAndSwap(pinKey, null, encodeCanonicalCbor([1n, 'indexeddb'])), 'fixture IDB pin')
  const fallbackStore = await fallback.openStorage()
  await fallbackStore.store.put('history/test', Uint8Array.of(42))
  await fallback.close()
  const fallbackAgain = await openBrowserDevice({ name: fallbackName })
  const idbStore = await fallbackAgain.openStorage()
  check((await idbStore.store.get('history/test'))?.[0] === 42, 'pinned IDB persists and reopens')
  await fallbackAgain.close()
  fallbackMeta.close()

  // Delete only records, not the immutable pin or signer. Must fail, never fork OPFS.
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase('chronolog-data:' + fallbackName)
    request.onsuccess = () => { resolve() }
    request.onerror = () => { reject(request.error) }
    request.onblocked = () => { reject(new Error('IDB delete blocked') ) }
  })
  const lost = await openBrowserDevice({ name: fallbackName })
  await fails(lost.openStorage(), 'APPLICATION_DATA_STORAGE_MISSING')
  await lost.close()

  if (report.opfs.createWritable) {
    // Simulate a legacy release interrupted after writing STORAGE_BINDING
    // but before its metadata STORAGE_OPENED flag was acknowledged.
    const legacyName = name + '-old'
    const legacy = await openBrowserDevice({ name: legacyName, create: true })
    const oldOwner = await acquireBrowserStorage(legacyName)
    await oldOwner.bytes.put(bindingKey, encodeCanonicalCbor([legacy.identity.publicKey, legacy.storageId]))
    await oldOwner.close()
    const oldMeta = await BrowserMetadataStore.open(legacyName)
    check(await oldMeta.get(openedKey) === null && await oldMeta.get(pinKey) === null, 'legacy crash fixture')
    const oldOpened = await legacy.openStorage()
    check((await oldOpened.store.get(bindingKey)) !== null, 'legacy directory retained')
    check((await oldMeta.get(pinKey))?.length === encodeCanonicalCbor([1n, 'opfs']).length, 'legacy OPFS pinned')
    await legacy.close()
    oldMeta.close()
  }

  // Metadata can disappear independently of records. Without an immutable
  // pin, an orphaned IDB store must never silently turn into fresh OPFS data.
  const orphanName = name + '-orphaned-idb'
  check(!await inspectExistingIndexedDbRecords(orphanName), 'missing IDB inspection is non-creating')
  const orphan = await IndexedDbBytesStore.open(orphanName)
  await orphan.put('history/test', Uint8Array.of(19))
  await orphan.close()
  check(await inspectExistingIndexedDbRecords(orphanName), 'orphaned IDB exists')
  const orphanDevice = await openBrowserDevice({ name: orphanName, create: true })
  await fails(orphanDevice.openStorage(), 'BROWSER_STORAGE_BACKEND_AMBIGUOUS')
  const orphanMetadata = await BrowserMetadataStore.open(orphanName)
  check(await orphanMetadata.get(pinKey) === null, 'ambiguous IDB does not claim a new backend')
  orphanMetadata.close()
  await orphanDevice.close()

  // Old OPFS directories with missing/corrupt bindings are ambiguous instead
  // of a fresh empty history. This is a different crash window from a valid
  // STORAGE_BINDING awaiting the metadata STORAGE_OPENED marker.
  if (report.opfs.createWritable) {
    const interruptedName = name + '-empty-legacy'
    const interrupted = await openBrowserDevice({ name: interruptedName, create: true })
    const root = await navigator.storage.getDirectory()
    await root.getDirectoryHandle('chronolog-' + interruptedName, { create: true })
    await fails(interrupted.openStorage(), 'BROWSER_STORAGE_BACKEND_AMBIGUOUS')
    await interrupted.close()
  }

  await idbConformance(name + '-conformance')
  await opfsConformance(name + '-conformance')
  return { id: device.identity.publicKey, storageId: device.storageId, backend: report.events.backend! }
}
async function resume(name: string): Promise<{ id: string; storageId: string }> {
  const device = await openBrowserDevice({ name })
  const storage = await device.openStorage()
  check((await storage.store.get('history/test'))?.[0] === 7, 'worker restart read')
  const result = { id: device.identity.publicKey, storageId: device.storageId }
  await device.close()
  return result
}

endpoint.addEventListener('message', ({ data }) => {
  const message = data as { id: number; method: 'run' | 'resume'; name: string }
  void (message.method === 'run' ? run(message.name) : resume(message.name)).then(value => {
    endpoint.postMessage({ id: message.id, value })
  }, (error: unknown) => {
    endpoint.postMessage({ id: message.id, error: error instanceof Error ? error.stack : String(error) })
  })
})

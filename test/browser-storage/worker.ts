import { encodeCanonicalCbor } from '@chronolog/canonical'
import { IndexedDbBytesStore } from '@chronolog/records/indexeddb-browser'
import { openBrowserDevice, probeBrowserCapabilities } from '@chronolog/peer-session/worker'
import type { BytesStore } from '@chronolog/records'

const endpoint = globalThis as unknown as {
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void
  postMessage(value: unknown): void
}
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
  check(store.delete !== undefined, 'local eviction is available')
  await store.put('evicted', new Uint8Array(65536))
  await store.delete('evicted'); await store.delete('evicted')
  check(await store.get('evicted') === null, 'local eviction removes exactly its key')
  await fails(store.put('', Uint8Array.of(1)), 'OPFS_KEY_INVALID')
  await fails(store.get('x'.repeat(4097)), 'OPFS_KEY_INVALID')
}
async function idbConformance(name: string): Promise<void> {
  let store = await IndexedDbBytesStore.open(name)
  check((await store.entries()).length === 0, 'empty IDB enumeration')
  await exercise(store)
  const seqBefore = await store.latestChangeSeq()
  check(seqBefore > 0, 'changelog advances on writes')
  const snapshot = store.entries(), laterWrite = store.put('later', Uint8Array.of(8))
  const entries = await snapshot
  await laterWrite
  check(entries.map(entry => entry.key).join(',') === 'data,empty,large,ordering', 'sorted IDB snapshot precedes queued write')
  const delta = await store.readChangesSince(seqBefore)
  check(delta.changes.some(c => c.key === 'later' && !c.deleted), 'changelog records incremental writes')
  const batch = await store.getMany(['missing', 'ordering', 'empty', 'data'])
  check(batch[0] === null && batch[1]?.[0] === 2 && batch[2]?.length === 0 && batch[3]?.[0] === 1, 'ordered IDB batch')
  for (let index = 0; index < 150; index++) await store.put(`page/${index.toString().padStart(3, '0')}`, new Uint8Array(128).fill(index))
  let prefixCount = 0
  for await (const entry of store.iteratePrefix('page/')) { check(entry.key.startsWith('page/'), 'prefix filter'); prefixCount++ }
  check(prefixCount === 150, 'prefix scan returns all matching pages')
  await store.deleteMany(['page/000', 'page/001'])
  check(await store.get('page/000') === null && await store.get('page/001') === null, 'deleteMany removes keys')
  const target = await IndexedDbBytesStore.open(name + '-stream-restore')
  try {
    await fails(target.putStreamIfEmpty((async function* () { yield { key: 'identity', value: Uint8Array.of(1) }; throw Error('restore-interrupted') })()), 'restore-interrupted')
    check((await target.entries()).length === 0, 'interrupted IDB import publishes no identity')
    check(await target.putStreamIfEmpty(store.iterateEntries()), 'IDB streamed atomic restore')
    check(!await target.putStreamIfEmpty((async function* () { throw Error('must not consume input') })()), 'IDB restore refuses existing identity')
  } finally { await target.close() }
  await store.close()
  await fails(store.put('after-close', Uint8Array.of(1)), 'INDEXEDDB_STORE_CLOSED')
  store = await IndexedDbBytesStore.open(name)
  check((await store.get('ordering'))?.[0] === 2, 'IDB persisted order')
  await store.close()

  // Corrupt envelope detection
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('chronolog-data:' + name, 3)
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

async function run(name: string): Promise<{ id: string; storageId: string; backend: string }> {
  const report = await probeBrowserCapabilities()
  check(report.secureContext && report.dedicatedWorker, 'worker available')
  check(report.crypto.ed25519 && report.crypto.x25519, 'native crypto available')
  check(report.indexedDb.writable && report.events.supported && report.events.backend === 'indexeddb', 'indexeddb backend available')
  check(report.sql.qualified, 'SQLite-CAS over IndexedDB is qualified')
  const device = await openBrowserDevice({ name, create: true })
  const storage = await device.openStorage()
  await storage.store.put('history/test', Uint8Array.of(7, 8, 9))

  // Multi-tab concurrent access succeeds with zero storage locks!
  const second = await openBrowserDevice({ name })
  const secondStorage = await second.openStorage()
  check((await secondStorage.store.get('history/test'))?.[2] === 9, 'concurrent second tab reads immediately')
  await secondStorage.store.put('history/from-tab2', Uint8Array.of(42))
  check((await storage.store.get('history/from-tab2'))?.[0] === 42, 'first tab sees second tab write')
  await secondStorage.close()
  await second.close()
  await storage.close()
  await device.close()

  await idbConformance(name + '-conformance')
  return { id: device.identity.publicKey, storageId: device.storageId, backend: report.events.backend }
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
    endpoint.postMessage({ id: message.id, error: error instanceof Error ? error.message + '\n' + (error.stack ?? '') : String(error) })
  })
})

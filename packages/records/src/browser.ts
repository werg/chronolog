import type { BytesStore } from './bytes-store.js'
import { assertRecordKey, decodeRecordValue, encodeRecordValue, recordFilename } from './record-envelope.js'

export interface OpfsWriter {
  write(bytes: ArrayBuffer): Promise<void>
  close(): Promise<void>
  abort(): Promise<void>
}
export interface OpfsFile {
  getFile(): Promise<{ arrayBuffer(): Promise<ArrayBuffer> }>
  createWritable(): Promise<OpfsWriter>
}
export interface OpfsDirectory {
  getFileHandle(name: string, options?: { create?: boolean }): Promise<OpfsFile>
}

/** An atomic OPFS writer; the same envelope and ordering rules as the IDB backend. */
export class OpfsBytesStore implements BytesStore {
  readonly #directory: OpfsDirectory
  #pending: Promise<void> = Promise.resolve()
  #closing: Promise<void> | undefined
  #closed = false

  constructor(directory: OpfsDirectory) { this.#directory = directory }

  async get(key: string): Promise<Uint8Array | null> {
    assertRecordKey(key)
    return this.#enqueue(async () => {
      let file: OpfsFile
      try { file = await this.#directory.getFileHandle(await recordFilename(key)) } catch (error) {
        if (error instanceof DOMException && error.name === 'NotFoundError') return null
        throw error
      }
      const raw = new Uint8Array(await (await file.getFile()).arrayBuffer())
      // A first createWritable() that never committed can leave an empty
      // placeholder; preserve the legacy OPFS absent-value interpretation.
      if (raw.length === 0) return null
      return decodeRecordValue(key, raw, 'OPFS_VALUE_CORRUPT')
    })
  }

  async put(key: string, input: Uint8Array): Promise<void> {
    assertRecordKey(key)
    const bytes = input.slice()
    return this.#enqueue(async () => {
      const raw = await encodeRecordValue(key, bytes)
      const file = await this.#directory.getFileHandle(await recordFilename(key), { create: true })
      const writer = await file.createWritable()
      try {
        await writer.write(raw.slice().buffer)
        await writer.close()
      } catch (error) {
        try { await writer.abort() } catch { /* Preserve the original storage failure. */ }
        throw error
      }
    })
  }

  close(): Promise<void> {
    if (this.#closing !== undefined) return this.#closing
    this.#closed = true
    this.#closing = this.#pending.then(() => undefined)
    return this.#closing
  }

  #enqueue<T>(work: () => Promise<T>): Promise<T> {
    if (this.#closed) return Promise.reject(new Error('OPFS_STORE_CLOSED'))
    const task = this.#pending.then(work)
    this.#pending = task.then(() => undefined, () => undefined)
    return task
  }
}

export interface BrowserStorageLock { close(): Promise<void> }
export interface BrowserStorageOwner {
  readonly directory: FileSystemDirectoryHandle
  readonly bytes: OpfsBytesStore
  close(): Promise<void>
}

/** Hold a single named exclusive Web Lock for selection AND the entire data lifetime. */
export function acquireBrowserStorageLock(name: string): Promise<BrowserStorageLock> {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(name)) return Promise.reject(new Error('BROWSER_STORAGE_NAME_INVALID'))
  if (typeof navigator === 'undefined' || navigator.locks === undefined) {
    return Promise.reject(new Error('BROWSER_DURABLE_STORAGE_UNAVAILABLE'))
  }
  return new Promise((resolve, reject) => {
    const completed = navigator.locks.request('chronolog:' + name, { mode: 'exclusive', ifAvailable: true }, async lock => {
      if (lock === null) { reject(new Error('BROWSER_STORAGE_IN_USE')); return }
      let release!: () => void
      const held = new Promise<void>(done => { release = done })
      let closing: Promise<void> | undefined
      resolve({ close() {
        if (closing !== undefined) return closing
        release()
        closing = completed.then(() => undefined)
        return closing
      } })
      await held
    })
    void completed.catch(reject)
  })
}

/** Compatible direct OPFS acquisition for existing browser consumers. */
export async function acquireBrowserStorage(name: string): Promise<BrowserStorageOwner> {
  const lock = await acquireBrowserStorageLock(name)
  try {
    if (navigator.storage?.getDirectory === undefined) throw new Error('BROWSER_DURABLE_STORAGE_UNAVAILABLE')
    const root = await navigator.storage.getDirectory()
    const directory = await root.getDirectoryHandle('chronolog-' + name, { create: true })
    const bytes = new OpfsBytesStore(directory)
    let closing: Promise<void> | undefined
    return { directory, bytes, close() {
      return closing ??= (async () => {
        try { await bytes.close() } finally { await lock.close() }
      })()
    } }
  } catch (error) { await lock.close(); throw error }
}

/** A prior app directory, even empty, is evidence of a possible interrupted legacy write. */
export async function inspectLegacyOpfsDirectory(name: string, providedRoot?: FileSystemDirectoryHandle): Promise<boolean> {
  if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) {
    throw new Error('BROWSER_STORAGE_BACKEND_AMBIGUOUS')
  }
  try {
    const root = providedRoot ?? await navigator.storage.getDirectory()
    try { await root.getDirectoryHandle('chronolog-' + name); return true }
    catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') return false
      throw error
    }
  } catch (error) { throw new Error('BROWSER_STORAGE_BACKEND_AMBIGUOUS', { cause: error }) }
}

/** An isolated writable-file test: API presence alone is insufficient on Safari. */
export async function probeOpfsWritable(providedRoot?: FileSystemDirectoryHandle): Promise<boolean> {
  if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined) return false
  const root = providedRoot ?? await navigator.storage.getDirectory()
  const fileName = 'chronolog-probe-' + crypto.randomUUID()
  let created = false
  try {
    const file = await root.getFileHandle(fileName, { create: true })
    created = true
    if (typeof file.createWritable !== 'function') return false
    let writer: FileSystemWritableFileStream
    try { writer = await file.createWritable() }
    catch (error) {
      if (error instanceof DOMException && error.name === 'NotSupportedError') return false
      throw error
    }
    try {
      await writer.write(Uint8Array.of(23, 42))
      await writer.close()
    } catch (error) {
      try { await writer.abort() } catch { /* Preserve the probe error. */ }
      throw error
    }
    const bytes = new Uint8Array(await (await file.getFile()).arrayBuffer())
    if (bytes.length !== 2 || bytes[0] !== 23 || bytes[1] !== 42) throw new Error('BROWSER_OPFS_PROBE_FAILED')
    return true
  } finally {
    if (created) try { await root.removeEntry(fileName) } catch { /* Scratch cleanup is best effort. */ }
  }
}

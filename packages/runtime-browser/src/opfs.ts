import { assertCanonicalCbor, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, equalBytes, sha256, utf8 } from '@chronolog/canonical'
import type { AtomicBytesStore } from '@chronolog/records'

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

/**
 * Atomic durable bytes on OPFS. createWritable publishes on close; interrupted
 * writes leave the previous file visible. The envelope detects wrong keys and
 * damaged bytes. This store is local/private, never a peer export interface.
 */
export class OpfsBytesStore implements AtomicBytesStore {
  readonly #directory: OpfsDirectory
  #pending: Promise<unknown> = Promise.resolve()
  #closed = false

  constructor(directory: OpfsDirectory) { this.#directory = directory }

  async get(key: string): Promise<Uint8Array | null> {
    if (this.#closed) throw new Error('OPFS_STORE_CLOSED')
    await this.#pending
    let file: OpfsFile
    try { file = await this.#directory.getFileHandle(await filename(key)) } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') return null
      throw error
    }
    const raw = new Uint8Array(await (await file.getFile()).arrayBuffer())
    // A newly created file whose first writable never committed has no value.
    if (raw.length === 0) return null
    const decoded = assertCanonicalCbor(raw, { ...DEFAULT_DECODE_LIMITS, maxBytes: 128 * 1024 * 1024, maxBlobBytes: 128 * 1024 * 1024 })
    if (!Array.isArray(decoded) || decoded.length !== 4 || decoded[0] !== 1n || decoded[1] !== key ||
        !(decoded[2] instanceof Uint8Array) || !(decoded[3] instanceof Uint8Array) ||
        !equalBytes(decoded[3], await sha256(decoded[2]))) throw new Error('OPFS_VALUE_CORRUPT')
    return decoded[2].slice()
  }

  put(key: string, input: Uint8Array): Promise<void> {
    const bytes = input.slice()
    const task = this.#pending.then(async () => {
      if (this.#closed) throw new Error('OPFS_STORE_CLOSED')
      const raw = encodeCanonicalCbor([1n, key, bytes, await sha256(bytes)])
      const file = await this.#directory.getFileHandle(await filename(key), { create: true })
      const writer = await file.createWritable()
      try {
        await writer.write(raw.slice().buffer)
        await writer.close()
      } catch (error) {
        try { await writer.abort() } catch { /* Preserve the original storage failure. */ }
        throw error
      }
    })
    this.#pending = task.catch(() => undefined)
    return task
  }

  async close(): Promise<void> { await this.#pending; this.#closed = true }
}

export interface BrowserStorageOwner {
  readonly directory: FileSystemDirectoryHandle
  readonly bytes: OpfsBytesStore
  close(): Promise<void>
}

/** One effective owner of a database's record, control, signer and SQL storage. */
export function acquireBrowserStorage(name: string): Promise<BrowserStorageOwner> {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(name)) return Promise.reject(new Error('BROWSER_STORAGE_NAME_INVALID'))
  if (typeof navigator === 'undefined' || navigator.locks === undefined || navigator.storage?.getDirectory === undefined) {
    return Promise.reject(new Error('BROWSER_DURABLE_STORAGE_UNAVAILABLE'))
  }
  return new Promise((resolve, reject) => {
    const completed = navigator.locks.request(`chronolog:${name}`, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
      if (lock === null) { reject(new Error('BROWSER_STORAGE_IN_USE')); return }
      let release!: () => void
      const held = new Promise<void>((done) => { release = done })
      try {
        const root = await navigator.storage.getDirectory()
        const directory = await root.getDirectoryHandle(`chronolog-${name}`, { create: true })
        const bytes = new OpfsBytesStore(directory)
        let closed = false
        resolve({
          directory, bytes,
          async close() {
            if (closed) return
            closed = true
            await bytes.close()
            release()
            await completed
          },
        })
        await held
      } catch (error) { reject(error) }
    })
    void completed.catch(reject)
  })
}

async function filename(key: string): Promise<string> {
  if (key.length === 0 || key.length > 4096) throw new Error('OPFS_KEY_INVALID')
  return `value-${[...await sha256(utf8(key))].map((value) => value.toString(16).padStart(2, '0')).join('')}`
}

import { randomUUID } from 'node:crypto'
import { mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { PeerIdentity } from '@chronolog/peer-generation/control'
import { MemoryBytesStore } from '@chronolog/records'
import { NativeBytesStore, type NativeBytesStoreOptions } from '@chronolog/records/native'

import { openApplicationDevice, type ApplicationDevice } from './device.js'
import { registerExitCleanup } from './exit-cleanup.js'
export { openPeerApplication as openNativeApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { NativeBytesStore } from '@chronolog/records/native'

export interface DisposableNativeDevice extends ApplicationDevice {
  readonly ephemeral: true
  readonly resumable: false
  readonly storageMode: 'disposable-events' | 'disposable-sql'
  /** Managed temp directory allocated for disposable SQL, or null for in-memory events. */
  readonly temporaryDirectory: string | null
  /** Path for a disposable SQL database file inside temporaryDirectory, or null for events. */
  readonly databasePath: string | null
}

/**
 * The SQLite file is the exclusive history owner; a second owner receives a busy error.
 * Without `managedSigner` the file holds its own device-local Ed25519 key. With
 * `managedSigner` (the agent path) the file records only that identity's public key,
 * so one agent signer can own many application devices in one process; every
 * resume must supply the same signer.
 */
export async function openNativeDevice(options: {
  readonly path: string
  readonly create?: true
  readonly managedSigner?: PeerIdentity
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
}): Promise<ApplicationDevice> {
  const limits: NativeBytesStoreOptions = {
    ...(options.quotaBytes === undefined ? {} : { quotaBytes: options.quotaBytes }),
    ...(options.maxValueBytes === undefined ? {} : { maxValueBytes: options.maxValueBytes }),
  }
  const store = await NativeBytesStore.open(options.path, limits)
  try {
    return await openApplicationDevice({ store,
      ...(options.create === undefined ? {} : { create: options.create }),
      ...(options.managedSigner === undefined ? {} : { managedSigner: options.managedSigner }),
      close: () => store.close() })
  }
  catch (error) { await store.close(); throw error }
}

/**
 * Explicit disposable native device replacing ad-hoc `:memory:` SQL workarounds.
 * - Events mode uses in-memory MemoryBytesStore.
 * - SQL mode allocates a managed temp directory under os.tmpdir() and cleans it up on close/exit.
 */
export async function openDisposableNativeDevice(options: {
  readonly sql?: boolean
  readonly managedSigner?: PeerIdentity
  readonly quotaBytes?: number
  readonly maxValueBytes?: number
} = {}): Promise<DisposableNativeDevice> {
  const signer = options.managedSigner === undefined ? {} : { managedSigner: options.managedSigner }
  if (options.sql !== true) {
    const store = new MemoryBytesStore(options)
    const device = await openApplicationDevice({ store, create: true, ...signer })
    return Object.freeze({
      ...device,
      ephemeral: true as const,
      resumable: false as const,
      storageMode: 'disposable-events' as const,
      temporaryDirectory: null,
      databasePath: null,
    })
  }
  const temporaryDirectory = join(tmpdir(), `tendriller-disposable-${randomUUID()}`)
  mkdirSync(temporaryDirectory, { recursive: true, mode: 0o700 })
  const storePath = join(temporaryDirectory, 'device.sqlite')
  const databasePath = join(temporaryDirectory, 'app.sqlite')
  const limits: NativeBytesStoreOptions = {
    ...(options.quotaBytes === undefined ? {} : { quotaBytes: options.quotaBytes }),
    ...(options.maxValueBytes === undefined ? {} : { maxValueBytes: options.maxValueBytes }),
  }
  let store: NativeBytesStore
  try { store = await NativeBytesStore.open(storePath, limits) }
  catch (error) { rmSync(temporaryDirectory, { recursive: true, force: true }); throw error }
  let cleaned = false
  const cleanupDir = (): void => {
    if (cleaned) return
    cleaned = true
    try { void store.close().catch(() => undefined) } catch { /* ignore on exit */ }
    try { rmSync(temporaryDirectory, { recursive: true, force: true }) } catch { /* best-effort temp cleanup */ }
  }
  const unregister = registerExitCleanup(cleanupDir)
  try {
    const device = await openApplicationDevice({
      store,
      create: true,
      ...signer,
      async close() {
        await store.close()
        unregister()
        cleanupDir()
      },
    })
    return Object.freeze({
      ...device,
      ephemeral: true as const,
      resumable: false as const,
      storageMode: 'disposable-sql' as const,
      temporaryDirectory,
      databasePath,
    })
  } catch (error) {
    unregister()
    try { await store.close() } catch { /* Preserve the construction error. */ }
    cleanupDir()
    throw error
  }
}

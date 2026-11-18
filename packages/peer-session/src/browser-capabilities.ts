import { probeIndexedDbBytesStore } from '@chronolog/records/indexeddb-browser'
import { probeOpfsWritable } from '@chronolog/records/browser'

export interface BrowserCapabilityReport {
  readonly secureContext: boolean
  readonly dedicatedWorker: boolean
  readonly indexedDb: { readonly supported: boolean; readonly writable: boolean }
  readonly webLocks: boolean
  readonly opfs: { readonly directory: boolean; readonly createWritable: boolean; readonly syncAccessHandle: boolean }
  readonly crypto: { readonly ed25519: boolean; readonly x25519: boolean }
  readonly wasm: boolean
  /** For a new store only. This does not inspect a device's persisted backend pin. */
  readonly events: { readonly supported: boolean; readonly backend: 'opfs' | 'indexeddb' | null; readonly reason?: string }
  /** API eligibility is not an application SQL/WASM qualification. */
  readonly sql: { readonly apiEligible: boolean; readonly qualified: false; readonly reason: string }
}

async function ed25519(): Promise<boolean> {
  try {
    const generated = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
    const exported = await crypto.subtle.exportKey('pkcs8', generated.privateKey)
    const signer = await crypto.subtle.importKey('pkcs8', exported, 'Ed25519', false, ['sign'])
    const bytes = Uint8Array.of(1, 2, 3)
    return crypto.subtle.verify('Ed25519', generated.publicKey, await crypto.subtle.sign('Ed25519', signer, bytes), bytes)
  } catch { return false }
}
async function x25519(): Promise<boolean> {
  try {
    const first = await crypto.subtle.generateKey('X25519', true, ['deriveBits'])
    const second = await crypto.subtle.generateKey('X25519', true, ['deriveBits'])
    const publicRaw = await crypto.subtle.exportKey('raw', second.publicKey)
    const publicKey = await crypto.subtle.importKey('raw', publicRaw, 'X25519', false, [])
    const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, first.privateKey, 256)
    return bits.byteLength === 32
  } catch { return false }
}

async function syncOpfsHandle(): Promise<boolean> {
  if (typeof navigator === 'undefined' || navigator.storage?.getDirectory === undefined || typeof document !== 'undefined') return false
  const root = await navigator.storage.getDirectory()
  const name = 'chronolog-sync-probe-' + crypto.randomUUID()
  let created = false
  try {
    const file = await root.getFileHandle(name, { create: true })
    created = true
    const method = (file as FileSystemFileHandle & { createSyncAccessHandle?: () => Promise<{ close(): void }> }).createSyncAccessHandle
    if (typeof method !== 'function') return false
    let handle: { close(): void } | undefined
    try { handle = await method.call(file); return true }
    finally { handle?.close() }
  } finally {
    if (created) try { await root.removeEntry(name) } catch { /* Scratch cleanup is best effort. */ }
  }
}

/**
 * Explicit scratch-only probe for an owning dedicated Worker. No application
 * metadata, signer, Web Lock, backend pin, SQL pool or real data store is opened.
 */
export async function probeBrowserCapabilities(): Promise<BrowserCapabilityReport> {
  const secureContext = globalThis.isSecureContext === true
  const dedicatedWorker = typeof document === 'undefined' && typeof self !== 'undefined' &&
    typeof (self as { postMessage?: unknown }).postMessage === 'function'
  const webLocks = typeof navigator !== 'undefined' && typeof navigator.locks?.request === 'function'
  const indexedSupported = typeof indexedDB !== 'undefined'
  const wasm = typeof WebAssembly !== 'undefined'
  const directory = typeof navigator !== 'undefined' && typeof navigator.storage?.getDirectory === 'function'

  const [ed, x] = await Promise.all([ed25519(), x25519()])
  let idbWritable = false, opfsWritable = false, syncHandle = false, reason: string | undefined
  try {
    if (indexedSupported) idbWritable = await probeIndexedDbBytesStore()
    if (directory) {
      opfsWritable = await probeOpfsWritable()
      if (dedicatedWorker) syncHandle = await syncOpfsHandle()
    }
  } catch (error) {
    // Quota, security and unknown I/O errors are not evidence that it is safe
    // to select another backend. Diagnostics preserve the failure explicitly.
    reason = error instanceof Error ? error.name + ': ' + error.message : String(error)
  }
  const backend = reason === undefined ? (opfsWritable ? 'opfs' : idbWritable ? 'indexeddb' : null) : null
  const supported = secureContext && dedicatedWorker && webLocks && ed && x && backend !== null
  const unavailable = reason ?? (!secureContext ? 'Secure context required' : !dedicatedWorker ? 'Dedicated owner Worker required'
    : !webLocks ? 'Web Locks unavailable' : !ed || !x ? 'Required native WebCrypto algorithms unavailable'
    : backend === null ? 'Neither durable record backend is writable' : undefined)
  const eligible = dedicatedWorker && wasm && syncHandle
  return {
    secureContext, dedicatedWorker, indexedDb: { supported: indexedSupported, writable: idbWritable },
    webLocks, opfs: { directory, createWritable: opfsWritable, syncAccessHandle: syncHandle },
    crypto: { ed25519: ed, x25519: x }, wasm,
    events: { supported, backend: supported ? backend : null, ...(supported ? {} : { reason: unavailable ?? 'Event prerequisites unavailable' }) },
    sql: { apiEligible: eligible, qualified: false, reason: eligible
      ? 'SQL/WASM application and VFS have not been qualified on this browser'
      : 'SQL/WASM requires an owner Worker, WebAssembly and OPFS sync access handles' },
  }
}

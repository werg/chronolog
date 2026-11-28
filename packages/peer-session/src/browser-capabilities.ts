import { probeIndexedDbBytesStore } from '@chronolog/records/indexeddb-browser'

export interface BrowserCapabilityReport {
  readonly secureContext: boolean
  readonly dedicatedWorker: boolean
  readonly sharedWorker: boolean
  readonly indexedDb: { readonly supported: boolean; readonly writable: boolean }
  readonly webLocks: boolean
  readonly crypto: { readonly ed25519: boolean; readonly x25519: boolean }
  readonly wasm: boolean
  readonly events: { readonly supported: boolean; readonly backend: 'indexeddb' | null; readonly reason?: string }
  readonly sql: { readonly apiEligible: boolean; readonly qualified: boolean; readonly reason: string }
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
    const first = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair
    const second = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair
    const publicRaw = await crypto.subtle.exportKey('raw', second.publicKey)
    const publicKey = await crypto.subtle.importKey('raw', publicRaw, 'X25519', false, [])
    const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, first.privateKey, 256)
    return bits.byteLength === 32
  } catch { return false }
}

/**
 * Explicit scratch-only probe for an owning dedicated Worker.
 * Chronolog uses multi-tab IndexedDB + WASM sqlite-cas (no OPFS sync handles or exclusive storage locks).
 */
export async function probeBrowserCapabilities(): Promise<BrowserCapabilityReport> {
  const secureContext = globalThis.isSecureContext === true
  const dedicatedWorker = typeof document === 'undefined' && typeof self !== 'undefined' &&
    typeof (self as { postMessage?: unknown }).postMessage === 'function'
  const sharedWorker = typeof document === 'undefined' && typeof self !== 'undefined' && 'onconnect' in self
  const ownerWorker = dedicatedWorker || sharedWorker
  const webLocks = typeof navigator !== 'undefined' && typeof navigator.locks?.request === 'function'
  const indexedSupported = typeof indexedDB !== 'undefined'
  const wasm = typeof WebAssembly !== 'undefined'

  const [ed, x] = await Promise.all([ed25519(), x25519()])
  let idbWritable = false, reason: string | undefined
  try {
    if (indexedSupported) idbWritable = await probeIndexedDbBytesStore()
  } catch (error) {
    reason = error instanceof Error ? error.name + ': ' + error.message : String(error)
  }
  const backend = reason === undefined && idbWritable ? 'indexeddb' : null
  const supported = secureContext && ownerWorker && ed && x && backend !== null
  const unavailable = reason ?? (!secureContext ? 'Secure context required' : !ownerWorker ? 'Dedicated owner Worker required'
    : !ed || !x ? 'Required native WebCrypto algorithms unavailable'
    : !idbWritable ? 'Writable IndexedDB is required for device and application storage' : undefined)
  const eligible = ownerWorker && wasm && idbWritable
  return {
    secureContext, dedicatedWorker, sharedWorker, indexedDb: { supported: indexedSupported, writable: idbWritable },
    webLocks, crypto: { ed25519: ed, x25519: x }, wasm,
    events: { supported, backend: supported ? backend : null, ...(supported ? {} : { reason: unavailable ?? 'Event prerequisites unavailable' }) },
    sql: {
      apiEligible: eligible,
      qualified: eligible,
      reason: eligible
        ? 'SQLite-CAS WASM over multi-tab IndexedDB is supported'
        : 'SQLite-CAS requires a Worker, WebAssembly, and writable IndexedDB',
    },
  }
}

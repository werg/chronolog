import { sha256 as nobleSha256 } from '@noble/hashes/sha256'

import { utf8 } from './bytes.js'
import { perfCount } from './perf.js'

/** Synchronous hashing for synchronous SQL engine callbacks on native and WASM. */
export function sha256Sync(bytes: Uint8Array): Uint8Array { perfCount('sha256Sync'); perfCount('sha256Sync.bytes', bytes.length); return nobleSha256(bytes) }

export function createSha256(): { update(bytes: Uint8Array | string): ReturnType<typeof createSha256>; digest(): Uint8Array } {
  const hash = nobleSha256.create()
  const writer = {
    update(bytes: Uint8Array | string) { hash.update(typeof bytes === 'string' ? utf8(bytes) : bytes); return writer },
    digest() { return hash.digest() },
  }
  return writer
}

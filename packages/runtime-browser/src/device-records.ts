import { loadEnrollmentIdentity, loadOrCreateEnrollmentIdentity, type EnrollmentIdentity } from '@chronolog/node-core/browser'
import { encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import { DurableFeedStore, webFeedCrypto, type AtomicBytesStore } from '@chronolog/records'

import { acquireBrowserStorage } from '@chronolog/records/browser'

/** Existing keys always require their feed. First setup persists an empty feed before keys. */
export async function openBrowserDeviceRecords(bytes: AtomicBytesStore, createIdentity?: true) {
  let identity: EnrollmentIdentity | undefined
  try { identity = await loadEnrollmentIdentity(bytes, 'peer') }
  catch (error) {
    if (createIdentity !== true || !(error instanceof Error) || error.message !== 'ENROLLMENT_IDENTITY_MISSING') throw error
  }
  const manifest = await bytes.get('feed/manifest'), binding = await bytes.get('browser/feed-initialized')
  if (identity !== undefined && manifest === null) throw new Error('BROWSER_FEED_MANIFEST_MISSING')
  if (identity !== undefined && binding === null) throw new Error('BROWSER_DEVICE_BINDING_MISSING')
  if (identity !== undefined && !equalBytes(binding!, encodeCanonicalCbor([1n, identity.signing.publicKeyBytes]))) {
    throw new Error('BROWSER_DEVICE_IDENTITY_MISMATCH')
  }
  if (identity === undefined && binding !== null) throw new Error('ENROLLMENT_IDENTITY_MISSING')
  const records = manifest === null
    ? await DurableFeedStore.create(bytes, webFeedCrypto)
    : await DurableFeedStore.open(bytes, webFeedCrypto)
  try {
    if (identity === undefined) {
      // Resume only interrupted first setup, before any signed feed/evidence existed.
      if (records.count() !== 0 || records.forkedAuthors().length !== 0 || records.evidenceAfter(0n, 1).length !== 0) {
        throw new Error('ENROLLMENT_IDENTITY_MISSING')
      }
      identity = await loadOrCreateEnrollmentIdentity(bytes, 'peer')
      // Complete setup before exposing keys/records to any publisher. This is
      // never an extra fallible write after a signed manifest publication.
      await bytes.put('browser/feed-initialized', encodeCanonicalCbor([1n, identity.signing.publicKeyBytes]))
    }
    return { identity, records }
  } catch (error) { await records.close(); throw error }
}

/** Explicit Worker-only setup for enrollment that needs public device keys before group creation. */
export async function prepareBrowserIdentity(name: string, createIdentity?: true): Promise<EnrollmentIdentity> {
  if (typeof document !== 'undefined') throw new Error('BROWSER_PEER_WORKER_REQUIRED')
  const storage = await acquireBrowserStorage(name)
  try {
    const opened = await openBrowserDeviceRecords(storage.bytes, createIdentity)
    await opened.records.close()
    return opened.identity
  } finally { await storage.close() }
}

import { loadEnrollmentIdentity, loadOrCreateEnrollmentIdentity } from '@chronolog/node-core/browser'
import { encodeCanonicalCbor, equalBytes } from '@chronolog/protocol'
import { DurableFeedStore, webFeedCrypto, type AtomicBytesStore } from '@chronolog/records'

const markerKey = 'browser/feed-initialized'
const manifestKey = 'feed/manifest'

/**
 * A surviving device must never restart its signed feed from position zero
 * because one manifest file disappeared. Mark the first manifest publication
 * durably before acknowledging it. A crash between manifest and marker writes
 * is recovered by validating the surviving manifest before installing its marker.
 */
export async function openBrowserDeviceRecords(bytes: AtomicBytesStore, createIdentity?: true) {
  const marker = await bytes.get(markerKey), manifest = await bytes.get(manifestKey)
  const existing = marker !== null || manifest !== null
  const identity = await (!existing && createIdentity === true ? loadOrCreateEnrollmentIdentity : loadEnrollmentIdentity)(bytes, 'peer')
  const binding = encodeCanonicalCbor([1n, identity.signing.publicKeyBytes])
  if (marker !== null && !equalBytes(marker, binding)) throw new Error('BROWSER_DEVICE_IDENTITY_MISMATCH')
  if (marker !== null && manifest === null) throw new Error('BROWSER_FEED_MANIFEST_MISSING')
  let marked = marker !== null
  const mark = async () => {
    if (marked) return
    await bytes.put(markerKey, binding)
    marked = true
  }
  const records = await DurableFeedStore.open({
    get: (key) => bytes.get(key),
    async put(key, value) {
      await bytes.put(key, value)
      if (key === manifestKey) await mark()
    },
  }, webFeedCrypto)
  try {
    if (manifest !== null) await mark()
    return { identity, records }
  } catch (error) { await records.close(); throw error }
}

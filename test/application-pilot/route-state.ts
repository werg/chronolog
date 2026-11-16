import { capabilitySnapshotDigest, type CapabilitySnapshot } from '@chronolog/capabilities'
import { bytesToBase64Url, encodeCanonicalCbor } from '@chronolog/protocol'
import { webFeedCrypto, type PortableFeedTransport } from '@chronolog/records'

/** Compare signed content, not replica-local arrival timestamps or revisions. */
export async function routeState(transport: PortableFeedTransport, membership: CapabilitySnapshot, finalOrderLength: number) {
  const records = [...await transport.history()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  const content = records.map(record => [record.id, record.author, record.sequence, record.previous ?? null, record.payload])
  return { records: records.length, recordDigest: bytesToBase64Url(await webFeedCrypto.sha256(encodeCanonicalCbor(content))),
    capabilityDigest: bytesToBase64Url(await capabilitySnapshotDigest(membership)), finalOrderLength }
}

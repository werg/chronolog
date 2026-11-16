import { loadEnrollmentIdentity, loadOrCreateEnrollmentIdentity } from '@chronolog/node-core/browser'
import { utf8 } from '@chronolog/protocol'
import { PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { openBrowserDeviceRecords } from './device-records.js'

function store() {
  const values = new Map<string, Uint8Array>()
  let failMarker = false
  const bytes = {
    async get(key: string) { return values.get(key)?.slice() ?? null },
    async put(key: string, value: Uint8Array) {
      if (failMarker && key === 'browser/feed-initialized') throw new Error('MARKER_WRITE_INTERRUPTED')
      values.set(key, value.slice())
    },
  }
  return { values, bytes, failMarker(value: boolean) { failMarker = value } }
}

function transport(opened: Awaited<ReturnType<typeof openBrowserDeviceRecords>>) {
  return new PortableFeedTransport({ store: opened.records, crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(opened.identity.signing.publicKeyBytes), opened.identity.signing.privateKey) })
}

describe('browser signed-feed continuity', () => {
  it('refuses a missing manifest with surviving keys even during explicit creation, then restores the exact feed', async () => {
    const f = store(), opened = await openBrowserDeviceRecords(f.bytes, true), first = transport(opened)
    const original = await first.publish(utf8('original position'))
    await first.close()
    const manifest = f.values.get('feed/manifest')!
    f.values.delete('feed/manifest')
    await expect(openBrowserDeviceRecords(f.bytes)).rejects.toThrow('BROWSER_FEED_MANIFEST_MISSING')
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('BROWSER_FEED_MANIFEST_MISSING')
    expect((await loadEnrollmentIdentity(f.bytes, 'peer')).signing.publicKeyBytes).toEqual(opened.identity.signing.publicKeyBytes)
    f.values.set('feed/manifest', manifest)
    const restored = transport(await openBrowserDeviceRecords(f.bytes))
    try {
      expect((await restored.history()).map(record => record.id)).toEqual([original.id])
      expect((await restored.publish(utf8('next position'))).sequence).toBe(2n)
    } finally { await restored.close() }
  })

  it('recovers a committed first manifest when the initialization marker reply was interrupted', async () => {
    const f = store(), opened = await openBrowserDeviceRecords(f.bytes, true), first = transport(opened)
    f.failMarker(true)
    await expect(first.publish(utf8('durable but unacknowledged'))).rejects.toThrow('MARKER_WRITE_INTERRUPTED')
    await first.close()
    expect(f.values.has('feed/manifest')).toBe(true)
    expect(f.values.has('browser/feed-initialized')).toBe(false)
    f.failMarker(false)
    const restored = transport(await openBrowserDeviceRecords(f.bytes))
    try {
      expect(f.values.has('browser/feed-initialized')).toBe(true)
      expect((await restored.history()).map(record => new TextDecoder().decode(record.payload))).toEqual(['durable but unacknowledged'])
      expect((await restored.publish(utf8('no position reuse'))).sequence).toBe(2n)
    } finally { await restored.close() }
  })

  it('does not create or substitute identity keys in an initialized feed store', async () => {
    const f = store(), opened = await openBrowserDeviceRecords(f.bytes, true), first = transport(opened)
    await first.publish(utf8('owned history')); await first.close()
    f.values.delete('enrollment/identity/peer')
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('ENROLLMENT_IDENTITY_MISSING')
    expect(f.values.has('enrollment/identity/peer')).toBe(false)
    const other = store()
    await loadOrCreateEnrollmentIdentity(other.bytes, 'peer')
    f.values.set('enrollment/identity/peer', other.values.get('enrollment/identity/peer')!)
    await expect(openBrowserDeviceRecords(f.bytes)).rejects.toThrow('BROWSER_DEVICE_IDENTITY_MISMATCH')
  })
})

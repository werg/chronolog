import { loadEnrollmentIdentity, loadOrCreateEnrollmentIdentity } from '@chronolog/node-core/browser'
import { utf8 } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { openBrowserDeviceRecords } from './device-records.js'

function store() {
  const values = new Map<string, Uint8Array>()
  let failMarker = false, failManifestAfterCommit = false
  const bytes = {
    async get(key: string) { return values.get(key)?.slice() ?? null },
    async put(key: string, value: Uint8Array) {
      if (failMarker && key === 'browser/feed-initialized') throw new Error('MARKER_WRITE_INTERRUPTED')
      values.set(key, value.slice())
      if (failManifestAfterCommit && key === 'feed/manifest') throw new Error('MANIFEST_REPLY_LOST')
    },
  }
  return { values, bytes, failMarker(value: boolean) { failMarker = value },
    failManifestAfterCommit(value: boolean) { failManifestAfterCommit = value } }
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
    const manifest = f.values.get('feed/manifest')!, binding = f.values.get('browser/feed-initialized')!
    f.values.delete('feed/manifest'); f.values.delete('browser/feed-initialized')
    await expect(openBrowserDeviceRecords(f.bytes)).rejects.toThrow('BROWSER_FEED_MANIFEST_MISSING')
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('BROWSER_FEED_MANIFEST_MISSING')
    expect((await loadEnrollmentIdentity(f.bytes, 'peer')).signing.publicKeyBytes).toEqual(opened.identity.signing.publicKeyBytes)
    f.values.set('feed/manifest', manifest)
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('BROWSER_DEVICE_BINDING_MISSING')
    f.values.set('browser/feed-initialized', binding)
    const restored = transport(await openBrowserDeviceRecords(f.bytes))
    try {
      expect((await restored.history()).map(record => record.id)).toEqual([original.id])
      expect((await restored.publish(utf8('next position'))).sequence).toBe(2n)
    } finally { await restored.close() }
  })

  it('fences the live owner after an ambiguous manifest commit until it reopens the durable head', async () => {
    const f = store(), opened = await openBrowserDeviceRecords(f.bytes, true), first = transport(opened)
    f.failManifestAfterCommit(true)
    await expect(first.publish(utf8('durable but unacknowledged'))).rejects.toThrow('MANIFEST_REPLY_LOST')
    const committed = f.values.get('feed/manifest')!.slice()
    f.failManifestAfterCommit(false)
    await expect(first.publish(utf8('must not replace position one'))).rejects.toThrow('FEED_STORE_REOPEN_REQUIRED')
    expect(f.values.get('feed/manifest')).toEqual(committed)
    await first.close()
    const restored = transport(await openBrowserDeviceRecords(f.bytes))
    try {
      expect((await restored.history()).map(record => new TextDecoder().decode(record.payload))).toEqual(['durable but unacknowledged'])
      expect((await restored.publish(utf8('no position reuse'))).sequence).toBe(2n)
    } finally { await restored.close() }
  })

  it('never returns usable keys or silently repairs an interrupted final setup write', async () => {
    const f = store()
    f.failMarker(true)
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('MARKER_WRITE_INTERRUPTED')
    expect(f.values.has('feed/manifest')).toBe(true)
    const originalKeys = f.values.get('enrollment/identity/peer')!.slice()
    f.failMarker(false)
    await expect(openBrowserDeviceRecords(f.bytes)).rejects.toThrow('BROWSER_DEVICE_BINDING_MISSING')
    await expect(openBrowserDeviceRecords(f.bytes, true)).rejects.toThrow('BROWSER_DEVICE_BINDING_MISSING')
    expect(f.values.get('enrollment/identity/peer')).toEqual(originalKeys)
  })

  it('finishes explicit pre-key setup only from a verified empty feed', async () => {
    const empty = store()
    await (await DurableFeedStore.create(empty.bytes, webFeedCrypto)).close()
    await (await openBrowserDeviceRecords(empty.bytes, true)).records.close()
    expect(empty.values.has('enrollment/identity/peer')).toBe(true)
    const nonempty = store(), records = await DurableFeedStore.create(nonempty.bytes, webFeedCrypto)
    await records.putEvidence(utf8('retained certified history')); await records.close()
    await expect(openBrowserDeviceRecords(nonempty.bytes, true)).rejects.toThrow('ENROLLMENT_IDENTITY_MISSING')
    expect(nonempty.values.has('enrollment/identity/peer')).toBe(false)
    const malformed = store()
    malformed.values.set('feed/manifest', Uint8Array.of(0))
    await expect(openBrowserDeviceRecords(malformed.bytes, true)).rejects.toThrow('FEED_STORE_MANIFEST_INVALID')
    expect(malformed.values.has('enrollment/identity/peer')).toBe(false)
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

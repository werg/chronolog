import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { createFeedRecord as nativeCreate, decodeFeedRecord as nativeDecode } from '../../transport-ssb/src/feed-store.js'
import {
  createFeedRecord, decodeBase64, encodeBase64, feedIdFromPublicKey,
  verifyFeedRecord, webFeedCrypto, webFeedSigner,
} from './feed-codec.js'

async function identity() {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index)
  const privateBytes = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed])
  const privateKey = createPrivateKey({ key: privateBytes, type: 'pkcs8', format: 'der' })
  const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(-32)
  const id = feedIdFromPublicKey(publicKey)
  const browserKey = await crypto.subtle.importKey('pkcs8', privateBytes, 'Ed25519', false, ['sign'])
  return { id, privateKey, signer: webFeedSigner(id, browserKey), native: { id, private: `${encodeBase64(seed)}.ed25519` } }
}

describe('portable feed wire contract', () => {
  it('produces the exact native bytes and identity using Web Crypto', async () => {
    const keys = await identity()
    const payload = Uint8Array.of(0, 255, 128, 3)
    const native = nativeCreate(keys.native, 1n, null, 42n, payload)
    const portable = await createFeedRecord(keys.signer, webFeedCrypto, 1n, null, 42n, payload)
    expect(portable).toEqual(native)
    expect(nativeDecode(portable.raw)).toEqual(native)
    expect(await verifyFeedRecord(native.raw, webFeedCrypto)).toEqual(native)
    expect(portable.id).toBe(`%${createHash('sha256').update(portable.raw).digest('base64')}.sha256`)
  })

  it('preserves the author and chain when another peer forwards exact bytes', async () => {
    const keys = await identity()
    const first = await createFeedRecord(keys.signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
    const second = await createFeedRecord(keys.signer, webFeedCrypto, 2n, first.id, 2n, Uint8Array.of(2))
    const relayCopy = decodeBase64(encodeBase64(second.raw))
    expect(await verifyFeedRecord(relayCopy, webFeedCrypto)).toEqual(second)
    expect(second.author).toBe(keys.id)
  })

  it('rejects changed bytes, oversize records, and a signer using the wrong key', async () => {
    const keys = await identity()
    const record = await createFeedRecord(keys.signer, webFeedCrypto, 1n, null, 1n, Uint8Array.of(1))
    const changed = record.raw.slice()
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1
    await expect(verifyFeedRecord(changed, webFeedCrypto)).rejects.toThrow('FEED_RECORD_SIGNATURE_INVALID')
    await expect(verifyFeedRecord(record.raw, webFeedCrypto, 1)).rejects.toThrow('FEED_RECORD_TOO_LARGE')
    await expect(createFeedRecord({ identity: feedIdFromPublicKey(new Uint8Array(32)), sign: (bytes) => sign(null, bytes, keys.privateKey) },
      webFeedCrypto, 1n, null, 1n, new Uint8Array())).rejects.toThrow('FEED_RECORD_SIGNATURE_INVALID')
  })

  it('rejects noncanonical base64 aliases and copies caller-owned payloads', async () => {
    expect(() => decodeBase64('AB==')).toThrow('FEED_BASE64_INVALID')
    const keys = await identity()
    const bytes = Uint8Array.of(1)
    const pending = createFeedRecord(keys.signer, webFeedCrypto, 1n, null, 0n, bytes)
    bytes[0] = 9
    expect((await pending).payload).toEqual(Uint8Array.of(1))
  })
})

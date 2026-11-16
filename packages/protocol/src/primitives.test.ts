import { describe, expect, it } from 'vitest'
import {
  DOMAINS,
  generateEd25519KeyPair,
  exportEd25519PrivateKey,
  hashDomain,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  signDomain,
  utf8,
  verifyDomain,
} from './index.js'

describe('domain-separated protocol cryptography', () => {
  it('signs and verifies only under the exact domain', async () => {
    const pair = await generateEd25519KeyPair()
    const payload = utf8('canonical protocol bytes')
    const signature = await signDomain(DOMAINS.transaction, payload, pair.privateKey)
    expect(signature).toHaveLength(64)
    expect(await verifyDomain(DOMAINS.transaction, payload, signature, pair.publicKeyBytes)).toBe(true)
    expect(await verifyDomain(DOMAINS.attestation, payload, signature, pair.publicKeyBytes)).toBe(false)
    expect(await verifyDomain(DOMAINS.transaction, utf8('changed'), signature, pair.publicKeyBytes)).toBe(false)
  })

  it('separates hashes for identical bytes in different structures', async () => {
    const payload = utf8('same')
    expect(await hashDomain(DOMAINS.transactionDigest, payload)).not.toEqual(
      await hashDomain(DOMAINS.canonicalResult, payload),
    )
  })

  it('imports Buffer key views and verifies a Buffer signature without consuming surrounding bytes', async () => {
    const pair = await generateEd25519KeyPair()
    const view = (bytes: Uint8Array): Buffer => {
      const allocation = Buffer.alloc(bytes.length + 40, 0x5a)
      const selected = allocation.subarray(17, 17 + bytes.length)
      selected.set(bytes)
      return selected
    }
    const publicKeyBytes = view(pair.publicKeyBytes)
    const privateKeyBytes = view(await exportEd25519PrivateKey(pair.privateKey))
    const originalPrivate = Uint8Array.from(privateKeyBytes)
    const publicKey = await importEd25519PublicKey(publicKeyBytes)
    const privateKey = await importEd25519PrivateKey(privateKeyBytes)
    const payload = view(utf8('exact signing bytes'))
    const signature = view(await signDomain(DOMAINS.transaction, payload, privateKey))
    expect(await verifyDomain(DOMAINS.transaction, payload, signature, publicKey)).toBe(true)
    expect(await verifyDomain(DOMAINS.transaction, payload, signature, publicKeyBytes)).toBe(true)
    expect(Uint8Array.from(privateKeyBytes)).toEqual(originalPrivate)
    signature[0]! ^= 1
    expect(await verifyDomain(DOMAINS.transaction, payload, signature, publicKeyBytes)).toBe(false)
  })
})


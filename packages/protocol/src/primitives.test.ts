import { describe, expect, it } from 'vitest'
import { generateEd25519KeyPair, verifyEd25519, verifyEd25519Sync } from './primitives.js'

const L = (1n << 252n) + 27742317777372353535851937790883648493n

function leBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) { out[i] = Number(value & 0xffn); value >>= 8n }
  return out
}

describe('protocol Ed25519 verifier (single strict rule set)', () => {
  it('accepts honest signatures for raw and CryptoKey public keys', async () => {
    const pair = await generateEd25519KeyPair()
    const msg = new TextEncoder().encode('chronolog')
    const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, msg))
    expect(verifyEd25519Sync(pair.publicKeyBytes, msg, sig)).toBe(true)
    expect(await verifyEd25519(pair.publicKeyBytes, msg, sig)).toBe(true)
    expect(await verifyEd25519(pair.publicKey, msg, sig)).toBe(true)
    expect(verifyEd25519Sync(pair.publicKeyBytes, new TextEncoder().encode('other'), sig)).toBe(false)
  })

  it('rejects non-canonical S, small-order keys, and malformed lengths', async () => {
    const pair = await generateEd25519KeyPair()
    const msg = new TextEncoder().encode('chronolog')
    const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, msg))
    // S + L verifies under a lax equation check but is not canonical.
    let s = 0n
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sig[32 + i]!)
    const malleated = Uint8Array.from(sig)
    malleated.set(leBytes(s + L, 32), 32)
    expect(verifyEd25519Sync(pair.publicKeyBytes, msg, malleated)).toBe(false)
    // Identity public key with identity R and S = 0 satisfies the group equation for any message.
    const identity = new Uint8Array(32); identity[0] = 1
    const trivial = new Uint8Array(64); trivial[0] = 1
    expect(verifyEd25519Sync(identity, msg, trivial)).toBe(false)
    expect(verifyEd25519Sync(pair.publicKeyBytes.subarray(0, 31), msg, sig)).toBe(false)
    expect(verifyEd25519Sync(pair.publicKeyBytes, msg, sig.subarray(0, 63))).toBe(false)
  })
})

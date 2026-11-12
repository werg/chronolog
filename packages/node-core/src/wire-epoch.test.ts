import { generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { EpochCipherRing, createEpochEnvelopeCipher } from './cipher.js'
import { WIRE_ENCRYPTION_EPOCH_UNAVAILABLE, decodeSignedEnvelope, encodeSignedEnvelope } from './wire.js'

describe('envelope epochs', () => {
  it('reports a key ring that has not received the epoch yet as retryable, then decodes once it has', async () => {
    const signer = await generateEd25519KeyPair()
    const route = new Uint8Array(32).fill(7)
    const key = new Uint8Array(32).fill(9)
    const encoded = await encodeSignedEnvelope(route, 'candidate', Uint8Array.of(1, 2, 3), signer, createEpochEnvelopeCipher(key, 4n))

    const ring = new EpochCipherRing()
    ring.install(new Uint8Array(32).fill(1), 3n, true)
    await expect(decodeSignedEnvelope(encoded, route, ring)).rejects.toThrow(WIRE_ENCRYPTION_EPOCH_UNAVAILABLE)
    ring.install(key, 4n)
    await expect(decodeSignedEnvelope(encoded, route, ring)).resolves.toMatchObject({ type: 'candidate', payload: Uint8Array.of(1, 2, 3) })
    // A fixed cipher for another epoch can never decode it: that stays a terminal mismatch.
    await expect(decodeSignedEnvelope(encoded, route, createEpochEnvelopeCipher(key, 5n))).rejects.toThrow('WIRE_ENCRYPTION_EPOCH_UNKNOWN')
  })
})

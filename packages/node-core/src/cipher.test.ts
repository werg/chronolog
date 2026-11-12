import { encodeCanonicalCbor, decodeCanonicalCbor, ProtocolError, type CborValue } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { createEpochEnvelopeCipher, EpochCipherRing } from './cipher.js'

const keyA = new Uint8Array(32).fill(0xa1)
const keyB = new Uint8Array(32).fill(0xb2)
const aad = new TextEncoder().encode('envelope-header')
const plaintext = new TextEncoder().encode('secret transaction body')

function fields(sealed: Uint8Array): CborValue[] {
  const value = decodeCanonicalCbor(sealed)
  if (!Array.isArray(value)) throw new Error('expected array envelope')
  return [...value]
}

async function expectAuthFailure(promise: Promise<unknown>): Promise<void> {
  const error = await promise.then(() => null, (caught: unknown) => caught)
  expect(error).toBeInstanceOf(ProtocolError)
  expect((error as ProtocolError).code).toBe('INVALID_SIGNATURE')
}

describe('createEpochEnvelopeCipher', () => {
  it('rejects content keys that are not exactly 32 bytes', () => {
    expect(() => createEpochEnvelopeCipher(new Uint8Array(31), 1n)).toThrow('EPOCH_CONTENT_KEY_INVALID')
    expect(() => createEpochEnvelopeCipher(new Uint8Array(33), 1n)).toThrow('EPOCH_CONTENT_KEY_INVALID')
    expect(() => createEpochEnvelopeCipher(new Uint8Array(0), 1n)).toThrow('EPOCH_CONTENT_KEY_INVALID')
  })

  it('round-trips and binds the epoch id to the canonical epoch number', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 7n)
    expect(cipher.epochId).toEqual(encodeCanonicalCbor(7n))
    const sealed = await cipher.seal(plaintext, aad)
    expect(fields(sealed)[0]).toBe(1n)
    expect(fields(sealed)[1]).toBe(7n)
    await expect(cipher.open(sealed, aad)).resolves.toEqual(plaintext)
  })

  it('takes a private copy of the content key', async () => {
    const callerKey = keyA.slice()
    const cipher = createEpochEnvelopeCipher(callerKey, 1n)
    callerKey.fill(0)
    const sealed = await cipher.seal(plaintext, aad)
    await expect(createEpochEnvelopeCipher(keyA, 1n).open(sealed, aad)).resolves.toEqual(plaintext)
    await expectAuthFailure(createEpochEnvelopeCipher(new Uint8Array(32), 1n).open(sealed, aad))
  })

  it('fails authentication on a wrong key for the same epoch', async () => {
    const sealed = await createEpochEnvelopeCipher(keyA, 3n).seal(plaintext, aad)
    await expectAuthFailure(createEpochEnvelopeCipher(keyB, 3n).open(sealed, aad))
  })

  it('fails authentication when associated data differs', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 3n)
    const sealed = await cipher.seal(plaintext, aad)
    await expectAuthFailure(cipher.open(sealed, new TextEncoder().encode('other-header')))
    await expectAuthFailure(cipher.open(sealed, new Uint8Array()))
  })

  it('fails authentication on any flipped ciphertext or nonce bit', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 3n)
    const [version, epoch, nonce, ciphertext] = fields(await cipher.seal(plaintext, aad)) as [bigint, bigint, Uint8Array, Uint8Array]
    for (const index of [0, Math.floor(ciphertext.length / 2), ciphertext.length - 1]) {
      const tampered = ciphertext.slice()
      tampered[index]! ^= 0x01
      await expectAuthFailure(cipher.open(encodeCanonicalCbor([version, epoch, nonce, tampered]), aad))
    }
    const tamperedNonce = nonce.slice()
    tamperedNonce[0]! ^= 0x80
    await expectAuthFailure(cipher.open(encodeCanonicalCbor([version, epoch, tamperedNonce, ciphertext]), aad))
    // Truncating the tag must not be accepted either.
    await expectAuthFailure(cipher.open(encodeCanonicalCbor([version, epoch, nonce, ciphertext.slice(0, -1)]), aad))
  })

  it('rejects envelopes relabelled with a different epoch, even under the same key', async () => {
    const sealed = await createEpochEnvelopeCipher(keyA, 3n).seal(plaintext, aad)
    // Different epoch label on the receiving cipher is rejected structurally.
    await expect(createEpochEnvelopeCipher(keyA, 4n).open(sealed, aad)).rejects.toThrow('EPOCH_CIPHERTEXT_INVALID')
    // Relabelling the envelope to match the receiver fails authentication, since the epoch is in the AAD.
    const [version, , nonce, ciphertext] = fields(sealed)
    await expectAuthFailure(createEpochEnvelopeCipher(keyA, 4n).open(encodeCanonicalCbor([version!, 4n, nonce!, ciphertext!]), aad))
  })

  it('rejects structurally malformed envelopes', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 2n)
    const [, , nonce, ciphertext] = fields(await cipher.seal(plaintext, aad)) as [bigint, bigint, Uint8Array, Uint8Array]
    const malformed: CborValue[] = [
      [2n, 2n, nonce, ciphertext],
      [0n, 2n, nonce, ciphertext],
      [1n, 2n, nonce],
      [1n, 2n, nonce, ciphertext, new Uint8Array()],
      [1n, 'two', nonce, ciphertext],
      [1n, 2n, 'nonce', ciphertext],
      [1n, 2n, nonce, 'ciphertext'],
      new Map<bigint, CborValue>([[0n, 1n]]),
      ciphertext,
    ]
    for (const value of malformed) {
      await expect(cipher.open(encodeCanonicalCbor(value), aad)).rejects.toThrow('EPOCH_CIPHERTEXT_INVALID')
    }
  })

  it('rejects a nonce of the wrong length before decrypting', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 2n)
    const [, , nonce, ciphertext] = fields(await cipher.seal(plaintext, aad)) as [bigint, bigint, Uint8Array, Uint8Array]
    const error = await cipher.open(encodeCanonicalCbor([1n, 2n, nonce.slice(0, 11), ciphertext]), aad).catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ProtocolError)
    expect((error as ProtocolError).code).toBe('SCHEMA_INVALID')
  })

  it('rejects non-canonical and truncated encodings', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 2n)
    const sealed = await cipher.seal(plaintext, aad)
    await expect(cipher.open(sealed.slice(0, -1), aad)).rejects.toBeInstanceOf(ProtocolError)
    await expect(cipher.open(Uint8Array.of(...sealed, 0x00), aad)).rejects.toBeInstanceOf(ProtocolError)
    // Array header 0x84 re-encoded as a non-minimal 0x98 0x04 is not canonical.
    const nonCanonical = Uint8Array.of(0x98, 0x04, ...sealed.slice(1))
    await expect(cipher.open(nonCanonical, aad)).rejects.toBeInstanceOf(ProtocolError)
  })

  it('uses a fresh nonce for every seal', async () => {
    const cipher = createEpochEnvelopeCipher(keyA, 2n)
    const first = fields(await cipher.seal(plaintext, aad))
    const second = fields(await cipher.seal(plaintext, aad))
    expect(first[2]).not.toEqual(second[2])
    expect(first[3]).not.toEqual(second[3])
  })
})

describe('EpochCipherRing', () => {
  it('has no current cipher until one is installed', () => {
    const ring = new EpochCipherRing()
    expect(() => ring.current()).toThrow('EPOCH_CIPHER_CURRENT_UNAVAILABLE')
    expect(ring.resolve(encodeCanonicalCbor(1n))).toBeUndefined()
    expect(ring.epochs()).toEqual([])
  })

  it('makes the first install current and only advances when asked', () => {
    const ring = new EpochCipherRing()
    const first = ring.install(keyA, 1n)
    const second = ring.install(keyB, 2n)
    expect(ring.current()).toBe(first)
    expect(ring.resolve(second.epochId)).toBe(second)
    ring.install(keyB, 2n, true)
    expect(ring.current()).toBe(second)
    expect(ring.epochs()).toEqual([1n, 2n])
  })

  it('keeps the originally installed key when an epoch is reinstalled with a different key', async () => {
    const ring = new EpochCipherRing()
    const original = ring.install(keyA, 5n)
    const reinstalled = ring.install(keyB, 5n, true)
    expect(reinstalled).toBe(original)
    const sealed = await createEpochEnvelopeCipher(keyB, 5n).seal(plaintext, aad)
    await expectAuthFailure(ring.resolve(encodeCanonicalCbor(5n))!.open(sealed, aad))
  })

  it('refuses to remove the current epoch and forgets removed epochs', async () => {
    const ring = new EpochCipherRing()
    const old = ring.install(keyA, 1n)
    ring.install(keyB, 2n, true)
    expect(() => ring.remove(2n)).toThrow('EPOCH_CIPHER_CURRENT_REMOVAL_PROHIBITED')
    const sealedUnderOld = await old.seal(plaintext, aad)
    ring.remove(1n)
    expect(ring.resolve(old.epochId)).toBeUndefined()
    expect(ring.epochs()).toEqual([2n])
    // Removing an unknown epoch is a no-op.
    ring.remove(99n)
    expect(ring.epochs()).toEqual([2n])
    // The current cipher cannot open data sealed under the removed epoch.
    await expect(ring.current().open(sealedUnderOld, aad)).rejects.toThrow('EPOCH_CIPHERTEXT_INVALID')
  })

  it('does not resolve epoch ids that differ only by encoding', () => {
    const ring = new EpochCipherRing()
    ring.install(keyA, 1n)
    expect(ring.resolve(Uint8Array.of(0x18, 0x01))).toBeUndefined()
    expect(ring.resolve(encodeCanonicalCbor(1n))).toBeDefined()
  })

  it('reports installed epochs in ascending numeric order', () => {
    const ring = new EpochCipherRing()
    for (const epoch of [10n, 2n, 300n, 0n]) ring.install(keyA, epoch)
    expect(ring.epochs()).toEqual([0n, 2n, 10n, 300n])
  })
})

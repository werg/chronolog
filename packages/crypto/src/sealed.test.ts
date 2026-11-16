import { describe, expect, it } from 'vitest'
import { utf8, type SealedContext, type SealedEnvelope } from '@chronolog/protocol'

import { generateX25519KeyPair } from './hpke.js'
import { openSealedValue, sealSealedValue } from './sealed.js'

const bytes = (seed: number): Uint8Array => new Uint8Array(32).fill(seed)
const context = (): SealedContext => ({ groupId: bytes(1), policyId: bytes(2), policyVersion: 1n, slot: 'body', dataVersion: 1n })

describe('sealed row values', () => {
  it('encrypts exactly a pooled Buffer subview and does not zero caller-owned memory', async () => {
    const reader = await generateX25519KeyPair()
    const backing = Buffer.allocUnsafe(128).fill(0xa5)
    const plaintext = backing.subarray(37, 48)
    plaintext.set(utf8('private row'))
    const original = Uint8Array.from(backing)
    const expected = Uint8Array.from(plaintext)
    expect(plaintext.byteOffset).toBeGreaterThan(0)
    expect(plaintext.buffer.byteLength).toBeGreaterThan(plaintext.byteLength)
    const expectedContext = context()
    const envelope = await sealSealedValue({ context: expectedContext, plaintext, recipients: [{ readerId: bytes(4), publicKey: reader.publicKeyBytes }] })
    // Check lengths first: a regression must not print unrelated pooled bytes.
    expect(envelope.ciphertext.byteLength).toBe(expected.byteLength + 16)
    const opened = await openSealedValue({ envelope, expectedContext, readerId: bytes(4), recipientPrivateKey: reader.privateKey })
    expect(opened.byteLength).toBe(expected.byteLength)
    expect(opened).toEqual(expected)
    expect(Uint8Array.from(backing)).toEqual(original)
  })

  it('snapshots Buffer plaintext, recipient ids and public keys before asynchronous sealing', async () => {
    const reader = await generateX25519KeyPair()
    const plaintext = Buffer.from('immutable buffer input')
    const expected = Uint8Array.from(plaintext)
    const recipient = { readerId: Buffer.from(bytes(4)), publicKey: Buffer.from(reader.publicKeyBytes) }
    const expectedContext = context()
    const pending = sealSealedValue({ context: expectedContext, plaintext, recipients: [recipient] })
    plaintext.fill(0xa5)
    recipient.readerId.fill(0xa6)
    recipient.publicKey.fill(0xa7)
    const envelope = await pending
    expect(envelope.wraps[0]!.readerId).toEqual(bytes(4))
    expect(envelope.wraps[0]!.publicKey).toEqual(reader.publicKeyBytes)
    expect(envelope.ciphertext.byteLength).toBe(expected.byteLength + 16)
    expect(await openSealedValue({ envelope, expectedContext, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).toEqual(expected)
    expect(plaintext.every((byte) => byte === 0xa5)).toBe(true)
  })

  it('opens only for explicit recipients, encrypts afresh, and never implicitly includes an owner', async () => {
    const [alice, bob, owner] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair(), generateX25519KeyPair()])
    const plaintext = utf8('secret notes for Alice and Bob')
    const input = {
      context: context(), plaintext,
      recipients: [{ readerId: bytes(5), publicKey: bob.publicKeyBytes }, { readerId: bytes(4), publicKey: alice.publicKeyBytes }],
    }
    const first = await sealSealedValue(input)
    const second = await sealSealedValue(input)
    expect(first.wraps.map((wrap) => wrap.readerId)).toEqual([bytes(4), bytes(5)])
    expect(first.nonce).not.toEqual(second.nonce)
    expect(first.ciphertext).not.toEqual(second.ciphertext)
    expect(first.wraps[0]!.encapsulatedKey).not.toEqual(second.wraps[0]!.encapsulatedKey)
    expect(await openSealedValue({ envelope: first, expectedContext: input.context, readerId: bytes(4), recipientPrivateKey: alice.privateKey })).toEqual(plaintext)
    expect(await openSealedValue({ envelope: first, expectedContext: input.context, readerId: bytes(5), recipientPrivateKey: bob.privateKey })).toEqual(plaintext)
    await expect(openSealedValue({ envelope: first, expectedContext: input.context, readerId: bytes(6), recipientPrivateKey: owner.privateKey })).rejects.toMatchObject({ code: 'INVALID_KEY' })
    await expect(openSealedValue({ envelope: first, expectedContext: input.context, readerId: bytes(4), recipientPrivateKey: owner.privateKey })).rejects.toBeDefined()
    expect(plaintext).toEqual(utf8('secret notes for Alice and Bob'))
  })

  it('requires the expected group, policy, policy version, column and data version', async () => {
    const reader = await generateX25519KeyPair()
    const expectedContext = context()
    const envelope = await sealSealedValue({ context: expectedContext, plaintext: utf8('value'), recipients: [{ readerId: bytes(4), publicKey: reader.publicKeyBytes }] })
    for (const change of [
      { groupId: bytes(9) }, { policyId: bytes(9) }, { policyVersion: 2n }, { slot: 'other' }, { dataVersion: 2n },
    ]) {
      const changed = { ...expectedContext, ...change }
      await expect(openSealedValue({ envelope, expectedContext: changed, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
      // Even if an attacker rewrites both the supplied metadata and the envelope,
      // the original HPKE wrap and payload remain bound to their old context.
      await expect(openSealedValue({ envelope: { ...envelope, context: changed }, expectedContext: changed, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).rejects.toBeDefined()
    }
  })

  it('authenticates ciphertext, nonce, recipient id, HPKE key and wrapped content key', async () => {
    const [reader, other] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()])
    const expectedContext = context()
    const original = await sealSealedValue({ context: expectedContext, plaintext: utf8('value'), recipients: [{ readerId: bytes(4), publicKey: reader.publicKeyBytes }] })
    const tamper = (value: Uint8Array): Uint8Array => { const copy = value.slice(); copy[0]! ^= 1; return copy }
    const wrap = original.wraps[0]!
    const changes: SealedEnvelope[] = [
      { ...original, ciphertext: tamper(original.ciphertext) },
      { ...original, nonce: tamper(original.nonce) },
      { ...original, wraps: [{ ...wrap, publicKey: other.publicKeyBytes }] },
      { ...original, wraps: [{ ...wrap, encapsulatedKey: tamper(wrap.encapsulatedKey) }] },
      { ...original, wraps: [{ ...wrap, ciphertext: tamper(wrap.ciphertext) }] },
    ]
    for (const envelope of changes) {
      await expect(openSealedValue({ envelope, expectedContext, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).rejects.toBeDefined()
    }
    await expect(openSealedValue({
      envelope: { ...original, wraps: [{ ...wrap, readerId: bytes(9) }] }, expectedContext,
      readerId: bytes(9), recipientPrivateKey: reader.privateKey,
    })).rejects.toBeDefined()
  })

  it('removes access to future values without pretending to revoke historical plaintext', async () => {
    const [alice, bob] = await Promise.all([generateX25519KeyPair(), generateX25519KeyPair()])
    const oldContext = context()
    const oldValue = await sealSealedValue({
      context: oldContext, plaintext: utf8('before removal'),
      recipients: [{ readerId: bytes(4), publicKey: alice.publicKeyBytes }, { readerId: bytes(5), publicKey: bob.publicKeyBytes }],
    })
    const nextContext = { ...oldContext, policyVersion: 2n, dataVersion: 2n }
    const nextValue = await sealSealedValue({ context: nextContext, plaintext: utf8('after removal'), recipients: [{ readerId: bytes(4), publicKey: alice.publicKeyBytes }] })
    expect(await openSealedValue({ envelope: oldValue, expectedContext: oldContext, readerId: bytes(5), recipientPrivateKey: bob.privateKey })).toEqual(utf8('before removal'))
    await expect(openSealedValue({ envelope: nextValue, expectedContext: nextContext, readerId: bytes(5), recipientPrivateKey: bob.privateKey })).rejects.toMatchObject({ code: 'INVALID_KEY' })
    expect(await openSealedValue({ envelope: nextValue, expectedContext: nextContext, readerId: bytes(4), recipientPrivateKey: alice.privateKey })).toEqual(utf8('after removal'))
  })

  it('rejects empty or duplicate recipients and snapshots inputs before asynchronous crypto', async () => {
    const reader = await generateX25519KeyPair()
    const recipient = { readerId: bytes(4), publicKey: reader.publicKeyBytes }
    await expect(sealSealedValue({ context: context(), plaintext: new Uint8Array(), recipients: [] })).rejects.toBeDefined()
    await expect(sealSealedValue({ context: context(), plaintext: new Uint8Array(), recipients: [recipient, recipient] })).rejects.toBeDefined()
    const suppliedContext = context()
    const expectedContext = context()
    const plaintext = utf8('immutable input')
    const pending = sealSealedValue({ context: suppliedContext, plaintext, recipients: [recipient] })
    plaintext.fill(0)
    suppliedContext.groupId.fill(0)
    recipient.readerId.fill(0)
    recipient.publicKey.fill(0)
    const envelope = await pending
    expect(await openSealedValue({ envelope, expectedContext, readerId: bytes(4), recipientPrivateKey: reader.privateKey })).toEqual(utf8('immutable input'))
  })
})

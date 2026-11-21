import { describe, expect, it } from 'vitest'
import { utf8 } from '@chronolog/protocol'
import {
  decryptEpochPayload,
  encryptEpochPayload,
  exportX25519PrivateKey,
  generateX25519KeyPair,
  hpkeOpenBase,
  hpkeSealBase,
  hpkeSendExportBase,
  hpkeReceiveExportBase,
  importX25519PrivateKey,
} from './index.js'

const bytes = (value: number, length = 32) => new Uint8Array(length).fill(value)
const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'))

describe('RFC 9180 base-mode adapter', () => {
  it('imports pooled Buffer keys and opens only the supplied Buffer payload/AAD ranges', async () => {
    const recipient = await generateX25519KeyPair()
    const privateKey = await importX25519PrivateKey(Buffer.from(await exportX25519PrivateKey(recipient.privateKey)))
    const publicKey = Buffer.from(recipient.publicKeyBytes)
    const backing = Buffer.allocUnsafe(96).fill(0xa5)
    const plaintext = backing.subarray(20, 31)
    plaintext.set(utf8('private row'))
    const expected = Uint8Array.from(plaintext)
    const info = Buffer.from('buffer info')
    const aad = Buffer.from('buffer aad')
    const sealed = await hpkeSealBase(publicKey, plaintext, info, aad)
    expect(sealed.ciphertext.byteLength).toBe(expected.byteLength + 16)
    const opened = await hpkeOpenBase(privateKey, publicKey, Buffer.from(sealed.encapsulatedKey), Buffer.from(sealed.ciphertext), info, aad)
    expect(opened.byteLength).toBe(expected.byteLength)
    expect(opened).toEqual(expected)
    expect(Uint8Array.from(plaintext)).toEqual(expected)
  })

  it('opens the published CFRG X25519/HKDF-SHA256/AES-256-GCM vector', async () => {
    const privateKey = await importX25519PrivateKey(hex(
      '302e020100300506032b656e04220420' +
      '497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d',
    ))
    const plaintext = await hpkeOpenBase(
      privateKey,
      hex('430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c'),
      hex('6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256'),
      hex('e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a'),
      hex('4f6465206f6e2061204772656369616e2055726e'),
      hex('436f756e742d30'),
    )
    expect(plaintext).toEqual(hex('4265617574792069732074727574682c20747275746820626561757479'))
  })

  it('matches all published CFRG AES-256-GCM exported-secret vectors', async () => {
    const privateKey = await importX25519PrivateKey(hex('302e020100300506032b656e04220420' +
      '497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d'))
    for (const [context, expected] of [
      ['', 'ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a'],
      ['00', '04d3cb6cc116b28ffd22ad5bc276c60d31fec71ceb87ae24db811c64b7507339'],
      ['54657374436f6e74657874', '7c5ded445732c14fe09727d29b4251c0fd38455fe8440571e687f0886aac94d2'],
    ]) {
      expect(await hpkeReceiveExportBase(privateKey,
        hex('430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c'),
        hex('6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256'),
        hex('4f6465206f6e2061204772656369616e2055726e'), hex(context!), 32)).toEqual(hex(expected!))
    }
  })

  it('exports matching application secrets bound to context, recipient and fresh encapsulation', async () => {
    const recipient = await generateX25519KeyPair(false), other = await generateX25519KeyPair(false)
    const info = utf8('signed peer transcript'), label = utf8('independent reliable/live keys')
    const sent = await hpkeSendExportBase(recipient.publicKeyBytes, info, label, 88)
    const receive = (context = label, transcript = info, key = recipient) => hpkeReceiveExportBase(
      key.privateKey, key.publicKeyBytes, sent.encapsulatedKey, transcript, context, 88)
    expect(await receive()).toEqual(sent.exportedSecret)
    expect(await receive(utf8('another purpose'))).not.toEqual(sent.exportedSecret)
    expect(await receive(label, utf8('another connection'))).not.toEqual(sent.exportedSecret)
    expect(await receive(label, info, other)).not.toEqual(sent.exportedSecret)
    expect((await hpkeSendExportBase(recipient.publicKeyBytes, info, label, 88)).exportedSecret).not.toEqual(sent.exportedSecret)
    await expect(hpkeSendExportBase(recipient.publicKeyBytes, info, label, 8161)).rejects.toThrow('HKDF output is too long')
    await expect(hpkeReceiveExportBase(recipient.privateKey, recipient.publicKeyBytes, new Uint8Array(32), info, label, 88)).rejects.toThrow('X25519')
  })

  it('seals to an X25519 recipient and authenticates info and AAD', async () => {
    const recipient = await generateX25519KeyPair()
    const info = utf8('chronolog epoch context')
    const aad = utf8('group/epoch/recipient')
    const plaintext = bytes(7)
    const sealed = await hpkeSealBase(recipient.publicKeyBytes, plaintext, info, aad)
    expect(sealed.encapsulatedKey).toHaveLength(32)
    expect(await hpkeOpenBase(recipient.privateKey, recipient.publicKeyBytes, sealed.encapsulatedKey, sealed.ciphertext, info, aad)).toEqual(plaintext)
    await expect(hpkeOpenBase(recipient.privateKey, recipient.publicKeyBytes, sealed.encapsulatedKey, sealed.ciphertext, info, utf8('wrong'))).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })

  it('does not open to another recipient', async () => {
    const recipient = await generateX25519KeyPair()
    const other = await generateX25519KeyPair()
    const sealed = await hpkeSealBase(recipient.publicKeyBytes, bytes(1), new Uint8Array(), new Uint8Array())
    await expect(hpkeOpenBase(other.privateKey, other.publicKeyBytes, sealed.encapsulatedKey, sealed.ciphertext, new Uint8Array(), new Uint8Array())).rejects.toBeDefined()
  })
})

describe('epoch payload encryption', () => {
  it('encrypts and decrypts exactly the supplied pooled Buffer views', async () => {
    const key = Buffer.from(bytes(9))
    const backing = Buffer.allocUnsafe(96).fill(0xa5)
    const plaintext = backing.subarray(20, 31)
    plaintext.set(utf8('private row'))
    const expected = Uint8Array.from(plaintext)
    const aad = Buffer.from('visible header')
    const encrypted = await encryptEpochPayload(key, 12n, plaintext, aad)
    expect(encrypted.ciphertext.byteLength).toBe(expected.byteLength + 16)
    const opened = await decryptEpochPayload(key, {
      ...encrypted, nonce: Buffer.from(encrypted.nonce), ciphertext: Buffer.from(encrypted.ciphertext),
    }, aad)
    expect(opened.byteLength).toBe(expected.byteLength)
    expect(opened).toEqual(expected)
    expect(Uint8Array.from(plaintext)).toEqual(expected)
  })

  it('encrypts payloads with the epoch and caller routing header bound as AAD', async () => {
    const key = bytes(9)
    const encrypted = await encryptEpochPayload(key, 12n, utf8('private transaction'), utf8('visible header'))
    expect(await decryptEpochPayload(key, encrypted, utf8('visible header'))).toEqual(utf8('private transaction'))
    await expect(decryptEpochPayload(key, encrypted, utf8('different header'))).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
    await expect(decryptEpochPayload(key, { ...encrypted, epoch: 13n }, utf8('visible header'))).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })
})

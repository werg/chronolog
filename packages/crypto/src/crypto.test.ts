import { describe, expect, it } from 'vitest'
import { p256 } from '@noble/curves/nist.js'
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { bytesToHex, utf8 } from '@chronolog/protocol'
import {
  decryptEpochPayload,
  deriveEpochMailboxKeyPair,
  ed25519PublicKeyFromSeedSync,
  hpkeBaseKeySchedule,
  encryptEpochPayload,
  exportX25519PrivateKey,
  generateX25519KeyPair,
  generateXWingKeyPair,
  hmacSha256Sync,
  hpkeOpenBase,
  hpkeSealBase,
  hpkeSendExportBase,
  hpkeReceiveExportBase,
  importX25519PrivateKey,
  padPlaintext,
  signEd25519Sync,
  unpadPlaintext,
  verifyEd25519Sync,
  verifyP256Sync,
  xwingOpenBase,
  xwingPublicKeyFromSeed,
  xwingSealBase,
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
    expect(encrypted.ciphertext.byteLength).toBe(1 + expected.byteLength + 16)
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

  it('uses hkdf-aes-256-gcm (192-bit salt) with power-of-two bucket padding', async () => {
    const key = bytes(0x33)
    const aad = utf8('log/op/anon')
    const shortMsg = utf8('hi')
    const medMsg = utf8('a slightly longer message inside the same bucket')
    const enc1 = await encryptEpochPayload(key, 3n, shortMsg, aad, undefined, { paddingBucketBytes: 256 })
    const enc2 = await encryptEpochPayload(key, 3n, medMsg, aad, undefined, { paddingBucketBytes: 256 })
    expect(enc1.nonce).toHaveLength(24)
    expect(enc1.ciphertext.byteLength).toBe(256 + 16)
    expect(enc2.ciphertext.byteLength).toBe(256 + 16)
    expect(await decryptEpochPayload(key, enc1, aad)).toEqual(shortMsg)
    expect(await decryptEpochPayload(key, enc2, aad)).toEqual(medMsg)
    expect(unpadPlaintext(padPlaintext(shortMsg, 0))).toEqual(shortMsg)
    const padded = padPlaintext(shortMsg, 128)
    expect(padded).toHaveLength(128)
    expect(unpadPlaintext(padded)).toEqual(shortMsg)
    padded[127] = 1
    expect(() => unpadPlaintext(padded)).toThrow()
  })

  it('has exactly one suite: rejects 12-byte nonces and applies padding by default path', async () => {
    const key = bytes(0x34)
    const aad = utf8('aad')
    await expect(encryptEpochPayload(key, 1n, utf8('x'), aad, new Uint8Array(12))).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
    const enc = await encryptEpochPayload(key, 1n, utf8('x'), aad, undefined, { paddingBucketBytes: 64 })
    expect(enc.nonce).toHaveLength(24)
    expect(enc.ciphertext.byteLength).toBe(64 + 16)
    await expect(decryptEpochPayload(key, { ...enc, nonce: enc.nonce.subarray(0, 12) }, aad)).rejects.toMatchObject({ code: 'SCHEMA_INVALID' })
  })
})

describe('hybrid post-quantum X-Wing HPKE, P-256, HMAC, and mailbox derivation', () => {
  it('seals and opens X-Wing (ML-KEM-768 + X25519) ciphertexts with deterministic seed derivation', async () => {
    const seed = bytes(0x42, 32)
    const kp = generateXWingKeyPair(seed)
    expect(kp.publicKey).toHaveLength(1216)
    expect(kp.secretKey).toHaveLength(32)
    expect(xwingPublicKeyFromSeed(seed)).toEqual(kp.publicKey)

    const plaintext = bytes(0x99, 32)
    const info = utf8('chronolog/epoch-key/v2:test:0')
    const aad = utf8('epoch:0')
    const sealed = await xwingSealBase(kp.publicKey, plaintext, info, aad)
    expect(sealed.encapsulatedKey).toHaveLength(1120)
    expect(await xwingOpenBase(kp.secretKey, sealed.encapsulatedKey, sealed.ciphertext, info, aad)).toEqual(plaintext)
    await expect(xwingOpenBase(kp.secretKey, sealed.encapsulatedKey, sealed.ciphertext, info, utf8('wrong'))).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })

    const other = generateXWingKeyPair()
    await expect(xwingOpenBase(other.secretKey, sealed.encapsulatedKey, sealed.ciphertext, info, aad)).rejects.toMatchObject({ code: 'INVALID_SIGNATURE' })
  })

  it('uses the RFC 9180 mode_base key schedule with X-Wing KEM 0x647a', async () => {
    const kp = generateXWingKeyPair(bytes(0x43, 32))
    const plaintext = utf8('rfc9180 xwing')
    const info = utf8('info'), aad = utf8('aad')
    const sealed = await xwingSealBase(kp.publicKey, plaintext, info, aad)
    const sharedSecret = ml_kem768_x25519.decapsulate(sealed.encapsulatedKey, kp.secretKey)
    const suiteId = Uint8Array.of(0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x02)
    const ks = await hpkeBaseKeySchedule(suiteId, sharedSecret, info)
    const k = await crypto.subtle.importKey('raw', Uint8Array.from(ks.key), 'AES-GCM', false, ['decrypt'])
    const opened = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Uint8Array.from(ks.nonce), additionalData: Uint8Array.from(aad) }, k, Uint8Array.from(sealed.ciphertext)))
    expect(opened).toEqual(plaintext)
  })

  it('verifies NIST P-256 WebAuthn compact & DER signatures, HMAC-SHA256, and epoch mailbox keys', () => {
    // RFC 4231 test case 2 for HMAC-SHA256
    const mac = hmacSha256Sync(utf8('Jefe'), utf8('what do ya want for nothing?'))
    expect(bytesToHex(mac)).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')

    const priv = p256.utils.randomSecretKey()
    const pubUncompressed = p256.getPublicKey(priv, false)
    const pubCompressed = p256.getPublicKey(priv, true)
    const msg = utf8('webauthn-challenge-payload')
    const compactSig = p256.sign(msg, priv, { format: 'compact' })
    const derSig = p256.sign(msg, priv, { format: 'der' })
    expect(verifyP256Sync(pubUncompressed, msg, compactSig, 'compact')).toBe(true)
    expect(verifyP256Sync(pubCompressed, msg, derSig, 'der')).toBe(true)
    expect(verifyP256Sync(pubUncompressed, utf8('tampered'), derSig, 'der')).toBe(false)
    // Format is explicit: a DER signature is never accepted as compact and vice versa.
    expect(verifyP256Sync(pubUncompressed, msg, derSig, 'compact')).toBe(false)
    expect(verifyP256Sync(pubUncompressed, msg, compactSig, 'der')).toBe(false)

    // Regression: a 64-byte compact signature whose r starts with 0x30 used to be misparsed as DER.
    let found: { readonly m: Uint8Array; readonly sig: Uint8Array } | null = null
    for (let i = 0; i < 20_000 && found === null; i++) {
      const m = utf8(`webauthn-r30-${i}`)
      const sig = p256.sign(m, priv, { format: 'compact' })
      if (sig[0] === 0x30) found = { m, sig }
    }
    expect(found).not.toBeNull()
    expect(verifyP256Sync(pubUncompressed, found!.m, found!.sig, 'compact')).toBe(true)

    const epochKey = bytes(0x77, 32)
    const mb = deriveEpochMailboxKeyPair(epochKey)
    expect(mb.publicKey).toHaveLength(32)
    const tag = signEd25519Sync(mb.seed, utf8('envelope-header'))
    expect(verifyEd25519Sync(mb.publicKey, utf8('envelope-header'), tag)).toBe(true)
    expect(verifyEd25519Sync(mb.publicKey, utf8('other'), tag)).toBe(false)
  })

  it('verifies Ed25519 under one strict rule set (non-canonical S and small-order keys rejected)', () => {
    const seed = bytes(0x42, 32)
    const pub = ed25519PublicKeyFromSeedSync(seed)
    const msg = utf8('strict-ed25519')
    const sig = signEd25519Sync(seed, msg)
    expect(verifyEd25519Sync(pub, msg, sig)).toBe(true)

    // S + L (non-canonical scalar) must be rejected.
    const L = (1n << 252n) + 27742317777372353535851937790883648493n
    let s = 0n
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]!)
    const sPlusL = s + L
    if (sPlusL < (1n << 256n)) {
      const malleated = sig.slice()
      let v = sPlusL
      for (let i = 32; i < 64; i++) { malleated[i] = Number(v & 0xffn); v >>= 8n }
      expect(verifyEd25519Sync(pub, msg, malleated)).toBe(false)
    }

    // Small-order public key (identity point) with identity R and S = 0 verifies under ZIP-215 but not here.
    const identity = new Uint8Array(32)
    identity[0] = 1
    const forged = new Uint8Array(64)
    forged[0] = 1
    expect(verifyEd25519Sync(identity, msg, forged)).toBe(false)
  })
})

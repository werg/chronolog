import { describe, expect, it } from 'vitest'
import { assertCanonicalCbor, bytesToHex, DEFAULT_DECODE_LIMITS, encodeCanonicalCbor, type CborMapKey, type CborValue } from '@chronolog/canonical'
import { generateEd25519KeyPair } from './primitives.js'
import {
  compareOperationOrder,
  decodeEncryptedEnvelope,
  decodeLogGenesis,
  decodeOperationCore,
  encodeEncryptedEnvelope,
  encodeLogGenesis,
  encodeOperationCore,
  encryptedEnvelopeDigest,
  envelopeAad,
  genesisLogId,
  normalizeJsonValue,
  operationIdDigest,
  signOperationCore,
  verifySignedOperation,
  type LogGenesis,
  type OperationCore,
} from './v2.js'

describe('protocol v2 codecs', () => {
  it('encodes, decodes, and hashes LogGenesis deterministically', () => {
    const modHash = 'a'.repeat(64)
    const genesis: LogGenesis = {
      version: 1,
      privateLog: true,
      initialTopics: {
        $reducers: {
          runtime: { js: 'quickjs-ng@1', builtins: { 'chronolog:crypto': 'crypto@1' } },
          imports: { 'chronolog/admission': `cas:sha256-${modHash}` },
          topics: { $admission: { module: 'chronolog/admission', export: 'attestedAdmission' } },
        },
        $admission: { members: [] },
      },
      limits: { maxMemoryBytes: 32 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 32, maxFuel: 100_000 },
      salt: new Uint8Array(16).fill(7),
    }
    const bytes = encodeLogGenesis(genesis)
    const decoded = decodeLogGenesis(bytes)
    expect(decoded).toEqual(genesis)
    expect(bytesToHex(genesisLogId(bytes))).toBe(bytesToHex(genesisLogId(decoded)))
  })

  it('requires maxFuel in genesis limits (no implementation default)', () => {
    const genesis: LogGenesis = {
      version: 1,
      privateLog: false,
      initialTopics: { $reducers: { runtime: { js: 'quickjs-ng@1', builtins: {} }, imports: {}, topics: {} } },
      limits: { maxMemoryBytes: 1024, maxTopicStateBytes: 1024, maxUpdatesPerOp: 4, maxFuel: 10 },
      salt: new Uint8Array(16).fill(1),
    }
    const map = assertCanonicalCbor(encodeLogGenesis(genesis), DEFAULT_DECODE_LIMITS) as Map<CborMapKey, CborValue>
    const limits = new Map(map.get(3n) as Map<CborMapKey, CborValue>)
    expect(limits.get(3n)).toBe(10n)
    limits.delete(3n)
    const withoutFuel = encodeCanonicalCbor(new Map([...map, [3n, limits]]))
    expect(() => decodeLogGenesis(withoutFuel)).toThrow(/Invalid genesis limits/)
    const { maxFuel: _omit, ...partial } = genesis.limits
    expect(() => encodeLogGenesis({ ...genesis, limits: partial as LogGenesis['limits'] })).toThrow(/Invalid genesis limits/)
  })

  it('signs, verifies, and orders flat timestamp operations', async () => {
    const keys = await generateEd25519KeyPair()
    const logId = new Uint8Array(32).fill(1)
    const opA: OperationCore = {
      version: 1,
      logId,
      author: keys.publicKeyBytes,
      operationId: 'op-1',
      authorTimestampMs: 100n,
      nonce: new Uint8Array(16).fill(2),
      visibility: 'public',
      updates: [{ topic: '$admission', input: { action: 'add', member: 'abc' } }],
    }
    const signed = await signOperationCore(opA, keys.privateKey)
    const verified = await verifySignedOperation(signed)
    expect(verified.core).toEqual(opA)
    expect(verified.opId).toEqual(operationIdDigest(opA))

    const opB: OperationCore = { ...opA, operationId: 'op-2', authorTimestampMs: 200n }
    const idA = operationIdDigest(encodeOperationCore(opA))
    const idB = operationIdDigest(encodeOperationCore(opB))
    expect(compareOperationOrder(
      { authorTimestampMs: opA.authorTimestampMs, author: opA.author, opId: idA },
      { authorTimestampMs: opB.authorTimestampMs, author: opB.author, opId: idB },
    )).toBeLessThan(0)
    expect(decodeOperationCore(encodeOperationCore(opB))).toEqual(opB)
  })

  it('produces distinct envelopeDigests for rewrapped epochs of the same opId', () => {
    const logId = new Uint8Array(32).fill(3)
    const opId = new Uint8Array(32).fill(4)
    const author = new Uint8Array(32).fill(5)
    const env0 = { version: 1 as const, logId, opId, author, epoch: 0, nonce: new Uint8Array(24).fill(1), ciphertext: new Uint8Array([1, 2, 3]) }
    const env1 = { version: 1 as const, logId, opId, author, epoch: 1, nonce: new Uint8Array(24).fill(2), ciphertext: new Uint8Array([4, 5, 6]) }
    expect(decodeEncryptedEnvelope(encodeEncryptedEnvelope(env0))).toEqual(env0)
    expect(bytesToHex(encryptedEnvelopeDigest(env0))).not.toBe(bytesToHex(encryptedEnvelopeDigest(env1)))
  })

  it('has one envelope AEAD suite: only 24-byte HKDF salts, no suite field, ring bound into the AAD', () => {
    const logId = new Uint8Array(32).fill(3)
    const opId = new Uint8Array(32).fill(4)
    const author = new Uint8Array(32).fill(5)
    const legacy = { version: 1 as const, logId, opId, author, epoch: 0, nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([1]) }
    expect(() => encodeEncryptedEnvelope(legacy)).toThrow('Invalid ciphertext/nonce')
    // A field-8 suite string (the removed legacy selector) is not a valid mailbox tag.
    const env = { ...legacy, nonce: new Uint8Array(24).fill(1) }
    const map = assertCanonicalCbor(encodeEncryptedEnvelope(env), DEFAULT_DECODE_LIMITS) as Map<CborMapKey, CborValue>
    map.set(8n, 'hkdf-aes-256-gcm')
    expect(() => decodeEncryptedEnvelope(encodeCanonicalCbor(map))).toThrow()
    const ringed = { ...env, ring: 'team', mailboxTag: new Uint8Array(64).fill(9) }
    expect(decodeEncryptedEnvelope(encodeEncryptedEnvelope(ringed))).toEqual(ringed)
    expect(bytesToHex(envelopeAad(logId, opId, author, 'default'))).not.toBe(bytesToHex(envelopeAad(logId, opId, author, 'team')))
    expect(() => envelopeAad(logId, opId, author, '')).toThrow()
  })

  it('rejects non-JSON / non-finite / -0 values cleanly', () => {
    expect(normalizeJsonValue(-0)).toBe(0)
    expect(() => normalizeJsonValue(Number.NaN)).toThrow()
    expect(() => normalizeJsonValue(Number.POSITIVE_INFINITY)).toThrow()
    expect(() => normalizeJsonValue(undefined)).toThrow()
  })
})

import { describe, expect, it } from 'vitest'
import { bytesToHex } from '@chronolog/canonical'
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
          imports: { 'chronolog/permissions': `cas:sha256-${modHash}` },
          topics: { $permissions: { module: 'chronolog/permissions', export: 'attestedMembers' } },
        },
        $permissions: { members: [] },
      },
      limits: { maxMemoryBytes: 32 * 1024 * 1024, maxTopicStateBytes: 65_536, maxUpdatesPerOp: 32 },
      salt: new Uint8Array(16).fill(7),
    }
    const bytes = encodeLogGenesis(genesis)
    const decoded = decodeLogGenesis(bytes)
    expect(decoded).toEqual(genesis)
    expect(bytesToHex(genesisLogId(bytes))).toBe(bytesToHex(genesisLogId(decoded)))
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
      updates: [{ topic: '$permissions', input: { action: 'add', member: 'abc' } }],
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
    const env0 = { version: 1 as const, logId, opId, author, epoch: 0, nonce: new Uint8Array(12).fill(1), ciphertext: new Uint8Array([1, 2, 3]) }
    const env1 = { version: 1 as const, logId, opId, author, epoch: 1, nonce: new Uint8Array(12).fill(2), ciphertext: new Uint8Array([4, 5, 6]) }
    expect(decodeEncryptedEnvelope(encodeEncryptedEnvelope(env0))).toEqual(env0)
    expect(bytesToHex(encryptedEnvelopeDigest(env0))).not.toBe(bytesToHex(encryptedEnvelopeDigest(env1)))
  })

  it('rejects non-JSON / non-finite / -0 values cleanly', () => {
    expect(normalizeJsonValue(-0)).toBe(0)
    expect(() => normalizeJsonValue(Number.NaN)).toThrow()
    expect(() => normalizeJsonValue(Number.POSITIVE_INFINITY)).toThrow()
    expect(() => normalizeJsonValue(undefined)).toThrow()
  })
})

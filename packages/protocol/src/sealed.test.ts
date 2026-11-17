import { describe, expect, it } from 'vitest'

import {
  MAX_SEALED_PLAINTEXT_BYTES, MAX_SEALED_VERSION, SEALED_OP_CODES,
  decodeSealedEnvelope, encodeSealedEnvelope, sealedContextToCanonicalCbor,
  sealedEnvelopeFromCanonicalCbor, sealedEnvelopeToCanonicalCbor, sealedOp,
  sealedPlatformOpFromCanonicalCbor, sealedPlatformOpToCanonicalCbor,
  type SealedEnvelope, type SealedPlatformOp,
} from './sealed.js'
import { assertCanonicalCbor, encodeCanonicalCbor, type CborValue } from './cbor.js'
import { decodePlatformOp, encodePlatformOp, isPlatformOp } from './platform.js'
import { decodeChangeProgram, encodeChangeProgram, isSqlStatementStep, MAX_PROGRAM_BYTES, program } from './program.js'

const bytes = (seed: number, length = 32): Uint8Array => new Uint8Array(length).fill(seed)
const envelope = (): SealedEnvelope => ({
  context: { groupId: bytes(1), policyId: bytes(2), policyVersion: 1n, slot: 'body', dataVersion: 1n },
  nonce: bytes(3, 12), ciphertext: bytes(4, 20),
  wraps: [{ readerId: bytes(5), publicKey: bytes(6), encapsulatedKey: bytes(7), ciphertext: bytes(8, 48) }],
})

function roundTrip(op: SealedPlatformOp): SealedPlatformOp {
  return sealedPlatformOpFromCanonicalCbor(assertCanonicalCbor(encodeCanonicalCbor(sealedPlatformOpToCanonicalCbor(op))))
}

describe('sealed protocol', () => {
  it('carries sealed operations through the platform wire codec and mixed SQL program codec', () => {
    const operations = [
      sealedOp.registerReaderKey(bytes(6)),
      sealedOp.readerPolicy({ table: 'notes', rowKey: [1n], expectedVersion: 0n, readers: [bytes(5)] }),
      sealedOp.put({ policyId: bytes(2), expectedPolicyVersion: 1n, expectedDataVersion: 0n, slot: 'body', envelope: envelope() }),
    ]
    for (const op of operations) {
      expect(isPlatformOp(op)).toBe(true)
      expect(decodePlatformOp(encodePlatformOp(op))).toEqual(op)
    }
    const change = program('INSERT INTO notes (id) VALUES (1)', ...operations)
    const decoded = decodeChangeProgram(encodeChangeProgram(change))
    expect(decoded).toEqual(change)
    expect(decoded.steps.map(isSqlStatementStep)).toEqual([true, false, false, false])
  })

  it('round-trips bounded envelopes and all three reserved operations', () => {
    const value = envelope()
    expect(decodeSealedEnvelope(encodeSealedEnvelope(value))).toEqual(value)
    const operations = [
      sealedOp.registerReaderKey(bytes(9)),
      sealedOp.readerPolicy({ table: 'notes', rowKey: [1n, 'a'], expectedVersion: 0n, readers: [bytes(5), bytes(4)] }),
      sealedOp.readerPolicy({ table: 'notes', rowKey: [1n, 'a'], expectedPolicyId: bytes(2), expectedVersion: 1n, readers: [] }),
      sealedOp.put({ policyId: bytes(2), expectedPolicyVersion: 1n, expectedDataVersion: 0n, slot: 'body', envelope: value }),
    ]
    for (const op of operations) {
      expect(roundTrip(op)).toEqual(op)
      expect((sealedPlatformOpToCanonicalCbor(op) as Map<bigint, CborValue>).get(0n)).toBe(SEALED_OP_CODES[op.op])
    }
    const policy = operations[1]!
    expect(policy.op === 'reader_policy' ? policy.readers : []).toEqual([bytes(4), bytes(5)])
  })

  it('applies the complete change-program budget to otherwise valid sealed values', () => {
    const value = { ...envelope(), ciphertext: bytes(4, MAX_PROGRAM_BYTES) }
    expect(decodeSealedEnvelope(encodeSealedEnvelope(value))).toEqual(value)
    const step = sealedOp.put({ policyId: bytes(2), expectedPolicyVersion: 1n, expectedDataVersion: 0n, slot: 'body', envelope: value })
    expect(() => program(step)).toThrow('Change program is too large')
  })

  it('requires a generation id for replacement and prevents version overflow', () => {
    const create = { table: 'notes', rowKey: [1n], expectedVersion: 0n, readers: [bytes(5)] }
    expect(() => sealedOp.readerPolicy({ ...create, expectedPolicyId: bytes(2) })).toThrow()
    expect(() => sealedOp.readerPolicy({ ...create, expectedVersion: 1n })).toThrow()
    expect(() => sealedOp.readerPolicy({ ...create, expectedVersion: MAX_SEALED_VERSION, expectedPolicyId: bytes(2) })).toThrow()
    expect(() => sealedOp.readerPolicy({ ...create, expectedVersion: -1n })).toThrow()
    expect(() => sealedOp.put({ policyId: bytes(2), expectedPolicyVersion: 1n, expectedDataVersion: MAX_SEALED_VERSION, slot: 'body', envelope: envelope() })).toThrow()
  })

  it('rejects a put whose ciphertext context disagrees with its compare-and-swap fields', () => {
    const input = { policyId: bytes(2), expectedPolicyVersion: 1n, expectedDataVersion: 0n, slot: 'body', envelope: envelope() }
    for (const changed of [
      { policyId: bytes(3) }, { expectedPolicyVersion: 2n }, { expectedDataVersion: 1n }, { slot: 'other' },
    ]) expect(() => sealedOp.put({ ...input, ...changed })).toThrow()
  })

  it('requires canonical sorted distinct readers and key wraps', () => {
    const policy: SealedPlatformOp = {
      op: 'reader_policy', table: 'notes', rowKey: [{ kind: 'integer', value: 1n }], expectedVersion: 0n,
      readers: [bytes(9), bytes(5)],
    }
    expect(() => sealedPlatformOpToCanonicalCbor(policy)).toThrow()
    expect(() => sealedOp.readerPolicy({ table: 'notes', rowKey: [1n], expectedVersion: 0n, readers: [bytes(5), bytes(5)] })).toThrow()
    const value = envelope()
    const wrap = value.wraps[0]!
    expect(() => encodeSealedEnvelope({ ...value, wraps: [wrap, wrap] })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, wraps: [{ ...wrap, readerId: bytes(9) }, wrap] })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, wraps: [{ ...wrap, ciphertext: bytes(1, 47) }] })).toThrow()
  })

  it('rejects unknown critical fields, noncanonical CBOR, malformed ids and oversize values', () => {
    const value = envelope()
    const encoded = sealedEnvelopeToCanonicalCbor(value) as Map<bigint, CborValue>
    expect(() => sealedEnvelopeFromCanonicalCbor(new Map([...encoded, [99n, 1n]]))).toThrow()
    const context = sealedContextToCanonicalCbor(value.context) as Map<bigint, CborValue>
    expect(() => sealedEnvelopeFromCanonicalCbor(new Map([...encoded, [1n, new Map([...context, [99n, 1n]])]]))).toThrow()
    expect(() => decodeSealedEnvelope(Uint8Array.of(0x18, 0x00))).toThrow()
    expect(() => sealedPlatformOpFromCanonicalCbor(new Map([[0n, 67n]]))).toThrow()
    expect(() => sealedOp.registerReaderKey(bytes(1, 31))).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, nonce: bytes(1, 11) })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, ciphertext: bytes(1, 15) })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, ciphertext: bytes(1, MAX_SEALED_PLAINTEXT_BYTES + 17) })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, context: { ...value.context, slot: 'bad\0column' } })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, context: { ...value.context, policyVersion: 0n } })).toThrow()
    expect(() => encodeSealedEnvelope({ ...value, context: { ...value.context, slot: 'é'.repeat(65) } })).toThrow()
  })

  it('copies nested bytes in builders so later input mutations cannot change a transaction', () => {
    const reader = bytes(5)
    const key = bytes(8)
    const policy = sealedOp.readerPolicy({ table: 'notes', rowKey: [key], expectedVersion: 0n, readers: [reader] })
    const serialized = encodeCanonicalCbor(sealedPlatformOpToCanonicalCbor(policy))
    reader.fill(0)
    key.fill(0)
    expect(encodeCanonicalCbor(sealedPlatformOpToCanonicalCbor(policy))).toEqual(serialized)
  })
})

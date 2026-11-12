import { describe, expect, it } from 'vitest'

import { materializedLogDigest } from './snapshot-evidence.js'
import type { TransactionLogRow } from './types.js'

const bytes = (fill: number, length = 32): Uint8Array => new Uint8Array(length).fill(fill)

function row(index: number, overrides: Partial<TransactionLogRow> = {}): TransactionLogRow {
  return {
    txId: bytes(0x10 + index),
    orderKey: { authorTimestampMs: 1_000n + BigInt(index), txId: bytes(0x10 + index) },
    orderIndex: index,
    outcome: 'accepted',
    rejectionCode: null,
    failingPreconditionId: null,
    failingPreconditionIndex: null,
    failingStatementIndex: null,
    failurePhase: null,
    failingConstraintIdentity: null,
    failingTriggerIdentity: null,
    resultEnvelopeVersion: 1,
    resultEnvelope: bytes(0x30 + index, 8),
    resultDigest: bytes(0x40 + index),
    authorId: bytes(0x50),
    authorTimestampMs: 1_000n + BigInt(index),
    authorFeedSequence: BigInt(index + 1),
    candidateDigest: bytes(0x60 + index),
    canonicalCandidate: bytes(0x70 + index, 16),
    ...overrides,
  } as TransactionLogRow
}

const hex = (value: Uint8Array): string => Buffer.from(value).toString('hex')

describe('materializedLogDigest', () => {
  it('is deterministic and independent of object identity', async () => {
    const first = await materializedLogDigest([row(0), row(1)])
    const second = await materializedLogDigest([row(0), row(1)])
    expect(first).toHaveLength(32)
    expect(hex(first)).toBe(hex(second))
  })

  it('distinguishes the empty log from a populated one', async () => {
    expect(hex(await materializedLogDigest([]))).not.toBe(hex(await materializedLogDigest([row(0)])))
  })

  it('detects reordering, truncation and duplication of rows', async () => {
    const base = hex(await materializedLogDigest([row(0), row(1), row(2)]))
    expect(hex(await materializedLogDigest([row(1), row(0), row(2)]))).not.toBe(base)
    expect(hex(await materializedLogDigest([row(0), row(1)]))).not.toBe(base)
    expect(hex(await materializedLogDigest([row(0), row(1), row(2), row(2)]))).not.toBe(base)
  })

  // Every protected field must change the evidence digest; a field omitted
  // from the encoding would let a tampered log present matching evidence.
  const tampered: ReadonlyArray<readonly [string, Partial<TransactionLogRow>]> = [
    ['txId', { txId: bytes(0xee) }],
    ['orderIndex', { orderIndex: 9 }],
    ['authorId', { authorId: bytes(0xee) }],
    ['authorTimestampMs', { authorTimestampMs: 5_000n }],
    ['authorFeedSequence', { authorFeedSequence: 99n }],
    ['candidateDigest', { candidateDigest: bytes(0xee) }],
    ['canonicalCandidate', { canonicalCandidate: bytes(0xee, 16) }],
    ['outcome', { outcome: 'rejected_execution' }],
    ['rejectionCode', { rejectionCode: 'SQL_CONSTRAINT' }],
    ['failingPreconditionId', { failingPreconditionId: 0 }],
    ['failingPreconditionIndex', { failingPreconditionIndex: 0 }],
    ['failingStatementIndex', { failingStatementIndex: 0 }],
    ['failurePhase', { failurePhase: 'statement' }],
    ['failingConstraintIdentity', { failingConstraintIdentity: new Uint8Array() }],
    ['failingTriggerIdentity', { failingTriggerIdentity: new Uint8Array() }],
    ['resultEnvelopeVersion', { resultEnvelopeVersion: null }],
    ['resultEnvelope', { resultEnvelope: null }],
    ['resultEnvelope bytes', { resultEnvelope: bytes(0x30, 7) }],
    ['resultDigest', { resultDigest: null }],
  ]

  it.each(tampered)('changes when %s is altered', async (_field, change) => {
    const base = hex(await materializedLogDigest([row(0), row(1)]))
    expect(hex(await materializedLogDigest([row(0), row(1, change)]))).not.toBe(base)
  })

  it('distinguishes null from zero and from empty bytes', async () => {
    const zeroIndex = hex(await materializedLogDigest([row(0, { failingStatementIndex: 0 })]))
    const nullIndex = hex(await materializedLogDigest([row(0, { failingStatementIndex: null })]))
    expect(zeroIndex).not.toBe(nullIndex)
    const emptyIdentity = hex(await materializedLogDigest([row(0, { failingConstraintIdentity: new Uint8Array() })]))
    const nullIdentity = hex(await materializedLogDigest([row(0, { failingConstraintIdentity: null })]))
    expect(emptyIdentity).not.toBe(nullIdentity)
  })

  it('does not let a value shift between adjacent fields', async () => {
    const left = hex(await materializedLogDigest([row(0, { failingPreconditionId: 1, failingPreconditionIndex: null })]))
    const right = hex(await materializedLogDigest([row(0, { failingPreconditionId: null, failingPreconditionIndex: 1 })]))
    expect(left).not.toBe(right)
  })
})

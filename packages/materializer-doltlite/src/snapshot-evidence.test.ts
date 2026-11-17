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
    failingStatementIndex: null,
    authorId: bytes(0x50),
    authorTimestampMs: 1_000n + BigInt(index),
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
    ['candidateDigest', { candidateDigest: bytes(0xee) }],
    ['canonicalCandidate', { canonicalCandidate: bytes(0xee, 16) }],
    ['outcome', { outcome: 'rejected' }],
    ['rejectionCode', { rejectionCode: 'SQL_CONSTRAINT' }],
    ['failingStatementIndex', { failingStatementIndex: 0 }],
  ]

  it.each(tampered)('changes when %s is altered', async (_field, change) => {
    const base = hex(await materializedLogDigest([row(0), row(1)]))
    expect(hex(await materializedLogDigest([row(0), row(1, change)]))).not.toBe(base)
  })

  it('distinguishes null from zero and from empty bytes', async () => {
    const zeroIndex = hex(await materializedLogDigest([row(0, { failingStatementIndex: 0 })]))
    const nullIndex = hex(await materializedLogDigest([row(0, { failingStatementIndex: null })]))
    expect(zeroIndex).not.toBe(nullIndex)
    const emptyCode = hex(await materializedLogDigest([row(0, { rejectionCode: '' })]))
    const nullCode = hex(await materializedLogDigest([row(0, { rejectionCode: null })]))
    expect(emptyCode).not.toBe(nullCode)
  })
})

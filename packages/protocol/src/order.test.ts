import { describe, expect, it } from 'vitest'
import { assertUniqueOrderKeys, compareTransactionOrder, transactionOrderKey } from './index.js'

describe('application timestamp order', () => {
  it('uses the exact timestamp, then signing key, then stable proposal ID', () => {
    const timestamp = 1n << 60n
    const key = (time: bigint, author: number[], proposal: number[]) =>
      transactionOrderKey({ authorTimestampMs: time, authorId: Uint8Array.from(author) }, Uint8Array.from(proposal))
    const expected = [
      key(timestamp - 1n, [255], [255]),
      key(timestamp, [1], [1]),
      key(timestamp, [1], [2]),
      key(timestamp, [1, 0], [0]),
      key(timestamp, [2], [0]),
      key(timestamp + 1n, [0], [0]),
    ]
    expect([...expected].reverse().sort(compareTransactionOrder)).toEqual(expected)
    expect(() => assertUniqueOrderKeys(expected)).not.toThrow()
    expect(() => assertUniqueOrderKeys([...expected, structuredClone(expected[2]!)])).toThrow('Duplicate transaction order key')
  })

  it('projects only the immutable application identity from a proposal', () => {
    const core = { authorTimestampMs: 100n, authorId: Uint8Array.of(2), operationId: 'edit' }
    const txId = Uint8Array.of(3)
    expect(transactionOrderKey(core, txId)).toEqual({ authorTimestampMs: 100n, authorId: core.authorId, txId })
  })
})

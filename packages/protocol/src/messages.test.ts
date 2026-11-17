import { describe, expect, it } from 'vitest'

import { assertUniqueOrderKeys, compareTransactionOrder, transactionOrderKey } from './messages.js'

const bytes = (...values: number[]) => Uint8Array.from(values)

describe('signed proposal order', () => {
  it('orders only by signed time, author bytes and stable proposal identity', () => {
    const first = transactionOrderKey({ authorTimestampMs: 9n, authorId: bytes(9) }, bytes(9))
    const second = transactionOrderKey({ authorTimestampMs: 10n, authorId: bytes(1) }, bytes(2))
    const third = transactionOrderKey({ authorTimestampMs: 10n, authorId: bytes(1) }, bytes(3))
    const fourth = transactionOrderKey({ authorTimestampMs: 10n, authorId: bytes(2) }, bytes(1))
    const expected = [first, second, third, fourth]

    for (const arrival of [[fourth, third, second, first], [third, first, fourth, second], expected]) {
      expect([...arrival].sort(compareTransactionOrder)).toEqual(expected)
    }
    expect(Object.keys(first)).toEqual(['authorTimestampMs', 'authorId', 'txId'])
  })

  it('gives repeated delivery of the same proposal the same order identity', () => {
    const proposal = { authorTimestampMs: 42n, authorId: bytes(1, 2), txId: bytes(5, 6) }
    const deliveries = [
      { ...proposal, route: 'direct', feedPosition: 900n },
      { ...proposal, route: 'retained', feedPosition: 3n },
    ]
    const keys = deliveries.map(delivery => transactionOrderKey(delivery, delivery.txId))
    expect(compareTransactionOrder(keys[0]!, keys[1]!)).toBe(0)
    expect(() => assertUniqueOrderKeys(keys)).toThrow('Duplicate transaction order key')
  })
})

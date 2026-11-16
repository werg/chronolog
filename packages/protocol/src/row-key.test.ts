import { describe, expect, it } from 'vitest'

import { decodeRowKey, encodeRowKey, sqlValue } from './index.js'

describe('canonical row keys', () => {
  it('has a stable typed binary encoding rather than SQL display literals', () => {
    expect(encodeRowKey([1n])).toBe('rk1:0001010000000000000001')
    expect(encodeRowKey([-1n])).toBe('rk1:000101ffffffffffffffff')
    expect(encodeRowKey([sqlValue.real(1)])).toBe('rk1:0001023ff0000000000000')
    expect(encodeRowKey(['a\0one'])).toBe('rk1:0001030000000561006f6e65')
    expect(encodeRowKey(['a\0one'])).not.toBe(encodeRowKey(['a\0two']))
    expect(encodeRowKey(['1'])).not.toBe(encodeRowKey([new Uint8Array([49])]))
    expect(encodeRowKey([1n])).not.toBe(encodeRowKey([sqlValue.real(1)]))
    expect(encodeRowKey([sqlValue.real(1.5)])).not.toBe(encodeRowKey([sqlValue.real(1.5000000000000002)]))
    expect(decodeRowKey(encodeRowKey([null, -42n, sqlValue.real(1.5), 'a\0b', new Uint8Array()]))).toEqual([
      { kind: 'null' }, { kind: 'integer', value: -42n }, { kind: 'real', value: 1.5 },
      { kind: 'text', value: Uint8Array.of(97, 0, 98) }, { kind: 'blob', value: new Uint8Array() },
    ])
  })

  it('fails closed on unknown versions, malformed tuples, noncanonical hex and NaNs', () => {
    for (const key of ['', '1', 'rk2:000100', 'rk1:000100ff', 'rk1:0001ff', 'rk1:000103ffffffff',
      'rk1:0001027ff8000000000000', 'rk1:000101FFFFFFFFFFFFFFFF', 'rk1:0000', 'rk1:0041']) {
      expect(() => decodeRowKey(key), key).toThrow('ROW_KEY_INVALID')
    }
    expect(() => encodeRowKey([])).toThrow('ROW_KEY_ARITY')
    expect(() => encodeRowKey(Array(65).fill(0))).toThrow('ROW_KEY_ARITY')
  })
})

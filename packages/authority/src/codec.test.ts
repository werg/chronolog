import { expect, it } from 'vitest'
import { bytesToHex } from '@chronolog/canonical'
import { encodeRecord, decodeRecord, equalRecord } from './codec.js'
it('compares canonical bytes without hex-sized intermediates and preserves exact validation failures', () => {
  const bytes = Uint8Array.from({ length: 65_536 }, (_, index) => index % 256)
  const values = [null, true, false, 0, -1, '', 'text', 9223372036854775807n, bytes, { bytes, integer: -1n, nested: [{ a: 1, z: 2 }] }]
  for (const value of values) {
    expect(decodeRecord(encodeRecord(value))).toEqual(value)
    for (const other of values) expect(equalRecord(value, other)).toBe(bytesToHex(encodeRecord(value)) === bytesToHex(encodeRecord(other)))
  }
  const invalid = [
    ['{"z":1,"a":2}', 'RECORD_NOT_CANONICAL'], [' {"a":1}', 'RECORD_NOT_CANONICAL'],
    ['{"a":1,"a":1}', 'RECORD_NOT_CANONICAL'], ['{"$bytes":"FF"}', 'RECORD_BYTES_INVALID'],
    ['{"$bytes":"0"}', 'RECORD_BYTES_INVALID'], ['{"$integer":"01"}', 'RECORD_INTEGER_INVALID'],
    ['{"$integer":"-0"}', 'RECORD_INVALID'], ['1.5', 'RECORD_INTEGER_INVALID'],
    ['9007199254740992', 'RECORD_INTEGER_INVALID'],
  ]
  for (const [text, error] of invalid) expect(() => decodeRecord(new TextEncoder().encode(text))).toThrow(error)
  expect(() => decodeRecord(Uint8Array.of(0xff))).toThrow()
})

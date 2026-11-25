import { expect, it } from 'vitest'
import { bytesToHex, hexToBytes } from './bytes.js'
it('encodes every byte and offset view identically to the original hex codec without changing accepted hex input', () => {
  const oracle = (bytes: Uint8Array): string => [...bytes].map(byte => byte.toString(16).padStart(2, '0')).join('')
  const allocation = Uint8Array.from({ length: 131_075 }, (_, index) => index % 256)
  for (const bytes of [new Uint8Array(), allocation.subarray(1, 257), allocation.subarray(17, 65_553), allocation]) {
    const encoded = bytesToHex(bytes)
    expect(encoded).toBe(oracle(bytes)); expect(hexToBytes(encoded)).toEqual(bytes); expect(hexToBytes(encoded.toUpperCase())).toEqual(bytes)
  }
  for (const invalid of ['0', '000', '0g', ' 00', '00\n', 'é0', 'ＦＦ', '-1']) expect(() => hexToBytes(invalid)).toThrow('Hex text is malformed')
})

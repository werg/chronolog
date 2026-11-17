import { describe, expect, it } from 'vitest'

import { base64UrlToBytes, bytesToBase64Url } from './bytes.js'

describe('portable base64url', () => {
  it('round-trips empty, binary and large byte arrays without Buffer', () => {
    for (const bytes of [new Uint8Array(), Uint8Array.of(0, 255, 254, 253), Uint8Array.from({ length: 100_000 }, (_, index) => index & 255)]) {
      const text = bytesToBase64Url(bytes)
      expect(text).toMatch(/^[A-Za-z0-9_-]*$/u)
      expect(base64UrlToBytes(text)).toEqual(bytes)
    }
  })

  it('rejects aliases, padding and nonzero unused bits', () => {
    for (const value of ['a', 'Zg==', 'Zh', '+w', '/w', ' Zg']) expect(() => base64UrlToBytes(value)).toThrow()
  })
})

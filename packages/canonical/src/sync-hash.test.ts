import { createHash } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { createSha256, sha256Sync } from './sync-hash.js'

describe('portable synchronous SHA-256', () => {
  it('matches native hashing across UTF-8, binary, and block boundaries', () => {
    for (const length of [0, 1, 55, 56, 63, 64, 65, 4097]) {
      const bytes = Uint8Array.from({ length }, (_, index) => index % 251)
      expect(sha256Sync(bytes)).toEqual(new Uint8Array(createHash('sha256').update(bytes).digest()))
      expect(createSha256().update('λ\0').update(bytes).digest())
        .toEqual(new Uint8Array(createHash('sha256').update('λ\0').update(bytes).digest()))
    }
  })
})

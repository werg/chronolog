import { describe, expect, it } from 'vitest'
import { decodeRecordValue, encodeRecordValue, MAX_RECORD_ENVELOPE_BYTES } from './record-envelope.js'

describe('shared durable record envelope', () => {
  it('round trips empty and binary values with independent output', async () => {
    for (const bytes of [new Uint8Array(), Uint8Array.of(0, 255, 17)]) {
      const raw = await encodeRecordValue('segment/1', bytes)
      const decoded = await decodeRecordValue('segment/1', raw, 'RECORD_CORRUPT')
      expect(decoded).toEqual(bytes)
      decoded.fill(3)
      expect(await decodeRecordValue('segment/1', raw, 'RECORD_CORRUPT')).toEqual(bytes)
    }
  })
  it('rejects key, version, checksum and truncation corruption', async () => {
    const data = Uint8Array.of(1, 2)
    const good = await encodeRecordValue('key', data)
    const wrongVersion = good.slice(); wrongVersion[0] = 1
    const wrongChecksum = good.slice(); wrongChecksum[good.length - 1] = wrongChecksum[good.length - 1]! ^ 0xff
    const invalid = [
      wrongVersion,
      await encodeRecordValue('another-key', data),
      wrongChecksum,
      good.slice(0, 6),
      new Uint8Array(),
      Uint8Array.of(0xff),
    ]
    for (const raw of invalid) await expect(decodeRecordValue('key', raw, 'RECORD_CORRUPT')).rejects.toThrow('RECORD_CORRUPT')
    await expect(decodeRecordValue('key', new Uint8Array(MAX_RECORD_ENVELOPE_BYTES + 1), 'RECORD_CORRUPT')).rejects.toThrow('RECORD_CORRUPT')
    await expect(encodeRecordValue('', data)).rejects.toThrow('OPFS_KEY_INVALID')
    await expect(encodeRecordValue('a'.repeat(4097), data)).rejects.toThrow('OPFS_KEY_INVALID')
  })
})

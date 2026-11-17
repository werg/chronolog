import { describe, expect, it } from 'vitest'

import { readEvidenceBatches, readEvidencePage } from './evidence.js'
import { MAX_EVIDENCE_BATCH_BYTES } from './types.js'

describe('bounded retained evidence pages', () => {
  it('splits a retained prefix at the byte budget without dropping the next object', async () => {
    const object = new Uint8Array(Math.floor(MAX_EVIDENCE_BATCH_BYTES / 2) + 1)
    const records = [{ index: 1n, evidence: { id: 'first', bytes: object } }, { index: 2n, evidence: { id: 'second', bytes: object } }]
    const store = { evidenceHead: () => 2n, evidenceAfter: (after: bigint, limit: number) => records.slice(Number(after), Number(after) + limit) }
    expect((await readEvidencePage(store, 0n, 64)).map(item => item.index)).toEqual([1n])
    const batches: string[][] = []
    for await (const batch of readEvidenceBatches(store)) batches.push(batch.map(item => item.id))
    expect(batches).toEqual([['first'], ['second']])
  })
})

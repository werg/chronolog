import type { OrderedRecordEntry, OrderedRecordHead } from '@chronolog/node-core/history'
import { utf8 } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { collectRetainedRange } from './lib/retained-range.js'

const historyId = 'h_0123456789abcdef0123456789abcdef'
const head = (position: number): OrderedRecordHead => ({ historyId, position, root: `root-${position}` })
const entry = (position: number): OrderedRecordEntry => ({ ...head(position), recordId: `record-${position}`,
  previousRoot: head(position - 1).root, bytes: utf8(`retained receipt ${position}`) })

describe('thin workload retained range measurement', () => {
  it('collects more than one page completely and excludes receipts appended beyond the captured head', async () => {
    // The collector consumes opaque, already retained receipts. Exercise its
    // pagination without benchmarking signature/hash verification or SQL.
    const retained = Array.from({ length: 141 }, (_, index) => entry(index + 1))
    const after = head(1), through = head(retained.length), expected = retained.slice(after.position)
    const read = vi.fn(async ({ after = 0, limit = 64 }: { after?: number; limit?: number } = {}) => {
      // Finality may retain more closure receipts while the fixed interval is read.
      retained.push(entry(retained.length + 1))
      return { entries: retained.slice(after, after + limit), head: head(retained.length), hasMore: after + limit < retained.length }
    })
    expect(await collectRetainedRange({ read }, after, through)).toEqual(expected)
    expect(read.mock.calls.map(([options]) => options)).toEqual([{ after: 1, limit: 128 }, { after: 129, limit: 12 }])
    expect(retained.length).toBeGreaterThan(through.position)
  })

  it('rejects stalled, truncated and discontinuous pages instead of returning partial measurements', async () => {
    const after = head(0), through = head(2), entries = [entry(1), entry(2)]
    await expect(collectRetainedRange({ read: async () => ({ entries: [], head: through, hasMore: true }) }, after, through))
      .rejects.toThrow('THIN_WORKLOAD_RANGE_NO_PROGRESS')
    await expect(collectRetainedRange({ read: async () => ({ entries: entries.slice(0, 1), head: through, hasMore: false }) }, after, through))
      .rejects.toThrow('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
    await expect(collectRetainedRange({ read: async () => ({ entries: entries.slice(1), head: through, hasMore: false }) }, after, through))
      .rejects.toThrow('THIN_WORKLOAD_RANGE_DISCONTINUOUS')
    await expect(collectRetainedRange({ read: async () => ({ entries, head: through, hasMore: false }) }, after, { ...through, root: 'wrong root' }))
      .rejects.toThrow('THIN_WORKLOAD_RANGE_COVERAGE_INVALID')
  })

  it('rejects invalid bounds and shrinking heads before accepting any range', async () => {
    const after = head(0), through = head(1)
    const read = vi.fn(async () => ({ entries: [], head: after, hasMore: false }))
    for (const target of [{ ...through, position: -1 }, { ...through, position: 1.5 }, { ...through, historyId: 'other-history' }]) {
      await expect(collectRetainedRange({ read }, after, target)).rejects.toThrow('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
    }
    expect(read).not.toHaveBeenCalled()
    await expect(collectRetainedRange({ read }, after, through)).rejects.toThrow('THIN_WORKLOAD_RANGE_BOUNDS_INVALID')
  })
})

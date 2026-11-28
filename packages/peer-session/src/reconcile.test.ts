import { describe, expect, it } from 'vitest'
import { bytesToHex, sha256Sync, utf8 } from '@chronolog/canonical'
import { FactIdSet, rangesNeedReply, reconcileRanges, type ReconcileRange } from './reconcile.js'

const id = (n: number): string => bytesToHex(sha256Sync(utf8(`fact-${n}`)))

/** Drive a full reconciliation between two sets; returns the union each side ends with and message stats. */
function run(a: FactIdSet, b: FactIdSet): { rounds: number; summaries: number; listed: number; moved: number } {
  const sides = [a, b] as const
  let inbox: ReconcileRange[] = [a.summary('')], turn = 1, rounds = 0, summaries = 1, listed = 0, moved = 0
  while (inbox.length > 0) {
    rounds++
    const self = sides[turn]!, peer = sides[1 - turn]!
    const step = reconcileRanges(self, inbox)
    for (const fact of step.push) { peer.add(fact); moved++ }
    for (const fact of step.want) { self.add(fact); moved++ }
    for (const range of step.reply) {
      if ('ids' in range) listed += range.ids.length
      else summaries++
    }
    // Id lists are terminal for the receiver; only summaries continue the exchange.
    inbox = [...step.reply]
    if (!rangesNeedReply(inbox) && inbox.length > 0) {
      const last = reconcileRanges(peer, inbox)
      for (const fact of last.push) { self.add(fact); moved++ }
      for (const fact of last.want) { peer.add(fact); moved++ }
      inbox = []
    }
    turn = 1 - turn
    if (rounds > 50) throw new Error('did not converge')
  }
  return { rounds, summaries, listed, moved }
}

describe('range-fingerprint reconciliation', () => {
  it('settles identical sets with a single summary', () => {
    const a = new FactIdSet(), b = new FactIdSet()
    for (let i = 0; i < 5000; i++) { a.add(id(i)); b.add(id(i)) }
    const stats = run(a, b)
    expect(stats).toMatchObject({ rounds: 1, moved: 0 })
  })

  it('converges to the union for disjoint, overlapping, empty and skewed sets', () => {
    const cases: Array<[number[], number[]]> = [
      [[], []],
      [[], range(0, 3000)],
      [range(0, 3000), []],
      [range(0, 2000), range(1000, 3000)],
      [range(0, 5000), [...range(0, 5000), 99_999]],
      [range(0, 40), range(20, 60)],
    ]
    for (const [left, right] of cases) {
      const a = new FactIdSet(), b = new FactIdSet()
      for (const n of left) a.add(id(n))
      for (const n of right) b.add(id(n))
      run(a, b)
      const union = new Set([...left, ...right].map(id))
      expect(a.size).toBe(union.size)
      expect(b.size).toBe(union.size)
      expect(a.ids()).toEqual(b.ids())
    }
  })

  it('costs O(diff · log N) for a single missing fact in a large set', () => {
    const a = new FactIdSet(), b = new FactIdSet()
    for (let i = 0; i < 20_000; i++) { a.add(id(i)); b.add(id(i)) }
    b.add(id(123_456))
    const stats = run(a, b)
    expect(stats.moved).toBe(1)
    expect(stats.summaries).toBeLessThan(80)
    expect(stats.listed).toBeLessThan(80)
  })

  it('rejects malformed ranges', () => {
    const set = new FactIdSet()
    expect(() => reconcileRanges(set, [{ prefix: 'zz', count: 1, fp: new Uint8Array(16) }])).toThrow('RECONCILE_RANGE_INVALID')
    expect(() => reconcileRanges(set, [{ prefix: 'ab', ids: [id(1)] }])).toThrow('RECONCILE_RANGE_INVALID')
  })
})

function range(start: number, end: number): number[] {
  return Array.from({ length: end - start }, (_, i) => start + i)
}

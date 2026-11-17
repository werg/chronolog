import type { EvidenceSink, NativeFinalityService } from '@chronolog/agent-service'
import type { OrderedRecordHead } from '@chronolog/node-core'
import { describe, expect, it } from 'vitest'

import { createFinalityEvidencePublisher } from './finality-evidence.js'

const head = (position: number): OrderedRecordHead => ({ historyId: 'h_0123456789abcdef0123456789abcdef',
  position, root: position.toString(16).padStart(64, '0') })

describe('manual finality evidence publication cursor', () => {
  it('serializes concurrent calls behind the last fully acknowledged publication', async () => {
    let release!: () => void, started!: () => void
    const blocked = new Promise<void>(resolve => { release = resolve })
    const firstStarted = new Promise<void>(resolve => { started = resolve })
    const cursors: number[] = [], sinks: EvidenceSink[] = []
    const source: Pick<NativeFinalityService, 'share'> = { async share(sink, options = {}) {
      const after = options.after ?? 0
      cursors.push(after); sinks.push(sink)
      if (cursors.length === 1) { started(); await blocked }
      return head(after + 2)
    } }
    const sink: EvidenceSink = { async putEvidence() {} }
    const publish = createFinalityEvidencePublisher(source, sink)
    const first = publish()
    await firstStarted
    const second = publish()
    try { expect(cursors).toEqual([0]) } finally { release() }
    expect(await Promise.all([first, second])).toEqual([head(2), head(4)])
    expect(cursors).toEqual([0, 2])
    expect(sinks).toEqual([sink, sink])
  })

  it('retries from the previous complete head after a partial sink write loses its reply', async () => {
    let target = 1, loseReply = false
    const cursors: number[] = [], received: number[] = []
    const lost = new Error('evidence acknowledgment lost')
    const source: Pick<NativeFinalityService, 'share'> = { async share(sink, options = {}) {
      const after = options.after ?? 0
      cursors.push(after)
      for (let position = after + 1; position <= target; position += 1) await sink.putEvidence(Uint8Array.of(position))
      return head(target)
    } }
    const publish = createFinalityEvidencePublisher(source, { async putEvidence(bytes) {
      received.push(bytes[0]!)
      if (loseReply) { loseReply = false; throw lost }
    } })
    expect(await publish()).toEqual(head(1))
    target = 3; loseReply = true
    await expect(publish()).rejects.toBe(lost)
    expect(await publish()).toEqual(head(3))
    expect(cursors).toEqual([0, 1, 1])
    expect(received).toEqual([1, 2, 2, 3])
  })

  it('keeps cursors independent for sinks sharing the same finality service', async () => {
    const one: EvidenceSink = { async putEvidence() {} }, two: EvidenceSink = { async putEvidence() {} }
    const calls: Array<{ sink: EvidenceSink; after: number }> = []
    const source: Pick<NativeFinalityService, 'share'> = { async share(sink, options = {}) {
      calls.push({ sink, after: options.after ?? 0 })
      return head(5)
    } }
    const first = createFinalityEvidencePublisher(source, one), second = createFinalityEvidencePublisher(source, two)
    await first(); await first(); await second()
    expect(calls).toEqual([{ sink: one, after: 0 }, { sink: one, after: 5 }, { sink: two, after: 0 }])
  })
})

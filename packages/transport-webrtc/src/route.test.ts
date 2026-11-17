import { describe, expect, it } from 'vitest'

import { observeWebRtcRoute } from './route.js'

function peer(local: unknown = 'host', remote: unknown = 'srflx') {
  const records: Record<string, unknown>[] = [
    { id: 'transport', type: 'transport', selectedCandidatePairId: 'pair' },
    { id: 'pair', type: 'candidate-pair', state: 'succeeded', localCandidateId: 'local', remoteCandidateId: 'remote' },
    { id: 'local', type: 'local-candidate', candidateType: local },
    { id: 'remote', type: 'remote-candidate', candidateType: remote },
  ]
  return { records, connectionState: 'connected', async getStats() { return records } }
}

describe('observed WebRTC routes', () => {
  it('classifies the selected pair, without treating unused TURN candidates as relay usage', async () => {
    const value = peer()
    value.records.push({ id: 'unused', type: 'local-candidate', candidateType: 'relay' })
    await expect(observeWebRtcRoute(value)).resolves.toEqual({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'srflx' })
  })

  it.each([['relay', 'host'], ['host', 'relay'], ['relay', undefined]])('identifies an observed relay on either endpoint: %s/%s', async (local, remote) => {
    await expect(observeWebRtcRoute(peer(local, remote))).resolves.toMatchObject({ route: 'relay' })
  })

  it('does not infer direct routing from missing stats or a merely nominated candidate', async () => {
    await expect(observeWebRtcRoute({ connectionState: 'connected' })).resolves.toMatchObject({ route: 'unknown' })
    const value = peer(); value.records.shift(); value.records[0]!.nominated = true
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'unknown' })
    await expect(observeWebRtcRoute(peer('unknown', 'host'))).resolves.toMatchObject({ route: 'unknown', localCandidateType: null })
  })

  it('uses a selected-pair observation when the adapter exposes no transport stats', async () => {
    const value = peer(); value.records.shift(); value.records[0]!.selected = true
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'direct' })
  })

  it('reports unknown when selection is ambiguous, failed, absent or no longer connected', async () => {
    const value = peer(); value.records.push({ id: 'second-transport', type: 'transport', selectedCandidatePairId: 'other-pair' })
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'unknown' })
    value.records.pop(); value.records[1]!.state = 'failed'
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'unknown' })
    value.records[1]!.state = 'succeeded'; value.records[0]!.selectedCandidatePairId = 'missing'
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'unknown' })
    value.connectionState = 'disconnected'
    await expect(observeWebRtcRoute(value)).resolves.toMatchObject({ route: 'unknown' })
  })

  it('contains unavailable diagnostic stats instead of failing the application connection', async () => {
    await expect(observeWebRtcRoute({ connectionState: 'connected', getStats() { throw new Error('not supported') } })).resolves.toMatchObject({ route: 'unknown' })
  })
})

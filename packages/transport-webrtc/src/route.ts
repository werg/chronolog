import type { IceCandidateType, RtcPeerConnection, WebRtcRoute } from './types.js'

/**
 * A successful RTC handshake or a supplied ICE configuration is not route
 * evidence. Only the currently selected candidate pair can identify a relay.
 */
export async function observeWebRtcRoute(connection: Pick<RtcPeerConnection, 'connectionState' | 'getStats'>): Promise<WebRtcRoute> {
  const unknown: WebRtcRoute = { route: 'unknown', localCandidateType: null, remoteCandidateType: null }
  if (connection.connectionState !== 'connected' || connection.getStats === undefined) return unknown
  try {
    const report = await connection.getStats(), stats = new Map<string, Record<string, unknown>>()
    report.forEach(value => {
      if (typeof value === 'object' && value !== null && 'id' in value && typeof value.id === 'string') {
        stats.set(value.id, value)
      }
    })
    // Prefer the transport's current selection. A merely nominated/succeeded
    // pair may be an old route after an ICE change, so it is not sufficient.
    const selected = [...stats.values()].filter(value => value.type === 'transport' && typeof value.selectedCandidatePairId === 'string')
    let pair: Record<string, unknown> | undefined
    if (selected.length === 1) pair = stats.get(selected[0]!.selectedCandidatePairId as string)
    else if (selected.length === 0) {
      const pairs = [...stats.values()].filter(value => value.type === 'candidate-pair' && value.selected === true)
      if (pairs.length === 1) pair = pairs[0]
    }
    if (connection.connectionState !== 'connected' || pair?.type !== 'candidate-pair' || pair.state !== 'succeeded') return unknown
    const local = typeof pair.localCandidateId === 'string' ? stats.get(pair.localCandidateId) : undefined
    const remote = typeof pair.remoteCandidateId === 'string' ? stats.get(pair.remoteCandidateId) : undefined
    const localCandidateType = local?.type === 'local-candidate' ? candidateType(local.candidateType) : null
    const remoteCandidateType = remote?.type === 'remote-candidate' ? candidateType(remote.candidateType) : null
    const route = localCandidateType === 'relay' || remoteCandidateType === 'relay' ? 'relay'
      : localCandidateType !== null && remoteCandidateType !== null ? 'direct' : 'unknown'
    return { route, localCandidateType, remoteCandidateType }
  } catch { return unknown }
}

function candidateType(value: unknown): IceCandidateType | null {
  return value === 'host' || value === 'srflx' || value === 'prflx' || value === 'relay' ? value : null
}

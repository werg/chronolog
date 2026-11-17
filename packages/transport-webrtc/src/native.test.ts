import os from 'node:os'
import { syncBuiltinESMExports } from 'node:module'

import { describe, expect, it, vi } from 'vitest'

import { createNativePeerConnection } from './native.js'
import { openWebRtcConnection } from './negotiation.js'
import type { PeerDescription, PeerSignaling } from './types.js'

function mailbox() {
  let resolve!: (value: PeerDescription) => void, closed = false
  const received = new Promise<PeerDescription>(done => { resolve = done })
  return { receive: resolve, async *messages() { yield await received }, close() { closed = true }, get closed() { return closed } }
}

export function signalingPair() {
  const left = mailbox(), right = mailbox()
  const descriptions: PeerDescription[] = []
  const a: PeerSignaling = { messages: left.messages(), async send(value) { descriptions.push(value); right.receive(structuredClone(value)) }, close: () => left.close() }
  const b: PeerSignaling = { messages: right.messages(), async send(value) { descriptions.push(value); left.receive(structuredClone(value)) }, close: () => right.close() }
  return { a, b, descriptions, closed: () => left.closed && right.closed }
}

describe('native WebRTC interoperability', () => {
  it('negotiates real ICE/DTLS/SCTP then sends large bidirectional frames after signaling closes', async () => {
    const signals = signalingPair()
    const factory = () => createNativePeerConnection({}, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false })
    const interfaces = vi.spyOn(os, 'networkInterfaces').mockReturnValue({})
    syncBuiltinESMExports()
    const [left, right] = await Promise.all([
      openWebRtcConnection({ role: 'offerer', signaling: signals.a, createPeerConnection: factory }),
      openWebRtcConnection({ role: 'answerer', signaling: signals.b, createPeerConnection: factory }),
    ]).finally(() => { interfaces.mockRestore(); syncBuiltinESMExports() })
    try {
      expect(signals.descriptions.map(description => description.type)).toEqual(['offer', 'answer'])
      expect(signals.closed()).toBe(true)
      expect(await left.session.getRoute()).toEqual({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })
      expect(await right.session.getRoute()).toEqual({ route: 'direct', localCandidateType: 'host', remoteCandidateType: 'host' })
      const leftRead = left.frames()[Symbol.asyncIterator](), rightRead = right.frames()[Symbol.asyncIterator]()
      const body = new Uint8Array(512 * 1024 + 13).fill(67)
      await Promise.all([left.send(body), right.send(new Uint8Array([7, 8, 9]))])
      expect((await rightRead.next()).value).toEqual(body)
      expect((await leftRead.next()).value).toEqual(new Uint8Array([7, 8, 9]))
      expect(left.stats.sentBytes).toBe(body.length)
      // A consumer ending its framed session must retire RTC even if the ICE
      // connection itself has not failed; supervisors observe that lifetime.
      await leftRead.return?.()
      expect(left.signal.aborted).toBe(true)
      expect(left.session.signal.aborted).toBe(true)
    } finally { await Promise.all([left.close(), right.close()]) }
  })

  it('aborting the native session wakes a blocked frame reader and closes its channel', async () => {
    const signals = signalingPair(), controller = new AbortController()
    const factory = () => createNativePeerConnection({}, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false })
    const interfaces = vi.spyOn(os, 'networkInterfaces').mockReturnValue({})
    syncBuiltinESMExports()
    const [left, right] = await Promise.all([
      openWebRtcConnection({ role: 'offerer', signaling: signals.a, createPeerConnection: factory, signal: controller.signal }),
      openWebRtcConnection({ role: 'answerer', signaling: signals.b, createPeerConnection: factory }),
    ]).finally(() => { interfaces.mockRestore(); syncBuiltinESMExports() })
    try {
      const reading = left.frames()[Symbol.asyncIterator]().next()
      const rejected = expect(reading).rejects.toThrow('WEBRTC_CONNECTION_ENDED')
      controller.abort()
      await rejected
      expect(left.session.signal.aborted).toBe(true)
      await expect(left.send(new Uint8Array([1]))).rejects.toThrow('WEBRTC_CONNECTION_ENDED')
    } finally { await Promise.all([left.close(), right.close()]) }
  })

})

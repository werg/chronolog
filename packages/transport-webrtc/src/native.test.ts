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
      // The negotiated unordered lane must work with the actual SCTP adapter,
      // independently of the large reliable body and its outstanding credit.
      const liveRead = right.live.frames()[Symbol.asyncIterator]()
      await left.live.trySend(new Uint8Array([4, 5, 6]))
      expect((await liveRead.next()).value).toEqual(new Uint8Array([4, 5, 6]))
      expect(right.live.stats.receivedBytes).toBe(3)
      expect(left.stats.sentBytes).toBe(body.length + 3)
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
      const rejected = expect(reading).rejects.toThrow('PEER_MESSAGE_CONNECTION_ENDED')
      controller.abort()
      await rejected
      expect(left.session.signal.aborted).toBe(true)
      await expect(left.send(new Uint8Array([1]))).rejects.toThrow('PEER_MESSAGE_CONNECTION_ENDED')
    } finally { await Promise.all([left.close(), right.close()]) }
  })

})


describe('native STUN gathering budget', () => {
  it('keeps an unreachable configured STUN server within the five-second direct attempt', async () => {
    const signals = signalingPair(), stop = new AbortController(), started = performance.now()
    const configuration: RTCConfiguration = { iceServers: [{ urls: 'stun:127.0.0.1:9' }] }
    Object.freeze(configuration.iceServers); Object.freeze(configuration)
    const factory = (configuration: RTCConfiguration) => createNativePeerConnection(configuration, {
      iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceAdditionalHostAddresses: ['127.0.0.1'], iceUseIpv6: false, iceUseTcp: false,
    })
    const opening = [
      openWebRtcConnection({ role: 'offerer', signaling: signals.a, configuration, createPeerConnection: factory, timeoutMs: 5000, signal: stop.signal }),
      openWebRtcConnection({ role: 'answerer', signaling: signals.b, configuration, createPeerConnection: factory, timeoutMs: 5000, signal: stop.signal }),
    ] as const
    try {
      const [left, right] = await Promise.all(opening)
      expect(performance.now() - started).toBeLessThan(5000)
      const reader = right.frames()[Symbol.asyncIterator]()
      await left.send(new Uint8Array([1, 2, 3]))
      expect((await reader.next()).value).toEqual(new Uint8Array([1, 2, 3]))
      await reader.return?.()
    } finally {
      stop.abort()
      const settled = await Promise.allSettled(opening)
      await Promise.all(settled.filter(value => value.status === 'fulfilled').map(value => value.value.close()))
    }
  })
})

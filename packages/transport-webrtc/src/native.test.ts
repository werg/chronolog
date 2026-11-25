import os from 'node:os'
import { syncBuiltinESMExports } from 'node:module'

import { describe, expect, it, vi } from 'vitest'
import { RtpHeader, RtpPacket } from 'werift'

import { createNativePeerConnection, MediaStreamTrack } from './native.js'
import { openWebRtcConnection } from './negotiation.js'
import type { PeerDescription, PeerSignaling, PeerSignalingMessage } from './types.js'

function queue() {
  const items: PeerSignalingMessage[] = []
  let wake: (() => void) | undefined
  let closed = false
  return {
    push(value: PeerSignalingMessage) {
      if (closed) return
      items.push(value); wake?.(); wake = undefined
    },
    async *messages() {
      while (true) {
        if (items.length > 0) { yield items.shift()!; continue }
        if (closed) return
        await new Promise<void>(resolve => { wake = resolve })
      }
    },
    close() { closed = true; wake?.(); wake = undefined },
    get closed() { return closed },
  }
}

export function signalingPair() {
  const left = queue(), right = queue()
  const descriptions: PeerDescription[] = []
  let candidates = 0
  const forward = (target: ReturnType<typeof queue>) => async (value: PeerSignalingMessage) => {
    if ('type' in value) descriptions.push(value)
    else if (value.kind === 'candidate') candidates += 1
    target.push(structuredClone(value))
  }
  const a: PeerSignaling = { messages: left.messages(), send: forward(right), close: () => left.close() }
  const b: PeerSignaling = { messages: right.messages(), send: forward(left), close: () => right.close() }
  return { a, b, descriptions, candidates: () => candidates, closed: () => left.closed && right.closed }
}

describe('native WebRTC interoperability', () => {
  it('negotiates trickle ICE/DTLS/SCTP then sends large bidirectional frames after signaling closes', async () => {
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
      const liveRead = right.live.frames()[Symbol.asyncIterator]()
      await left.live.trySend(new Uint8Array([4, 5, 6]))
      expect((await liveRead.next()).value).toEqual(new Uint8Array([4, 5, 6]))
      expect(right.live.stats.receivedBytes).toBe(3)
      expect(left.stats.sentBytes).toBe(body.length + 3)
      await leftRead.return?.()
      expect(left.signal.aborted).toBe(true)
      expect(left.session.signal.aborted).toBe(true)
    } finally { await Promise.all([left.close(), right.close()]) }
  })

  it('supports in-band Perfect Negotiation for custom app:* binary streams and Opus RTP audio tracks', async () => {
    const signals = signalingPair()
    const factory = () => createNativePeerConnection({}, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false })
    const interfaces = vi.spyOn(os, 'networkInterfaces').mockReturnValue({})
    syncBuiltinESMExports()
    const [left, right] = await Promise.all([
      openWebRtcConnection({ role: 'offerer', signaling: signals.a, createPeerConnection: factory }),
      openWebRtcConnection({ role: 'answerer', signaling: signals.b, createPeerConnection: factory }),
    ]).finally(() => { interfaces.mockRestore(); syncBuiltinESMExports() })
    try {
      // Attach in-band signaling (deterministic polite/impolite roles, async delivery like a real wire).
      const sendTo = { left: undefined as ReturnType<typeof left.session.attachInBandSignaling> | undefined, right: undefined as ReturnType<typeof right.session.attachInBandSignaling> | undefined }
      sendTo.left = left.session.attachInBandSignaling({
        polite: true,
        async send(msg) { const copy = structuredClone(msg); queueMicrotask(() => { void sendTo.right?.receive(copy) }) },
      })
      sendTo.right = right.session.attachInBandSignaling({
        polite: false,
        async send(msg) { const copy = structuredClone(msg); queueMicrotask(() => { void sendTo.left?.receive(copy) }) },
      })

      // 1. Dynamic custom app:* binary DataChannel (zero SDP renegotiation).
      const incomingStream = new Promise<ReturnType<typeof left.session.streams.open>>(resolve => {
        right.session.streams.onStream(resolve)
      })
      const outbound = left.session.streams.open('whiteboard', { ordered: false, maxRetransmits: 0 })
      const inbound = await incomingStream
      expect(inbound.label).toBe('whiteboard')
      expect(inbound.ordered).toBe(false)
      await vi.waitFor(() => expect(outbound.readyState).toBe('open'))
      const reader = inbound.messages()[Symbol.asyncIterator]()
      outbound.send(new Uint8Array([10, 20, 30, 40]))
      expect((await reader.next()).value).toEqual(new Uint8Array([10, 20, 30, 40]))

      // 2. Dynamic audio RTP track added mid-session via in-band Perfect Negotiation.
      const receivedTrack = new Promise<MediaStreamTrack>(resolve => {
        right.session.media.onTrack(event => { resolve(event.track as MediaStreamTrack) })
      })
      const localAudio = new MediaStreamTrack({ kind: 'audio' })
      left.session.media.addTrack(localAudio)
      const remoteAudio = await receivedTrack
      expect(remoteAudio.kind).toBe('audio')

      // Send an RTP audio packet and verify reception while chronolog.reliable stays healthy.
      const rtpReceived = new Promise<Buffer>(resolve => {
        remoteAudio.onReceiveRtp.subscribe(packet => resolve(packet.payload))
      })
      const payload = Buffer.from([0xf8, 0xff, 0xfe, 1, 2, 3, 4])
      const header = new RtpHeader({ payloadType: 96, sequenceNumber: 1, timestamp: 960, ssrc: 0x12345678 })
      const packet = new RtpPacket(header, payload)
      // Allow SRTP keys/transceiver to finish settling after answer before pumping packets.
      const pump = setInterval(() => { try { localAudio.writeRtp(packet) } catch { /* Wait for SRTP readiness. */ } }, 25)
      try {
        expect(await rtpReceived).toEqual(payload)
      } finally { clearInterval(pump) }

      // Verify pre-negotiated Chronolog sync channel is completely unaffected!
      const syncRead = right.frames()[Symbol.asyncIterator]()
      await left.send(new Uint8Array([99, 100]))
      expect((await syncRead.next()).value).toEqual(new Uint8Array([99, 100]))
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

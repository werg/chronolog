import { once } from 'node:events'
import { createServer } from 'node:http'
import { syncBuiltinESMExports } from 'node:module'
import os from 'node:os'
import { Readable } from 'node:stream'

import { describe, expect, it, vi } from 'vitest'

import { createHttpWebRtcSignaling, createWebRtcOfferHandler, WEBRTC_HTTP_LIMITS, WEBRTC_HTTP_PROTOCOL } from './http.js'
import { createNativePeerConnection } from './native.js'
import { openWebRtcConnection } from './negotiation.js'
import type { PeerDescription, RtcPeerConnection } from './types.js'

const origin = 'https://page.example.test', url = 'https://resident.example.test/introduce'
const offer: PeerDescription = { type: 'offer', sdp: 'v=0\r\n' }, answer: PeerDescription = { type: 'answer', sdp: 'v=0\r\n' }
const body = (description = offer): string => JSON.stringify({ protocol: WEBRTC_HTTP_PROTOCOL, description })
const request = (value = body(), headers: HeadersInit = {}): Request => new Request(url, {
  method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', ...headers }, body: value,
})
function pendingPeer(close: () => Promise<void> = async () => undefined) {
  const calls = { created: 0, closed: 0 }, events = new EventTarget()
  let localDescription: RTCSessionDescriptionInit | undefined
  const factory = (): RtcPeerConnection => {
    calls.created++
    return { get localDescription() { return localDescription as PeerDescription ?? null }, iceGatheringState: 'complete', connectionState: 'connecting',
      createOffer: async () => offer, createAnswer: async () => answer,
      async setLocalDescription(description) { localDescription = description }, async setRemoteDescription() {},
      createDataChannel() { throw new Error('ANSWERER_MUST_NOT_CREATE_CHANNEL') },
      addEventListener: (name, listener) => events.addEventListener(name, listener), removeEventListener: (name, listener) => events.removeEventListener(name, listener),
      async close() { calls.closed++; await close() } }
  }
  return { calls, factory }
}
function handler(options: { authorize?: () => boolean | Promise<boolean>; timeoutMs?: number; maxPending?: number; closePeer?: () => Promise<void> } = {}) {
  const peer = pendingPeer(options.closePeer), accept = vi.fn(async () => { throw new Error('PENDING_CONNECTION_MUST_NOT_BE_ACCEPTED') })
  const value = createWebRtcOfferHandler({ createPeerConnection: peer.factory, accept, authorize: options.authorize ?? (() => true), allowedOrigins: [origin],
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }), ...(options.maxPending === undefined ? {} : { maxPending: options.maxPending }) })
  return { ...peer, handler: value, accept }
}

describe('direct HTTP WebRTC introductions', () => {
  it('returns the answer before ICE completion and bounds pending introductions', async () => {
    const value = handler({ maxPending: 1 })
    try {
      const caller = new AbortController()
      const response = await value.handler.fetch(new Request(request(), { signal: caller.signal }))
      expect(response.status).toBe(200)
      expect(await response.json()).toEqual({ protocol: WEBRTC_HTTP_PROTOCOL, description: answer })
      expect(value.accept).not.toHaveBeenCalled()
      expect(value.handler.stats).toMatchObject({ offers: 1, pending: 1, active: 0 })
      caller.abort()
      expect(value.calls.closed).toBe(0) // Completing/cancelling HTTP does not own the RTC lifecycle.
      expect((await value.handler.fetch(request())).status).toBe(429)
    } finally { await value.handler.close() }
    expect(value.calls.closed).toBe(1)
    expect(value.handler.stats.pending).toBe(0)
  })

  it('rejects origin, authorization, malformed and oversized requests before allocating RTC', async () => {
    const value = handler({ authorize: () => false })
    try {
      expect((await value.handler.fetch(request(body(), { Origin: 'https://untrusted.example' }))).status).toBe(403)
      expect((await value.handler.fetch(request())).status).toBe(403)
      expect((await value.handler.fetch(new Request(url))).status).toBe(405)
      expect((await value.handler.fetch(request(body(), { 'Content-Type': 'text/plain' }))).status).toBe(415)
      expect(value.calls.created).toBe(0)
    } finally { await value.handler.close() }
    const granted = handler()
    try {
      expect((await granted.handler.fetch(request('invalid JSON'))).status).toBe(400)
      expect((await granted.handler.fetch(request(body({ type: 'answer', sdp: 'wrong role' })))).status).toBe(400)
      expect((await granted.handler.fetch(request(body({ type: 'offer', sdp: 'x'.repeat(64 * 1024 + 1) })))).status).toBe(400)
      expect((await granted.handler.fetch(request('x'.repeat(WEBRTC_HTTP_LIMITS.messageBytes + 1)))).status).toBe(413)
      expect((await granted.handler.fetch(request(body(), { 'Content-Length': String(WEBRTC_HTTP_LIMITS.messageBytes + 1) }))).status).toBe(413)
      expect(granted.calls.created).toBe(0)
    } finally { await granted.handler.close() }
    const mistaken = handler({ authorize: () => 'truthy configuration mistake' as unknown as boolean })
    try { expect((await mistaken.handler.fetch(request())).status).toBe(403); expect(mistaken.calls.created).toBe(0) }
    finally { await mistaken.handler.close() }
  })

  it('serves only an explicit-origin POST preflight without allocating or authorizing a peer', async () => {
    const authorize = vi.fn(() => true), value = handler({ authorize })
    try {
      const preflight = new Request(url, { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'authorization, content-type' } })
      const response = await value.handler.fetch(preflight)
      expect(response.status).toBe(204)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe(origin)
      expect(response.headers.get('Access-Control-Allow-Credentials')).toBeNull()
      expect(authorize).not.toHaveBeenCalled(); expect(value.calls.created).toBe(0)
    } finally { await value.handler.close() }
  })

  it('expires a body whose reader and cancellation promise never settle', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => undefined))
    const stream = new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => undefined), cancel })
    const value = handler({ timeoutMs: 20 })
    try {
      const response = await value.handler.fetch(new Request(url, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' },
        body: stream, ...{ duplex: 'half' } }))
      expect(response.status).toBe(408)
      await expect.poll(() => value.handler.stats.pending).toBe(0)
      expect(cancel).toHaveBeenCalledOnce(); expect(value.calls.created).toBe(0)
    } finally { await value.handler.close() }
  })

  it('keeps an expired native connection counted until its asynchronous close finishes', async () => {
    let release!: () => void
    const closing = new Promise<void>(resolve => { release = resolve })
    const value = handler({ timeoutMs: 20, maxPending: 1, closePeer: () => closing })
    try {
      expect((await value.handler.fetch(request())).status).toBe(200)
      await expect.poll(() => value.calls.closed).toBe(1)
      expect(value.handler.stats.pending).toBe(1)
      expect((await value.handler.fetch(request())).status).toBe(429)
      release()
      await expect.poll(() => value.handler.stats.pending).toBe(0)
    } finally { release(); await value.handler.close() }
  })

  it('sends one credential-isolated offer and consumes one bounded answer', async () => {
    const fetcher = vi.fn<typeof globalThis.fetch>(async () => Response.json({ protocol: WEBRTC_HTTP_PROTOCOL, description: answer }))
    const signaling = createHttpWebRtcSignaling({ url, fetch: fetcher, headers: { Authorization: 'Bearer introduction-test' } })
    try {
      await signaling.send(offer)
      expect((await signaling.messages[Symbol.asyncIterator]().next()).value).toEqual(answer)
      await expect(signaling.send(offer)).rejects.toThrow('ALREADY_SENT')
      expect(fetcher).toHaveBeenCalledOnce()
      expect(fetcher.mock.calls[0]![1]).toMatchObject({ method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store' })
      expect(signaling.stats.requests).toBe(1)
    } finally { signaling.close() }
    expect(signaling.stats.closed).toBe(true)
    for (const address of ['http://resident.example/introduce', `${url}?token=secret`, 'https://secret@resident.example/introduce']) {
      expect(() => createHttpWebRtcSignaling({ url: address })).toThrow('HTTPS_REQUIRED')
    }
  })

  it('bounds injected fetch and response streams even if they ignore cancellation', async () => {
    const ignored = createHttpWebRtcSignaling({ url, timeoutMs: 20, fetch: () => new Promise<Response>(() => undefined) })
    await expect(ignored.send(offer)).rejects.toThrow('SIGNALING_TIMEOUT')
    expect(ignored.stats.closed).toBe(true)
    const cancel = vi.fn(() => new Promise<void>(() => undefined))
    const blocked = createHttpWebRtcSignaling({ url, timeoutMs: 20,
      fetch: async () => new Response(new ReadableStream({ pull: () => new Promise<void>(() => undefined), cancel }), { headers: { 'Content-Type': 'application/json' } }) })
    await expect(blocked.send(offer)).rejects.toThrow('SIGNALING_TIMEOUT')
    expect(cancel).toHaveBeenCalledOnce()
  })
})

it('cold-connects a resident through actual HTTP and keeps native RTC alive after its listener stops', async () => {
  const interfaces = vi.spyOn(os, 'networkInterfaces').mockReturnValue({})
  syncBuiltinESMExports()
  const factory = () => createNativePeerConnection({}, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false })
  const errors: unknown[] = []
  const endpoint = createWebRtcOfferHandler({ createPeerConnection: factory, allowedOrigins: [origin],
    authorize: incoming => incoming.headers.get('Authorization') === 'Bearer introduction-test', onError: error => errors.push(error),
    async accept(connection) {
      const completion = (async () => { for await (const frame of connection.frames()) await connection.send(frame) })()
      return { completion, close: () => connection.close() }
    } })
  const server = createServer((incoming, outgoing) => {
    const req = new Request(`http://127.0.0.1${incoming.url}`, { method: incoming.method ?? 'POST',
      headers: incoming.headers as HeadersInit, body: Readable.toWeb(incoming) as ReadableStream<Uint8Array>, ...{ duplex: 'half' } })
    void endpoint.fetch(req).then(async response => {
      const headers: Record<string, string> = {}
      response.headers.forEach((value, name) => { headers[name] = value })
      outgoing.writeHead(response.status, headers); outgoing.end(Buffer.from(await response.arrayBuffer()))
    }).catch(error => { errors.push(error); outgoing.writeHead(500); outgoing.end() })
  })
  let connection: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined
  try {
    server.listen(0, '127.0.0.1'); await once(server, 'listening')
    const address = server.address()
    if (address === null || typeof address === 'string') throw new Error('MISSING_LISTENER')
    const signaling = createHttpWebRtcSignaling({ url: `http://127.0.0.1:${address.port}/introduce`,
      headers: { Origin: origin, Authorization: 'Bearer introduction-test' } })
    connection = await openWebRtcConnection({ role: 'offerer', signaling, createPeerConnection: factory })
    await expect.poll(() => endpoint.stats.active).toBe(1)
    expect(signaling.stats).toMatchObject({ requests: 1, closed: true })
    expect(endpoint.stats).toMatchObject({ offers: 1, accepted: 1, pending: 0, failed: 0 })
    server.closeAllConnections()
    await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
    const before = endpoint.stats.requests
    const frames = connection.frames()[Symbol.asyncIterator](), payload = new Uint8Array(48 * 1024 + 7).fill(31)
    await connection.send(payload)
    expect((await frames.next()).value).toEqual(payload)
    expect(endpoint.stats.requests).toBe(before)
    expect(errors).toEqual([])
  } finally {
    await endpoint.close(); await connection?.close()
    server.closeAllConnections()
    if (server.listening) await new Promise<void>(resolve => { server.close(() => resolve()) })
    interfaces.mockRestore(); syncBuiltinESMExports()
  }
})

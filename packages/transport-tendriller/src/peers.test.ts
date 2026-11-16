import { describe, expect, it } from 'vitest'
import { encodeCanonicalCbor } from '@chronolog/protocol'
import { createPeerConnection, decodePeerFrame, PEER_LIMITS, type PeerSocket } from '@tendriller/core/peers'
import { frameTendrillerPeer } from './peers.js'

class Socket extends EventTarget implements PeerSocket {
  readyState = 1
  readonly bufferedAmount = 0
  readonly sent: Uint8Array[] = []
  other?: Socket
  send(value: Uint8Array | string): void {
    if (!(value instanceof Uint8Array)) throw new Error('Only binary application frames in this direct fixture')
    this.sent.push(value.slice())
    this.other?.dispatchEvent(new MessageEvent('message', { data: value.slice().buffer }))
  }
  close(): void {
    if (this.readyState === 3) return
    this.readyState = 3; this.dispatchEvent(new Event('close'))
    this.other?.close()
  }
}
function pair() {
  const left = new Socket(), right = new Socket()
  left.other = right; right.other = left
  const a = createPeerConnection(left, { route: 'direct' }), b = createPeerConnection(right, { route: 'direct' })
  return { left, right, a, b, first: frameTendrillerPeer(a), second: frameTendrillerPeer(b) }
}
const rpc = (bytes: number, value = 1): Uint8Array => encodeCanonicalCbor([1n, 'chronolog/peer/v1', 'range', new Uint8Array(bytes).fill(value)])

describe('public Tendriller framed connection adapter', () => {
  it('fragments a bounded complete RPC message into real public frames and reassembles exact ordered bytes', async () => {
    const { left, first, second } = pair(), reader = second.frames()[Symbol.asyncIterator]()
    const large = rpc(900_000), later = rpc(100, 9)
    const received = reader.next()
    await Promise.all([first.send(large), first.send(later)])
    expect((await received).value).toEqual(large)
    expect((await reader.next()).value).toEqual(later)
    expect(left.sent.length).toBe(5)
    expect(left.sent.every(bytes => bytes.length <= PEER_LIMITS.frameBytes + 3 && decodePeerFrame(bytes).domain === 'records')).toBe(true)
    expect(first.route).toBe('direct')
    expect(first.stats.sentBytes).toBe(left.sent.reduce((total, bytes) => total + bytes.length, 0))
    await reader.return?.(); await first.close()
  })

  it('carries signals in the separate domain and refuses records relabeled as ephemeral', async () => {
    const { first, second, a, left } = pair(), reader = second.frames()[Symbol.asyncIterator]()
    const signal = encodeCanonicalCbor([1n, 'chronolog/ephemeral/v1', 'typing', Uint8Array.of(1)])
    const received = reader.next(); await first.send(signal)
    expect((await received).value).toEqual(signal)
    expect(decodePeerFrame(left.sent[0]!).domain).toBe('signals')
    const invalid = reader.next(); await a.send({ domain: 'signals', payload: rpc(8) })
    await expect(invalid).rejects.toThrow('PEER_PROTOCOL_DOMAIN_MISMATCH')
    await first.close()
  })

  it('rejects out-of-order and truncated assemblies, with no partial message delivery', async () => {
    for (const offset of [0, 9]) {
      const { first, second, a } = pair(), reader = second.frames()[Symbol.asyncIterator]()
      const next = reader.next(), fragment = new Uint8Array(20), header = new DataView(fragment.buffer)
      fragment.set([0x43, 1]); header.setUint32(2, 100, false); header.setUint32(6, offset, false)
      await a.send({ domain: 'records', payload: fragment })
      await first.close()
      await expect(next).rejects.toThrow(offset === 0 ? 'PEER_FRAGMENT_TRUNCATED' : 'PEER_FRAGMENT_INVALID')
    }
  })

  it('bounds complete-message queuing before an unready host session', async () => {
    const socket = new Socket(); socket.readyState = 0
    const host = createPeerConnection(socket, { route: 'direct' }), framed = frameTendrillerPeer(host)
    const message = rpc(1_000_000), pending = [framed.send(message), framed.send(message), framed.send(message), framed.send(message)]
    const results = Promise.allSettled(pending)
    await expect(framed.send(message)).rejects.toThrow('PEER_MESSAGE_BACKPRESSURE')
    await framed.close()
    expect((await results).every(result => result.status === 'rejected')).toBe(true)
    expect(socket.sent).toHaveLength(0)
  })
})

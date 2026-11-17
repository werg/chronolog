import { afterEach, describe, expect, it } from 'vitest'
import { MAX_SIGNAL_BYTES } from '@chronolog/signals'
import type { FramedPeerConnection } from '@chronolog/records'
import { ApplicationSecureChannel, APPLICATION_CHANNEL_LIMITS } from './secure-channel.js'
import { createFramedPeerConnectionPair } from './network-wire.js'

const closing: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closing.splice(0)) await close() })
const bytes = (text: string): Uint8Array => new TextEncoder().encode(text)
const text = (value: Uint8Array): string => new TextDecoder().decode(value)
async function pair(wrap: (raw: FramedPeerConnection) => FramedPeerConnection = raw => raw) {
  const raw = createFramedPeerConnectionPair(), lifetime = new AbortController()
  const a = new ApplicationSecureChannel(wrap(raw[0]), lifetime.signal), b = new ApplicationSecureChannel(raw[1], lifetime.signal)
  const hello = await Promise.all([a.hello(), b.hello()])
  const left = { application: 'private application', author: 'first peer', nonce: 'first fresh nonce', channel: hello[0] },
    right = { application: 'private application', author: 'second peer', nonce: 'second fresh nonce', channel: hello[1] }
  const proofs = await Promise.all([a.prepare(right.channel.receiverKey, left, right), b.prepare(left.channel.receiverKey, right, left)])
  await Promise.all([a.accept(proofs[1], right, left), b.accept(proofs[0], left, right)])
  a.enableSending(); b.enableSending()
  closing.push(() => a.connection.close())
  return { a: a.connection, b: b.connection, raw, lifetime }
}

describe('shared encrypted peer channel', () => {
  it('hides both reliable RPC metadata and complete live signal payloads on the raw transport', async () => {
    const reliable: Uint8Array[] = [], live: Uint8Array[] = []
    const p = await pair(raw => ({ ...raw,
      async send(frame, options) { reliable.push(frame.slice()); await raw.send(frame, options) },
      live: { ...raw.live!, async trySend(frame, options) { live.push(frame.slice()); return raw.live!.trySend(frame, options) } },
    }))
    const received = p.b.frames()[Symbol.asyncIterator](), signals = p.b.live!.frames()[Symbol.asyncIterator]()
    const message = bytes('request contentManifest for private-object'), payload = bytes('private live cursor and location')
    await p.a.send(message); expect((await received.next()).value).toEqual(message)
    expect(await p.a.live!.trySend(payload)).toBe(true); expect((await signals.next()).value).toEqual(payload)
    expect(text(reliable[0]!)).not.toContain('contentManifest'); expect(text(live[0]!)).not.toContain('cursor')
    expect(reliable[0]!.length).toBe(message.length + APPLICATION_CHANNEL_LIMITS.overheadBytes)
    expect(live[0]!.length).toBe(payload.length + APPLICATION_CHANNEL_LIMITS.overheadBytes)
    await p.b.send(message); expect((await p.a.frames()[Symbol.asyncIterator]().next()).value).toEqual(message)
  })

  it.each(['ciphertext', 'plaintext', 'sequence', 'truncate'] as const)('rejects a relay replacing a reliable record with %s', async fault => {
    const p = await pair(raw => ({ ...raw, async send(frame, options) {
      let altered: Uint8Array = frame.slice()
      if (fault === 'ciphertext') altered[altered.length - 1]! ^= 1
      if (fault === 'plaintext') altered = bytes('a forged plaintext response')
      if (fault === 'sequence') new DataView(altered.buffer).setUint32(2, 2)
      if (fault === 'truncate') altered = altered.slice(0, -1)
      await raw.send(altered, options)
    } }))
    await p.a.send(bytes('authenticated response'))
    await expect(p.b.frames()[Symbol.asyncIterator]().next()).rejects.toThrow(fault === 'ciphertext' || fault === 'truncate'
      ? 'APPLICATION_CHANNEL_AUTHENTICATION_FAILED' : fault === 'sequence' ? 'APPLICATION_CHANNEL_SEQUENCE_INVALID' : 'APPLICATION_CHANNEL_FRAME_INVALID')
  })

  it('rejects reliable replay, cross-direction reflection, cross-lane substitution and another connection\'s record', async () => {
    const captured: Uint8Array[] = []
    const p = await pair(raw => ({ ...raw, async send(frame, options) { captured.push(frame.slice()); await raw.send(frame, options) } }))
    const reader = p.b.frames()[Symbol.asyncIterator]()
    await p.a.send(bytes('once only')); expect((await reader.next()).value).toEqual(bytes('once only'))
    await p.raw[0].send(captured[0]!)
    await expect(reader.next()).rejects.toThrow('APPLICATION_CHANNEL_SEQUENCE_INVALID')
    await p.raw[1].send(captured[0]!)
    await expect(p.a.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('APPLICATION_CHANNEL_AUTHENTICATION_FAILED')
    const swapped = captured[0]!.slice(); swapped[1] = 2
    await p.raw[0].live!.trySend(swapped)
    await expect(p.b.live!.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('APPLICATION_CHANNEL_AUTHENTICATION_FAILED')
    const next = await pair()
    await next.raw[0].send(captured[0]!)
    await expect(next.b.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('APPLICATION_CHANNEL_AUTHENTICATION_FAILED')
  })

  it('accepts live loss, drops replay and reordering, and never retries refused dispatch', async () => {
    const captured: Uint8Array[] = []
    const p = await pair(raw => ({ ...raw, live: { ...raw.live!,
      async trySend(frame) { captured.push(frame.slice()); return captured.length !== 1 },
    } }))
    expect(await p.a.live!.trySend(bytes('refused'))).toBe(false)
    for (const value of ['old', 'latest', 'next']) expect(await p.a.live!.trySend(bytes(value))).toBe(true)
    expect(captured).toHaveLength(4)
    const reader = p.b.live!.frames()[Symbol.asyncIterator]()
    for (const index of [2, 1, 2, 3]) await p.raw[0].live!.trySend(captured[index]!)
    expect(text((await reader.next()).value)).toBe('latest')
    expect(text((await reader.next()).value)).toBe('next')
    expect(captured).toHaveLength(4)
  })

  it('authenticates the live sequence and ciphertext before advancing its replay window', async () => {
    const p = await pair(raw => ({ ...raw, live: { ...raw.live!, async trySend(frame, options) {
      const changed = frame.slice(); new DataView(changed.buffer).setUint32(2, 100)
      return raw.live!.trySend(changed, options)
    } } }))
    await p.a.live!.trySend(bytes('private live payload'))
    await expect(p.b.live!.frames()[Symbol.asyncIterator]().next()).rejects.toThrow('APPLICATION_CHANNEL_AUTHENTICATION_FAILED')
  })

  it('keeps independent live dispatch bounded while a reliable dispatch is stalled', async () => {
    let release!: () => void, entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }), started = new Promise<void>(resolve => { entered = resolve })
    const p = await pair(raw => ({ ...raw, async send(frame, options) { entered(); await gate; await raw.send(frame, options) } }))
    const sending = p.a.send(bytes('large reliable transfer'))
    await started
    await expect(p.a.send(bytes('cannot queue twice'))).rejects.toThrow('APPLICATION_NETWORK_BACKPRESSURE')
    const live = p.a.live!.trySend(bytes('fresh live payload'))
    expect(await p.a.live!.trySend(bytes('not queued'))).toBe(false)
    expect(await live).toBe(true)
    expect(text((await p.b.live!.frames()[Symbol.asyncIterator]().next()).value)).toBe('fresh live payload')
    release(); await sending
  })

  it('preserves the full signal budget and refuses oversized or canceled sends before raw dispatch', async () => {
    let calls = 0
    const p = await pair(raw => ({ ...raw, async send(frame, options) { calls++; await raw.send(frame, options) } }))
    const full = new Uint8Array(MAX_SIGNAL_BYTES).fill(7)
    expect(await p.a.live!.trySend(full)).toBe(true)
    expect((await p.b.live!.frames()[Symbol.asyncIterator]().next()).value).toEqual(full)
    await expect(p.a.live!.trySend(new Uint8Array(MAX_SIGNAL_BYTES + 1))).rejects.toThrow('APPLICATION_CHANNEL_FRAME_LIMIT')
    const cancelled = new AbortController(), reason = new Error('canceled before dispatch')
    const sending = p.a.send(bytes('must stay local'), { signal: cancelled.signal }); cancelled.abort(reason)
    await expect(sending).rejects.toBe(reason); expect(calls).toBe(0)
    expect(p.a.signal.aborted).toBe(true); expect(p.b.signal.aborted).toBe(true)
    await p.a.close()
    await expect(p.a.send(bytes('closed'))).rejects.toThrow('APPLICATION_NETWORK_CLOSED')
  })

  it('cannot reuse handshake key material or enable a plaintext downgrade after activation', async () => {
    const [raw] = createFramedPeerConnectionPair(), lifetime = new AbortController()
    const channel = new ApplicationSecureChannel(raw, lifetime.signal)
    closing.push(() => channel.connection.close())
    await channel.hello()
    await expect(channel.hello()).rejects.toThrow('APPLICATION_NETWORK_HANDSHAKE_ORDER')
    expect(() => channel.enableSending()).toThrow('APPLICATION_NETWORK_HANDSHAKE_ORDER')
    await expect(channel.connection.live!.trySend(bytes('unauthenticated'))).rejects.toThrow('APPLICATION_PEER_AUTHENTICATION_REQUIRED')
    channel.clear()
    await expect(channel.hello()).rejects.toThrow('APPLICATION_CHANNEL_CLOSED')
  })
})

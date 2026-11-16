import { assertCanonicalCbor, encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { EphemeralChannel } from './signals.js'

async function fixture() {
  const identity = await generateEd25519KeyPair(), receiverIdentity = await generateEd25519KeyPair()
  const groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2)
  let now = 100, active = true
  const frames: Uint8Array[] = []
  const options = { groupId, identity, grantId, send: async (frame: Uint8Array) => { frames.push(frame) },
    now: () => now, authorize: ({ topic }: { topic: string }) => active && topic === 'typing' }
  const sender = await EphemeralChannel.open(options)
  const receiver = await EphemeralChannel.open({ ...options, identity: receiverIdentity })
  return { sender, receiver, frames, options, setNow(value: number) { now = value }, revoke() { active = false } }
}

describe('authorized ephemeral peer signals', () => {
  it('verifies exact signed identity and rejects replay, tampering and revocation', async () => {
    const f = await fixture()
    const sent = await f.sender.publish('typing', { messageId: 'draft', typing: true })
    const received = await f.receiver.receive(f.frames[0]!)
    expect(received).toEqual(sent)
    await expect(f.receiver.receive(f.frames[0]!)).rejects.toThrow('SIGNAL_REPLAY')
    const tampered = assertCanonicalCbor(f.frames[0]!) as unknown[]
    tampered[10] = 'null'
    await expect(f.receiver.receive(encodeCanonicalCbor(tampered as never))).rejects.toThrow('SIGNAL_SIGNATURE_INVALID')
    await f.sender.publish('typing', false)
    f.revoke()
    await expect(f.receiver.receive(f.frames[1]!)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    await expect(f.sender.publish('typing', true)).rejects.toThrow('SIGNAL_UNAUTHORIZED')
    f.sender.close(); f.receiver.close()
  })

  it('keeps the session replay floor when a later sequence has a shorter TTL', async () => {
    const f = await fixture()
    await f.sender.publish('typing', 'older', { ttlMs: 5000 })
    await f.sender.publish('typing', 'newer', { ttlMs: 10 })
    await f.receiver.receive(f.frames[1]!)
    f.setNow(111)
    await expect(f.receiver.receive(f.frames[0]!)).rejects.toThrow('SIGNAL_REPLAY')
    f.setNow(5200)
    await expect(f.receiver.receive(f.frames[0]!)).rejects.toThrow('SIGNAL_EXPIRED_OR_CLOCK_INVALID')
    f.sender.close(); f.receiver.close()
  })

  it('coalesces slow-consumer values without making a durable event history', async () => {
    const f = await fixture()
    const iterator = f.receiver.subscribe({ topics: ['typing'] })[Symbol.asyncIterator]()
    const first = iterator.next()
    await f.sender.publish('typing', 1); await f.receiver.receive(f.frames[0]!)
    expect((await first).value?.payload).toBe(1)
    await f.sender.publish('typing', 2); await f.receiver.receive(f.frames[1]!)
    await f.sender.publish('typing', 3); await f.receiver.receive(f.frames[2]!)
    expect((await iterator.next()).value?.payload).toBe(3)
    await iterator.return?.()
    f.sender.close(); f.receiver.close()
  })

  it('bounds active sessions without evicting replay protection for live frames', async () => {
    const f = await fixture()
    const receiver = await EphemeralChannel.open({ ...f.options, maxSessions: 1 })
    await f.sender.publish('typing', 1); await receiver.receive(f.frames[0]!)
    const replacement = await EphemeralChannel.open(f.options)
    await replacement.publish('typing', 2)
    await expect(receiver.receive(f.frames[1]!)).rejects.toThrow('SIGNAL_SESSION_QUOTA_EXCEEDED')
    f.setNow(40_000)
    await replacement.publish('typing', 3)
    expect((await receiver.receive(f.frames[2]!)).payload).toBe(3)
    replacement.close(); receiver.close(); f.sender.close(); f.receiver.close()
  })

  it('bounds outgoing queues and preserves backpressure', async () => {
    const f = await fixture()
    let release!: () => void, entered!: () => void
    const started = new Promise<void>((resolve) => { entered = resolve })
    const blocked = new Promise<void>((resolve) => { release = resolve })
    const channel = await EphemeralChannel.open({ ...f.options, maxPendingSends: 1,
      send: async () => { entered(); await blocked } })
    const first = channel.publish('typing', 1)
    await started
    await expect(channel.publish('typing', 2)).rejects.toThrow('SIGNAL_BACKPRESSURE')
    release(); await first
    channel.close(); f.sender.close(); f.receiver.close()
  })
})

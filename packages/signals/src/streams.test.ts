import { afterEach, describe, expect, it } from 'vitest'
import { assertCanonicalCbor, encodeCanonicalCbor } from '@chronolog/canonical'
import { generateSignalIdentity, SignalChannel } from './index.js'

const channels: SignalChannel[] = []
afterEach(() => { for (const channel of channels.splice(0)) channel.close() })
async function channel(options: { localEcho?: boolean; relay?: boolean } = {}) {
  const result = new SignalChannel({ scope: 'collaboration:test', identity: await generateSignalIdentity(), authorize: () => true, ...options })
  channels.push(result); return result
}
async function fixture() {
  const sender = await channel(), receiver = await channel(), frames: Uint8Array[] = []
  sender.attachRoute({ async trySend(frame) { frames.push(frame); return true } })
  return { sender, receiver, frames }
}

describe('signed logical signal streams', () => {
  it('keeps simultaneous runs, endpoint incarnations and recipients independent before latest coalescing', async () => {
    const { sender, receiver, frames } = await fixture()
    const stream = receiver.subscribe({ mode: 'latest' })[Symbol.asyncIterator](), ready = stream.next()
    await sender.send('progress', 'first', { stream: { streamId: 'run-one', endpointId: 'page', endpointIncarnation: 'one', target: 'reviewer' } })
    await receiver.receive(frames[0]!); expect((await ready).value?.payload).toBe('first')
    const variants = [
      { streamId: 'run-one', endpointId: 'page', endpointIncarnation: 'one', target: 'reviewer' },
      { streamId: 'run-two', endpointId: 'page', endpointIncarnation: 'one', target: 'reviewer' },
      { streamId: 'run-one', endpointId: 'page', endpointIncarnation: 'two', target: 'reviewer' },
      { streamId: 'run-one', endpointId: 'page', endpointIncarnation: 'one', target: 'planner' },
    ]
    for (const [index, context] of variants.entries()) {
      await sender.send('progress', index, { stream: context }); await receiver.receive(frames.at(-1)!)
    }
    await sender.send('progress', 'updated', { stream: variants[0]! }); await receiver.receive(frames.at(-1)!)
    const values = await Promise.all(variants.map(() => stream.next()))
    expect(values.map(value => value.value?.payload)).toEqual([1, 2, 3, 'updated'])
    expect(new Set(values.map(value => value.value?.sessionId)).size).toBe(1)
    await stream.return?.()
  })

  it('filters runs before they occupy queue or replacement state', async () => {
    const { sender, receiver, frames } = await fixture()
    const stream = receiver.subscribe({ topics: ['progress'], mode: 'latest', streams: [{ streamId: 'mine', target: 'reviewer' }] })[Symbol.asyncIterator]()
    const ready = stream.next()
    for (let index = 0; index < 80; index++) {
      await sender.send('progress', index, { stream: { streamId: `other-${index}`, target: 'reviewer' } })
      await receiver.receive(frames.at(-1)!)
    }
    await sender.send('progress', 'selected', { stream: { streamId: 'mine', target: 'reviewer' } }); await receiver.receive(frames.at(-1)!)
    expect((await ready).value?.payload).toBe('selected'); await stream.return?.()
  })

  it('authenticates stream scope and rejects malformed endpoint tuples', async () => {
    const { sender, receiver, frames } = await fixture()
    await expect(sender.send('progress', 1, { stream: { streamId: 'run', endpointId: 'spoof' } })).rejects.toThrow('SIGNAL_STREAM_INVALID')
    await sender.send('progress', 1, { stream: { streamId: 'run', endpointId: 'page', endpointIncarnation: 'one' } })
    const decoded = assertCanonicalCbor(frames[0]!, { maxBytes: 16384, maxDepth: 2, maxArrayItems: 13, maxMapItems: 0, maxTextBytes: 16384, maxBlobBytes: 1024 }) as unknown[]
    decoded[11] = JSON.stringify({ streamId: 'other', endpointId: 'page', endpointIncarnation: 'one' })
    await expect(receiver.receive(encodeCanonicalCbor(decoded as Parameters<typeof encodeCanonicalCbor>[0]))).rejects.toThrow('SIGNAL_SIGNATURE_INVALID')
  })

  it('supports explicit local fan-out without durable resources and suppresses relay loops', async () => {
    const local = await channel({ localEcho: true }), hub = await channel({ relay: true }), remote = await channel()
    const localStream = local.subscribe({ mode: 'latest', streams: [{ streamId: 'run' }] })[Symbol.asyncIterator]()
    const localNext = localStream.next()
    const first = await local.send('progress', 1, { stream: { streamId: 'run' } })
    expect((await localNext).value).toEqual(first)
    const remoteStream = remote.subscribe()[Symbol.asyncIterator](), incoming = remoteStream.next()
    hub.attachRoute({ async trySend(frame) { await remote.receive(frame); return true } })
    const incomingRoute = hub.attachRoute({ async trySend(frame) { await local.receive(frame); return true } })
    local.attachRoute({ async trySend(frame) { await incomingRoute.receive(frame); return true } })
    expect(local.delivery).toBe('neighbors'); expect(hub.delivery).toBe('application')
    const sent = await local.send('progress', 2, { stream: { streamId: 'run' } })
    expect((await incoming).value).toEqual(sent)
    await localStream.return?.(); await remoteStream.return?.()
  })
})

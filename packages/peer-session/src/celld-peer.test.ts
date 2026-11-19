import { describe, expect, it, vi } from 'vitest'
import { createCelldPeerTransport, type CelldPeerStream } from './celld-peer.js'

const nodeId = 'a'.repeat(64)
const peer = { identity: 'b'.repeat(64), route: 'directory entry' }

function nativeStream(remoteNodeId = nodeId) {
  let end!: () => void
  const closed = new Promise<void>(resolve => { end = resolve })
  return {
    remoteNodeId, closed,
    readable: new ReadableStream<Uint8Array>(), writable: new WritableStream<Uint8Array>(),
    close: vi.fn(async () => { end() }),
  } satisfies CelldPeerStream
}

describe('celld peer participation transport', () => {
  it('dials the admitted node and accepts a handoff from the same node', async () => {
    const outgoing = nativeStream(), incoming = nativeStream()
    const connect = vi.fn(async () => outgoing)
    const takeInvitation = vi.fn(async () => incoming)
    const resolveEndpoint = vi.fn(async () => ({ nodeId, addrs: ['127.0.0.1:1234'] }))
    const transport = createCelldPeerTransport({ binding: { connect }, resolveEndpoint, takeInvitation })
    const { signal } = new AbortController()
    const dial = await transport.open({ peer }, { signal })
    const invitation = { id: 'one-use-token' }
    const accepted = await transport.open({ peer, invitation }, { signal })
    await Promise.all([dial.close(), accepted.close()])
    expect(resolveEndpoint).toHaveBeenCalledWith(peer, signal)
    expect(connect).toHaveBeenCalledExactlyOnceWith(nodeId, { addrs: ['127.0.0.1:1234'] })
    expect(takeInvitation).toHaveBeenCalledExactlyOnceWith(peer, invitation, signal)
    expect(outgoing.close).toHaveBeenCalledTimes(1)
    expect(incoming.close).toHaveBeenCalledTimes(1)
  })

  it('closes a stream whose Iroh identity differs from the admitted endpoint', async () => {
    const stream = nativeStream('c'.repeat(64))
    const transport = createCelldPeerTransport({
      binding: { connect: async () => stream },
      resolveEndpoint: async () => ({ nodeId }),
      takeInvitation: async () => stream,
    })
    await expect(transport.open({ peer, invitation: 'one-use-token' }, { signal: new AbortController().signal }))
      .rejects.toThrow('CELLD_PEER_ENDPOINT_MISMATCH')
    expect(stream.close).toHaveBeenCalledTimes(1)
  })

  it('joins a dial that settles after cancellation and closes its stream', async () => {
    let settle!: (stream: CelldPeerStream) => void
    const opening = new Promise<CelldPeerStream>(resolve => { settle = resolve })
    const connect = vi.fn(() => opening)
    const stream = nativeStream()
    const transport = createCelldPeerTransport({
      binding: { connect },
      resolveEndpoint: async () => ({ nodeId }),
      takeInvitation: async () => stream,
    })
    const controller = new AbortController()
    const port = transport.open({ peer }, { signal: controller.signal })
    await Promise.resolve()
    expect(connect).toHaveBeenCalledTimes(1)
    const reason = new Error('caller retired')
    controller.abort(reason)
    settle(stream)
    await expect(port).rejects.toBe(reason)
    expect(stream.close).toHaveBeenCalledTimes(1)
  })
})

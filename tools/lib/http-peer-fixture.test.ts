import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { ChangeSignal, frameLivePeerStream, type FeedLink, type FramedPeerConnection } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { openHttpPeerConnection } from '../../test/browser/event-connection.js'
import { createHttpPeerFixture } from './http-peer-fixture.js'

function emptyLink(identity: string): FeedLink {
  const changes = new ChangeSignal()
  return { identity, async head() { return 0n }, async evidenceHead() { return 0n },
    async read() { return [] }, async readEvidence() { return [] }, async readPayload() { return null },
    watch: signal => changes.watch(signal) }
}

describe('paired HTTP qualification transport', () => {
  it('refuses saturated live dispatch without writing or closing its stream', async () => {
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }), writes: Uint8Array[] = []
    const lane = frameLivePeerStream({ readable: new ReadableStream(),
      writable: new WritableStream({ write: bytes => { writes.push(bytes); return gate } }) })
    const first = lane.trySend(new Uint8Array([1]))
    await expect(lane.trySend(new Uint8Array([2]))).resolves.toBe(false)
    release()
    await expect(first).resolves.toBe(true)
    await expect(lane.trySend(new Uint8Array([3]))).resolves.toBe(true)
    expect(writes.map(frame => [...frame.subarray(4)])).toEqual([[1], [3]])
    await lane.close()
    await expect(lane.trySend(new Uint8Array([4]))).rejects.toThrow('PEER_CONNECTION_CLOSED')
  })

  it('keeps a cancelled in-flight write bounded until the underlying stream settles', async () => {
    let release!: () => void, entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }), started = new Promise<void>(resolve => { entered = resolve })
    const writes: Uint8Array[] = [], controller = new AbortController()
    const lane = frameLivePeerStream({ readable: new ReadableStream(),
      writable: new WritableStream({ write(bytes) { writes.push(bytes); entered(); return gate } }) })
    const first = lane.trySend(new Uint8Array([1]), { signal: controller.signal })
    try {
      await started; controller.abort(new Error('observation expired'))
      await expect(lane.trySend(new Uint8Array([2]))).resolves.toBe(false)
      await expect(lane.trySend(new Uint8Array([3]), { signal: controller.signal })).rejects.toThrow('observation expired')
      expect(writes).toHaveLength(1)
      release(); await expect(first).resolves.toBe(true)
      await expect(lane.trySend(new Uint8Array([4]))).resolves.toBe(true)
      expect(writes.map(frame => [...frame.subarray(4)])).toEqual([[1], [4]])
      expect(lane.signal.aborted).toBe(false)
    } finally { release(); await lane.close() }
  })

  it('carries live frames independently of a blocked reliable stream and closes both lanes together', async () => {
    let connected!: (connection: FramedPeerConnection) => void, ended!: () => void, closes = 0
    const accepted = new Promise<FramedPeerConnection>(resolve => { connected = resolve })
    const completion = new Promise<void>(resolve => { ended = resolve })
    const failures: unknown[] = []
    const server = await createHttpPeerFixture({ async accept(connection) {
      connected(connection)
      return { completion, async close() { closes++; ended() } }
    }, onError: error => { failures.push(error) } })
    let client: FramedPeerConnection | undefined
    try {
      client = await openHttpPeerConnection(server.url, server.token)
      const remote = await accepted
      let sentReliable = false
      const sendingReliable = client.send(new Uint8Array([1, 2, 3])).then(() => { sentReliable = true })
      void sendingReliable.catch(() => undefined)
      const receivingLive = remote.live!.frames()[Symbol.asyncIterator]()
      const nextLive = receivingLive.next()
      await client.live!.trySend(new Uint8Array([4, 5]))
      expect((await nextLive).value).toEqual(new Uint8Array([4, 5]))
      expect(sentReliable).toBe(false)

      const receivingReply = client.live!.frames()[Symbol.asyncIterator]()
      const reply = receivingReply.next()
      await remote.live!.trySend(new Uint8Array([6]))
      expect((await reply).value).toEqual(new Uint8Array([6]))
      expect(sentReliable).toBe(false)

      const receivingReliable = remote.frames()[Symbol.asyncIterator]()
      expect((await receivingReliable.next()).value).toEqual(new Uint8Array([1, 2, 3]))
      await sendingReliable
      await client.close(); await completion
      expect(closes).toBe(1)
      expect(failures).toEqual([])
      await Promise.allSettled([receivingLive.return?.(), receivingReply.return?.(), receivingReliable.return?.()])
    } finally { await client?.close(); await server.close() }
  })

  it('refuses invalid fixture admission before creating an authenticated peer owner', async () => {
    let accepted = 0
    const server = await createHttpPeerFixture({ async accept() { accepted++; throw new Error('unexpected admission') }, onError() {} })
    try {
      await expect(openHttpPeerConnection(server.url, 'wrong-token')).rejects.toThrow('PEER_STREAM_OPEN_FAILED: 403')
      expect(accepted).toBe(0)
    } finally { await server.close() }
  })

  it.each(['authorization', 'live protocol'] as const)('reports %s failure after the authenticated owner has closed both streams', async failure => {
    const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
    const groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2), failures: unknown[] = []
    let observed!: (error: unknown) => void
    const reported = new Promise<unknown>(resolve => { observed = resolve })
    const server = await createHttpPeerFixture({ accept: connection => openAuthenticatedPeerLink({ connection,
      local: emptyLink('server'), identity: identities[0], groupId, grantId, authorizePeer: () => failure !== 'authorization' }),
      onError(error) { failures.push(error); observed(error) } })
    let client: FramedPeerConnection | undefined, session: Awaited<ReturnType<typeof openAuthenticatedPeerLink>> | undefined
    try {
      client = await openHttpPeerConnection(server.url, server.token)
      const opening = openAuthenticatedPeerLink({ connection: client, local: emptyLink('client'), identity: identities[1],
        groupId, grantId, authorizePeer: () => true })
      if (failure === 'authorization') {
        // Only the server decides admission here; its close can race client readiness.
        const [result] = await Promise.allSettled([opening])
        if (result.status === 'fulfilled') session = result.value
      }
      else {
        session = await opening
        // Valid framing, invalid live protocol: the authenticated owner must fail.
        await client.live!.trySend(encodeCanonicalCbor([1n, 'unexpected'])).catch(() => undefined)
      }
      const error = await reported
      expect(error).toMatchObject({ message: failure === 'authorization' ? 'PEER_READ_UNAUTHORIZED' : 'SIGNAL_FRAME_INVALID' })
      expect(failures).toEqual([error])
    } finally { await session?.close(); await client?.close(); await server.close() }
  })
})

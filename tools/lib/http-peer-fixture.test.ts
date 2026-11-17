import type { FramedPeerConnection } from '@chronolog/agent-service/framing'
import { describe, expect, it } from 'vitest'

import { openHttpPeerConnection } from '../../test/browser/event-connection.js'
import { createHttpPeerFixture } from './http-peer-fixture.js'

describe('paired HTTP qualification transport', () => {
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
      await client.live!.send(new Uint8Array([4, 5]))
      expect((await nextLive).value).toEqual(new Uint8Array([4, 5]))
      expect(sentReliable).toBe(false)

      const receivingReply = client.live!.frames()[Symbol.asyncIterator]()
      const reply = receivingReply.next()
      await remote.live!.send(new Uint8Array([6]))
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
})

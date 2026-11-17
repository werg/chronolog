import { once } from 'node:events'
import { createServer } from 'node:http'

import type { FramedPeerConnection } from '@chronolog/agent-service/framing'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { encodeCanonicalCbor, generateEd25519KeyPair } from '@chronolog/protocol'
import { ChangeSignal, type FeedLink } from '@chronolog/records'
import { describe, expect, it } from 'vitest'

import { openHttpPeerConnection } from '../../test/browser/event-connection.js'
import { createHttpPeerFixture } from './http-peer-fixture.js'

async function serve(options: {
  readonly accept: (connection: FramedPeerConnection) => Promise<{ readonly completion: Promise<void>; close(): Promise<void> }>
}) {
  const token = crypto.randomUUID(), fixture = createHttpPeerFixture({ token, connect: options.accept })
  const server = createServer((request, response) => {
    void fixture.handle(request, response).then(handled => {
      if (!handled) { response.writeHead(404); response.end() }
    }).catch(() => { response.writeHead(500); response.end() })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('HTTP_FIXTURE_ADDRESS_REQUIRED')
  return { url: `http://127.0.0.1:${address.port}/peer`, token, assertHealthy: () => fixture.assertHealthy(),
    async close() {
      await fixture.close(); server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
    } }
}

function emptyLink(identity: string): FeedLink {
  const changes = new ChangeSignal()
  return { identity, async head() { return 0n }, async evidenceHead() { return 0n },
    async read() { return [] }, async readEvidence() { return [] }, async readPayload() { return null },
    watch: signal => changes.watch(signal) }
}

describe('paired HTTP qualification transport', () => {
  it('carries live frames independently of a blocked reliable stream and closes both lanes together', async () => {
    let connected!: (connection: FramedPeerConnection) => void, ended!: () => void, closes = 0
    const accepted = new Promise<FramedPeerConnection>(resolve => { connected = resolve })
    const completion = new Promise<void>(resolve => { ended = resolve })
    const server = await serve({ async accept(connection) {
      connected(connection)
      return { completion, async close() { closes++; ended() } }
    } })
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
      server.assertHealthy()
      await Promise.allSettled([receivingLive.return?.(), receivingReply.return?.(), receivingReliable.return?.()])
    } finally { await client?.close(); await server.close() }
  })

  it('refuses invalid fixture admission before creating an authenticated peer owner', async () => {
    let accepted = 0
    const server = await serve({ async accept() { accepted++; throw new Error('unexpected admission') } })
    try {
      await expect(openHttpPeerConnection(server.url, 'wrong-token')).rejects.toThrow('PEER_STREAM_OPEN_FAILED: 403')
      expect(accepted).toBe(0)
    } finally { await server.close() }
  })

  it.each(['authorization', 'live protocol', 'reliable protocol'] as const)('preserves %s diagnostics and the corresponding connection boundary', async failure => {
    const identities = await Promise.all([generateEd25519KeyPair(), generateEd25519KeyPair()])
    const groupId = new Uint8Array(32).fill(1), grantId = new Uint8Array(32).fill(2), failures: unknown[] = []
    let observed!: (error: unknown) => void
    const reported = new Promise<unknown>(resolve => { observed = resolve })
    const report = (error: unknown): void => { failures.push(error); observed(error) }
    const server = await serve({ async accept(connection) {
      try {
        const peer = await openAuthenticatedPeerLink({ connection, local: emptyLink('server'), identity: identities[0],
          groupId, grantId, authorizePeer: () => failure !== 'authorization', onSignalError: report })
        void peer.completion.catch(report)
        return peer
      } catch (error) { report(error); throw error }
    } })
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
        // A malformed live message has no authority to end durable replication.
        const lane = failure === 'live protocol' ? client.live! : client
        await lane.send(encodeCanonicalCbor([1n, 'unexpected'])).catch(() => undefined)
      }
      const error = await reported
      const message = failure === 'authorization' ? 'PEER_READ_UNAUTHORIZED'
        : failure === 'live protocol' ? 'signal_frame_invalid' : 'PEER_PROTOCOL_DOMAIN_INVALID'
      expect(error).toMatchObject({ message })
      expect(failures).toEqual([error])
      if (failure === 'reliable protocol') {
        // Cleanup can run before completion rejects; it cannot hide this failure.
        await expect.poll(() => { try { server.assertHealthy(); return null } catch (cause) { return cause } }).toMatchObject({ message })
      } else {
        server.assertHealthy()
        if (failure === 'live protocol') expect(await session!.link.read('server', 0n, 1)).toEqual([])
      }
    } finally { await session?.close(); await client?.close(); await server.close() }
  })
})

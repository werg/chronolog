import { MessageChannel } from 'node:worker_threads'

import { ChronologClient } from '@chronolog/client'
import { bytesToBase64Url, bytesToHex, generateEd25519KeyPair } from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService, type ChronologRpcNodeService } from '@chronolog/rpc/browser'
import { SignalChannel, type Signals } from '@chronolog/signals'
import { expect, it, vi } from 'vitest'

import { serveWorkerRpc, WorkerRpcTransport, type WorkerEndpoint } from './worker-rpc.js'

it('uses the ordinary Worker bridge for signed live delivery, latest backpressure and cancellation', async () => {
  const groupId = new Uint8Array(32).fill(7), group = bytesToBase64Url(groupId)
  const identity = await generateEd25519KeyPair(), remoteIdentity = await generateEd25519KeyPair()
  const local = new SignalChannel({ scope: group, identity, authorize: () => true })
  const remote = new SignalChannel({ scope: group, identity: remoteIdentity, authorize: () => true })
  local.attachRoute({ send: async frame => { await remote.receive(frame) } })
  remote.attachRoute({ send: async frame => { await local.receive(frame) } })
  let pulls = 0, stopped = 0
  const signals: Signals = { send: (topic, payload, options) => local.send(topic, payload, options),
    subscribe: options => ({ async *[Symbol.asyncIterator]() {
      const iterator = local.subscribe(options)[Symbol.asyncIterator]()
      try {
        for (;;) {
          pulls++
          const result = await iterator.next()
          if (result.done) return
          yield result.value
        }
      } finally { stopped++; await iterator.return?.() }
    } }),
  }
  const publish = vi.fn()
  const node = { groupId, publish } as unknown as ChronologRpcNodeService
  const service = new NodeRpcService({ node, signals })
  const channel = new MessageChannel()
  const closePeer = vi.fn(async () => { local.close() })
  const stop = serveWorkerRpc(channel.port1 as unknown as WorkerEndpoint, new InProcessRpcTransport(service), closePeer)
  const client = new ChronologClient({ groupId: group, transport: new WorkerRpcTransport(channel.port2 as unknown as WorkerEndpoint) })
  try {
    const abort = new AbortController()
    const incoming = client.signals.subscribe({ topics: ['typing'], mode: 'latest', signal: abort.signal })[Symbol.asyncIterator]()
    const first = incoming.next()
    await expect.poll(() => pulls).toBe(1)
    const sent = await remote.send('typing', { active: true })
    expect((await first).value).toEqual(sent)
    expect(typeof sent.authorId).toBe('string'); expect(typeof sent.sessionId).toBe('string')

    await remote.send('typing', { active: false })
    const latest = await remote.send('typing', { active: true })
    expect(pulls).toBe(1)
    expect((await incoming.next()).value).toEqual(latest)
    expect(pulls).toBe(2)

    const outgoing = remote.subscribe({ topics: ['typing'] })[Symbol.asyncIterator]()
    const receiving = outgoing.next()
    const published = await client.signals.send('typing', { active: false }, { ttlMs: 1000 })
    expect((await receiving).value).toEqual(published)
    expect(published.authorId).toBe(bytesToHex(identity.publicKeyBytes))
    await outgoing.return?.()
    expect(publish).not.toHaveBeenCalled()

    const waiting = incoming.next()
    const cancelled = expect(waiting).rejects.toMatchObject({ code: 'cancelled' })
    await expect.poll(() => pulls).toBe(3)
    abort.abort()
    await cancelled
    await expect.poll(() => stopped).toBe(1)
    await client.close()
    expect(closePeer).toHaveBeenCalledTimes(1)
  } finally {
    await client.close(); await stop()
    local.close(); remote.close(); channel.port1.close(); channel.port2.close()
  }
})

import { MessageChannel } from 'node:worker_threads'

import { ChronologClient } from '@chronolog/client'
import { bytesToBase64Url, type ApplicationChangeOptions } from '@chronolog/protocol'
import { InProcessRpcTransport, NodeRpcService, type ChronologRpcNodeService } from '@chronolog/rpc/browser'
import { expect, it, vi } from 'vitest'

import { serveWorkerRpc, WorkerRpcTransport, type WorkerEndpoint } from './worker-rpc.js'

it('carries application invalidations through the Worker and releases an idle subscription on cancellation', async () => {
  const groupId = new Uint8Array(32).fill(7), group = bytesToBase64Url(groupId)
  const readView = vi.fn()
  let lifetime: AbortSignal | undefined, stopped!: () => void
  const sourceStopped = new Promise<void>(resolve => { stopped = resolve })
  const node = { groupId, readView, changes: (options: ApplicationChangeOptions = {}) => ({ async *[Symbol.asyncIterator]() {
    lifetime = options.signal!
    try {
      yield { view: options.view ?? 'final', revision: 'current-local', finalRevision: 'current-final' }
      await new Promise<void>(resolve => {
        if (lifetime!.aborted) resolve()
        else lifetime!.addEventListener('abort', () => resolve(), { once: true })
      })
    } finally { stopped() }
  } }) } as unknown as ChronologRpcNodeService
  const channel = new MessageChannel(), closePeer = vi.fn(async () => {})
  const stop = serveWorkerRpc(channel.port1 as unknown as WorkerEndpoint,
    new InProcessRpcTransport(new NodeRpcService({ node })), closePeer)
  const client = new ChronologClient({ groupId: group, transport: new WorkerRpcTransport(channel.port2 as unknown as WorkerEndpoint) })
  try {
    const controller = new AbortController()
    const iterator = client.changes({ view: 'local', signal: controller.signal })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual({ view: 'local', revision: 'current-local', finalRevision: 'current-final' })
    const pending = iterator.next()
    controller.abort()
    expect((await pending).done).toBe(true)
    await sourceStopped
    expect(lifetime?.aborted).toBe(true)
    expect(readView).not.toHaveBeenCalled()
    await client.close()
    expect(closePeer).toHaveBeenCalledTimes(1)
  } finally { await client.close(); await stop(); channel.port1.close(); channel.port2.close() }
})

import { bytesToBase64Url, type ApplicationChangeOptions } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { HttpRpcServer, HttpRpcTransport } from './http.js'
import { InProcessRpcTransport } from './in-process.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService } from './service-contract.js'

const groupId = new Uint8Array(32).fill(8), group = bytesToBase64Url(groupId)
function fixture() {
  const subscriptions: ApplicationChangeOptions[] = []
  const readView = vi.fn(async () => { throw new Error('No read lease is needed') })
  let stopped!: () => void
  const closed = new Promise<void>(resolve => { stopped = resolve })
  const changes = vi.fn((options: ApplicationChangeOptions = {}) => ({ async *[Symbol.asyncIterator]() {
    subscriptions.push(options)
    try {
      yield { view: options.view ?? 'final', revision: 'opaque-applied-view', finalRevision: 'opaque-final-prefix' }
      await new Promise<void>(resolve => {
        if (options.signal!.aborted) resolve()
        else options.signal!.addEventListener('abort', () => resolve(), { once: true })
      })
    } finally { stopped() }
  } }))
  const node = { groupId, revision: 1n, changes, readView } as unknown as ChronologRpcNodeService
  return { service: new NodeRpcService({ node }), changes, readView, subscriptions, closed }
}

describe('view changes RPC', () => {
  it('delegates current-view invalidations without acquiring a read lease', async () => {
    const f = fixture(), transport = new InProcessRpcTransport(f.service)
    const iterator = transport.stream('view.changes', { groupId: group })[Symbol.asyncIterator]()
    try {
      expect((await iterator.next()).value).toEqual({ view: 'final', revision: 'opaque-applied-view', finalRevision: 'opaque-final-prefix' })
      expect(f.subscriptions).toMatchObject([{ view: 'final', signal: expect.any(AbortSignal) }])
      expect(f.readView).not.toHaveBeenCalled()
    } finally { await iterator.return?.(); await transport.close() }
  })

  it('validates group, view and feature availability before starting a stream', async () => {
    const f = fixture(), transport = new InProcessRpcTransport(f.service)
    await expect(transport.stream('view.changes', { groupId: 'wrong' })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'not_found' })
    await expect(transport.stream('view.changes', { groupId: group, view: 'invalid' as 'local' })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'invalid_argument' })
    expect(f.changes).not.toHaveBeenCalled()
    await transport.close()
    const missing = new InProcessRpcTransport(new NodeRpcService({ node: { groupId, revision: 1n } as ChronologRpcNodeService }))
    await expect(missing.stream('view.changes', { groupId: group })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'failed_precondition' })
    await missing.close()
  })

  it('closes an idle subscription when its service closes', async () => {
    const f = fixture(), iterator = f.service.changes({ groupId: group, view: 'local' }, { method: 'view.changes' })[Symbol.asyncIterator]()
    await iterator.next()
    const pending = iterator.next()
    await f.service.close()
    expect((await pending).done).toBe(true)
    await f.closed
    expect(f.subscriptions[0]!.signal?.aborted).toBe(true)
  })

  it('keeps the HTTP stream authenticated and preserves exact application tokens', async () => {
    const f = fixture(), server = new HttpRpcServer({ service: f.service, port: 0, token: 'owner-token' })
    const transport = new HttpRpcTransport({ baseUrl: (await server.listen()).url })
    try {
      await expect(transport.stream('view.changes', { groupId: group })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'unauthenticated' })
      expect(f.changes).not.toHaveBeenCalled()
      const iterator = transport.stream('view.changes', { groupId: group, view: 'local' }, { token: 'owner-token' })[Symbol.asyncIterator]()
      expect((await iterator.next()).value).toEqual({ view: 'local', revision: 'opaque-applied-view', finalRevision: 'opaque-final-prefix' })
      expect(f.readView).not.toHaveBeenCalled()
      await iterator.return?.(); await f.closed
      expect(f.subscriptions[0]!.signal?.aborted).toBe(true)
    } finally { await transport.close(); await server.close() }
  })
})

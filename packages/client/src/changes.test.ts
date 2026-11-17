import type { ViewChange } from '@chronolog/protocol'
import { ChronologRpcError, type RpcCallOptions, type RpcTransport } from '@chronolog/rpc'
import { describe, expect, it, vi } from 'vitest'

import { ChronologClient } from './client.js'

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
function untilAborted(signal: AbortSignal) {
  return signal.aborted ? Promise.resolve() : new Promise<void>(resolve => signal.addEventListener('abort', () => resolve(), { once: true }))
}
const state = (revision: string): ViewChange => ({ view: 'local', revision, finalRevision: 'immutable' })

describe('application change subscriptions', () => {
  it('uses one bounded latest snapshot without read leases or unary queries', async () => {
    const advance = deferred(), delivered = deferred(), stopped = deferred()
    const calls: Array<{ method: string; request: unknown }> = []
    const unary = vi.fn(async () => { throw new Error('No SQL or read-view call is needed') })
    let lifetime: AbortSignal | undefined
    const transport = { unary, stream: (method: string, request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      calls.push({ method, request }); lifetime = options.signal!
      try {
        yield state('first'); await advance.promise
        yield state('second'); yield state('third')
        delivered.resolve(); await untilAborted(lifetime)
      } finally { stopped.resolve() }
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const iterator = client.changes({ view: 'local' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(state('first'))
    advance.resolve(); await delivered.promise
    expect((await iterator.next()).value).toEqual(state('third'))
    expect(calls).toEqual([{ method: 'view.changes', request: { groupId: 'group', view: 'local' } }])
    expect(unary).not.toHaveBeenCalled()
    await iterator.return?.(); await stopped.promise
    expect(lifetime?.aborted).toBe(true)
    await client.close()
  })

  it('reconnects to current state without inventing a durable cursor', async () => {
    const disconnected = deferred(), reconnected = deferred()
    const calls: Array<{ method: string; request: unknown }> = []
    const transport = { stream: (method: string, request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      calls.push({ method, request })
      if (calls.length === 1) {
        yield state('before-disconnect'); await disconnected.promise
        throw new ChronologRpcError('transport_unavailable', 'Disconnected')
      }
      yield state('current-after-reconnect'); reconnected.resolve()
      await untilAborted(options.signal!)
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', streamRetryDelayMs: () => 0 })
    const iterator = client.changes({ view: 'local' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(state('before-disconnect'))
    disconnected.resolve(); await reconnected.promise
    expect((await iterator.next()).value).toEqual(state('current-after-reconnect'))
    expect(calls).toEqual(Array.from({ length: 2 }, () => ({ method: 'view.changes', request: { groupId: 'group', view: 'local' } })))
    await iterator.return?.(); await client.close()
  })

  it.each(['return', 'throw', 'abort', 'close'] as const)('releases an idle source on %s', async action => {
    const stopped = deferred(), controller = new AbortController()
    let lifetime: AbortSignal | undefined
    const transport = { stream: (_method: string, _request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      lifetime = options.signal!
      try { yield { view: 'final' as const, revision: 'final', finalRevision: 'final' }; await untilAborted(lifetime) }
      finally { stopped.resolve() }
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const iterator = client.changes({ signal: controller.signal })[Symbol.asyncIterator]()
    await iterator.next()
    const pending = iterator.next()
    if (action === 'return') await iterator.return?.()
    else if (action === 'throw') await expect(iterator.throw?.(new Error('stop'))).rejects.toThrow('stop')
    else if (action === 'abort') controller.abort()
    else await client.close()
    expect((await pending).done).toBe(true)
    await stopped.promise
    expect(lifetime?.aborted).toBe(true)
    expect((await iterator.next()).done).toBe(true)
    await client.close()
  })

  it.each(['abort', 'close'] as const)('drops a paused snapshot and releases its source on %s', async action => {
    const delivered = deferred(), stopped = deferred(), controller = new AbortController()
    const transport = { stream: (_method: string, _request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      try {
        yield state('initial'); yield state('pending'); delivered.resolve()
        await untilAborted(options.signal!)
      } finally { stopped.resolve() }
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const iterator = client.changes({ view: 'local', signal: controller.signal })[Symbol.asyncIterator]()
    await iterator.next(); await delivered.promise
    if (action === 'abort') controller.abort()
    else await client.close()
    await stopped.promise
    expect((await iterator.next()).done).toBe(true)
    await client.close()
  })

  it('surfaces a terminal authorization error without reconnecting', async () => {
    const stream = vi.fn(() => ({ async *[Symbol.asyncIterator]() { throw new ChronologRpcError('permission_denied', 'Access revoked') } }))
    const client = new ChronologClient({ transport: { stream } as unknown as RpcTransport, groupId: 'group' })
    await expect(client.changes()[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'permission_denied' })
    expect(stream).toHaveBeenCalledTimes(1)
    await client.close()
  })
})

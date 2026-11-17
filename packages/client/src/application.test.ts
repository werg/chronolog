import { decodeChangeProgram, emit, program, type EventBatch, type ViewChange } from '@chronolog/protocol'
import { ChronologRpcError, type RpcCallOptions, type RpcTransport, type SubmitChangeRequest } from '@chronolog/rpc'
import type { EphemeralSignal } from '@chronolog/signals'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'

const batch = (cursor: string): EventBatch => ({ transactions: [], revision: `revision-${cursor}`, scannedThrough: cursor, hasMore: false })

describe('application client', () => {
  it('reconnects view invalidations from current state and cancels an abandoned pending pull', async () => {
    const requests: unknown[] = []
    let disconnect!: () => void
    const disconnected = new Promise<void>(resolve => { disconnect = resolve })
    let lifetime: AbortSignal | undefined, stopped = 0
    const transport = { stream: (method: string, request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      expect(method).toBe('view.changes'); requests.push(request); lifetime = options.signal
      try {
        yield { view: 'local', revision: `local-${requests.length}`, finalRevision: 'final-1' }
        if (requests.length === 1) { await disconnected; throw new ChronologRpcError('transport_unavailable', 'Worker restarted') }
        await new Promise<void>(resolve => {
          if (lifetime!.aborted) resolve()
          else lifetime!.addEventListener('abort', () => resolve(), { once: true })
        })
      } finally { stopped++ }
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', streamRetryDelayMs: () => 0, requestId: () => 'view-notifications' })
    const selection: { view: 'local' | 'final' } = { view: 'local' }
    const changes = client.changes(selection)
    selection.view = 'final'
    const iterator = changes[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.revision).toBe('local-1')
    disconnect()
    expect((await iterator.next()).value?.revision).toBe('local-2')
    expect(requests).toEqual([{ groupId: 'group', requestId: 'view-notifications', view: 'local' }, { groupId: 'group', requestId: 'view-notifications', view: 'local' }])
    const pending = iterator.next()
    await iterator.return?.()
    expect(await pending).toMatchObject({ done: true })
    expect(lifetime?.aborted).toBe(true)
    await expect.poll(() => stopped).toBe(2)
    await client.close()
  })

  it('never retries a live send after a lost reply, even when durable unary retries are enabled', async () => {
    const calls: unknown[] = []
    const transport = { unary: async (method: string, request: unknown) => {
      calls.push({ method, request })
      throw new ChronologRpcError('transport_unavailable', 'Reply lost after send')
    } } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', unaryRetryAttempts: 5, requestId: () => 'live-attempt' })
    await expect(client.signals.send('typing', { active: true }, { ttlMs: 1000 })).rejects.toMatchObject({ code: 'transport_unavailable' })
    expect(calls).toEqual([{ method: 'signals.send', request: {
      groupId: 'group', topic: 'typing', payload: { active: true }, ttlMs: 1000,
    } }])
    await client.close()
  })

  it('copies live filters, preserves string identities, and ends a disconnected subscription without resume', async () => {
    const value: EphemeralSignal = { scope: 'group', authorId: 'author', sessionId: 'session', sequence: 1,
      topic: 'typing', payload: { active: true }, issuedAtMs: 100, expiresAtMs: 200 }
    const calls: unknown[] = []
    let lifetime: AbortSignal | undefined
    const transport = { stream: (method: string, request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      calls.push({ method, request }); lifetime = options.signal
      yield value
      throw new ChronologRpcError('transport_unavailable', 'Live connection ended')
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', streamRetryDelayMs: () => 0, requestId: () => 'live-stream' })
    const topics = ['typing']
    const source = client.signals.subscribe({ topics, mode: 'latest' })
    topics.push('changed-after-subscribe')
    const iterator = source[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(value)
    await expect(iterator.next()).rejects.toMatchObject({ code: 'transport_unavailable' })
    expect(lifetime?.aborted).toBe(true)
    expect(calls).toEqual([{ method: 'signals.subscribe', request: {
      groupId: 'group', topics: ['typing'], mode: 'latest',
    } }])
    await client.close()
  })

  it('cancels outstanding live intent when its client closes', async () => {
    let signal: AbortSignal | undefined
    const transport = { unary: async (_method: string, _request: unknown, options: RpcCallOptions) => {
      signal = options.signal
      return new Promise((_resolve, reject) => signal!.addEventListener('abort', () => reject(signal!.reason), { once: true }))
    } } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const sending = client.signals.send('typing', { active: true })
    const rejected = expect(sending).rejects.toMatchObject({ code: 'cancelled' })
    await client.close(); await rejected
    expect(signal?.aborted).toBe(true)
  })

  it('carries requested and approved SQL/topic/signal scopes without broadening either request', async () => {
    const calls: Array<{ method: string; request: unknown }> = []
    const transport = { unary: async (method: string, request: unknown) => {
      calls.push({ method, request }); return method === 'enrollment.createRequest' ? { signedRequest: 'signed' } : { signedApproval: 'approved' }
    } } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const requested = { sql: true, topics: ['conversation', 'jobs'], signals: ['typing'], forwarded: false }
    const approved = { sql: false, topics: ['conversation'], signals: ['typing'], forwarded: false }
    await client.enrollment.createRequest({ requestId: 'device', roles: ['reader', 'writer'], writerProgram: requested })
    await client.enrollment.approveRequest({ operationId: 'approve', signedRequest: 'signed', roles: ['reader', 'writer'], writerProgram: approved, grantFullHistory: false })
    expect(calls).toEqual([
      { method: 'enrollment.createRequest', request: { groupId: 'group', requestId: 'device', roles: ['reader', 'writer'], writerProgram: requested } },
      { method: 'enrollment.approveRequest', request: { groupId: 'group', requestId: 'approve', signedRequest: 'signed', roles: ['reader', 'writer'], writerProgram: approved, grantFullHistory: false } },
    ])
    await client.close()
  })

  it('retries a copied signed proposal and follows the original transaction identity', async () => {
    const original = new Uint8Array([1, 3, 7])
    const requests: Array<{ signedWire: Uint8Array; requestId: string }> = []
    const transport = { unary: async (method: string, request: { signedWire: Uint8Array; requestId: string }) => {
      expect(method).toBe('ingress.submit'); requests.push(request)
      if (requests.length === 1) { original.fill(0); throw new ChronologRpcError('transport_unavailable', 'reply lost') }
      return { transactionId: 'original-proposal' }
    }, stream: () => ({ async *[Symbol.asyncIterator]() { /* observe only when requested */ } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const handle = await client.submitSigned(original)
    expect(handle.transactionId).toBe('original-proposal')
    expect(handle.operationId).toBeUndefined()
    expect(requests).toHaveLength(2)
    expect(requests[0]!.requestId).toBe(requests[1]!.requestId)
    expect(requests[1]!.signedWire).toEqual(new Uint8Array([1, 3, 7]))
    handle.dispose(); await client.close()
  })

  it('publishes events as canonical change programs with the original operation identity', async () => {
    const calls: SubmitChangeRequest[] = []
    const transport = { unary: async (method: string, request: SubmitChangeRequest) => {
      expect(method).toBe('change.submit'); calls.push(request)
      return { operationId: request.operationId, proposalId: 'tx-a', transactionId: 'tx-a' }
    }, stream: () => ({ async *[Symbol.asyncIterator]() { /* handles stay idle until observed */ } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const event = await client.events.publish('chat', { messageId: 'one', text: 'Hello' }, { operationId: 'operation-one' })
    expect(event.operationId).toBe('operation-one'); expect(event.proposalId).toBe('tx-a')
    expect(decodeChangeProgram(calls[0]!.program)).toEqual(program(emit('chat', { messageId: 'one', text: 'Hello' })))
    event.dispose(); await client.close()
  })

  it('keeps durable batches uncoalesced and reconnects from received progress after the next pull', async () => {
    const requests: Array<{ cursor?: string; topics?: readonly string[] }> = []
    let pulls = 0
    const transport = { stream: (_method: string, request: { cursor?: string; topics?: readonly string[] }) => ({ async *[Symbol.asyncIterator]() {
      requests.push(request)
      pulls++
      if (requests.length === 1) { yield batch('after-empty'); throw new ChronologRpcError('transport_unavailable', 'Disconnected') }
      yield batch('after-event')
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', streamRetryDelayMs: () => 0 })
    const topics = ['chat']
    const source = client.events.subscribe({ topics, cursor: 'processed-before-start' })
    topics.push('new-filter')
    const iterator = source[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(batch('after-empty'))
    await Promise.resolve(); expect(pulls).toBe(1)
    expect((await iterator.next()).value).toEqual(batch('after-event'))
    expect(requests.map(request => request.cursor)).toEqual(['processed-before-start', 'after-empty'])
    expect(requests[1]!.topics).toEqual(['chat'])
    await iterator.return?.(); await client.close()
  })

  it('does not hide a changed-filter cursor error by retrying from the beginning', async () => {
    let calls = 0
    const transport = { stream: () => ({ async *[Symbol.asyncIterator]() { calls++; throw new ChronologRpcError('invalid_argument', 'Filter mismatch') } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const iterator = client.events.subscribe({ topics: ['changed'], cursor: 'old' })[Symbol.asyncIterator]()
    await expect(iterator.next()).rejects.toMatchObject({ code: 'invalid_argument' })
    expect(calls).toBe(1); await client.close()
  })

  it('observes keyed finality changes and recovers the original operation after reopening', async () => {
    const states = [{ operationId: 'original', proposalId: 'tx-a', final: false, outcome: { outcome: 'accepted', rejectionCode: null, failingStatementIndex: null } },
      { operationId: 'original', proposalId: 'tx-a', final: true, outcome: { outcome: 'accepted', rejectionCode: null, failingStatementIndex: null } }]
    const transport = { unary: async (method: string, request: { operationId: string }) => {
      expect(method).toBe('operation.get'); expect(request.operationId).toBe('original'); return states[1]
    }, stream: (_method: string, request: { operationId: string }) => ({ async *[Symbol.asyncIterator]() { expect(request.operationId).toBe('original'); yield* states } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const iterator = client.operations.subscribe({ operationId: 'original' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.final).toBe(false)
    expect((await iterator.next()).value?.final).toBe(true)
    await iterator.return?.()
    expect(await client.operations.get('original')).toEqual(states[1]); await client.close()
  })

  it('keeps every read on the same lease and releases before closing its transport', async () => {
    const calls: Array<{ method: string; viewId?: string }> = []
    const transport = { unary: async (method: string, request: { viewId?: string }) => {
      calls.push({ method, ...(request.viewId === undefined ? {} : { viewId: request.viewId }) })
      if (method === 'view.open') return { viewId: 'lease-a', revision: 'captured', finalRevision: 'final', view: 'final', expiresAt: 100 }
      if (method === 'view.query') return { columns: [{ name: 'v' }], rows: [[{ kind: 'integer', value: '3' }]], consensusSafe: false, truncated: false }
      if (method === 'view.events') return batch('captured-events')
      return { released: true }
    }, close: async () => { calls.push({ method: 'transport.close' }) } } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    const view = await client.readView()
    expect(view.revision).toBe('captured')
    expect((await view.query('SELECT v')).rows).toEqual([[3n]])
    expect((await view.readEvents()).scannedThrough).toBe('captured-events')
    await client.close()
    expect(calls.map(call => call.method)).toEqual(['view.open', 'view.query', 'view.events', 'view.release', 'transport.close'])
    expect(calls.slice(1, 4).every(call => call.viewId === 'lease-a')).toBe(true)
    await view.release()
    await expect(view.query('SELECT v')).rejects.toMatchObject({ code: 'revision_unavailable' })
  })

  it('coalesces view invalidations independently of durable event cursors and releases a waiting pull', async () => {
    const calls: unknown[] = []
    let startBurst!: () => void, drained!: () => void, stopped = false, lifetime: AbortSignal | undefined
    const burst = new Promise<void>(resolve => { startBurst = resolve })
    const caughtUp = new Promise<void>(resolve => { drained = resolve })
    const value = (revision: number): ViewChange => ({ view: 'local', revision: `local-${revision}`, finalRevision: 'final-1' })
    const transport = { stream: (method: string, request: unknown, options: RpcCallOptions) => ({ async *[Symbol.asyncIterator]() {
      calls.push({ method, request }); lifetime = options.signal
      try {
        yield value(0)
        await burst
        for (let revision = 1; revision <= 100; revision++) yield value(revision)
        drained()
        await new Promise<void>(resolve => {
          if (options.signal!.aborted) resolve()
          else options.signal!.addEventListener('abort', () => resolve(), { once: true })
        })
      } finally { stopped = true }
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', requestId: () => 'view-watch' })
    const iterator = client.changes({ view: 'local' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(value(0))
    startBurst(); await caughtUp
    expect((await iterator.next()).value).toEqual(value(100))
    const pending = iterator.next()
    await iterator.return?.()
    expect((await pending).done).toBe(true)
    expect(lifetime?.aborted).toBe(true)
    await expect.poll(() => stopped).toBe(true)
    expect(calls).toEqual([{ method: 'view.changes', request: { groupId: 'group', requestId: 'view-watch', view: 'local' } }])
    await client.close()
  })

  it('reconnects view changes from current confirmed state without a replay cursor', async () => {
    const requests: unknown[] = []
    const transport = { stream: (_method: string, request: unknown) => ({ async *[Symbol.asyncIterator]() {
      requests.push(request)
      yield { view: 'final', revision: `final-${requests.length}`, finalRevision: `final-${requests.length}` }
      throw new ChronologRpcError('transport_unavailable', 'Disconnected')
    } }) } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', requestId: () => 'watch', streamRetryDelayMs: () => 0 })
    const iterator = client.changes()[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.revision).toBe('final-1')
    expect((await iterator.next()).value?.revision).toBe('final-2')
    await iterator.return?.()
    expect(requests).toEqual(Array.from({ length: 2 }, () => ({ groupId: 'group', requestId: 'watch', view: 'final' })))
    await client.close()
  })
})

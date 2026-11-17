import { bytesToBase64Url, emit, encodeChangeProgram, program, type EventBatch, type ViewChangeOptions } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'
import type { EphemeralSignal, SignalSubscribeOptions } from '@chronolog/signals'

import { InProcessRpcTransport } from './in-process.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService, RpcReadHandle } from './service-contract.js'
import { HttpRpcServer, HttpRpcTransport } from './http.js'
import type { ChronologRpcService } from './contract.js'

const groupId = new Uint8Array(32).fill(7)
const group = bytesToBase64Url(groupId)
const request = { groupId: group, requestId: 'request-1' }
const batch = (revision = 'view-1'): EventBatch => ({ transactions: [], revision, scannedThrough: 'cursor-after-empty-topic', hasMore: false })
const published = { txId: new TextEncoder().encode('tx-a'), txIdText: 'tx-a', candidateDigest: new Uint8Array(32), core: { authorTimestampMs: 1n, nonce: new Uint8Array(32), executionManifestDigest: new Uint8Array(32) } }

function node(input: Partial<ChronologRpcNodeService>): ChronologRpcNodeService {
  return { groupId, revision: 1n, ...input } as ChronologRpcNodeService
}

function readHandle(revision: string, release: () => void): RpcReadHandle {
  return { revision, finalRevision: revision, view: 'final',
    query: () => ({ revision: 1n, orderLength: 1, columns: [{ name: 'v' }], rows: [[{ kind: 'text', value: revision }]] }),
    readEvents: () => batch(revision), release }
}

describe('application RPC', () => {
  it('streams view metadata without opening read leases or accepting event replay cursors', async () => {
    const readView = vi.fn(), read = vi.fn(), options: unknown[] = []
    const service = new NodeRpcService({ node: node({ readView,
      events: { read, subscribe: () => ({ async *[Symbol.asyncIterator]() { throw new Error('must not replay events') } }) },
      changes: value => ({ async *[Symbol.asyncIterator]() {
        options.push(value); yield { view: value!.view!, revision: 'current', finalRevision: 'final' }
      } }),
    }) })
    const transport = new InProcessRpcTransport(service)
    const iterator = transport.stream('view.changes', { groupId: group, view: 'local' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual({ view: 'local', revision: 'current', finalRevision: 'final' })
    expect(options).toEqual([expect.objectContaining({ view: 'local', signal: expect.any(AbortSignal) })])
    expect(readView).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled()
    await iterator.return?.()
    for (const malformed of [{ groupId: group, view: 'branch' }, { groupId: group, cursor: 'durable-progress' }, request]) {
      await expect(transport.stream('view.changes', malformed as never)[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'invalid_argument' })
    }
    await transport.close()
  })

  it('preserves authenticated event origin on HTTP reads, subscriptions and captured views', async () => {
    const origin = { kind: 'chronolog' as const, groupId: group, authorId: '11'.repeat(32), operationId: 'signed-operation',
      authorTimestampMs: '9007199254740993', membershipRevision: group, writerCapability: group }
    const history: EventBatch = { ...batch(), transactions: [{ proposalId: 'proposal', events: [{ id: 'proposal:0', proposalId: 'proposal', eventOrdinal: 0,
      topic: 'jobs', payload: { origin: { authorId: 'forged-owner' }, $chronologRpc: ['bytes', 'AA=='] }, origin }] }] }
    const service = new NodeRpcService({ node: node({
      events: { read: async () => history, async *subscribe() { yield history } },
      readView: async () => ({ ...readHandle(history.revision, () => undefined), readEvents: () => history }),
    }) })
    const server = new HttpRpcServer({ service, port: 0 })
    const transport = new HttpRpcTransport({ baseUrl: (await server.listen()).url })
    try {
      expect(await transport.unary('events.read', request)).toEqual(history)
      const received = []
      for await (const value of transport.stream('events.subscribe', request)) received.push(value)
      expect(received).toEqual([history])
      const captured = await transport.unary('view.open', request)
      expect(await transport.unary('view.events', { ...request, viewId: captured.viewId })).toEqual(history)
    } finally { await transport.close(); await server.close() }
  })

  it('routes view changes separately from events and cancels them when their service closes', async () => {
    const calls: ViewChangeOptions[] = []
    const service = new NodeRpcService({ node: node({ changes: options => ({ async *[Symbol.asyncIterator]() {
      calls.push(options!)
      yield { view: options!.view!, revision: 'view-1', finalRevision: 'final-1' }
      await new Promise<void>(resolve => {
        if (options!.signal!.aborted) resolve()
        else options!.signal!.addEventListener('abort', () => resolve(), { once: true })
      })
    } }) }) })
    const transport = new InProcessRpcTransport(service)
    const iterator = transport.stream('view.changes', { groupId: group })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual({ view: 'final', revision: 'view-1', finalRevision: 'final-1' })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.view).toBe('final')
    await expect(transport.stream('view.changes', { groupId: group, view: 'invalid' as never })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'invalid_argument' })
    const pending = iterator.next()
    await service.close()
    expect((await pending).done).toBe(true)
    expect(calls[0]!.signal!.aborted).toBe(true)
    await transport.close()
  })

  it('carries live signals over HTTP with exact string identities and no durable publication', async () => {
    const value: EphemeralSignal = { scope: group, authorId: 'author', sessionId: 'session', sequence: 1,
      topic: 'typing', payload: { active: true, $chronologRpc: ['bytes', 'AA=='] }, issuedAtMs: 1, expiresAtMs: 1000 }
    const publish = vi.fn()
    const send = vi.fn(async () => value)
    const subscriptions: SignalSubscribeOptions[] = []
    const service = new NodeRpcService({ node: node({ publish }), signals: { send,
      subscribe: options => ({ async *[Symbol.asyncIterator]() { subscriptions.push(options!); yield value } }),
    } })
    const server = new HttpRpcServer({ service, port: 0 })
    const transport = new HttpRpcTransport({ baseUrl: (await server.listen()).url })
    try {
      expect(await transport.unary('signals.send', { ...request, topic: 'typing', payload: value.payload, ttlMs: 999 })).toEqual(value)
      expect(send).toHaveBeenCalledWith('typing', value.payload, expect.objectContaining({ ttlMs: 999, signal: expect.any(AbortSignal) }))
      const received = []
      for await (const signal of transport.stream('signals.subscribe', { ...request, topics: ['typing'], mode: 'latest' })) received.push(signal)
      expect(received).toEqual([value])
      expect(subscriptions).toHaveLength(1)
      expect(subscriptions[0]).toMatchObject({ topics: ['typing'], mode: 'latest' })
      expect(publish).not.toHaveBeenCalled()
      await expect(transport.unary('signals.send', { ...request, groupId: 'wrong', topic: 'typing', payload: null })).rejects.toMatchObject({ code: 'not_found' })
      expect(send).toHaveBeenCalledTimes(1)
    } finally { await transport.close(); await server.close() }
  })

  it('cancels live service work on close without closing the injected peer signal channel', async () => {
    let lifetime: AbortSignal | undefined
    const signals = { send: vi.fn(async (_topic: string, _payload: unknown, options?: { signal?: AbortSignal }) => {
      lifetime = options?.signal
      return new Promise<EphemeralSignal>((_resolve, reject) => lifetime!.addEventListener('abort', () => reject(lifetime!.reason), { once: true }))
    }), subscribe: () => ({ async *[Symbol.asyncIterator]() { /* no history to replay */ } }), close: vi.fn() }
    const service = new NodeRpcService({ node: node({}), signals })
    const sent = service.sendSignal({ ...request, topic: 'typing', payload: null }, { method: 'signals.send' })
    const rejected = expect(sent).rejects.toMatchObject({ code: 'cancelled' })
    await service.close(); await rejected
    expect(lifetime?.aborted).toBe(true)
    expect(signals.close).not.toHaveBeenCalled()
  })

  it('closes the owning service once when HTTP shutdown calls overlap', async () => {
    const close = vi.fn(async () => { await Promise.resolve() })
    const server = new HttpRpcServer({ service: { close } as unknown as ChronologRpcService, port: 0 })
    await server.listen()
    await Promise.all([server.close(), server.close()])
    expect(close).toHaveBeenCalledTimes(1)
    expect(server.address).toBeNull()
  })

  it('forwards original publisher bytes without invoking local authoring or operation lookup', async () => {
    const publish = vi.fn<ChronologRpcNodeService['publish']>(async () => { throw new Error('must not re-author') })
    const submitSigned = vi.fn(async (_wire: Uint8Array) => published)
    const service = new NodeRpcService({ node: node({ publish, submitSigned }) })
    const transport = new InProcessRpcTransport(service)
    const signedWire = new Uint8Array([3, 8, 21, 55])
    const result = await transport.unary('ingress.submit', { ...request, signedWire })
    expect(result).toMatchObject({ transactionId: 'tx-a', durableLocalAppend: true })
    expect(submitSigned).toHaveBeenCalledWith(signedWire)
    expect(publish).not.toHaveBeenCalled()
    await expect(transport.unary('ingress.submit', { ...request, signedWire: new Uint8Array() })).rejects.toMatchObject({ code: 'invalid_argument' })
    await transport.close()
    const unavailable = new NodeRpcService({ node: node({}) })
    await expect(unavailable.submitSigned({ ...request, signedWire }, { method: 'ingress.submit' })).rejects.toMatchObject({ code: 'failed_precondition' })
    await unavailable.close()
  })

  it('submits canonical programs and emit steps through one principal-scoped operation identity', async () => {
    const publish = vi.fn<ChronologRpcNodeService['publish']>(async () => published)
    const service = new NodeRpcService({ node: node({ publish }) })
    const transport = new InProcessRpcTransport(service)
    const change = program(emit('conversation', { text: 'Hello' }))
    const result = await transport.unary('change.submit', { ...request, operationId: 'message-1', program: encodeChangeProgram(change) }, { metadata: { principal: 'alice' } })
    await transport.unary('transaction.submit', { ...request, idempotencyKey: 'message-1', steps: [{ emit: { topic: 'conversation', payload: { text: 'Hello' } } }] }, { metadata: { principal: 'alice' } })
    await transport.unary('change.submit', { ...request, operationId: 'message-1', program: encodeChangeProgram(change) }, { metadata: { principal: 'bob' } })
    expect(result).toMatchObject({ operationId: 'message-1', proposalId: 'tx-a', transactionId: 'tx-a', durableLocalAppend: true })
    expect(publish.mock.calls[0]![0].program).toEqual(change)
    expect(publish.mock.calls[1]![0].operationId).toBe(publish.mock.calls[0]![0].operationId)
    expect(publish.mock.calls[2]![0].operationId).not.toBe(publish.mock.calls[0]![0].operationId)
    await expect(transport.unary('change.submit', { ...request, operationId: 'bad', program: new Uint8Array([0xff]) })).rejects.toMatchObject({ code: 'invalid_argument' })
    await expect(transport.unary('transaction.submit', { ...request, steps: [{ emit: { topic: 'unauthorized space', payload: {} } }] })).rejects.toMatchObject({ code: 'invalid_argument' })
    await transport.close()
  })

  it('looks up the same durable identity after service recreation without exposing another principal', async () => {
    let identity = ''
    const instance = node({ publish: async input => { identity = input.operationId; return published }, operation: async id => id === identity
      ? { operationId: id, proposalId: 'tx-a', final: true, outcome: { outcome: 'rejected', rejectionCode: 'assert:closed', failingStatementIndex: 0 } } : null })
    const first = new NodeRpcService({ node: instance })
    await first.submitChange({ ...request, operationId: 'claim-1', program: encodeChangeProgram(program(emit('tasks', {}))) }, { method: 'change.submit', token: 'alice' })
    await first.close()
    const reopened = new NodeRpcService({ node: instance })
    expect(await reopened.getOperation({ ...request, operationId: 'claim-1' }, { method: 'operation.get', token: 'alice' })).toMatchObject({ operationId: 'claim-1', final: true, outcome: { rejectionCode: 'assert:closed' } })
    expect(await reopened.getOperation({ ...request, operationId: 'claim-1' }, { method: 'operation.get', token: 'bob' })).toBeNull()
    await reopened.close()
  })

  it('preserves empty event batches and pulls only when the consumer asks', async () => {
    let pulls = 0
    const read = vi.fn(async () => batch())
    const service = new NodeRpcService({ node: node({ events: { read, subscribe: () => ({ async *[Symbol.asyncIterator]() {
      pulls++; yield batch('first'); pulls++; yield batch('second')
    } }) } }) })
    const transport = new InProcessRpcTransport(service)
    expect(await transport.unary('events.read', { ...request, topics: ['idle'], cursor: 'original', limit: 2 })).toEqual(batch())
    expect(read).toHaveBeenCalledWith({ topics: ['idle'], cursor: 'original', limit: 2 })
    const iterator = transport.stream('events.subscribe', request)[Symbol.asyncIterator]()
    expect((await iterator.next()).value?.revision).toBe('first')
    await Promise.resolve(); expect(pulls).toBe(1)
    expect((await iterator.next()).value?.revision).toBe('second')
    await iterator.return?.()
    await service.close()
  })

  it('pins coherent views, deduplicates opens, enforces owner/bounds and releases on close', async () => {
    let revision = 'view-1', released = 0
    const capture = vi.fn(async () => readHandle(revision, () => { released++ }))
    const service = new NodeRpcService({ node: node({ readView: capture }), maxReadViews: 1 })
    const transport = new InProcessRpcTransport(service)
    const captured = await transport.unary('view.open', request, { token: 'alice' })
    revision = 'view-2'
    expect(await transport.unary('view.open', request, { token: 'alice' })).toEqual(captured)
    expect(capture).toHaveBeenCalledTimes(1)
    await expect(transport.unary('view.open', { ...request, requestId: 'second' }, { token: 'alice' })).rejects.toMatchObject({ code: 'resource_exhausted' })
    await expect(transport.unary('view.open', { ...request, view: 'local' }, { token: 'alice' })).rejects.toMatchObject({ code: 'already_exists' })
    const selected = { ...request, viewId: captured.viewId }
    const query = await transport.unary('view.query', { ...selected, sql: 'SELECT v', parameters: [] }, { token: 'alice' })
    expect(query.rows).toEqual([[{ kind: 'text', value: 'view-1' }]])
    expect((await transport.unary('view.events', selected, { token: 'alice' })).revision).toBe('view-1')
    await expect(transport.unary('view.events', selected, { token: 'bob' })).rejects.toMatchObject({ code: 'revision_unavailable' })
    await transport.unary('view.release', selected, { token: 'alice' })
    expect(released).toBe(1)
    await transport.unary('view.open', { ...request, requestId: 'second' }, { token: 'alice' })
    await transport.close()
    expect(released).toBe(2)
  })

  it('expires leaked read leases rather than quietly moving an existing view', async () => {
    let now = 10, released = 0
    const service = new NodeRpcService({ node: node({ readView: async () => readHandle('pinned', () => { released++ }) }), now: () => now, readViewLeaseMs: 100 })
    const opened = await service.openReadView(request, { method: 'view.open' })
    now = 111
    await expect(service.eventsReadView({ ...request, viewId: opened.viewId }, { method: 'view.events' })).rejects.toMatchObject({ code: 'revision_unavailable' })
    expect(released).toBe(1)
    await service.close()
  })

  it('does not fabricate events or snapshots on a node without those ports', async () => {
    const service = new NodeRpcService({ node: node({}) })
    await expect(service.readEvents(request, { method: 'events.read' })).rejects.toMatchObject({ code: 'failed_precondition' })
    await expect(service.openReadView(request, { method: 'view.open' })).rejects.toMatchObject({ code: 'failed_precondition' })
    expect(() => service.viewChanges({ groupId: group }, { method: 'view.changes' })).toThrowError(expect.objectContaining({ code: 'failed_precondition' }))
    await expect(service.sendSignal({ ...request, topic: 'typing', payload: null }, { method: 'signals.send' })).rejects.toMatchObject({ code: 'failed_precondition' })
    await expect(service.subscribeSignals(request, { method: 'signals.subscribe' })[Symbol.asyncIterator]().next()).rejects.toMatchObject({ code: 'failed_precondition' })
    await service.close()
  })

  it('preserves literal JSON transport-marker keys and real bytes over HTTP', async () => {
    const payload = { nested: { $chronologBytes: 'AA==' }, $chronologRpc: ['bytes', 'AA=='], binary: new Uint8Array([1, 2]) }
    const service = { getStatus: async (input: unknown) => input } as unknown as ChronologRpcService
    const server = new HttpRpcServer({ service, port: 0 })
    const transport = new HttpRpcTransport({ baseUrl: (await server.listen()).url })
    try { expect(await transport.unary('node.getStatus', payload as never)).toEqual(payload) }
    finally { await transport.close(); await server.close() }
  })
})

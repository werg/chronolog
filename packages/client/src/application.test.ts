import { decodeChangeProgram, emit, program, type EventBatch } from '@chronolog/protocol'
import { ChronologRpcError, type RpcTransport, type SubmitChangeRequest } from '@chronolog/rpc'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'

const batch = (cursor: string): EventBatch => ({ transactions: [], revision: `revision-${cursor}`, scannedThrough: cursor, hasMore: false })

describe('application client', () => {
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
})

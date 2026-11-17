import { decodeChangeProgram, type SqlStatement } from '@chronolog/protocol'
import type { LocalSqlRequest, LocalSqlResponse, RpcCallOptions, RpcTransport, SubmitChangeRequest, SubmitTransactionResponse } from '@chronolog/rpc'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'
import { platformOp, sqlValue } from './values.js'

function recordingClient(): { readonly client: ChronologClient; readonly submitted: SubmitChangeRequest[] } {
  const submitted: SubmitChangeRequest[] = []
  const response: SubmitTransactionResponse = {
    transactionId: 'tx-1',
    candidateDigest: 'digest',
    authorTimestampMs: '1',
    transactionNonce: 'nonce',
    executionManifestDigest: 'manifest',
    durableLocalAppend: true,
    publishedAt: '2026-11-13T00:00:00.000Z',
  }
  const transport = {
    async unary(method: string, request: SubmitChangeRequest) {
      if (method !== 'change.submit') throw new Error(`unexpected ${method}`)
      submitted.push(request)
      return { ...response, operationId: request.operationId, proposalId: response.transactionId }
    },
    stream() { return { async *[Symbol.asyncIterator]() { /* no events */ } } },
  } as unknown as RpcTransport
  return { client: new ChronologClient({ transport, groupId: 'group-1', requestId: () => 'request-1' }), submitted }
}

describe('ChronologClient.transaction', () => {
  it('submits plain SQL and platform operations through the canonical change program', async () => {
    const { client, submitted } = recordingClient()
    const handle = await client.transaction([
      "SELECT chronolog_assert(1, 'ok')",
      { sql: 'INSERT INTO t VALUES (?, ?, ?, ?, ?)', params: [1, 2n ** 62n, 1.5, 'text', new Uint8Array([1, 2])] },
      { sql: 'UPDATE t SET v = :v, w = @w WHERE id = :id', params: { v: sqlValue.real(1), '@w': null, id: true } },
      platformOp.grant({ table: 't', grantee: new Uint8Array(32).fill(2), operations: ['update'], rowKey: [1n] }),
    ], { operationId: 'key-1' })
    handle.dispose()
    expect(handle.transactionId).toBe('tx-1')
    expect(submitted).toHaveLength(1)
    const request = submitted[0]!
    expect(request.operationId).toBe('key-1')
    const change = decodeChangeProgram(request.program)
    const statement = (index: number): SqlStatement => change.steps[index] as SqlStatement
    expect(handle.operationId).toBe('key-1')
    expect(statement(0)).toEqual({ sql: "SELECT chronolog_assert(1, 'ok')", bindings: [] })
    expect(statement(1).bindings.map((binding) => binding.value)).toEqual([
      { kind: 'integer', value: 1n },
      { kind: 'integer', value: 2n ** 62n },
      { kind: 'real', value: 1.5 },
      { kind: 'text', value: 'text' },
      { kind: 'blob', value: new Uint8Array([1, 2]) },
    ])
    // Platform operations travel as their canonical CBOR.
    expect(change.steps[3]).toEqual(
      platformOp.grant({ table: 't', grantee: new Uint8Array(32).fill(2), operations: ['update'], rowKey: [1n] }))
    expect(statement(2).bindings).toEqual([
      { parameter: { kind: 'name', name: ':v' }, value: { kind: 'real', value: 1 } },
      { parameter: { kind: 'name', name: '@w' }, value: { kind: 'null' } },
      { parameter: { kind: 'name', name: ':id' }, value: { kind: 'integer', value: 1n } },
    ])
    await client.close()
  })

  it('returns the generated durable operation identity for an ordinary transaction', async () => {
    const { client, submitted } = recordingClient()
    const handle = await client.transaction(['SELECT 1'])
    expect(handle.operationId).toMatch(/^[0-9a-f-]{36}$/u)
    expect(submitted[0]?.operationId).toBe(handle.operationId)
    expect(submitted[0]?.requestId).not.toBe(handle.operationId)
    handle.dispose()
    await client.close()
  })

  it('rejects missing and unused named bindings before submitting', async () => {
    const { client, submitted } = recordingClient()
    await expect(client.transaction([{ sql: 'SELECT :a', params: {} }])).rejects.toThrow('Missing SQL binding :a')
    await expect(client.transaction([{ sql: 'SELECT 1', params: { b: 1 } }])).rejects.toThrow('Unused SQL bindings: b')
    expect(submitted).toHaveLength(0)
    await client.close()
  })
})

describe('ChronologClient policy views and enrollment', () => {
  it('keeps final/local query identities distinct and forwards durable enrollment identities', async () => {
    const calls: Array<{ readonly method: string; readonly request: unknown }> = []
    const transport = {
      async unary(method: string, request: unknown) {
        calls.push({ method, request })
        if (method === 'query.localSql') return {
          revision: { groupId: 'group', view: 'final', eventSetRevision: '4', materializedRevision: '2',
            publishedOrderLength: '1', finalRevision: '2', finalOrderLength: '1', executionManifestDigest: 'manifest', replaying: false },
          result: { columns: [{ name: 'answer' }], rows: [[{ kind: 'integer', value: '42' }]], truncated: false, consensusSafe: false },
        }
        if (method === 'enrollment.createRequest') return { signedRequest: 'signed-request' }
        if (method === 'enrollment.approveRequest') return { signedApproval: 'signed-approval' }
        if (method === 'enrollment.getStatus') return { requestId: 'device-join', state: 'awaiting-history', missingEpochs: [], roles: ['reader'] }
        throw new Error(`unexpected ${method}`)
      },
    } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group', requestId: () => 'query-id' })
    expect((await client.query('SELECT 42')).result.rows).toEqual([[42n]])
    expect(client.queryResourceKey('SELECT 42')).toBe(client.queryResourceKey('SELECT 42', [], 'final'))
    expect(client.queryResourceKey('SELECT 42', [], 'local')).not.toBe(client.queryResourceKey('SELECT 42', [], 'final'))
    expect(await client.enrollment.createRequest({ requestId: 'device-join', roles: ['reader'] })).toEqual({ signedRequest: 'signed-request' })
    expect(await client.enrollment.approveRequest({ operationId: 'approve-join', signedRequest: 'signed-request', roles: ['reader'], grantFullHistory: true }))
      .toEqual({ signedApproval: 'signed-approval' })
    expect(await client.enrollment.getStatus('device-join', { signedApproval: 'signed-approval' })).toMatchObject({ state: 'awaiting-history' })
    expect(calls).toEqual([
      { method: 'query.localSql', request: { groupId: 'group', requestId: 'query-id', sql: 'SELECT 42', parameters: [], view: 'final' } },
      { method: 'enrollment.createRequest', request: { groupId: 'group', requestId: 'device-join', roles: ['reader'] } },
      { method: 'enrollment.approveRequest', request: { groupId: 'group', requestId: 'approve-join', signedRequest: 'signed-request', roles: ['reader'], grantFullHistory: true } },
      { method: 'enrollment.getStatus', request: { groupId: 'group', requestId: 'device-join', signedApproval: 'signed-approval' } },
    ])
    await client.close()
  })

  it('defaults queries and live queries to final while keeping local previews explicit', async () => {
    const calls: Array<{ readonly method: string; readonly view: LocalSqlRequest['view'] }> = []
    const response = (request: LocalSqlRequest): LocalSqlResponse => {
      // Deliberately use local if the client forgets to transmit its default.
      const view = request.view ?? 'local'
      return {
        revision: { groupId: 'group', view, eventSetRevision: '4', materializedRevision: view === 'final' ? '2' : '6',
          publishedOrderLength: view === 'final' ? '1' : '3', finalRevision: '2', finalOrderLength: '1', executionManifestDigest: 'manifest', replaying: false },
        result: { columns: [{ name: 'value' }], rows: [[{ kind: 'integer', value: view === 'final' ? '10' : '30' }]], truncated: false, consensusSafe: false },
      }
    }
    const transport = {
      async unary(method: string, request: LocalSqlRequest) {
        calls.push({ method, view: request.view })
        return response(request)
      },
      stream(method: string, request: LocalSqlRequest, options: RpcCallOptions) {
        calls.push({ method, view: request.view })
        return { async *[Symbol.asyncIterator]() {
          yield { type: 'snapshot', queryDigest: request.view, ...response(request) }
          await new Promise<void>((resolve) => {
            if (options.signal?.aborted) resolve()
            else options.signal?.addEventListener('abort', () => resolve(), { once: true })
          })
        } }
      },
    } as unknown as RpcTransport
    const client = new ChronologClient({ transport, groupId: 'group' })
    try {
      expect((await client.query('SELECT value')).result.rows).toEqual([[10n]])
      expect((await client.queryCompiled({ sql: 'SELECT value' })).revision.view).toBe('final')
      expect((await client.query('SELECT value', [], { view: 'local' })).result.rows).toEqual([[30n]])
      for (const view of [undefined, 'local'] as const) {
        const resource = client.liveQuery('SELECT value', [], view === undefined ? {} : { view })
        const iterator = resource[Symbol.asyncIterator]()
        try {
          const snapshot = (await iterator.next()).value
          expect(snapshot?.revision.view).toBe(view ?? 'final')
          expect(snapshot?.result?.rows).toEqual([[view === 'local' ? 30n : 10n]])
        } finally {
          resource.dispose()
          await iterator.return?.()
        }
      }
      expect(calls).toEqual([
        { method: 'query.localSql', view: 'final' },
        { method: 'query.localSql', view: 'final' },
        { method: 'query.localSql', view: 'local' },
        { method: 'query.liveSql', view: 'final' },
        { method: 'query.liveSql', view: 'local' },
      ])
    } finally { await client.close() }
  })
})

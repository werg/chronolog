import { decodePlatformOp } from '@chronolog/protocol'
import type { RpcPlatformStep, RpcSqlStatement, RpcTransport, SubmitTransactionRequest, SubmitTransactionResponse } from '@chronolog/rpc'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'
import { platformOp, sqlValue } from './values.js'

function recordingClient(): { readonly client: ChronologClient; readonly submitted: SubmitTransactionRequest[] } {
  const submitted: SubmitTransactionRequest[] = []
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
    async unary(method: string, request: SubmitTransactionRequest) {
      if (method !== 'transaction.submit') throw new Error(`unexpected ${method}`)
      submitted.push(request)
      return response
    },
    stream() { return { async *[Symbol.asyncIterator]() { /* no events */ } } },
  } as unknown as RpcTransport
  return { client: new ChronologClient({ transport, groupId: 'group-1', requestId: () => 'request-1' }), submitted }
}

describe('ChronologClient.transaction', () => {
  it('submits plain SQL statements with JSON-safe SQLite values', async () => {
    const { client, submitted } = recordingClient()
    const handle = await client.transaction([
      "SELECT chronolog_assert(1, 'ok')",
      { sql: 'INSERT INTO t VALUES (?, ?, ?, ?, ?)', params: [1, 2n ** 62n, 1.5, 'text', new Uint8Array([1, 2])] },
      { sql: 'UPDATE t SET v = :v, w = @w WHERE id = :id', params: { v: sqlValue.real(1), '@w': null, id: true } },
      platformOp.grant({ table: 't', grantee: new Uint8Array(32).fill(2), operations: ['update'], rowKey: [1n] }),
    ], { idempotencyKey: 'key-1' })
    handle.dispose()
    expect(handle.transactionId).toBe('tx-1')
    expect(submitted).toHaveLength(1)
    const request = submitted[0]!
    expect(request.idempotencyKey).toBe('key-1')
    const statement = (index: number): RpcSqlStatement => request.steps[index] as RpcSqlStatement
    expect(statement(0)).toEqual({ sql: "SELECT chronolog_assert(1, 'ok')", bindings: [] })
    expect(statement(1).bindings.map((binding) => binding.value)).toEqual([
      { kind: 'integer', value: '1' },
      { kind: 'integer', value: (2n ** 62n).toString() },
      { kind: 'real', value: 1.5 },
      { kind: 'text', value: 'text' },
      { kind: 'blob', value: new Uint8Array([1, 2]) },
    ])
    // Platform operations travel as their canonical CBOR.
    expect(decodePlatformOp((request.steps[3] as RpcPlatformStep).platform)).toEqual(
      platformOp.grant({ table: 't', grantee: new Uint8Array(32).fill(2), operations: ['update'], rowKey: [1n] }))
    expect(statement(2).bindings).toEqual([
      { parameter: { kind: 'name', name: ':v' }, value: { kind: 'real', value: 1 } },
      { parameter: { kind: 'name', name: '@w' }, value: { kind: 'null' } },
      { parameter: { kind: 'name', name: ':id' }, value: { kind: 'integer', value: '1' } },
    ])
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
    expect((await client.query('SELECT 42', [], { view: 'final' })).result.rows).toEqual([[42n]])
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
})

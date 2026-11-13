import type { RpcTransport, SubmitTransactionRequest, SubmitTransactionResponse } from '@chronolog/rpc'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'
import { sqlValue } from './values.js'

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
    ], { idempotencyKey: 'key-1' })
    handle.dispose()
    expect(handle.transactionId).toBe('tx-1')
    expect(submitted).toHaveLength(1)
    const request = submitted[0]!
    expect(request.idempotencyKey).toBe('key-1')
    expect(request.statements[0]).toEqual({ sql: "SELECT chronolog_assert(1, 'ok')", bindings: [] })
    expect(request.statements[1]?.bindings.map((binding) => binding.value)).toEqual([
      { kind: 'integer', value: '1' },
      { kind: 'integer', value: (2n ** 62n).toString() },
      { kind: 'real', value: 1.5 },
      { kind: 'text', value: 'text' },
      { kind: 'blob', value: new Uint8Array([1, 2]) },
    ])
    expect(request.statements[2]?.bindings).toEqual([
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

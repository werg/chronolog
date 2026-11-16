import { bytesToBase64Url } from '@chronolog/protocol'
import { describe, expect, it, vi } from 'vitest'

import { HttpRpcServer, HttpRpcTransport } from './http.js'
import { NodeRpcService } from './node-service.js'
import type { ChronologRpcNodeService } from './service-contract.js'
import { createHttpPublisherIngress } from './publisher-http.js'

const groupId = new Uint8Array(32).fill(4), group = bytesToBase64Url(groupId)
function service() {
  const publish = vi.fn(async () => { throw new Error('Owner signing must never be invoked') })
  const submitSigned = vi.fn(async (_wire: Uint8Array) => ({ txId: new TextEncoder().encode('tx-original'), txIdText: 'tx-original',
    candidateDigest: new Uint8Array(32), core: { authorTimestampMs: 1n, nonce: new Uint8Array(32), executionManifestDigest: new Uint8Array(32) } }))
  const node = { groupId, revision: 0n, publish, submitSigned } as unknown as ChronologRpcNodeService
  return { rpc: new NodeRpcService({ node }), publish, submitSigned }
}

describe('limited publisher HTTP ingress', () => {
  it('requires explicit enablement and an owner token, while retaining authenticated ingress', async () => {
    const fixture = service()
    expect(() => new HttpRpcServer({ service: fixture.rpc, publisherIngress: true })).toThrow('owner RPC token')
    expect(() => new HttpRpcServer({ service: fixture.rpc, publisherIngress: true, token: '' })).toThrow('owner RPC token')
    const server = new HttpRpcServer({ service: fixture.rpc, token: 'owner-secret', port: 0 })
    const { url } = await server.listen()
    const authenticated = new HttpRpcTransport({ baseUrl: url, token: 'owner-secret' })
    try {
      await expect(createHttpPublisherIngress({ baseUrl: url, groupId: group }).submitSigned(new Uint8Array([1]))).rejects.toMatchObject({ code: 'unauthenticated' })
      expect(fixture.submitSigned).not.toHaveBeenCalled()
      expect(await authenticated.unary('ingress.submit', { groupId: group, requestId: 'authorized', signedWire: new Uint8Array([1]) })).toMatchObject({ transactionId: 'tx-original' })
    } finally { await authenticated.close(); await server.close() }
  })

  it('exposes only exact signed submission without giving the publisher read, administration or local signing', async () => {
    const fixture = service()
    const server = new HttpRpcServer({ service: fixture.rpc, token: 'owner-secret', publisherIngress: true, port: 0 })
    const { url } = await server.listen()
    const sent = vi.fn<typeof fetch>((input, init) => fetch(input, init))
    const publisher = createHttpPublisherIngress({ baseUrl: url, groupId: group, fetch: sent })
    const original = new Uint8Array(512).map((_, index) => index % 256)
    try {
      expect(Object.keys(publisher)).toEqual(['submitSigned'])
      expect(await publisher.submitSigned(original)).toEqual({ proposalId: 'tx-original' })
      expect(fixture.submitSigned).toHaveBeenCalledWith(original)
      expect(fixture.publish).not.toHaveBeenCalled()
      expect(sent.mock.calls[0]![1]).toMatchObject({ credentials: 'omit', redirect: 'error', headers: { 'content-type': 'application/json' } })
      expect(new Headers(sent.mock.calls[0]![1]?.headers).has('authorization')).toBe(false)
      const protectedPaths = [
        '/rpc/unary/events.read', '/rpc/stream/events.subscribe', '/rpc/unary/query.localSql', '/rpc/unary/view.open',
        '/rpc/unary/enrollment.createRequest', '/rpc/unary/enrollment.approveRequest', '/rpc/unary/governance.grantCapability',
        '/rpc/unary/change.submit', '/rpc/unary/transaction.submit', '/rpc/unary/operation.get', '/rpc/unary/transaction.getOutcome',
        '/rpc/unary/ingress.submit?extra=1', '/rpc/unary/ingress%2esubmit', '/rpc/stream/ingress.submit',
      ]
      for (const path of protectedPaths) {
        const response = await fetch(`${url}${path}`, { method: 'POST', body: '{}' })
        expect(response.status, path).toBe(401)
      }
      expect(fixture.submitSigned).toHaveBeenCalledTimes(1)
      expect(fixture.publish).not.toHaveBeenCalled()
      await expect(createHttpPublisherIngress({ baseUrl: url, groupId: bytesToBase64Url(new Uint8Array(32).fill(9)) }).submitSigned(original)).rejects.toMatchObject({ code: 'not_found' })
      expect(fixture.submitSigned).toHaveBeenCalledTimes(1)
    } finally { await server.close() }
  })

  it('keeps anonymous ingress subject to normal body limits and node rejection', async () => {
    const fixture = service()
    const server = new HttpRpcServer({ service: fixture.rpc, token: 'owner-secret', publisherIngress: true, port: 0, maxBodyBytes: 512 })
    const { url } = await server.listen()
    const publisher = createHttpPublisherIngress({ baseUrl: url, groupId: group })
    try {
      await expect(publisher.submitSigned(new Uint8Array(512))).rejects.toMatchObject({ code: 'resource_exhausted' })
      expect(fixture.submitSigned).not.toHaveBeenCalled()
      fixture.submitSigned.mockRejectedValueOnce(new Error('ORIGINAL_SIGNATURE_INVALID'))
      await expect(publisher.submitSigned(new Uint8Array([1]))).rejects.toThrow('ORIGINAL_SIGNATURE_INVALID')
      expect(fixture.publish).not.toHaveBeenCalled()
      await expect(publisher.submitSigned(new Uint8Array())).rejects.toMatchObject({ code: 'invalid_argument' })
    } finally { await server.close() }
  })
})

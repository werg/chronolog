import { describe, expect, it, vi } from 'vitest'

import type { ChronologRpcService, RpcCallContext } from './contract.js'
import { HttpRpcServer } from './http.js'

function serviceWithStatusStream(
  stream: (context: RpcCallContext) => AsyncIterable<unknown>,
): ChronologRpcService {
  return {
    streamStatus(_request: unknown, context: RpcCallContext) { return stream(context) },
  } as unknown as ChronologRpcService
}

async function openStatusStream(url: string): Promise<Response> {
  return fetch(`${url}/rpc/stream/node.streamStatus`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  })
}

describe('HttpRpcServer lifecycle', () => {
  it('serves detailed health and authenticated Prometheus metrics', async () => {
    const server = new HttpRpcServer({
      service: {} as ChronologRpcService,
      port: 0,
      token: 'metrics-secret',
      health: () => ({ ok: false, state: 'degraded' }),
      metrics: () => 'chronolog_up 0\n',
    })
    const address = await server.listen()
    try {
      const health = await fetch(`${address.url}/health`)
      expect(health.status).toBe(503)
      await expect(health.json()).resolves.toEqual({ ok: false, state: 'degraded' })
      expect((await fetch(`${address.url}/metrics`)).status).toBe(401)
      const metrics = await fetch(`${address.url}/metrics`, {
        headers: { authorization: 'Bearer metrics-secret' },
      })
      expect(metrics.status).toBe(200)
      await expect(metrics.text()).resolves.toBe('chronolog_up 0\n')
    } finally {
      await server.close()
    }
  })

  it('aborts active streams before waiting for graceful shutdown', async () => {
    let aborted = false
    const service = serviceWithStatusStream(async function* (context) {
      yield { revision: '1' }
      await new Promise<void>((resolve) => context.signal?.addEventListener('abort', () => {
        aborted = true
        resolve()
      }, { once: true }))
    })
    const server = new HttpRpcServer({ service, port: 0, shutdownTimeoutMs: 100 })
    const address = await server.listen()
    const response = await openStatusStream(address.url)
    const reader = response.body!.getReader()
    await reader.read()

    await server.close()

    expect(aborted).toBe(true)
    expect(server.address).toBeNull()
    reader.releaseLock()
  })

  it('aborts a call when the peer cancels the response body', async () => {
    let resolveAbort: (() => void) | undefined
    const aborted = new Promise<void>((resolve) => { resolveAbort = resolve })
    const service = serviceWithStatusStream(async function* (context) {
      context.signal?.addEventListener('abort', () => resolveAbort?.(), { once: true })
      yield { revision: '1' }
      await new Promise<void>((resolve) => context.signal?.addEventListener('abort', () => resolve(), { once: true }))
    })
    const server = new HttpRpcServer({ service, port: 0, shutdownTimeoutMs: 100 })
    const address = await server.listen()
    const response = await openStatusStream(address.url)
    const reader = response.body!.getReader()
    await reader.read()
    await reader.cancel()

    await expect(aborted).resolves.toBeUndefined()
    await server.close()
  })

  it('bounds shutdown even when a stream handler ignores cancellation', async () => {
    let release: (() => void) | undefined
    const blocked = new Promise<void>((resolve) => { release = resolve })
    const service = serviceWithStatusStream(async function* () {
      yield { revision: '1' }
      await blocked
    })
    const server = new HttpRpcServer({ service, port: 0, shutdownTimeoutMs: 10 })
    const address = await server.listen()
    const response = await openStatusStream(address.url)
    const reader = response.body!.getReader()
    await reader.read()

    const started = performance.now()
    await server.close()
    expect(performance.now() - started).toBeLessThan(250)

    release?.()
    reader.releaseLock()
  })
})

describe('HttpRpcServer signed membership mount', () => {
  it('passes bounded raw CBOR only on the exact separately authenticated route', async () => {
    const bytes = new Uint8Array([0x82, 0x01, 0xff])
    const handler = vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://localhost/_chronolog/membership')
      expect(request.headers.get('content-type')).toBe('application/cbor')
      expect(new Uint8Array(await request.arrayBuffer())).toEqual(bytes)
      return new Response(new Uint8Array([0xa0]).buffer, { headers: { 'content-type': 'application/cbor', 'cache-control': 'no-store' } })
    })
    const server = new HttpRpcServer({ service: {} as ChronologRpcService, port: 0, token: 'owner-secret', membershipLedger: handler })
    const address = await server.listen()
    try {
      const response = await fetch(`${address.url}/_chronolog/membership`, { method: 'POST',
        headers: { 'content-type': 'application/cbor' }, body: bytes.buffer })
      expect(response.status).toBe(200)
      expect(response.headers.get('content-type')).toBe('application/cbor')
      expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([0xa0]))
      for (const path of ['/_chronolog/membership?alias=1', '/_chronolog/%6dembership', '/_chronolog/membership/',
        '/rpc/unary/node.getStatus', '/rpc/unary/governance.grantCapability', '/rpc/stream/events.subscribe']) {
        expect((await fetch(`${address.url}${path}`, { method: 'POST', body: '{}' })).status).toBe(401)
      }
      expect(handler).toHaveBeenCalledTimes(1)
    } finally { await server.close() }
  })

  it('preserves handler authorization failures even when an owner bearer is present', async () => {
    const handler = vi.fn(async () => new Response('MEMBERSHIP_REQUEST_UNAUTHORIZED', { status: 403 }))
    const server = new HttpRpcServer({ service: {} as ChronologRpcService, port: 0, token: 'owner-secret', membershipLedger: handler })
    const address = await server.listen()
    try {
      const response = await fetch(`${address.url}/_chronolog/membership`, { method: 'POST',
        headers: { 'content-type': 'application/cbor', authorization: 'Bearer owner-secret' }, body: new Uint8Array([1]).buffer })
      expect(response.status).toBe(403)
      expect(await response.text()).toBe('MEMBERSHIP_REQUEST_UNAUTHORIZED')
      expect(handler).toHaveBeenCalledTimes(1)
    } finally { await server.close() }
  })

  it('applies the configured request bound before invoking the signed handler', async () => {
    const handler = vi.fn(async () => new Response('unexpected'))
    const server = new HttpRpcServer({ service: {} as ChronologRpcService, port: 0, token: 'owner-secret',
      membershipLedger: handler, maxBodyBytes: 2 })
    const address = await server.listen()
    try {
      const response = await fetch(`${address.url}/_chronolog/membership`, { method: 'POST',
        headers: { 'content-type': 'application/cbor' }, body: new Uint8Array([1, 2, 3]).buffer })
      expect(response.status).toBe(400)
      expect(handler).not.toHaveBeenCalled()
    } finally { await server.close() }
  })

  it('propagates daemon shutdown to an active membership request', async () => {
    let entered!: () => void
    const started = new Promise<void>(resolve => { entered = resolve })
    let aborted = false
    const handler = async (request: Request) => {
      entered()
      await new Promise<void>(resolve => request.signal.addEventListener('abort', () => { aborted = true; resolve() }, { once: true }))
      return new Response('stopped', { status: 503 })
    }
    const server = new HttpRpcServer({ service: {} as ChronologRpcService, port: 0,
      membershipLedger: handler, shutdownTimeoutMs: 10 })
    const address = await server.listen()
    const pending = fetch(`${address.url}/_chronolog/membership`, { method: 'POST',
      headers: { 'content-type': 'application/cbor' }, body: new Uint8Array([1]).buffer }).catch(() => null)
    await started
    await server.close()
    expect(aborted).toBe(true)
    await pending
  })
})

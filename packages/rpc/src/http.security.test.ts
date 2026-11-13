import { request as httpRequest } from 'node:http'

import { afterEach, describe, expect, it } from 'vitest'

import type { ChronologRpcService, RpcCallContext } from './contract.js'
import { ChronologRpcError } from './errors.js'
import { HttpRpcServer, HttpRpcTransport } from './http.js'

const TOKEN = 'correct-horse-battery-staple'

interface Recorded { readonly method: string; readonly input: unknown; readonly context: RpcCallContext }

function recordingService(overrides: Partial<Record<keyof ChronologRpcService, unknown>> = {}): {
  readonly service: ChronologRpcService
  readonly calls: Recorded[]
} {
  const calls: Recorded[] = []
  const service = {
    async getStatus(input: unknown, context: RpcCallContext) {
      calls.push({ method: 'getStatus', input, context })
      return { echoed: input }
    },
    async *streamStatus(input: unknown, context: RpcCallContext) {
      calls.push({ method: 'streamStatus', input, context })
      yield { n: 1 }
      yield { n: 2 }
    },
    ...overrides,
  } as unknown as ChronologRpcService
  return { service, calls }
}

const servers: HttpRpcServer[] = []
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.close())) })

async function start(options: Omit<ConstructorParameters<typeof HttpRpcServer>[0], 'port'>): Promise<string> {
  const server = new HttpRpcServer({ ...options, port: 0 })
  servers.push(server)
  return (await server.listen()).url
}

async function post(url: string, body: string, authorization?: string): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(authorization === undefined ? {} : { authorization }) },
    body,
  })
}

async function errorOf(response: Response): Promise<{ code: string; message: string; retryable: boolean }> {
  const payload = await response.json() as { ok: boolean; error: { code: string; message: string; retryable: boolean } }
  expect(payload.ok).toBe(false)
  return payload.error
}

describe('HttpRpcServer authentication', () => {
  it('rejects missing, wrong, truncated, extended and mis-schemed bearer tokens without dispatching', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service, token: TOKEN })
    const bad: Array<string | undefined> = [
      undefined,
      '',
      'Bearer',
      `Bearer ${TOKEN.slice(0, -1)}`,
      `Bearer ${TOKEN}x`,
      `Bearer ${TOKEN.slice(0, -1)}X`,
      `bearer ${TOKEN}`,
      `Basic ${TOKEN}`,
      `Bearer  ${TOKEN}`,
      TOKEN,
    ]
    for (const authorization of bad) {
      const response = await post(`${url}/rpc/unary/node.getStatus`, '{}', authorization)
      expect(response.status, String(authorization)).toBe(401)
      expect((await errorOf(response)).code).toBe('unauthenticated')
      const stream = await post(`${url}/rpc/stream/node.streamStatus`, '{}', authorization)
      expect(stream.status, String(authorization)).toBe(401)
      await stream.body?.cancel()
    }
    expect(calls).toEqual([])
  })

  it('authenticates before routing, so unauthenticated callers cannot probe methods', async () => {
    const url = await start({ service: recordingService().service, token: TOKEN })
    expect((await post(`${url}/rpc/unary/no.such.method`, '{}')).status).toBe(401)
    expect((await post(`${url}/not-rpc`, '{}')).status).toBe(401)
    expect((await post(`${url}/rpc/unary/no.such.method`, '{}', `Bearer ${TOKEN}`)).status).toBe(404)
  })

  it('accepts the exact token and forwards it to the handler context', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service, token: TOKEN })
    const response = await post(`${url}/rpc/unary/node.getStatus`, '{"a":1}', `Bearer ${TOKEN}`)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true, value: { echoed: { a: 1 } } })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.context.token).toBe(TOKEN)
    expect(calls[0]!.context.method).toBe('node.getStatus')
  })

  it('protects metrics with the token while health stays public', async () => {
    let metricReads = 0
    const url = await start({
      service: recordingService().service,
      token: TOKEN,
      metrics: () => { metricReads += 1; return 'm 1\n' },
    })
    expect((await fetch(`${url}/metrics`, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401)
    expect(metricReads).toBe(0)
    const health = await fetch(`${url}/health`)
    expect(health.status).toBe(200)
    expect(await health.json()).toEqual({ ok: true })
  })
})

describe('HttpRpcServer request validation', () => {
  it('rejects unknown methods, including prototype property names', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    for (const name of ['node.unknown', 'constructor', '__proto__', 'toString', 'hasOwnProperty', 'getStatus']) {
      const response = await post(`${url}/rpc/unary/${encodeURIComponent(name)}`, '{}')
      expect(response.status, name).toBe(404)
      expect((await errorOf(response)).code).toBe('not_found')
    }
    expect(calls).toEqual([])
  })

  it('does not dispatch a unary method through the stream route or vice versa', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    expect((await post(`${url}/rpc/stream/node.getStatus`, '{}')).status).toBe(404)
    expect((await post(`${url}/rpc/unary/node.streamStatus`, '{}')).status).toBe(404)
    expect(calls).toEqual([])
  })

  it('rejects malformed routes and non-POST RPC requests', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    expect((await post(`${url}/rpc/unary/node.getStatus/extra`, '{}')).status).toBe(404)
    expect((await post(`${url}/rpc/other/node.getStatus`, '{}')).status).toBe(404)
    expect((await post(`${url}/rpc/unary/`, '{}')).status).toBe(404)
    expect((await fetch(`${url}/rpc/unary/node.getStatus`)).status).toBe(404)
    expect((await fetch(`${url}/rpc/unary/node.getStatus`, { method: 'PUT', body: '{}' })).status).toBe(404)
    // Malformed percent-encoding in the method segment is a client error, not a crash.
    const badEscape = await post(`${url}/rpc/unary/node%E0%A4%A`, '{}')
    expect(badEscape.status).toBe(400)
    await errorOf(badEscape)
    expect(calls).toEqual([])
  })

  it('rejects malformed JSON bodies without dispatching', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    for (const body of ['{', 'not json', '{"a":}', '']) {
      const response = await post(`${url}/rpc/unary/node.getStatus`, body)
      expect(response.status, body).toBe(400)
      await errorOf(response)
    }
    expect(calls).toEqual([])
  })

  it('rejects bodies larger than the configured limit with resource_exhausted', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service, maxBodyBytes: 64 })
    const ok = await post(`${url}/rpc/unary/node.getStatus`, JSON.stringify({ pad: 'x'.repeat(40) }))
    expect(ok.status).toBe(200)
    const oversized = await post(`${url}/rpc/unary/node.getStatus`, JSON.stringify({ pad: 'x'.repeat(10_000) }))
    expect(oversized.status).toBe(400)
    const error = await errorOf(oversized)
    expect(error.code).toBe('resource_exhausted')
    expect(calls).toHaveLength(1)
  })

  it('rejects a malformed JSON body with invalid_argument without calling the handler', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    const response = await post(`${url}/rpc/unary/node.getStatus`, '{"groupId":')
    expect(response.status).toBe(400)
    expect((await errorOf(response)).code).toBe('invalid_argument')
    expect(calls).toEqual([])
  })

  it('enforces the body limit on chunked uploads without a content-length', async () => {
    const { service, calls } = recordingService()
    const url = new URL(await start({ service, maxBodyBytes: 1024 }))
    const status = await new Promise<number>((resolve, reject) => {
      const request = httpRequest({
        host: url.hostname,
        port: url.port,
        method: 'POST',
        path: '/rpc/unary/node.getStatus',
        headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' },
      }, (response) => { response.resume(); resolve(response.statusCode ?? 0) })
      request.on('error', reject)
      for (let index = 0; index < 8; index += 1) request.write('x'.repeat(512))
      request.end()
    }).catch((error: unknown) => (error as NodeJS.ErrnoException).code === 'ECONNRESET' || (error as NodeJS.ErrnoException).code === 'EPIPE' ? -1 : Promise.reject(error))
    // Either an explicit 400 or a dropped connection is acceptable; the handler must never run.
    expect([400, -1]).toContain(status)
    expect(calls).toEqual([])
  })

  it('maps handler failures to typed error payloads', async () => {
    const url = await start({
      service: recordingService({
        async getStatus() { throw new ChronologRpcError('permission_denied', 'not a member', { details: { reason: 'revoked' } }) },
      }).service,
    })
    const response = await post(`${url}/rpc/unary/node.getStatus`, '{}')
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({
      ok: false,
      error: { code: 'permission_denied', message: 'not a member', retryable: false, details: { reason: 'revoked' } },
    })
  })

  it('reports an error line when a stream fails after headers were sent', async () => {
    const url = await start({
      service: recordingService({
        async *streamStatus() {
          yield { n: 1 }
          throw new ChronologRpcError('revision_unavailable', 'gone')
        },
      }).service,
    })
    const response = await post(`${url}/rpc/stream/node.streamStatus`, '{}')
    expect(response.status).toBe(200)
    const lines = (await response.text()).trim().split('\n').map((line) => JSON.parse(line) as unknown)
    expect(lines).toEqual([
      { ok: true, value: { n: 1 } },
      { ok: false, error: { code: 'revision_unavailable', message: 'gone', retryable: false } },
    ])
  })

  it('refuses new calls once shutdown has begun', async () => {
    const server = new HttpRpcServer({ service: recordingService().service, port: 0 })
    await server.listen()
    await server.close()
    await expect(server.listen()).rejects.toMatchObject({ code: 'transport_unavailable' })
  })

  it('rejects an invalid shutdown timeout', () => {
    const service = recordingService().service
    expect(() => new HttpRpcServer({ service, shutdownTimeoutMs: -1 })).toThrow(TypeError)
    expect(() => new HttpRpcServer({ service, shutdownTimeoutMs: 1.5 })).toThrow(TypeError)
  })
})

describe('HttpRpcTransport', () => {
  it('round-trips bytes and authenticates with the configured token', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service, token: TOKEN })
    const transport = new HttpRpcTransport({ baseUrl: `${url}/`, token: TOKEN })
    const value = await transport.unary('node.getStatus', { raw: Uint8Array.of(0, 255, 7) } as never)
    expect(value).toEqual({ echoed: { raw: Uint8Array.of(0, 255, 7) } })
    expect((calls[0]!.input as { raw: Uint8Array }).raw).toEqual(Uint8Array.of(0, 255, 7))
  })

  it('does not reinterpret objects that merely contain a $chronologBytes key', async () => {
    const { service, calls } = recordingService()
    const url = await start({ service })
    const transport = new HttpRpcTransport({ baseUrl: url })
    await transport.unary('node.getStatus', { a: { $chronologBytes: 'AA==', extra: 1 }, b: { $chronologBytes: 5 } } as never)
    expect(calls[0]!.input).toEqual({ a: { $chronologBytes: 'AA==', extra: 1 }, b: { $chronologBytes: 5 } })
  })

  it('surfaces authentication failures as typed unauthenticated errors', async () => {
    const url = await start({ service: recordingService().service, token: TOKEN })
    const wrong = new HttpRpcTransport({ baseUrl: url, token: 'nope' })
    await expect(wrong.unary('node.getStatus', {} as never)).rejects.toMatchObject({ code: 'unauthenticated', retryable: false })
    const none = new HttpRpcTransport({ baseUrl: url })
    await expect(none.unary('node.getStatus', {} as never)).rejects.toMatchObject({ code: 'unauthenticated' })
    // A per-call token overrides the transport default.
    await expect(wrong.unary('node.getStatus', {} as never, { token: TOKEN })).resolves.toEqual({ echoed: {} })
    // Streams fail the same way, before yielding anything.
    const received: unknown[] = []
    await expect((async () => {
      for await (const item of wrong.stream('node.streamStatus', {} as never)) received.push(item)
    })()).rejects.toMatchObject({ code: 'unauthenticated' })
    expect(received).toEqual([])
  })

  it('propagates a mid-stream error after earlier items', async () => {
    const url = await start({
      service: recordingService({
        async *streamStatus() {
          yield { n: 1 }
          throw new ChronologRpcError('revision_not_retained', 'pruned')
        },
      }).service,
    })
    const transport = new HttpRpcTransport({ baseUrl: url })
    const received: unknown[] = []
    await expect((async () => {
      for await (const item of transport.stream('node.streamStatus', {} as never)) received.push(item)
    })()).rejects.toMatchObject({ code: 'revision_not_retained' })
    expect(received).toEqual([{ n: 1 }])
  })

  it('treats a non-JSON response as a transport failure', async () => {
    const transport = new HttpRpcTransport({
      baseUrl: 'http://example.invalid',
      fetch: async () => new Response('<html>proxy error</html>', { status: 502 }),
    })
    await expect(transport.unary('node.getStatus', {} as never)).rejects.toMatchObject({ code: 'transport_unavailable' })
  })

  it('rejects a stream error response that claims success', async () => {
    const transport = new HttpRpcTransport({
      baseUrl: 'http://example.invalid',
      fetch: async () => new Response('{"ok":true,"value":1}', { status: 500 }),
    })
    await expect((async () => {
      for await (const _ of transport.stream('node.streamStatus', {} as never)) { /* drain */ }
    })()).rejects.toMatchObject({ code: 'internal' })
  })

  it('maps network failures and cancellation to typed errors', async () => {
    const failing = new HttpRpcTransport({
      baseUrl: 'http://example.invalid',
      fetch: async () => { throw new TypeError('connect ECONNREFUSED') },
    })
    await expect(failing.unary('node.getStatus', {} as never)).rejects.toMatchObject({ code: 'transport_unavailable', retryable: true })
    const hanging = new HttpRpcTransport({
      baseUrl: 'http://example.invalid',
      fetch: (_url, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
      }),
    })
    const controller = new AbortController()
    const pending = hanging.unary('node.getStatus', {} as never, { signal: controller.signal })
    controller.abort()
    await expect(pending).rejects.toMatchObject({ code: 'cancelled' })
    await expect(hanging.unary('node.getStatus', {} as never, { timeoutMs: 5 })).rejects.toMatchObject({ code: 'cancelled' })
  })

  it('refuses calls after close', async () => {
    const transport = new HttpRpcTransport({ baseUrl: 'http://example.invalid', fetch: async () => { throw new Error('unreachable') } })
    await transport.close()
    await expect(transport.unary('node.getStatus', {} as never)).rejects.toMatchObject({ code: 'transport_unavailable' })
    await expect((async () => {
      for await (const _ of transport.stream('node.streamStatus', {} as never)) { /* drain */ }
    })()).rejects.toMatchObject({ code: 'transport_unavailable' })
  })
})

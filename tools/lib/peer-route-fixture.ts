import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import { join, resolve } from 'node:path'

import { frameTendrillerPeer } from '@chronolog/transport-tendriller'
import { createPeerConnection, PEER_LIMITS, type PeerConnection, type PeerSocket } from '@tendriller/core/peers'
import { Miniflare, Response as HostResponse } from 'miniflare'
import { WebSocketServer, type WebSocket } from 'ws'

import type { NativeBrowserFixture } from '../browser-event-fixture.js'

type Route = 'direct' | 'relay'
interface SessionMeasurement {
  readonly id: number
  readonly route: Route
  readonly startedAt: string
  readyMs: number | null
  authenticatedMs: number | null
  closed: boolean
  sampledPeakQueuedBytes: number
  sentBytes: number
  receivedBytes: number
  readonly domains: Record<string, { sent: number; received: number }>
}

/**
 * Real local WSS and the packaged workerd relay. The relay's browser-facing
 * socket crosses an explicit local bridge: it supplies a synthetic authenticated
 * page session, without exposing the agent credential to the browser. It is
 * intentionally reported as a bridge, never as a deployed browser/login route.
 */
export async function createPeerRouteFixture(options: {
  readonly directory: string
  readonly engine: string
  readonly native: NativeBrowserFixture
}) {
  await mkdir(options.directory, { recursive: true })
  const keyPath = join(options.directory, 'localhost-key.pem'), certPath = join(options.directory, 'localhost-cert.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' })
  const [key, cert, engine] = await Promise.all([readFile(keyPath), readFile(certPath), readFile(join(options.engine, 'worker.mjs'))])
  // Qualification is entirely local: do not fetch CF location hints or emit
  // telemetry when starting the simulator.
  const mf = new Miniflare({ cf: false, telemetry: { enabled: false }, enableDevRegistry: false, workers: [{ config: {
    name: 'route-host', compatibilityDate: '2026-11-01', compatibilityFlags: ['nodejs_compat'],
    manifest: { mainModule: 'worker.mjs', modulesRoot: resolve(options.engine),
      modules: { 'worker.mjs': { type: 'esm', contents: engine.toString('utf8') } } },
    env: {
      TENDRIL: { type: 'durable-object', worker: 'route-host', exportName: 'Tendril' },
      ADMISSION: { type: 'durable-object', worker: 'route-host', exportName: 'Admission' },
      ACCOUNTS: { type: 'd1', name: 'route-accounts' }, FILES: { type: 'r2', name: 'route-files' },
      PUBLIC_BASE: { type: 'text', value: 'https://route.test' }, PAGE_BASE_DOMAIN: { type: 'text', value: 'pages.route.test' },
      ASSETS: { type: 'fetcher', handler: () => new HostResponse('Route qualification host') },
    },
    exports: { Tendril: { type: 'durable-object', storage: 'sqlite' }, Admission: { type: 'durable-object', storage: 'sqlite' } },
  } }] })
  let relayPage: { id: string; api: string; token: string; page_url: string }
  let cookie: string
  try {
    const database = await mf.getD1Database('ACCOUNTS')
    // D1 exec separates input lines. Keep the complete fresh migration on one
    // line so multiline trigger bodies remain one SQLite script.
    const migration = (await readFile(join(options.engine, 'migrations/0001_accounts.sql'), 'utf8')).replace(/^\s*--.*$/gmu, '').replace(/\r?\n/gu, ' ')
    await database.exec(migration)
    const account = crypto.randomUUID(), raw = crypto.randomUUID(), now = Date.now(), email = `${account}@example.test`
    await database.batch([
      database.prepare("UPDATE service_state SET mode='open' WHERE id=1"),
      database.prepare('INSERT INTO accounts(id,created_at,email) VALUES(?,?,?)').bind(account, now, email),
      database.prepare("INSERT INTO identities(provider,subject,account_id,login,email,created_at) VALUES('google',?,?,?,?,?)").bind(account, account, account, email, now),
      database.prepare("INSERT INTO identity_emails(provider,subject,email) VALUES('google',?,?)").bind(account, email),
      database.prepare('INSERT INTO sessions(hash,account_id,created_at,expires_at) VALUES(?,?,?,?)')
        .bind(createHash('sha256').update(raw).digest('hex'), account, now, now + 86_400_000),
    ])
    const created = await mf.dispatchFetch('https://route.test/api/tendrils', { method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.18.0.1' },
      body: JSON.stringify({ owner: email, mode: 'dashboard', application: { kind: 'peer', id: 'route-qualification' } }) })
    if (created.status !== 201) throw new Error(`ROUTE_HOST_CREATE_FAILED: ${created.status} ${await created.text()}`)
    relayPage = await created.json() as typeof relayPage
    const code = await mf.dispatchFetch(`https://route.test/auth/page?tendril=${relayPage.id}&key=${new URL(relayPage.page_url).pathname.split('/')[2]}`, {
      headers: { Cookie: `__Host-tendriller=${raw}` }, redirect: 'manual',
    })
    const location = code.headers.get('Location')
    if (code.status !== 303 || location === null) throw new Error(`ROUTE_HOST_CLAIM_FAILED: ${code.status}`)
    const redeemed = await mf.dispatchFetch(location, { redirect: 'manual' })
    const sessionCookie = redeemed.headers.get('Set-Cookie')?.split(';')[0]
    if (redeemed.status !== 303 || sessionCookie === undefined) throw new Error(`ROUTE_HOST_SESSION_FAILED: ${redeemed.status}`)
    cookie = sessionCookie
  } catch (error) { await mf.dispose(); throw error }

  const measurements: SessionMeasurement[] = [], trace: unknown[] = [], failures: string[] = []
  const traceStarted = performance.now()
  const connections = new Map<number, { peer: PeerConnection; sendSignal(bytes: Uint8Array): Promise<void>; close(): Promise<void> }>()
  const bridges = new Set<WebSocket>()
  let sequence = 0, closed = false, relayAvailable = true
  const server = createServer({ key, cert }, (_request, response) => { response.writeHead(404); response.end() })
  const sockets = new WebSocketServer({ noServer: true, maxPayload: PEER_LIMITS.frameBytes + 3, perMessageDeflate: false })
  const signals = await options.native.agent.context.createSignals({
    grantId: [...options.native.governed.activeSnapshot.capabilities.values()].find(value =>
      value.grant.role === 'writer' && Buffer.from(value.grant.signingPublicKey).equals(options.native.identity.signing.publicKeyBytes))!.id,
    send: async () => undefined,
  })
  const appendTrace = (event: Record<string, unknown>) => {
    if (trace.length >= 100_000) throw new Error('ROUTE_TRACE_LIMIT')
    trace.push({ elapsedMs: Math.round(performance.now() - traceStarted), ...event })
  }
  const connect = (socket: PeerSocket, route: Route) => {
    const id = ++sequence, started = performance.now()
    const measurement: SessionMeasurement = { id, route, startedAt: new Date().toISOString(), readyMs: null, authenticatedMs: null,
      closed: false, sampledPeakQueuedBytes: 0, sentBytes: 0, receivedBytes: 0, domains: {} }
    measurements.push(measurement)
    const count = (data: unknown, direction: 'sent' | 'received') => {
      const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data instanceof ArrayBuffer ? new Uint8Array(data) : data as Uint8Array
      const domain = typeof data === 'string' ? 'relay-control' : bytes[0] === 0x54 && bytes[1] === 1 ? ['records', 'signals', 'control'][bytes[2]!] ?? 'invalid' : 'invalid'
      const counters = measurement.domains[domain] ??= { sent: 0, received: 0 }
      counters[direction] += bytes.byteLength
      appendTrace({ session: id, route, direction, domain, bytes: bytes.byteLength })
    }
    socket.addEventListener('message', (event: { data: unknown }) => count(event.data, 'received'))
    const observed: PeerSocket = { get readyState() { return socket.readyState }, get bufferedAmount() { return socket.bufferedAmount ?? 0 },
      set binaryType(value: string) { socket.binaryType = value },
      addEventListener: (type, listener) => socket.addEventListener(type, listener), removeEventListener: (type, listener) => socket.removeEventListener(type, listener),
      send(data) { count(data, 'sent'); socket.send(data) }, close(code, reason) { if (socket.readyState < 2) socket.close(code, reason) } }
    const peer = createPeerConnection(observed, { route, relayHandshake: route === 'relay' })
    const sample = () => { const stats = peer.stats; measurement.sentBytes = stats.sentBytes; measurement.receivedBytes = stats.receivedBytes;
      measurement.sampledPeakQueuedBytes = Math.max(measurement.sampledPeakQueuedBytes, stats.queuedBytes) }
    const timer = setInterval(sample, 10)
    let authenticated: Awaited<ReturnType<typeof options.native.agent.context.connectPeer>> | undefined
    const close = async () => {
      if (measurement.closed) return
      measurement.closed = true; sample(); clearInterval(timer); connections.delete(id); peer.close(); await authenticated?.close()
      appendTrace({ session: id, route, event: 'closed' })
    }
    socket.addEventListener('close', () => { void close() })
    connections.set(id, { peer, async sendSignal(bytes) { await authenticated?.sendSignal(bytes) }, close })
    void peer.ready.then(() => { measurement.readyMs = performance.now() - started }, () => undefined)
    void options.native.agent.context.connectPeer({ connection: frameTendrillerPeer(peer), signals: { async receive(bytes) {
      const verified = await signals.receive(bytes)
      await Promise.allSettled([...connections.entries()].filter(([other]) => other !== id).map(([, other]) => other.sendSignal(bytes)))
      return verified
    } } }).then(value => {
      authenticated = value; measurement.authenticatedMs = performance.now() - started
      appendTrace({ session: id, route, event: 'authenticated', authenticatedMs: Math.round(measurement.authenticatedMs) })
      if (measurement.closed) { void value.close(); return }
      void value.completion.catch((error: unknown) => { if (!measurement.closed) failures.push(String(error)) }).finally(close)
    }, (error: unknown) => { if (!measurement.closed) failures.push(String(error)); void close() })
    return { close }
  }
  server.on('upgrade', (request, socket, head) => {
    const route = new URL(request.url ?? '/', 'https://localhost').pathname.slice(1)
    if (closed || !['direct', 'relay'].includes(route) || connections.size >= 16 || route === 'relay' && !relayAvailable) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return
    }
    sockets.handleUpgrade(request, socket, head, ws => {
      if (route === 'direct') { connect(ws, 'direct'); return }
      bridges.add(ws)
      const channel = crypto.randomUUID()
      let upstream: Awaited<ReturnType<typeof mf.dispatchFetch>>['webSocket'] | undefined
      let nativeConnection: { close(): Promise<void> } | undefined
      let finished = false
      const stop = () => {
        if (finished) return
        finished = true; bridges.delete(ws); ws.close(); if (upstream?.readyState === 1) upstream.close(); void nativeConnection?.close()
      }
      ws.once('close', stop); ws.once('error', stop)
      const start = async () => {
        const common = { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': 'tendriller.peer.v1' }
        const remote = await mf.dispatchFetch(`${relayPage.page_url}_tendril/peers/socket?channel=${channel}&peerId=browser`, {
          headers: { ...common, Cookie: cookie, Origin: new URL(relayPage.page_url).origin },
        })
        if (remote.status !== 101 || remote.webSocket === null) throw new Error(`ROUTE_RELAY_PAGE_FAILED: ${remote.status}`)
        upstream = remote.webSocket
        upstream.addEventListener('message', event => {
          if (ws.bufferedAmount + (typeof event.data === 'string' ? Buffer.byteLength(event.data) : event.data.byteLength) > PEER_LIMITS.queueBytes) { stop(); return }
          ws.send(event.data)
        })
        upstream.addEventListener('close', stop); upstream.addEventListener('error', stop)
        ws.on('message', (data, binary) => {
          if (finished || upstream === undefined || upstream === null) return
          const bytes = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer)
          upstream.send(binary ? bytes : bytes.toString('utf8'))
        })
        upstream.accept()
        const counterpart = await mf.dispatchFetch(`${relayPage.api}/peers/socket?channel=${channel}&peerId=native`, {
          headers: { ...common, Authorization: `Bearer ${relayPage.token}` },
        })
        if (counterpart.status !== 101 || counterpart.webSocket === null) throw new Error(`ROUTE_RELAY_AGENT_FAILED: ${counterpart.status}`)
        nativeConnection = connect(counterpart.webSocket as unknown as PeerSocket, 'relay')
        counterpart.webSocket.accept()
        if (finished) { if (counterpart.webSocket.readyState === 1) counterpart.webSocket.close(); await nativeConnection.close() }
      }
      void start().catch((error: unknown) => { if (!finished) failures.push(String(error)); stop() })
    })
  })
  server.listen(0, '127.0.0.1'); await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('ROUTE_SERVER_ADDRESS_UNAVAILABLE')
  return {
    endpoint(route: Route) { return { url: `wss://127.0.0.1:${address.port}/${route}`, route, relayHandshake: route === 'relay' } },
    async disableRelay() { relayAvailable = false; for (const bridge of bridges) bridge.close();
      await Promise.all([...connections.entries()].filter(([id]) => measurements.find(item => item.id === id)?.route === 'relay').map(([, value]) => value.close())) },
    enableRelay() { relayAvailable = true },
    async disconnect() { await Promise.all([...connections.values()].map(value => value.close())); for (const bridge of bridges) bridge.close() },
    snapshot() { return { sessions: structuredClone(measurements), failures: [...failures], traceEvents: trace.length,
      engineSha256: createHash('sha256').update(engine).digest('hex'), certificateSha256: createHash('sha256').update(cert).digest('hex'),
      topology: { direct: ['Chromium', 'local TLS WebSocket endpoint', 'native authenticated peer'],
        relay: ['Chromium', 'local TLS WebSocket bridge with synthetic page session', 'packaged workerd paired relay', 'native authenticated peer'] },
      limits: { frameBytes: PEER_LIMITS.frameBytes, signalBytes: PEER_LIMITS.signalBytes, queueBytes: PEER_LIMITS.queueBytes },
      measurement: { queueSampleIntervalMs: 10, byteBoundary: 'Tendriller encoded frames; per-domain observations additionally count relay ready/credit text, which is excluded from SDK totals',
        queueScope: 'Observed send and receive queue samples; saturation and worst-case memory are separate tests' },
      excludes: ['TLS/TCP/WebSocket framing bytes', 'provider billing', 'public DNS/NAT', 'real identity provider', 'home/mobile/corporate network conditions'] } },
    async saveTrace(path: string) { await writeFile(path, trace.map(value => JSON.stringify(value)).join('\n') + '\n') },
    async close() {
      if (closed) return
      closed = true
      await Promise.all([...connections.values()].map(value => value.close()))
      for (const bridge of bridges) bridge.terminate()
      signals.close(); sockets.close(); server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
      await mf.dispose()
    },
  }
}

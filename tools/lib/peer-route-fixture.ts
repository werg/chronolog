import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:https'
import { join, resolve } from 'node:path'
import os from 'node:os'
import { syncBuiltinESMExports } from 'node:module'

import { openWebRtcConnection, WEBRTC_LIMITS, type RtcDataChannel } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { createPeerRendezvous, PEER_RENDEZVOUS_LIMITS, PEER_RENDEZVOUS_PROTOCOL, type PeerRendezvous } from '@tendriller/core/peers'
import { Miniflare, Response as HostResponse } from 'miniflare'
import { WebSocketServer, type WebSocket } from 'ws'

import type { NativeBrowserFixture } from '../browser-event-fixture.js'

interface SessionMeasurement {
  readonly id: number
  readonly route: 'webrtc'
  readonly startedAt: string
  readyMs: number | null
  authenticatedMs: number | null
  closed: boolean
  sampledPeakQueuedBytes: number
  sentBytes: number
  receivedBytes: number
  nativeSignaling: PeerRendezvous['stats'] | null
}

/**
 * The packaged host exchanges bounded SDP through a local authenticated bridge;
 * every application frame crosses native/browser WebRTC on loopback UDP. The
 * synthetic page session is explicit fixture plumbing, not production login.
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
  let hostPage: { id: string; api: string; token: string; page_url: string }
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
    hostPage = await created.json() as typeof hostPage
    const code = await mf.dispatchFetch(`https://route.test/auth/page?tendril=${hostPage.id}&key=${new URL(hostPage.page_url).pathname.split('/')[2]}`, {
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
  const connections = new Map<number, { sample(): void; close(): Promise<void> }>()
  const bridges = new Set<WebSocket>()
  let sequence = 0, closed = false, rendezvousAvailable = true, unexpectedHostRequests = 0
  const signaling = { opened: 0, sentMessages: 0, receivedMessages: 0, sentBytes: 0, receivedBytes: 0 }
  // Some restricted runners deny interface enumeration while permitting UDP
  // loopback. This qualification explicitly selects 127.0.0.1, so it needs no
  // enumerated interfaces. Restore the process function when the fixture ends.
  const originalInterfaces = os.networkInterfaces
  let restrictedInterfaceEnumeration = false
  try { originalInterfaces() } catch { restrictedInterfaceEnumeration = true; os.networkInterfaces = () => ({}); syncBuiltinESMExports() }
  const server = createServer({ key, cert }, (_request, response) => {
    unexpectedHostRequests++; response.writeHead(503); response.end('Host application services are unavailable')
  })
  const sockets = new WebSocketServer({ noServer: true, maxPayload: PEER_RENDEZVOUS_LIMITS.messageBytes, perMessageDeflate: false })
  const appendTrace = (event: Record<string, unknown>) => {
    if (trace.length >= 100_000) throw new Error('ROUTE_TRACE_LIMIT')
    trace.push({ elapsedMs: Math.round(performance.now() - traceStarted), ...event })
  }
  const connect = async (rendezvous: PeerRendezvous): Promise<void> => {
    const id = ++sequence, started = performance.now(), abort = new AbortController()
    const measurement: SessionMeasurement = { id, route: 'webrtc', startedAt: new Date().toISOString(), readyMs: null, authenticatedMs: null,
      closed: false, sampledPeakQueuedBytes: 0, sentBytes: 0, receivedBytes: 0, nativeSignaling: null }
    measurements.push(measurement)
    let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined
    let authenticated: Awaited<ReturnType<typeof options.native.agent.context.connectPeer>> | undefined
    const sample = () => {
      measurement.nativeSignaling = { ...rendezvous.stats }
      if (rtc === undefined) return
      const stats = rtc.stats
      measurement.sentBytes = stats.sentBytes; measurement.receivedBytes = stats.receivedBytes
      measurement.sampledPeakQueuedBytes = Math.max(measurement.sampledPeakQueuedBytes, stats.queuedSendBytes + stats.queuedReceiveBytes)
    }
    const timer = setInterval(sample, 10)
    const close = async () => {
      if (measurement.closed) return
      measurement.closed = true; sample(); clearInterval(timer); connections.delete(id)
      abort.abort(); rendezvous.close()
      await authenticated?.close(); await rtc?.close()
      appendTrace({ session: id, event: 'closed', sentBytes: measurement.sentBytes, receivedBytes: measurement.receivedBytes })
    }
    connections.set(id, { sample, close })
    try {
      const { role } = await rendezvous.ready
      rtc = await openWebRtcConnection({ role, signaling: rendezvous, signal: abort.signal, configuration: { iceServers: [] },
        createPeerConnection(configuration) {
          const peer = createNativePeerConnection(configuration, { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false })
          peer.addEventListener('connectionstatechange', () => appendTrace({ session: id, event: 'rtc-state', state: peer.connectionState }))
          peer.addEventListener('datachannel', event => {
            const channel = (event as Event & { channel: RtcDataChannel }).channel
            appendTrace({ session: id, event: 'rtc-channel', state: channel.readyState })
            channel.addEventListener('close', () => { appendTrace({ session: id, event: 'rtc-closed' }); void close() })
          })
          return peer
        } })
      measurement.readyMs = performance.now() - started
      authenticated = await options.native.agent.context.connectPeer({ connection: rtc })
      measurement.authenticatedMs = performance.now() - started; sample()
      appendTrace({ session: id, event: 'authenticated', authenticatedMs: Math.round(measurement.authenticatedMs) })
      if (measurement.closed) { await authenticated.close(); await rtc.close(); return }
      void authenticated.completion.catch((error: unknown) => {
        appendTrace({ session: id, event: 'ended', error: String(error) })
        if (!measurement.closed) failures.push(String(error))
      }).finally(close)
    } catch (error) { appendTrace({ session: id, event: 'opening-failed', error: String(error) }); if (!measurement.closed) failures.push(String(error)); await close() }
  }
  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url ?? '/', 'https://localhost')
    if (url.pathname !== '/host/_tendril/peers/rendezvous') {
      unexpectedHostRequests++; socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return
    }
    if (closed || !rendezvousAvailable || connections.size >= PEER_RENDEZVOUS_LIMITS.sessions) {
      socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return
    }
    const channel = url.searchParams.get('channel'), peerId = url.searchParams.get('peerId')
    if (channel === null || peerId === null) { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return }
    sockets.handleUpgrade(request, socket, head, ws => {
      bridges.add(ws); signaling.opened++
      let upstream: Awaited<ReturnType<typeof mf.dispatchFetch>>['webSocket'] | undefined
      let finished = false
      const stop = () => {
        if (finished) return
        finished = true; bridges.delete(ws); ws.close(); if (upstream?.readyState === 1) upstream.close()
        // Signaling closure must not close its established RTC connection.
      }
      ws.once('close', stop); ws.once('error', stop)
      const start = async () => {
        const common = { Upgrade: 'websocket', 'Sec-WebSocket-Protocol': PEER_RENDEZVOUS_PROTOCOL }
        const query = new URLSearchParams({ channel, peerId })
        const remote = await mf.dispatchFetch(`${hostPage.page_url}_tendril/peers/rendezvous?${query}`, {
          headers: { ...common, Cookie: cookie, Origin: new URL(hostPage.page_url).origin },
        })
        if (remote.status !== 101 || remote.webSocket === null) throw new Error(`ROUTE_RENDEZVOUS_PAGE_FAILED: ${remote.status}`)
        upstream = remote.webSocket
        upstream.addEventListener('message', event => {
          if (finished) return
          if (typeof event.data !== 'string' || ws.bufferedAmount + Buffer.byteLength(event.data) > PEER_RENDEZVOUS_LIMITS.messageBytes * 2) { stop(); return }
          signaling.receivedMessages++; signaling.receivedBytes += Buffer.byteLength(event.data)
          appendTrace({ channel, boundary: 'host-to-browser', bytes: Buffer.byteLength(event.data), kind: (JSON.parse(event.data) as { t: unknown }).t })
          ws.send(event.data)
        })
        upstream.addEventListener('close', stop); upstream.addEventListener('error', stop)
        ws.on('message', (data, binary) => {
          if (finished || upstream === undefined || upstream === null) return
          if (binary) { stop(); return }
          const bytes = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as ArrayBuffer)
          signaling.sentMessages++; signaling.sentBytes += bytes.byteLength
          appendTrace({ channel, boundary: 'browser-to-host', bytes: bytes.byteLength, kind: (JSON.parse(bytes.toString('utf8')) as { t: unknown }).t })
          upstream.send(bytes.toString('utf8'))
        })
        upstream.accept()
        const counterpart = await mf.dispatchFetch(`${hostPage.api}/peers/rendezvous?${new URLSearchParams({ channel, peerId: 'native' })}`, {
          headers: { ...common, Authorization: `Bearer ${hostPage.token}` },
        })
        if (counterpart.status !== 101 || counterpart.webSocket === null) throw new Error(`ROUTE_RENDEZVOUS_AGENT_FAILED: ${counterpart.status}`)
        const rendezvous = createPeerRendezvous(counterpart.webSocket)
        counterpart.webSocket.accept()
        if (closed) { rendezvous.close(); return }
        void connect(rendezvous)
      }
      void start().catch((error: unknown) => { if (!finished) failures.push(String(error)); stop() })
    })
  })
  server.listen(0, '127.0.0.1'); await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('ROUTE_SERVER_ADDRESS_UNAVAILABLE')
  return {
    hostBase: `https://127.0.0.1:${address.port}/host/`,
    async disableRendezvous() {
      rendezvousAvailable = false
      for (const bridge of bridges) bridge.close()
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
    },
    async enableRendezvous() { server.listen(address.port, '127.0.0.1'); await once(server, 'listening'); rendezvousAvailable = true },
    snapshot() {
      for (const connection of connections.values()) connection.sample()
      return { sessions: structuredClone(measurements), failures: [...failures], traceEvents: trace.length, recentTrace: trace.slice(-8),
        signaling: { ...signaling, activeSockets: bridges.size, available: rendezvousAvailable }, unexpectedHostRequests,
        engineSha256: createHash('sha256').update(engine).digest('hex'), certificateSha256: createHash('sha256').update(cert).digest('hex'),
        topology: { signaling: ['Chromium', 'local TLS bridge with synthetic page session', 'packaged workerd SDP rendezvous', 'native peer'],
          application: ['Chromium Worker', 'WebRTC DataChannel over loopback UDP', 'native authenticated Chronolog peer'] },
        limits: WEBRTC_LIMITS,
        measurement: { queueSampleIntervalMs: 10, byteBoundary: 'Logical authenticated peer frame payload bytes before RTC packet headers; SDP JSON envelopes counted separately',
          queueScope: 'Sampled native send and receive queues; saturation and worst-case memory are separate transport tests', restrictedInterfaceEnumeration },
        excludes: ['RTC packet headers and credit messages', 'IP/UDP/DTLS/SCTP packet overhead', 'provider billing', 'public DNS/NAT', 'real identity provider', 'home/mobile/corporate network conditions'] }
    },
    async saveTrace(path: string) { await writeFile(path, trace.map(value => JSON.stringify(value)).join('\n') + '\n') },
    async close() {
      if (closed) return
      closed = true
      await Promise.all([...connections.values()].map(value => value.close()))
      for (const bridge of bridges) bridge.terminate()
      sockets.close(); server.closeAllConnections()
      if (server.listening) await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
      await mf.dispose()
      if (restrictedInterfaceEnumeration) { os.networkInterfaces = originalInterfaces; syncBuiltinESMExports() }
    },
  }
}

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { getEventListeners, once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { request as httpsRequest } from 'node:https'
import { syncBuiltinESMExports } from 'node:module'
import { createServer } from 'node:net'
import os, { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'

import type { AgentApplicationContext } from '@chronolog/agent-service'
import { createGovernedPeerService, type GovernedPeerService } from '@chronolog/agent-service/governed-peer'
import { openAuthenticatedPeerLink } from '@chronolog/agent-service/peer-link'
import { loadOrCreateEnrollmentIdentity, MemoryOperationStore } from '@chronolog/node-core'
import { bytesToBase64Url, equalBytes, generateEd25519KeyPair } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { createHttpWebRtcSignaling, openWebRtcConnection, type WebRtcOfferHandler } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { build } from 'esbuild'

import { createNativeBrowserFixture } from './browser-event-fixture.js'

interface ResidentTask {
  readonly stats: WebRtcOfferHandler['stats'] | null
  run(signal: AbortSignal): Promise<void>
}
interface ResidentModule {
  createResidentWebRtcTask(this: void, options: {
    readonly context: AgentApplicationContext
    readonly endpoint: string
    readonly listen: { readonly host: string; readonly port: number }
    readonly tls: { readonly key: Buffer; readonly cert: Buffer }
    readonly authorize: (request: Request, signal: AbortSignal) => boolean
    readonly allowedOrigins: readonly string[]
    readonly configuration: RTCConfiguration
    readonly nativeOptions: Parameters<typeof createNativePeerConnection>[1]
    readonly onError: (error: unknown) => void
  }): ResidentTask
}

const workspace = resolve(import.meta.dirname, '..')
const { values } = parseArgs({ options: { contrib: { type: 'string' }, output: { type: 'string' } } })
assert(values.contrib && values.output, 'Supply --contrib /exact/checkout --output /new/evidence-directory')
const contrib = resolve(values.contrib), output = resolve(values.output)
await mkdir(resolve(output, '..'), { recursive: true }); await mkdir(output)
const recipe = join(contrib, 'cookbooks/run-a-peer-application/snippets/serve-resident-webrtc.mjs')
const bundlePath = join(output, 'serve-resident-webrtc.mjs')
const bundle = await build({ entryPoints: [recipe], outfile: bundlePath, bundle: true, platform: 'node', format: 'esm', target: 'node22', metafile: true,
  banner: { js: 'import { createRequire as bundledCreateRequire } from "node:module"; const require = bundledCreateRequire(import.meta.url);' },
  alias: Object.fromEntries(['@chronolog/transport-webrtc', '@chronolog/transport-webrtc/native', '@chronolog/transport-webrtc/resident']
    .map(name => [name, fileURLToPath(import.meta.resolve(name))])) })
await writeFile(join(output, 'bundle.json'), JSON.stringify(bundle.metafile, null, 2) + '\n')
const { createResidentWebRtcTask } = await import(pathToFileURL(bundlePath).href) as ResidentModule
const report = { format: 'chronolog-resident-webrtc-qualification/v1', passed: false,
  source: { chronolog: gitState(workspace), contrib: gitState(contrib) },
  runtime: { node: process.version, native: 'werift@0.27.0' },
  artifacts: { recipeSha256: await fileHash(recipe), bundleSha256: await fileHash(bundlePath) },
  checks: [] as string[], metrics: {} as Record<string, unknown>, error: '' }
const passed = (check: string) => { report.checks.push(check); process.stdout.write(`Passed: ${check}\n`) }
const directory = await mkdtemp(join(tmpdir(), 'chronolog-resident-rtc-'))
const interfaces = os.networkInterfaces
let changedInterfaces = false
try { interfaces() } catch { changedInterfaces = true; os.networkInterfaces = () => ({}); syncBuiltinESMExports() }
let native: Awaited<ReturnType<typeof createNativeBrowserFixture>> | undefined
let local: PortableFeedTransport | undefined
let rtc: Awaited<ReturnType<typeof openWebRtcConnection>> | undefined
let session: Awaited<ReturnType<GovernedPeerService['connectPeer']>> | undefined
let peerService: GovernedPeerService | undefined
let task: ResidentTask | undefined, running: Promise<void> | undefined
const lifetime = new AbortController(), errors: string[] = []
try {
  const keyPath = join(directory, 'localhost-key.pem'), certPath = join(directory, 'localhost-cert.pem')
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', keyPath, '-out', certPath], { stdio: 'ignore' })
  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)])
  const fetch = trustedFetch(cert), port = await freePort(), endpoint = `https://127.0.0.1:${port}/rtc`, origin = 'https://page.example'
  const store = new MemoryOperationStore(), identity = await loadOrCreateEnrollmentIdentity(store, 'resident-task-client')
  local = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
    signer: webFeedSigner(feedIdFromPublicKey(identity.signing.publicKeyBytes), identity.signing.privateKey) })
  native = await createNativeBrowserFixture({ directory: join(directory, 'native'), topics: ['chat'], browsers: [{
    identity: bytesToBase64Url(identity.signing.publicKeyBytes), readerKey: bytesToBase64Url(identity.reader.publicKeyBytes), transportAuthor: local.identity }] })
  peerService = await createGovernedPeerService({ groupId: native.node.groupId, identity: identity.signing,
    activeMembership: () => native!.governed.activeSnapshot, local: local.asLink(), attach: link => local!.connect(link) })
  const signals = peerService.signals
  const token = crypto.randomUUID(), nativeOptions = { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }
  let authorizations = 0
  const options = { context: native.agent.context, endpoint, listen: { host: '127.0.0.1', port }, tls: { key, cert },
    allowedOrigins: [origin], configuration: { iceServers: [] }, nativeOptions,
    authorize: (request: Request) => { authorizations++; return request.headers.get('Authorization') === `Bearer ${token}` },
    onError: (error: unknown) => { errors.push(String(error)) } }
  task = createResidentWebRtcTask(options)
  running = task.run(lifetime.signal); void running.catch(() => undefined)
  await waitFor(async () => (await fetch(endpoint, { method: 'OPTIONS', headers: { Origin: origin,
    'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization, content-type' } }).catch(() => null))?.status === 204)
  assert.equal((await fetch(`${endpoint}/other`)).status, 404)
  const callsBefore = authorizations
  const blockedOrigin = await fetch(endpoint, { method: 'POST', headers: { Origin: 'https://untrusted.example',
    Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: '{}' })
  assert.equal(blockedOrigin.status, 403); assert.equal(blockedOrigin.headers.get('Access-Control-Allow-Origin'), null)
  assert.equal(authorizations, callsBefore, 'unapproved browser origins must not consume admission or RTC work')
  assert.equal((await fetch(endpoint, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: '{}' })).status, 403)
  assert.equal((await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 403)
  assert.equal(task.stats?.offers, 0)
  passed('exact HTTPS resident recipe starts independently and rejects unmatched routes, origins and missing admission credentials')

  const snapshot = native.governed.activeSnapshot
  const grant = [...snapshot.capabilities.values()].find(capability => capability.grant.role === 'reader' &&
    equalBytes(capability.grant.signingPublicKey, identity.signing.publicKeyBytes))!
  const unauthorized = await openWebRtcConnection({ role: 'offerer',
    signaling: createHttpWebRtcSignaling({ url: endpoint, headers: { Authorization: `Bearer ${token}` }, fetch }), configuration: { iceServers: [] },
    createPeerConnection: configuration => createNativePeerConnection(configuration, nativeOptions) })
  let unauthorizedSession: Awaited<ReturnType<typeof openAuthenticatedPeerLink>> | undefined
  try {
    await assert.rejects(async () => {
      unauthorizedSession = await openAuthenticatedPeerLink({ connection: unauthorized, local: local!.asLink(), groupId: snapshot.groupId,
        identity: await generateEd25519KeyPair(), grantId: grant.id,
        authorizePeer: ({ authorId }) => equalBytes(authorId, native!.identity.signing.publicKeyBytes) })
      await unauthorizedSession.link.read(native!.transport.identity, 0n, 1)
    })
  } finally { await unauthorizedSession?.close(); await unauthorized.close() }
  await waitFor(async () => task!.stats?.pending === 0 && task!.stats?.active === 0)
  assert.equal(task.stats.accepted, 0, 'HTTP admission cannot turn an ungranted signing key into an application reader')
  passed('an admitted HTTPS caller with an ungranted signing key receives no authenticated application history')

  const signaling = createHttpWebRtcSignaling({ url: endpoint, headers: { Origin: origin, Authorization: `Bearer ${token}` }, fetch })
  rtc = await openWebRtcConnection({ role: 'offerer', signaling, configuration: { iceServers: [] },
    createPeerConnection: configuration => createNativePeerConnection(configuration, nativeOptions) })
  session = await peerService.connectPeer({ connection: rtc, peerIdentity: native.identity.signing.publicKeyBytes })
  void session.completion.catch(() => undefined)
  await waitFor(async () => task!.stats?.active === 1)
  assert.equal(signaling.stats.closed, true); assert.equal(signaling.stats.requests, 1)
  passed('a cold native client completes one direct HTTPS offer and authenticates through the actual resident context')

  const before = task.stats
  const operation = await native.client.events.publish('chat', { text: 'after direct resident HTTPS introduction closes' }, { operationId: 'resident-task-operation' })
  let outcome
  try { outcome = await operation.final({ signal: AbortSignal.timeout(20_000) }) } finally { operation.dispose() }
  assert.equal(outcome.outcome.type, 'accepted')
  await local.catchUp()
  const nativeRecords = await native.transport.history(), localRecords = await local.history()
  assert(nativeRecords.length > 0)
  assert.deepEqual(localRecords.map(record => record.id).sort(), nativeRecords.map(record => record.id).sort())
  assert.deepEqual(task.stats, before, 'application progress must not make more HTTPS introduction requests')
  assert(rtc.stats.sentBytes > 0 && rtc.stats.receivedBytes > 0)
  native.assertHealthy()
  passed('the authenticated RTC channel retains original native signed records without more HTTPS introduction work')

  const nativeMessages = native.client.signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(10_000) })[Symbol.asyncIterator]()
  const clientMessages = signals.subscribe({ topics: ['typing'], signal: AbortSignal.timeout(10_000) })[Symbol.asyncIterator]()
  const nativeMessage = nativeMessages.next(), clientMessage = clientMessages.next()
  try {
    const sentByClient = await signals.send('typing', { typing: true, from: 'rtc-client' })
    assert.deepEqual((await nativeMessage).value, sentByClient)
    const sentByNative = await native.client.signals.send('typing', { typing: false, from: 'native-client' })
    assert.deepEqual((await clientMessage).value, sentByNative)
    assert.deepEqual((await native.transport.history()).map(record => record.id), nativeRecords.map(record => record.id))
    assert.deepEqual((await local.history()).map(record => record.id), localRecords.map(record => record.id))
    assert.deepEqual(task.stats, before)
  } finally { await nativeMessages.return?.(); await clientMessages.return?.() }
  passed('public signal channels and native RPC exchange authenticated live values over real RTC without records or more HTTPS introduction requests')

  report.metrics = { signaling: signaling.stats, beforeApplication: before, afterApplication: task.stats,
    logicalPeerFrames: rtc.stats, records: nativeRecords.length, recordIds: nativeRecords.map(record => record.id).sort(), originalOutcome: outcome,
    certificateSha256: hash(cert), byteBoundary: 'Logical peer frame payload bytes exclude RTC headers, credits and IP/UDP/DTLS/SCTP overhead.',
    network: 'Both native RTC peers use loopback UDP. HTTPS verifies the generated loopback certificate; no TLS checks are disabled.',
    excludes: ['browser RTCDataChannel transfer', 'packaged Tendriller host', 'production certificate provisioning', 'public NAT', 'TURN', 'provider billing'] }
  lifetime.abort()
  await bounded(running, 5_000)
  await bounded(session.completion.catch(() => undefined), 5_000)
  await assert.rejects(native.client.signals.send('typing', { typing: false }), /SIGNAL_ROUTE_UNAVAILABLE/u)
  await assert.rejects(signals.send('typing', { typing: false }), /SIGNAL_ROUTE_UNAVAILABLE/u)
  assert.equal(task.stats?.closed, true); assert.equal(task.stats?.active, 0); assert.equal(task.stats?.pending, 0)
  assert.equal(getEventListeners(lifetime.signal, 'abort').length, 0)
  await assert.rejects(fetch(endpoint))
  passed('resident task abort closes the HTTPS listener and authenticated peer lifetime without retained entries or abort listeners')

  const earlyPort = await freePort(), early = new AbortController()
  const earlyTask = createResidentWebRtcTask({ ...options, endpoint: `https://127.0.0.1:${earlyPort}/rtc`, listen: { host: '127.0.0.1', port: earlyPort } })
  const earlyRun = earlyTask.run(early.signal)
  early.abort()
  await bounded(earlyRun, 5_000)
  assert.equal(earlyTask.stats?.closed, true); assert.equal(getEventListeners(early.signal, 'abort').length, 0)
  await assert.rejects(fetch(`https://127.0.0.1:${earlyPort}/rtc`))
  const occupied = createServer(); occupied.listen(0, '127.0.0.1'); await once(occupied, 'listening')
  try {
    const address = occupied.address(); assert(address !== null && typeof address === 'object')
    const failed = new AbortController()
    const failedTask = createResidentWebRtcTask({ ...options, endpoint: `https://127.0.0.1:${address.port}/rtc`, listen: { host: '127.0.0.1', port: address.port } })
    await assert.rejects(bounded(failedTask.run(failed.signal), 5_000), /EADDRINUSE/u)
    assert.equal(failedTask.stats?.closed, true); assert.equal(getEventListeners(failed.signal, 'abort').length, 0)
  } finally { await new Promise<void>(resolve => occupied.close(() => resolve())) }
  passed('synchronous abort before listening and bind failure both dispose the handler and external abort listeners')
  report.passed = true
} catch (error) { report.error = error instanceof Error ? error.stack ?? error.message : String(error); throw error }
finally {
  lifetime.abort()
  await Promise.allSettled([running, peerService?.close(), session?.close(), rtc?.close()])
  await local?.close(); await native?.close()
  await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n')
  if (changedInterfaces) { os.networkInterfaces = interfaces; syncBuiltinESMExports() }
  await rm(directory, { recursive: true, force: true })
}
process.stdout.write(`Resident HTTPS/RTC qualification: ${join(output, 'report.json')}\n`)

function trustedFetch(cert: Buffer): typeof globalThis.fetch {
  return ((input: string | URL | Request, init: RequestInit = {}) => new Promise<Response>((resolve, reject) => {
    assert(!(input instanceof Request), 'Qualification fetch accepts a URL and explicit options')
    const headers: Record<string, string> = {}
    new Headers(init.headers).forEach((value, name) => { headers[name] = value })
    const request = httpsRequest(input, { method: init.method ?? 'GET', headers, ca: cert, agent: false,
      ...(init.signal === undefined || init.signal === null ? {} : { signal: init.signal }) }, response => {
      const parts: Buffer[] = []; let bytes = 0
      response.on('data', (part: Buffer) => { bytes += part.length; if (bytes > 128 * 1024) request.destroy(new Error('RESIDENT_TEST_RESPONSE_TOO_LARGE')); else parts.push(part) })
      response.on('error', reject)
      response.on('end', () => resolve(new Response(response.statusCode === 204 ? null : Buffer.concat(parts), {
        status: response.statusCode!, headers: Object.entries(response.headers).flatMap(([name, value]) =>
          value === undefined ? [] : Array.isArray(value) ? value.map(item => [name, item] as [string, string]) : [[name, value] as [string, string]]),
      })))
    })
    request.on('error', reject)
    if (init.body !== undefined && init.body !== null) { assert.equal(typeof init.body, 'string'); request.write(init.body) }
    request.end()
  }))
}
async function freePort(): Promise<number> {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening')
  const address = server.address(); assert(address !== null && typeof address === 'object')
  await new Promise<void>(resolve => server.close(() => resolve())); return address.port
}
async function waitFor(predicate: () => Promise<boolean>): Promise<void> {
  const end = Date.now() + 10_000
  while (!await predicate()) { if (Date.now() >= end) throw new Error('RESIDENT_TEST_PROGRESS_TIMEOUT'); await new Promise(resolve => setTimeout(resolve, 20)) }
}
async function bounded<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('RESIDENT_TEST_CLEANUP_TIMEOUT')), milliseconds) })]) }
  finally { clearTimeout(timer!) }
}
function hash(value: Uint8Array): string { return createHash('sha256').update(value).digest('hex') }
async function fileHash(path: string): Promise<string> { return hash(await readFile(path)) }
function gitState(directory: string) {
  return { head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: directory, encoding: 'utf8' }).trim(),
    dirty: execFileSync('git', ['status', '--porcelain'], { cwd: directory, encoding: 'utf8' }).trim().length > 0 }
}

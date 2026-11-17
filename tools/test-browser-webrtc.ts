import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import os, { tmpdir } from 'node:os'
import { syncBuiltinESMExports } from 'node:module'
import { join, resolve } from 'node:path'

import type { GovernedPeerSession } from '@chronolog/agent-service/governed-peer'
import type { EventBatch } from '@chronolog/protocol'
import type { TransactionOutcome } from '@chronolog/rpc'
import { createWebRtcOfferHandler, WEBRTC_HTTP_LIMITS } from '@chronolog/transport-webrtc'
import type { DataChannelConnection, DataChannelStats, PeerDescription, WebRtcOfferHandler } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import { chromium } from '@playwright/test'
import { build } from 'esbuild'

import type { WebRtcTestApi } from '../test/browser/webrtc-page.js'
import { createNativeBrowserFixture } from './browser-event-fixture.js'
import { waitFor } from './lib/wait-for.js'

interface TestWindow { readonly chronologWebRtcTest: WebRtcTestApi }
interface BrowserState {
  readonly records: readonly { readonly id: string; readonly author: string }[]
  readonly historySha256: string
  readonly events: EventBatch
  readonly stats: DataChannelStats
}
interface PublishedOperation { readonly proposalId: string; readonly outcome: TransactionOutcome }
function finalDecision({ proposalId, outcome }: PublishedOperation) {
  return { proposalId, transactionId: outcome.transactionId, outcome: outcome.outcome,
    orderKey: outcome.orderKey, admissible: outcome.admissible, final: outcome.final }
}
const workspace = resolve(import.meta.dirname, '..')
const contribArg = process.argv.indexOf('--contrib')
if (contribArg < 0 || process.argv[contribArg + 1] === undefined) throw new Error('Supply --contrib /exact/public-recipe-checkout')
const contrib = resolve(process.argv[contribArg + 1]!)
const recipe = join(contrib, 'cookbooks/run-a-peer-application/snippets/connect-resident-worker.mjs')
const outputArg = process.argv.indexOf('--output')
const output = outputArg < 0 ? join(workspace, 'artifacts/browser-webrtc') : resolve(process.argv[outputArg + 1]!)
await mkdir(output, { recursive: true })
const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap(name =>
  ['', '/browser'].map(suffix => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
for (const [name, file] of [['history', 'history-policy'], ['finality', 'finality'], ['ledger', 'ledger-record'], ['membership', 'membership']]) {
  alias[`@chronolog/node-core/${name}`] = join(workspace, `packages/node-core/src/${file}.ts`)
}
alias['@chronolog/transport-webrtc'] = join(workspace, 'packages/transport-webrtc/src/index.ts')
const bundle = await build({ absWorkingDir: workspace,
  entryPoints: { 'webrtc-worker': 'test/browser/webrtc-worker.ts', 'webrtc-page': 'test/browser/webrtc-page.ts', 'connect-resident-worker': recipe },
  outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias, metafile: true })
const forbidden = Object.values(bundle.metafile.outputs).flatMap(entry => Object.entries(entry.inputs)
  .filter(([name, input]) => input.bytesInOutput > 0 && /(?:werift|transport-webrtc\/src\/native|runtime-workerd|transport-tendriller)/u.test(name)).map(([name]) => name))
assert.deepEqual(forbidden, [], 'browser RTC data plane imports native or hosted transports')
await writeFile(join(output, 'bundle.json'), JSON.stringify(bundle.metafile, null, 2) + '\n')
if (process.argv.includes('--build-only')) { process.stdout.write('WebRTC page/Worker bundles built; runtime qualification was not run.\n'); process.exit(0) }

const host = { requests: 0, requestBytes: 0, responseBytes: 0, applicationRequests: 0, signalingMessages: 0, signalingBytes: 0 }
let introduction: WebRtcOfferHandler | undefined, hostClosed = false
const introductionToken = crypto.randomUUID()
const server = createServer((request, response) => {
  host.requests += 1
  response.setHeader('Cache-Control', 'no-store')
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  const run = async (): Promise<void> => {
    if (path === '/signal' && request.method === 'POST') {
      if (introduction === undefined) { response.writeHead(503); response.end(); return }
      const chunks: Buffer[] = []; let bytes = 0
      for await (const chunk of request) {
        const value = Buffer.from(chunk as Uint8Array); bytes += value.length
        if (bytes > WEBRTC_HTTP_LIMITS.messageBytes) throw new Error('WEBRTC_SIGNAL_TOO_LARGE')
        chunks.push(value)
      }
      host.requestBytes += bytes
      const headers = new Headers()
      for (const [name, value] of Object.entries(request.headers)) {
        if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value)
      }
      const body = Buffer.concat(chunks)
      const result = await introduction.fetch(new Request(`${base}/signal`, { method: 'POST', headers, body }))
      const returned = new Uint8Array(await result.arrayBuffer())
      host.responseBytes += returned.length
      if (result.ok) {
        const offer = JSON.parse(body.toString('utf8')) as { description: PeerDescription }
        const answer = JSON.parse(new TextDecoder().decode(returned)) as { description: PeerDescription }
        host.signalingMessages += 2
        host.signalingBytes += Buffer.byteLength(offer.description.sdp) + Buffer.byteLength(answer.description.sdp)
      }
      result.headers.forEach((value, name) => response.setHeader(name, value))
      response.writeHead(result.status); response.end(returned); return
    }
    const file = new Map([['/webrtc-page.js', 'webrtc-page.js'], ['/webrtc-worker.js', 'webrtc-worker.js'],
      ['/connect-resident-worker.js', 'connect-resident-worker.js']]).get(path)
    const bytes = path === '/' ? Buffer.from('<!doctype html><meta charset="utf-8"><title>Chronolog WebRTC qualification</title><script type="module" src="/webrtc-page.js"></script>')
      : file === undefined ? null : await readFile(join(output, file))
    if (bytes === null) { if (path !== '/favicon.ico') host.applicationRequests += 1; response.writeHead(404); response.end(); return }
    response.setHeader('Content-Type', path === '/' ? 'text/html' : 'application/javascript')
    host.responseBytes += bytes.length; response.end(bytes)
  }
  void run().catch((error: unknown) => { response.writeHead(500); response.end(String(error)) })
})
server.listen(0, '127.0.0.1'); await once(server, 'listening')
const address = server.address()
if (address === null || typeof address === 'string') throw new Error('WEBRTC_FIXTURE_ADDRESS_MISSING')
const base = `http://127.0.0.1:${address.port}`
const browser = await chromium.launch({ headless: true,
  ...(process.env.CHRONOLOG_CHROMIUM_EXECUTABLE === undefined ? {} : { executablePath: process.env.CHRONOLOG_CHROMIUM_EXECUTABLE }) }).catch(async (error: unknown) => {
  server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()))
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-webrtc-qualification/v2', passed: false,
    phase: 'browser-launch', error: error instanceof Error ? error.message : String(error) }, null, 2) + '\n')
  throw error
})
const context = await browser.newContext(), page = await context.newPage()
const directory = await mkdtemp(join(tmpdir(), 'chronolog-webrtc-'))
let native: Awaited<ReturnType<typeof createNativeBrowserFixture>> | undefined
let nativeConnection: DataChannelConnection | undefined
let nativeSession: GovernedPeerSession | undefined
const errors: string[] = [], checks: Array<{ id: string; passed: boolean }> = []
const expectedTerminations: string[] = []
let injectingInterruption = false
page.on('pageerror', error => errors.push(error.message))
const passed = (id: string): void => { checks.push({ id, passed: true }); process.stdout.write(`Passed: ${id}\n`) }
const closeHost = async (): Promise<void> => {
  if (hostClosed) return
  hostClosed = true; server.closeAllConnections()
  await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
}
const digest = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex')
const payload = Uint8Array.from({ length: 512 * 1024 + 37 }, (_, i) => i % 251), payloadHash = digest(payload)
try {
  await page.goto(base)
  await page.waitForFunction(() => 'chronologWebRtcTest' in globalThis)
  const name = `rtc-${crypto.randomUUID()}`
  const identity = await page.evaluate(name => (globalThis as unknown as TestWindow).chronologWebRtcTest.prepare(name), name)
  native = await createNativeBrowserFixture({ directory, browsers: [identity], topics: ['chat'] })
  assert.equal(await native.feedStore.putPayload(payload), payloadHash)
  await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologWebRtcTest.open(name, bootstrap), { name, bootstrap: native.bootstrap })
  // The fixture binds loopback explicitly. Avoid optional interface discovery,
  // which this sandbox denies; all ICE/DTLS/SCTP packets still use real sockets.
  const enumerate = os.networkInterfaces
  os.networkInterfaces = () => ({})
  syncBuiltinESMExports()
  introduction = createWebRtcOfferHandler({ allowedOrigins: [base],
    authorize: request => request.headers.get('Authorization') === `Bearer ${introductionToken}`,
    createPeerConnection: configuration => createNativePeerConnection(configuration,
      { iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false }), configuration: { iceServers: [] },
    onError: error => {
      const message = error instanceof Error ? error.message : String(error)
      if (injectingInterruption && ['WEBRTC_CONNECTION_ENDED', 'WEBRTC_CONNECTION_CLOSED', 'WEBRTC_LIVE_ENDED', 'WEBRTC_LIVE_CLOSED'].includes(message)) expectedTerminations.push(message)
      else errors.push(String(error))
    }, async accept(connection) {
    nativeConnection = connection
    nativeSession = await native!.agent.context.connectPeer({ connection })
    return nativeSession
  } })
  const firstIntroduction = await page.evaluate(options => (globalThis as unknown as TestWindow).chronologWebRtcTest.connect(options),
    { url: `${base}/signal`, token: introductionToken })
    .finally(() => { os.networkInterfaces = enumerate; syncBuiltinESMExports() })
  assert.equal(firstIntroduction.workerOwnsChannel, true); assert.equal(firstIntroduction.signalingClosed, true)
  assert.equal(firstIntroduction.state.readiness, 'authenticated')
  assert.equal(firstIntroduction.http.requests, 1)
  assert.equal(host.signalingMessages, 2)
  await waitFor(async () => introduction!.stats.accepted === 1 && introduction!.stats.pending === 0,
    'both ends authenticate the first resident connection', 10_000)
  passed('native-browser-rtc-and-worker-ownership')

  const reconnectOriginal = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.publish(
    'rtc-reconnect-operation', 'original operation before a forced RTC interruption')) as PublishedOperation
  assert.equal(reconnectOriginal.outcome.final, true); assert.equal(reconnectOriginal.outcome.outcome.type, 'accepted')
  const prior = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
  const reconnectAuthoredBefore = prior.records.filter(record => record.author === identity.transportAuthor).map(record => record.id).sort()
  const recovering = performance.now()
  injectingInterruption = true
  os.networkInterfaces = () => ({}); syncBuiltinESMExports()
  const negotiation = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.interrupt())
    .finally(() => { os.networkInterfaces = enumerate; syncBuiltinESMExports() })
  await waitFor(async () => introduction!.stats.accepted === 2 && introduction!.stats.pending === 0 && introduction!.stats.active === 1,
    'replacement authenticates and the injected old connection retires', 10_000)
  injectingInterruption = false
  const reconnectElapsedMs = performance.now() - recovering
  assert.equal(negotiation.state.readiness, 'authenticated')
  assert.equal(negotiation.introductions.length, 2)
  assert(negotiation.introductions.every(value => value.requests === 1 && value.closed))
  assert.equal(host.signalingMessages, 4)
  assert.equal(introduction.stats.accepted, 2); assert.equal(introduction.stats.pending, 0)
  const reconnectRetry = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.publish(
    'rtc-reconnect-operation', 'original operation before a forced RTC interruption')) as PublishedOperation
  assert.deepEqual(finalDecision(reconnectRetry), finalDecision(reconnectOriginal))
  const resumed = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
  const reconnectAuthoredAfter = resumed.records.filter(record => record.author === identity.transportAuthor).map(record => record.id).sort()
  assert.deepEqual(reconnectAuthoredAfter, reconnectAuthoredBefore)
  const nativeSignalingClosed = introduction.stats.accepted === 2 && introduction.stats.pending === 0
  passed('public-resident-supervisor-reconnects-once-and-preserves-original-operations')
  const before = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
  const nativeBefore = nativeConnection!.stats
  await closeHost()
  const hostBefore = structuredClone(host)
  const first = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.publish('rtc-browser-operation', 'browser after signaling host stopped')) as PublishedOperation
  assert.equal(first.outcome.transactionId, first.proposalId)
  assert.equal(first.outcome.final, true)
  assert.equal(first.outcome.outcome.type, 'accepted')
  const nativeHandle = await native.client.events.publish('chat', { text: 'native after signaling host stopped' }, { operationId: 'rtc-native-operation' })
  let nativeOutcome: TransactionOutcome
  try { nativeOutcome = await nativeHandle.final({ signal: AbortSignal.timeout(20_000) }) } finally { nativeHandle.dispose() }
  assert.equal(nativeOutcome.transactionId, nativeHandle.proposalId)
  assert.equal(nativeOutcome.final, true)
  assert.equal(nativeOutcome.outcome.type, 'accepted')
  passed('both-original-operations-reach-accepted-finality')
  const receivedPayload = await page.evaluate(hash => (globalThis as unknown as TestWindow).chronologWebRtcTest.payload(hash), payloadHash) as { bytes: number; sha256: string }
  assert.equal(receivedPayload.sha256, payloadHash); assert.equal(receivedPayload.bytes, payload.length)
  passed('detached-body-after-signaling-host-stopped')
  const beforeRetry = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
  const browserAuthoredBefore = beforeRetry.records.filter(record => record.author === identity.transportAuthor).map(record => record.id).sort()
  assert(browserAuthoredBefore.length > 0)
  const retry = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.publish('rtc-browser-operation', 'browser after signaling host stopped')) as PublishedOperation
  // Observation timestamps and applied revisions advance after the native
  // operation. The retained original identity and final decision cannot change.
  assert.deepEqual(finalDecision(retry), finalDecision(first))
  const afterRetry = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
  const browserAuthoredAfter = afterRetry.records.filter(record => record.author === identity.transportAuthor).map(record => record.id).sort()
  assert.deepEqual(browserAuthoredAfter, browserAuthoredBefore)
  passed('exact-original-operation-retry')
  let final!: BrowserState
  let records: Array<{ id: string; author: string }> = [], nativeHistorySha256 = ''
  const deadline = Date.now() + 20_000
  for (;;) {
    final = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.state()) as BrowserState
    await native.transport.catchUp(); await native.node.waitForIdle()
    records = (await native.transport.history()).map(record => ({ id: record.id, author: record.author })).sort((a, b) => a.id.localeCompare(b.id))
    nativeHistorySha256 = digest(records.map(record => record.id).join('\n'))
    if (JSON.stringify(final.events) === JSON.stringify(await native.client.events.read()) &&
        final.historySha256 === nativeHistorySha256 && JSON.stringify(final.records) === JSON.stringify(records)) break
    if (Date.now() >= deadline) throw new Error('WEBRTC_HISTORY_AND_EVENTS_DID_NOT_CONVERGE')
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  assert.equal(final.historySha256, nativeHistorySha256)
  assert.deepEqual(final.records, records)
  assert.deepEqual(final.events.transactions.flatMap(transaction => transaction.events).map(event =>
    ({ proposalId: event.proposalId, topic: event.topic, payload: event.payload })).sort((a, b) => a.proposalId.localeCompare(b.proposalId)),
  [{ proposalId: first.proposalId, topic: 'chat', payload: { text: 'browser after signaling host stopped' } },
    { proposalId: reconnectOriginal.proposalId, topic: 'chat', payload: { text: 'original operation before a forced RTC interruption' } },
    { proposalId: nativeHandle.proposalId, topic: 'chat', payload: { text: 'native after signaling host stopped' } }]
    .sort((a, b) => a.proposalId.localeCompare(b.proposalId)))
  assert.deepEqual(host, hostBefore)
  assert.equal(host.applicationRequests, 0)
  const signalingAfter = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.signaling())
  assert.equal(signalingAfter.sentMessages, negotiation.sentMessages)
  assert.deepEqual(signalingAfter.http, negotiation.http)
  assert.deepEqual(errors, [])
  native.assertHealthy()
  passed('final-events-and-original-records-converge-with-host-unavailable')
  const metrics = { signalingMessages: host.signalingMessages, signalingBytes: host.signalingBytes,
    signalingMessagesAfterClosed: signalingAfter.sentMessages - negotiation.sentMessages, signalingClosed: nativeSignalingClosed && signalingAfter.signalingClosed,
    hostApplicationRequests: host.applicationRequests, host: { before: hostBefore, after: host },
    bytesAfterSignalingClosed: { browserSent: final.stats.sentBytes - before.stats.sentBytes, nativeSent: nativeConnection!.stats.sentBytes - nativeBefore.sentBytes },
    records: { browserAuthored: records.filter(record => record.author === identity.transportAuthor).length,
      nativeAuthored: records.filter(record => record.author === native!.transport.identity).length, atBrowser: final.records.length, atNative: records.length },
    history: { browserSha256: final.historySha256, nativeSha256: nativeHistorySha256, recordIds: records.map(record => record.id) },
    payload: { bytes: payload.length, expectedSha256: payloadHash, receivedSha256: receivedPayload.sha256 },
    outcomes: { browser: first, retry, native: nativeOutcome, events: final.events },
    retry: { browserAuthoredBefore, browserAuthoredAfter },
    channels: { browser: final.stats, native: nativeConnection!.stats }, introduction: introduction.stats,
    reconnect: { readiness: 'authenticated', introductions: negotiation.introductions, elapsedMs: reconnectElapsedMs,
      original: reconnectOriginal, retry: reconnectRetry, browserAuthoredBefore: reconnectAuthoredBefore, browserAuthoredAfter: reconnectAuthoredAfter,
      expectedTerminations, routes: [firstIntroduction.route, negotiation.route] },
    byteBoundary: 'Logical authenticated peer frame payload bytes; excludes framing headers/credit and SCTP/DTLS/IP overhead.' }
  assert(metrics.bytesAfterSignalingClosed.browserSent > 0); assert(metrics.bytesAfterSignalingClosed.nativeSent >= payload.length)
  const source = Object.fromEntries(([['chronolog', workspace], ['contrib', contrib]] as const).map(([name, cwd]) => [name, {
    head: execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim(),
    dirty: execFileSync('git', ['status', '--porcelain'], { cwd, encoding: 'utf8' }).trim().length > 0 }]))
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-webrtc-qualification/v2', passed: true, source,
    artifacts: { residentRecipeSha256: digest(await readFile(recipe)), residentBundleSha256: digest(await readFile(join(output, 'connect-resident-worker.js'))) },
    runtime: { node: process.version, browser: browser.version(), native: 'werift@0.27.0' },
    topology: { transport: 'webrtc', nativeImplementation: 'werift', signaling: 'public direct HTTP offer/answer client and native handler on loopback',
      networkDiscovery: 'native binds loopback explicitly; optional interface enumeration disabled in fixture', browserStorage: 'OPFS', channelOwner: 'DedicatedWorker', hostStoppedAfterNegotiation: true,
      excludes: ['packaged Tendriller signaling host', 'public NAT connectivity', 'TURN interoperability', 'provider billing'] },
    checks, metrics }, null, 2) + '\n')
  process.stdout.write(`WebRTC qualification passed: ${join(output, 'report.json')}\n`)
} catch (error) {
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-webrtc-qualification/v2', passed: false, checks, errors,
    error: error instanceof Error ? error.stack : String(error) }, null, 2) + '\n')
  throw error
} finally {
  await introduction?.close()
  await nativeSession?.close(); await nativeConnection?.close()
  try { await page.evaluate(() => (globalThis as unknown as TestWindow).chronologWebRtcTest.close()) } catch { /* Preserve qualification errors. */ }
  await context.close(); await browser.close(); await native?.close(); await closeHost()
  await rm(directory, { recursive: true, force: true })
}

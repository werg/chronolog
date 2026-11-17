import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'

import {
  applicationDefinitionDigest, bytesDigest, bytesToHex, controlParticipantGrant, createGenerationRegistry,
  createPeerIdentity, eventExecutionManifest, executionManifestArtifacts, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
  type ApplicationDevice, type ApplicationPeerLink, type ApplicationSession,
} from '@chronolog/peer-session'
import { openNativeApplication, openNativeDevice } from '@chronolog/peer-session/native'
import { createWebRtcOfferHandler, WEBRTC_HTTP_LIMITS, type DataChannelConnection, type WebRtcOfferHandler } from '@chronolog/transport-webrtc'
import { createNativePeerConnection } from '@chronolog/transport-webrtc/native'
import type { EphemeralSignal } from '@chronolog/signals'
import { chromium } from '@playwright/test'
import { build } from 'esbuild'

import { definition, type BrowserState } from '../test/peer-session-webrtc/contract.js'
import type { GenerationRtcTestApi } from '../test/peer-session-webrtc/page.js'
import { waitFor } from './lib/wait-for.js'

interface TestWindow { readonly peerGenerationRtcTest: GenerationRtcTestApi }
const workspace = resolve(import.meta.dirname, '..')
const { values } = parseArgs({ options: { output: { type: 'string', default: 'artifacts/peer-session-webrtc' }, 'build-only': { type: 'boolean', default: false } } })
const output = resolve(values.output)
const git = (args: readonly string[]) => execFileSync('git', [...args], { cwd: workspace, encoding: 'utf8' }).trim()
const source = { repository: 'werg/chronolog-db', head: git(['rev-parse', 'HEAD']), tree: git(['rev-parse', 'HEAD^{tree}']), dirty: git(['status', '--porcelain']) !== '' }
const digest = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex')
await mkdir(output, { recursive: true })
const bundle = await build({ absWorkingDir: workspace, entryPoints: {
  'generation-rtc-page': 'test/peer-session-webrtc/page.ts', 'generation-rtc-worker': 'test/peer-session-webrtc/worker.ts',
}, outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', metafile: true })
const forbidden = Object.values(bundle.metafile.outputs).flatMap(value => Object.entries(value.inputs)
  .filter(([name, contribution]) => contribution.bytesInOutput > 0 && /(?:werift|transport-webrtc\/src\/native|materializer-doltlite|agent-service|transport-tendriller|runtime-workerd)/u.test(name))
  .map(([name]) => name))
assert.deepEqual(forbidden, [], 'The Worker data plane must not import native SQL or hosted application paths')
const files = await Promise.all(['generation-rtc-page.js', 'generation-rtc-worker.js'].map(async file => {
  const bytes = await readFile(join(output, file)); return { file, bytes: bytes.length, sha256: digest(bytes) }
}))
const inputs = Object.fromEntries(await Promise.all(Object.keys(bundle.metafile.inputs).sort().map(async file => [file, digest(await readFile(resolve(workspace, file)))] as const)))
await writeFile(join(output, 'bundle.json'), JSON.stringify({ format: 'chronolog-peer-session-webrtc-build/v1', source, files, inputs, metafile: bundle.metafile }, null, 2) + '\n')
if (values['build-only']) {
  process.stdout.write(`Built actual browser entrypoints only; WebRTC runtime qualification was not run: ${output}\n`)
  process.exit(0)
}
assert.equal(source.dirty, false, 'Runtime qualification requires a clean source checkout')

const checks: Array<{ id: string; passed: true }> = [], errors: string[] = [], expectedTerminations: string[] = []
const host = { requests: 0, requestBytes: 0, responseBytes: 0, applicationRequests: 0, introductions: 0 }
const browserRequests: Array<{ method: string; path: string }> = []
let phase = 'browser-launch', intentionalClose = false, hostClosed = false, base = ''
let introduction: WebRtcOfferHandler | undefined
let native: ApplicationSession<typeof definition> | undefined, nativeDevice: ApplicationDevice | undefined
let nativeLink: ApplicationPeerLink | undefined, nativeChannel: DataChannelConnection | undefined
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined
let context: Awaited<ReturnType<NonNullable<typeof browser>['newContext']>> | undefined
let page: Awaited<ReturnType<NonNullable<typeof context>['newPage']>> | undefined
const nativeSignals: EphemeralSignal[] = []
const directory = await mkdtemp(join(tmpdir(), 'peer-session-rtc-'))
const token = crypto.randomUUID()
const server = createServer((request, response) => {
  host.requests++; response.setHeader('Cache-Control', 'no-store')
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  const run = async (): Promise<void> => {
    if (path === '/signal' && request.method === 'POST') {
      if (introduction === undefined) { response.writeHead(503); response.end(); return }
      const chunks: Buffer[] = []; let size = 0
      for await (const chunk of request) {
        const bytes = Buffer.from(chunk as Uint8Array); size += bytes.length
        assert(size <= WEBRTC_HTTP_LIMITS.messageBytes); chunks.push(bytes)
      }
      host.requestBytes += size; host.introductions++
      const headers = new Headers()
      for (const [name, value] of Object.entries(request.headers)) if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value)
      const result = await introduction.fetch(new Request(`${base}/signal`, { method: 'POST', headers, body: Buffer.concat(chunks) }))
      const bytes = new Uint8Array(await result.arrayBuffer()); host.responseBytes += bytes.length
      result.headers.forEach((value, name) => response.setHeader(name, value)); response.writeHead(result.status); response.end(bytes); return
    }
    if (path === '/favicon.ico') { response.writeHead(204); response.end(); return }
    const file = new Map([['/generation-rtc-page.js', 'generation-rtc-page.js'], ['/generation-rtc-worker.js', 'generation-rtc-worker.js']]).get(path)
    const bytes = path === '/' ? Buffer.from('<!doctype html><meta charset="utf-8"><title>Peer generation RTC qualification</title><script type="module" src="/generation-rtc-page.js"></script>')
      : file === undefined ? null : await readFile(join(output, file))
    if (bytes === null) { host.applicationRequests++; response.writeHead(404); response.end(); return }
    response.setHeader('Content-Type', path === '/' ? 'text/html' : 'application/javascript')
    host.responseBytes += bytes.length; response.end(bytes)
  }
  void run().catch((error: unknown) => { errors.push(String(error)); response.writeHead(500); response.end('fixture request failed') })
})
server.listen(0, '127.0.0.1'); await once(server, 'listening')
const address = server.address(); assert(address !== null && typeof address !== 'string')
base = `http://127.0.0.1:${address.port}`
const closeHost = async (): Promise<void> => {
  if (hostClosed) return
  hostClosed = true; server.closeAllConnections()
  await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error)))
}
const passed = (id: string): void => { checks.push({ id, passed: true }); process.stdout.write(`Passed: ${id}\n`) }
const content = Uint8Array.from({ length: 512 * 1024 + 37 }, (_, index) => index % 251), contentHash = digest(content)
try {
  browser = await chromium.launch({ headless: true,
    ...(process.env.CHRONOLOG_CHROMIUM_EXECUTABLE === undefined ? {} : { executablePath: process.env.CHRONOLOG_CHROMIUM_EXECUTABLE }) })
  context = await browser.newContext(); page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  context.on('request', request => { browserRequests.push({ method: request.method(), path: new URL(request.url()).pathname }) })
  await page.goto(base); await page.waitForFunction(() => 'peerGenerationRtcTest' in globalThis)
  phase = 'explicit-fixture-enrollment'
  const identity = await page.evaluate(name => (globalThis as unknown as TestWindow).peerGenerationRtcTest.prepare(name), `generation-rtc-${crypto.randomUUID()}`)
  nativeDevice = await openNativeDevice({ path: join(directory, 'native.sqlite'), create: true })
  const owner = await createPeerIdentity(), key = crypto.getRandomValues(new Uint8Array(32))
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '98'.repeat(32), historyId: 'generation-rtc', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: owner.publicKey, schemaAdministrator: nativeDevice.identity.publicKey,
    definitionDigest: await applicationDefinitionDigest(definition), executionManifestDigest: bytesToHex(manifest.executionManifestDigest), schemaDigest: null }, owner)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [controlParticipantGrant(owner.publicKey), participantGrant(nativeDevice.identity.publicKey, { dataRole: 'admin' }), participantGrant(identity.publicKey)] }, owner)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: owner })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    transitionId: 'initial', expectedGeneration: null, coordinator: nativeDevice.identity.publicKey, requester: nativeDevice.identity.publicKey,
    controlRevision: 0, reason: 'create', base: null }, nativeDevice.identity))
  const authority = await registry.read()
  native = await openNativeApplication({ device: nativeDevice, authority, definition, epochKeys: new Map([[0, key]]) })
  const owned = native
  void (async () => {
    try { for await (const value of owned.signals.subscribe({ signal: owned.signal })) nativeSignals.push(value) }
    catch (error) { if (!owned.signal.aborted) errors.push(String(error)) }
  })()
  await page.evaluate(bootstrap => (globalThis as unknown as TestWindow).peerGenerationRtcTest.open(bootstrap), { authority, epoch: 0, epochKey: bytesToHex(key) })
  const upload = await native.content.stage({ bytes: content.length })
  for (let offset = 0; offset < content.length; offset += 65_536) await upload.write(offset / 65_536, content.slice(offset, offset + 65_536))
  const reference = await upload.commit()
  introduction = createWebRtcOfferHandler({ allowedOrigins: [base], configuration: { iceServers: [] },
    authorize: request => request.headers.get('Authorization') === `Bearer ${token}`,
    createPeerConnection: configuration => createNativePeerConnection(configuration, {
      iceInterfaceAddresses: { udp4: '127.0.0.1' }, iceUseIpv6: false, iceUseTcp: false,
    }),
    onError(error) {
      const message = error instanceof Error ? error.message : String(error)
      if (intentionalClose && /CLOSED|ENDED|DISCONNECTED|ABORT/iu.test(message)) expectedTerminations.push(message)
      else errors.push(message)
    },
    async accept(connection, signal) {
      nativeChannel = connection
      nativeLink = await owned.connectPeer({ connection, signal, peerIdentity: identity.publicKey })
      return nativeLink
    },
  })
  const connect = () => page!.evaluate(options => (globalThis as unknown as TestWindow).peerGenerationRtcTest.connect(options),
    { url: `${base}/signal`, token, peerIdentity: owned.deviceId })
  phase = 'first-authenticated-connection'
  const first = await connect()
  assert.equal(first.peerId, native.deviceId); assert.equal(first.state.deviceId, identity.publicKey); assert.equal(first.state.workerOwnsSession, true)
  assert.equal(first.signaling.requests, 1); assert.equal(first.signaling.closed, true); assert.equal(first.route.route, 'direct')
  await waitFor(async () => introduction!.stats.accepted === 1 && introduction!.stats.pending === 0, 'generation RTC first authentication', 10_000)
  passed('worker-native-authenticated-webrtc')
  await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.publish('before-reconnect', 'first connection'))
  intentionalClose = true
  await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.disconnect())
  await waitFor(async () => introduction!.stats.active === 0, 'old generation RTC connection retires', 10_000)
  intentionalClose = false
  const saved = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.save('offline-original', 'saved without a route'))
  assert.equal(saved.state.status, 'saved')
  phase = 'authenticated-reconnect'
  const began = performance.now(), second = await connect(), reconnectElapsedMs = performance.now() - began
  const retried = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.publish('offline-original', 'saved without a route'))
  assert.deepEqual(retried.attempt, saved.attempt); assert.equal(retried.applied.outcome, 'accepted')
  assert.equal(second.signaling.requests, 1); assert.equal(second.signaling.closed, true); assert.equal(second.route.route, 'direct')
  await waitFor(async () => introduction!.stats.accepted === 2 && introduction!.stats.active === 1 && introduction!.stats.pending === 0,
    'replacement generation RTC connection authenticates', 10_000)
  passed('saved-original-attempt-survives-rtc-reconnect')

  await page.waitForLoadState('networkidle')
  const before = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.transport())
  const nativeBefore = nativeChannel!.stats
  await closeHost()
  const hostBefore = structuredClone(host), requestsBefore = structuredClone(browserRequests)
  phase = 'host-offline-data-plane'
  const browserOperation = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.publish('browser-offline', 'browser with host stopped'))
  const nativeOperation = await native.command('say', 'native with host stopped', { operationId: 'native-offline' })
  const nativeApplied = await nativeOperation.applied({ signal: AbortSignal.timeout(20_000) })
  assert.equal(browserOperation.applied.outcome, 'accepted'); assert.equal(nativeApplied.outcome, 'accepted')
  passed('both-peers-apply-commands-after-host-shutdown')
  const receivedContent = await page.evaluate(reference => (globalThis as unknown as TestWindow).peerGenerationRtcTest.content(reference), reference)
  assert.equal(receivedContent.bytes, content.length); assert.equal(receivedContent.sha256, contentHash)
  assert.equal(receivedContent.retained.payload.peer, identity.publicKey)
  assert((await native.content.retention(reference)).some(value => value.payload.peer === identity.publicKey))
  passed('encrypted-content-arrives-over-peer-chunks')

  let converged!: BrowserState
  await waitFor(async () => {
    converged = await page!.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.state())
    const current = await owned.query('messages', null)
    return converged.events.length === 4 && JSON.stringify(converged.events) === JSON.stringify(current.value.events) &&
      JSON.stringify(converged.revision.point) === JSON.stringify(current.revision.point)
  }, 'generation RTC applied histories converge', 20_000)
  const beforeSignal = converged.revision, nativeRevision = native.revision
  await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.signal('browser live'))
  await native.signals.send('typing', { text: 'native live' })
  await waitFor(async () => {
    const current = await page!.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.state())
    return current.signals.some(value => value.authorId === owned.deviceId && value.topic === 'typing') &&
      nativeSignals.some(value => value.authorId === identity.publicKey && value.topic === 'typing')
  }, 'signed live signals cross independent lanes', 10_000)
  const afterSignals = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.state())
  assert.deepEqual(afterSignals.revision, beforeSignal); assert.deepEqual(native.revision, nativeRevision)
  passed('signed-live-signals-leave-application-history-unchanged')
  const exactRetry = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.publish('browser-offline', 'browser with host stopped'))
  assert.deepEqual(exactRetry, browserOperation)
  const coverage = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.shared('browser-offline'))
  assert(coverage.some(value => value.payload.peer === owned.deviceId))
  const after = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.transport())
  assert(after.stats.sentBytes > before.stats.sentBytes); assert(nativeChannel!.stats.sentBytes > nativeBefore.sentBytes)
  assert.equal(host.applicationRequests, 0); assert.deepEqual(host, hostBefore); assert.deepEqual(browserRequests, requestsBefore)
  assert.deepEqual(after.signaling, before.signaling)
  passed('original-retry-coverage-and-peer-history-converge')

  phase = 'offline-opfs-reopen'; intentionalClose = true
  const reopened = await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.reopen())
  await waitFor(async () => introduction!.stats.active === 0, 'closed Worker RTC peer retires', 10_000)
  assert.equal(reopened.deviceId, identity.publicKey); assert.equal(reopened.storageId, identity.storageId)
  assert.deepEqual(reopened.events, converged.events); assert.deepEqual(reopened.revision.point, converged.revision.point)
  const reopenedContent = await page.evaluate(reference => (globalThis as unknown as TestWindow).peerGenerationRtcTest.content(reference), reference)
  assert.equal(reopenedContent.sha256, contentHash); assert.equal(reopenedContent.bytes, content.length)
  passed('offline-opfs-reopen-preserves-history-and-content')
  assert.deepEqual(host, hostBefore); assert.deepEqual(browserRequests, requestsBefore); assert.equal(host.introductions, 2)
  assert.deepEqual(errors, [])
  passed('host-http-and-signaling-remain-idle')
  await page.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.close())
  await introduction.close(); await native.close()
  assert.equal(introduction.stats.pending, 0); assert.equal(introduction.stats.active, 0)
  passed('owned-peer-and-storage-lifetimes-close')
  assert.equal(git(['rev-parse', 'HEAD']), source.head); assert.equal(git(['status', '--porcelain']), '')
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-peer-session-webrtc-qualification/v1', passed: true, source,
    runtime: { node: process.version, browser: browser.version(), native: 'werift@0.27.0' }, files, checks,
    topology: { profile: 'peer-generation-v1', transport: 'real WebRTC ICE/DTLS/SCTP', browserStorage: 'OPFS', nativeStorage: 'SQLite',
      channelOwner: 'DedicatedWorker', signaling: 'two direct one-POST loopback introductions', hostStopped: true,
      epochProvisioning: 'explicit fixture enrollment through the local test harness',
      excludes: ['packaged Tendriller host', 'automatic key delivery', 'automatic reconnect policy', 'public NAT traversal', 'TURN interoperability', 'provider billing', 'irreversible finality'] },
    metrics: { host: { before: hostBefore, after: host }, browserHttp: { before: requestsBefore, after: browserRequests },
      reconnect: { elapsedMs: reconnectElapsedMs, routes: [first.route, second.route], originalAttemptId: saved.attempt.id, retriedAttemptId: retried.attempt.id },
      signaling: after.signaling, reliable: { before: before.stats, after: after.stats }, nativeChannels: { before: nativeBefore, after: nativeChannel!.stats },
      content: { bytes: content.length, expectedSha256: contentHash, receivedSha256: receivedContent.sha256, reopenedSha256: reopenedContent.sha256,
        referenceId: reference.id, retainedBy: receivedContent.retained.payload.peer },
      history: { nativePoint: nativeRevision.point, browserPoint: converged.revision.point, reopenedPoint: reopened.revision.point,
        events: converged.events, browserOriginal: browserOperation.applied, browserRetry: exactRetry.applied, native: nativeApplied },
      signals: { browser: afterSignals.signals, native: nativeSignals }, coverage, introduction: introduction.stats, expectedTerminations,
      byteBoundary: 'Reliable network counters include application framing; RTC adapter counters include its packets. Neither is provider billing or IP/DTLS overhead.' },
  }, null, 2) + '\n')
  process.stdout.write(`Peer generation browser/native WebRTC qualification passed: ${join(output, 'report.json')}\n`)
} catch (error) {
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-peer-session-webrtc-qualification/v1', passed: false,
    source, phase, checks, errors, expectedTerminations, host, browserRequests, error: error instanceof Error ? error.stack : String(error) }, null, 2) + '\n')
  throw error
} finally {
  intentionalClose = true
  await introduction?.close(); await nativeLink?.close(); await nativeChannel?.close()
  try { await page?.evaluate(() => (globalThis as unknown as TestWindow).peerGenerationRtcTest.close()) } catch { /* Preserve the original qualification outcome. */ }
  await native?.close(); await nativeDevice?.close(); await context?.close(); await browser?.close(); await closeHost()
  await rm(directory, { recursive: true, force: true })
}

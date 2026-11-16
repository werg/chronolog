import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { extname, join, resolve } from 'node:path'

import { chromium } from '@playwright/test'
import { build } from 'esbuild'

import type { BrowserBridgeSnapshot } from '../test/browser/bridge-contract.js'
import type { BrowserBridgeApi } from '../test/browser/bridge-page.js'
import { createBrowserBridgeFixture } from './browser-bridge-fixture.js'

interface TestWindow { readonly chronologBrowserBridge: BrowserBridgeApi }

const workspace = resolve(import.meta.dirname, '..')
const artifacts = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? join(workspace, 'artifacts/wasm'))
const output = join(workspace, 'artifacts/browser-bridge')
await mkdir(output, { recursive: true })
const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap((name) =>
  ['', '/browser'].map((suffix) => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
alias['@chronolog/node-core/history'] = join(workspace, 'packages/node-core/src/history-policy.ts')
await build({
  absWorkingDir: workspace,
  entryPoints: { 'bridge-worker': 'test/browser/bridge-worker.ts', 'bridge-page': 'test/browser/bridge-page.ts' },
  outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias,
})
const html = '<!doctype html><meta charset="utf-8"><title>Chronolog browser and native claim qualification</title><script type="module" src="/bridge-page.js"></script>'
const files = new Map([
  ['/bridge-page.js', join(output, 'bridge-page.js')], ['/bridge-worker.js', join(output, 'bridge-worker.js')],
  ...['sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js', 'manifest.json'].map((name) => [`/engine/${name}`, join(artifacts, name)] as const),
])
const server = createServer((request, response) => {
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp')
  response.setHeader('Cache-Control', 'no-store')
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  if (path === '/') { response.setHeader('Content-Type', 'text/html'); response.end(html); return }
  const file = files.get(path)
  if (file === undefined) { response.writeHead(404); response.end(); return }
  response.setHeader('Content-Type', extname(file) === '.wasm' ? 'application/wasm' : extname(file) === '.json' ? 'application/json' : 'application/javascript')
  void readFile(file).then((bytes) => response.end(bytes), () => { response.writeHead(500); response.end() })
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
if (address === null || typeof address === 'string') throw new Error('BROWSER_BRIDGE_SERVER_ADDRESS_UNAVAILABLE')
const directory = await mkdtemp(join(tmpdir(), 'chronolog-browser-bridge-'))
const fixture = await createBrowserBridgeFixture({ rootDirectory: directory })
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHRONOLOG_CHROMIUM_EXECUTABLE === undefined ? {} : { executablePath: process.env.CHRONOLOG_CHROMIUM_EXECUTABLE }),
})
const context = await browser.newContext()
const page = await context.newPage()
page.setDefaultTimeout(30_000)
page.on('console', (message) => { if (message.type() === 'error') process.stderr.write(`browser bridge: ${message.text()}\n`) })
page.on('pageerror', (error) => process.stderr.write(`browser bridge page error: ${error.message}\n`))
const overallDeadline = setTimeout(() => { void page.close() }, 180_000)
const checks: string[] = []
const passed = (check: string): void => { checks.push(check); process.stdout.write(`Passed: ${check}\n`) }
const state = (id: string, transactionIds: readonly string[] = []): Promise<BrowserBridgeSnapshot> =>
  page.evaluate(({ id, transactionIds }) => (globalThis as unknown as TestWindow).chronologBrowserBridge.state(id, transactionIds), { id, transactionIds })
const sync = async (id = 'browser'): Promise<void> => {
  await page.evaluate((id) => (globalThis as unknown as TestWindow).chronologBrowserBridge.sync(id), id)
}
const compare = (actual: BrowserBridgeSnapshot, expected: BrowserBridgeSnapshot): void => {
  assert.equal(actual.hash, expected.hash, 'native and browser SQL content hashes differ')
  assert.equal(actual.finalOrderLength, expected.finalOrderLength)
  assert.equal(actual.finalThrough, expected.finalThrough)
  assert.deepEqual(actual.rows, expected.rows)
  assert.deepEqual(actual.outcomes.map(({ outcome, final }) => ({ outcome, final })), expected.outcomes.map(({ outcome, final }) => ({ outcome, final })))
}
const report = async (details: Record<string, unknown>): Promise<void> => {
  await writeFile(join(output, 'report.json'), JSON.stringify({
    ...details, browser: browser.version(), checks,
    wasmManifest: JSON.parse(await readFile(join(artifacts, 'manifest.json'), 'utf8')) as unknown,
  }, null, 2) + '\n')
}

try {
  const origin = `http://127.0.0.1:${address.port}/`
  await page.goto(origin)
  await page.waitForFunction(() => 'chronologBrowserBridge' in globalThis)
  const name = `bridge-${crypto.randomUUID()}`
  const identity = await page.evaluate(({ name, bootstrap }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.open('browser', name, bootstrap), { name, bootstrap: fixture.bootstrap })
  assert.notEqual(identity.identity, fixture.bootstrap.rootIdentity)
  const request = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.request('browser', 'join-browser', ['reader', 'writer']))
  assert.equal((await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.enrollmentStatus('browser', 'join-browser'))).state, 'requested')
  const approval = await fixture.approveEnrollment(request.signedRequest, 'approve-browser', ['reader', 'writer'])
  await fixture.sync()
  await sync()
  const enrolled = await page.evaluate(({ signedApproval }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.enrollmentStatus('browser', 'join-browser', signedApproval), approval)
  assert.equal(enrolled.state, 'ready')
  assert.deepEqual(enrolled.roles, ['reader', 'writer'])
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.query('browser', 'SELECT id, value FROM history ORDER BY id')), [[1n, 'before-enrollment']])
  passed('independent browser keys enroll through the public client, signed approval, and explicit full-history access')

  const task = await fixture.prepareTask(identity.identity)
  await sync()
  const membership = await page.evaluate(({ teamId }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.acceptTeam('browser', teamId), task)
  await fixture.sync()
  await sync()
  const membershipFinal = await page.evaluate((transactionId) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.final('browser', transactionId), membership)
  assert.equal(membershipFinal.final, true)
  assert.equal(membershipFinal.outcome.type, 'accepted')
  passed('native agent and browser explicitly join one collective owning the SQL task')

  const [nativeClaim, browserClaim] = await Promise.all([
    fixture.claimTask('native-claim'),
    page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.claim('browser', 'browser-claim')),
  ])
  const transactionIds = [nativeClaim, browserClaim]
  const beforeCertification = await fixture.snapshot([nativeClaim])
  assert(beforeCertification.outcomes.every(({ outcome, final }) => outcome.type === 'pending' && !final))
  const browserPending = await page.evaluate((transactionId) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.outcome('browser', transactionId), browserClaim)
  assert.equal(browserPending.outcome.type, 'pending')
  assert.equal(browserPending.final, false)
  const nativeFinal = await fixture.sync(transactionIds)
  await sync()
  const browserFinal = await page.evaluate((transactionId) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.final('browser', transactionId), browserClaim)
  assert.equal(browserFinal.final, true)
  const shared = await state('browser', transactionIds)
  compare(shared, nativeFinal)
  assert.deepEqual(shared.outcomes.map(({ outcome }) => outcome.type).sort(), ['accepted', 'rejected'])
  assert(shared.outcomes.every(({ final }) => final))
  const rejected = shared.outcomes.find(({ outcome }) => outcome.type === 'rejected')!
  assert.deepEqual(rejected.outcome, { type: 'rejected', rejection: { code: 'assert:already_claimed', statementIndex: 0 } })
  const winner = shared.outcomes[0]!.outcome.type === 'accepted' ? 'native' : 'browser'
  assert.deepEqual(shared.rows, [[{ kind: 'integer', value: '1' }, { kind: 'text', value: winner }]])
  passed('two claims through the public Tendriller SDK produce one final winner and one assertion rejection in real native/WASM SQL')

  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.stop('browser'))
  await page.reload()
  await page.waitForFunction(() => 'chronologBrowserBridge' in globalThis)
  const reopened = await page.evaluate(({ name, bootstrap }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.open('browser', name, bootstrap), { name, bootstrap: fixture.bootstrap })
  assert.deepEqual(reopened, identity)
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.request('browser', 'join-browser', ['reader', 'writer'])), request)
  assert.equal((await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.enrollmentStatus('browser', 'join-browser'))).state, 'ready')
  assert.equal(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.claim('browser', 'browser-claim')), browserClaim)
  const retryFinal = await page.evaluate((transactionId) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.final('browser', transactionId), browserClaim)
  assert.deepEqual(retryFinal.outcome, browserFinal.outcome)
  const retried = await fixture.sync(transactionIds)
  assert.equal(retried.logPosition, nativeFinal.logPosition, 'retry appended a duplicate ordered proposal')
  compare(await state('browser', transactionIds), nativeFinal)
  passed('page reload retains OPFS signer, reader key, signed enrollment request, final SQL, and exact durable claim identity')

  const third = await page.evaluate(({ name, bootstrap }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.open('reader', `${name}-reader`, bootstrap, false), { name, bootstrap: fixture.bootstrap })
  assert.notEqual(third.identity, identity.identity)
  assert.notEqual(third.identity, fixture.bootstrap.rootIdentity)
  const readerRequest = await page.evaluate(() =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.request('reader', 'join-reader', ['reader']))
  const readerApproval = await fixture.approveEnrollment(readerRequest.signedRequest, 'approve-reader', ['reader'])
  const approvedHistory = await fixture.sync(transactionIds)
  await sync()
  const readySource = await state('browser', transactionIds)
  compare(readySource, approvedHistory)
  const beforePeer = await page.evaluate(({ signedApproval }) =>
    (globalThis as unknown as TestWindow).chronologBrowserBridge.enrollmentStatus('reader', 'join-reader', signedApproval), readerApproval)
  assert.notEqual(beforePeer.state, 'ready', 'fresh reader became ready before receiving any retained history')
  fixture.cutHub()
  const offlineResponse = await fetch(`${fixture.bootstrap.hubUrl}/records`, {
    headers: { Authorization: `Bearer ${fixture.bootstrap.token}` },
  })
  assert.equal(offlineResponse.status, 503, 'the retained log remained available after shutdown')
  await offlineResponse.arrayBuffer()
  const hubRequestsBefore = fixture.hubRequests()
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.connect('browser', 'reader'))
  await sync('reader')
  const readyReader = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.enrollmentStatus('reader', 'join-reader'))
  assert.equal(readyReader.state, 'ready')
  assert.deepEqual(readyReader.roles, ['reader'])
  compare(await state('reader', transactionIds), approvedHistory)
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.query('reader', 'SELECT id, value FROM history ORDER BY id')), [[1n, 'before-enrollment']])
  assert.deepEqual(fixture.hubRequests(), hubRequestsBefore, 'offline peer recovery contacted the hub or authority')
  passed('fresh approved reader replays certified history and historical keys from an ordinary browser peer with the hub offline')

  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.stop('reader'))
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserBridge.stop('browser'))
  await report({ passed: true, winner, transactionIds, finalOrderLength: approvedHistory.finalOrderLength,
    finalThrough: approvedHistory.finalThrough, databaseContentHash: approvedHistory.hash,
    finalOutcomes: shared.outcomes.map(({ transactionId, outcome, final }) => ({ transactionId, outcome, final })),
    enrollmentStates: { browser: enrolled.state, reader: readyReader.state }, hubRequestsDuringOfflineReplay: 0 })
  process.stdout.write(`Browser/native coordinated qualification passed (${checks.length} checks), Chromium ${browser.version()}\n`)
} catch (error) {
  await report({ passed: false, error: error instanceof Error ? error.stack : String(error) })
  throw error
} finally {
  clearTimeout(overallDeadline)
  await context.close()
  await browser.close()
  await fixture.close()
  server.close()
  await rm(directory, { recursive: true, force: true, maxRetries: 5 })
}

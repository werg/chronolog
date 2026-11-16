import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { chromium } from '@playwright/test'
import { build } from 'esbuild'

import type { BrowserEventTestApi } from '../test/browser/event-page.js'
import { createNativeBrowserFixture, type NativeBrowserFixture } from './browser-event-fixture.js'

interface TestWindow { readonly chronologEventTest: BrowserEventTestApi }
const workspace = resolve(import.meta.dirname, '..')
const output = join(workspace, 'artifacts/browser-events')
await mkdir(output, { recursive: true })
const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap((name) =>
  ['', '/browser'].map((suffix) => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
for (const [name, file] of [['history', 'history-policy'], ['finality', 'finality'], ['ledger', 'ledger-record'], ['membership', 'membership']]) {
  alias[`@chronolog/node-core/${name}`] = join(workspace, `packages/node-core/src/${file}.ts`)
}
const bundled = await build({ absWorkingDir: workspace,
  entryPoints: { 'event-worker': 'test/browser/event-worker.ts', 'event-page': 'test/browser/event-page.ts' },
  outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias, metafile: true })
// Check emitted bytes, not just names: a barrel may be parsed and tree-shaken.
const forbidden = Object.values(bundled.metafile.outputs).flatMap((entry) => Object.entries(entry.inputs)
  .filter(([name, input]) => input.bytesInOutput > 0 && (/materializer-doltlite/u.test(name) ||
    /runtime-browser\/src\/(?:wasm-engine|load-engine|control-persistence|peer)\.ts$/u.test(name)))
  .map(([name]) => name))
assert.deepEqual(forbidden, [], 'event-only browser bundle includes SQL/WASM implementation code')
await writeFile(join(output, 'bundle.json'), JSON.stringify({ sqlFree: true, metafile: bundled.metafile }, null, 2) + '\n')
if (process.argv.includes('--build-only')) {
  process.stdout.write('Event-only browser bundle built; no SQL/WASM implementation bytes emitted.\n')
  process.exit(0)
}

let engineRequests = 0
const server = createServer((request, response) => {
  // This profile must work without cross-origin isolation headers.
  response.setHeader('Cache-Control', 'no-store')
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  if (/engine|\.wasm/u.test(path)) engineRequests += 1
  if (path === '/') {
    response.setHeader('Content-Type', 'text/html')
    response.end('<!doctype html><meta charset="utf-8"><title>Chronolog SQL-free events qualification</title><script type="module" src="/event-page.js"></script>')
    return
  }
  const file = new Map([['/event-page.js', 'event-page.js'], ['/event-worker.js', 'event-worker.js']]).get(path)
  if (file === undefined) { response.writeHead(404); response.end(); return }
  response.setHeader('Content-Type', 'application/javascript')
  void readFile(join(output, file)).then((bytes) => response.end(bytes), () => { response.writeHead(500); response.end() })
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
if (address === null || typeof address === 'string') throw new Error('EVENT_BROWSER_SERVER_ADDRESS_UNAVAILABLE')
const browser = await chromium.launch({ headless: true,
  ...(process.env.CHRONOLOG_CHROMIUM_EXECUTABLE === undefined ? {} : { executablePath: process.env.CHRONOLOG_CHROMIUM_EXECUTABLE }) })
const context = await browser.newContext()
const page = await context.newPage()
const directory = await mkdtemp(join(tmpdir(), 'chronolog-browser-events-'))
let native: NativeBrowserFixture | undefined
const checks: string[] = ['SQL-free Worker/client emitted bundle has no SQL or WASM implementation bytes']
const deviceEvidence: Record<string, unknown> = {
  boundary: 'real Chromium OPFS and native process on loopback; synthetic enrolled identities',
  quotaMethod: 'Chromium Storage Bucket with 64 KiB quota; production OPFS checkpoint and operation-journal classes',
  defaultBucketQuota: { qualified: false, reason: 'DevTools quota override did not enforce OPFS replacement in Chromium 158.0.8127.18',
    observedRun: 'https://github.com/werg/chronolog-db/actions/runs/43967265774' },
  storageLossMethod: 'Chromium DevTools Storage.clearDataForOrigin after orderly Worker shutdown',
  exclusions: ['physical device storage pressure or OS eviction', 'deployed identity-provider authentication',
    'private production workload audit', 'browser-vendor and mobile background policies'],
}
const passed = (check: string) => { checks.push(check); process.stdout.write(`Passed: ${check}\n`) }
const save = (passed: boolean, error?: unknown) => writeFile(join(output, 'report.json'), JSON.stringify({
  passed, browser: browser.version(), checks, engineRequests,
  nativeFinalThrough: native?.node.finalThrough ?? null, backend: 'native-fixed-authority',
  transport: 'authenticated-framed-loopback', deviceEvidence,
  ...(error === undefined ? {} : { error: error instanceof Error ? error.stack ?? error.message :
    typeof error === 'string' ? error : 'Unknown non-Error failure' }),
}, null, 2) + '\n')
const deadline = setTimeout(() => { void page.close() }, 210_000)
page.on('pageerror', (error) => process.stderr.write(`browser: ${error.message}\n`))
page.on('console', (message) => { if (message.type() === 'error') process.stderr.write(`browser: ${message.text()}\n`) })
try {
  await page.goto(`http://127.0.0.1:${address.port}`)
  await page.waitForFunction(() => 'chronologEventTest' in globalThis)
  const name = `events-${crypto.randomUUID()}`
  const identity = await page.evaluate((name) => (globalThis as unknown as TestWindow).chronologEventTest.prepare(name), name)
  native = await createNativeBrowserFixture({ directory, browsers: [identity], topics: ['chat', 'tasks'] })
  const bootstrap = native.bootstrap
  const opened = await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('owner', name, bootstrap), { name, bootstrap })
  assert.equal(opened.isolated, false)
  assert.equal(opened.identity, identity.identity)
  await assert.rejects(page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('contender', name, bootstrap), { name, bootstrap }), /BROWSER_STORAGE_IN_USE/u)
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.sql('owner')), /SQL_DISABLED_FOR_EVENT_PROFILE/u)
  passed('real OPFS Worker opens without cross-origin isolation or a SQL engine; exclusive ownership and SQL refusal hold')

  const events = [{ topic: 'chat', payload: { message: 'first' } }, { topic: 'tasks', payload: { task: 'same atomic proposal' } }]
  const published = await page.evaluate(({ events }) => (globalThis as unknown as TestWindow).chronologEventTest.publish('owner', events, 'browser-atomic-1'), { events })
  assert.equal(published.outcome.outcome.type, 'accepted')
  const first = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.read('owner'))
  assert.equal(first.transactions.length, 1)
  assert.deepEqual(first.transactions[0]!.events.map((event) => event.eventOrdinal), [0, 1])
  assert.deepEqual(await native.client.events.read(), first)
  const filtered = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.read('owner', { topics: ['chat'], limit: 1 }))
  assert.equal(filtered.transactions[0]!.events.length, 1)
  assert.equal(filtered.transactions[0]!.proposalId, published.proposalId)
  passed('browser signs one atomic event proposal; native inclusion and closure evidence produces identical chronologically ordered final events over framed ranges')

  const revision = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.capture('owner', 'before-native'))
  const pending = page.evaluate(({ cursor }) => (globalThis as unknown as TestWindow).chronologEventTest.readNext('owner', { cursor }), { cursor: first.scannedThrough })
  const nativeHandle = await native.client.events.publish('tasks', { task: 'native publication' }, { operationId: 'native-event-1' })
  try { assert.equal((await nativeHandle.final({ signal: AbortSignal.timeout(20_000) })).outcome.type, 'accepted') }
  finally { nativeHandle.dispose() }
  const delivered = await pending
  assert.equal(delivered.transactions.length, 1)
  assert.deepEqual(delivered.transactions[0]!.events[0]!.payload, { task: 'native publication' })
  const captured = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.viewEvents('owner', 'before-native'))
  assert.equal(captured.revision, revision)
  assert.equal(captured.transactions.length, 1)
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.release('owner', 'before-native'))
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.viewEvents('owner', 'before-native')), /released/u)
  passed('native publication reaches durable browser subscription; retained read view stays pinned until explicit release')

  const checkpoint = { cursor: first.scannedThrough, revision: first.revision, state: 'two-events-reduced' }
  const next = { cursor: delivered.scannedThrough, revision: delivered.revision, state: 'three-events-reduced' }
  await page.evaluate(({ checkpoint }) => (globalThis as unknown as TestWindow).chronologEventTest.checkpoint('owner', checkpoint), { checkpoint })
  await page.evaluate(({ next }) => (globalThis as unknown as TestWindow).chronologEventTest.crashCheckpoint('owner', { ...next, pause: 'before' }), { next })
  await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('reopened', name, bootstrap), { name, bootstrap })
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.checkpointState('reopened')), checkpoint)
  const replayed = await page.evaluate(({ cursor }) => (globalThis as unknown as TestWindow).chronologEventTest.read('reopened', { cursor }), { cursor: checkpoint.cursor })
  assert.deepEqual(replayed.transactions, delivered.transactions)
  passed('termination before checkpoint replacement retains prior state and processed cursor together, with at-least-once replay')
  await page.evaluate(({ next }) => (globalThis as unknown as TestWindow).chronologEventTest.crashCheckpoint('reopened', { ...next, pause: 'after' }), { next })
  await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('committed', name, bootstrap), { name, bootstrap })
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.checkpointState('committed')), next)
  assert.equal((await page.evaluate(({ cursor }) => (globalThis as unknown as TestWindow).chronologEventTest.read('committed', { cursor }), { cursor: next.cursor })).transactions.length, 0)
  passed('termination after OPFS checkpoint replacement retains new state and processed cursor together without skipped final events')

  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.crashCutoff('committed', '987654321'))
  await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('cutoff-reopened', name, bootstrap), { name, bootstrap })
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.cutoff('cutoff-reopened')), ['987654321'])
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.cutoff('cutoff-reopened', '987654320')), /CUTOFF_REGRESSION/u)
  const retry = await page.evaluate(({ events }) => (globalThis as unknown as TestWindow).chronologEventTest.publish('cutoff-reopened', events, 'browser-atomic-1'), { events })
  assert.equal(retry.proposalId, published.proposalId)
  const final = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.read('cutoff-reopened'))
  assert.deepEqual(final.transactions[0], first.transactions[0])
  assert.equal(final.transactions.length, 2)
  assert.equal(engineRequests, 0)
  native.assertHealthy()
  passed('private cutoff flush survives abrupt Worker termination; original operation identity and event IDs survive restart without engine requests')

  const privateKey = 'qualification/private-device-value', privateNative = `native-private-${crypto.randomUUID()}`
  const privateBrowser = `browser-private-${crypto.randomUUID()}`
  const recordsBeforePrivate = (await native.transport.history()).length
  await native.store.put(privateKey, new TextEncoder().encode(privateNative))
  assert.equal(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.privateValue('cutoff-reopened')), null)
  assert.equal(await page.evaluate((value) => (globalThis as unknown as TestWindow).chronologEventTest.privateValue('cutoff-reopened', value), privateBrowser), privateBrowser)
  assert.equal(new TextDecoder().decode((await native.store.get(privateKey))!), privateNative)
  assert.equal((await native.transport.history()).length, recordsBeforePrivate)
  assert.deepEqual((await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.read('cutoff-reopened'))).transactions, final.transactions)
  deviceEvidence.privateStores = { nativeValueRemainedLocal: true, browserValueRemainedLocal: true, addedRecords: 0 }
  passed('private agent and device store values stay separate and produce no replicated records or application events')

  const isolatedContext = await browser.newContext()
  try {
    const isolatedPage = await isolatedContext.newPage()
    await isolatedPage.goto(page.url())
    await isolatedPage.waitForFunction(() => 'chronologEventTest' in globalThis)
    await assert.rejects(isolatedPage.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('isolated', name, bootstrap), { name, bootstrap }), /ENROLLMENT_IDENTITY_MISSING/u)
    const isolatedIdentity = await isolatedPage.evaluate((name) => (globalThis as unknown as TestWindow).chronologEventTest.prepare(name), name)
    assert.notEqual(isolatedIdentity.identity, identity.identity)
    assert.notEqual(isolatedIdentity.readerKey, identity.readerKey)
    deviceEvidence.isolatedStores = { sameOriginAndPeerName: true, originalKeysAbsent: true,
      originalIdentity: identity.identity, independentIdentity: isolatedIdentity.identity }
  } finally { await isolatedContext.close() }
  passed('an isolated browser context cannot reopen another device identity; explicit setup produces independently keyed storage')

  const cdp = await context.newCDPSession(page), origin = new URL(page.url()).origin
  deviceEvidence.originStorageBeforeQuotaProbe = await cdp.send('Storage.getUsageAndQuota', { origin })
  const quota = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.quota('cutoff-reopened'))
  deviceEvidence.quota = quota
  assert.equal(quota.passed, true)
  assert.equal((await native.transport.history()).length, recordsBeforePrivate)
  passed('real limited-bucket quota errors preserve production OPFS checkpoints and durable operation retries without calling apply for failed preparation')

  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.close('cutoff-reopened'))
  const quotaReopened = await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('quota-reopened', name, bootstrap), { name, bootstrap })
  assert.equal(quotaReopened.identity, identity.identity)
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.checkpointState('quota-reopened')), next)
  const acceptedRetry = await page.evaluate(({ events }) => (globalThis as unknown as TestWindow).chronologEventTest.publish('quota-reopened', events, 'browser-atomic-1'), { events })
  assert.equal(acceptedRetry.proposalId, published.proposalId)
  assert.equal((await native.transport.history()).length, recordsBeforePrivate)
  deviceEvidence.defaultPeerReopen = { boundary: 'separate default bucket; it was not quota-exhausted',
    identity: quotaReopened.identity, preservedCheckpoint: next, originalProposalId: published.proposalId,
    retryProposalId: acceptedRetry.proposalId, exactRetryAddedRecords: 0 }

  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.close('quota-reopened'))
  const partialLossHead = (await native.transport.history()).length
  const backup = await page.evaluate((name) => (globalThis as unknown as TestWindow).chronologEventTest.removeFeedMetadata(name), name)
  assert.equal(backup.identity, identity.identity)
  await assert.rejects(page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('partial-loss', name, bootstrap), { name, bootstrap }), /BROWSER_FEED_MANIFEST_MISSING/u)
  assert.equal((await native.transport.history()).length, partialLossHead)
  await page.evaluate(({ name, manifest, binding }) => (globalThis as unknown as TestWindow).chronologEventTest.restoreFeedMetadata(name, manifest, binding),
    { name, manifest: backup.manifest, binding: backup.binding })
  const partialRestored = await page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('partial-restored', name, bootstrap), { name, bootstrap })
  assert.equal(partialRestored.identity, identity.identity)
  const partialRetry = await page.evaluate(({ events }) => (globalThis as unknown as TestWindow).chronologEventTest.publish('partial-restored', events, 'browser-atomic-1'), { events })
  assert.equal(partialRetry.proposalId, published.proposalId)
  assert.equal((await native.transport.history()).length, partialLossHead)
  const afterPartialRestore = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.publish('partial-restored',
    [{ topic: 'chat', payload: { message: 'continues the original signed feed' } }], 'browser-after-manifest-restore'))
  assert.equal(afterPartialRestore.outcome.outcome.type, 'accepted')
  assert.notEqual(afterPartialRestore.proposalId, published.proposalId)
  deviceEvidence.partialStorageLoss = { deleted: ['feed/manifest', 'browser/feed-initialized'], identityRetained: true, error: 'BROWSER_FEED_MANIFEST_MISSING',
    exactManifestRestored: true, originalRetryProposalId: partialRetry.proposalId, exactRetryAddedRecords: 0,
    nextPublication: afterPartialRestore.proposalId }
  passed('loss of both OPFS feed metadata files with surviving keys fails closed; verified restore retains original proposals and continues without position reuse')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologEventTest.close('partial-restored'))
  const nativeRecordsBeforeLoss = (await native.transport.history()).length
  await cdp.send('Storage.clearDataForOrigin', { origin, storageTypes: 'all' })
  await assert.rejects(page.evaluate(({ name, bootstrap }) => (globalThis as unknown as TestWindow).chronologEventTest.open('lost-device', name, bootstrap), { name, bootstrap }), /ENROLLMENT_IDENTITY_MISSING/u)
  const replacement = await page.evaluate((name) => (globalThis as unknown as TestWindow).chronologEventTest.prepare(`${name}-replacement`), name)
  assert.notEqual(replacement.identity, identity.identity)
  assert.notEqual(replacement.readerKey, identity.readerKey)
  assert.equal([...native.governed.activeSnapshot.capabilities.values()].some((entry) =>
    Buffer.from(entry.grant.signingPublicKey).toString('base64url') === replacement.identity), false)
  assert.equal((await native.transport.history()).length, nativeRecordsBeforeLoss)
  deviceEvidence.storageLoss = { error: 'ENROLLMENT_IDENTITY_MISSING', originalIdentity: identity.identity,
    replacementIdentity: replacement.identity, replacementHasNoInheritedGrants: true,
    preservedExternalOperationReference: 'browser-atomic-1', nativeHistoryUnchanged: true }
  passed('cleared OPFS fails closed instead of silently replacing identity; deliberate replacement has new keys and no inherited grants or original operation journal')
  await cdp.detach()
  native.assertHealthy()
  await save(true)
  process.stdout.write(`SQL-free browser qualification passed (${checks.length} checks), Chromium ${browser.version()}\n`)
} catch (error) {
  await save(false, error)
  throw error
} finally {
  clearTimeout(deadline)
  await context.close()
  await browser.close()
  await native?.close()
  server.closeAllConnections()
  await new Promise<void>((resolve) => server.close(() => resolve()))
  await rm(directory, { recursive: true, force: true })
}

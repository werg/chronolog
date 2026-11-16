import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { extname, join, resolve } from 'node:path'
import { once } from 'node:events'

import { chromium } from '@playwright/test'
import { build } from 'esbuild'
import { DeterministicMaterializer, createDoltLiteExecutionManifest } from '@chronolog/materializer-doltlite'
import { base64UrlToBytes, decodeTransactionCore, encodeExecutionManifest, transactionDigest } from '@chronolog/protocol'
import { verifyFeedRecord, webFeedCrypto } from '@chronolog/records'
import type { BrowserTestApi } from '../test/browser/page.js'

interface TestWindow { readonly chronologBrowserTest: BrowserTestApi }
interface Snapshot {
  readonly identity: string
  readonly hash: string
  readonly revision: string
  readonly finalRevision: string
  readonly records: string[]
  readonly transactions: Array<{ txId: string; canonical: string; sequence: string }>
}

const workspace = resolve(import.meta.dirname, '..')
const artifacts = resolve(process.env.CHRONOLOG_WASM_DIRECTORY ?? join(workspace, 'artifacts/wasm'))
const output = join(workspace, 'artifacts/browser-qualification')
await mkdir(output, { recursive: true })
// Explicit aliases also cover this monorepo's native-default tsconfig paths.
const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap((name) =>
  ['', '/browser'].map((suffix) => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
await build({
  absWorkingDir: workspace, entryPoints: { 'peer-worker': 'test/browser/peer-worker.ts', page: 'test/browser/page.ts' },
  outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias,
})
const executionManifest = createDoltLiteExecutionManifest()
const manifestBytes = encodeExecutionManifest(executionManifest)
const html = '<!doctype html><meta charset="utf-8"><title>Chronolog browser qualification</title><script type="module" src="/page.js"></script>'
const server = createServer((request, response) => {
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
  response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp')
  response.setHeader('Cache-Control', 'no-store')
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  if (path === '/') { response.setHeader('Content-Type', 'text/html'); response.end(html); return }
  if (path === '/execution-manifest.cbor') { response.setHeader('Content-Type', 'application/cbor'); response.end(manifestBytes); return }
  const allowed = new Map([
    ['/page.js', join(output, 'page.js')], ['/peer-worker.js', join(output, 'peer-worker.js')],
    ...['sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js', 'manifest.json'].map((name) => [`/engine/${name}`, join(artifacts, name)] as const),
  ])
  const file = allowed.get(path)
  if (file === undefined) { response.writeHead(404); response.end(); return }
  response.setHeader('Content-Type', extname(file) === '.wasm' ? 'application/wasm' : extname(file) === '.json' ? 'application/json' : 'application/javascript')
  void readFile(file).then((bytes) => response.end(bytes), () => { response.writeHead(500); response.end() })
})
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
if (address === null || typeof address === 'string') throw new Error('TEST_SERVER_ADDRESS_UNAVAILABLE')
const browser = await chromium.launch({
  headless: true,
  ...(process.env.CHRONOLOG_CHROMIUM_EXECUTABLE === undefined ? {} : { executablePath: process.env.CHRONOLOG_CHROMIUM_EXECUTABLE }),
})
const context = await browser.newContext()
const page = await context.newPage()
const overallDeadline = setTimeout(() => { void page.close() }, 120_000)
page.setDefaultTimeout(30_000)
page.on('console', (message) => { if (message.type() === 'error') process.stderr.write(`browser: ${message.text()}\n`) })
page.on('pageerror', (error) => process.stderr.write(`page error: ${error.message}\n`))
const nativeDirectory = await mkdtemp(join(tmpdir(), 'chronolog-browser-oracle-'))
let native: DeterministicMaterializer | undefined
const checks: string[] = []
const passed = (check: string): void => { checks.push(check); process.stdout.write(`Passed: ${check}\n`) }
const snapshot = async (id: string): Promise<Snapshot> => page.evaluate(async (id) =>
  (globalThis as unknown as TestWindow).chronologBrowserTest.state(id), id) as Promise<Snapshot>
const compare = async (state: Snapshot): Promise<void> => {
  native ??= await DeterministicMaterializer.open({ path: join(nativeDirectory, 'application.db'), executionManifest,
    rootAdministrator: base64UrlToBytes(state.identity), checkpointEvery: 1 })
  const transactions = await Promise.all(state.transactions.map(async (row) => {
    const canonicalCandidate = base64UrlToBytes(row.canonical)
    return { txId: base64UrlToBytes(row.txId), authorFeedSequence: BigInt(row.sequence), canonicalCandidate,
      candidateDigest: await transactionDigest(canonicalCandidate), core: decodeTransactionCore(canonicalCandidate) }
  }))
  await native.materialize(transactions)
  assert.equal(state.hash, native.databaseContentHash, 'real OPFS Worker and native content hashes differ')
  for (const record of state.records) await verifyFeedRecord(base64UrlToBytes(record), webFeedCrypto)
}

try {
  await page.goto(`http://127.0.0.1:${address.port}/`)
  await page.waitForFunction(() => 'chronologBrowserTest' in globalThis)
  const name = `qualification-${crypto.randomUUID()}`
  const initial = await page.evaluate(({ name }) => (globalThis as unknown as TestWindow).chronologBrowserTest.open('owner', name), { name })
  await assert.rejects(page.evaluate(({ name }) => (globalThis as unknown as TestWindow).chronologBrowserTest.open('contender', name), { name }), /BROWSER_STORAGE_IN_USE/u)
  passed('one effective Worker storage owner')
  const schema = [
    'CREATE TABLE notes (id INTEGER PRIMARY KEY, value TEXT NOT NULL, clock TEXT, noise BLOB)',
    "INSERT INTO notes(id,value,clock,noise) VALUES(1,'initial',datetime('now'),randomblob(12))",
  ]
  const transactionId = await page.evaluate(({ schema }) => (globalThis as unknown as TestWindow).chronologBrowserTest.submit('owner', schema, 'schema'), { schema })
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('owner', 'SELECT value FROM notes')), [['initial']])
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('owner', "UPDATE notes SET value='bad'")), /SQL|denied|write|profile|authoriz/iu)
  passed('shared ChronologClient submits signed encrypted records and reads local WASM SQL; local writes denied')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.advanceFinal('owner'))
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('owner', 'SELECT value FROM notes', { view: 'final' })), [['initial']])
  const mixed = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.change('owner', 'mixed', 'mixed-event'))
  assert.equal(mixed.outcome.outcome.type, 'accepted')
  assert.equal((await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.events('owner'))).transactions.length, 0)
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.advanceFinal('owner'))
  const mixedEvents = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.events('owner'))
  assert.equal(mixedEvents.transactions[0]?.proposalId, mixed.proposalId)
  const capturedRevision = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.capture('owner', 'mixed'))
  const rejected = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.change('owner', 'rollback', 'rejected-event', true))
  assert.equal(rejected.outcome.outcome.type, 'rejected')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.advanceFinal('owner'))
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('owner', 'SELECT value FROM notes')), [['mixed']])
  assert.deepEqual((await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.events('owner'))).transactions, mixedEvents.transactions)
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.change('owner', 'after-view', 'view-successor'))
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.advanceFinal('owner'))
  const held = await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.view('owner', 'mixed'))
  assert.deepEqual(held.rows, [['mixed']])
  assert.equal(held.events.revision, capturedRevision)
  assert.deepEqual(held.events.transactions, mixedEvents.transactions)
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.release('owner', 'mixed'))
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.view('owner', 'mixed')), /released/u)
  passed('real WASM mixed SQL/events commits atomically, rejected changes emit nothing, and one retained read view pins SQL plus events')
  const first = await snapshot('owner')
  await compare(first)
  passed('real final-prefix query and native/Worker deterministic state equality')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.stop('owner'))
  const reopened = await page.evaluate(({ name }) => (globalThis as unknown as TestWindow).chronologBrowserTest.open('reopened', name), { name })
  assert.deepEqual(reopened, initial)
  assert.equal((await snapshot('reopened')).hash, first.hash)
  assert.equal(await page.evaluate(({ schema }) => (globalThis as unknown as TestWindow).chronologBrowserTest.submit('reopened', schema, 'schema'), { schema }), transactionId)
  assert.equal((await snapshot('reopened')).records.length, first.records.length)
  passed('OPFS keys, signed records, control index, SQL and durable operation identity survive reopening')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.privateCutoff('reopened', '987654321'))
  await assert.rejects(page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.privateCutoff('reopened', '987654320')), /CUTOFF_REGRESSION/u)

  const preparedSteps = ["INSERT INTO notes(id,value) VALUES(2,'prepared')"]
  const prepared = await page.evaluate(({ steps }) => (globalThis as unknown as TestWindow).chronologBrowserTest.crash('reopened', steps, 'crash-prepared', 'prepared'), { steps: preparedSteps }) as { canonical: string }
  await page.evaluate(({ name }) => (globalThis as unknown as TestWindow).chronologBrowserTest.open('recovered', name), { name })
  await page.evaluate(({ steps }) => (globalThis as unknown as TestWindow).chronologBrowserTest.submit('recovered', steps, 'crash-prepared'), { steps: preparedSteps })
  const recovered = await snapshot('recovered')
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.privateCutoff('recovered')), ['987654321'])
  assert.equal(recovered.transactions.filter((row) => row.canonical === prepared.canonical).length, 1)
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('recovered', 'SELECT count(*) FROM notes WHERE id=2')), [[1n]])
  await compare(recovered)
  passed('termination after durable preparation recovers the original exact canonical transaction once')
  passed('private validator cutoff survives Worker termination without any reconstructing feed record')

  const applicationSteps = ["INSERT INTO notes(id,value) VALUES(3,'application')"]
  await page.evaluate(({ steps }) => (globalThis as unknown as TestWindow).chronologBrowserTest.crash('recovered', steps, 'crash-application', 'application'), { steps: applicationSteps })
  await page.evaluate(({ name }) => (globalThis as unknown as TestWindow).chronologBrowserTest.open('final', name), { name })
  await page.evaluate(({ steps }) => (globalThis as unknown as TestWindow).chronologBrowserTest.submit('final', steps, 'crash-application'), { steps: applicationSteps })
  assert.deepEqual(await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.query('final', 'SELECT count(*) FROM notes WHERE id=3')), [[1n]])
  await compare(await snapshot('final'))
  passed('termination after candidate SQL commit safely replays unpublished application state')
  await page.evaluate(() => (globalThis as unknown as TestWindow).chronologBrowserTest.stop('final'))
  const report = { passed: true, browser: browser.version(), checks, wasmManifest: JSON.parse(await readFile(join(artifacts, 'manifest.json'), 'utf8')) as unknown }
  await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n')
  process.stdout.write(`Browser qualification passed (${checks.length} checks), Chromium ${browser.version()}\n`)
} finally {
  clearTimeout(overallDeadline)
  native?.close()
  await context.close()
  await browser.close()
  server.close()
  await rm(nativeDirectory, { recursive: true, force: true })
}

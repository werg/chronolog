import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer, type IncomingMessage } from 'node:http'
import { tmpdir } from 'node:os'
import { extname, join, relative, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'

import type { AgentApplicationModule } from '@chronolog/agent-service'
import { OWNER_FOR_KEY_SQL, type TransactionHandle } from '@chronolog/client'
import { DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime } from '@chronolog/materializer-doltlite'
import { base64UrlToBytes, bytesToBase64Url, compareTransactionOrder, emit, program, sqlStatement, utf8, type EffectiveEvent, type EventBatch } from '@chronolog/protocol'
import { chromium, expect, type Browser, type Page } from '@playwright/test'
import { build } from 'esbuild'

import { createAgent } from '../examples/resident-agent.js'
import type { PilotBootstrap, PilotProgress, PilotRegistration, PilotWindow } from '../test/application-pilot/contract.js'
import { createNativeBrowserFixture, type NativeBrowserFixture } from './browser-event-fixture.js'
import { qualifyApplicationScope } from './lib/application-scope.js'
import { createPeerRouteFixture } from './lib/peer-route-fixture.js'
import { routeState } from '../test/application-pilot/route-state.js'
import { waitFor } from './lib/wait-for.js'
import { createAdmissionClock, observeIncludedProposals } from './lib/application-admission.js'

/** Real public runtime + independent OPFS replicas + native final-intent worker. */
const workspace = resolve(import.meta.dirname, '..')
const { values } = parseArgs({ options: {
  contrib: { type: 'string' }, 'tendriller-runtime': { type: 'string' }, wasm: { type: 'string' },
  output: { type: 'string' }, browser: { type: 'string' }, 'build-only': { type: 'boolean', default: false },
  'tendriller-engine': { type: 'string' },
} })
if (values.contrib === undefined || values['tendriller-runtime'] === undefined || !values['build-only'] && values['tendriller-engine'] === undefined) {
  throw new Error('Usage: application-pilot.ts --contrib /checkout --tendriller-runtime /packaged/runtime --tendriller-engine /packaged/engine [--wasm /engine] [--output /new/directory] [--browser /chromium] [--build-only]')
}
const contrib = resolve(values.contrib), runtime = resolve(values['tendriller-runtime'])
const wasm = resolve(values.wasm ?? process.env.CHRONOLOG_WASM_DIRECTORY ?? join(workspace, 'artifacts/wasm'))
const output = resolve(values.output ?? join(workspace, `artifacts/application-pilot/run-${Date.now()}`))
await mkdir(resolve(output, '..'), { recursive: true })
await mkdir(output) // Never mix an earlier run's assets or evidence into this run.
const deployment = join(output, 'deployment'), pages = join(output, 'pages')
await mkdir(deployment)
const report = { format: 'chronolog-application-pilot/v3', status: 'building', passed: false,
  startedAt: new Date().toISOString(), command: process.argv.slice(1), checks: [] as string[],
  revisions: { chronolog: gitState(workspace), contrib: gitState(contrib), tendrillerRuntime: gitState(runtime) },
  publicArtifacts: {} as Record<string, unknown>, counts: { effectDispatches: 0, hostApplicationRequests: 0, hostApplicationWrites: 0 },
  browser: '', pageErrors: [] as string[], timingsMs: {} as Record<string, number>, diagnostics: {} as Record<string, unknown>, error: '' }
const record = async () => writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n')
const passed = (check: string) => { report.checks.push(check); process.stdout.write(`Passed: ${check}\n`) }
let native: NativeBrowserFixture | undefined, browser: Browser | undefined, directory: string | undefined
const admission = createAdmissionClock()
report.diagnostics.admissionWindows = admission.windows
let readInclusions: ReturnType<typeof observeIncludedProposals> | undefined
const included = async (ids: readonly string[]) => {
  native!.assertHealthy()
  const observed = await readInclusions!()
  return ids.every(id => observed.has(id))
}
const authorWithAdmission = <T extends { readonly proposalId: string }>(scenario: string, author: () => Promise<T>) =>
  admission.include(scenario, async () => { const value = await author(); return { value, proposalIds: [value.proposalId] } }, included)
let routes: Awaited<ReturnType<typeof createPeerRouteFixture>> | undefined
let closeServer: (() => Promise<void>) | undefined
let deadline: ReturnType<typeof setTimeout> | undefined
const observedPages: Page[] = []
try {
  const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap(name =>
    ['', '/browser'].map(suffix => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
  alias['@chronolog/node-core/history'] = join(workspace, 'packages/node-core/src/history-policy.ts')
  alias['@chronolog/node-core/finality'] = join(workspace, 'packages/node-core/src/finality.ts')
  alias['@chronolog/node-core/ledger'] = join(workspace, 'packages/node-core/src/ledger-record.ts')
  alias['@chronolog/node-core/membership'] = join(workspace, 'packages/node-core/src/membership.ts')
  alias['@chronolog/transport-webrtc'] = join(workspace, 'packages/transport-webrtc/src/index.ts')
  const introductionRecipe = join(contrib, 'cookbooks/run-a-peer-application/snippets/introduce-peer-worker.mjs')
  const publicBundle = await build({ absWorkingDir: workspace, entryPoints: ['test/application-pilot/public.ts'],
    outfile: join(output, 'public-application.mjs'), bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias, metafile: true })
  const deploymentBundle = await build({ absWorkingDir: workspace,
    entryPoints: { bootstrap: 'test/application-pilot/bootstrap.ts', worker: 'test/application-pilot/worker.ts', 'introduce-peer-worker': introductionRecipe }, outdir: deployment,
    outExtension: { '.js': '.mjs' }, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', alias, metafile: true })
  // These are the packaged runtime's public assets, never sibling runtime source.
  await cp(join(runtime, 'assets'), join(deployment, 'tendriller'), { recursive: true, dereference: false })
  await mkdir(join(deployment, 'engine'))
  for (const name of ['sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js', 'manifest.json']) {
    await cp(join(wasm, name), join(deployment, 'engine', name), { dereference: false })
  }
  process.stdout.write(execFileSync(process.execPath, [join(contrib, 'cookbooks/run-a-peer-application/checks/build-pages.mjs'),
    '--public-module', join(output, 'public-application.mjs'), '--deployment', deployment, '--output', pages], { encoding: 'utf8' }))
  const packageMetadata: unknown = JSON.parse(await readFile(join(runtime, 'package.json'), 'utf8'))
  report.publicArtifacts = { runtimePackage: packageMetadata, kernelSha256: await sha256(join(runtime, 'assets/kernel.mjs')),
    peerIntroductionRecipeSha256: await sha256(introductionRecipe), peerIntroductionBundleSha256: await sha256(join(deployment, 'introduce-peer-worker.mjs')),
    wasmManifestSha256: await sha256(join(wasm, 'manifest.json')), wasmSha256: await sha256(join(wasm, 'sqlite3.wasm')),
    publicModuleSha256: await sha256(join(output, 'public-application.mjs')), scopeModuleSha256: await sha256(join(pages, 'scoped-state.mjs')), specimenManifestSha256: await sha256(join(pages, 'specimen-manifest.json')) }
  await writeFile(join(output, 'bundles.json'), JSON.stringify({ public: publicBundle.metafile, deployment: deploymentBundle.metafile }, null, 2) + '\n')
  passed('both contrib layouts compile from an explicit public application bundle, packaged Tendriller runtime and pinned WASM assets')
  if (values['build-only']) {
    report.status = 'built; browser scenarios not run'
    await record()
    process.stdout.write(`Built graph and provenance: ${output}\n`)
  } else {
    report.status = 'native scope reset qualification'
    report.diagnostics.scopeReset = await qualifyApplicationScope(join(pages, 'scoped-state.mjs'))
    passed('the built scope recipe rejects a durably queued stale edit after reset and preserves the original accepted retry without another write')
    report.status = 'browser launch'
    await record()
    const executable = values.browser ?? process.env.CHRONOLOG_CHROMIUM_EXECUTABLE
    browser = await chromium.launch({ headless: true, ...(executable === undefined ? {} : { executablePath: executable }) })
    report.browser = browser.version()
    directory = await mkdtemp(join(tmpdir(), 'chronolog-application-pilot-'))
    const nativeDirectory = directory
    const registrations = new Map<string, PilotRegistration>()
    let resolveBootstrap!: (value: PilotBootstrap) => void, rejectBootstrap!: (error: unknown) => void
    const bootstrapped = new Promise<PilotBootstrap>((resolve, reject) => { resolveBootstrap = resolve; rejectBootstrap = reject })
    void bootstrapped.catch(() => undefined)
    let starting = false
    const application: AgentApplicationModule = { createAgent(context) {
      const app = createAgent(context)
      return { ...app, effects: (app.effects ?? []).map(effect => ({ ...effect, handler: { ...effect.handler,
        async dispatch(input) { report.counts.effectDispatches++; return effect.handler.dispatch(input) },
      } })) }
    } }
    const startNative = async (): Promise<PilotBootstrap> => {
      const executionManifest = createDoltLiteExecutionManifest()
      native = await createNativeBrowserFixture({ directory: nativeDirectory, browsers: [...registrations.values()].map(value => value.identity),
        manifest: executionManifest, application, finalityClock: admission.now,
        materialization: async ({ identity }) => createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({
          path: join(nativeDirectory, 'application.db'), executionManifest, rootAdministrator: identity.signing.publicKeyBytes,
        })) })
      readInclusions = observeIncludedProposals(native)
      await accepted(await native.client.submit(program(sqlStatement("CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT NOT NULL, claimed_by TEXT, status TEXT NOT NULL CHECK(status IN ('open','done'))) STRICT")), { operationId: 'pilot-schema' }))
      const team = await native.client.ownership.createTeam({ invite: [...registrations.values()].map(value => base64UrlToBytes(value.identity.identity)) }, { operationId: 'pilot-team' })
      await accepted(team.handle)
      await accepted(await native.client.submit(program(sqlStatement(`INSERT INTO tasks (id, title, claimed_by, status, chronolog_owner) VALUES (?, ?, NULL, 'open', ${OWNER_FOR_KEY_SQL})`,
        ['task-1', 'Review the shared inspection evidence', team.id])), { operationId: 'pilot-task' }))
      routes = await createPeerRouteFixture({ native, directory: join(nativeDirectory, 'routes'), engine: resolve(values['tendriller-engine']!) })
      const { peerUrl: _httpFixtureUrl, peerToken: _httpFixtureToken, ...peer } = native.bootstrap
      return { peer, hostBase: routes.hostBase, teamId: bytesToBase64Url(team.id), applicationId: `inspection-${bytesToBase64Url(native.node.groupId)}` }
    }
    const files = await staticFiles(pages)
    const server = createServer((request, response) => {
      response.setHeader('Cross-Origin-Opener-Policy', 'same-origin')
      response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp')
      response.setHeader('Cache-Control', 'no-store')
      response.setHeader('X-Content-Type-Options', 'nosniff')
      const run = async () => {
        const path = new URL(request.url ?? '/', 'http://localhost').pathname
        if (path === '/pilot/registered' && request.method === 'GET') {
          const device = new URL(request.url!, 'http://localhost').searchParams.get('device')
          response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify({ registered: device !== null && registrations.has(device) })); return
        }
        if (path === '/pilot/register' && request.method === 'POST') {
          const registration = validateRegistration(await jsonBody(request))
          const prior = registrations.get(registration.device)
          if (prior !== undefined && JSON.stringify(prior) !== JSON.stringify(registration)) throw new Error('PILOT_DEVICE_IDENTITY_CHANGED')
          registrations.set(registration.device, registration)
          if (registrations.size === 2 && !starting) { starting = true; void startNative().then(resolveBootstrap, rejectBootstrap) }
          const bootstrap = await bootstrapped
          response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(bootstrap)); return
        }
        if (path.startsWith('/host/')) {
          report.counts.hostApplicationRequests++
          if (request.method !== 'GET' && request.method !== 'HEAD') report.counts.hostApplicationWrites++
          response.writeHead(503); response.end('Host application persistence is offline'); return
        }
        const file = files.get(path)
        if (file === undefined || request.method !== 'GET') { response.writeHead(404); response.end(); return }
        response.setHeader('Content-Type', mime(file))
        response.end(await readFile(file))
      }
      void run().catch((error: unknown) => {
        rejectBootstrap(error)
        response.writeHead(500, { 'Content-Type': 'text/plain' }); response.end(error instanceof Error ? error.message : String(error))
      })
    })
    server.listen(0, '127.0.0.1')
    await once(server, 'listening')
    closeServer = async () => { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error === undefined ? resolve() : reject(error))) }
    const address = server.address()
    if (address === null || typeof address === 'string') throw new Error('PILOT_SERVER_ADDRESS_UNAVAILABLE')
    const base = `http://127.0.0.1:${address.port}`
    const contexts = await Promise.all([browser.newContext({ viewport: { width: 1365, height: 1000 }, ignoreHTTPSErrors: true }),
      browser.newContext({ viewport: { width: 430, height: 932 }, ignoreHTTPSErrors: true })])
    const [board, compact] = await Promise.all(contexts.map(context => context.newPage())) as [Page, Page]
    const all = [board, compact]
    observedPages.push(...all)
    for (const page of all) {
      page.setDefaultTimeout(40_000)
      page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/host/') && !request.url().includes('/peers/rendezvous?')) report.counts.hostApplicationRequests++ })
      page.on('websocket', socket => { if (new URL(socket.url()).pathname.startsWith('/host/') && !socket.url().includes('/peers/rendezvous?')) report.counts.hostApplicationRequests++ })
      page.on('pageerror', error => { report.pageErrors.push(error.message); process.stderr.write(`pilot browser: ${error.message}\n`) })
    }
    deadline = setTimeout(() => { void browser?.close() }, 240_000)
    report.status = 'real browser scenarios'
    const coldStart = performance.now()
    await Promise.all([board.goto(`${base}/board.html?device=board`), compact.goto(`${base}/compact.html?device=compact`)])
    await Promise.all(all.map(ready))
    report.timingsMs.coldBootstrap = performance.now() - coldStart
    assert(native !== undefined && routes !== undefined)
    const identities = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.identity)))
    assert.notEqual(identities[0], identities[1])
    await Promise.all(all.map(page => expect(page.locator('#tasks [data-task="task-1"] h3')).toHaveText('Review the shared inspection evidence')))
    assert.equal(report.counts.hostApplicationWrites, 0)
    assert.equal(report.counts.hostApplicationRequests + routes.snapshot().unexpectedHostRequests, 0)
    passed('independent browser identities and OPFS replicas render one shared team-owned task through the actual selected Tendriller backend')

    const beforeTyping = (await native.client.events.read()).transactions
    await board.locator('#message').fill('Typing only; not submitted')
    await expect(compact.locator('#typing')).toHaveText('Someone is typing…')
    await expect(compact.locator('#typing')).toBeEmpty({ timeout: 8_000 })
    assert.deepEqual((await native.client.events.read()).transactions, beforeTyping)
    passed('typing traverses authenticated ephemeral frames, expires and leaves no durable event')

    // Keep the timestamp window open while deliberately disconnected clients
    // prepare their conflicting writes. An ordinary offline write arriving
    // after its timestamp has closed must instead be finally rejected.
    const claimIds = await admission.include('disconnected competing task claims', async () => {
      await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.disconnect())))
      await Promise.all(all.map(page => page.locator('#tasks [data-action="claim"]').click()))
      await Promise.all(all.map(page => page.waitForFunction(() => {
        const row = document.querySelector('#operations li'); return row !== null && row.getAttribute('data-status') !== 'unknown'
      })))
      const ids = await Promise.all(all.map(page => page.locator('#operations > li').first().getAttribute('data-operation')))
      assert(ids.every(id => id !== null))
      const proposals = await Promise.all(all.map((page, index) => authoredOperation(page, ids[index]!)))
      await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.reconnect())))
      return { value: ids, proposalIds: proposals.map(value => value.proposalId) }
    }, included)
    const claimWindow = admission.windows.at(-1)!
    report.diagnostics.concurrentClaims = { clock: 'native finality clock held only through disconnected authoring and inclusion of both claims',
      heldAtMs: claimWindow.heldAtMs, heldForMs: claimWindow.heldForMs, proposalTimestamps: 'unchanged browser clocks',
      arbitraryOfflineAdmissionClaim: false }
    await Promise.all(all.map((page, index) => page.waitForFunction(id => {
      const row = document.querySelector(`[data-operation="${id}"]`); return row?.getAttribute('data-status') === 'final'
    }, claimIds[index]!)))
    const claimStates = await Promise.all(all.map((page, index) => page.evaluate(id => (globalThis as unknown as PilotWindow).applicationPilot.operation(id), claimIds[index]!)))
    assert.deepEqual(claimStates.map(state => state?.status), ['final', 'final'])
    assert.deepEqual(claimStates.map(state => state?.outcome).sort(), ['accepted', 'rejected'])
    assert.equal(claimStates.find(state => state?.outcome === 'rejected')?.error, 'assert:task_unavailable')
    await native.node.waitForIdle()
    const claimOrder = claimStates.map((state, index) => {
      assert(state?.proposalId !== undefined)
      const candidate = native!.node.candidate(utf8(state.proposalId))
      assert(candidate !== null)
      return { index, orderKey: candidate.orderKey }
    }).sort((left, right) => compareTransactionOrder(left.orderKey, right.orderKey))
    assert.equal(claimStates[claimOrder[0]!.index]?.outcome, 'accepted', 'the earlier deterministic author-time key must win the SQL conflict')
    const winner = all[claimStates[0]?.outcome === 'accepted' ? 0 : 1]!
    const loser = all[claimStates[0]?.outcome === 'accepted' ? 1 : 0]!
    await Promise.all(all.map(page => expect(page.locator('#tasks [data-action="claim"]')).toBeDisabled()))
    assert.equal(await board.locator('#tasks .task > p').textContent(), await compact.locator('#tasks .task > p').textContent())
    passed('with the finality clock held through inclusion, disconnected competing claims resolve by deterministic author order to one acceptance and one SQL rejection')

    const rejectedJobStarted = Date.now()
    const rejectedJob = await authorWithAdmission('losing claimant job SQL guard', () =>
      submitUiOperation(loser, () => loser.locator('#tasks [data-action="job"]').click()))
    const rejectedJobId = rejectedJob.operationId
    // Rejected proposals produce no durable event. Observe their public
    // operation frontier before applying the renderer's short DOM deadline.
    await waitFor(async () => {
      const operation = await loser.evaluate(id => (globalThis as unknown as PilotWindow).applicationPilot.operation(id), rejectedJobId)
      if (operation?.status === 'final') {
        assert.equal(operation.outcome, 'rejected'); assert.equal(operation.error, 'assert:claim_required')
      }
      return operation?.status === 'final'
    }, 'losing claimant final job rejection')
    report.timingsMs.browserRejectedJob = Date.now() - rejectedJobStarted
    await expect(loser.locator(`#operations > li[data-operation="${rejectedJobId}"]`)).toHaveAttribute('data-status', 'final')
    await expect(loser.locator(`#operations > li[data-operation="${rejectedJobId}"]`)).toHaveAttribute('data-outcome', 'rejected')
    assert.equal(report.counts.effectDispatches, 0)
    const jobStarted = Date.now()
    const winningJob = await authorWithAdmission('winning claimant native job intent', () =>
      submitUiOperation(winner, () => winner.locator('#tasks [data-action="job"]').click()))
    // Native execution and each real WASM replica have separate applied
    // frontiers. Observe those before testing the UI renderer's short deadline.
    // In the first CI run the preceding two claims needed 8s to apply, while
    // Playwright's default DOM expectation allowed only 5s for two more writes.
    let resultEvent: EffectiveEvent | undefined
    await waitFor(async () => {
      native!.assertHealthy()
      assertNotFinallyRejected(winningJob.proposalId)
      resultEvent = (await native!.client.events.read()).transactions.flatMap(transaction => transaction.events).find(event => event.topic === 'job-results')
      return resultEvent !== undefined
    }, 'native final worker result')
    report.timingsMs.nativeWorkerResult = Date.now() - jobStarted
    assert(resultEvent !== undefined)
    const resultProposalId = resultEvent.proposalId
    await Promise.all(all.map(async (page, index) => {
      await browserHasProposal(page, resultProposalId)
      report.timingsMs[`browser${index}WorkerResult`] = Date.now() - jobStarted
    }))
    await Promise.all(all.map(page => expect(page.locator('#jobs')).toContainText('completed · task-1')))
    assert.equal(report.counts.effectDispatches, 1)
    await assert.rejects(board.evaluate(async () => (globalThis as unknown as PilotWindow).tendril.application.backend.events.publish('job-results',
      { type: 'forged-result', version: 1 }, { operationId: 'forged-pilot-result' })), /authoriz|capabilit|scope|permission|PROGRAM|cannot write/iu)
    passed('a failed SQL guard emits no intent; the final winning intent runs the native worker once and records a correlated result that browser scope cannot forge')

    const delayed = await authorWithAdmission('delayed durable reply', async () => {
      await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.holdNextSubmission())
      await board.locator('#message').fill('A note whose append reply is delayed')
      await board.locator('#send').click()
      await board.waitForFunction(() => (globalThis as unknown as PilotWindow).applicationPilot.heldSubmission() !== null)
      const receipt = await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.heldSubmission())
      assert(receipt !== null)
      return receipt
    })
    await Promise.all(all.map(page => browserHasProposal(page, delayed.proposalId)))
    await expect(compact.locator('#conversation')).toContainText('A note whose append reply is delayed')
    await expect(board.locator(`#operations > li[data-operation="${delayed.operationId}"]`)).toHaveAttribute('data-status', 'final')
    await board.locator('#message').fill('Newer unsent text must survive')
    await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.releaseSubmission())
    await expect(board.locator('#send')).toBeEnabled()
    await expect(board.locator('#message')).toHaveValue('Newer unsent text must survive')
    await expect(board.locator(`#operations > li[data-operation="${delayed.operationId}"]`)).toHaveAttribute('data-status', 'final')
    passed('a delayed durable append reply preserves newer typing and cannot regress the already observed final receipt')

    const interrupted = await authorWithAdmission('abrupt reload before reply delivery', async () => {
      await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.holdNextSubmission())
      await board.locator('#message').fill('One original intent across abrupt reload')
      await board.locator('#send').click()
      await board.waitForFunction(() => (globalThis as unknown as PilotWindow).applicationPilot.heldSubmission() !== null)
      const receipt = await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.heldSubmission())
      assert(receipt !== null)
      return receipt
    })
    await board.reload()
    await ready(board)
    assert.equal(await board.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.identity), identities[0])
    await Promise.all(all.map(page => browserHasProposal(page, interrupted.proposalId)))
    await expect(board.locator(`#operations > li[data-operation="${interrupted.operationId}"]`)).toHaveAttribute('data-status', 'final')
    const recovered = await board.evaluate(id => (globalThis as unknown as PilotWindow).applicationPilot.operation(id), interrupted.operationId)
    assert.equal(recovered?.proposalId, interrupted.proposalId)
    await expect(compact.locator('#conversation')).toContainText('One original intent across abrupt reload')
    await expect(board.locator('#message')).toHaveValue('One original intent across abrupt reload')
    const events = (await native.client.events.read()).transactions.flatMap(transaction => transaction.events)
    assert.equal(events.filter(event => event.proposalId === interrupted.proposalId).length, 1)
    assert.equal(events.filter(event => event.topic === 'conversation').length, 2)
    passed('Worker termination before reply delivery reopens durable identity and original operation; one message survives with its saved draft and original proposal ID')

    await compact.reload(); await ready(compact)
    await Promise.all(all.map(page => page.locator('#refresh').click()))
    await Promise.all(all.map(page => expect(page.locator('#jobs')).toContainText('completed · task-1')))
    assert.equal(report.counts.effectDispatches, 1)
    assert.equal(report.counts.hostApplicationWrites, 0)
    assert.deepEqual(report.pageErrors, [])
    for (const page of all) assert.deepEqual(await page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.connectionErrors), [])
    native.assertHealthy()
    assertResultOrigins(events)
    await Promise.all([board.screenshot({ path: join(output, 'board.png'), fullPage: true }), compact.screenshot({ path: join(output, 'compact.png'), fullPage: true })])
    passed('both layouts rebuild from retained final events without redispatching the worker or writing host application state')
    {
      const beforeRoutes = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.events())))
      assert.deepEqual(sharedHistory(beforeRoutes[0]!), sharedHistory(beforeRoutes[1]!), 'both RTC replicas must expose the identical final history')
      const authoredIds = [[claimIds[0]!, delayed.operationId, interrupted.operationId], [claimIds[1]!]]
      const capturedOutcomes = await Promise.all(all.map((page, index) => page.evaluate(async ids => Promise.all(ids.map(id =>
        (globalThis as unknown as PilotWindow).applicationPilot.operation(id))), authoredIds[index]!)))
      assert(capturedOutcomes.every(outcomes => outcomes.every(outcome => outcome !== null)))
      await waitFor(async () => routes!.snapshot().signaling.activeSockets === 0, 'every bounded introduction socket closes after SDP exchange')
      assert(routes.snapshot().sessions.every(session => session.nativeSignaling?.closed === true))
      passed('independent replicas receive identical task/chat final events over WebRTC after every host introduction socket has closed')

      await routes.disableRendezvous()
      const signalingBefore = { host: routes.snapshot().signaling,
        browsers: await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.signalingStats()))) }
      const bytesBefore = routes.snapshot().sessions.reduce((total, session) => total + session.sentBytes + session.receivedBytes, 0)
      const warm = await authorWithAdmission('chat while the host listener is stopped', () => submitUiOperation(board, async () => {
        await board.locator('#message').fill('Warm WebRTC session with the host unavailable')
        await board.locator('#send').click()
      }))
      await expect(compact.locator('#conversation')).toContainText('Warm WebRTC session with the host unavailable', { timeout: 40_000 })
      const warmHistory = await native.client.events.read()
      const warmProposal = warmHistory.transactions.find(transaction => transaction.events.some(event =>
        JSON.stringify(event.payload).includes('Warm WebRTC session with the host unavailable')))?.proposalId
      assert(warmProposal !== undefined)
      assert.equal(warmProposal, warm.proposalId)
      await Promise.all(all.map(page => browserHasProposal(page, warmProposal)))
      const signalingAfter = { host: routes.snapshot().signaling,
        browsers: await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.signalingStats()))) }
      const bytesAfter = routes.snapshot().sessions.reduce((total, session) => total + session.sentBytes + session.receivedBytes, 0)
      assert.deepEqual(signalingAfter, signalingBefore, 'application progress must not send any additional signaling')
      assert(bytesAfter > bytesBefore, 'application progress must cross the established RTC channels')
      assert.equal(report.counts.hostApplicationRequests + routes.snapshot().unexpectedHostRequests, 0)
      assert.equal(report.counts.hostApplicationWrites, 0)
      passed('warm authenticated WebRTC sessions finalize new chat while the host listener is stopped, with increasing RTC bytes and exactly zero host requests or signaling growth')

      await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.disconnect())))
      await routes.enableRendezvous()
      const catchUp = await native.client.events.publish('conversation', { type: 'message.posted', version: 1, messageId: 'route-catchup-message', text: 'History added during a route interruption' }, { operationId: 'route-catchup-message' })
      await accepted(catchUp)
      // Keep four large proposals while respecting the public 16 KiB event
      // payload cap: each atomic program carries sixteen 12 KiB event bodies.
      const eventBodySize = 12 * 1024, eventsPerProposal = 16, bodyCount = 4
      const bodySize = eventBodySize * eventsPerProposal
      for (let i = 0; i < bodyCount; i++) await accepted(await native.client.submit(program(
        ...Array.from({ length: eventsPerProposal }, (_, chunk) => emit('route-benchmark',
          { sample: i, chunk, body: 'x'.repeat(eventBodySize) })),
      ), { operationId: `route-catchup-body-${i}` }))
      const resumeStarted = performance.now()
      await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.reconnect())))
      report.timingsMs.routeReconnectAttachment = performance.now() - resumeStarted
      const finalNative = await native.client.events.read()
      assert.equal(finalNative.hasMore, false, 'route benchmark must compare the complete final event history')
      const lastProposal = finalNative.transactions.at(-1)!.proposalId
      // A healthy authenticated channel must stay open while SQL/WASM applies
      // history. Observe cheap committed frontiers, not a sync call queued behind
      // the materialization mutex under the connection command's short deadline.
      const replay = { target: { records: (await native.transport.status()).records, finalOrderLength: native.node.finalOrderLength },
        latest: [] as PilotProgress[], elapsedMs: 0 }
      report.diagnostics.routeReplay = replay
      await waitFor(async () => {
        native!.assertHealthy()
        replay.latest = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.progress())))
        replay.elapsedMs = performance.now() - resumeStarted
        for (const state of replay.latest) {
          assert(state.connected, `RTC disconnected during durable replay: ${JSON.stringify(state)}`)
          assert.equal(state.error, undefined, `Replica ingestion failed: ${JSON.stringify(state)}`)
          assert.equal(state.transportError, undefined, `Replica replication failed: ${JSON.stringify(state)}`)
        }
        return replay.latest.every(state => state.records >= replay.target.records && state.processedRecords >= replay.target.records &&
          state.finalOrderLength >= replay.target.finalOrderLength && !state.materializationPending)
      }, 'both replicas apply the complete large reconnect history', 120_000)
      await Promise.all(all.map(page => browserHasProposal(page, lastProposal)))
      report.timingsMs.routeReconnectCatchUp = performance.now() - resumeStarted
      const finalViews = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.events())))
      assert(finalViews.every(view => !view.hasMore), 'both browser histories must include every benchmark proposal')
      assert.deepEqual(sharedHistory(finalViews[0]!), sharedHistory(finalViews[1]!))
      assert.deepEqual(sharedHistory(finalViews[0]!), sharedHistory(finalNative))
      const finalOperations = await Promise.all(all.map((page, index) => page.evaluate(async ids => Promise.all(ids.map(id =>
        (globalThis as unknown as PilotWindow).applicationPilot.operation(id))), authoredIds[index]!)))
      assert.deepEqual(finalOperations, capturedOutcomes, 'a fresh RTC connection cannot change original operation outcomes')
      const replicaStates = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.routeState())))
      const nativeState = await routeState(native.transport, native.governed.activeSnapshot, native.node.finalOrderLength)
      assert.deepEqual(replicaStates[0], nativeState)
      assert.deepEqual(replicaStates[1], nativeState)
      const routeStats = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.routeStats())))
      const browserSignaling = await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.signalingStats())))
      assert(browserSignaling.flat().every(session => session.sentMessages === 1 && session.receivedMessages === 1))
      await waitFor(async () => routes!.snapshot().signaling.activeSockets === 0, 'fresh introductions retire their signaling sockets before final evidence')
      const memory = await Promise.all(all.map(async page => {
        const session = await page.context().newCDPSession(page)
        try { await session.send('Performance.enable'); return await session.send('Performance.getMetrics') }
        finally { await session.detach() }
      }))
      report.diagnostics.routes = { ...routes.snapshot(), browserSessions: routeStats, browserSignaling, pagePerformanceMetrics: memory, replicaStates, nativeState,
        originalOperations: { before: capturedOutcomes, after: finalOperations },
        hostOutage: { signalingBefore, signalingAfter, rtcBytesBefore: bytesBefore, rtcBytesAfter: bytesAfter,
          hostApplicationRequests: report.counts.hostApplicationRequests + routes.snapshot().unexpectedHostRequests },
        catchUp: { applicationStringBytes: bodySize * bodyCount, eventsPerProposal, eventBodyBytes: eventBodySize, elapsedMs: report.timingsMs.routeReconnectCatchUp,
          applicationBytesPerSecond: bodySize * bodyCount * 1000 / report.timingsMs.routeReconnectCatchUp },
        nativeHarnessPeakRssBytes: process.resourceUsage().maxRSS * 1024, finalEventDigest: createHash('sha256').update(JSON.stringify(sharedHistory(finalNative))).digest('hex'),
        notes: ['Page JS heap snapshots exclude Worker/WASM memory; native peak RSS includes this qualification harness and excludes workerd/browser child processes.',
          'RTC uses loopback UDP; signaling uses loopback TLS and synthetic host accounts. Production identity-provider login, public Internet NAT and optional TURN remain outside this gate.'] }
      await routes.saveTrace(join(output, 'route-trace.ndjson'))
      assert.deepEqual(routes.snapshot().failures, [])
      assert.equal(report.counts.hostApplicationRequests + routes.snapshot().unexpectedHostRequests, 0)
      assert(routes.snapshot().sessions.every(session => session.sampledPeakQueuedBytes <= 2 * 4 * 1024 * 1024))
      passed('fresh RTC introduction recovers the same signed history and exact outcomes after interruption, including four 192 KiB programs of sixteen 12 KiB events, with measured bytes and bounded queues')
    }
    await Promise.all(all.map(page => page.evaluate(() => (globalThis as unknown as PilotWindow).applicationPilot.close())))
    report.status = 'passed'; report.passed = true
    await record()
    // The exact public checkout supplies both the application and its evidence
    // contract. Save observations before checking that contract so a rejected
    // report still leaves the original runtime evidence available to inspect.
    const { validateApplicationReport } = await import(pathToFileURL(join(contrib,
      'cookbooks/run-a-peer-application/checks/application-report.mjs')).href) as {
        validateApplicationReport: (observations: unknown) => unknown
      }
    validateApplicationReport(report)
    process.stdout.write(`Application pilot evidence: ${output}\n`)
  }
} catch (error) {
  report.passed = false
  report.error = error instanceof Error ? error.stack ?? error.message : String(error)
  report.status = `failed during ${report.status}`
  const observations = await Promise.allSettled(observedPages.map(async (page, index) => {
    const observation = await bounded(page.evaluate(async () => {
      const target = globalThis as unknown as PilotWindow
      const ui = Object.fromEntries(['status', 'revision', 'jobs', 'operations', 'typing'].map(id => [id, document.getElementById(id)?.textContent]))
      const operationIds = Array.from(document.querySelectorAll('#operations > li')).map(row => row.getAttribute('data-operation')).filter((id): id is string => id !== null)
      const outcomes = await Promise.allSettled(operationIds.map(id => target.applicationPilot.operation(id)))
      const events = await target.applicationPilot.events()
      return { url: location.href, ui, failure: document.getElementById('status')?.getAttribute('data-failure'), outcomes, events,
        connectionErrors: target.applicationPilot.connectionErrors }
    }), 5_000)
    await page.screenshot({ path: join(output, `failure-${index}.png`), fullPage: true }).catch(() => undefined)
    return observation
  }))
  report.diagnostics.pages = observations.map(value => value.status === 'fulfilled' ? value.value : String(value.reason))
  if (native !== undefined) {
    report.diagnostics.nativeAgent = native.agent.status
    report.diagnostics.nativeRevision = native.node.revision.toString()
    report.diagnostics.nativeFinalEvents = await bounded(native.client.events.read(), 5_000).catch((error: unknown) => String(error))
  }
  if (routes !== undefined) { report.diagnostics.routes ??= routes.snapshot(); await routes.saveTrace(join(output, 'route-trace.ndjson')) }
  await record()
  // Preserve complete event evidence in report.json without burying the actual
  // failure beneath 768 KiB of repeated benchmark payloads in the CI log.
  process.stderr.write(`Pilot diagnostics: ${JSON.stringify(report.diagnostics, (key, value: unknown) =>
    key === 'body' && typeof value === 'string' && value.length > 1024 ? `[${value.length} benchmark characters; retained in report.json]` : value)}\n`)
  throw error
} finally {
  if (deadline !== undefined) clearTimeout(deadline)
  await browser?.close()
  await routes?.close()
  await native?.close()
  await closeServer?.()
  if (directory !== undefined) await rm(directory, { recursive: true, force: true })
}

function gitState(directory: string) {
  try { return { head: execFileSync('git', ['-C', directory, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    dirty: execFileSync('git', ['-C', directory, 'status', '--porcelain'], { encoding: 'utf8' }).trim().length !== 0 } }
  catch { return { head: 'not-a-git-checkout', dirty: true } }
}
async function sha256(file: string) { return createHash('sha256').update(await readFile(file)).digest('hex') }
function sharedHistory(batch: EventBatch) {
  // A replica's local publication revision is intentionally not a shared hash.
  return { transactions: batch.transactions, scannedThrough: batch.scannedThrough, hasMore: batch.hasMore }
}
async function accepted(handle: TransactionHandle) {
  try { assert.equal((await handle.final({ signal: AbortSignal.timeout(30_000) })).outcome.type, 'accepted') }
  finally { handle.dispose() }
}
async function ready(page: Page) {
  await page.waitForFunction(() => 'applicationPilot' in globalThis)
  await expect(page.locator('#message')).toBeEnabled()
  await expect(page.locator('#status')).toHaveAttribute('data-failure', 'false')
}
async function browserHasProposal(page: Page, proposalId: string) {
  await waitFor(async () => {
    assertNotFinallyRejected(proposalId)
    return page.evaluate(async id => {
      const events = await (globalThis as unknown as PilotWindow).applicationPilot.events()
      return events.transactions.some(transaction => transaction.proposalId === id)
    }, proposalId)
  }, `browser final proposal ${proposalId}`)
}
function assertNotFinallyRejected(proposalId: string): void {
  const id = utf8(proposalId), outcome = native!.node.outcome(id)
  if (native!.node.isFinal(id) && outcome?.outcome === 'rejected') {
    throw new Error(`PILOT_FINAL_PROPOSAL_REJECTED: ${proposalId}: ${outcome.rejectionCode}`)
  }
}
async function authoredOperation(page: Page, operationId: string): Promise<{ operationId: string; proposalId: string }> {
  let receipt: { operationId: string; proposalId: string } | null = null
  await waitFor(async () => {
    receipt = await page.evaluate(id => (globalThis as unknown as PilotWindow).applicationPilot.operation(id), operationId)
    return receipt !== null
  }, `durably authored operation ${operationId}`, 25_000)
  assert(receipt !== null)
  return receipt
}
async function submitUiOperation(page: Page, submit: () => Promise<unknown>): Promise<{ operationId: string; proposalId: string }> {
  const previous = await page.locator('#operations > li').first().getAttribute('data-operation')
  await submit()
  await page.waitForFunction(before => {
    const current = document.querySelector('#operations > li')?.getAttribute('data-operation')
    return current !== null && current !== undefined && current !== before
  }, previous)
  const operationId = await page.locator('#operations > li').first().getAttribute('data-operation')
  assert(operationId !== null)
  return authoredOperation(page, operationId)
}
async function bounded<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try { return await Promise.race([promise, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('PILOT_DIAGNOSTIC_TIMEOUT')), timeoutMs) })]) }
  finally { if (timer !== undefined) clearTimeout(timer) }
}
async function jsonBody(request: IncomingMessage): Promise<unknown> {
  let bytes = 0
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    const next = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array)
    bytes += next.length
    if (bytes > 4096) throw new Error('PILOT_REGISTRATION_TOO_LARGE')
    chunks.push(next)
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown
}
function validateRegistration(value: unknown): PilotRegistration {
  if (typeof value !== 'object' || value === null || !('device' in value) || !['board', 'compact'].includes(String(value.device)) ||
    !('identity' in value) || typeof value.identity !== 'object' || value.identity === null) throw new Error('PILOT_REGISTRATION_INVALID')
  const identity = value.identity
  if (!('identity' in identity) || typeof identity.identity !== 'string' || base64UrlToBytes(identity.identity).length !== 32 ||
    !('readerKey' in identity) || typeof identity.readerKey !== 'string' || base64UrlToBytes(identity.readerKey).length !== 32 ||
    !('transportAuthor' in identity) || typeof identity.transportAuthor !== 'string' || identity.transportAuthor.length > 128) throw new Error('PILOT_REGISTRATION_INVALID')
  return { device: String(value.device), identity: { identity: identity.identity, readerKey: identity.readerKey, transportAuthor: identity.transportAuthor } }
}
async function staticFiles(directory: string, root = directory): Promise<Map<string, string>> {
  const files = new Map<string, string>()
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    assert(!entry.isSymbolicLink(), 'Pilot publication cannot follow a symlink')
    const path = join(directory, entry.name)
    if (entry.isDirectory()) for (const [name, file] of await staticFiles(path, root)) files.set(name, file)
    else files.set(`/${relative(root, path).replaceAll('\\', '/')}`, path)
  }
  return files
}
function mime(file: string) {
  return ({ '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.mjs': 'application/javascript', '.js': 'application/javascript',
    '.json': 'application/json', '.wasm': 'application/wasm', '.png': 'image/png', '.svg': 'image/svg+xml' } as Record<string, string>)[extname(file)] ?? 'application/octet-stream'
}
function assertResultOrigins(events: readonly EffectiveEvent[]) {
  const requests = new Set(events.filter(event => event.topic === 'job-requests').map(event => event.id))
  const results = events.filter(event => event.topic === 'job-results')
  assert.equal(requests.size, 1); assert.equal(results.length, 1)
  const payload = results[0]!.payload
  assert(payload !== null && typeof payload === 'object' && 'originEventId' in payload && typeof payload.originEventId === 'string')
  assert(requests.has(payload.originEventId))
}

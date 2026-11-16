import { spawn, execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { chromium, type Browser, type Page } from '@playwright/test'
import { build } from 'esbuild'
import { bytesToBase64Url } from '@chronolog/protocol'

import { createThinMembershipNative, type ThinMembershipBootstrap } from './thin-membership-native.js'

type NativeFixture = Awaited<ReturnType<typeof createThinMembershipNative>>

const workspace = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { values } = parseArgs({ options: {
  'tendriller-artifacts': { type: 'string' }, wasm: { type: 'string' }, output: { type: 'string' },
  browser: { type: 'string' }, 'build-only': { type: 'boolean', default: false },
} })
if (values['tendriller-artifacts'] === undefined) throw new Error('Usage: thin-membership-pilot.ts --tendriller-artifacts /public/dist --wasm /engine --output /new/evidence [--browser /chromium] [--build-only]')
const artifacts = resolve(values['tendriller-artifacts'])
const wasm = resolve(values.wasm ?? process.env.CHRONOLOG_WASM_DIRECTORY ?? join(workspace, 'artifacts/wasm'))
const output = resolve(values.output ?? join(workspace, `artifacts/thin-membership/run-${Date.now()}`))
await mkdir(dirname(output), { recursive: true }); await mkdir(output)
const host = join(output, 'host'), assets = join(output, 'browser')
await mkdir(host); await mkdir(assets)
const report = { format: 'chronolog-thin-membership/v2', passed: false, status: 'building', startedAt: new Date().toISOString(),
  command: process.argv.slice(1), revisions: { chronolog: gitState(workspace), tendrillerArtifacts: gitState(artifacts) },
  topology: { membership: ['packaged workerd administrator', 'signed native membership HTTP'],
    introduction: ['Window', 'one direct SDP HTTP offer/answer', 'resident native WebRTC handler'],
    application: ['DedicatedWorker with OPFS/WASM', 'authenticated RTCDataChannel', 'native full replica and finality service'],
    nativeImplementation: 'werift@0.27.0' },
  measurement: { applicationBytes: 'Logical authenticated RTC frame payload; excludes framing headers/credit and SCTP/DTLS/IP overhead.',
    rtcSdpBytes: 'UTF-8 bytes of the complete offer and answer SDP descriptions.',
    rtcSignalingRequestBytes: 'Actual direct introduction HTTP request bodies, including the protocol JSON envelope; excludes HTTP headers.',
    rtcSignalingResponseBytes: 'Actual direct introduction HTTP response bodies, including the protocol JSON envelope; excludes HTTP headers.' },
  artifacts: {} as Record<string, unknown>, browser: '', checks: [] as Array<{ name: string; evidence: unknown }>,
  pageErrors: [] as string[], final: null as unknown, error: '', limits: [
    'The built Cloudflare Worker runs in the real local workerd test harness with synthetic authenticated accounts; this is not a deployed Cloudflare service or public-network qualification.',
    'Descriptor/body byte counters cover the actual loopback membership and peer boundaries; they do not predict provider billing or NAT traversal.',
    'Application peer bytes are logical authenticated RTC frame payloads, excluding framing headers/credit and SCTP/DTLS/IP overhead. SDP HTTP body bytes are measured separately.',
  ] }
const save = () => writeFile(join(output, 'report.json'), JSON.stringify(report, bigintJson, 2) + '\n')
let browser: Browser | undefined, page: Page | undefined
let native: NativeFixture | undefined
let bootstrap: ThinMembershipBootstrap | undefined
let completed = false
const assetPaths = new Map([
  ['/membership-worker.mjs', 'membership-worker.mjs'],
  ['/membership-page.mjs', 'membership-page.mjs'],
  ...['sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js', 'manifest.json'].map(name => [`/engine/${name}`, `engine/${name}`] as const),
])

try {
  const selected = async (kind: string) => {
    const names = (await readdir(artifacts)).filter(name => new RegExp(`^tendriller-${kind}-.+\\.tgz$`, 'u').test(name))
    if (names.length !== 1) throw new Error(`THIN_EXPECT_ONE_PUBLIC_${kind.toUpperCase()}_ARTIFACT`)
    return join(artifacts, names[0]!)
  }
  const sourceSdk = await selected('sdk'), sourceEngine = await selected('engine')
  const inputs = join(output, 'inputs'); await mkdir(inputs)
  const sdk = join(inputs, 'sdk.tgz'), engine = join(inputs, 'engine.tgz')
  await cp(sourceSdk, sdk); await cp(sourceEngine, engine)
  const alias = Object.fromEntries(['rpc', 'node-core', 'control-store'].flatMap(name =>
    ['', '/browser'].map(suffix => [`@chronolog/${name}${suffix}`, join(workspace, `packages/${name}/src/browser.ts`)])))
  alias['@chronolog/node-core/history'] = join(workspace, 'packages/node-core/src/history-policy.ts')
  alias['@chronolog/node-core/finality'] = join(workspace, 'packages/node-core/src/finality.ts')
  alias['@chronolog/node-core/ledger'] = join(workspace, 'packages/node-core/src/ledger-record.ts')
  alias['@chronolog/node-core/membership'] = join(workspace, 'packages/node-core/src/membership.ts')
  const publicApi = await build({ absWorkingDir: workspace, entryPoints: ['test/thin-membership/public.ts'],
    outfile: join(host, 'membership-api.mjs'), bundle: true, platform: 'browser', format: 'esm', target: 'es2022', alias, metafile: true })
  const worker = await build({ absWorkingDir: workspace, entryPoints: ['test/thin-membership/worker.ts'],
    outfile: join(assets, 'membership-worker.mjs'), bundle: true, platform: 'browser', format: 'esm', target: 'es2022', alias, metafile: true })
  const window = await build({ absWorkingDir: workspace, entryPoints: ['test/thin-membership/page.ts'],
    outfile: join(assets, 'membership-page.mjs'), bundle: true, platform: 'browser', format: 'esm', target: 'es2022', alias, metafile: true })
  for (const bundle of [worker, window]) {
    const forbidden = Object.values(bundle.metafile.outputs).flatMap(output => Object.entries(output.inputs)
      .filter(([name, value]) => value.bytesInOutput > 0 && /(?:werift|transport-webrtc\/src\/native|transport-tendriller|runtime-workerd|event-connection)/u.test(name)).map(([name]) => name))
    if (forbidden.length > 0) throw new Error(`THIN_RTC_BROWSER_IMPORT_AUDIT_FAILED: ${forbidden.join(', ')}`)
  }
  await mkdir(join(assets, 'engine'))
  for (const name of ['sqlite3.mjs', 'sqlite3.wasm', 'sqlite3-opfs-async-proxy.js', 'manifest.json']) await cp(join(wasm, name), join(assets, 'engine', name))
  await writeFile(join(assets, 'index.html'), browserPage())
  await cp(join(workspace, 'test/thin-membership/host.scenarios.mjs'), join(host, 'host.test.mjs'))
  await writeFile(join(host, 'package.json'), JSON.stringify({ private: true, type: 'module', dependencies: {
    '@tendriller/core': `file:${sdk}`, '@tendriller/engine': `file:${engine}`, '@cloudflare/vitest-plugin': '1.8.1', vitest: '4.1.12',
  } }, null, 2) + '\n')
  await writeFile(join(host, 'entry.mjs'), "export { default, Tendril, Admission } from '@tendriller/engine';\n")
  await mkdir(join(host, 'assets')); await writeFile(join(host, 'assets/index.txt'), 'Thin membership qualification host')
  await writeFile(join(host, 'wrangler.jsonc'), JSON.stringify({ name: 'thin-membership-qualification', main: 'entry.mjs',
    compatibility_date: '2026-11-01', compatibility_flags: ['nodejs_compat'],
    assets: { directory: './assets', binding: 'ASSETS', run_worker_first: true },
    durable_objects: { bindings: [{ name: 'TENDRIL', class_name: 'Tendril' }, { name: 'ADMISSION', class_name: 'Admission' }] },
    migrations: [{ tag: 'baseline', new_sqlite_classes: ['Tendril', 'Admission'] }],
    d1_databases: [{ binding: 'ACCOUNTS', database_name: 'test', database_id: '00000000-0000-4000-8000-000000000001' }],
    r2_buckets: [{ binding: 'FILES', bucket_name: 'test' }], vars: { PUBLIC_BASE: 'https://tendriller.dev', PAGE_BASE_DOMAIN: 'tendriller.site' },
  }, null, 2) + '\n')
  report.artifacts = { sdk: { source: sourceSdk, path: sdk, sha256: await hash(sdk) }, engine: { source: sourceEngine, path: engine, sha256: await hash(engine) },
    wasmManifestSha256: await hash(join(wasm, 'manifest.json')), wasmSha256: await hash(join(wasm, 'sqlite3.wasm')),
    browserWorkerSha256: await hash(join(assets, 'membership-worker.mjs')), browserPageSha256: await hash(join(assets, 'membership-page.mjs')),
    publicMembershipApiSha256: await hash(join(host, 'membership-api.mjs')) }
  await writeFile(join(output, 'bundles.json'), JSON.stringify({ publicApi: publicApi.metafile, worker: worker.metafile, window: window.metafile }, null, 2) + '\n')
  await run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], host)
  // The installed public package must expose the real default host and testing
  // boundary. A source checkout or test replacement provider is never injected.
  await run(process.execPath, ['--input-type=module', '-e', "import.meta.resolve('@tendriller/engine'); import.meta.resolve('@tendriller/engine/testing'); import.meta.resolve('@tendriller/core/members');"], host)
  const provenanceUrl = execFileSync(process.execPath, ['--input-type=module', '-e',
    "console.log(import.meta.resolve('@tendriller/engine/membership-provenance'))"], { cwd: host, encoding: 'utf8' }).trim()
  const provenance = JSON.parse(await readFile(fileURLToPath(provenanceUrl), 'utf8')) as {
    readonly source?: unknown; readonly dirty?: unknown; readonly inputs?: unknown; readonly sha256?: unknown
  }
  if (provenance.dirty !== false || typeof provenance.source !== 'string' || !/^[0-9a-f]{40}$/u.test(provenance.source) ||
      !Array.isArray(provenance.inputs) || provenance.inputs.length === 0 || provenance.inputs.some((input: unknown) =>
        typeof input !== 'string' || /(?:materializer|transport-ssb|node-core\/src\/node\.ts|node:)/u.test(input))) {
    throw new Error('THIN_PUBLIC_MEMBERSHIP_IMPORT_AUDIT_FAILED')
  }
  report.artifacts.membership = provenance
  await writeFile(join(output, 'membership-provenance.json'), JSON.stringify(provenance, null, 2) + '\n')
  report.checks.push({ name: 'independent public SDK/engine and browser membership bundles build with pinned artifacts', evidence: {} })
  if (values['build-only']) {
    report.status = 'built; workerd and browser scenarios not run'
    await save()
  } else {
    report.status = 'launching Chromium and real workerd host'
    await save()
    const executable = values.browser ?? process.env.CHRONOLOG_CHROMIUM_EXECUTABLE
    browser = await chromium.launch({ headless: true, ...(executable === undefined ? {} : { executablePath: executable }) })
    report.browser = browser.version()
    native = await createThinMembershipNative({ directory: join(output, 'native-state'), extraRequest: async request => {
      const url = new URL(request.url)
      if (url.pathname === '/favicon.ico') return new Response(null, { status: 204 })
      if (url.pathname === '/') return new Response(await readFile(join(assets, 'index.html')), { headers: isolated('text/html') })
      const file = assetPaths.get(url.pathname)
      if (file !== undefined) return new Response(await readFile(join(assets, file)), { headers: isolated(file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.json') ? 'application/json' : 'text/javascript') })
      if (!url.pathname.startsWith('/fixture/')) return null
      try {
        const input = request.method === 'GET' ? undefined : await request.json() as Record<string, unknown>
        let result: unknown
        switch (url.pathname.slice('/fixture/'.length)) {
          case 'configuration': {
            result = { executionManifestDigest: bytesToBase64Url(native!.executionManifestDigest),
              schemaAdministratorPublicKey: bytesToBase64Url(native!.identity.signing.publicKeyBytes),
              nativeAuthority: { url: native!.membershipUrl, historyId: native!.historyId, publicKey: bytesToBase64Url(native!.identity.signing.publicKeyBytes) },
              initialMembers: [{ signingPublicKey: bytesToBase64Url(native!.identity.signing.publicKeyBytes),
                readerPublicKey: bytesToBase64Url(native!.identity.reader.publicKeyBytes), transportAuthor: native!.initialCapabilities[0]!.transportAuthor,
                writerProgram: { sql: true, topics: ['*'], signals: ['*'] } }] }
            break
          }
          case 'start':
            bootstrap = await native!.start(input as unknown as Parameters<NativeFixture['start']>[0]); result = bootstrap; break
          case 'workload': result = await native!.publishWorkload(input as unknown as Parameters<NativeFixture['publishWorkload']>[0]); break
          case 'snapshot': result = await native!.snapshot(); break
          case 'device': result = await callDevice(page!, input!); break
          case 'new-device': {
            await page!.evaluate(() => (globalThis as unknown as BrowserPage).thinMembership.replaceWorker())
            const prepared = await callDevice(page!, { method: 'prepare', name: input!.name })
            const opened = await callDevice(page!, { method: 'open', name: input!.name, bootstrap: input!.bootstrap })
            result = { prepared, opened }; break
          }
          case 'reload-device': {
            await page!.evaluate(() => (globalThis as unknown as BrowserPage).thinMembership.replaceWorker())
            await callDevice(page!, { method: 'open', name: input!.name, bootstrap: input!.bootstrap })
            result = await callDevice(page!, { method: 'approval', requestId: input!.requestId, signedApproval: input!.signedApproval })
            break
          }
          case 'check':
            report.checks.push({ name: String(input!.name), evidence: input!.evidence })
            process.stdout.write(`Passed: ${String(input!.name)}\n`); await save(); result = { recorded: true }; break
          case 'complete': report.final = input; completed = true; await save(); result = { recorded: true }; break
          default: return new Response(null, { status: 404 })
        }
        return json(result)
      } catch (error) { return json({ error: error instanceof Error ? error.stack : String(error) }, 500) }
    } })
    const context = await browser.newContext()
    page = await context.newPage()
    page.on('pageerror', error => report.pageErrors.push(error.message))
    await page.goto(native.base)
    await page.waitForFunction(() => 'thinMembership' in globalThis)
    await writeFile(join(host, 'vitest.config.mjs'), `import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import { dirname } from 'node:path';
const require = createRequire(import.meta.url);
const d1Migrations = await readD1Migrations(dirname(require.resolve('@tendriller/engine/accounts-schema')));
export default defineConfig({ plugins: [cloudflareTest({main: new URL('./entry.mjs', import.meta.url).pathname,
  wrangler: {configPath: new URL('./wrangler.jsonc', import.meta.url).pathname}})],
  test: {include: ['host.test.mjs'], testTimeout: 240000, provide: {d1Migrations, fixtureBase: ${JSON.stringify(native.base)}}} });
`)
    await run(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', '--config', 'vitest.config.mjs',
      '--reporter=default', '--reporter=json', '--outputFile=host-results.json'], host, 360_000)
    if (!completed) throw new Error('THIN_HOST_DID_NOT_COMPLETE_QUALIFICATION')
    if (report.pageErrors.length > 0) throw new Error(`THIN_BROWSER_PAGE_ERRORS: ${report.pageErrors.join('; ')}`)
    native.assertHealthy()
    report.passed = true; report.status = 'passed'
    await save()
  }
} catch (error) {
  report.status = 'failed'; report.error = error instanceof Error ? error.stack ?? error.message : String(error)
  if (page !== undefined) {
    try { report.final = { browser: await callDevice(page, { method: 'status' }), native: await native?.snapshot() } } catch { /* Preserve the original failure. */ }
    await page.screenshot({ path: join(output, 'failure.png'), fullPage: true }).catch(() => undefined)
  }
  await save(); throw error
} finally {
  if (page !== undefined) await callDevice(page, { method: 'close' }).catch(() => undefined)
  await browser?.close(); await native?.close(); await save()
}
process.stdout.write(`Thin membership evidence: ${output}\n`)

interface BrowserPage { readonly thinMembership: { call(command: Record<string, unknown>): Promise<unknown>; replaceWorker(): Promise<void> } }
async function callDevice(current: Page, command: Record<string, unknown>): Promise<unknown> {
  return current.evaluate(input => (globalThis as unknown as BrowserPage).thinMembership.call(input), command)
}
function isolated(type: string): Record<string, string> {
  return { 'Content-Type': type, 'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Embedder-Policy': 'require-corp', 'Cache-Control': 'no-store' }
}
function bigintJson(_key: string, value: unknown): unknown { return typeof value === 'bigint' ? value.toString() : value }
function json(value: unknown, status = 200): Response { return new Response(JSON.stringify(value, bigintJson), { status, headers: { 'Content-Type': 'application/json' } }) }
async function hash(path: string): Promise<string> { return createHash('sha256').update(await readFile(path)).digest('hex') }
function gitState(path: string) {
  try { return { head: execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(),
    dirty: execFileSync('git', ['-C', path, 'status', '--porcelain'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim().length > 0 } }
  catch { return { head: 'not-a-git-checkout', dirty: null } }
}
async function run(command: string, args: readonly string[], cwd: string, timeoutMs = 180_000): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, stdio: 'inherit', env: { ...process.env, NO_COLOR: '1' } })
    let timedOut = false, force: ReturnType<typeof setTimeout> | undefined
    const deadline = setTimeout(() => {
      timedOut = true; child.kill('SIGTERM')
      force = setTimeout(() => child.kill('SIGKILL'), 5000)
    }, timeoutMs)
    const clear = () => { clearTimeout(deadline); if (force !== undefined) clearTimeout(force) }
    child.once('error', error => { clear(); reject(error) })
    child.once('exit', (code, signal) => {
      clear()
      if (timedOut) reject(new Error(`THIN_PROCESS_TIMEOUT: ${command} after ${timeoutMs}ms`))
      else if (code === 0) resolvePromise()
      else reject(new Error(`THIN_PROCESS_FAILED: ${command} (${code ?? signal})`))
    })
  })
}
function browserPage(): string { return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Thin membership qualification</title>
<body><h1>Thin membership qualification</h1><p>Actual OPFS device. Membership is approved by the built Cloudflare host; application records and bodies use native WebRTC.</p><pre id="status">Waiting for the qualification runner.</pre>
<script type="module" src="/membership-page.mjs"></script></body></html>` }

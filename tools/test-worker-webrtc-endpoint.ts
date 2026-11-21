import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { resolve, join } from 'node:path'
import { parseArgs } from 'node:util'
import { build } from 'esbuild'
import { chromium } from '@playwright/test'
import type { qualify } from '../test/worker-webrtc-endpoint/page.js'

const { values } = parseArgs({ options: { output: { type: 'string', default: 'artifacts/worker-webrtc-endpoint' } } })
const root = resolve(import.meta.dirname, '..'), output = resolve(values.output)
const git = (args: string[]) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim()
const digest = (value: Uint8Array | string) => createHash('sha256').update(value).digest('hex')
await mkdir(output, { recursive: true })
const bundle = await build({ absWorkingDir: root, entryPoints: { page: 'test/worker-webrtc-endpoint/page.ts', worker: 'test/worker-webrtc-endpoint/worker.ts' },
  outdir: output, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', metafile: true })
const sources = Object.fromEntries(await Promise.all(Object.keys(bundle.metafile.inputs).sort().map(async path => [path, digest(await readFile(join(root, path)))] as const)))
const files = await Promise.all(['page.js', 'worker.js'].map(async path => ({ path, sha256: digest(await readFile(join(output, path))) })))
const server = createServer((req, res) => {
  if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><script type="module" src="/page.js"></script>'); return }
  if (req.url !== '/page.js' && req.url !== '/worker.js') { res.writeHead(404); res.end(); return }
  void readFile(join(output, req.url.slice(1))).then(bytes => { res.writeHead(200, { 'Content-Type': 'text/javascript' }); res.end(bytes) }, () => { res.writeHead(500); res.end() })
})
server.listen(0, '127.0.0.1'); await once(server, 'listening')
const address = server.address(); assert(address !== null && typeof address !== 'string')
const browser = await chromium.launch({ ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH === undefined ? {} : { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }) })
const results: Array<Awaited<ReturnType<typeof qualify>>> = []
try {
  for (const mode of ['shared', 'dedicated', 'broadcast', 'shared-unreachable-stun'] as const) {
    const page = await browser.newPage()
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await page.goto(`http://127.0.0.1:${address.port}/`)
      await page.waitForFunction(() => 'qualifyWorkerRtc' in globalThis)
      const result = await Promise.race([
        page.evaluate(async mode => (globalThis as unknown as { qualifyWorkerRtc: typeof qualify }).qualifyWorkerRtc(mode), mode),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(Error('WORKER_RTC_BROWSER_TIMEOUT')), 30_000) }),
      ])
      assert(result.ready.every(value => (value as { worker: boolean; route: { route: string } }).worker && (value as { route: { route: string } }).route.route === 'direct'))
      assert.deepEqual(result.live, [true, true]); assert.equal(result.idleMessages, 0)
      assert.deepEqual(result.state, [{ received: 24, liveReceived: 1, bytes: 24 * 65_536 }, { received: 24, liveReceived: 1, bytes: 24 * 65_536 }])
      if (mode === 'shared-unreachable-stun') {
        assert(result.negotiationMs < 5000, 'Unreachable STUN must not consume the whole direct attempt')
        assert.equal(result.descriptions.length, 2)
        assert(result.descriptions.every(value => value.candidates > 0 && value.servers === 2), 'Keep real STUN configured and publish usable candidate batches')
        assert(result.descriptions.some(value => value.gathering !== 'complete'), 'Exercise actual incomplete ICE gathering, not an already completed gather')
      }
      results.push(result); console.log(`${mode}: bidirectional reliable/live direct RTC, ordered 3 MiB, quiet idle PASS`)
    } finally { clearTimeout(timer); await page.close() }
  }
  await writeFile(join(output, 'report.json'), JSON.stringify({ format: 'chronolog-worker-rtc-endpoint-v1', source: {
    head: git(['rev-parse', 'HEAD']), tree: git(['rev-parse', 'HEAD^{tree}']), dirty: git(['status', '--porcelain']) !== '', inputs: sources },
  browser: browser.version(), limits: 'raw transport only; loopback ICE; broadcast fixture tests routing, not endpoint authentication or application/session authorization',
  emitted: files, results }, null, 2) + '\n')
} finally { await browser.close(); server.closeAllConnections(); await new Promise<void>(resolve => { server.close(() => resolve()) }) }

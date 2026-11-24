import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { chromium, webkit, type BrowserContext } from '@playwright/test'
import { build } from 'esbuild'

const bundle = await build({ entryPoints: ['test/browser-storage/worker.ts'], write: false, bundle: true,
  platform: 'browser', format: 'esm', target: 'es2022' })
const workerCode = bundle.outputFiles[0]!.contents
const server = createServer((request, response) => {
  const path = new URL(request.url ?? '/', 'http://localhost').pathname
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('Content-Type', path === '/worker.js' ? 'text/javascript' : 'text/html')
  response.end(path === '/worker.js' ? workerCode :
    '<!doctype html><meta charset="utf-8"><title>Record storage qualification</title>')
})
const profile = await mkdtemp(join(tmpdir(), 'chronolog-storage-profile-'))
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
assert(address !== null && typeof address !== 'string')
const origin = 'http://127.0.0.1:' + address.port

type Result = { id: string; storageId: string; backend?: string }
async function command(context: BrowserContext, method: 'run' | 'resume', name: string): Promise<Result> {
  const page = await context.newPage()
  try {
    await page.addInitScript({ content: 'globalThis.__name = (value) => value' })
    await page.goto(origin)
    return await page.evaluate(async ({ method, name }) => {
      const worker = new Worker('/worker.js', { type: 'module' })
      try {
        return await new Promise<Result>((resolve, reject) => {
          const timer = setTimeout(() => { reject(new Error('Storage Worker qualification timed out')) }, 45_000)
          worker.onerror = event => { clearTimeout(timer); reject(new Error(event.message)) }
          worker.onmessage = event => {
            const data = event.data as { error?: string; value?: Result }
            clearTimeout(timer)
            if (data.error) reject(new Error(data.error))
            else if (data.value !== undefined) resolve(data.value)
            else reject(new Error('Storage Worker response is missing a result'))
          }
          worker.postMessage({ id: 1, method, name })
        })
      } finally { worker.terminate() }
    }, { method, name })
  } finally { await page.close() }
}

let context: BrowserContext | undefined
try {
  const engine = process.env.CHRONOLOG_STORAGE_BROWSER === 'webkit' ? webkit : chromium
  const executablePath = process.env.CHRONOLOG_STORAGE_BROWSER_EXECUTABLE
  const launch = () => engine.launchPersistentContext(profile, { headless: true, ...(executablePath ? { executablePath } : {}) })
  // WebKit's private contexts expose getDirectory(), but reject it with
  // UnknownError. Qualify durable storage in a fresh normal profile instead;
  // never weaken fail-closed backend selection to accommodate private mode.
  context = await launch()
  const name = 'browser-storage-' + randomUUID()
  const initial = await command(context, 'run', name)
  await context.close(); context = undefined
  context = await launch()
  const resumed = await command(context, 'resume', name)
  assert.equal(initial.id, resumed.id)
  assert.equal(initial.storageId, resumed.storageId)
  assert.ok(initial.backend === 'opfs' || initial.backend === 'indexeddb')
  console.log('Browser record stores, backend pin, legacy protection and browser restart passed:', engine.name(), initial.backend)
} finally {
  try { await context?.close() } finally {
    server.closeAllConnections()
    await Promise.all([
      rm(profile, { recursive: true, force: true }),
      new Promise<void>((resolve, reject) => {
        server.close(error => error === undefined ? resolve() : reject(error))
      }),
    ])
  }
}

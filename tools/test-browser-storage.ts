import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { randomUUID } from 'node:crypto'
import { chromium } from '@playwright/test'
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
server.listen(0, '127.0.0.1')
await once(server, 'listening')
const address = server.address()
assert(address !== null && typeof address !== 'string')
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined
try {
  browser = await chromium.launch({ headless: true })
  const page = await browser.newPage()
  await page.goto('http://127.0.0.1:' + address.port)
  const result = await page.evaluate(async (name: string) => {
    async function command(method: 'run' | 'resume'): Promise<{ id: string; storageId: string; backend?: string }> {
      const worker = new Worker('/worker.js', { type: 'module' })
      try {
        return await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { reject(new Error('Storage Worker qualification timed out')) }, 45_000)
          worker.onerror = event => { clearTimeout(timer); reject(new Error(event.message)) }
          worker.onmessage = ({ data }) => {
            clearTimeout(timer)
            if (data.error) reject(new Error(data.error))
            else resolve(data.value)
          }
          worker.postMessage({ id: 1, method, name })
        })
      } finally { worker.terminate() }
    }
    const initial = await command('run')
    const resumed = await command('resume')
    return { initial, resumed }
  }, 'browser-storage-' + randomUUID())
  assert.equal(result.initial.id, result.resumed.id)
  assert.equal(result.initial.storageId, result.resumed.storageId)
  assert.ok(result.initial.backend === 'opfs' || result.initial.backend === 'indexeddb')
  console.log('Browser record stores, backend pin, legacy protection and Worker restart passed:', result.initial.backend)
} finally {
  await browser?.close()
  server.closeAllConnections()
  await new Promise<void>((resolve, reject) => {
    server.close(error => error === undefined ? resolve() : reject(error))
  })
}

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { expect, it } from 'vitest'

const binary = process.env.CHRONOLOG_CELLD_BINARY

it.skipIf(binary === undefined)('runs the actual Chronolog materializer bridge inside the rebuilt Celld engine and reopens after restart', async () => {
  const directory = await mkdtemp(join(process.env.CHRONOLOG_CELLD_TEST_DIRECTORY ?? tmpdir(), 'chronolog-celld-bridge-'))
  const port = await new Promise<number>((resolve, reject) => {
    const server = createServer()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') throw new Error('CELLD_TEST_PORT_UNAVAILABLE')
      server.close(() => resolve(address.port))
    })
  })
  let child: ChildProcessWithoutNullStreams | undefined
  let logs = ''
  const stop = async () => {
    const running = child
    child = undefined
    if (running === undefined || running.exitCode !== null || running.signalCode !== null) return
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => running.kill('SIGKILL'), 5000)
      running.once('exit', () => { clearTimeout(timer); resolve() })
      running.kill('SIGTERM')
    })
  }
  const start = async () => {
    child = spawn(binary!, ['dev', '.', '--host', '127.0.0.1', '--port', String(port), '--no-watch', '--logs'], {
      cwd: directory,
      env: { ...process.env, CELLD_ESBUILD: fileURLToPath(new URL('../../../node_modules/esbuild/bin/esbuild', import.meta.url)), NO_COLOR: '1' },
    })
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`CELLD_TEST_START_TIMEOUT\n${logs}`)), 30_000)
      const output = (data: Buffer) => {
        logs += data.toString()
        if (/\bready\s+http:\/\//u.test(logs)) { clearTimeout(timer); resolve() }
      }
      child!.stdout.on('data', output)
      child!.stderr.on('data', output)
      child!.once('error', (error) => { clearTimeout(timer); reject(error) })
      child!.once('exit', (code) => { clearTimeout(timer); reject(new Error(`CELLD_TEST_START_EXIT:${code}\n${logs}`)) })
    })
  }
  const request = async (path: string): Promise<Record<string, unknown>> => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`)
    const data = await response.json() as Record<string, unknown>
    expect(response.status, JSON.stringify({ data, logs })).toBe(200)
    return data
  }
  try {
    await build({ entryPoints: [fileURLToPath(new URL('./celld-bridge.fixture.ts', import.meta.url))], outfile: join(directory, 'index.js'),
      bundle: true, platform: 'browser', format: 'esm', target: 'es2023', tsconfig: fileURLToPath(new URL('../../../tsconfig.json', import.meta.url)) })
    await writeFile(join(directory, 'wrangler.jsonc'), JSON.stringify({ name: 'chronolog-bridge', main: 'index.js', compatibility_date: '2026-01-01', compatibility_flags: ['sqlite_vec'],
      durable_objects: { bindings: [{ name: 'REPO', class_name: 'Repo' }] }, migrations: [{ tag: 'v1', new_dolt_classes: ['Repo'] }] }))
    await start()
    const before = await request('/exercise')
    expect(before).toMatchObject({ orderLength: 7, finalOrderLength: 2,
      profile: { sqliteVec: true, manifest: { execProfile: 'celld-spec10-v7' } },
      rows: [[{ kind: 'integer', value: '1' }, { kind: 'integer', value: '60' }]],
      finalRows: [[{ kind: 'integer', value: '1' }, { kind: 'integer', value: '110' }]],
      grants: [[{ kind: 'integer', value: '1' }]],
      schema: [[{ kind: 'text', value: 'accounts' }], [{ kind: 'text', value: 'audit' }], [{ kind: 'text', value: 'mine' }], [{ kind: 'text', value: 'other' }]],
    })
    await stop()
    logs = ''
    await start()
    expect(await request('/state')).toEqual(before)
  } finally { await stop(); await rm(directory, { recursive: true, force: true }) }
}, 90_000)

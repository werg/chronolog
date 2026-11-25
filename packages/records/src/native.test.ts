import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { NativeBytesStore } from './native.js'

it('accounts incremental writes, replacements and failures under exclusive ownership across reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-bytes-')), path = join(directory, 'peer.sqlite')
  let store = await NativeBytesStore.open(path, { quotaBytes: 1024 })
  try {
    for (let index = 0; index < 64; index++) await store.put(`record/${index}`, new Uint8Array(16))
    expect(store.usageBytes()).toBe(1024)
    await expect(store.put('overflow', new Uint8Array(1))).rejects.toThrow('BYTES_STORE_QUOTA_EXCEEDED')
    expect(await store.get('overflow')).toBeNull()
    expect(store.usageBytes()).toBe(1024)
    const replacement = Buffer.alloc(7, 5)
    const writing = store.put('record/0', replacement)
    replacement.fill(9)
    await writing
    const captured = await store.get('record/0')
    expect(captured).toEqual(new Uint8Array(7).fill(5))
    captured!.fill(1)
    expect(await store.get('record/0')).toEqual(new Uint8Array(7).fill(5))
    expect(store.usageBytes()).toBe(1015)
    await expect(NativeBytesStore.open(path)).rejects.toMatchObject({ code: 'BYTES_STORE_IN_USE', message: 'BYTES_STORE_IN_USE' })
    await store.close()
    store = await NativeBytesStore.open(path, { quotaBytes: 1024 })
    expect(store.usageBytes()).toBe(1015)
    expect(await store.get('record/0')).toEqual(new Uint8Array(7).fill(5))
    await store.put('after-reopen', new Uint8Array(9))
    expect(store.usageBytes()).toBe(1024)
  } finally { await store.close(); await rm(directory, { recursive: true, force: true }) }
})

it('runs SQLite work outside the caller event loop and rolls back interrupted streamed restores', async () => {
  const store = await NativeBytesStore.open(':memory:')
  try {
    let progressed = false
    const immediate = new Promise<void>(resolve => { setImmediate(() => { progressed = true; resolve() }) })
    for (let index = 0; index < 32; index++) await store.put(`row/${index}`, new Uint8Array(8192))
    expect(progressed).toBe(true)
    await immediate
    const iterator = store.iterateEntries()[Symbol.asyncIterator]()
    await iterator.next()
    let written = false
    const writing = store.put('after-snapshot', Uint8Array.of(7)).then(() => { written = true })
    await new Promise(setImmediate)
    expect(written).toBe(false)
    await iterator.return?.(); await writing
    expect(await store.get('after-snapshot')).toEqual(Uint8Array.of(7))
  } finally { await store.close() }
  const target = await NativeBytesStore.open(':memory:')
  try {
    await expect(target.putStreamIfEmpty((async function* () { yield { key: 'identity', value: Uint8Array.of(1) }; throw Error('input interrupted') })())).rejects.toThrow('input interrupted')
    expect(await target.entries()).toEqual([])
    expect(await target.putStreamIfEmpty((async function* () { yield { key: 'identity', value: Uint8Array.of(2) } })())).toBe(true)
  } finally { await target.close() }
})

it('releases the durable SQLite fence when its owning process is killed', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-worker-crash-')), path = join(directory, 'peer.sqlite')
  const moduleUrl = new URL('./native.ts', import.meta.url).href
  const code = `import { NativeBytesStore } from ${JSON.stringify(moduleUrl)};
    const store = await NativeBytesStore.open(${JSON.stringify(path)});
    await store.put('identity', Uint8Array.of(19)); process.send('ready'); setInterval(() => {}, 1000);`
  const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] })
  let stderr = ''
  child.stderr?.on('data', (bytes: Buffer) => { stderr += bytes.toString() })
  try {
    await Promise.race([once(child, 'message'), once(child, 'exit').then(([code]) => { throw Error(`owner exited before acquiring storage: ${String(code)} ${stderr}`) })])
    await expect(NativeBytesStore.open(path)).rejects.toMatchObject({ code: 'BYTES_STORE_IN_USE', message: 'BYTES_STORE_IN_USE' })
    const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited
    const recovered = await NativeBytesStore.open(path)
    try { expect(await recovered.get('identity')).toEqual(Uint8Array.of(19)) } finally { await recovered.close() }
  } finally {
    if (child.exitCode === null && child.signalCode === null) { const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited }
    await rm(directory, { recursive: true, force: true })
  }
})


it('deletes durable local bytes, reclaims quota, and preserves absent keys on reopen', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'chronolog-prune-')), path = join(directory, 'peer.sqlite')
  let store = await NativeBytesStore.open(path, { quotaBytes: 4 })
  try {
    await store.put('discard', Uint8Array.of(1, 2, 3, 4))
    await store.delete('discard'); await store.delete('discard')
    expect(store.usageBytes()).toBe(0)
    await store.put('keep', Uint8Array.of(4, 3, 2, 1)); await store.close()
    store = await NativeBytesStore.open(path, { quotaBytes: 4 })
    expect(await store.get('discard')).toBeNull()
    expect(await store.get('keep')).toEqual(Uint8Array.of(4, 3, 2, 1))
    expect(store.usageBytes()).toBe(4)
  } finally { await store.close(); await rm(directory, { recursive: true, force: true }) }
})

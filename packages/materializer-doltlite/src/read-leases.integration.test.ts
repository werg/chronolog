import { afterEach, describe, expect, it } from 'vitest'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { DeterministicMaterializer } from './materializer.js'
import { createNativeSqlEngine } from './native.js'
import { MaterializerFixture, replayProposal, ROOT_KEY } from './test-fixtures.js'
import type { DatabaseLike, MaterializerOptions } from './types.js'

const fixtures = new MaterializerFixture()
afterEach(async () => fixtures.cleanup())

async function fixture() {
  const calls: Array<{ id: number; method: string; args: unknown[] }> = []
  const databases: DatabaseLike[] = []
  const native = createNativeSqlEngine()
  let fail: ((id: number, method: string) => boolean) | undefined
  const engine = { ...native, openDatabase(options: Parameters<typeof native.openDatabase>[0]) {
    const id = databases.length
    if (fail?.(id, 'openDatabase')) throw new Error('INJECTED_READER_FAILURE')
    const opened = native.openDatabase(options)
    databases.push(opened.database)
    return { ...opened, database: new Proxy(opened.database, { get(target, name) {
      const value: unknown = Reflect.get(target, name, target)
      if (typeof value !== 'function') return value
      return (...args: unknown[]) => {
        const method = String(name)
        calls.push({ id, method, args })
        if (fail?.(id, method)) throw new Error('INJECTED_READER_FAILURE')
        return Reflect.apply(value, target, args) as unknown
      }
    } }) }
  } }
  const options: MaterializerOptions = { engine, path: join(await fixtures.directory(), 'leases.db'),
    rootPrincipal: ROOT_KEY, checkpointEvery: 1, retainCheckpoints: 1 }
  const materializer = await DeterministicMaterializer.open(options)
  const proposal = (id: number, sql: string) => replayProposal(BigInt(id), String(id), [sql], materializer.executionManifestDigest)
  const setup = await proposal(1, 'CREATE TABLE drafts (id INTEGER PRIMARY KEY, value TEXT)')
  // Each step is separate SQL in the public ChangeProgram, not a multi-statement shortcut.
  await materializer.materialize([setup])
  const first = await proposal(2, "INSERT INTO drafts (id, value) VALUES (1, 'first')")
  const second = await proposal(3, "UPDATE drafts SET value = 'second' WHERE id = 1")
  return { materializer, options, calls, databases, proposal, setup, first, second,
    inject(value: typeof fail) { fail = value } }
}
const value = (handle: { query(sql: string): { rows: readonly unknown[] } }) => handle.query('SELECT value FROM drafts').rows
const liveValue = (materializer: DeterministicMaterializer) => materializer.localSql('SELECT value FROM drafts').rows
const pinned = [[{ kind: 'text', value: 'first' }]]

describe('publication-owned SQL reader leases', () => {
  it('captures/releases sixteen views with no opens, branches, checkout, listing or close', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      f.calls.length = 0
      const opened = f.databases.length
      const views = Array.from({ length: 16 }, (_, i) => m.captureRead({ view: i % 2 ? 'final' : 'local' }))
      expect(() => m.captureRead()).toThrow('MATERIALIZER_SNAPSHOT_LIMIT')
      for (const view of views) { view.release(); view.release() }
      expect(f.calls).toEqual([])
      expect(f.databases).toHaveLength(opened)
      expect(() => views[0]!.query('SELECT 1')).toThrow('MATERIALIZER_SNAPSHOT_RELEASED')
      const next = m.captureRead(); next.release()
      expect(f.calls).toEqual([])
    } finally { m.close() }
  })

  it('shares a pinned reader until its last lease, across append and rollback cleanup', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      const readerId = f.databases.length - 1
      const branch = f.calls.findLast(call => call.id === readerId && call.method === 'doltCheckout')!.args[0]
      const a = m.captureRead(), b = m.captureRead()
      const snapshot = { revision: a.revision, orderLength: a.orderLength, transaction: a.transactionAt(1) }
      await m.materialize([f.setup, f.first, f.second])
      expect(value(a)).toEqual(pinned)
      expect(value(b)).toEqual(pinned)
      expect(liveValue(m)).toEqual([[{ kind: 'text', value: 'second' }]])
      // Rollback to an exact earlier commit must not make reopen ambiguous.
      await m.materialize([f.setup])
      expect(value(a)).toEqual(pinned)
      expect({ revision: a.revision, orderLength: a.orderLength, transaction: a.transactionAt(1) }).toEqual(snapshot)
      expect(f.databases[0]!.doltBranches().some(ref => ref.name === branch)).toBe(true)
      f.calls.length = 0
      a.release()
      expect(f.calls).toEqual([])
      b.release()
      expect(f.calls.map(call => [call.id, call.method])).toEqual([[readerId, 'close']])
      expect(f.databases[0]!.doltBranches().some(ref => ref.name === branch)).toBe(true)
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      expect(f.databases[0]!.doltBranches().some(ref => ref.name === branch)).toBe(false)
      m.close()
      const reopened = await DeterministicMaterializer.open(f.options)
      try { expect(liveValue(reopened)).toEqual(pinned) } finally { reopened.close() }
    } finally { m.close() }
  })

  it('pins local and final SQL/log snapshots independently across final advances', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      await m.publishFinal(2)
      const final = m.captureRead({ view: 'final' }), local = m.captureRead()
      await m.materialize([f.setup, f.first, f.second])
      await m.publishFinal(3)
      expect(value(final)).toEqual(pinned)
      expect(value(local)).toEqual(pinned)
      expect(final.orderLength).toBe(2)
      expect(final.transactionAt(2)).toBeNull()
      expect(final.finalOrderLength).toBe(2)
      const current = m.captureRead({ view: 'final' })
      try { expect(value(current)).toEqual([[{ kind: 'text', value: 'second' }]]) } finally { current.release() }
      local.release(); final.release()
    } finally { m.close() }
  })

  it('keeps shared handles coherent after query errors and rejects writes', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      const a = m.captureRead(), b = m.captureRead()
      expect(() => a.query('SELECT * FROM absent')).toThrow()
      expect(() => a.query("UPDATE drafts SET value = 'wrong'")).toThrow()
      expect(value(a)).toEqual(pinned)
      expect(value(b)).toEqual(pinned)
      a.release(); expect(value(b)).toEqual(pinned); b.release()
    } finally { m.close() }
  })

  it.each(['doltCheckout', 'openDatabase'])('preserves old readers when candidate %s fails', async method => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      const held = m.captureRead(), firstNew = f.databases.length
      f.inject((id, name) => id >= firstNew && name === method)
      await expect(m.materialize([f.setup, f.first, f.second])).rejects.toThrow('INJECTED_READER_FAILURE')
      expect(value(held)).toEqual(pinned)
      expect(liveValue(m)).toEqual(pinned)
      expect(m.orderLength).toBe(2)
      f.inject(undefined)
      await m.materialize([f.setup, f.first, f.second])
      expect(value(held)).toEqual(pinned)
      held.release()
    } finally { f.inject(undefined); m.close() }
  })

  it('retains the final reader on failed candidate checkout and reclaims unleased final readers', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first, f.second])
      await m.publishFinal(2)
      const held = m.captureRead({ view: 'final' }), firstNew = f.databases.length
      f.inject((id, name) => id >= firstNew && name === 'doltCheckout')
      await expect(m.publishFinal(3)).rejects.toThrow('INJECTED_READER_FAILURE')
      expect(m.finalOrderLength).toBe(2)
      expect(value(held)).toEqual(pinned)
      f.inject(undefined)
      held.release()
      await m.publishFinal(3)
      expect(f.databases[0]!.doltBranches().filter(ref => ref.name.startsWith('chronolog_read_'))).toHaveLength(2)
      const current = m.captureRead({ view: 'final' })
      try { expect(value(current)).toEqual([[{ kind: 'text', value: 'second' }]]) } finally { current.release() }
    } finally { f.inject(undefined); m.close() }
  })

  it('keeps sixteen different historical readers valid through repeated publication and GC', async () => {
    const f = await fixture(), m = f.materializer
    try {
      const history = [f.setup, f.first]
      await m.materialize(history)
      const held = []
      for (let i = 0; i < 16; i++) {
        const view = m.captureRead()
        held.push({ view, expected: value(view), log: view.transactionAt(view.orderLength - 1) })
        history.push(await f.proposal(i + 10, `UPDATE drafts SET value = 'revision${i}' WHERE id = 1`))
        await m.materialize(history)
      }
      expect(() => m.captureRead()).toThrow('MATERIALIZER_SNAPSHOT_LIMIT')
      for (const entry of held) {
        expect(value(entry.view)).toEqual(entry.expected)
        expect(entry.view.transactionAt(entry.view.orderLength - 1)).toEqual(entry.log)
        entry.view.release()
      }
      const current = m.captureRead(); current.release()
      history.push(await f.proposal(50, "UPDATE drafts SET value = 'last' WHERE id = 1"))
      await m.materialize(history)
      expect(f.databases[0]!.doltBranches().filter(ref => ref.name.startsWith('chronolog_read_'))).toHaveLength(2)
    } finally { m.close() }
  })

  it('reclaims leased reader refs after abrupt death and reopens an exact rollback commit', async () => {
    const path = join(await fixtures.directory(), 'crash.db')
    const child = spawnSync(process.execPath, ['--import', 'tsx', resolve('test/fixtures/materializer-reader-lease-crash.ts'), path],
      { encoding: 'utf8', timeout: 20_000 })
    expect(child.signal === 'SIGKILL' || child.status === 137, `${child.stdout}\n${child.stderr}`).toBe(true)
    const m = await DeterministicMaterializer.open({ path, engine: createNativeSqlEngine(), rootPrincipal: ROOT_KEY, checkpointEvery: 1 })
    try {
      expect(m.revision).toBe(3n)
      expect(m.orderLength).toBe(1)
      const view = m.captureRead()
      try { expect(view.query('SELECT value FROM crash_view').rows).toEqual(pinned) } finally { view.release() }
    } finally { m.close() }
  })

  it('invalidates every view and attempts every database close despite a close failure', async () => {
    const f = await fixture(), m = f.materializer
    await m.materialize([f.setup, f.first])
    const retiredId = f.databases.length - 1
    const a = m.captureRead(), b = m.captureRead({ view: 'final' })
    await m.materialize([f.setup, f.first, f.second])
    f.calls.length = 0
    let failed = false
    f.inject((id, method) => {
      if (id !== retiredId || method !== 'close' || failed) return false
      failed = true; return true
    })
    expect(() => m.close()).toThrow('INJECTED_READER_FAILURE')
    expect(f.calls.filter(call => call.method === 'close').length).toBe(4)
    expect(() => value(a)).toThrow('MATERIALIZER_SNAPSHOT_RELEASED')
    expect(() => value(b)).toThrow('MATERIALIZER_SNAPSHOT_RELEASED')
    expect(() => m.captureRead()).toThrow('MATERIALIZER_CLOSED')
    const before = f.calls.length
    m.close(); m.close(); a.release(); b.release()
    expect(f.calls.slice(before).map(call => [call.id, call.method])).toEqual([[retiredId, 'close']])
  })

  it('frees a released lease slot and retains failed retired closes for final cleanup', async () => {
    const f = await fixture(), m = f.materializer
    try {
      await m.materialize([f.setup, f.first])
      expect(m.outcome(f.first.txId)?.outcome).toBe('accepted')
      const retiredId = f.databases.length - 1, held = m.captureRead()
      await m.materialize([f.setup, f.first, f.second])
      let failed = false
      f.inject((id, name) => id === retiredId && name === 'close' && !failed && (failed = true))
      expect(() => held.release()).toThrow('INJECTED_READER_FAILURE')
      expect(() => value(held)).toThrow('MATERIALIZER_SNAPSHOT_RELEASED')
      held.release()
      const views = Array.from({ length: 16 }, () => m.captureRead())
      for (const view of views) view.release()
      f.inject(undefined)
    } finally { f.inject(undefined); m.close() }
  })
})

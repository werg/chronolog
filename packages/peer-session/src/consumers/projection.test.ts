import { MemoryPeerStore, type PeerStore } from '@chronolog/peer-generation'
import { afterEach, describe, expect, it } from 'vitest'

import { ApplicationProjection } from './projection.js'
import { consumerFixture, publish } from './test-support.js'
import { ownSessionResource } from '../internals.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('generation-aware application projections', () => {
  it('bounds read-only observations and waits for them before releasing the owner', async () => {
    const f = await consumerFixture(); cleanup.push(() => f.close())
    const durable = new MemoryPeerStore(); let block = false, reads = 0, entered!: () => void, release!: () => void
    const reading = new Promise<void>(resolve => { entered = resolve }), blocked = new Promise<void>(resolve => { release = resolve })
    const store: PeerStore = { async get(key) { if (block) { reads++; entered(); await blocked }; return durable.get(key) }, put: (key, bytes) => durable.put(key, bytes) }
    const projection = await ApplicationProjection.open({ id: 'observe', version: '1', session: f.a, store, initial: () => 0, reduce: (n: number) => n + 1 })
    block = true
    const observations = Array.from({ length: 16 }, () => projection.inspect())
    await expect(projection.inspect()).rejects.toThrow('APPLICATION_CONSUMER_OBSERVATION_LIMIT')
    await reading
    let closed = false
    const closing = f.a.close().then(() => { closed = true })
    await Promise.resolve(); await Promise.resolve()
    expect(closed).toBe(false); expect(reads).toBe(16)
    release(); expect(await Promise.all(observations)).toEqual(Array.from({ length: 16 }, () => null))
    await closing; expect(closed).toBe(true)
  })

  it('settles an active durable checkpoint before the session releases its storage owner', async () => {
    const f = await consumerFixture(); cleanup.push(() => f.close())
    await publish(f.a, 'message', 'one', 'one')
    const durable = new MemoryPeerStore()
    let entered!: () => void, release!: () => void
    const writing = new Promise<void>(resolve => { entered = resolve }), blocked = new Promise<void>(resolve => { release = resolve })
    const store: PeerStore = { get: key => durable.get(key), async put(key, value) { entered(); await blocked; await durable.put(key, value) } }
    const projection = await ApplicationProjection.open({ id: 'close-order', version: '1', session: f.a, store, initial: () => 0, reduce: (n: number) => n + 1 })
    const checkpoint = projection.catchUp(); await writing
    expect(await projection.inspect()).toBeNull()
    let closed = false
    const closing = f.a.close().then(() => { closed = true })
    await Promise.resolve(); await Promise.resolve()
    expect(f.a.signal.aborted).toBe(true); expect(closed).toBe(false)
    expect(() => ownSessionResource(f.a, { close() {} })).toThrow()
    release(); await checkpoint; await closing
    expect(closed).toBe(true)
  })
  it('rebuilds the selected prefix as one coherent checkpoint and resumes it after reopening', async () => {
    const f = await consumerFixture(); cleanup.push(() => f.close())
    await publish(f.a, 'message', 'keep', 'keep')
    const link = await f.synchronize(), prefix = await f.b.recoveryPoint(); link.close()
    await publish(f.a, 'message', 'drop', 'drop')
    const held = await f.a.readView(); cleanup.push(() => held.release())
    const options = { id: 'messages', version: '1', session: f.a, store: new MemoryPeerStore(), topics: ['message'],
      batchTransactions: 1, initial: () => [] as string[], reduce: (state: string[], value: { readonly payload: unknown }) => [...state, String(value.payload)] }
    const projection = await ApplicationProjection.open(options); cleanup.push(() => projection.close())
    expect(await projection.catchUp()).toMatchObject({ state: ['keep', 'drop'], reset: false })
    await f.recover(prefix)
    const reset = await projection.catchUp()
    expect(reset).toMatchObject({ state: ['keep'], reset: true, revision: f.a.revision })
    expect(held.readEvents().events.map(e => e.payload)).toEqual(['keep', 'drop'])
    await projection.close()
    const reopened = await ApplicationProjection.open(options); cleanup.push(() => reopened.close())
    expect(await reopened.inspect()).toMatchObject({ state: ['keep'], cursor: reset.cursor, revision: reset.revision })
    expect(await reopened.catchUp()).toMatchObject({ state: ['keep'], reset: false })
  })

  it('reloads an ambiguously acknowledged commit and refuses competing or changed consumer identities', async () => {
    const f = await consumerFixture(); cleanup.push(() => f.close())
    await publish(f.a, 'message', 'one', 'one')
    const durable = new MemoryPeerStore(); let lose = true
    const store: PeerStore = { get: key => durable.get(key), async put(key, value) {
      await durable.put(key, value)
      if (lose) { lose = false; throw new Error('CHECKPOINT_ACK_LOST') }
    } }
    const options = { id: 'count', version: '1', session: f.a, store, initial: () => 0, reduce: (count: number) => count + 1 }
    const projection = await ApplicationProjection.open(options); cleanup.push(() => projection.close())
    await expect(ApplicationProjection.open(options)).rejects.toThrow('APPLICATION_CONSUMER_IN_USE')
    await expect(projection.catchUp()).rejects.toThrow('CHECKPOINT_ACK_LOST')
    expect(await projection.catchUp()).toMatchObject({ state: 1 })
    await projection.close()
    await expect(ApplicationProjection.open({ ...options, version: '2' })).rejects.toThrow('APPLICATION_CONSUMER_BINDING_MISMATCH')
    const reopened = await ApplicationProjection.open(options); cleanup.push(() => reopened.close())
    expect(await reopened.inspect()).toMatchObject({ state: 1 })
  })

  it('keeps the prior cache when a reset reducer fails and releases its captured view', async () => {
    const f = await consumerFixture(); cleanup.push(() => f.close())
    await publish(f.a, 'message', 'keep', 'keep')
    const link = await f.synchronize(), prefix = await f.b.recoveryPoint(); link.close()
    await publish(f.a, 'message', 'drop', 'drop')
    let fail = false
    const projection = await ApplicationProjection.open({ id: 'atomic-reset', version: '1', session: f.a, store: new MemoryPeerStore(),
      initial: () => 0, reduce: (count: number) => { if (fail) throw new Error('REDUCER_FAILED'); return count + 1 } })
    cleanup.push(() => projection.close())
    const before = await projection.catchUp()
    await f.recover(prefix); fail = true
    await expect(projection.catchUp()).rejects.toThrow('REDUCER_FAILED')
    expect(await projection.inspect()).toEqual({ revision: before.revision, cursor: before.cursor, state: 2 })
    fail = false
    expect(await projection.catchUp()).toMatchObject({ state: 1, reset: true })
    const view = await f.a.readView(); view.release()
  })
})

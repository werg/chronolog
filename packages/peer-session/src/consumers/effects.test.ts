import { MemoryPeerStore, type PeerStore } from '@chronolog/peer-generation'
import { afterEach, describe, expect, it } from 'vitest'

import { ApplicationEffectUncertainError, ApplicationEffectWorker, type ApplicationEffectOptions } from './effects.js'
import { consumerFixture, publish } from './test-support.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const payload = { intentId: 'mail-1', message: 'hello', requestedByLabel: 'administrator' }

async function setup() {
  const f = await consumerFixture(); cleanup.push(() => f.close())
  const calls: Array<{ id: string; author: string }> = []
  const options: ApplicationEffectOptions = { id: 'mail', version: '1', session: f.a, store: new MemoryPeerStore(), topics: ['intent'],
    intentKey: e => (e.payload as typeof payload).intentId, recovery: 'manual', authorize: ({ event }) => event.author === f.a.deviceId,
    dispatch: async context => { calls.push({ id: context.idempotencyKey, author: context.event.author }); return { delivered: true } } }
  return { ...f, calls, options }
}

describe('retained application effects', () => {
  it('retains completed external facts across recovery and deduplicates explicit logical-intent reapplication', async () => {
    const f = await setup(), before = await f.b.recoveryPoint()
    await publish(f.a, 'intent', payload, 'send-mail')
    let worker = await ApplicationEffectWorker.open(f.options); cleanup.push(() => worker.close())
    expect(await worker.processNext()).toMatchObject({ handled: 1 })
    const original = (await worker.inspect())[0]!
    expect(original).toMatchObject({ stage: 'completed', event: { operationId: 'send-mail', author: f.a.deviceId } })
    await worker.close(); await f.recover(before)
    worker = await ApplicationEffectWorker.open(f.options)
    await worker.processNext()
    expect((await worker.inspect(original.effectId))?.stage).toBe('completed')
    const link = await f.synchronize()
    const reapplied = await f.a.reapply('send-mail', 'record', { topic: 'intent', payload: JSON.stringify(payload) }, { operationId: 'restore-mail-intent' })
    await reapplied.applied({ signal: AbortSignal.timeout(5000) }); await link.synchronize()
    await worker.processNext()
    expect(f.calls).toEqual([{ id: original.effectId, author: f.a.deviceId }])
    expect((await worker.inspect(original.effectId))?.observedEvents.map(e => e.operationId)).toEqual(['send-mail', 'restore-mail-intent'])
    await publish(f.a, 'intent', { ...payload, intentId: 'mail-2' }, 'new-mail')
    await worker.processNext(); expect(f.calls).toHaveLength(2)
    await publish(f.a, 'intent', { ...payload, message: 'different provider action' }, 'conflicting-mail')
    await expect(worker.processNext()).rejects.toThrow('APPLICATION_EFFECT_INTENT_KEY_REUSED')
    expect(f.calls).toHaveLength(2)
  })

  it('reconciles an uncertain provider call after its source disappears without dispatching again', async () => {
    const f = await setup(), before = await f.b.recoveryPoint(); let reconciled = 0
    await publish(f.a, 'intent', payload, 'uncertain-mail')
    const options: ApplicationEffectOptions = { ...f.options, recovery: 'reconcile',
      dispatch: async context => { f.calls.push({ id: context.idempotencyKey, author: context.event.author }); throw new Error('PROVIDER_REPLY_LOST') },
      reconcile: async context => { reconciled++; expect(context.event.author).toBe(f.a.deviceId); return { kind: 'completed', result: { providerReceipt: 'receipt-1' } } } }
    const worker = await ApplicationEffectWorker.open(options)
    await expect(worker.processNext()).rejects.toBeInstanceOf(ApplicationEffectUncertainError)
    const uncertain = (await worker.inspect())[0]!
    expect(uncertain.stage).toBe('dispatching')
    await worker.close(); await f.recover(before)
    const reopened = await ApplicationEffectWorker.open(options); cleanup.push(() => reopened.close())
    await reopened.processNext()
    expect((await reopened.inspect(uncertain.effectId))?.stage).toBe('dispatching')
    expect(await reopened.reconcile(uncertain.effectId)).toMatchObject({ stage: 'completed', result: { providerReceipt: 'receipt-1' } })
    expect(f.calls).toHaveLength(1); expect(reconciled).toBe(1)
  })

  it('checks current authorization for saved undispatched intent and never trusts payload authority labels', async () => {
    const f = await setup(); await publish(f.a, 'intent', payload, 'saved-mail')
    const durable = new MemoryPeerStore(); let lost = true, allowed = true
    const store: PeerStore = { get: key => durable.get(key), async put(key, value) {
      await durable.put(key, value); if (lost) { lost = false; throw new Error('PREPARED_ACK_LOST') }
    } }
    const observed: string[] = []
    const options: ApplicationEffectOptions = { ...f.options, store, authorize: ({ event }) => {
      observed.push(event.author); expect(event.author).not.toBe((event.payload as typeof payload).requestedByLabel); return allowed
    } }
    const worker = await ApplicationEffectWorker.open(options)
    await expect(worker.processNext()).rejects.toThrow('PREPARED_ACK_LOST'); await worker.close()
    allowed = false
    const reopened = await ApplicationEffectWorker.open(options); cleanup.push(() => reopened.close())
    await reopened.processNext()
    expect((await reopened.inspect())[0]).toMatchObject({ stage: 'denied', reason: 'unauthorized' })
    expect(observed).toEqual([f.a.deviceId]); expect(f.calls).toEqual([])
  })

  it('bounds a non-cooperative provider call, retains uncertainty, and permits only a deliberate same-key retry', async () => {
    const f = await setup(); await publish(f.a, 'intent', payload, 'slow-mail')
    let finish!: () => void, calls = 0
    const blocked = new Promise<void>(resolve => { finish = resolve })
    const options: ApplicationEffectOptions = { ...f.options, recovery: 'idempotent', timeoutMs: 20,
      dispatch: async context => { calls++; f.calls.push({ id: context.idempotencyKey, author: context.event.author }); if (calls === 1) await blocked; return { delivered: true } } }
    const worker = await ApplicationEffectWorker.open(options)
    await expect(worker.processNext()).rejects.toBeInstanceOf(ApplicationEffectUncertainError)
    const entry = (await worker.inspect())[0]!
    await expect(worker.retry(entry.effectId)).rejects.toThrow('APPLICATION_EFFECT_PROVIDER_BUSY')
    expect(calls).toBe(1); await worker.close()
    finish(); await blocked; await Promise.resolve(); await Promise.resolve()
    const reopened = await ApplicationEffectWorker.open(options); cleanup.push(() => reopened.close())
    expect((await reopened.inspect(entry.effectId))?.stage).toBe('dispatching')
    expect(await reopened.retry(entry.effectId)).toMatchObject({ stage: 'completed' })
    expect(f.calls.map(c => c.id)).toEqual([entry.effectId, entry.effectId])
  })

  it('keeps a provider completion when its result command is abandoned and restores that result only by explicit reapplication', async () => {
    const f = await setup(); await publish(f.a, 'intent', payload, 'mail-with-result')
    const link = await f.synchronize(), beforeResult = await f.b.recoveryPoint(); link.close()
    const options: ApplicationEffectOptions = { ...f.options, publishResult: async (entry, { operationId, reapplyOf }) => {
      const input = { topic: 'completed', payload: JSON.stringify({ effectId: entry.effectId, result: entry.result }) }
      return reapplyOf === null ? f.a.command('record', input, { operationId }) : f.a.reapply(reapplyOf, 'record', input, { operationId })
    } }
    const worker = await ApplicationEffectWorker.open(options); cleanup.push(() => worker.close())
    await worker.processNext()
    const original = (await worker.inspect())[0]!
    expect(original.publications.at(-1)?.status).toBe('applied')
    await f.recover(beforeResult); await worker.processNext()
    expect((await worker.inspect(original.effectId))?.publications.at(-1)?.status).toBe('abandoned')
    expect(f.calls).toHaveLength(1)
    await f.synchronize()
    const restored = await worker.republish(original.effectId, { operationId: 'restore-provider-result', signal: AbortSignal.timeout(5000) })
    expect(restored.publications).toEqual([
      { ...original.publications[0], status: 'abandoned' },
      { operationId: 'restore-provider-result', reapplyOf: original.publications[0]!.operationId, status: 'applied' },
    ])
    expect(f.calls).toHaveLength(1)
  })
})

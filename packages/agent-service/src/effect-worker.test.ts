import { MemoryOperationStore } from '@chronolog/node-core'
import type { DurableOperationStore } from '@chronolog/node-core'
import type { EventPayload } from '@chronolog/protocol'
import { describe, expect, it } from 'vitest'

import { DurableEffectWorker, effectIdentity } from './effect-worker.js'
import type { EffectHandler, EffectWorkerOptions } from './effect-worker.js'
import type { EventReadOptions, FinalEventBatch, FinalEventSource } from './event-source.js'
import { ResidentAgentService } from './service.js'

function source(batches: readonly { readonly topic: string; readonly payloads: readonly EventPayload[] }[]): FinalEventSource {
  return {
    read: async (options: EventReadOptions = {}) => {
      const start = Number((options.cursor ?? 'c:0').slice(2)), end = Math.min(batches.length, start + (options.limit ?? 8))
      return {
        transactions: batches.slice(start, end).flatMap((batch, offset) => {
          const proposalId = `proposal-${start + offset}`
          return options.topics?.includes(batch.topic) === false ? [] : [{ proposalId,
            events: batch.payloads.map((payload, eventOrdinal) => ({ id: `${proposalId}:${eventOrdinal}`, proposalId,
              eventOrdinal, topic: batch.topic, payload })) }]
        }),
        scannedThrough: `c:${end}`, hasMore: end < batches.length, revision: `r:${end}`,
      }
    },
    async *subscribe(): AsyncIterable<FinalEventBatch> { throw new Error('test uses bounded reads') },
  }
}

function fixture(options: { readonly store?: DurableOperationStore; readonly recovery?: EffectHandler['recovery'] } = {}) {
  const calls: string[] = [], results: { operationId: string; payload: EventPayload }[] = []
  const configuration: EffectWorkerOptions = {
    sourceId: 'group/history', store: options.store ?? new MemoryOperationStore(),
    source: source([{ topic: 'jobs.requested', payloads: [{ command: 'first' }, { command: 'second' }] }]),
    handler: { id: 'jobs', version: '1', topics: ['jobs.requested'], recovery: options.recovery ?? 'manual',
      dispatch: async ({ effectId }) => { calls.push(effectId); return { ok: true } } },
    resultTopic: 'jobs.results',
    publisher: { publishFinal: async (_topic, payload, { operationId }) => { results.push({ operationId, payload }) } },
  }
  return { configuration, calls, results }
}

describe('durable final-intent workers', () => {
  it('checkpoints a whole final batch and does not dispatch again on restart', async () => {
    const f = fixture()
    const worker = await DurableEffectWorker.open(f.configuration)
    expect(await worker.processNext()).toEqual({ progressed: true, hasMore: false })
    expect(f.calls).toHaveLength(2)
    expect(f.results).toHaveLength(2)
    const reopened = await DurableEffectWorker.open(f.configuration)
    expect(await reopened.status()).toMatchObject({ cursor: 'c:1', revision: 'r:1', remaining: 0, effect: null })
    expect(await reopened.processNext()).toEqual({ progressed: false, hasMore: false })
    expect(f.calls).toHaveLength(2)
  })

  it('advances empty topic scans without inventing handled events', async () => {
    const f = fixture()
    const worker = await DurableEffectWorker.open({ ...f.configuration, source: source([{ topic: 'other', payloads: [null] }]) })
    await worker.processNext()
    expect((await worker.status()).cursor).toBe('c:1')
    expect(f.calls).toHaveLength(0)
  })

  it('leaves uncertain effects blocked after provider action and a failed result-state commit', async () => {
    const backing = new MemoryOperationStore()
    let writes = 0
    const store: DurableOperationStore = { get: (key) => backing.get(key), put: async (key, value) => {
      writes += 1
      if (writes === 4) throw new Error('interrupted result commit')
      await backing.put(key, value)
    } }
    const f = fixture({ store })
    const worker = await DurableEffectWorker.open(f.configuration)
    await expect(worker.processNext()).rejects.toThrow('interrupted result commit')
    expect(f.calls).toHaveLength(1)
    const reopened = await DurableEffectWorker.open(f.configuration)
    await expect(reopened.processNext()).rejects.toThrow('EFFECT_OUTCOME_UNCERTAIN')
    expect(f.calls).toHaveLength(1)
    const status = await reopened.status()
    expect(status.cursor).toBeNull()
    expect(status.effect?.stage).toBe('dispatching')
    await reopened.resolve(status.effect!.effectId, { kind: 'completed', result: { recovered: true } })
    await reopened.processNext()
    expect(f.calls).toHaveLength(2)
    expect(f.results[0]!.payload).toMatchObject({ result: { recovered: true } })
    expect((await reopened.status()).cursor).toBe('c:1')
  })

  it('retries an idempotent provider with the same key and does not repeat completed earlier events', async () => {
    const f = fixture({ recovery: 'idempotent' })
    const performed = new Map<string, EventPayload>()
    let calls = 0, failSecond = true
    const handler: EffectHandler = { ...f.configuration.handler, dispatch: async ({ idempotencyKey }) => {
      calls += 1
      const result = performed.get(idempotencyKey) ?? { providerReceipt: performed.size + 1 }
      performed.set(idempotencyKey, result)
      if (performed.size === 2 && failSecond) { failSecond = false; throw new Error('provider reply lost') }
      return result
    } }
    const configuration = { ...f.configuration, handler }
    await expect((await DurableEffectWorker.open(configuration)).processNext()).rejects.toThrow('EFFECT_OUTCOME_UNCERTAIN')
    expect(calls).toBe(2)
    await (await DurableEffectWorker.open(configuration)).processNext()
    expect(calls).toBe(3)
    expect(performed.size).toBe(2)
    expect(f.results).toHaveLength(2)
  })

  it('reconciles an uncertain provider outcome before retrying', async () => {
    const f = fixture({ recovery: 'reconcile' })
    let attempted = 0, reconciled = 0
    const configuration: EffectWorkerOptions = { ...f.configuration,
      source: source([{ topic: 'jobs.requested', payloads: [null] }]),
      handler: { ...f.configuration.handler,
        dispatch: async () => { attempted += 1; throw new Error('unknown result') },
        reconcile: async () => { reconciled += 1; return { kind: 'completed', result: { receipt: 'verified-provider-result' } } },
      } }
    await expect((await DurableEffectWorker.open(configuration)).processNext()).rejects.toThrow('EFFECT_OUTCOME_UNCERTAIN')
    await (await DurableEffectWorker.open(configuration)).processNext()
    expect(attempted).toBe(1)
    expect(reconciled).toBe(1)
    expect(f.results).toHaveLength(1)
  })

  it('retries exact result publication after a lost final response without calling the provider again', async () => {
    const f = fixture()
    let fail = true
    const attempts: { operationId: string; payload: EventPayload }[] = []
    const configuration: EffectWorkerOptions = { ...f.configuration,
      source: source([{ topic: 'jobs.requested', payloads: [null] }]),
      publisher: { publishFinal: async (_topic, payload, { operationId }) => {
        attempts.push({ operationId, payload: structuredClone(payload) })
        if (fail) { fail = false; throw new Error('publication response lost') }
      } } }
    await expect((await DurableEffectWorker.open(configuration)).processNext()).rejects.toThrow('publication response lost')
    await (await DurableEffectWorker.open(configuration)).processNext()
    expect(f.calls).toHaveLength(1)
    expect(attempts).toHaveLength(2)
    expect(attempts[1]).toEqual(attempts[0])
  })

  it('stops result finality waits after a sibling service failure and resumes the exact saved result', async () => {
    const f = fixture()
    let entered!: () => void, interrupt!: () => void
    const publishing = new Promise<void>((resolve) => { entered = resolve })
    const attempts: { operationId: string; payload: EventPayload }[] = []
    let publicationSignal: AbortSignal | undefined
    const configuration: EffectWorkerOptions = { ...f.configuration,
      source: { ...f.configuration.source, async *subscribe() { yield await f.configuration.source.read() } },
      publisher: { publishFinal: async (_topic: string, payload: EventPayload, input: { operationId: string; signal?: AbortSignal }) => {
        attempts.push({ operationId: input.operationId, payload: structuredClone(payload) })
        publicationSignal = input.signal
        entered()
        await new Promise<void>((_resolve, reject) => {
          interrupt = () => reject(new Error('publication interrupted'))
          input.signal?.addEventListener('abort', interrupt, { once: true })
          if (input.signal?.aborted) interrupt()
        })
      } } }
    const worker = await DurableEffectWorker.open(configuration)
    const service = new ResidentAgentService([
      { id: 'effects', run: (signal) => worker.run(signal) },
      { id: 'authority', run: async () => { await publishing; throw new Error('authority stopped') } },
    ])
    let finished = false
    const running = service.run().then(() => { finished = true; return null }, (error: unknown) => { finished = true; return error })
    await publishing
    await new Promise<void>((resolve) => setImmediate(resolve))
    try {
      expect(finished).toBe(true)
      expect(publicationSignal?.aborted).toBe(true)
    } finally { interrupt() }
    expect(await running).toMatchObject({ message: 'RESIDENT_TASK_FAILED: authority', cause: { message: 'authority stopped' } })
    expect(await worker.status()).toMatchObject({ cursor: null, remaining: 2, effect: { stage: 'result', result: { ok: true } } })
    expect(f.calls).toHaveLength(1)
    const reopened = await DurableEffectWorker.open({ ...f.configuration, publisher: {
      publishFinal: async (_topic, payload, input) => { attempts.push({ operationId: input.operationId, payload: structuredClone(payload) }) },
    } })
    await reopened.processNext()
    expect(attempts[1]).toEqual(attempts[0])
    expect(f.calls).toHaveLength(2)
    expect(await reopened.status()).toMatchObject({ cursor: 'c:1', remaining: 0, effect: null })
  })

  it('binds consumer progress to source, topic filter and handler version', async () => {
    const f = fixture()
    await (await DurableEffectWorker.open(f.configuration)).processNext()
    await expect(DurableEffectWorker.open({ ...f.configuration, sourceId: 'another-history' })).rejects.toThrow('CHECKPOINT_BINDING_MISMATCH')
    await expect(DurableEffectWorker.open({ ...f.configuration, handler: { ...f.configuration.handler, version: '2' } }))
      .rejects.toThrow('CHECKPOINT_BINDING_MISMATCH')
    await expect(DurableEffectWorker.open({ ...f.configuration, handler: { ...f.configuration.handler, topics: ['new-input'] } }))
      .rejects.toThrow('CHECKPOINT_BINDING_MISMATCH')
    expect(await effectIdentity('history', 'event', 'handler', '1')).not.toBe(await effectIdentity('history', 'event', 'handler', '2'))
  })

  it('stops a hung provider on service cancellation and preserves uncertain dispatch state for recovery', async () => {
    const f = fixture()
    const controller = new AbortController()
    let started!: () => void, finish!: (result: EventPayload) => void
    const entered = new Promise<void>((resolve) => { started = resolve })
    let providerSignal: AbortSignal | undefined
    const configuration: EffectWorkerOptions = { ...f.configuration,
      source: { ...f.configuration.source, async *subscribe() { yield await f.configuration.source.read() } },
      handler: { ...f.configuration.handler, dispatch: async ({ signal, deadlineAtMs }) => {
        providerSignal = signal
        expect(deadlineAtMs).toBeGreaterThan(Date.now())
        started()
        return new Promise<EventPayload>((resolve) => { finish = resolve })
      } } }
    const worker = await DurableEffectWorker.open(configuration)
    const running = worker.run(controller.signal)
    await entered
    controller.abort()
    await running
    expect(providerSignal?.aborted).toBe(true)
    expect(await worker.status()).toMatchObject({ cursor: null, remaining: 2, effect: { stage: 'dispatching' } })
    finish({ late: 'completed after shutdown' })
    await Promise.resolve()
    expect(f.results).toHaveLength(0)
    const reopened = await DurableEffectWorker.open(configuration)
    await expect(reopened.processNext()).rejects.toThrow('EFFECT_OUTCOME_UNCERTAIN')
  })

  it('bounds provider time without treating timeout as proof that no external effect happened', async () => {
    const f = fixture()
    let providerSignal: AbortSignal | undefined
    const worker = await DurableEffectWorker.open({ ...f.configuration,
      handler: { ...f.configuration.handler, timeoutMs: 10, dispatch: async ({ signal }) => {
        providerSignal = signal
        return new Promise(() => { /* Deliberately non-cooperative provider. */ })
      } } })
    await expect(worker.processNext()).rejects.toThrow('EFFECT_OUTCOME_UNCERTAIN')
    expect(providerSignal?.aborted).toBe(true)
    expect(await worker.status()).toMatchObject({ cursor: null, effect: { stage: 'dispatching' } })
    expect(f.results).toHaveLength(0)
  })
})

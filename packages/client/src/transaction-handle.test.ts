import { AsyncQueue, type RpcCallOptions, type RpcTransport, type SubmitTransactionResponse, type TransactionOutcome } from '@chronolog/rpc'
import { describe, expect, it } from 'vitest'

import { ChronologClient } from './client.js'
import { TransactionRejectedError } from './ownership.js'

const submission: SubmitTransactionResponse = {
  transactionId: 'tx-1', candidateDigest: 'digest', authorTimestampMs: '1', transactionNonce: 'nonce',
  executionManifestDigest: 'manifest', durableLocalAppend: true, publishedAt: '1970-01-01T00:00:00.001Z',
}

function outcome(revision: number, final: boolean, rejected = false): TransactionOutcome {
  return { transactionId: 'tx-1', phase: rejected ? 'rejected' : 'accepted',
    outcome: rejected ? { type: 'rejected', rejection: { code: 'constraint', statementIndex: 0 } } : { type: 'accepted' },
    eventSetRevision: String(revision), materializedRevision: String(revision),
    changedByReplay: rejected, admissible: true, final, observedAt: new Date(revision).toISOString() }
}

function fixture() {
  const values = new AsyncQueue<TransactionOutcome>()
  let opened = 0
  let cancelled = 0
  const transport = {
    async unary() { return submission },
    stream(_method: string, _request: unknown, options: RpcCallOptions) {
      return {
        async *[Symbol.asyncIterator]() {
          opened += 1
          const abort = () => { cancelled += 1; values.close() }
          options.signal?.addEventListener('abort', abort, { once: true })
          try { for await (const value of values) yield value }
          finally { options.signal?.removeEventListener('abort', abort) }
        },
      }
    },
  } as unknown as RpcTransport
  return { client: new ChronologClient({ groupId: 'group', transport }), values,
    get opened() { return opened }, get cancelled() { return cancelled } }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error('Expected stream state was not reached')
}

describe('TransactionHandle finality', () => {
  it.each([false, true])('accepted waits through replay and resolves only a final acceptance (final rejection: %s)', async rejected => {
    const f = fixture(), handle = await f.client.transaction(['SELECT 1'])
    let finished = false
    const accepted = handle.accepted().then(value => { finished = true; return { value } },
      (error: unknown) => { finished = true; return { error } })
    try {
      await waitFor(() => f.opened === 1)
      f.values.push(outcome(1, false))
      await expect(handle.settled()).resolves.toMatchObject({ final: false, outcome: { type: 'accepted' } })
      expect(finished).toBe(false)
      f.values.push(outcome(2, false, true))
      await waitFor(() => handle.outcome.getSnapshot().value?.eventSetRevision === '2')
      expect(finished).toBe(false)
      f.values.push(outcome(3, true, rejected))
      const result = await accepted
      if (rejected) {
        expect(result).toMatchObject({ error: { name: 'TransactionRejectedError', code: 'constraint', stepIndex: 0,
          reason: { kind: 'engine', code: 'constraint' } } })
        expect('error' in result && result.error).toBeInstanceOf(TransactionRejectedError)
      } else {
        expect(result).toMatchObject({ value: { final: true, eventSetRevision: '3', outcome: { type: 'accepted' } } })
        await expect(handle.accepted()).resolves.toMatchObject({ final: true, eventSetRevision: '3' })
      }
    } finally { handle.dispose(); await f.client.close() }
  })

  it('waits through speculative acceptance and replay until the applied final outcome', async () => {
    const fixture_ = fixture()
    const handle = await fixture_.client.transaction(['SELECT 1'])
    let finished = false
    const final = handle.final().then((value) => { finished = true; return value })
    const speculative = handle.settled()
    await waitFor(() => fixture_.opened === 1)
    fixture_.values.push(outcome(1, false))
    await expect(speculative).resolves.toMatchObject({ final: false, outcome: { type: 'accepted' } })
    expect(finished).toBe(false)
    fixture_.values.push(outcome(2, false, true))
    await waitFor(() => handle.outcome.getSnapshot().value?.eventSetRevision === '2')
    expect(finished).toBe(false)
    fixture_.values.push(outcome(3, true, true))
    await expect(final).resolves.toMatchObject({ final: true, outcome: { type: 'rejected' } })
    // A second final waiter can use the retained immutable result without
    // waiting for another event or disrupting other subscribers.
    await expect(handle.final()).resolves.toMatchObject({ eventSetRevision: '3', final: true })
    await fixture_.client.close()
  })

  it.each(['final', 'accepted'] as const)('%s aborts immediately while the outcome stream is quiet', async method => {
    const fixture_ = fixture()
    const handle = await fixture_.client.transaction(['SELECT 1'])
    const abort = new AbortController()
    const failure = new Error('caller stopped waiting')
    const waiting = expect(handle[method]({ signal: abort.signal })).rejects.toBe(failure)
    await waitFor(() => fixture_.opened === 1)
    abort.abort(failure)
    await waiting
    await waitFor(() => fixture_.cancelled === 1)
    await fixture_.client.close()
  })

  it.each(['final', 'accepted'] as const)('%s does not open a stream for a previously aborted wait and rejects on disposal', async method => {
    const fixture_ = fixture()
    const handle = await fixture_.client.transaction(['SELECT 1'])
    const failure = new Error('already aborted')
    await expect(handle[method]({ signal: AbortSignal.abort(failure) })).rejects.toBe(failure)
    expect(fixture_.opened).toBe(0)
    const waiting = expect(handle[method]()).rejects.toMatchObject({ code: 'transport_unavailable' })
    handle.dispose()
    await waiting
    await fixture_.client.close()
  })
})

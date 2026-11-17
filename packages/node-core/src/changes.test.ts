import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { ControlStore, MemoryControlStorePersistence } from '@chronolog/control-store'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { emit, generateEd25519KeyPair, program, sqlStatement } from '@chronolog/protocol'
import type { ChangeProgram, ViewChange } from '@chronolog/protocol'
import { DurableFeedStore, PortableFeedTransport, feedIdFromPublicKey, webFeedCrypto, webFeedSigner } from '@chronolog/records'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ChronologNode } from './node.js'
import { MemoryOperationStore } from './operations.js'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

async function fixture(profile: 'events' | 'sql' = 'events') {
  const identity = await generateEd25519KeyPair(), store = new MemoryOperationStore()
  const persistence = new MemoryControlStorePersistence(), clock = { now: 10_000 }
  const directory = profile === 'sql' ? await mkdtemp(join(tmpdir(), 'chronolog-view-changes-')) : undefined
  const open = async () => {
    const materialization = directory === undefined
      ? await createEventMaterializationRuntime({ store, namespace: 'changes' })
      : await (async () => {
        const { DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime } = await import('@chronolog/materializer-doltlite')
        return createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({ path: join(directory, 'application.db'),
          executionManifest: createDoltLiteExecutionManifest(), rootAdministrator: identity.publicKeyBytes }))
      })()
    const transport = new PortableFeedTransport({ store: await DurableFeedStore.open(store, webFeedCrypto), crypto: webFeedCrypto,
      signer: webFeedSigner(feedIdFromPublicKey(identity.publicKeyBytes), identity.privateKey) })
    const node = new ChronologNode({ identity, operationStore: store, transport, materialization,
      groupId: new Uint8Array(32).fill(1), membershipRevision: new Uint8Array(32).fill(2), validationPolicy: new Uint8Array(32).fill(3),
      controlStore: new ControlStore(persistence), clock: { now: () => clock.now },
      membership: { canWrite: () => true, canValidate: () => true, threshold: () => 1,
        watermarkPolicy: () => ({ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }),
        admissionScopes: () => [{ membershipRevision: new Uint8Array(32).fill(2), authorTimeAfterMs: -1n,
          policies: [{ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }] }] },
      validator: { capabilityId: new Uint8Array(32).fill(4), cutoffLagMs: 100 },
    })
    await node.start()
    return { node, materialization, transport }
  }
  let current = await open()
  cleanup.push(async () => { await current.node.close(); if (directory !== undefined) await rm(directory, { recursive: true, force: true }) })
  const sync = async () => {
    for (const record of await current.transport.history()) await current.node.ingest(record)
    await current.node.waitForIdle()
  }
  return {
    get current() { return current }, clock, sync,
    async publish(change: ChangeProgram, operationId: string, timestamp?: bigint) {
      const published = await current.node.publish({ program: change, operationId, ...(timestamp === undefined ? {} : { authorTimestampMs: timestamp }) })
      await sync()
      return published
    },
    async finalize() { clock.now += 1_000; await current.node.publishHeartbeat(); await sync() },
    async restart() { await current.node.close(); current = await open() },
  }
}

async function viewState(node: ChronologNode, view: 'local' | 'final'): Promise<ViewChange> {
  const captured = await node.readView({ view })
  try {
    expect(captured.readEvents().revision).toBe(captured.revision)
    return { view: captured.view, revision: captured.revision, finalRevision: captured.finalRevision }
  } finally { captured.release() }
}

describe('applied application view changes', () => {
  it('reports the current coherent token without acquiring SQL leases or scanning outcomes', async () => {
    const f = await fixture(), { node, materialization } = f.current
    const expected = await viewState(node, 'local')
    const capture = vi.spyOn(materialization.queries, 'captureRead'), outcome = vi.spyOn(materialization.queries, 'outcome')
    const iterator = node.changes({ view: 'local' })[Symbol.asyncIterator]()
    expect((await iterator.next()).value).toEqual(expected)
    expect(capture).not.toHaveBeenCalled(); expect(outcome).not.toHaveBeenCalled()
    let changed = false
    const pending = iterator.next().then(result => { changed = !result.done; return result })
    const oldNodeRevision = node.revision
    await node.publishHeartbeat(); await f.sync()
    expect(node.revision).toBeGreaterThan(oldNodeRevision)
    await Promise.resolve()
    expect(changed).toBe(false)
    expect(capture).not.toHaveBeenCalled(); expect(outcome).not.toHaveBeenCalled()
    await iterator.return?.()
    expect((await pending).done).toBe(true)
  })

  it('reports the published view without waiting for an in-progress replay', async () => {
    const f = await fixture(), { node, materialization } = f.current
    const expected = await viewState(node, 'local')
    let enter!: () => void, release!: () => void
    const entered = new Promise<void>(resolve => { enter = resolve })
    const held = new Promise<void>(resolve => { release = resolve })
    const materialize = materialization.coordinator.materialize.bind(materialization.coordinator)
    vi.spyOn(materialization.coordinator, 'materialize').mockImplementationOnce(async input => {
      enter(); await held; return materialize(input)
    })
    const publishing = f.publish(program(emit('conversation', 'held replay')), 'held-replay')
    await entered
    const iterator = node.changes({ view: 'local' })[Symbol.asyncIterator]()
    let received: ViewChange | undefined
    const pull = iterator.next().then(result => { received = result.value })
    try { await expect.poll(() => received).toEqual(expected) }
    finally { release(); await publishing; await pull; await iterator.return?.() }
  })

  it('keeps a published local view observable when a later final publication fails', async () => {
    const f = await fixture(), { node, materialization } = f.current
    const before = await viewState(node, 'local')
    const publishFinal = materialization.coordinator.publishFinal!.bind(materialization.coordinator)
    let failFinal = true
    materialization.coordinator.publishFinal = async (length: number) => {
      if (failFinal) throw new Error('FINAL_PUBLICATION_UNAVAILABLE')
      await publishFinal(length)
    }
    await node.publish({ operationId: 'local-before-final-failure', program: program(emit('conversation', 'published')) })
    try {
      await expect(f.sync()).rejects.toThrow('FINAL_PUBLICATION_UNAVAILABLE')
      const local = await node.readView({ view: 'local' })
      try {
        expect(local.revision).not.toBe(before.revision)
        expect(local.finalRevision).toBe(before.finalRevision)
        expect(local.readEvents().transactions.flatMap(item => item.events.map(event => event.payload))).toEqual(['published'])
        const iterator = node.changes({ view: 'local' })[Symbol.asyncIterator]()
        expect((await iterator.next()).value).toEqual({ view: 'local', revision: local.revision, finalRevision: local.finalRevision })
        await iterator.return?.()
      } finally { local.release() }
    } finally { failFinal = false; await node.waitForIdle() }
  })

  it('coalesces speculative changes, keeps the final stream quiet, and preserves tokens across reopen', async () => {
    const f = await fixture(), { node } = f.current
    const local = node.changes({ view: 'local' })[Symbol.asyncIterator](), final = node.changes()[Symbol.asyncIterator]()
    const initialLocal = (await local.next()).value!, initialFinal = (await final.next()).value!
    let finalChanged = false
    const finalPending = final.next().then(result => { finalChanged = !result.done; return result })
    for (let index = 0; index < 3; index++) await f.publish(program(emit('conversation', index)), `event-${index}`)
    const latestLocal = (await local.next()).value!
    expect(latestLocal).toEqual(await viewState(node, 'local'))
    expect(latestLocal.revision).not.toBe(initialLocal.revision)
    expect(latestLocal.finalRevision).toBe(initialFinal.revision)
    expect(finalChanged).toBe(false)
    expect(await viewState(node, 'final')).toEqual(initialFinal)
    const localPending = local.next()
    await f.finalize()
    expect(node.finalOrderLength).toBe(3)
    const finalChange = (await finalPending).value!
    expect(finalChange).toEqual(await viewState(node, 'final'))
    expect((await localPending).value).toEqual({ ...latestLocal, finalRevision: finalChange.revision })
    const localBefore = await viewState(node, 'local'), finalBefore = await viewState(node, 'final')
    await local.return?.(); await final.return?.()
    await f.restart()
    const reopened = f.current.node.changes()[Symbol.asyncIterator]()
    expect((await reopened.next()).value).toEqual(finalBefore)
    expect(await viewState(f.current.node, 'local')).toEqual(localBefore)
    await reopened.return?.()
  })

  it('invalidates SQL-only replay and changed outcomes even when no durable event is emitted', async () => {
    const f = await fixture('sql'), { node } = f.current
    const setup = await f.publish(program(sqlStatement('CREATE TABLE balance (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO balance (id, amount) VALUES (1, 100)')), 'setup', 10_000n)
    expect(node.outcome(setup.txId)).toMatchObject({ outcome: 'accepted', rejectionCode: null })
    const local = node.changes({ view: 'local' })[Symbol.asyncIterator]()
    await local.next()
    const later = await f.publish(program(
      sqlStatement("SELECT chronolog_assert((SELECT amount FROM balance WHERE id = 1) = 100, 'balance_changed')"),
      sqlStatement('UPDATE balance SET amount = 90 WHERE id = 1')), 'later', 10_020n)
    const accepted = (await local.next()).value!
    expect(node.outcome(later.txId)?.outcome).toBe('accepted')
    const before = await node.readView({ view: 'local' })
    await f.publish(program(sqlStatement('UPDATE balance SET amount = 80 WHERE id = 1')), 'earlier', 10_010n)
    const replayed = (await local.next()).value!
    expect(replayed.revision).not.toBe(accepted.revision)
    expect(replayed.finalRevision).toBe(accepted.finalRevision)
    expect(node.outcome(later.txId)?.outcome).toBe('rejected')
    const after = await node.readView({ view: 'local' })
    try {
      expect(before.query('SELECT amount FROM balance').rows).toEqual([[{ kind: 'integer', value: '90' }]])
      expect(after.query('SELECT amount FROM balance').rows).toEqual([[{ kind: 'integer', value: '80' }]])
      expect(after.revision).toBe(replayed.revision)
      expect(before.readEvents().transactions).toEqual([])
      expect(after.readEvents().transactions).toEqual([])
    } finally { before.release(); after.release() }
    await local.return?.()
  })

  it.each(['return', 'throw', 'abort', 'close'] as const)('releases an idle subscription on %s', async action => {
    const f = await fixture(), controller = new AbortController(), node = f.current.node
    const iterator = node.changes({ signal: controller.signal })[Symbol.asyncIterator]()
    await iterator.next()
    const pending = iterator.next()
    if (action === 'return') await iterator.return?.()
    else if (action === 'throw') await expect(iterator.throw?.(new Error('stop'))).rejects.toThrow('stop')
    else if (action === 'abort') controller.abort()
    else await node.close()
    expect((await pending).done).toBe(true)
    expect((await iterator.next()).done).toBe(true)
  })

  it('does not deliver an update to a paused subscriber after abort or close', async () => {
    const f = await fixture(), controller = new AbortController(), node = f.current.node
    const aborted = node.changes({ view: 'local', signal: controller.signal })[Symbol.asyncIterator]()
    const closed = node.changes({ view: 'local' })[Symbol.asyncIterator]()
    await aborted.next(); await closed.next()
    await f.publish(program(emit('conversation', 'new')), 'new')
    controller.abort(); await node.close()
    expect((await aborted.next()).done).toBe(true)
    expect((await closed.next()).done).toBe(true)
  })

  it('releases an initial subscription while materialization holds the node mutex', async () => {
    const f = await fixture(), { node, materialization } = f.current
    const materialize = materialization.coordinator.materialize.bind(materialization.coordinator)
    let entered!: () => void, release!: () => void
    const blocked = new Promise<void>(resolve => { entered = resolve })
    const resumed = new Promise<void>(resolve => { release = resolve })
    materialization.coordinator.materialize = async input => {
      entered()
      await resumed
      return materialize(input)
    }
    const progress = node.refreshMembership()
    await blocked
    const iterator = node.changes()[Symbol.asyncIterator]()
    const pending = iterator.next()
    let stopped = false
    const stopping = iterator.return!().then(() => { stopped = true })
    try {
      // No application work is released before checking consumer cancellation.
      await new Promise(resolve => setTimeout(resolve, 0))
      expect(stopped).toBe(true)
    } finally {
      release()
      await progress
      await stopping
      await pending
      materialization.coordinator.materialize = materialize
    }
    expect((await iterator.next()).done).toBe(true)
  })
})

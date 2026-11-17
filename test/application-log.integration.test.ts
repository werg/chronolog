import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { NativeBytesStore } from '@chronolog/records/native'

import { ChronologClient, DurableProjection, ProjectionConflictError, type ProjectionCheckpoint, type ProjectionStore } from '@chronolog/client'
import { ControlStore, NodeStateDatabase, SqliteControlStorePersistence } from '@chronolog/control-store'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { ChronologNode, type MembershipResolver } from '@chronolog/node-core'
import { bytesToBase64Url, bytesToHex, emit, equalBytes, generateEd25519KeyPair, program, sqlStatement, type ViewChange } from '@chronolog/protocol'
import { feedIdFromPublicKey, PortableFeedTransport } from '@chronolog/records'
import { InProcessRpcTransport, NodeRpcService } from '@chronolog/rpc'
import { FeedStore, nativeFeedCrypto } from '@chronolog/transport-ssb'
import { createChronologApplicationBackend } from '@chronolog/transport-tendriller'
import { afterEach, describe, expect, it } from 'vitest'

const cleanup: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })

describe('public application backend with native durable execution', () => {
  it('keeps SQL, events and view notifications on the published order while earlier admission awaits replay', async () => {
    const fixture = await nativeReplica('sql')
    const { node, backend, client } = fixture.current
    const local = backend.changes({ view: 'local' })[Symbol.asyncIterator]()
    const final = backend.changes({ view: 'final' })[Symbol.asyncIterator]()
    const initialLocal = (await local.next()).value!, initialFinal = (await final.next()).value!
    let finalChanged = false
    const finalNext = final.next().then(value => { finalChanged = true; return value })
    const setup = await backend.submit(program(
      sqlStatement('CREATE TABLE view_balance (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO view_balance (id, value) VALUES (1, 100)'),
    ), { operationId: 'view-setup' })
    expect((await terminal(client, setup.proposalId)).outcome).toEqual({ type: 'accepted' })
    const sqlOnly = (await local.next()).value!
    expect(sqlOnly.revision).not.toBe(initialLocal.revision)
    expect(sqlOnly.finalRevision).toBe(initialFinal.revision)
    const empty = await backend.readView({ view: 'local' })
    try { expect((await empty.readEvents()).transactions).toEqual([]) } finally { await empty.release() }

    const setupTime = node.candidateCore(new TextEncoder().encode(setup.proposalId))!.authorTimestampMs
    fixture.clock.now += 20
    const later = await backend.submit(program(
      sqlStatement("SELECT chronolog_assert((SELECT value FROM view_balance) = 100, 'changed')"),
      sqlStatement('UPDATE view_balance SET value = 90'), emit('view.balance', { value: 90 }),
    ), { operationId: 'view-later' })
    expect((await terminal(client, later.proposalId)).outcome).toEqual({ type: 'accepted' })
    const before = await backend.readView({ view: 'local' })
    fixture.pauseMaterialization()
    try {
      expect((await local.next()).value?.revision).toBe(before.revision)
      const nextApplied = local.next()
      const earlier = await node.publish({ operationId: 'view-earlier', authorTimestampMs: setupTime + 1n,
        program: program(sqlStatement('UPDATE view_balance SET value = 80'), emit('view.balance', { value: 80 })) })
      await waitFor(async () => node.controlStore.orderedTransactionIds().some(id => equalBytes(id, earlier.txId)))
      await expect(node.waitForIdle()).rejects.toThrow('TEST_MATERIALIZATION_PAUSED')
      const during = await backend.readView({ view: 'local' })
      try {
        expect(during.revision).toBe(before.revision)
        expect((await during.query('SELECT value FROM view_balance')).rows).toEqual([[90n]])
        expect((await during.readEvents()).transactions.map(value => value.proposalId)).toEqual([later.proposalId])
      } finally { await during.release() }
      fixture.resumeMaterialization()
      await node.waitForIdle()
      // Pending control replay is silent; the next invalidation names its applied view.
      const changed = (await nextApplied).value!
      const current = await backend.readView({ view: 'local' })
      try {
        expect(changed.revision).toBe(current.revision)
        expect(changed.revision).not.toBe(before.revision)
        expect((await current.query('SELECT value FROM view_balance')).rows).toEqual([[80n]])
        expect((await current.readEvents()).transactions.map(value => value.proposalId)).toEqual([earlier.txIdText])
      } finally { await current.release() }
      expect((await before.query('SELECT value FROM view_balance')).rows).toEqual([[90n]])
      expect((await before.readEvents()).transactions.map(value => value.proposalId)).toEqual([later.proposalId])
      expect(finalChanged).toBe(false)
      await fixture.finalize()
      const confirmed = (await finalNext).value!
      const finalView = await backend.readView({ view: 'final' })
      try { expect(confirmed.revision).toBe(finalView.revision) } finally { await finalView.release() }
      expect((await local.next()).value).toEqual({ view: 'local', revision: changed.revision, finalRevision: confirmed.revision })

      const nativeChanges = node.changes()[Symbol.asyncIterator]()
      await nativeChanges.next()
      const pending = nativeChanges.next()
      await nativeChanges.return?.()
      expect(await pending).toMatchObject({ done: true })
    } finally {
      fixture.resumeMaterialization()
      await before.release(); await local.return?.(); await final.return?.()
    }
  })

  it('commits SQL and emits atomically and recovers accepted/rejected operations after revocation and restart', async () => {
    const fixture = await nativeReplica('sql')
    const { client, backend, node } = fixture.current
    const setup = await backend.submit(program(
      sqlStatement('CREATE TABLE tasks (id TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT'),
      sqlStatement("INSERT INTO tasks (id, value) VALUES ('one', 0)"),
    ), { operationId: 'setup' })
    await terminal(client, setup.proposalId)

    const acceptedProgram = program(
      sqlStatement("UPDATE tasks SET value = 10 WHERE id = 'one'"),
      emit('tasks', { type: 'task.updated', taskId: 'one', value: 10 }),
      emit('conversation', { type: 'message.posted', messageId: 'm1', text: 'Updated', authorId: 'pretend-administrator' }),
    )
    const rejectedProgram = program(
      sqlStatement("UPDATE tasks SET value = 20 WHERE id = 'one'"),
      emit('tasks', { type: 'task.updated', taskId: 'one', value: 20 }),
      sqlStatement("SELECT chronolog_assert(0, 'claim_lost')"),
    )
    const accepted = await client.submit(acceptedProgram, { operationId: 'accepted' })
    const finalAcceptance = accepted.final()
    const rejected = await backend.submit(rejectedProgram, { operationId: 'rejected' })
    expect((await terminal(client, accepted.proposalId)).outcome).toEqual({ type: 'accepted' })
    expect((await terminal(client, rejected.proposalId)).outcome).toEqual({ type: 'rejected', rejection: { code: 'assert:claim_lost', statementIndex: 2 } })
    await fixture.finalize()
    expect(await finalAcceptance).toMatchObject({ final: true, outcome: { type: 'accepted' } })
    accepted.dispose()

    const core = node.candidateCore(new TextEncoder().encode(accepted.proposalId))!
    const origin = { kind: 'chronolog', groupId: bytesToBase64Url(core.groupId), authorId: bytesToHex(core.authorId),
      operationId: core.operationId, membershipRevision: bytesToBase64Url(core.membershipRevision), writerCapability: null,
      authorTimestampMs: core.authorTimestampMs.toString() }
    const view = await backend.readView({ view: 'final' })
    try {
      const rows = await view.query('SELECT value FROM tasks')
      const history = await view.readEvents()
      expect(rows).toMatchObject({ revision: view.revision, rows: [[10n]] })
      expect(history.revision).toBe(view.revision)
      expect(history.transactions).toEqual([{ proposalId: accepted.proposalId, events: [
        { id: `${accepted.proposalId}:0`, proposalId: accepted.proposalId, eventOrdinal: 0, topic: 'tasks', payload: { type: 'task.updated', taskId: 'one', value: 10 }, origin },
        { id: `${accepted.proposalId}:1`, proposalId: accepted.proposalId, eventOrdinal: 1, topic: 'conversation', payload: { type: 'message.posted', messageId: 'm1', text: 'Updated', authorId: 'pretend-administrator' }, origin },
      ] }])
      expect((await client.events.read()).transactions).toEqual(history.transactions)
      expect((await node.events.read()).transactions).toEqual(history.transactions)
    } finally { await view.release() }
    // Rejection stays auditable even though it contributes no effective events.
    expect(node.candidateCore(new TextEncoder().encode(rejected.proposalId))?.program).toEqual(rejectedProgram)
    expect(await backend.operations.get('accepted')).toMatchObject({ proposalId: accepted.proposalId, status: 'final', outcome: 'accepted' })
    expect(await backend.operations.get('rejected')).toMatchObject({ proposalId: rejected.proposalId, status: 'final', outcome: 'rejected', error: 'assert:claim_lost' })
    const retained = await fixture.current.feed.history()

    fixture.revokeWriter()
    await fixture.restart()
    expect(await fixture.current.node.isWritable()).toBe(false)
    const retryAccepted = await fixture.current.backend.submit(acceptedProgram, { operationId: 'accepted' })
    const retryRejected = await fixture.current.backend.submit(rejectedProgram, { operationId: 'rejected' })
    expect(retryAccepted.proposalId).toBe(accepted.proposalId)
    expect(retryRejected.proposalId).toBe(rejected.proposalId)
    expect(await fixture.current.backend.operations.get('accepted')).toMatchObject({ status: 'final', outcome: 'accepted' })
    expect(await fixture.current.backend.operations.get('rejected')).toMatchObject({ status: 'final', outcome: 'rejected', error: 'assert:claim_lost' })
    expect(retryAccepted).toMatchObject({ status: 'final', outcome: 'accepted' })
    expect(retryRejected).toMatchObject({ status: 'final', outcome: 'rejected', error: 'assert:claim_lost' })
    const recovered = await fixture.current.backend.events.read()
    expect(recovered.transactions[0]!.events.map(event => event.origin)).toEqual([origin, origin])
    await expect(fixture.current.backend.submit(program(emit('tasks', { changed: true })), { operationId: 'accepted' })).rejects.toMatchObject({ code: 'already_exists' })
    await expect(fixture.current.backend.submit(acceptedProgram, { operationId: 'new-after-revocation' })).rejects.toMatchObject({ code: 'failed_precondition' })
    expect(await fixture.current.feed.history()).toEqual(retained)
  })

  it('keeps SQL/events pinned through a speculative rebase and observes finality-only rejection changes', async () => {
    const fixture = await nativeReplica('sql')
    const { client, backend, node } = fixture.current
    const setup = await backend.submit(program(
      sqlStatement('CREATE TABLE balances (id INTEGER PRIMARY KEY, value INTEGER NOT NULL) STRICT'),
      sqlStatement('INSERT INTO balances (id, value) VALUES (1, 100)'),
    ), { operationId: 'setup' })
    expect((await terminal(client, setup.proposalId)).outcome).toEqual({ type: 'accepted' })
    const setupTime = node.candidateCore(new TextEncoder().encode(setup.proposalId))!.authorTimestampMs
    fixture.clock.now += 20
    const later = await client.submit(program(
      sqlStatement("SELECT chronolog_assert((SELECT value FROM balances) = 100, 'balance_changed')"),
      sqlStatement('UPDATE balances SET value = 90'),
      emit('tasks', { value: 90 }),
    ), { operationId: 'later' })
    let finalFinished = false
    const finalResult = later.final().then(value => { finalFinished = true; return value })
    await terminal(client, later.proposalId)
    const oldLocal = await backend.readView({ view: 'local' })
    const oldFinal = await backend.readView({ view: 'final' })
    const statuses = backend.operations.subscribe({ operationId: 'later', signal: AbortSignal.timeout(10_000) })[Symbol.asyncIterator]()
    try {
      expect((await statuses.next()).value).toMatchObject({ status: 'provisional', outcome: 'accepted' })
      expect((await later.local()).outcome).toEqual({ type: 'accepted' })
      expect(finalFinished).toBe(false)
      const afterRebase = statuses.next()
      const predecessor = await node.publish({ operationId: 'earlier-arrival', authorTimestampMs: setupTime + 1n,
        program: program(sqlStatement('UPDATE balances SET value = 80'), emit('tasks', { value: 80 })) })
      await terminal(client, predecessor.txIdText)
      expect((await afterRebase).value).toMatchObject({ status: 'provisional', outcome: 'rejected', error: 'assert:balance_changed' })
      expect(finalFinished).toBe(false)
      expect((await oldLocal.query('SELECT value FROM balances')).rows).toEqual([[90n]])
      expect((await oldLocal.readEvents()).transactions.map(transaction => transaction.proposalId)).toEqual([later.proposalId])
      expect((await oldLocal.readEvents()).revision).toBe(oldLocal.revision)
      expect((await oldFinal.query("SELECT name FROM sqlite_schema WHERE name = 'balances'")).rows).toEqual([])
      expect((await oldFinal.readEvents()).transactions).toEqual([])

      const current = await backend.readView({ view: 'local' })
      try {
        expect(current.revision).not.toBe(oldLocal.revision)
        expect((await current.query('SELECT value FROM balances')).rows).toEqual([[80n]])
        expect((await current.readEvents()).transactions.map(transaction => transaction.proposalId)).toEqual([predecessor.txIdText])
      } finally { await current.release() }

      const finalStatus = statuses.next()
      await fixture.finalize()
      expect((await finalStatus).value).toMatchObject({ status: 'final', outcome: 'rejected', error: 'assert:balance_changed' })
      expect(await finalResult).toMatchObject({ final: true, outcome: { type: 'rejected',
        rejection: { code: 'assert:balance_changed', statementIndex: 0 } } })
      const confirmed = await backend.readView({ view: 'final' })
      try {
        expect((await confirmed.query('SELECT value FROM balances')).rows).toEqual([[80n]])
        expect((await confirmed.readEvents()).transactions.map(transaction => transaction.proposalId)).toEqual([predecessor.txIdText])
      } finally { await confirmed.release() }
      // A previously captured final view cannot acquire later rows or events.
      expect((await oldFinal.readEvents()).transactions).toEqual([])
      expect((await oldFinal.query("SELECT name FROM sqlite_schema WHERE name = 'balances'")).rows).toEqual([])
    } finally { later.dispose(); await statuses.return?.(); await oldLocal.release(); await oldFinal.release() }
  })

  it('resumes complete event-only transactions after replica restart, including empty filtered progress', async () => {
    const fixture = await nativeReplica('events')
    const { backend, client } = fixture.current
    expect(backend.capabilities).not.toContain('sql')
    const spoofed = { messageId: 'a', origin: { authorId: 'forged-owner', writerCapability: 'forged-grant' }, role: 'administrator' }
    const first = await backend.submit(program(emit('conversation', spoofed), emit('conversation', { messageId: 'b' })), { operationId: 'first-pair' })
    await terminal(client, first.proposalId)
    await terminal(client, (await backend.events.publish('jobs', { jobId: 'unrelated' }, { operationId: 'unrelated' })).proposalId)
    await fixture.finalize()
    const read = backend.events.subscribe({ topics: ['conversation'], limit: 1, signal: AbortSignal.timeout(10_000) })[Symbol.asyncIterator]()
    const firstRead = await read.next()
    if (firstRead.done) throw new Error('Durable reader ended before catch-up')
    const delivered = firstRead.value
    expect(delivered.transactions).toHaveLength(1)
    expect(delivered.transactions[0]!.events.map(event => event.id)).toEqual([`${first.proposalId}:0`, `${first.proposalId}:1`])
    const core = fixture.current.node.candidateCore(new TextEncoder().encode(first.proposalId))!
    const firstEvent = delivered.transactions[0]!.events[0]!
    expect(firstEvent.payload).toEqual(spoofed)
    expect(firstEvent.origin).toEqual({ kind: 'chronolog', groupId: bytesToBase64Url(core.groupId), authorId: bytesToHex(core.authorId),
      operationId: core.operationId, authorTimestampMs: core.authorTimestampMs.toString(), membershipRevision: bytesToBase64Url(core.membershipRevision), writerCapability: null })
    expect(delivered.hasMore).toBe(true)
    await read.return?.()

    await fixture.restart()
    expect((await fixture.current.backend.events.read({ topics: ['conversation'] })).transactions[0]!.events[0]!.origin).toEqual(firstEvent.origin)
    const resumed = fixture.current.backend.events.subscribe({ topics: ['conversation'], cursor: delivered.scannedThrough, limit: 1, signal: AbortSignal.timeout(10_000) })[Symbol.asyncIterator]()
    try {
      const empty = (await resumed.next()).value!
      expect(empty.transactions).toEqual([])
      expect(empty.scannedThrough).not.toBe(delivered.scannedThrough)
      expect(empty.hasMore).toBe(false)
      const pending = resumed.next()
      const next = await fixture.current.backend.events.publish('conversation', { messageId: 'c' }, { operationId: 'third' })
      await terminal(fixture.current.client, next.proposalId)
      await fixture.finalize()
      const received = await pending
      if (received.done) throw new Error('Durable reader ended before the next final event')
      expect(received.value.transactions.map(transaction => transaction.proposalId)).toEqual([next.proposalId])
      await expect(fixture.current.backend.events.read({ topics: ['jobs'], cursor: empty.scannedThrough })).rejects.toThrow('EVENT_CURSOR_MISMATCH')
      const captured = await fixture.current.backend.readView({ view: 'final' })
      try {
        await expect(captured.query('SELECT 1')).rejects.toThrow('SQL_DISABLED_FOR_EVENT_PROFILE')
        expect((await captured.readEvents()).revision).toBe(captured.revision)
      } finally { await captured.release() }
    } finally { await resumed.return?.() }
  })

  it('invalidates captured views for SQL-only changes and finality without using event delivery', async () => {
    const fixture = await nativeReplica('sql'), { backend, client } = fixture.current
    const lifetime = AbortSignal.timeout(10_000)
    const local = backend.changes({ view: 'local', signal: lifetime })[Symbol.asyncIterator]()
    const final = backend.changes({ signal: lifetime })[Symbol.asyncIterator]()
    const initialLocal = (await local.next()).value!, initialFinal = (await final.next()).value!
    expect(initialLocal).toMatchObject({ view: 'local', finalRevision: initialFinal.revision })
    expect(initialFinal.view).toBe('final')
    try {
      const submitted = await backend.submit(program(sqlStatement('CREATE TABLE notifications (id INTEGER PRIMARY KEY) STRICT')), { operationId: 'sql-only' })
      await terminal(client, submitted.proposalId)
      const captured = await backend.readView({ view: 'local' })
      const localRevision = captured.revision
      await captured.release()
      const sqlChange = await nextChange(local, value => value.revision === localRevision)
      expect(sqlChange.finalRevision).toBe(initialFinal.revision)
      expect((await backend.events.read()).transactions).toEqual([])
      await fixture.finalize()
      const finalChange = await nextChange(final, value => value.revision !== initialFinal.revision)
      const localFinality = await nextChange(local, value => value.finalRevision === finalChange.revision)
      expect(localFinality.finalRevision).not.toBe(initialLocal.finalRevision)
      const confirmed = await backend.readView()
      expect(confirmed.revision).toBe(finalChange.revision)
      await confirmed.release()
    } finally { await local.return?.(); await final.return?.() }
  })

  it('replays from the committed projection checkpoint after an actual SQLite transaction rollback and reopen', async () => {
    const fixture = await nativeReplica('events')
    let store = new SqliteProjectionStore(join(fixture.directory, 'projection.sqlite'))
    cleanup.push(async () => { store.close() })
    const source = fixture.current.client.events
    const identity = { groupId: fixture.current.client.groupId, historyId: 'application-pilot', filterVersion: 'conversation/v1', reducerVersion: 'messages/v1' }
    const projection = (reducerVersion = identity.reducerVersion) => new DurableProjection({
      key: 'conversation', identity: { ...identity, reducerVersion }, topics: ['conversation'], source, store,
      initial: () => ({ messages: [] as string[] }),
      reduce: (state, event) => {
        if (event.payload !== null && typeof event.payload === 'object' && 'messageId' in event.payload && typeof event.payload.messageId === 'string') state.messages.push(event.payload.messageId)
        return state
      },
    })
    const first = await fixture.current.client.events.publish('conversation', { messageId: 'one' }, { operationId: 'one' })
    await terminal(fixture.current.client, first.proposalId); first.dispose(); await fixture.finalize()
    const committed = await projection().catchUp()
    expect(committed.state.messages).toEqual(['one'])
    const next = await fixture.current.client.events.publish('conversation', { messageId: 'two' }, { operationId: 'two' })
    await terminal(fixture.current.client, next.proposalId); next.dispose(); await fixture.finalize()
    store.failBeforeCommit = true
    await expect(projection().catchUp()).rejects.toThrow('injected before checkpoint commit')
    store.close()
    store = new SqliteProjectionStore(join(fixture.directory, 'projection.sqlite'))
    expect(await store.load('conversation')).toEqual(committed)
    const recovered = await projection().catchUp()
    expect(recovered.state.messages).toEqual(['one', 'two'])
    expect(recovered.cursor).not.toBe(committed.cursor)
    expect(await store.load('conversation')).toEqual(recovered)
    const rebuilt = await projection('messages/v2').catchUp()
    expect(rebuilt.state.messages).toEqual(['one', 'two'])
    expect(rebuilt.identity.reducerVersion).toBe('messages/v2')
    expect((await projection('messages/v2').catchUp()).state.messages).toEqual(['one', 'two'])
  })
})

async function nextChange(iterator: AsyncIterator<ViewChange>, matches: (value: ViewChange) => boolean): Promise<ViewChange> {
  for (;;) {
    const next = await iterator.next()
    if (next.done) throw new Error('View changes ended before the expected applied view')
    if (matches(next.value)) return next.value
  }
}

async function nativeReplica(profile: 'sql' | 'events') {
  const directory = await mkdtemp(join(tmpdir(), `chronolog-application-${profile}-`))
  const identity = await generateEd25519KeyPair()
  const groupId = new Uint8Array(32).fill(1), capabilityId = new Uint8Array(32).fill(4)
  const clock = { now: 10_000 }
  let materializationPaused = false
  let revokedAfter: bigint | undefined
  const membership: MembershipResolver = {
    canWrite: context => equalBytes(context.writerId, identity.publicKeyBytes) &&
      (revokedAfter === undefined || (context.authorTimestampMs !== undefined && context.authorTimestampMs <= revokedAfter)),
    canValidate: context => equalBytes(context.validatorId, identity.publicKeyBytes) && equalBytes(context.validatorCapability, capabilityId),
    threshold: () => 1,
    watermarkPolicy: () => ({ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }),
    admissionScopes: () => [{ membershipRevision: new Uint8Array(32).fill(2), authorTimeAfterMs: -1n,
      policies: [{ kind: 'threshold', policyId: 'one-validator', validatorIds: [identity.publicKeyBytes], threshold: 1 }] }],
  }
  const open = async () => {
    const store = new NativeBytesStore(join(directory, 'agent.sqlite'))
    const control = new NodeStateDatabase(join(directory, 'control.sqlite'))
    const feed = new PortableFeedTransport({ store: new FeedStore(join(directory, 'feed.sqlite')), crypto: nativeFeedCrypto,
      signer: { identity: feedIdFromPublicKey(identity.publicKeyBytes),
        sign: async bytes => new Uint8Array(await crypto.subtle.sign('Ed25519', identity.privateKey, Uint8Array.from(bytes))) } })
    const materialization = profile === 'events'
      ? await createEventMaterializationRuntime({ store, namespace: bytesToBase64Url(groupId) })
      : await (async () => {
        const { DeterministicMaterializer, createDoltLiteExecutionManifest, createDoltLiteMaterializationRuntime } = await import('@chronolog/materializer-doltlite')
        return createDoltLiteMaterializationRuntime(await DeterministicMaterializer.open({ path: join(directory, 'application.db'), executionManifest: createDoltLiteExecutionManifest(), rootAdministrator: identity.publicKeyBytes }))
      })()
    const node = new ChronologNode({ identity, groupId, membershipRevision: new Uint8Array(32).fill(2), validationPolicy: new Uint8Array(32).fill(3),
      transport: feed, operationStore: store, controlStore: new ControlStore(new SqliteControlStorePersistence(control)),
      materialization: { ...materialization, coordinator: { ...materialization.coordinator,
        async materialize(ordered) {
          if (materializationPaused) throw new Error('TEST_MATERIALIZATION_PAUSED')
          return materialization.coordinator.materialize(ordered)
        },
      } }, membership, clock: { now: () => clock.now }, validator: { capabilityId, cutoffLagMs: 100 } })
    await node.start()
    const client = new ChronologClient({ groupId: bytesToBase64Url(groupId), transport: new InProcessRpcTransport(new NodeRpcService({ node })) })
    const backend = createChronologApplicationBackend({ id: 'application-pilot', replica: client, sql: profile === 'sql' })
    let closed = false
    return { client, backend, node, feed, async close() {
      if (closed) return
      closed = true
      await client.close(); await node.close(); control.close(); store.close()
    } }
  }
  let current = await open()
  cleanup.push(async () => { await current.close(); await rm(directory, { recursive: true, force: true }) })
  return {
    directory, clock, get current() { return current },
    pauseMaterialization() { materializationPaused = true },
    resumeMaterialization() { materializationPaused = false },
    revokeWriter() { revokedAfter = BigInt(clock.now); clock.now += 1_000 },
    async restart() { await current.close(); current = await open() },
    async finalize() {
      clock.now += 1_000
      await current.node.publishHeartbeat()
      await waitFor(async () => { await current.node.waitForIdle(); return current.node.finalOrderLength === current.node.orderLength })
    },
  }
}

async function terminal(client: ChronologClient, proposalId: string) {
  let result = await client.getTransactionOutcome(proposalId)
  await waitFor(async () => { result = await client.getTransactionOutcome(proposalId); return result.outcome.type !== 'pending' })
  return result
}
async function waitFor(predicate: () => Promise<boolean>) {
  const deadline = Date.now() + 5_000
  while (!await predicate()) {
    if (Date.now() >= deadline) throw new Error('Application did not reach the expected durable state')
    await new Promise(resolve => setTimeout(resolve, 5))
  }
}

type ConversationState = { messages: string[] }
/** A real atomic consumer store exercises the public ProjectionStore contract. */
class SqliteProjectionStore implements ProjectionStore<ConversationState> {
  readonly #database: DatabaseSync
  #closed = false
  failBeforeCommit = false
  constructor(path: string) {
    this.#database = new DatabaseSync(path)
    this.#database.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS checkpoints (key TEXT PRIMARY KEY, generation INTEGER NOT NULL, body TEXT NOT NULL)')
  }
  async load(key: string): Promise<ProjectionCheckpoint<ConversationState> | null> {
    const row = this.#database.prepare('SELECT body FROM checkpoints WHERE key = ?').get(key) as { body: string } | undefined
    return row === undefined ? null : JSON.parse(row.body) as ProjectionCheckpoint<ConversationState>
  }
  async commit(key: string, expected: number | null, value: ProjectionCheckpoint<ConversationState>): Promise<void> {
    this.#database.exec('BEGIN IMMEDIATE')
    try {
      const previous = this.#database.prepare('SELECT generation FROM checkpoints WHERE key = ?').get(key) as { generation: number } | undefined
      if ((previous?.generation ?? null) !== expected) throw new ProjectionConflictError()
      this.#database.prepare('INSERT INTO checkpoints (key, generation, body) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET generation=excluded.generation, body=excluded.body').run(key, value.generation, JSON.stringify(value))
      if (this.failBeforeCommit) { this.failBeforeCommit = false; throw new Error('injected before checkpoint commit') }
      this.#database.exec('COMMIT')
    } catch (error) { this.#database.exec('ROLLBACK'); throw error }
  }
  close() { if (!this.#closed) { this.#closed = true; this.#database.close() } }
}

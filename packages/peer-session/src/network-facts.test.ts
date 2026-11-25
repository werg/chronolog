import { afterEach, expect, it, vi } from 'vitest'
import { encodeRecord, recordDigest, createSigningIdentity, signFinalityStatement } from '@chronolog/authority'
import { emit, program } from '@chronolog/protocol'
import { createFramedPeerConnectionPair } from './network-wire.js'
import { sessionFixture, eventDefinition } from './test-fixture.js'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { openApplicationDevice } from './device.js'
import { createApplicationSession } from './runtime.js'
import type { ApplicationPeerLink } from './network.js'
import { PeerFactKnowledge } from './network-facts.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { vi.restoreAllMocks(); for (const close of closes.splice(0).reverse()) await close() })
async function until(predicate: () => boolean): Promise<void> {
  const deadline = performance.now() + 10_000
  while (!predicate()) { if (performance.now() > deadline) throw new Error('FACT_CONVERGENCE_TIMEOUT'); await new Promise<void>(resolve => setImmediate(resolve)) }
}
it('bounds authenticated eight-participant 48KB fanout, concurrent edits and idle synchronization by new facts rather than full snapshots', async () => {
  const f = await sessionFixture({ count: 8 }), sessions = await Promise.all(f.identities.map((_, index) => f.open(index)))
  closes.push(...sessions.map(session => () => session.close()))
  const notifications = sessions.map(session => { const listener = vi.fn(); session.onFacts(listener); return listener })
  const merges = sessions.map(session => vi.spyOn(session, 'mergeFacts'))
  const started = performance.now(), links: ApplicationPeerLink[][] = []
  let frames = 0
  for (let index = 1; index < sessions.length; index++) {
    const pair = createFramedPeerConnectionPair()
    const counted = pair.map(connection => ({ ...connection, async send(...args: Parameters<typeof connection.send>) { frames++; await connection.send(...args) } }))
    links.push(await Promise.all([sessions[0]!.connectPeer({ connection: counted[0]! }), sessions[index]!.connectPeer({ connection: counted[1]! })]))
  }
  closes.push(...links.map(pair => async () => { await Promise.all(pair.map(link => link.close())) }))
  const operation = await sessions[0]!.submit({ program: program(...Array.from({ length: 3 }, () => emit('message', 'x'.repeat(8_000)))), operationId: 'large-init', authorTimestampMs: 1n })
  await operation.materialized()
  const envelopeBytes = encodeRecord(sessions[0]!.exportFacts().envelopes[0]).length
  expect(envelopeBytes).toBeGreaterThan(48_000)
  await until(() => sessions.every(session => session.exportFacts().retentions.length === 8))
  await Promise.all(links.flat().map(link => link.synchronize()))
  const initialBytes = links.flat().reduce((sum, link) => sum + link.stats.sentBytes, 0), initialFrames = frames
  expect(sessions.every(session => session.exportFacts().envelopes.length === 1)).toBe(true)
  expect(initialBytes).toBeLessThan(1_200_000)
  expect(initialFrames).toBeLessThan(250)
  expect(notifications.reduce((sum, listener) => sum + listener.mock.calls.length, 0)).toBeLessThan(100)
  // Every participant authors independently, while notifications and explicit
  // fences contend for the same reliable writer. No snapshot can overtake one.
  const operations = await Promise.all(sessions.map((session, index) => session.command('say', `concurrent-${index}`, { operationId: `edit-${index}`, authorTimestampMs: BigInt(index + 2) })))
  await Promise.all(operations.map(op => op.materialized()))
  await until(() => sessions.every(session => session.exportFacts().envelopes.length === 9 && session.exportFacts().retentions.length === 72))
  await Promise.all(links.flat().map(link => link.synchronize()))
  const totalBytes = links.flat().reduce((sum, link) => sum + link.stats.sentBytes, 0)
  expect(totalBytes - initialBytes).toBeLessThan(1_200_000)
  for (const session of sessions) { await session.retryMaterialization(); expect((await session.readEvents()).events).toHaveLength(11) }
  // An idle fence carries no historical envelope, and duplicate facts neither
  // emit notifications nor create new durable work.
  const before = links.flat().reduce((sum, link) => sum + link.stats.sentBytes, 0), notified = notifications.map(listener => listener.mock.calls.length)
  await Promise.all(links.flat().map(link => link.synchronize()))
  expect(links.flat().reduce((sum, link) => sum + link.stats.sentBytes, 0) - before).toBeLessThan(12_000)
  await sessions[0]!.mergeFacts(sessions[0]!.exportFacts())
  expect(notifications.map(listener => listener.mock.calls.length)).toEqual(notified)
  expect(merges.reduce((sum, spy) => sum + spy.mock.calls.length, 0)).toBeLessThan(800)
  expect(links.flat().every(link => !link.signal.aborted)).toBe(true)
  console.log(JSON.stringify({ envelopeBytes, initialBytes, initialFrames, totalBytes, frames, notifications: notifications.reduce((sum, listener) => sum + listener.mock.calls.length, 0), merges: merges.reduce((sum, spy) => sum + spy.mock.calls.length, 0), elapsedMs: Math.round(performance.now() - started) }))
})
it('reconciles disconnected edits on a new link and preserves pending-key bodies and later finality evidence', async () => {
  const identities = await Promise.all([createSigningIdentity(), createSigningIdentity()]), f = await sessionFixture({ identities, finalityPolicy: { kind: 'signed-frontier', signer: identities[0].publicKey, scopes: [{ id: '99'.repeat(32), authorTimeAfterMs: -1n }] } })
  const a = await f.open(0), b = await f.open(1, false); closes.push(() => a.close(), () => b.close())
  const connect = async () => { const pair = createFramedPeerConnectionPair(); const links = await Promise.all([a.connectPeer({ connection: pair[0] }), b.connectPeer({ connection: pair[1] })]); closes.push(async () => { await Promise.all(links.map(link => link.close())) }); return links }
  let links = await connect()
  const operation = await a.command('say', 'opaque but retained', { authorTimestampMs: 1n }); await operation.materialized(); await links[0].synchronize()
  await until(() => b.exportFacts().envelopes.length === 1)
  expect(b.inspectOperation(operation.id).pending).toBe('key')
  expect(await recordDigest(b.exportFacts().envelopes)).toBe(await recordDigest(a.exportFacts().envelopes))
  await Promise.all(links.map(link => link.close()))
  await b.authority.installEpochKey(0, f.epochKey); await b.retryMaterialization()
  const offline = await b.command('say', 'offline edit', { authorTimestampMs: 2n }); await offline.materialized()
  links = await connect(); await links[1].synchronize(); await a.retryMaterialization()
  expect((await a.readEvents()).events.map(event => event.payload)).toEqual(['opaque but retained', 'offline edit'])
  await a.finality.closeAuthorTime({ throughMs: 3n }); await links[0].synchronize(); await b.retryMaterialization()
  expect(b.inspectOperation(operation.id).finalized).toBe(true); expect(b.inspectOperation(offline.id).finalized).toBe(true)
  const facts = a.exportFacts(), corrupt = { ...facts, envelopes: facts.envelopes.map((envelope, index) => index === 0 ? { ...envelope, signature: '00'.repeat(64) } : envelope) }
  await expect(b.mergeFacts(corrupt)).rejects.toThrow('AUTHORITY_SIGNATURE_INVALID')
  const knowledge = new PeerFactKnowledge(); expect((await knowledge.missing(a.exportFacts())).envelopes).toHaveLength(2)
  await knowledge.remember(a.exportFacts()); expect(await knowledge.missing(a.exportFacts())).toEqual({ envelopes: [], retentions: [], finality: [] })
  // A changed signature is not knowledge of the original authenticated fact.
  expect((await knowledge.missing(corrupt)).envelopes).toHaveLength(1)
  vi.spyOn(a, 'exportFacts').mockReturnValue(corrupt)
  await a.operations.retry(operation.id)
  await until(() => links.every(link => link.signal.aborted))
  expect(b.exportFacts().envelopes).toEqual(facts.envelopes)
})
it('durably notifies new retention without replaying or rewriting materialization, and does no new work on duplicates', async () => {
  const f = await sessionFixture(), runtime = await createEventMaterializationRuntime({ store: f.stores[0]!, namespace: f.applicationId })
  const materialize = vi.spyOn(runtime.replay, 'materialize')
  const a = await createApplicationSession({ device: await openApplicationDevice({ store: f.stores[0]!, create: true, managedSigner: f.identities[0]! }), definition: eventDefinition, authority: f.bundle, epochKeys: new Map([[0, f.epochKey]]), createMaterializer: () => runtime }), b = await f.open(1)
  closes.push(() => a.close(), () => b.close())
  const operation = await a.command('say', 'retention is not execution', { authorTimestampMs: 1n }); await operation.materialized(); await a.readEvents()
  await b.mergeFacts(a.exportFacts()); const evidence = await b.retain(operation.id)
  const notification = vi.fn(), stop = a.onFacts(notification), writes = vi.spyOn(f.stores[0]!, 'put'), replays = materialize.mock.calls.length
  await a.mergeFacts({ envelopes: [], retentions: [evidence], finality: [] }); await a.readEvents()
  expect(materialize).toHaveBeenCalledTimes(replays); expect(writes).toHaveBeenCalledTimes(1); expect(notification).toHaveBeenCalledTimes(1)
  expect(operation.inspect().retained).toEqual([evidence])
  await a.mergeFacts({ envelopes: [], retentions: [evidence], finality: [] }); await a.readEvents()
  expect(materialize).toHaveBeenCalledTimes(replays); expect(writes).toHaveBeenCalledTimes(1); expect(notification).toHaveBeenCalledTimes(1)
  stop()
})
it('bounds proof knowledge across authenticated reordered/subset variants without mistaking a statement for its complete proof', async () => {
  const identities = await Promise.all(Array.from({ length: 4 }, () => createSigningIdentity())), f = await sessionFixture({ identities, finalityPolicy: { kind: 'fixed-validator', validators: identities.map(identity => identity.publicKey), threshold: 2, scopes: [{ id: '99'.repeat(32), authorTimeAfterMs: -1n }] } }), session = await f.open(0)
  closes.push(() => session.close())
  const votes = await session.finality.voteAuthorTime({ throughMs: 2n }), signatures = await Promise.all(votes.map(vote => Promise.all(identities.map(identity => signFinalityStatement(vote.payload, identity)))))
  const variants: number[][] = []
  const permute = (prefix: number[], rest: number[]): void => { if (prefix.length > 0) variants.push(prefix); for (const index of rest) permute([...prefix, index], rest.filter(other => other !== index)) }
  permute([], [0, 1, 2, 3]); expect(variants).toHaveLength(64)
  const knowledge = new PeerFactKnowledge()
  for (const indexes of variants) {
    const facts = { envelopes: [], retentions: [], finality: votes.map((vote, index) => ({ statement: vote.payload, signatures: indexes.map(signer => signatures[index]![signer]!) })) }
    // The cache never accepts an unverified peer claim in place of a merge.
    await session.mergeFacts(facts); await knowledge.remember(facts)
    expect(knowledge.size).toBe(votes.length)
  }
  expect(session.exportFacts().finality).toHaveLength(votes.length)
  const partial = { envelopes: [], retentions: [], finality: votes.map((vote, index) => ({ statement: vote.payload, signatures: [signatures[index]![0]!] })) }, complete = session.exportFacts()
  await knowledge.remember(partial)
  expect((await knowledge.missing(complete)).finality).toHaveLength(votes.length)
  await knowledge.remember(complete); expect((await knowledge.missing(complete)).finality).toHaveLength(0)
  expect(knowledge.size).toBe(votes.length + 1)
})
it('replicates a new quorum for an already-known finality statement over the same live link', async () => {
  const identities = await Promise.all([createSigningIdentity(), createSigningIdentity()]), f = await sessionFixture({ identities, finalityPolicy: { kind: 'fixed-validator', validators: identities.map(identity => identity.publicKey), threshold: 2, scopes: [{ id: '99'.repeat(32), authorTimeAfterMs: -1n }] } }), a = await f.open(0), b = await f.open(1), pair = createFramedPeerConnectionPair()
  closes.push(() => a.close(), () => b.close())
  const links = await Promise.all([a.connectPeer({ connection: pair[0] }), b.connectPeer({ connection: pair[1] })]); closes.push(async () => { await Promise.all(links.map(link => link.close())) })
  const operation = await a.command('say', 'quorum delta', { authorTimestampMs: 1n }); await operation.materialized(); await links[0].synchronize(); await b.retryMaterialization()
  const first = await a.finality.voteAuthorTime({ throughMs: 2n })
  await a.finality.submitProofs(first.map(vote => ({ statement: vote.payload, signatures: [vote] }))); await links[0].synchronize(); await b.retryMaterialization()
  expect(b.exportFacts().finality.every(proof => proof.signatures.length === 1)).toBe(true); expect(b.inspectOperation(operation.id).finalized).toBe(false)
  const second = await b.finality.voteAuthorTime({ throughMs: 2n })
  expect(await recordDigest(first.map(vote => vote.payload))).toBe(await recordDigest(second.map(vote => vote.payload)))
  await b.finality.submitProofs(second.map(vote => ({ statement: vote.payload, signatures: [vote] }))); await links[1].synchronize(); await a.retryMaterialization()
  expect(a.exportFacts().finality.every(proof => proof.signatures.length === 2)).toBe(true)
  expect(a.inspectOperation(operation.id).finalized).toBe(true); expect(b.inspectOperation(operation.id).finalized).toBe(true)
})
it('keeps an explicit synchronization fence behind blocked and concurrent delta publication', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1), pair = createFramedPeerConnectionPair()
  closes.push(() => a.close(), () => b.close())
  let hold = false, blocked = false, release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const connection = { ...pair[0], async send(...args: Parameters<typeof pair[0]['send']>) {
    if (hold) { blocked = true; await gate }
    await pair[0].send(...args)
  } }
  closes.push(async () => { release() })
  const links = await Promise.all([a.connectPeer({ connection }), b.connectPeer({ connection: pair[1] })])
  closes.push(async () => { release(); await Promise.all(links.map(link => link.close())) })
  await Promise.all(links.map(link => link.synchronize()))
  hold = true
  const first = await a.command('say', 'first', { authorTimestampMs: 1n })
  await until(() => blocked)
  const second = await a.command('say', 'second', { authorTimestampMs: 2n })
  let acknowledged = false
  const fence = links[0].synchronize().then(() => { acknowledged = true })
  await new Promise<void>(resolve => setImmediate(resolve))
  expect(acknowledged).toBe(false); expect(b.inspectOperation(first.id).stored).toBe(false)
  hold = false; release(); await fence
  expect(b.inspectOperation(first.id).stored).toBe(true); expect(b.inspectOperation(second.id).stored).toBe(true)
  await b.retryMaterialization(); expect((await b.readEvents()).events.map(event => event.payload)).toEqual(['first', 'second'])
})

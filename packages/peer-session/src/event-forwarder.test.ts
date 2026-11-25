import { afterEach, expect, it } from 'vitest'
import { createSigningIdentity } from '@chronolog/authority'
import { emit, program } from '@chronolog/protocol'
import { sessionFixture } from './test-fixture.js'
import { forwardSessionEvents, type EventDeliveryProjection, type EventProjection } from './event-forwarder.js'
import { signOperation, unwrapOperation, wrapOperation } from './operation-codec.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
function checkpoint() { let state: string | undefined; return { load: () => state, save(value: string) { state = value }, get state() { return state } } }
it('rederives effective event sets, retracts late-rejected proposals, exports independent facts and resumes acknowledged IDs', async () => {
  const f = await sessionFixture({ count: 2 }), session = await f.open(0), peer = await f.open(1); closes.push(() => session.close(), () => peer.close()); const durable = checkpoint(), abort = new AbortController(), active = new Map<string, unknown>(), deliveries: Array<{ change: string; id: string; value: unknown; retained: number; outcome: string | null }> = []
  const running = forwardSessionEvents({ session, checkpoint: durable, signal: abort.signal, project: event => ({ name: 'message', payload: event.payload, observation: { finalized: true } }), deliver(projection, event) {
    const pending = JSON.parse(durable.state!) as { entries: Record<string, { acknowledged: boolean }> }; expect(pending.entries[event.id]?.acknowledged).toBe(false)
    expect(projection.observation.finalized).toBe(false)
    if (projection.change === 'retract') active.delete(event.id); else active.set(event.id, projection.payload)
    deliveries.push({ change: projection.change, id: event.id, value: projection.payload, retained: projection.observation.retained.length, outcome: projection.observation.materialized?.outcome ?? null })
  } }); void running.catch(() => undefined)
  const late = await session.command('say', 'late accepted', { operationId: 'same-handle', authorTimestampMs: 10n }); await late.materialized(); await expect.poll(() => active.size).toBe(1)
  await peer.mergeFacts(session.exportFacts()); await peer.retain(late.id); await session.mergeFacts(peer.exportFacts()); await expect.poll(() => deliveries.some(delivery => delivery.id.startsWith(late.id) && delivery.retained === 1)).toBe(true)
  const decoded = await unwrapOperation(session.exportFacts().envelopes[0]!, session.authority); if (typeof decoded === 'string') throw new Error(decoded)
  const body = await signOperation({ ...decoded.core, authorTimestampMs: 5n, nonce: crypto.getRandomValues(new Uint8Array(16)), program: program(emit('message', 'earlier canonical winner')) }, f.identities[0]!), envelope = await wrapOperation(body, f.identities[0]!, 0, f.epochKey)
  await session.mergeFacts({ envelopes: [envelope], retentions: [], finality: [] }); await session.retryMaterialization()
  await expect.poll(() => [...active.values()]).toEqual(['earlier canonical winner']); expect(deliveries.some(delivery => delivery.change === 'retract' && delivery.id.startsWith(late.id) && delivery.outcome === 'rejected')).toBe(true)
  abort.abort(new Error('stop exporter')); await expect(running).rejects.toThrow('stop exporter')
  const count = deliveries.length, resumedAbort = new AbortController(); let projected = 0
  const resumed = forwardSessionEvents({ session, checkpoint: durable, signal: resumedAbort.signal, project(event) { projected++; return { name: 'message', payload: event.payload, observation: { finalized: true } } }, deliver() { deliveries.push({ change: 'unexpected', id: '', value: null, retained: 0, outcome: null }) } }); void resumed.catch(() => undefined)
  await expect.poll(() => projected).toBeGreaterThan(0); await new Promise<void>(resolve => setImmediate(resolve)); expect(deliveries).toHaveLength(count); resumedAbort.abort(new Error('stop resumed')); await expect(resumed).rejects.toThrow('stop resumed')
})
it('persists uncertain delivery before callback and retries the same stable event/revision after a lost acknowledgement', async () => {
  const f = await sessionFixture({ count: 1 }), session = await f.open(0); closes.push(() => session.close()); await (await session.command('say', 'external delivery', { authorTimestampMs: 1n })).materialized()
  const durable = checkpoint(), delivered: Array<{ id: string; revision: string }> = []
  await expect(forwardSessionEvents({ session, checkpoint: durable, project: event => ({ name: 'message', payload: event.payload }), deliver(_projection, event, batch) { delivered.push({ id: event.id, revision: batch.revision.digest }); throw new Error('ACK_REPLY_LOST') } })).rejects.toThrow('ACK_REPLY_LOST')
  const pending = JSON.parse(durable.state!) as { entries: Record<string, { acknowledged: boolean }> }; expect(Object.values(pending.entries)[0]?.acknowledged).toBe(false)
  const abort = new AbortController(), resumed = forwardSessionEvents({ session, checkpoint: durable, signal: abort.signal, project: event => ({ name: 'message', payload: event.payload }), deliver(_projection, event, batch) { delivered.push({ id: event.id, revision: batch.revision.digest }) } }); void resumed.catch(() => undefined)
  await expect.poll(() => delivered.length).toBe(2); expect(delivered[1]).toEqual(delivered[0]); abort.abort(new Error('done')); await expect(resumed).rejects.toThrow('done')
})
it('final mode uses verified final reads and none mode explicitly refuses a final exporter', async () => {
  const identity = await createSigningIdentity(), f = await sessionFixture({ identities: [identity], finalityPolicy: { kind: 'signed-frontier', signer: identity.publicKey, scopes: [{ id: 'ab'.repeat(32), authorTimeAfterMs: -1n }] } }), session = await f.open(0); closes.push(() => session.close()); await (await session.command('say', 'closed', { authorTimestampMs: 1n })).materialized(); await session.finality.closeAuthorTime({ throughMs: 2n })
  const delivered: EventDeliveryProjection<EventProjection>[] = [], abort = new AbortController(), running = forwardSessionEvents({ session, checkpoint: checkpoint(), view: 'final', signal: abort.signal, project: event => ({ name: 'message', payload: event.payload }), deliver(projection, _event, batch) { expect(batch.revision.view).toBe('final'); delivered.push(projection) } }); void running.catch(() => undefined)
  await expect.poll(() => delivered.length).toBe(1); expect(delivered[0]?.observation.finalized).toBe(true); abort.abort(new Error('done')); await expect(running).rejects.toThrow('done')
  const noFinality = await sessionFixture({ count: 1 }), local = await noFinality.open(0); closes.push(() => local.close())
  await expect(forwardSessionEvents({ session: local, checkpoint: checkpoint(), view: 'final', project: event => ({ name: 'message', payload: event.payload }), deliver() {} })).rejects.toMatchObject({ code: 'FINALITY_UNSUPPORTED' })
})

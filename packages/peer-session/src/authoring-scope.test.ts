import { afterEach, expect, it, vi } from 'vitest'
import { createEventMaterializationRuntime } from '@chronolog/materializer'
import { recordDigest } from '@chronolog/authority'
import { sessionFixture, eventDefinition } from './test-fixture.js'
import { createScopedApplicationTools } from './tools.js'
import { createApplicationSession } from './runtime.js'
import { openApplicationDevice } from './device.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close(); vi.restoreAllMocks() })
it('explicit local and remote int64 maxima never poison default author timestamp allocation, including restart', async () => {
  const f = await sessionFixture(), a = await f.open(0), b = await f.open(1); closes.push(() => a.close(), () => b.close()); vi.spyOn(Date, 'now').mockReturnValue(100)
  const maximum = (1n << 63n) - 1n, remote = await a.command('say', 'remote future', { operationId: 'remote-maximum', authorTimestampMs: maximum }); await remote.materialized(); await b.mergeFacts(a.exportFacts()); await b.retryMaterialization()
  const first = await b.command('say', 'default after remote', { operationId: 'default-1' }); await first.materialized()
  const own = await b.command('say', 'own future', { operationId: 'own-maximum', authorTimestampMs: maximum }); await own.materialized(); const second = await b.command('say', 'default after own', { operationId: 'default-2' }); await second.materialized()
  expect(b.exportFacts().envelopes.filter(envelope => [first.id, second.id].includes(envelope.payload.proposalId)).map(envelope => envelope.payload.authorTimestampMs)).toEqual([100n, 101n])
  expect(b.exportFacts().envelopes.filter(envelope => [remote.id, own.id].includes(envelope.payload.proposalId)).every(envelope => envelope.payload.authorTimestampMs === maximum)).toBe(true)
  await b.close(); const reopened = await f.open(1); closes.push(() => reopened.close()); const third = await reopened.command('say', 'durable default counter', { operationId: 'default-3' }); await third.materialized(); expect(reopened.exportFacts().envelopes.find(envelope => envelope.payload.proposalId === third.id)?.payload.authorTimestampMs).toBe(102n)
})
it('scoped tools derive exactly one caller identity then apply a trusted idempotent physical binding namespace', async () => {
  const f = await sessionFixture({ count: 1 }), session = await f.open(0); closes.push(() => session.close())
  const scopeOperationId = (raw: string): string => raw.startsWith('native_binding_') ? raw : `native_binding_${raw}`
  const facade = { definition: session.definition, applicationId: session.applicationId, identity: session.identity, scopeOperationId, operations: session.operations, readView: session.readView.bind(session), query: session.query.bind(session), command: (name: string, input: unknown, options: { operationId?: string } = {}) => session.command(name, input, { operationId: scopeOperationId(options.operationId ?? crypto.randomUUID()) }) }
  const tools = createScopedApplicationTools(facade, { commands: ['say'], queries: ['messages'] }), expected = await tools.operationId('raw', { caller: 'trusted-caller' })
  const result = await tools.execute({ kind: 'command', name: 'say', input: 'scoped', operationId: 'raw' }, { caller: 'trusted-caller' }) as { state: { operationId: string; proposalId: string }; operationReference: { operationId: string } }
  expect(result.state.operationId).toBe(expected); expect(result.operationReference.operationId).toBe(expected); expect(scopeOperationId(expected)).toBe(expected)
  await session.operations.get(expected)!.materialized(); const before = await recordDigest(session.exportFacts()); let wakes = 0; const stop = session.onFacts(() => { wakes++ })
  await tools.execute({ kind: 'retry', operationId: 'raw' }, { caller: 'trusted-caller' }); stop(); expect(wakes).toBe(1); expect(await recordDigest(session.exportFacts())).toBe(before)
  await expect(tools.execute({ kind: 'inspect', operationId: 'raw' }, { caller: 'other-caller' })).rejects.toThrow('APPLICATION_TOOL_OPERATION_FORBIDDEN')
  const named = await tools.execute({ kind: 'query', name: 'messages', input: null }, { caller: 'trusted-caller' }) as { applicationId: string; revision: { digest: string } }; expect(named.applicationId).toBe(f.applicationId); expect(named.revision.digest).toHaveLength(64)
})
it('common operation retry reopens a transiently unavailable engine without changing signed intent bytes', async () => {
  const f = await sessionFixture({ count: 1 }); let fail = true
  const session = await createApplicationSession({ device: await openApplicationDevice({ store: f.stores[0]!, create: true, managedSigner: f.identities[0]! }), definition: eventDefinition, authority: f.bundle, epochKeys: new Map([[0, f.epochKey]]), createMaterializer: ({ store }) => { if (fail) throw new Error('ENGINE_TEMPORARILY_UNAVAILABLE'); return createEventMaterializationRuntime({ store, namespace: f.applicationId }) } }); closes.push(() => session.close())
  const operation = await session.command('say', 'durably stored', { operationId: 'retry-engine', authorTimestampMs: 1n }), intent = await recordDigest(session.exportFacts().envelopes)
  await expect(session.retryMaterialization()).rejects.toThrow('ENGINE_TEMPORARILY_UNAVAILABLE'); fail = false
  const retry = await session.operations.retry(operation.operationId); expect(retry.id).toBe(operation.id); expect((await retry.materialized()).outcome).toBe('accepted'); expect(await recordDigest(session.exportFacts().envelopes)).toBe(intent)
})
it('reuses one bounded prepared signature after a precommit store error without claiming it was durable', async () => {
  const f = await sessionFixture({ count: 1 }), store = f.stores[0]!, put = store.put.bind(store); let blocked = true, firstBytes: Uint8Array | undefined
  store.put = async (key, bytes) => { if (blocked && key.startsWith('operation-set/') && new TextDecoder().decode(bytes).includes('prepared-once')) { firstBytes ??= bytes.slice(); throw new Error('PRECOMMIT_UNCERTAIN') }; await put(key, bytes) }
  const session = await f.open(0); closes.push(() => session.close()); vi.spyOn(Date, 'now').mockReturnValue(100)
  await expect(session.command('say', 'reviewed intent', { operationId: 'prepared-once' })).rejects.toMatchObject({ message: 'PRECOMMIT_UNCERTAIN', operationId: 'prepared-once', durability: 'unconfirmed' }); expect(session.operations.get('prepared-once')).toBeNull()
  await expect(session.command('say', 'changed input', { operationId: 'prepared-once' })).rejects.toThrow('OPERATION_ID_REUSED')
  vi.mocked(Date.now).mockReturnValue(200); blocked = false
  const operation = await session.command('say', 'reviewed intent', { operationId: 'prepared-once' }); expect(operation.stored).toBe(true); expect((await operation.materialized()).outcome).toBe('accepted')
  expect(session.exportFacts().envelopes[0]?.payload.authorTimestampMs).toBe(100n)
  const { decodeRecord } = await import('@chronolog/authority'), prepared = decodeRecord<{ envelopes: unknown }>(firstBytes!)
  expect(await recordDigest(session.exportFacts().envelopes)).toBe(await recordDigest(prepared.envelopes))
})

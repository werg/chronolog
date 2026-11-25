import { MessageChannel } from 'node:worker_threads'
import { afterEach, expect, it } from 'vitest'
import { createApplicationOwner } from './session-owner.js'
import { connectApplicationOwner } from './worker-application.js'
import { sessionFixture } from './test-fixture.js'
import type { ApplicationWorkerEndpoint } from './worker-transport.js'
import type { ApplicationAttachmentPolicy, ApplicationOwnerOptions } from './owner-types.js'
import type { ApplicationEventBatch } from './session-types.js'
import { createLiveView } from './live-view.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
async function fixture(policy: ApplicationAttachmentPolicy = {}, ownerOptions: ApplicationOwnerOptions = {}) {
  const f = await sessionFixture({ count: 1 }), session = await f.open(0), owner = createApplicationOwner(session, ownerOptions), channel = new MessageChannel()
  owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, policy)
  const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId, context: { viewId: 'claimed-view' } })
  closes.push(() => owner.close(), () => client.detach()); return { ...f, session, owner, client, channel }
}
it('real MessagePort facade separates durable submission, materialized reads, named-query revisions and none finality', async () => {
  const f = await fixture(), operation = await f.client.command('say', 'from facade', { operationId: 'facade' })
  expect(operation.stored).toBe(true); expect((await operation.materialized()).outcome).toBe('accepted'); expect((await operation.inspect()).author).toBe(f.client.identity.publicKey)
  const named = await f.client.query('messages', null); expect(named.applicationId).toBe(f.applicationId); expect((named.value as ApplicationEventBatch).events[0]?.payload).toBe('from facade')
  await expect(operation.finalized()).rejects.toMatchObject({ code: 'FINALITY_UNSUPPORTED' })
  const projection = createLiveView(f.client, async view => (await view.readEvents()).events.map(event => event.payload)); closes.push(async () => projection.close()); expect((await projection.ready()).value).toEqual(['from facade'])
  const view = await f.client.readView(); expect(view.applicationId).toBe(f.applicationId); await view.release(); await expect(view.readEvents()).rejects.toThrow('READ_VIEW_RELEASED')
  expect(f.client.endpoint?.evidence).toBe('owner-bound'); expect(f.client.endpoint?.contextEvidence).toBe('caller-asserted'); expect((await f.client.endpoints())[0]?.endpointId).toBe(f.client.endpoint?.endpointId)
  expect(await f.client.readAuthority()).toEqual(f.session.authority.bundle()); expect('epochKeys' in await f.client.readAuthority()).toBe(false)
})
it('captured reads cannot bypass named-query allowlists or independent event capabilities', async () => {
  const f = await fixture({ capabilities: ['queries'], queries: [] }), op = await f.session.command('say', 'private'); await op.materialized()
  await expect(f.client.query('messages', null)).rejects.toThrow('ENDPOINT_QUERY_FORBIDDEN'); await expect(f.client.readEvents()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  const captured = await f.client.readView(); await expect(captured.query('SELECT * FROM secret')).rejects.toThrow('ENDPOINT_RAW_SQL_FORBIDDEN'); await expect(captured.readEvents()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN'); await captured.release()
  await expect(f.client.readAuthority()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
})
it('reserves captured view quota before asynchronous acquisition and always releases cancelled late captures', async () => {
  const f = await fixture({ maxViews: 1 }), captures = await Promise.allSettled([f.client.readView(), f.client.readView()])
  expect(captures.filter(value => value.status === 'fulfilled')).toHaveLength(1); expect(captures.filter(value => value.status === 'rejected')).toHaveLength(1)
  for (const value of captures) if (value.status === 'fulfilled') await value.value.release()
  const original = f.session.readView.bind(f.session); let release!: () => void, began!: () => void
  const started = new Promise<void>(resolve => { began = resolve }), gate = new Promise<void>(resolve => { release = resolve }); let released = 0
  f.session.readView = async options => { began(); await gate; const view = await original(options); return { ...view, release() { released++; view.release() } } }
  const cancel = new AbortController(), request = f.client.request('readView', [{}], { signal: cancel.signal }); await started; cancel.abort(new Error('cancelled capture')); await expect(request).rejects.toThrow('cancelled capture'); release()
  await new Promise<void>(resolve => setImmediate(resolve)); await new Promise<void>(resolve => setImmediate(resolve)); expect(released).toBe(1)
  f.session.readView = original; const next = await f.client.readView(); await next.release()
})
it('cancels owner waits, permits lifecycle controls under a full quota, and cleans physical detach', async () => {
  const f = await fixture({ maxRequests: 1 }), operation = await f.client.command('say', 'no remote retention', { operationId: 'wait' }); await operation.materialized()
  const cancel = new AbortController(), waiting = operation.retained({ signal: cancel.signal, timeoutMs: 60_000 }); await new Promise<void>(resolve => setImmediate(resolve)); cancel.abort(new Error('stop wait')); await expect(waiting).rejects.toThrow('stop wait')
  await f.client.request('attachment.ping', []); expect((await f.client.query('messages', null)).applicationId).toBe(f.applicationId)
  const blocked = operation.retained({ timeoutMs: 60_000 }); const rejected = expect(blocked).rejects.toThrow(); await new Promise<void>(resolve => setImmediate(resolve)); await f.client.detach(); await rejected
  expect(f.owner.endpoints()).toHaveLength(0); expect(f.session.status.phase).not.toBe('closed')
})
it('discard uses its upload handle and committed uploads no longer consume active upload quota', async () => {
  const f = await fixture(), abandoned = await f.client.content.stage({ bytes: 0 }); await abandoned.discard()
  for (let i = 0; i < 6; i++) { const upload = await f.client.content.stage({ bytes: 0 }), reference = await upload.commit(); expect(await upload.commit()).toEqual(reference); expect((await upload.progress()).bytes).toBe(0) }
  const upload = await f.client.content.stage({ bytes: 65537 }); await upload.write(0, new Uint8Array(65536).fill(7)); await upload.write(1, Uint8Array.of(8)); const reference = await upload.commit(); expect((await f.client.content.readBytes(reference, { maxBytes: 65537 })).at(-1)).toBe(8)
})
it('suspension releases views without closing the storage owner and owner-bound command context cannot be forged', async () => {
  const seen: string[] = [], f = await fixture({ context: { viewId: 'verified-view', documentPath: 'document' }, contextEvidence: 'owner-validated', rawSubmit: false }, { prepareCommand(endpoint, _name, input) { seen.push(endpoint.context.viewId!); return String(input) + ':' + endpoint.context.viewId } })
  const operation = await f.client.command('say', 'text', { operationId: 'context' }); await operation.materialized(); expect(seen).toEqual(['verified-view']); expect((await f.client.readEvents()).events[0]?.payload).toBe('text:verified-view')
  const view = await f.client.readView(); await f.client.suspendAttachment(); expect(f.client.status.canAuthor).toBe(false); await view.release(); await expect(f.client.command('say', 'blocked')).rejects.toThrow('ENDPOINT_SUSPENDED'); await f.client.resumeAttachment(); expect(f.client.status.canAuthor).toBe(true); expect(f.client.endpoint?.contextEvidence).toBe('owner-validated')
})
it('physical MessagePort loss retires owner endpoint state without waiting for an operation deadline', async () => {
  const f = await fixture(); f.channel.port2.close(); await expect.poll(() => f.owner.endpoints().length).toBe(0); await expect.poll(() => f.client.signal.aborted).toBe(true)
})
it('live signals cross bounded facade subscriptions with authenticated endpoint context, not history entries', async () => {
  const f = await fixture(), controller = new AbortController(), iterator = f.client.signals.subscribe({ topics: ['typing'], signal: controller.signal })[Symbol.asyncIterator](), next = iterator.next()
  await new Promise<void>(resolve => setImmediate(resolve)); await new Promise<void>(resolve => setImmediate(resolve))
  const signal = await f.client.signals.send('typing', { text: 'live' }, { stream: { streamId: 'draft', endpointId: 'forged' } }); expect(signal.stream?.endpointId).toBe(f.client.endpoint?.endpointId)
  expect((await next).value?.payload).toEqual({ text: 'live' }); controller.abort(); await iterator.return?.(); expect((await f.client.readEvents()).events).toHaveLength(0)
})
it('cancelling a warming captured read frees ordinary request quota so durable Save is not engine-gated', async () => {
  const f = await fixture({ maxRequests: 1, maxViews: 1 }), original = f.session.readView.bind(f.session); let release!: () => void, began!: () => void
  const gate = new Promise<void>(resolve => { release = resolve }), started = new Promise<void>(resolve => { began = resolve })
  f.session.readView = async options => { began(); await gate; return original(options) }
  const abort = new AbortController(), captured = f.client.request('readView', [{}], { signal: abort.signal }); await started; abort.abort(new Error('stop warming read')); await expect(captured).rejects.toThrow('stop warming read')
  const operation = await f.client.command('say', 'Save remains local', { operationId: 'not-engine-gated' }); expect(operation.stored).toBe(true); expect((await operation.materialized()).outcome).toBe('accepted')
  release(); f.session.readView = original; await new Promise<void>(resolve => setImmediate(resolve))
})
it('diagnostic-only attachments cannot exercise owner finalizer or key-provisioning authority', async () => {
  const f = await fixture({ capabilities: ['diagnostics'] }), request = await f.session.provisioning.createProvisioningRequest(), packageValue = await f.session.provisioning.exportProvisioning(request)
  expect(f.client.status.canAuthor).toBe(false); expect(await f.client.diagnostics()).toEqual([]); expect(await f.client.readAuthority()).toEqual(f.session.authority.bundle()); expect((await f.client.endpoints()).length).toBe(1)
  await expect(f.client.finality.closeAuthorTime({ throughMs: 1n })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.finality.voteAuthorTime({ throughMs: 1n })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.finality.submitProofs([])).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.provisioning.createProvisioningRequest()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.provisioning.exportProvisioning(request)).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.provisioning.importProvisioning(packageValue)).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
})
it('explicit finality and provisioning capabilities are independent and still require actual member/policy authority', async () => {
  const { createSigningIdentity } = await import('@chronolog/authority'), identity = await createSigningIdentity(), f = await sessionFixture({ identities: [identity], finalityPolicy: { kind: 'signed-frontier', signer: identity.publicKey, scopes: [{ id: 'cd'.repeat(32), authorTimeAfterMs: -1n }] } }), session = await f.open(0), owner = createApplicationOwner(session); closes.push(() => owner.close())
  const attach = async (capabilities: NonNullable<ApplicationAttachmentPolicy['capabilities']>) => { const channel = new MessageChannel(); owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, { capabilities }); const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId }); closes.push(() => client.detach()); return client }
  const finalizer = await attach(['finality']), keys = await attach(['provisioning']), operation = await session.command('say', 'eligible finalizer', { authorTimestampMs: 1n }); await operation.materialized()
  expect((await finalizer.finality.closeAuthorTime({ throughMs: 2n })).closedThroughMs).toBe(2n); expect(operation.inspect().finalized).toBe(true)
  await expect(finalizer.diagnostics()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN'); await expect(finalizer.provisioning.createProvisioningRequest()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN'); await expect(keys.finality.voteAuthorTime({ throughMs: 3n })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  const request = await keys.provisioning.createProvisioningRequest(), packageValue = await keys.provisioning.exportProvisioning(request); await keys.provisioning.importProvisioning(packageValue)
})
it('cancels an actual deferred named-query callback and promptly frees its ordinary RPC slot', async () => {
  const { defineApplication, defineQuery } = await import('./definition.js'), { createApplicationSession } = await import('./runtime.js'), { openApplicationDevice } = await import('./device.js')
  const f = await sessionFixture({ count: 1 }); let entered!: () => void, release!: () => void
  const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
  const definition = defineApplication({ id: 'callback-cancel', version: '1', commands: {}, queries: {
    hold: defineQuery({ description: 'Deferred actual read callback', input: { type: 'null' }, async read() { entered(); await gate; return 'late' } }),
    ready: defineQuery({ description: 'Ready after cancellation', input: { type: 'null' }, read() { return 'ready' } }),
  } })
  const session = await createApplicationSession({ device: await openApplicationDevice({ store: f.stores[0]!, create: true, managedSigner: f.identities[0]! }), definition, authority: f.bundle, epochKeys: new Map([[0, f.epochKey]]) }), owner = createApplicationOwner(session); closes.push(() => owner.close())
  const channel = new MessageChannel(); owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, { capabilities: ['queries'], maxRequests: 1 })
  const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId }); closes.push(() => client.detach())
  const abort = new AbortController(), held = client.request('query', ['hold', null], { signal: abort.signal }); await started; abort.abort(new Error('stop actual callback')); await expect(held).rejects.toThrow('stop actual callback')
  try { expect((await client.query('ready', null)).value).toBe('ready') } finally { release() }
})
it('fences copied active view namespaces across real attachments while retaining suspended claims and releasing detach', async () => {
  const f = await fixture({ context: { viewId: 'copied-view', documentPath: 'owner-document' }, contextEvidence: 'owner-validated' })
  const attach = async () => {
    const channel = new MessageChannel(); f.owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint)
    const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId, context: { viewId: 'copied-view', documentPath: 'caller-document' } }); closes.push(() => client.detach()); return client
  }
  expect(f.client.endpoint?.context.viewId).toBe('copied-view')
  const copied = await attach(); expect(copied.endpoint?.context.viewId).toBeTruthy(); expect(copied.endpoint?.context.viewId).not.toBe('copied-view')
  expect(copied.endpoint?.context.documentPath).toBe('caller-document'); expect(copied.endpoint?.contextEvidence).toBe('caller-asserted')
  await f.client.suspendAttachment(); const whileHidden = await attach(); expect(whileHidden.endpoint?.context.viewId).not.toBe('copied-view')
  expect(new Set(f.owner.endpoints().map(endpoint => endpoint.context.viewId)).size).toBe(3)
  expect(f.owner.endpoints().find(endpoint => endpoint.endpointId === f.client.endpoint?.endpointId)?.state).toBe('suspended')
  await f.client.resumeAttachment(); expect(f.client.endpoint?.context.viewId).toBe('copied-view')
  await f.client.detach(); const resumedPage = await attach(); expect(resumedPage.endpoint?.context.viewId).toBe('copied-view')
  const detachedEndpoint = f.owner.endpoints().find(endpoint => endpoint.endpointId === copied.endpoint?.endpointId)!; expect(detachedEndpoint.context.viewId).toBe(copied.endpoint?.context.viewId)
  await copied.detach(); expect(f.owner.endpoints().some(endpoint => endpoint.endpointId === detachedEndpoint.endpointId)).toBe(false)
})

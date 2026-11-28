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
  closes.push(() => owner.close(), () => client.detach())
  return { ...f, session, owner, client, channel }
}

it('real MessagePort facade separates durable submission, materialized reads, named-query revisions and none finality', async () => {
  const f = await fixture(), operation = await f.client.command('say', 'from facade', { operationId: 'facade' })
  expect(operation.stored).toBe(true)
  expect((await operation.materialized()).outcome).toBe('accepted')
  expect((await operation.inspect()).author).toBe(f.client.identity.publicKey)
  const named = await f.client.query('messages', null)
  expect(named.applicationId).toBe(f.applicationId)
  expect((named.value as ApplicationEventBatch).events[0]?.payload).toBe('from facade')
  await expect(operation.finalized()).rejects.toMatchObject({ code: 'FINALITY_UNSUPPORTED' })
  const projection = createLiveView(f.client, async view => (await view.readEvents()).events.map(event => event.payload))
  closes.push(async () => projection.close())
  expect((await projection.ready()).value).toEqual(['from facade'])
  const view = await f.client.readView()
  expect(view.applicationId).toBe(f.applicationId)
  await view.release()
  await expect(view.readEvents()).rejects.toThrow('READ_VIEW_RELEASED')
  expect(f.client.endpoint?.evidence).toBe('owner-bound')
  expect(f.client.endpoint?.contextEvidence).toBe('caller-asserted')
  expect((await f.client.endpoints())[0]?.endpointId).toBe(f.client.endpoint?.endpointId)
})

it('captured reads cannot bypass named-query allowlists or independent event capabilities', async () => {
  const f = await fixture({ capabilities: ['queries'], queries: [] }), op = await f.session.command('say', 'private')
  await op.materialized()
  await expect(f.client.query('messages', null)).rejects.toThrow('ENDPOINT_QUERY_FORBIDDEN')
  await expect(f.client.readEvents()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  const captured = await f.client.readView()
  await expect(captured.readEvents()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await captured.release()
})

it('reserves captured view quota before asynchronous acquisition and always releases cancelled late captures', async () => {
  const f = await fixture({ maxViews: 1 }), captures = await Promise.allSettled([f.client.readView(), f.client.readView()])
  expect(captures.filter(value => value.status === 'fulfilled')).toHaveLength(1)
  expect(captures.filter(value => value.status === 'rejected')).toHaveLength(1)
  for (const value of captures) if (value.status === 'fulfilled') await value.value.release()
  const original = f.session.readView.bind(f.session)
  let release!: () => void, began!: () => void
  const started = new Promise<void>(resolve => { began = resolve }), gate = new Promise<void>(resolve => { release = resolve })
  let released = 0
  f.session.readView = async options => { began(); await gate; const view = await original(options); return { ...view, release() { released++; view.release() } } }
  const cancel = new AbortController(), request = f.client.request('readView', [{}], { signal: cancel.signal })
  await started; cancel.abort(new Error('cancelled capture'))
  await expect(request).rejects.toThrow('cancelled capture')
  await new Promise<void>(resolve => setImmediate(resolve))
  release()
  await expect.poll(() => released).toBe(1)
  f.session.readView = original
  const next = await f.client.readView()
  await next.release()
})

it('cancels owner waits, permits lifecycle controls under a full quota, and cleans physical detach', async () => {
  const f = await fixture({ maxRequests: 1 }), operation = await f.client.command('say', 'no remote retention', { operationId: 'wait' })
  await operation.materialized()
  const cancel = new AbortController(), waiting = operation.retained({ signal: cancel.signal, timeoutMs: 60_000 })
  await new Promise<void>(resolve => setImmediate(resolve))
  cancel.abort(new Error('stop wait'))
  await expect(waiting).rejects.toThrow('stop wait')
  await f.client.request('attachment.ping', [])
  expect((await f.client.query('messages', null)).applicationId).toBe(f.applicationId)
  const blocked = operation.retained({ timeoutMs: 60_000 })
  const rejected = expect(blocked).rejects.toThrow()
  await new Promise<void>(resolve => setImmediate(resolve))
  await f.client.detach()
  await rejected
  expect(f.owner.endpoints()).toHaveLength(0)
  expect(f.session.status.phase).not.toBe('closed')
})

it('discard uses its upload handle and committed uploads no longer consume active upload quota', async () => {
  const f = await fixture(), abandoned = await f.client.content.stage({ bytes: 0 })
  await abandoned.discard()
  for (let i = 0; i < 6; i++) {
    const upload = await f.client.content.stage({ bytes: 0 }), reference = await upload.commit()
    expect(await upload.commit()).toEqual(reference)
    expect((await upload.progress()).bytes).toBe(0)
  }
  const upload = await f.client.content.stage({ bytes: 65537 })
  await upload.write(0, new Uint8Array(65536).fill(7))
  await upload.write(1, Uint8Array.of(8))
  const reference = await upload.commit()
  expect((await f.client.content.readBytes(reference, { maxBytes: 65537 })).at(-1)).toBe(8)
})

it('suspension releases views without closing the storage owner and owner-bound command context cannot be forged', async () => {
  const seen: string[] = []
  const f = await fixture(
    { context: { viewId: 'verified-view', documentPath: 'document' }, contextEvidence: 'owner-validated', rawSubmit: false },
    { prepareCommand(endpoint, _name, input) { seen.push(endpoint.context.viewId!); return String(input) + ':' + endpoint.context.viewId } },
  )
  const operation = await f.client.command('say', 'text', { operationId: 'context' })
  await operation.materialized()
  expect(seen).toEqual(['verified-view'])
  expect((await f.client.readEvents()).events[0]?.payload).toBe('text:verified-view')
  const view = await f.client.readView()
  await f.client.suspendAttachment()
  expect(f.client.status.canAuthor).toBe(false)
  await view.release()
  await expect(f.client.command('say', 'blocked')).rejects.toThrow('ENDPOINT_SUSPENDED')
  await f.client.resumeAttachment()
  expect(f.client.status.canAuthor).toBe(true)
  expect(f.client.endpoint?.contextEvidence).toBe('owner-validated')
})

it('physical MessagePort loss retires owner endpoint state without waiting for an operation deadline', async () => {
  const f = await fixture()
  f.channel.port2.close()
  await expect.poll(() => f.owner.endpoints().length).toBe(0)
  await expect.poll(() => f.client.signal.aborted).toBe(true)
})

it('live signals cross bounded facade subscriptions with authenticated endpoint context, not history entries', async () => {
  const f = await fixture(), controller = new AbortController()
  const iterator = f.client.signals.subscribe({ topics: ['typing'], signal: controller.signal })[Symbol.asyncIterator]()
  const next = iterator.next()
  await new Promise<void>(resolve => setImmediate(resolve))
  await new Promise<void>(resolve => setImmediate(resolve))
  const signal = await f.client.signals.send('typing', { text: 'live' }, { stream: { streamId: 'draft', endpointId: 'forged' } })
  expect(signal.stream?.endpointId).toBe(f.client.endpoint?.endpointId)
  expect((await next).value?.payload).toEqual({ text: 'live' })
  controller.abort()
  await iterator.return?.()
  expect((await f.client.readEvents()).events).toHaveLength(0)
})

it('diagnostic-only attachments cannot exercise owner finalizer or extension authority', async () => {
  const f = await fixture({ capabilities: ['diagnostics'] })
  expect(f.client.status.canAuthor).toBe(false)
  expect(await f.client.diagnostics()).toEqual([])
  expect((await f.client.endpoints()).length).toBe(1)
  await expect(f.client.admission.createCheckpoint({ throughMs: 1n })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.admission.submitEvidence([])).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(f.client.extensions.call('admission.state')).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
})

it('owner extensions are capability-scoped named actions with owner notices, independent of admission', async () => {
  const { createSigningIdentity } = await import('@chronolog/authority')
  const identity = await createSigningIdentity()
  const f = await sessionFixture({ identities: [identity], admissionPolicy: { kind: 'signed-frontier', signer: identity.publicKey } })
  const session = await f.open(0)
  const listeners = new Set<(value: unknown) => void>(), calls: unknown[] = []
  const owner = createApplicationOwner(session, {
    extensions: {
      async call(name, args, context) {
        calls.push([name, args, context.endpoint.capabilities])
        if (name === 'fail') throw new Error('EXTENSION_FAILED')
        for (const listener of listeners) listener({ name })
        return { ok: name }
      },
      subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener) },
    },
  })
  closes.push(() => owner.close())
  const attach = async (capabilities: NonNullable<ApplicationAttachmentPolicy['capabilities']>) => {
    const channel = new MessageChannel()
    owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, { capabilities })
    const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId })
    closes.push(() => client.detach())
    return client
  }
  const finalizer = await attach(['admission']), extended = await attach(['extensions'])
  const operation = await session.command('say', 'eligible finalizer', { authorTimestampMs: 1n })
  await operation.materialized()
  const cp = await finalizer.admission.createCheckpoint({ throughMs: 2n })
  expect((cp.evidence.payload as { readonly closedThroughMs: bigint }).closedThroughMs).toBe(2n)
  expect(operation.inspect().finalized).toBe(true)
  await expect(finalizer.extensions.call('admission.state')).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(extended.admission.createCheckpoint({ throughMs: 3n })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  const notices: unknown[] = []
  const heard = new Promise<void>(resolve => { extended.extensions.subscribe(value => { notices.push(value); resolve() }) })
  const muted: unknown[] = []
  finalizer.extensions.subscribe(value => muted.push(value))
  expect(await extended.extensions.call('admission.state', [1])).toEqual({ ok: 'admission.state' })
  await heard
  expect(notices).toEqual([{ name: 'admission.state' }])
  expect(muted).toEqual([])
  expect(calls).toEqual([['admission.state', [1], ['extensions']]])
  await expect(extended.extensions.call('fail')).rejects.toThrow('EXTENSION_FAILED')
  await expect(extended.extensions.call('bad name!')).rejects.toThrow('ENDPOINT_REQUEST_INVALID')
})

it('replication capability exchanges authenticated operation-set facts with an out-of-band replica in both directions', async () => {
  const f = await sessionFixture({ count: 2 }), session = await f.open(0), replica = await f.open(1), owner = createApplicationOwner(session)
  const attach = async (capabilities?: NonNullable<ApplicationAttachmentPolicy['capabilities']>) => {
    const channel = new MessageChannel()
    owner.attach(channel.port1 as unknown as ApplicationWorkerEndpoint, capabilities === undefined ? {} : { capabilities })
    const client = await connectApplicationOwner(channel.port2 as unknown as ApplicationWorkerEndpoint, { applicationId: f.applicationId })
    closes.push(() => client.detach())
    return client
  }
  closes.push(() => owner.close(), () => replica.close())
  const client = await attach(), denied = await attach(['diagnostics'])
  await expect(denied.exportFacts()).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  await expect(denied.mergeFacts({ publicOps: [], encryptedEnvelopes: [], casNodes: [], retentions: [], evidence: [] })).rejects.toThrow('ENDPOINT_CAPABILITY_FORBIDDEN')
  const local = await client.command('say', 'from owner', { operationId: 'owner-1', authorTimestampMs: 20n })
  await local.materialized()
  const remote = await replica.command('say', 'from replica', { operationId: 'replica-1', authorTimestampMs: 10n })
  await remote.materialized()
  await replica.mergeFacts(await client.exportFacts())
  await client.mergeFacts(await replica.exportFacts())
  const read = async (target: { readEvents(): ApplicationEventBatch | Promise<ApplicationEventBatch> }) => (await target.readEvents()).events.map(event => event.payload)
  await expect.poll(() => read(client)).toEqual(['from replica', 'from owner'])
  await expect.poll(() => read(replica)).toEqual(['from replica', 'from owner'])
  await client.mergeFacts(await replica.exportFacts())
  expect((await client.exportFacts()).encryptedEnvelopes).toHaveLength(2)
})

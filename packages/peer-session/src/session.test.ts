import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createGenerationRegistry, createPeerIdentity, MemoryBytesStore, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, participantGrant, bytesDigest, peerDigest, type PeerIdentity, type PrefixProof, type AuthorityBundle,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, defineQuery, applicationDefinitionDigest } from './definition.js'
import { connectApplications, AbandonedOperationError, RecoveredViewError, type ApplicationEvent, type ApplicationReadView, type ApplicationSession } from './session.js'
import { openNativeApplication, openNativeDevice } from './native.js'
import { createApplicationTools, serveApplicationToolLines } from './tools.js'
import { ApplicationControlConflictError } from './recovery.js'
import { createApplicationBackend } from './tendriller.js'

const definition = defineApplication({ id: 'messages', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string', minLength: 1 }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'peer-session-'))
  cleanup.push(() => rm(directory, { recursive: true, force: true }))
  const host = await createPeerIdentity()
  const a = await openNativeDevice({ path: join(directory, 'a.sqlite'), create: true }), b = await openNativeDevice({ path: join(directory, 'b.sqlite'), create: true })
  const c = await openNativeDevice({ path: join(directory, 'c.sqlite'), create: true })
  cleanup.push(() => a.close(), () => b.close(), () => c.close())
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: '77'.repeat(32), historyId: 'session-test', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.identity.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b, c].map(device => participantGrant(device.identity.publicKey, { administrator: true, dataRole: 'member' })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(a.identity, null, 'create')
  const open = async (device: typeof a, options: { readonly data?: boolean; readonly authority?: AuthorityBundle } = {}) => {
    const session = await openNativeApplication({ device, authority: options.authority ?? await registry.read(), epochKeys, definition })
    cleanup.push(() => session.close()); if (options.data !== false) await session.keys.missing(); return session
  }
  return { a, b, c, directory, registry, select, open, host }
}

async function applied(session: ApplicationSession<typeof definition>, text: string, id: string) {
  const operation = await session.command('say', text, { operationId: id })
  return operation.applied({ signal: AbortSignal.timeout(5000) })
}

describe('public peer application sessions', () => {
  it('owns a single saved attempt, exposes authenticated current results and isolates cancelled waiters', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const operation = await b.command('say', 'saved offline', { operationId: 'once' })
    expect(await operation.get()).toMatchObject({ status: 'saved' })
    const cancelled = new AbortController(), waiting = operation.applied({ signal: cancelled.signal })
    cancelled.abort(new Error('stop waiting'))
    await expect(waiting).rejects.toThrow('stop waiting')
    expect(await operation.get()).toMatchObject({ status: 'saved' })
    const original = await b.operations.inspect('once')
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    expect(await operation.applied({ signal: AbortSignal.timeout(5000) })).toMatchObject({ status: 'applied', outcome: 'accepted', sequence: 1 })
    await operation.retry(); await link.synchronize()
    expect((await b.operations.inspect('once'))?.attempt).toEqual(original?.attempt)
    const result = await a.query('messages', null)
    expect(result.value.events).toHaveLength(1)
    expect(result.value.events[0]).toMatchObject({ author: b.deviceId, operationId: 'once', payload: { text: 'saved offline' } })
    expect(a.capabilities.finality).toBe(false)
    expect('final' in operation).toBe(false)
    expect(await operation.shared({ signal: AbortSignal.timeout(5000) })).toHaveLength(1)
  })

  it('keeps a cut after durable ordering recoverable as the same exact attempt', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    let link = await connectApplications(a, b)
    const changes = a.changes()[Symbol.asyncIterator]()
    await changes.next()
    const cut = changes.next().then(() => link.close())
    const operation = await b.command('say', 'lost response', { operationId: 'lost' })
    await cut
    await b.retry('lost').catch(error => { expect(String(error)).toContain('APPLICATION_PEER_DISCONNECTED') })
    expect((await b.operations.get('lost'))?.status).toBe('saved')
    expect((await a.operations.get('lost', { author: b.deviceId }))?.status).toBe('applied')
    const original = await b.operations.inspect('lost')
    link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    const result = await operation.applied({ signal: AbortSignal.timeout(5000) })
    expect(result.sequence).toBe(1)
    expect((await b.operations.inspect('lost'))?.attempt).toEqual(original?.attempt)
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
    await changes.return?.()
  })

  it('emits applied changes only when the coherent application revision advances', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const changes = a.changes()[Symbol.asyncIterator]()
    expect((await changes.next()).value?.revision.point.sequence).toBe(0)
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    await link.synchronize()
    const next = changes.next()
    await applied(a, 'published change', 'published-change')
    expect((await next).value?.revision.point.sequence).toBe(1)
    await changes.return?.()
  })

  it('atomically resets recovery views, preserves abandoned evidence and links a deliberate reapplication', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained', 'retained'); await link.synchronize(); await link.close()
    const base = await b.recoveryPoint()
    const abandoned = await a.command('say', 'tail', { operationId: 'tail' }); await abandoned.applied()
    const old = await a.query('messages', null), captured = await a.readView()
    await f.select(f.b.identity, base, 'recover')
    await b.adopt(await f.registry.read())
    const recoveryLink = await connectApplications(a, b)
    cleanup.push(() => recoveryLink.close())
    await expect(abandoned.applied()).rejects.toBeInstanceOf(AbandonedOperationError)
    expect(captured.readEvents().events).toHaveLength(2); captured.release()
    const current = await a.readView()
    expect(() => current.readEvents({ cursor: old.value.cursor })).toThrow(RecoveredViewError); current.release()
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
    const prior = await a.operations.inspect('tail')
    const retried = await a.reapply('tail', 'say', 'tail reviewed', { operationId: 'tail-again', basedOn: a.revision! })
    expect((await retried.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    expect((await a.operations.inspect('tail-again'))?.attempt.payload.header.reapplyOf).toBe(prior?.attempt.id)
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
  })

  it('keeps device identity and applied outcomes across close/reopen and rejects another owner', async () => {
    const f = await fixture(), a = await f.open(f.a), publicKey = a.deviceId
    await expect(openNativeDevice({ path: join(f.directory, 'a.sqlite') })).rejects.toThrow('BYTES_STORE_IN_USE')
    await applied(a, 'persistent', 'saved')
    await a.close()
    const reopenedDevice = await openNativeDevice({ path: join(f.directory, 'a.sqlite') })
    const reopened = await f.open(reopenedDevice)
    expect(reopened.deviceId).toBe(publicKey)
    expect((await reopened.operations.get('saved'))?.status).toBe('applied')
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
  })

  it('retains recovered authority in protocol metadata before reopening without data', async () => {
    const f = await fixture(), initial = await f.registry.read(), b = await f.open(f.b)
    const host = { application: () => f.registry.read(), selectGeneration: (request: Parameters<typeof f.registry.select>[0]) => f.registry.select(request) }
    await b.recovery.takeover(host, { transitionId: 'metadata-anchor' })
    const selected = (await f.registry.read()).generations.at(-1)!.id
    expect(selected).not.toBe(initial.generations.at(-1)!.id)
    await b.close()
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }), { data: false, authority: initial })
    expect(reopened.status).toMatchObject({ database: 'idle', generation: selected, coordinator: reopened.deviceId })
    expect(reopened.revision).toBeNull()
    const authority = await reopened.authority()
    expect(authority.generations.at(-1)?.id).toBe(selected)
    Object.assign(authority.descriptor.payload, { applicationId: '00'.repeat(32) })
    expect((await reopened.authority()).descriptor.payload.applicationId).toBe(reopened.applicationId)
    expect(reopened.status.database).toBe('idle')
    await reopened.close()
    await expect(reopened.authority()).rejects.toThrow('APPLICATION_SESSION_CLOSED')
  })

  it('seeds a fresh peer with the selected inherited prefix before its application view is ready', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const original = await connectApplications(a, b)
    await applied(a, 'inherited', 'inherited'); await original.synchronize(); await original.close()
    const selected = await f.select(f.b.identity, await b.recoveryPoint(), 'recover-fresh')
    await b.adopt(await f.registry.read())

    const c = await f.open(f.c)
    await expect(c.query('messages', null)).rejects.toThrow('PEER_RECOVERING')
    const recovered = await connectApplications(b, c)
    cleanup.push(() => recovered.close())
    const observed = await c.query('messages', null)
    expect(observed.revision.generation).toBe(selected.id)
    expect(observed.value.events).toEqual((await b.query('messages', null)).value.events)
    expect(observed.value.events).toHaveLength(1)
    expect(await c.operations.get('inherited', { author: a.deviceId })).toMatchObject({ status: 'applied', outcome: 'accepted' })
  })

  it('exchanges a retained prefix between followers regardless of connection argument order', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), c = await f.open(f.c)
    const original = await connectApplications(a, b)
    await applied(a, 'retained by follower', 'retained'); await original.synchronize(); await original.close()
    expect((await c.query('messages', null)).value.events).toHaveLength(0)
    expect(b.status.role).toBe('follower'); expect(c.status.role).toBe('follower')

    // The left peer has no retained body; the right peer owns the useful copy.
    const followers = await connectApplications(c, b)
    cleanup.push(() => followers.close())
    const expected = (await b.query('messages', null)).value.events
    expect((await c.query('messages', null)).value.events).toEqual(expected)
    expect(expected).toHaveLength(1)
    const retained = await b.operations.get('retained', { author: a.deviceId })
    expect(await c.operations.get('retained', { author: a.deviceId })).toEqual(retained)
  })

  it('persists the exact recovery request across a lost hosted reply and device reopen', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained', 'retained'); await link.synchronize(); await link.close()
    let lost = true
    const host = { application: () => f.registry.read(), selectGeneration: async (request: Parameters<typeof f.registry.select>[0]) => {
      const result = await f.registry.select(request)
      if (lost) { lost = false; throw new Error('LOST_SELECTION_REPLY') }
      return result
    } }
    await expect(b.recovery.takeover(host, { transitionId: 'recover-once' })).rejects.toThrow('LOST_SELECTION_REPLY')
    const original = (await b.recovery.inspect())[0]!.request
    await b.close()
    await applied(a, 'excluded tail', 'tail')
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    await reopened.recovery.takeover(host, { transitionId: 'recover-once' })
    expect((await reopened.recovery.inspect())[0]).toMatchObject({ request: original, selected: reopened.revision!.generation })
    expect((await f.registry.read()).generations).toHaveLength(2)
    const recovered = await connectApplications(a, reopened)
    cleanup.push(() => recovered.close())
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
  })

  it('keeps inherited recovery private until selection and retries its exact ancestor base after reopen', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained ancestor', 'retained'); await link.synchronize(); await link.close()
    const ancestor = await b.recoveryPoint(), captured = await b.readView(), notices: unknown[] = []
    b.onRecovery(notice => { notices.push(notice) })
    const projectionDefinition = { id: 'message-ids', version: '1', topics: ['message'], initial: [] as string[],
      reduce: (state: string[], event: ApplicationEvent) => [...state, event.operationId] }
    const projection = b.project(projectionDefinition), changes = projection.changes()[Symbol.asyncIterator]()
    expect((await changes.next()).value?.state).toEqual(['retained'])
    let advanced = false
    const next = changes.next().then(value => { advanced = true; return value })
    cleanup.push(() => { captured.release() })
    await f.select(f.a.identity, ancestor, 'second'); await a.adopt(await f.registry.read())
    await applied(a, 'unavailable newer data', 'unavailable')
    const current = await f.select(f.c.identity, await a.recoveryPoint(), 'third')
    await expect(b.adopt(await f.registry.read())).rejects.toThrow('PEER_RECOVERY_PREFIX_INCOMPLETE')
    expect(await b.recoveryPoint()).toEqual(ancestor)
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
    await expect(projection.read()).rejects.toThrow('PEER_RECOVERING')
    expect(captured.readEvents().events.map(event => event.operationId)).toEqual(['retained'])
    expect(notices).toEqual([]); expect(advanced).toBe(false)

    let entered!: () => void, release!: () => void, lost = true
    const started = new Promise<void>(resolve => { entered = resolve }), gate = new Promise<void>(resolve => { release = resolve })
    const requests: Array<Parameters<typeof f.registry.select>[0]> = []
    const host = { application: () => f.registry.read(), async selectGeneration(request: Parameters<typeof f.registry.select>[0]) {
      requests.push(request); entered(); await gate
      const selected = await f.registry.select(request)
      if (lost) { lost = false; throw new Error('LOST_ANCESTOR_SELECTION_REPLY') }
      return selected
    } }
    const expected = { generation: current.id, controlRevision: 0, point: ancestor.point }
    const takeover = b.recovery.takeover(host, { transitionId: 'ancestor-once', expected })
    const lostReply = expect(takeover).rejects.toThrow('LOST_ANCESTOR_SELECTION_REPLY')
    await started
    expect(requests[0]!.payload).toMatchObject({ expectedGeneration: current.id, base: ancestor })
    expect(advanced).toBe(false); expect(notices).toEqual([])
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
    release(); await lostReply
    const original = (await b.recovery.inspect())[0]!.request
    expect(advanced).toBe(false)
    expect(captured.readEvents().events.map(event => event.operationId)).toEqual(['retained'])
    await b.close(); expect((await next).done).toBe(true)
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    await reopened.recovery.takeover(host, { transitionId: 'ancestor-once', expected })
    expect(requests).toEqual([original, original])
    expect((await reopened.recovery.inspect())[0]).toMatchObject({ request: original, selected: reopened.revision!.generation })
    expect((await f.registry.read()).generations).toHaveLength(4)
    const resumed = await reopened.project(projectionDefinition).read()
    expect(resumed.state).toEqual(['retained'])
    expect(resumed.reset).toMatchObject({ reason: 'recovery', previousRevision: captured.revision })
    const recovered = await connectApplications(a, reopened)
    cleanup.push(() => recovered.close())
    expect(await a.operations.get('unavailable')).toMatchObject({ status: 'abandoned' })
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
  })

  it.each(['recovery', 'coordinator'] as const)('does not journal an ancestor transition without current %s authority', async permission => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await a.waitForCoverage(await applied(a, 'retained ancestor', 'retained'), { signal: AbortSignal.timeout(5000) })
    const ancestor = await b.recoveryPoint()
    await link.close()
    await f.select(f.a.identity, ancestor, 'second'); await a.adopt(await f.registry.read())
    await applied(a, 'unavailable newer data', 'unavailable')
    const bundle = await f.registry.read(), previous = bundle.controls[0]!
    const control = await signControlRevision({ ...previous.payload, revision: 1, previous: await peerDigest(previous),
      grants: previous.payload.grants.map(grant => grant.publicKey === b.deviceId ? { ...grant, [permission]: false } : grant),
    }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: bundle.descriptor.payload.profile,
      policy: bundle.descriptor.payload.policy, expectedGeneration: a.revision!.generation, requester: a.deviceId,
      coordinator: a.deviceId, controlRevision: 1, reason: 'control-change', transitionId: `revoke-${permission}`,
      base: await a.recoveryPoint() }, f.a.identity), { control })
    const host = { application: () => f.registry.read(), selectGeneration: vi.fn((request: Parameters<typeof f.registry.select>[0]) => f.registry.select(request)) }
    await expect(b.recovery.takeover(host, { transitionId: 'forbidden' })).rejects.toThrow(permission === 'recovery' ? 'PEER_RECOVERY_FORBIDDEN' : 'PEER_COORDINATOR_FORBIDDEN')
    expect(await b.recovery.inspect()).toEqual([]); expect(host.selectGeneration).not.toHaveBeenCalled()
    await expect(b.readView()).rejects.toThrow('PEER_RECOVERING')
  })

  it('closes an unanswered hosted recovery wait while retaining its exact saved request', async () => {
    const f = await fixture(), b = await f.open(f.b)
    let selected!: () => void
    const started = new Promise<void>(resolve => { selected = resolve })
    let original: Parameters<typeof f.registry.select>[0] | undefined
    const host = { application: () => f.registry.read(), selectGeneration(request: Parameters<typeof f.registry.select>[0]) {
      original = request; selected()
      return new Promise<Awaited<ReturnType<typeof f.registry.select>>>(() => {})
    } }
    const pending = b.recovery.takeover(host, { transitionId: 'unanswered' })
    const outcome = pending.catch((error: unknown) => error)
    await started
    await b.close()
    expect(await outcome).toMatchObject({ message: 'APPLICATION_SESSION_CLOSED' })
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    expect((await reopened.recovery.inspect())[0]).toEqual({ request: original, selected: null, superseded: false })
    expect((await f.registry.read()).generations).toHaveLength(1)
  })

  it('requires an exact retained prefix before selecting another eligible coordinator', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b), c = await f.open(f.c)
    const host = { application: () => f.registry.read(), selectGeneration: (request: Parameters<typeof f.registry.select>[0]) => f.registry.select(request) }
    await expect(b.recovery.takeover(host, { coordinator: c.deviceId, transitionId: 'remote' }))
      .rejects.toThrow('APPLICATION_TAKEOVER_REQUIRES_RETAINED_PREFIX')
    expect(await b.recovery.inspect()).toEqual([])
    const ab = await connectApplications(a, b), bc = await connectApplications(b, c)
    cleanup.push(() => ab.close(), () => bc.close())
    await applied(a, 'retained', 'retained'); await ab.synchronize(); await bc.synchronize()
    await b.recovery.takeover(host, { coordinator: c.deviceId, transitionId: 'remote' })
    expect((await f.registry.read()).generations.at(-1)?.payload.coordinator).toBe(c.deviceId)
    expect((await b.recovery.inspect())[0]?.request.payload.coordinator).toBe(c.deviceId)
  })

  it('fences a cancelled recovery owner while preserving its exact request for later resolution', async () => {
    const f = await fixture(), b = await f.open(f.b), controller = new AbortController()
    let release!: () => void, entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve }), started = new Promise<void>(resolve => { entered = resolve })
    let committed: Promise<Awaited<ReturnType<typeof f.registry.select>>> | undefined
    const host = { application: () => f.registry.read(), selectGeneration(request: Parameters<typeof f.registry.select>[0]) {
      entered(); committed = gate.then(() => f.registry.select(request)); return committed
    } }
    const before = b.revision, waiting = b.recovery.takeover(host, { transitionId: 'cancel-owner', signal: controller.signal })
    const rejected = expect(waiting).rejects.toThrow('owner stopped')
    await started; controller.abort(new Error('owner stopped')); await rejected
    const saved = (await b.recovery.inspect())[0]!
    expect(saved.selected).toBeNull()
    release(); await committed
    expect(b.revision).toEqual(before)
    await b.recovery.takeover(host, { transitionId: 'cancel-owner' })
    expect((await b.recovery.inspect())[0]?.request).toEqual(saved.request)
    expect(b.status.role).toBe('coordinator')
  })

  it('adopts a typed hosted conflict and never resubmits its superseded saved request', async () => {
    const f = await fixture(), b = await f.open(f.b), c = await f.open(f.c)
    const conflict = Object.assign(new Error('A different eligible coordinator won the transition'), {
      code: 'peer_generation_conflict', status: 409,
    })
    let original: Parameters<typeof f.registry.select>[0] | undefined, selections = 0
    const host = { application: () => f.registry.read(), async selectGeneration(request: Parameters<typeof f.registry.select>[0]) {
      original = request; selections++
      await f.select(f.c.identity, await c.recoveryPoint(), 'competing-selection')
      throw conflict
    } }
    await expect(b.recovery.takeover(host, { transitionId: 'lost-cas' })).rejects.toBe(conflict)
    const current = (await f.registry.read()).generations.at(-1)!
    expect(current.payload.coordinator).toBe(c.deviceId)
    expect(b.revision!.generation).toBe(current.id)
    expect((await b.recovery.inspect())[0]).toEqual({ request: original, selected: null, superseded: true })
    await b.close()
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    await expect(reopened.recovery.takeover(host, { transitionId: 'lost-cas' })).rejects.toBeInstanceOf(ApplicationControlConflictError)
    expect(selections).toBe(1)
    expect((await reopened.recovery.inspect())[0]).toEqual({ request: original, selected: null, superseded: true })

    // Human text does not carry control semantics. Without the typed code, a
    // failed transport leaves the exact attempt available for explicit retry.
    const untyped = new Error('PEER_GENERATION_CONFLICT')
    await expect(reopened.recovery.takeover({ application: () => f.registry.read(),
      selectGeneration: async () => { throw untyped },
    }, { transitionId: 'transport-failure' })).rejects.toBe(untyped)
    expect((await reopened.recovery.inspect())[1]).toMatchObject({ selected: null, superseded: false })
    expect(reopened.revision!.generation).toBe(current.id)
  })

  it('executes local agent and CLI tools through the same validated operation journal', async () => {
    const f = await fixture(), app = await f.open(f.a), tools = createApplicationTools(app)
    expect(tools.list().map(tool => tool.name)).toContain('command')
    await expect(tools.call('command', { name: 'say', input: 123, operationId: 'invalid' })).rejects.toThrow('APPLICATION_INPUT_INVALID')
    expect(await app.operations.get('invalid')).toBeNull()
    const lines = [
      { id: 1, tool: 'command', input: { name: 'say', input: 'from local tool', operationId: 'tool-once' } },
      { id: 2, tool: 'wait', input: { operationId: 'tool-once' } },
      { id: 3, tool: 'retry', input: { operationId: 'tool-once' } },
      { id: 4, tool: 'query', input: { name: 'messages', input: null } },
    ], output: string[] = []
    await serveApplicationToolLines(app, { input: { async *[Symbol.asyncIterator]() { for (const line of lines) yield JSON.stringify(line) } },
      write(line) { output.push(line) } })
    expect(output).toHaveLength(4)
    expect(JSON.parse(output[1]!)).toMatchObject({ id: 2, result: { status: 'applied', outcome: 'accepted' } })
    expect(JSON.parse(output[3]!)).toMatchObject({ id: 4, result: { value: { events: [expect.objectContaining({ operationId: 'tool-once', payload: { text: 'from local tool' } })] } } })
    expect((await app.query('messages', null)).value.events).toHaveLength(1)
  })

  it('bounds a CLI takeover wait without discarding the saved transition or closing its session', async () => {
    const f = await fixture(), app = await f.open(f.b), deadline = new AbortController()
    let select!: () => void
    const started = new Promise<void>(resolve => { select = resolve })
    let original: Parameters<typeof f.registry.select>[0] | undefined
    const host = { application: () => f.registry.read(), selectGeneration(request: Parameters<typeof f.registry.select>[0]) {
      original = request; select()
      return new Promise<Awaited<ReturnType<typeof f.registry.select>>>(() => {})
    } }
    const timer = vi.spyOn(AbortSignal, 'timeout').mockImplementation(milliseconds => {
      expect(milliseconds).toBe(1000); return deadline.signal
    })
    const output: string[] = []
    try {
      const serving = serveApplicationToolLines(app, { host,
        input: { async *[Symbol.asyncIterator]() { yield JSON.stringify({ id: 1, tool: 'takeover', input: { transitionId: 'cli-once' }, timeoutMs: 1000 }) } },
        write: line => { output.push(line) },
      })
      await started
      deadline.abort(new Error('CALL_DEADLINE'))
      await serving
      expect(JSON.parse(output[0]!)).toEqual({ id: 1, error: 'CALL_DEADLINE' })
      expect(app.signal.aborted).toBe(false)
    } finally { timer.mockRestore(); await app.close() }
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    expect((await reopened.recovery.inspect())[0]).toEqual({ request: original, selected: null, superseded: false })
  })

  it.each(['input', 'output'] as const)('releases a CLI owner with an uncooperative %s stream', async blocked => {
    const f = await fixture(), app = await f.open(f.a)
    let entered!: () => void, returned = 0
    const started = new Promise<void>(resolve => { entered = resolve })
    const input: AsyncIterable<string> = { [Symbol.asyncIterator]() { return {
      next(): Promise<IteratorResult<string>> {
        if (blocked === 'input') { entered(); return new Promise(() => {}) }
        return Promise.resolve({ done: false, value: JSON.stringify({ id: 1, tool: 'describe', input: {} }) })
      },
      return(): Promise<IteratorResult<string>> { returned++; return new Promise(() => {}) },
    } } }
    const serving = serveApplicationToolLines(app, { input, write() {
      entered(); return new Promise<void>(() => {})
    } }).catch((error: unknown) => error)
    await started
    await app.close()
    expect(await serving).toMatchObject({ message: 'APPLICATION_SESSION_CLOSED' })
    expect(returned).toBe(1)
  })
  it('binds Tendriller to applied views and authenticated operations without hosted command calls', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const backend = createApplicationBackend({ id: b.applicationId, session: b })
    expect(b.capabilities.sql).toBe(false)
    expect(backend.capabilities).not.toContain('sql')
    const phases: string[] = [], unsubscribe = backend.onStatus(status => { phases.push(status.phase) })
    expect(phases).toEqual(['waiting'])
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close()); cleanup.push(unsubscribe)
    expect(phases.at(-1)).toBe('ready')
    await backend.submit({ name: 'say', input: 'via adapter' }, { operationId: 'adapter-once' })
    const result = await b.operations.wait('adapter-once')
    const view = await backend.readView()
    await expect(view.query('SELECT 1')).rejects.toThrow('SQL_NOT_AVAILABLE')
    expect(view.view).toBe('applied')
    expect('finalRevision' in view).toBe(false)
    const events = await view.readEvents()
    expect(events.transactions[0]?.proposalId).toBe(result.attemptId)
    expect(events.transactions[0]?.events[0]?.origin).toMatchObject({ kind: 'peer-generation', authorId: b.deviceId, operationId: 'adapter-once' })
    await view.release()
    // @ts-expect-error Unsupported views must also fail at the runtime boundary.
    await expect(backend.readView({ view: 'final' })).rejects.toThrow('APPLICATION_VIEW_UNSUPPORTED')
    await expect(backend.events.publish('anything', {}, { operationId: 'undeclared' })).rejects.toThrow('APPLICATION_EVENT_PUBLICATION_NOT_CONFIGURED')
    await link.close()
    expect(phases.at(-1)).toBe('waiting')
  })

})

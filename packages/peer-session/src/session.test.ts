import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import {
  createGenerationRegistry, createPeerIdentity, MemoryPeerStore, signApplicationDescriptor,
  signControlRevision, signTransitionRequest, bytesDigest, participantGrant, peerDigest, type PeerIdentity, type PrefixProof,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { defineApplication, defineCommand, defineQuery, applicationDefinitionDigest } from './definition.js'
import { connectApplications, AbandonedOperationError, RecoveredViewError, type ApplicationReadView, type ApplicationSession } from './session.js'
import { openNativeApplication, openNativeDevice } from './native.js'
import { createApplicationTools, serveApplicationToolLines } from './tools.js'
import { sessionInternals } from './internals.js'
import { createPeerGenerationApplicationBackend } from './tendriller.js'

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
  cleanup.push(() => a.close(), () => b.close())
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const artifacts = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '77'.repeat(32), historyId: 'session-test', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: host.publicKey, schemaAdministrator: a.identity.publicKey,
    executionManifestDigest: bytesToHex(artifacts.executionManifestDigest), definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [a, b].map(device => ({ publicKey: device.identity.publicKey, reader: true, writer: true, coordinator: true, recovery: true, administrator: true, dataRole: 'member' as const })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host })
  const select = async (identity: PeerIdentity, base: PrefixProof | null, transitionId: string) => {
    const bundle = await registry.read()
    return registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, expectedGeneration: bundle.generations.at(-1)?.id ?? null, coordinator: identity.publicKey,
      requester: identity.publicKey, controlRevision: 0, base, transitionId, reason: base === null ? 'create' : 'takeover' }, identity))
  }
  await select(a.identity, null, 'create')
  const open = async (device: typeof a) => {
    const session = await openNativeApplication({ device, authority: await registry.read(), epochKeys, definition })
    cleanup.push(() => session.close()); return session
  }
  return { a, b, directory, registry, select, open, host }
}

async function applied(session: ApplicationSession<typeof definition>, text: string, id: string) {
  const operation = await session.command('say', text, { operationId: id })
  return operation.applied({ signal: AbortSignal.timeout(5000) })
}

describe('public peer application sessions', () => {
  it('learns a newly granted reader’s signed authority before authorizing its direct connection', async () => {
    const f = await fixture(), a = await f.open(f.a)
    await applied(a, 'before the new reader', 'before-grant')
    const device = await openNativeDevice({ path: join(f.directory, 'c.sqlite'), create: true })
    cleanup.push(() => device.close())
    const before = await f.registry.read(), previous = before.controls[0]!
    const control = await signControlRevision({ ...previous.payload, revision: 1, previous: await peerDigest(previous),
      grants: [...previous.payload.grants, participantGrant(device.identity.publicKey)] }, f.host)
    await f.registry.select(await signTransitionRequest({ applicationId: a.applicationId, profile: 'peer-generation-v1', policy: 'eligible-members-v1',
      expectedGeneration: before.generations.at(-1)!.id, coordinator: a.deviceId, requester: a.deviceId,
      controlRevision: 1, base: await a.recoveryPoint(), transitionId: 'enroll-reader', reason: 'control-change' }, f.a.identity), { control })
    const c = await openNativeApplication({ device, definition, authority: await f.registry.read() })
    cleanup.push(() => c.close())
    expect(a.status.generation).not.toBe(c.status.generation)
    expect(c.status.phase).toBe('awaiting-keys')
    const link = await connectApplications(a, c)
    cleanup.push(() => link.close())
    expect(a.status.generation).toBe(c.status.generation)
    expect(c.status.phase).toBe('ready')
    expect((await c.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['before-grant'])
    expect(await applied(c, 'new reader contribution', 'after-grant')).toMatchObject({ outcome: 'accepted', author: c.deviceId })
    await link.synchronize()
    expect((await a.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['before-grant', 'after-grant'])
  })

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
    const cut = changes.next().then(() => { link.close() })
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

  it('acknowledges the transferred prefix when the coordinator advances before the retention reply', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    await applied(a, 'captured', 'captured')
    const replica = sessionInternals.get(b)!.replica
    const retainedCoverage = replica.retainedCoverage.bind(replica)
    let advanced = false
    replica.retainedCoverage = async point => {
      const coverage = await retainedCoverage(point)
      if (!advanced) { advanced = true; await applied(a, 'newer than captured', 'later') }
      return coverage
    }
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    await link.synchronize()
    expect(advanced).toBe(true)
    expect(a.status.connectedPeers).toBe(1)
    expect(b.status.connectedPeers).toBe(1)
    expect((await b.query('messages', null)).value.events.map(event => event.operationId)).toEqual(['captured', 'later'])
  })

  it('atomically resets recovery views, preserves abandoned evidence and links a deliberate reapplication', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained', 'retained'); await link.synchronize(); link.close()
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
    const retried = await a.reapply('tail', 'say', 'tail reviewed', { operationId: 'tail-again', basedOn: a.revision })
    expect((await retried.applied({ signal: AbortSignal.timeout(5000) })).outcome).toBe('accepted')
    expect((await a.operations.inspect('tail-again'))?.attempt.payload.header.reapplyOf).toBe(prior?.attempt.id)
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
  })

  it('keeps device identity and applied outcomes across close/reopen and rejects another owner', async () => {
    const f = await fixture(), a = await f.open(f.a), publicKey = a.deviceId
    await expect(openNativeDevice({ path: join(f.directory, 'a.sqlite') })).rejects.toThrow('AGENT_STORE_IN_USE')
    await applied(a, 'persistent', 'saved')
    await a.close()
    const reopenedDevice = await openNativeDevice({ path: join(f.directory, 'a.sqlite') })
    const reopened = await f.open(reopenedDevice)
    expect(reopened.deviceId).toBe(publicKey)
    expect((await reopened.operations.get('saved'))?.status).toBe('applied')
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
  })

  it('persists the exact recovery request across a lost hosted reply and device reopen', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const link = await connectApplications(a, b)
    await applied(a, 'retained', 'retained'); await link.synchronize(); link.close()
    let lost = true
    const host = { application: () => f.registry.read(), selectGeneration: async (...args: Parameters<typeof f.registry.select>) => {
      const result = await f.registry.select(...args)
      if (lost) { lost = false; throw new Error('LOST_SELECTION_REPLY') }
      return result
    } }
    await expect(b.recovery.takeover(host, { transitionId: 'recover-once' })).rejects.toThrow('LOST_SELECTION_REPLY')
    const original = (await b.recovery.inspect())[0]!.request
    await b.close()
    await applied(a, 'excluded tail', 'tail')
    const reopened = await f.open(await openNativeDevice({ path: join(f.directory, 'b.sqlite') }))
    await reopened.recovery.takeover(host, { transitionId: 'recover-once' })
    expect((await reopened.recovery.inspect())[0]).toMatchObject({ request: original, selected: reopened.revision.generation })
    expect((await f.registry.read()).generations).toHaveLength(2)
    const recovered = await connectApplications(a, reopened)
    cleanup.push(() => recovered.close())
    expect((await a.operations.get('tail'))?.status).toBe('abandoned')
    expect((await reopened.query('messages', null)).value.events).toHaveLength(1)
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
    const before = app.revision, waiting = tools.call('changes', { after: before }, { signal: AbortSignal.timeout(5000) })
    await tools.call('command', { name: 'say', input: 'with captured guard', operationId: 'guarded', basedOn: before })
    expect(await waiting).toMatchObject({ kind: 'applied', revision: { point: { sequence: 2 } } })
    const cancelled = new AbortController(), changeWait = tools.call('changes', { after: app.revision }, { signal: cancelled.signal })
    cancelled.abort(new Error('AGENT_STOPPED_WAITING'))
    await expect(changeWait).rejects.toThrow('AGENT_STOPPED_WAITING')
    expect(await app.operations.get('guarded')).toMatchObject({ status: 'applied', outcome: 'accepted' })
  })

  it('binds Tendriller to applied views and authenticated operations without hosted command calls', async () => {
    const f = await fixture(), a = await f.open(f.a), b = await f.open(f.b)
    const backend = createPeerGenerationApplicationBackend({ id: b.applicationId, session: b })
    const phases: string[] = [], unsubscribe = backend.onStatus(status => { phases.push(status.phase) })
    expect(phases).toEqual(['waiting'])
    const link = await connectApplications(a, b)
    cleanup.push(() => link.close()); cleanup.push(unsubscribe)
    expect(phases.at(-1)).toBe('ready')
    await backend.submit({ name: 'say', input: 'via adapter' }, { operationId: 'adapter-once' })
    const result = await b.operations.wait('adapter-once')
    const view = await backend.readView()
    expect(view.view).toBe('applied')
    expect('finalRevision' in view).toBe(false)
    const events = await view.readEvents()
    expect(events.transactions[0]?.proposalId).toBe(result.attemptId)
    expect(events.transactions[0]?.events[0]?.origin).toMatchObject({ kind: 'peer-generation', authorId: b.deviceId, operationId: 'adapter-once' })
    await view.release()
    await expect(backend.readView({ view: 'final' })).rejects.toThrow('APPLICATION_VIEW_UNSUPPORTED')
    await expect(backend.events.publish('anything', {}, { operationId: 'undeclared' })).rejects.toThrow('APPLICATION_EVENT_PUBLICATION_NOT_CONFIGURED')
    link.close()
    expect(phases.at(-1)).toBe('waiting')
  })
})

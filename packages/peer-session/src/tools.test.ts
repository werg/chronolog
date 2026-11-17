import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  bytesDigest, createGenerationRegistry, createPeerIdentity, MemoryBytesStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest, type PrefixProof,
} from '@chronolog/peer-generation'
import { eventExecutionManifest } from '@chronolog/materializer'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery } from './definition.js'
import { openApplicationDevice } from './device.js'
import { openPeerApplication } from './runtime.js'
import { connectApplications, type ApplicationReadView, type ApplicationSession } from './session.js'
import { createApplicationTools, serveApplicationToolLines } from './tools.js'

const definition = defineApplication({ id: 'agent-tools', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', { text })) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })
const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { vi.restoreAllMocks(); for (const close of cleanup.splice(0).reverse()) await close() })
async function fixture() {
  const host = await createPeerIdentity()
  const devices = await Promise.all([0, 1].map(() => openApplicationDevice({ store: new MemoryBytesStore(), create: true })))
  const key = crypto.getRandomValues(new Uint8Array(32)), epochKeys = new Map([[0, key]])
  const manifest = await executionManifestArtifacts(await eventExecutionManifest())
  const descriptor = await signApplicationDescriptor({ applicationId: 'ab'.repeat(32), historyId: 'tool-observations',
    profile: 'peer-generation-v1', policy: 'eligible-members-v1', controlPublicKey: host.publicKey,
    schemaAdministrator: devices[0]!.identity.publicKey, executionManifestDigest: bytesToHex(manifest.executionManifestDigest),
    definitionDigest: await applicationDefinitionDigest(definition), schemaDigest: null }, host)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: devices.map(device => participantGrant(device.identity.publicKey, { administrator: true })) }, host)
  const registry = await createGenerationRegistry({ store: new MemoryBytesStore(), descriptor, controls: [control], signer: host })
  await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
    policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null, coordinator: devices[0]!.identity.publicKey,
    requester: devices[0]!.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, devices[0]!.identity))
  const sessions = await Promise.all(devices.map(async device => {
    const session = await openPeerApplication({ device, definition, authority: await registry.read(), epochKeys })
    cleanup.push(() => session.close()); return session
  }))
  return { a: sessions[0]!, b: sessions[1]!, async recover(point?: PrefixProof) {
    const base = point ?? await sessions[1]!.recoveryPoint(), authority = await registry.read()
    await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile,
      policy: descriptor.payload.policy, transitionId: 'recover', expectedGeneration: authority.generations.at(-1)!.id,
      coordinator: devices[1]!.identity.publicKey, requester: devices[1]!.identity.publicKey, controlRevision: 0,
      reason: 'takeover', base }, devices[1]!.identity))
    await sessions[1]!.adopt(await registry.read()); await sessions[0]!.adopt(await registry.read())
  } }
}
async function post(session: ApplicationSession<typeof definition>, operationId: string) {
  const operation = await session.command('say', operationId, { operationId })
  await operation.applied({ signal: AbortSignal.timeout(5000) })
}
function observeReleases(session: ApplicationSession) {
  const original = session.changes.bind(session), released = vi.fn()
  vi.spyOn(session, 'changes').mockImplementation(options => ({ [Symbol.asyncIterator]() {
    const iterator = original(options)[Symbol.asyncIterator]()
    return { next: () => iterator.next(), async return() { released(); return iterator.return!() } }
  } }))
  return released
}

describe('local application tool revisions and bounded changes', () => {
  it('advertises optional canonical revision guards and preserves them in the signed command', async () => {
    const { a } = await fixture(), tools = createApplicationTools(a), schemas = tools.list()
    const command = (schemas.find(tool => tool.name === 'command')!.inputSchema.oneOf as Array<Record<string, unknown>>)[0]!
    const reapply = (schemas.find(tool => tool.name === 'reapply')!.inputSchema.oneOf as Array<Record<string, unknown>>)[0]!
    const changes = schemas.find(tool => tool.name === 'changes')!.inputSchema
    for (const name of ['operation', 'wait']) {
      const schema = schemas.find(tool => tool.name === name)!.inputSchema
      expect(schema.required).toEqual(['operationId'])
      expect((schema.properties as Record<string, unknown>).author).toEqual({ type: 'string', pattern: '^[0-9a-f]{64}$' })
    }
    expect(command.required).toEqual(['name', 'input', 'operationId'])
    expect(reapply.required).toEqual(['name', 'input', 'operationId', 'originalOperationId'])
    expect(changes.required).toEqual([])
    const revision = (command.properties as Record<string, unknown>).basedOn
    expect((reapply.properties as Record<string, unknown>).basedOn).toEqual(revision)
    expect((reapply.properties as Record<string, unknown>).originalAuthor).toEqual({ type: 'string', pattern: '^[0-9a-f]{64}$' })
    expect((changes.properties as Record<string, unknown>).after).toEqual(revision)
    expect(revision).toMatchObject({ additionalProperties: false,
      required: ['applicationId', 'historyId', 'generation', 'point', 'controlRevision', 'materializationRevision'],
      properties: { point: { additionalProperties: false, required: ['generation', 'sequence', 'root'] } } })
    const basedOn = (await a.query('messages', null)).revision
    await tools.call('command', { name: 'say', input: 'guarded', operationId: 'guarded', basedOn })
    expect((await a.operations.inspect('guarded'))?.attempt.payload.header.basedOn).toEqual(basedOn)
    await expect(tools.call('command', { name: 'say', input: 'foreign', operationId: 'foreign',
      basedOn: { ...basedOn, historyId: 'another-history' } })).rejects.toThrow('APPLICATION_TOOL_REVISION_SCOPE_MISMATCH')
    expect(await a.operations.get('foreign')).toBeNull()
  })

  it('scopes duplicate operation IDs by original author and reapplies vanished-author work as the current device', async () => {
    const f = await fixture(), tools = createApplicationTools(f.b), originalAuthor = f.a.deviceId
    const link = await connectApplications(f.a, f.b)
    await post(f.a, 'collision'); await link.synchronize()
    const base = await f.b.recoveryPoint()
    await post(f.b, 'collision'); await post(f.a, 'other-abandoned'); await link.synchronize()
    const local = await tools.call('operation', { operationId: 'collision' })
    const remote = await tools.call('operation', { operationId: 'collision', author: originalAuthor })
    expect(local).toMatchObject({ attempt: { payload: { header: { author: f.b.deviceId } } } })
    expect(remote).toMatchObject({ attempt: { payload: { header: { author: originalAuthor } } } })
    await link.close(); await f.recover(base)
    const recovered = await connectApplications(f.a, f.b)
    await recovered.synchronize()
    const retained = await f.b.operations.wait('collision', { author: originalAuthor })
    expect(await tools.call('wait', { operationId: 'collision', author: originalAuthor })).toEqual(retained)
    expect(retained.author).toBe(originalAuthor)
    await expect(tools.call('wait', { operationId: 'collision' })).rejects.toMatchObject({ operation: { status: 'abandoned' } })
    expect(await f.b.waitForCoverage(retained, { signal: AbortSignal.timeout(5000) })).not.toHaveLength(0)
    await recovered.close(); await f.a.close()
    const abandoned = await f.b.operations.inspect('other-abandoned', { author: originalAuthor })
    expect(await tools.call('operation', { operationId: 'other-abandoned' })).toBeNull()
    expect(await tools.call('operation', { operationId: 'other-abandoned', author: originalAuthor })).toEqual(abandoned)
    await expect(tools.call('wait', { operationId: 'other-abandoned', author: originalAuthor }))
      .rejects.toMatchObject({ operation: { status: 'abandoned', attemptId: abandoned!.attempt.id } })
    const basedOn = (await f.b.query('messages', null)).revision
    await tools.call('reapply', { name: 'say', input: 'Reviewed after recovery', operationId: 'reapplied-by-b',
      originalOperationId: 'other-abandoned', originalAuthor, basedOn })
    expect(await tools.call('wait', { operationId: 'reapplied-by-b' })).toMatchObject({ status: 'applied', author: f.b.deviceId })
    expect((await f.b.operations.inspect('reapplied-by-b'))!.attempt.payload.header).toMatchObject({
      author: f.b.deviceId, reapplyOf: abandoned!.attempt.id, basedOn,
    })
    await expect(tools.call('retry', { operationId: 'other-abandoned', author: originalAuthor })).rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
  })

  it('rejects malformed explicit authors before reading or creating an operation', async () => {
    const { a } = await fixture(), tools = createApplicationTools(a)
    for (const author of [null, 1, '', 'ff', 'GG'.repeat(32)]) {
      await expect(tools.call('operation', { operationId: 'missing', author })).rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
      await expect(tools.call('wait', { operationId: 'missing', author })).rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
      await expect(tools.call('reapply', { name: 'say', input: 'invalid', operationId: 'new', originalOperationId: 'missing', originalAuthor: author }))
        .rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
    }
    expect(await a.operations.get('new')).toBeNull()
  })

  it('returns the current coherent revision and bounds an unchanged observation without a replay queue', async () => {
    const { a } = await fixture(), tools = createApplicationTools(a), released = observeReleases(a)
    const revision = a.revision
    expect(await tools.call('changes', {})).toEqual({ change: { kind: 'applied', revision, recovery: null }, resetRequired: false })
    expect(await tools.call('changes', { after: revision, waitMs: 5 })).toEqual({ change: null, resetRequired: false })
    expect(released).toHaveBeenCalledTimes(2)
    expect(a.signal.aborted).toBe(false)
    const waiting = tools.call('changes', { after: revision, waitMs: 5000 })
    await post(a, 'new-work')
    expect(await waiting).toEqual({ change: { kind: 'applied', revision: a.revision, recovery: null }, resetRequired: false })
    expect(released).toHaveBeenCalledTimes(3)
    expect((await a.query('messages', null)).value.events).toHaveLength(1)
  })

  it('rejects malformed and foreign observation revisions instead of accepting them as authority', async () => {
    const { a } = await fixture(), tools = createApplicationTools(a), revision = a.revision
    for (const input of [
      { after: { ...revision, applicationId: 'ff'.repeat(32) } },
      { after: { ...revision, historyId: 'foreign' } },
      { after: { ...revision, point: { ...revision.point, sequence: -1 } } },
      { after: { ...revision, materializationRevision: 'not-a-revision' } },
      { after: { ...revision, extra: true } }, { after: null },
      { waitMs: -1 }, { waitMs: 30_001 }, { waitMs: 0.5 }, { waitMs: null }, { limit: 2 },
    ]) await expect(tools.call('changes', input)).rejects.toThrow()
    expect(await tools.call('changes', { after: { ...revision, point: { ...revision.point } }, waitMs: 0 }))
      .toEqual({ change: null, resetRequired: false })
  })

  it('reports a recovery that happened between calls and reapplication keeps its reviewed revision', async () => {
    const f = await fixture(), tools = createApplicationTools(f.a)
    const link = await connectApplications(f.a, f.b)
    await post(f.a, 'retained'); await link.synchronize(); await link.close()
    await post(f.a, 'abandoned')
    const after = f.a.revision
    await f.recover()
    const notice = f.a.inspectRecovery().at(-1)!
    expect(notice.abandoned).toContainEqual(expect.objectContaining({ operationId: 'abandoned' }))
    expect(await tools.call('changes', { after })).toEqual({
      change: { kind: 'recovery', revision: f.a.revision, recovery: notice }, resetRequired: true,
    })
    const basedOn = (await f.a.query('messages', null)).revision
    await tools.call('reapply', { name: 'say', input: 'reviewed', operationId: 'reviewed', originalOperationId: 'abandoned', basedOn })
    const old = await f.a.operations.inspect('abandoned'), retried = await f.a.operations.inspect('reviewed')
    expect(retried?.attempt.payload.header).toMatchObject({ basedOn, reapplyOf: old?.attempt.id })
    // A new observer may have no retained notice. A generation difference still
    // requires a reread, but cannot manufacture an abandoned range or loss claim.
    vi.spyOn(f.a, 'inspectRecovery').mockReturnValue([])
    expect(await tools.call('changes', { after })).toEqual({
      change: { kind: 'applied', revision: f.a.revision, recovery: null }, resetRequired: true,
    })
  })

  it('releases its actual session iterator on caller cancellation and session close', async () => {
    const { a } = await fixture(), tools = createApplicationTools(a), released = observeReleases(a)
    const cancellation = new AbortController()
    const cancelled = tools.call('changes', { after: a.revision, waitMs: 30_000 }, { signal: cancellation.signal })
    const cancelledResult = expect(cancelled).rejects.toThrow('caller stopped')
    cancellation.abort(new Error('caller stopped'))
    await cancelledResult
    await vi.waitFor(() => { expect(released).toHaveBeenCalledTimes(1) })
    expect(a.signal.aborted).toBe(false)
    const closed = tools.call('changes', { after: a.revision, waitMs: 30_000 })
    const closedResult = expect(closed).rejects.toThrow('APPLICATION_SESSION_CLOSED')
    await a.close(); await closedResult
    await vi.waitFor(() => { expect(released).toHaveBeenCalledTimes(2) })
  })

  it('serves bounded changes through the same JSON-lines transport without retaining a watcher', async () => {
    const { a } = await fixture(), output: string[] = [], released = observeReleases(a)
    const requests = [{ id: 'current', tool: 'changes', input: {} },
      { id: 'unchanged', tool: 'changes', input: { after: a.revision, waitMs: 1 }, timeoutMs: 1000 }]
    await serveApplicationToolLines(a, { input: { async *[Symbol.asyncIterator]() {
      for (const request of requests) yield JSON.stringify(request)
    } }, write: line => { output.push(line) } })
    expect(JSON.parse(output[0]!)).toEqual({ id: 'current', result: {
      change: { kind: 'applied', revision: a.revision, recovery: null }, resetRequired: false,
    } })
    expect(JSON.parse(output[1]!)).toEqual({ id: 'unchanged', result: { change: null, resetRequired: false } })
    expect(released).toHaveBeenCalledTimes(2)
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { eventExecutionManifest } from '@chronolog/materializer'
import {
  bytesDigest, controlParticipantGrant, createGenerationRegistry, createPeerIdentity, MemoryPeerStore, participantGrant,
  signApplicationDescriptor, signControlRevision, signTransitionRequest,
} from '@chronolog/peer-generation'
import { bytesToHex, emit, executionManifestArtifacts, program } from '@chronolog/protocol'
import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery, type ApplicationDefinition } from './definition.js'
import { openApplicationDevice } from './device.js'
import { createApplicationMcpServer } from './mcp.js'
import { openPeerApplication } from './runtime.js'
import { connectApplications, type ApplicationReadView } from './session.js'
import { createApplicationTools } from './tools.js'

const cleanup: Array<() => void | Promise<void>> = []
afterEach(async () => { for (const close of cleanup.splice(0).reverse()) await close() })
const definition = defineApplication({ id: 'recovery-tools', version: '1', commands: {
  say: defineCommand({ description: 'Post a message', input: { type: 'string' }, prepare: text => program(emit('message', text)) }),
}, queries: {
  messages: defineQuery({ description: 'Read messages', input: { type: 'null' }, read: (view: ApplicationReadView) => view.readEvents() }),
} })

async function fixture<const D extends ApplicationDefinition>(definition: D) {
  const signer = await createPeerIdentity(), devices = await Promise.all([0, 1].map(() => openApplicationDevice({ store: new MemoryPeerStore(), create: true })))
  const first = devices[0]!, second = devices[1]!, key = crypto.getRandomValues(new Uint8Array(32))
  const manifest = await executionManifestArtifacts(await eventExecutionManifest('peer-generation-v1'))
  const descriptor = await signApplicationDescriptor({ applicationId: '68'.repeat(32), historyId: 'tools', profile: 'peer-generation-v1',
    policy: 'eligible-members-v1', controlPublicKey: signer.publicKey, schemaAdministrator: first.identity.publicKey, schemaDigest: null,
    definitionDigest: await applicationDefinitionDigest(definition), executionManifestDigest: bytesToHex(manifest.executionManifestDigest) }, signer)
  const control = await signControlRevision({ applicationId: descriptor.payload.applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [controlParticipantGrant(signer.publicKey), ...devices.map(device => participantGrant(device.identity.publicKey))] }, signer)
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer })
  const initial = await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
    profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'initial', expectedGeneration: null,
    requester: first.identity.publicKey, coordinator: first.identity.publicKey, controlRevision: 0, reason: 'create', base: null }, first.identity))
  const sessions = await Promise.all(devices.map(async device => openPeerApplication({ device, definition, authority: await registry.read(), epochKeys: new Map([[0, key]]) })))
  cleanup.push(...sessions.map(session => () => session.close()))
  return { a: sessions[0]!, b: sessions[1]!, first, second, registry, initial, descriptor }
}

describe('local application tool capabilities', () => {
  it('inspects another signer and deliberately reapplies abandoned intent as the current device', async () => {
    const { a, b, second, registry, initial, descriptor } = await fixture(definition)
    const base = await b.recoveryPoint(), link = await connectApplications(a, b)
    cleanup.push(() => link.close())
    const original = await a.command('say', 'original', { operationId: 'old-intent' })
    await original.applied({ signal: AbortSignal.timeout(5000) }); await link.synchronize()
    const prior = await a.operations.inspect('old-intent')
    link.close(); await a.close()
    await registry.select(await signTransitionRequest({ applicationId: descriptor.payload.applicationId,
      profile: descriptor.payload.profile, policy: descriptor.payload.policy, transitionId: 'recover', expectedGeneration: initial.id,
      requester: b.deviceId, coordinator: b.deviceId, controlRevision: 0, reason: 'takeover', base }, second.identity))
    await b.adopt(await registry.read())
    const tools = createApplicationTools(b)
    expect(await tools.call('operation', { operationId: 'old-intent' })).toBeNull()
    expect(await tools.call('operation', { operationId: 'old-intent', author: a.deviceId })).toMatchObject({
      state: { status: 'abandoned' }, attempt: prior!.attempt,
    })
    await tools.call('reapply', { name: 'say', input: 'reviewed by survivor', originalOperationId: 'old-intent',
      originalAuthor: a.deviceId, operationId: 'new-intent', basedOn: b.revision })
    await tools.call('wait', { operationId: 'new-intent' }, { signal: AbortSignal.timeout(5000) })
    const reapplied = await b.operations.inspect('new-intent')
    expect(reapplied?.state).toMatchObject({ status: 'applied', author: b.deviceId, outcome: 'accepted' })
    expect(reapplied?.attempt.payload.header).toMatchObject({ author: b.deviceId, reapplyOf: prior!.attempt.id })
    expect((await b.query('messages', null)).value.events).toHaveLength(1)
    expect((await b.operations.inspect('old-intent', { author: a.deviceId }))?.attempt).toEqual(prior!.attempt)
    await expect(tools.call('retry', { operationId: 'old-intent', author: a.deviceId })).rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
  })

  it('validates bounded author selectors before inspecting or reapplying', async () => {
    const { b } = await fixture(definition), tools = createApplicationTools(b)
    for (const invalid of ['', 'ab'.repeat(31), 'ab'.repeat(33), 'AB'.repeat(32), 'gg'.repeat(32), 42, null]) {
      await expect(tools.call('operation', { operationId: 'old', author: invalid })).rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
      await expect(tools.call('reapply', { name: 'say', input: 'reviewed', operationId: 'new', originalOperationId: 'old', originalAuthor: invalid }))
        .rejects.toThrow('APPLICATION_TOOL_INPUT_INVALID')
    }
    const operation = tools.list().find(tool => tool.name === 'operation')!
    expect(operation.inputSchema).toMatchObject({ required: ['operationId'], properties: { author: { minLength: 64, maxLength: 64, pattern: '^[0-9a-f]{64}$' } } })
  })

  it.each([
    { name: 'read-only', commands: {}, queries: definition.queries, present: ['query'], absent: ['command', 'reapply'] },
    { name: 'commands-only', commands: definition.commands, queries: {}, present: ['command', 'reapply'], absent: ['query'] },
    { name: 'inspection-only', commands: {}, queries: {}, present: [], absent: ['command', 'query', 'reapply'] },
  ])('advertises only supported domain tools for $name definitions', async ({ name, commands, queries, present, absent }) => {
    const { b } = await fixture(defineApplication({ id: name, version: '1', commands, queries }))
    const tools = createApplicationTools(b).list(), names = tools.map(tool => tool.name)
    expect(names).toEqual(expect.arrayContaining(['describe', 'operation', 'retry', 'wait', 'recoveries', 'changes', ...present]))
    for (const unsupported of absent) expect(names).not.toContain(unsupported)
    for (const tool of tools) if ('oneOf' in tool.inputSchema) expect(tool.inputSchema.oneOf).not.toHaveLength(0)
    const mcp = createApplicationMcpServer(b)
    cleanup.push(() => mcp.close())
    await mcp.handle({ jsonrpc: '2.0', id: 1, method: 'initialize' })
    for (const unsupported of absent) expect(await mcp.handle({ jsonrpc: '2.0', id: unsupported, method: 'tools/call', params: { name: unsupported, arguments: {} } }))
      .toMatchObject({ error: { code: -32602, message: 'Unknown application tool' } })
  })
})
